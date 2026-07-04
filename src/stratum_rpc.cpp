#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <jansson.h>

#include "miner.h"
#include "stratum_internal.h"

enum stratum_message_status {
    STRATUM_MESSAGE_OK = 0,
    STRATUM_MESSAGE_IGNORED,
    STRATUM_MESSAGE_FATAL,
};

struct stratum_method_ctx {
    struct stratum_ctx *sctx;
    json_t *id;
    json_t *params;
    const struct stratum_protocol_ops *ops;
};

typedef enum stratum_message_status (*stratum_method_handler_fn)(const struct stratum_method_ctx *ctx);

struct stratum_method_handler {
    const char *name;
    stratum_method_handler_fn handle;
};

struct stratum_response_view {
    uint32_t id;
    json_t *result;
    json_t *error;
};

static enum stratum_message_status stratum_status_from_bool(bool ok)
{
    return ok ? STRATUM_MESSAGE_OK : STRATUM_MESSAGE_FATAL;
}

bool stratum_parse_rpc_id(json_t *id_val, uint32_t *id_out)
{
    const char *id_str;
    char *endptr;
    unsigned long parsed;
    json_int_t id;

    if (!id_val || json_is_null(id_val))
        return false;

    if (json_is_integer(id_val)) {
        id = json_integer_value(id_val);
        if (id < 0 || (uint64_t)id > UINT32_MAX)
            return false;
        if (id_out)
            *id_out = (uint32_t)id;
        return true;
    }

    if (!json_is_string(id_val))
        return false;

    id_str = json_string_value(id_val);
    if (!id_str || !id_str[0] || id_str[0] == '-')
        return false;

    parsed = strtoul(id_str, &endptr, 10);
    if (endptr == id_str || *endptr != '\0' || parsed > UINT32_MAX)
        return false;

    if (id_out)
        *id_out = (uint32_t)parsed;
    return true;
}

static bool stratum_send_json_message(struct stratum_ctx *sctx, json_t *val)
{
    char *line;
    bool ret;

    if (!val)
        return false;

    line = json_dumps(val, 0);
    if (!line)
        return false;

    ret = stratum_send_line(sctx, line);
    free(line);
    return ret;
}

static bool stratum_send_rpc_result(struct stratum_ctx *sctx, json_t *id, json_t *result)
{
    json_t *reply;
    bool ret;

    if (!id || json_is_null(id) || !result) {
        if (result)
            json_decref(result);
        return false;
    }

    reply = json_object();
    if (!reply) {
        json_decref(result);
        return false;
    }

    if (json_object_set(reply, "id", id) != 0) {
        json_decref(result);
        json_decref(reply);
        return false;
    }
    json_object_set_new(reply, "error", json_null());
    json_object_set_new(reply, "result", result);
    ret = stratum_send_json_message(sctx, reply);
    json_decref(reply);
    return ret;
}

static bool stratum_send_rpc_bool_result(struct stratum_ctx *sctx, json_t *id, bool result)
{
    return stratum_send_rpc_result(sctx, id, result ? json_true() : json_false());
}

static bool stratum_send_rpc_string_result(struct stratum_ctx *sctx, json_t *id, const char *result)
{
    json_t *json_result = json_string(result ? result : "");

    if (!json_result)
        return false;

    return stratum_send_rpc_result(sctx, id, json_result);
}

static bool stratum_send_rpc_error(struct stratum_ctx *sctx, json_t *id, int code, const char *message)
{
    json_t *reply;
    json_t *error;
    bool ret;

    if (!id || json_is_null(id))
        return false;

    reply = json_object();
    error = json_object();
    if (!reply || !error) {
        if (reply)
            json_decref(reply);
        if (error)
            json_decref(error);
        return false;
    }

    if (json_object_set(reply, "id", id) != 0) {
        json_decref(error);
        json_decref(reply);
        return false;
    }
    json_object_set_new(reply, "result", json_false());
    json_object_set_new(error, "code", json_integer(code));
    json_object_set_new(error, "message", json_string(message ? message : "error"));
    json_object_set_new(reply, "error", error);
    ret = stratum_send_json_message(sctx, reply);
    json_decref(reply);
    return ret;
}

uint32_t stratum_submit_id_next(struct stratum_ctx *sctx)
{
    uint32_t id = 0;

    pthread_mutex_lock(&sctx->submit_lock);
    if (sctx->next_submit_id < 10)
        sctx->next_submit_id = 10;
    id = sctx->next_submit_id++;
    pthread_mutex_unlock(&sctx->submit_lock);

    return id;
}

static int submit_id_timeout_seconds(const struct stratum_ctx *sctx)
{
    int timeout = miner_get_pool_timeout(sctx->pooln);

    return timeout > 0 ? timeout : 1;
}

static unsigned int submit_id_reap_stale_locked(struct stratum_ctx *sctx, time_t now, int timeout_seconds)
{
    unsigned int reaped = 0;

    for (int slot = 0; slot < MAX_PENDING_SUBMITS; slot++) {
        struct pending_submit *pending = &sctx->pending_submits[slot];

        if (!pending->used)
            continue;
        if (pending->queued_at == 0)
            continue;
        if (now < pending->queued_at)
            continue;
        if ((int)(now - pending->queued_at) < timeout_seconds)
            continue;

        pending->used = false;
        pending->queued_at = 0;
        reaped++;
    }

    return reaped;
}

static void submit_id_request_reconnect(struct stratum_ctx *sctx, const char *label, const char *reason)
{
    if (__atomic_exchange_n(&sctx->reconnect_requested, 1, __ATOMIC_ACQ_REL) != 0)
        return;

    applog(LOG_WARNING, "%s %s, forcing reconnect to recover share submission", label, reason);
    stratum_request_shutdown(sctx);
}

static bool submit_id_reserve(struct stratum_ctx *sctx, uint32_t id, double sharediff, int thread_id,
    const char *label)
{
    bool stored = false;
    time_t now = time(NULL);
    unsigned int reaped = 0;

    pthread_mutex_lock(&sctx->submit_lock);
    reaped = submit_id_reap_stale_locked(sctx, now, submit_id_timeout_seconds(sctx));
    for (int slot = 0; slot < MAX_PENDING_SUBMITS; slot++) {
        if (sctx->pending_submits[slot].used)
            continue;

        sctx->pending_submits[slot].id = id;
        sctx->pending_submits[slot].sharediff = sharediff;
        sctx->pending_submits[slot].thread_id = thread_id;
        sctx->pending_submits[slot].queued_at = now;
        sctx->pending_submits[slot].used = true;
        stored = true;
        break;
    }
    pthread_mutex_unlock(&sctx->submit_lock);

    if (reaped > 0) {
        applog(LOG_WARNING, "Reaped %u stale pending submit(s) before reserving id %u", reaped, id);
        submit_id_request_reconnect(sctx, label, "timed out waiting for submit replies");
    }

    return stored;
}

static void submit_id_release(struct stratum_ctx *sctx, uint32_t id)
{
    pthread_mutex_lock(&sctx->submit_lock);
    for (int slot = 0; slot < MAX_PENDING_SUBMITS; slot++) {
        if (!sctx->pending_submits[slot].used || sctx->pending_submits[slot].id != id)
            continue;

        sctx->pending_submits[slot].used = false;
        sctx->pending_submits[slot].queued_at = 0;
        break;
    }
    pthread_mutex_unlock(&sctx->submit_lock);
}

bool stratum_send_submit(struct stratum_ctx *sctx, const char *line, uint32_t submit_id, double sharediff,
    int thread_id, const char *label)
{
    if (!submit_id_reserve(sctx, submit_id, sharediff, thread_id, label)) {
        applog(LOG_WARNING,
               "%s pending submit queue is full (%d entries), dropping share submission id %u",
               label, MAX_PENDING_SUBMITS, submit_id);
        submit_id_request_reconnect(sctx, label, "pending submit queue is full");
        return false;
    }

    if (!stratum_send_line(sctx, line)) {
        submit_id_release(sctx, submit_id);
        applog(LOG_ERR, "%s stratum_send_line failed", label);
        return false;
    }

    return true;
}

static bool submit_id_take_metadata(struct stratum_ctx *sctx, uint32_t id, double *sharediff, int *thread_id)
{
    bool found = false;

    pthread_mutex_lock(&sctx->submit_lock);
    for (int slot = 0; slot < MAX_PENDING_SUBMITS; slot++) {
        if (!sctx->pending_submits[slot].used || sctx->pending_submits[slot].id != id)
            continue;

        *sharediff = sctx->pending_submits[slot].sharediff;
        *thread_id = sctx->pending_submits[slot].thread_id;
        sctx->pending_submits[slot].used = false;
        sctx->pending_submits[slot].queued_at = 0;
        found = true;
        break;
    }
    pthread_mutex_unlock(&sctx->submit_lock);

    return found;
}

static bool stratum_parse_response_view(json_t *val, struct stratum_response_view *msg)
{
    json_t *id_val = json_object_get(val, "id");
    const char *method = json_string_value(json_object_get(val, "method"));

    memset(msg, 0, sizeof(*msg));

    if (method || !stratum_parse_rpc_id(id_val, &msg->id))
        return false;

    msg->result = json_object_get(val, "result");
    msg->error = json_object_get(val, "error");
    return true;
}

static const char *stratum_get_reject_reason(json_t *err_val)
{
    if (!err_val)
        return NULL;

    /* Monero dialect: error is an object {"code":-1,"message":"..."} */
    if (json_is_object(err_val))
        return json_string_value(json_object_get(err_val, "message"));

    if (!json_is_array(err_val) || json_array_size(err_val) <= 1)
        return NULL;

    return json_string_value(json_array_get(err_val, 1));
}

static bool stratum_handle_submit_response(struct stratum_ctx *sctx,
    const struct stratum_response_view *response)
{
    uint32_t accepted_count = 0;
    uint32_t rejected_count = 0;
    double sharediff = 0.0;
    int thread_id = -1;

    bool have_metadata = submit_id_take_metadata(sctx, response->id, &sharediff, &thread_id);
    if (!have_metadata && opt_debug)
        applog(LOG_DEBUG, "No pending submit metadata for response id %u", response->id);

    /* A spec-compliant pool always sends an explicit result on a submit reply.
     * Treat a missing result as a rejection (json_is_true(NULL) is false) rather
     * than a fatal protocol error — an out-of-spec reject shouldn't cycle the
     * whole connection. */
    /* Monero dialect: an accepted submit returns {"status":"OK"} instead of
     * boolean true. */
    bool result_ok = json_is_true(response->result);
    if (!result_ok && json_is_object(response->result)) {
        const char *status =
            json_string_value(json_object_get(response->result, "status"));
        result_ok = status && strcasecmp(status, "OK") == 0;
    }

    if (result_ok) {
        miner_record_thread_share_result(thread_id, true);
        stratum_update_share_stats(sctx->pooln, true, &accepted_count, &rejected_count);
        if (have_metadata)
            applog(LOG_NOTICE, "%sAccepted%s share %u/%u (diff %.3f)",
                   CL_GRN, CL_N, accepted_count, accepted_count + rejected_count, sharediff);
        else
            applog(LOG_NOTICE, "%sAccepted%s share %u/%u",
                   CL_GRN, CL_N, accepted_count, accepted_count + rejected_count);
        return true;
    }

    miner_record_thread_share_result(thread_id, false);
    stratum_update_share_stats(sctx->pooln, false, &accepted_count, &rejected_count);
    applog(LOG_WARNING, "%sRejected%s share %u/%u",
           CL_RED, CL_N, accepted_count, accepted_count + rejected_count);

    const char *reason = stratum_get_reject_reason(response->error);
    if (reason)
        applog(LOG_WARNING, "Reject reason: %s", reason);

    return true;
}

static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
    double diff = json_number_value(json_array_get(params, 0));

    if (diff <= 0.0)
        return false;

    stratum_store_next_diff(sctx, diff);
    return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
    json_t *port_val = json_array_get(params, 1);
    const char *host = json_string_value(json_array_get(params, 0));
    char *url = NULL;
    int port;
    size_t url_len;
    bool ret = false;

    if (json_is_string(port_val))
        port = atoi(json_string_value(port_val));
    else
        port = (int)json_integer_value(port_val);
    if (!host || !host[0] || port <= 0 || port > 65535) {
        applog(LOG_ERR, "client.reconnect: missing or invalid host/port");
        goto out;
    }

    url_len = 32 + strlen(host);
    url = (char *)malloc(url_len);
    if (!url)
        goto out;
    snprintf(url, url_len, "stratum+tcp://%s:%d", host, port);
    if (!stratum_set_url(sctx, url))
        goto out;

    /* Keep the pool table in step with the session: failover logs, the API
     * pool listing and dev-fee return messages all print pools[].url, and
     * leaving the pre-redirect URL there makes them name a host this
     * session is no longer talking to (connects use sctx->url). */
    if (sctx->pooln >= 0 && sctx->pooln < num_pools) {
        struct pool_infos *pool = &pools[sctx->pooln];
        const char *short_url = strstr(url, "://");
        short_url = short_url ? short_url + 3 : url;
        pthread_mutex_lock(&stratum_work_lock);
        snprintf(pool->url, sizeof(pool->url), "%s", url);
        snprintf(pool->short_url, sizeof(pool->short_url), "%s", short_url);
        pthread_mutex_unlock(&stratum_work_lock);
    }

    applog(LOG_NOTICE, "Server requested reconnection to %s", sctx->url);
    __atomic_store_n(&sctx->reconnect_requested, 1, __ATOMIC_RELEASE);
    stratum_disconnect(sctx);
    ret = true;

out:
    free(url);
    return ret;
}

static bool stratum_pong(struct stratum_ctx *sctx, json_t *id)
{
    return stratum_send_rpc_string_result(sctx, id, "pong");
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
    json_t *val = json_array_get(params, 0);

    if (val) {
        const char *data = json_string_value(val);
        if (data && strlen(data)) {
            char symbol[32] = {0};
            char job_id[128] = {0};
            uint32_t height = 0;
            int ss = sscanf(data, "equihash %31s block %u", symbol, &height);
            if (height && ss > 1) {
                bool height_updated = false;

                pthread_mutex_lock(&stratum_work_lock);
                sctx->job.height = height;
                if (sctx->job.job_id) {
                    snprintf(job_id, sizeof(job_id), "%s", sctx->job.job_id);
                    height_updated = stratum_update_active_work_height_locked(sctx->pooln, job_id, height);
                }
                pthread_mutex_unlock(&stratum_work_lock);

                if (height_updated && !opt_quiet)
                    applog(LOG_INFO, "Updated work height: block %u, job %s", height, job_id);
                if (opt_debug)
                    applog(LOG_DEBUG, "Block height set to %u from: %s", height, data);
            }
            applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", data);
        }
    }

    if (!id || json_is_null(id))
        return true;

    return stratum_send_rpc_bool_result(sctx, id, true);
}

static bool stratum_get_algo(struct stratum_ctx *sctx, json_t *id)
{
    return stratum_send_rpc_string_result(sctx, id, algo_names[opt_algo]);
}

static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id)
{
    return stratum_send_rpc_string_result(sctx, id, USER_AGENT);
}

static enum stratum_message_status stratum_handle_notify_method(const struct stratum_method_ctx *ctx)
{
    return stratum_status_from_bool(ctx->ops->handle_notify(ctx->sctx, ctx->params));
}

static enum stratum_message_status stratum_handle_ping_method(const struct stratum_method_ctx *ctx)
{
    if (opt_debug)
        applog(LOG_DEBUG, "Pool ping");
    return stratum_status_from_bool(stratum_pong(ctx->sctx, ctx->id));
}

static enum stratum_message_status stratum_handle_set_difficulty_method(const struct stratum_method_ctx *ctx)
{
    return stratum_status_from_bool(stratum_set_difficulty(ctx->sctx, ctx->params));
}

static enum stratum_message_status stratum_handle_set_target_method(const struct stratum_method_ctx *ctx)
{
    if (!ctx->ops->handle_set_target) {
        if (opt_debug)
            applog(LOG_DEBUG, "Ignoring mining.set_target for non-Verus protocol");
        return STRATUM_MESSAGE_IGNORED;
    }

    /* Only commit the session to the Verus protocol once the target actually
     * validates; flipping the flag before validation would route subsequent
     * notifies to the Verus handler even if this set_target was malformed. */
    if (!ctx->ops->handle_set_target(ctx->sctx, ctx->params))
        return STRATUM_MESSAGE_FATAL;
    stratum_is_verus_protocol_store(ctx->sctx, true);
    return STRATUM_MESSAGE_OK;
}

static enum stratum_message_status stratum_handle_set_extranonce_method(const struct stratum_method_ctx *ctx)
{
    return stratum_status_from_bool(stratum_parse_extranonce(ctx->sctx, ctx->params, 0));
}

static enum stratum_message_status stratum_handle_reconnect_method(const struct stratum_method_ctx *ctx)
{
    return stratum_status_from_bool(stratum_reconnect(ctx->sctx, ctx->params));
}

static enum stratum_message_status stratum_handle_show_message_method(const struct stratum_method_ctx *ctx)
{
    return stratum_status_from_bool(stratum_show_message(ctx->sctx, ctx->id, ctx->params));
}

static enum stratum_message_status stratum_handle_get_algo_method(const struct stratum_method_ctx *ctx)
{
    if (opt_debug)
        applog(LOG_DEBUG, "Pool requested client algorithm");
    return stratum_status_from_bool(stratum_get_algo(ctx->sctx, ctx->id));
}

static enum stratum_message_status stratum_handle_get_version_method(const struct stratum_method_ctx *ctx)
{
    return stratum_status_from_bool(stratum_get_version(ctx->sctx, ctx->id));
}

static const struct stratum_method_handler stratum_method_handlers[] = {
    { "mining.notify", stratum_handle_notify_method },
    /* Monero dialect: new work is pushed as method "job" with the job object
     * as params; routed through the same ops->handle_notify. */
    { "job", stratum_handle_notify_method },
    { "mining.ping", stratum_handle_ping_method },
    { "mining.set_difficulty", stratum_handle_set_difficulty_method },
    { "mining.set_target", stratum_handle_set_target_method },
    { "mining.set_extranonce", stratum_handle_set_extranonce_method },
    { "client.reconnect", stratum_handle_reconnect_method },
    { "client.get_algo", stratum_handle_get_algo_method },
    { "client.get_version", stratum_handle_get_version_method },
    { "client.show_message", stratum_handle_show_message_method },
};

static const struct stratum_method_handler *find_stratum_method_handler(const char *method)
{
    size_t count = sizeof(stratum_method_handlers) / sizeof(stratum_method_handlers[0]);

    for (size_t i = 0; i < count; i++) {
        if (!strcasecmp(method, stratum_method_handlers[i].name))
            return &stratum_method_handlers[i];
    }

    return NULL;
}

static enum stratum_message_status stratum_handle_method_value(struct stratum_ctx *sctx, json_t *val)
{
    json_t *id = json_object_get(val, "id");
    json_t *params = json_object_get(val, "params");
    const char *method = json_string_value(json_object_get(val, "method"));
    const struct stratum_protocol_ops *ops = stratum_get_protocol_ops(sctx);
    const struct stratum_method_handler *handler;
    struct stratum_method_ctx ctx;

    if (!method)
        return STRATUM_MESSAGE_FATAL;

    if (opt_debug)
        applog(LOG_DEBUG, "Stratum method: %s", method);

    handler = find_stratum_method_handler(method);
    if (!handler) {
        if (opt_debug)
            applog(LOG_DEBUG, "unknown stratum method %s!", method);
        if (!id || json_is_null(id))
            return STRATUM_MESSAGE_IGNORED;
        return stratum_send_rpc_error(sctx, id, -32601, "Method not found")
            ? STRATUM_MESSAGE_IGNORED
            : STRATUM_MESSAGE_FATAL;
    }

    ctx.sctx = sctx;
    ctx.id = id;
    ctx.params = params;
    ctx.ops = ops;
    return handler->handle(&ctx);
}

static enum stratum_message_status stratum_handle_response_value(struct stratum_ctx *sctx, json_t *val)
{
    struct stratum_response_view response;

    if (!stratum_parse_response_view(val, &response))
        return STRATUM_MESSAGE_FATAL;
    if (response.id < 10)
        return STRATUM_MESSAGE_IGNORED;

    return stratum_handle_submit_response(sctx, &response)
        ? STRATUM_MESSAGE_OK
        : STRATUM_MESSAGE_FATAL;
}

static enum stratum_message_status stratum_dispatch_json_message(struct stratum_ctx *sctx, json_t *val)
{
    if (json_string_value(json_object_get(val, "method")))
        return stratum_handle_method_value(sctx, val);

    return stratum_handle_response_value(sctx, val);
}

bool stratum_handle_json_message(struct stratum_ctx *sctx, json_t *val)
{
    return stratum_dispatch_json_message(sctx, val) != STRATUM_MESSAGE_FATAL;
}

bool stratum_handle_message(struct stratum_ctx *sctx, const char *s)
{
    json_error_t err;
    json_t *val = JSON_LOADS(s, &err);
    enum stratum_message_status status;

    if (!val) {
        applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
        return false;
    }

    status = stratum_dispatch_json_message(sctx, val);
    json_decref(val);
    return status != STRATUM_MESSAGE_FATAL;
}
