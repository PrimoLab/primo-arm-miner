#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <jansson.h>

#include "miner.h"
#include "stratum_internal.h"

enum stratum_wait_status {
    STRATUM_WAIT_OK = 0,
    STRATUM_WAIT_TIMEOUT,
    STRATUM_WAIT_RECV_ERROR,
    STRATUM_WAIT_JSON_ERROR,
    STRATUM_WAIT_SEND_ERROR,
};

enum stratum_request_id {
    STRATUM_REQUEST_SUBSCRIBE = 1,
    STRATUM_REQUEST_AUTHORIZE = 2,
    STRATUM_REQUEST_EXTRANONCE_SUBSCRIBE = 3,
};

static bool stratum_reply_matches_id(json_t *reply, uint32_t expected_id)
{
    uint32_t reply_id = 0;

    return stratum_parse_rpc_id(json_object_get(reply, "id"), &reply_id) &&
           reply_id == expected_id;
}

static enum stratum_wait_status stratum_wait_for_response(struct stratum_ctx *sctx, int expected_id,
    json_t **reply_out, int timeout, bool log_timeout)
{
    json_error_t err;
    time_t deadline = 0;

    *reply_out = NULL;
    if (timeout > 0)
        deadline = time(NULL) + timeout;

    while (1) {
        char *line;
        json_t *val;
        bool timed_out = false;
        int receive_timeout = miner_get_pool_timeout(sctx->pooln);

        if (deadline > 0) {
            time_t now = time(NULL);
            if (now >= deadline)
                return STRATUM_WAIT_TIMEOUT;
            receive_timeout = (int)difftime(deadline, now);
            if (receive_timeout < 1)
                receive_timeout = 1;
        }

        line = stratum_recv_line_timeout(sctx, receive_timeout, &timed_out, log_timeout);
        if (!line)
            return timed_out ? STRATUM_WAIT_TIMEOUT : STRATUM_WAIT_RECV_ERROR;

        val = JSON_LOADS(line, &err);
        if (!val) {
            applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
            free(line);
            return STRATUM_WAIT_JSON_ERROR;
        }

        if (stratum_reply_matches_id(val, (uint32_t)expected_id)) {
            free(line);
            *reply_out = val;
            return STRATUM_WAIT_OK;
        }

        stratum_handle_json_message(sctx, val);
        json_decref(val);
        free(line);
    }
}

static enum stratum_wait_status stratum_send_request_and_wait(struct stratum_ctx *sctx, char *request,
    int expected_id, int timeout, useconds_t post_send_delay_us, json_t **reply_out, bool log_timeout)
{
    *reply_out = NULL;

    if (!stratum_send_line(sctx, request))
        return STRATUM_WAIT_SEND_ERROR;
    if (post_send_delay_us > 0)
        usleep(post_send_delay_us);

    return stratum_wait_for_response(sctx, expected_id, reply_out, timeout, log_timeout);
}

static char *stratum_build_subscribe_request(const struct stratum_ctx *sctx, bool retry)
{
    json_t *params = json_array();

    if (!params)
        return NULL;

    if (!retry) {
        if (!stratum_json_array_append_string(params, USER_AGENT))
            goto out;
        if (sctx->session_id &&
            !stratum_json_array_append_string(params, sctx->session_id)) {
            goto out;
        }
    }

    return stratum_build_request_line("mining.subscribe", STRATUM_REQUEST_SUBSCRIBE, params);

out:
    json_decref(params);
    return NULL;
}

static char *stratum_build_authorize_request(const char *user, const char *pass)
{
    json_t *params = json_array();

    if (!params)
        return NULL;
    if (!stratum_json_array_append_string(params, user) ||
        !stratum_json_array_append_string(params, pass)) {
        json_decref(params);
        return NULL;
    }

    return stratum_build_request_line("mining.authorize", STRATUM_REQUEST_AUTHORIZE, params);
}

static char *stratum_build_extranonce_subscribe_request(void)
{
    json_t *params = json_array();

    if (!params)
        return NULL;

    return stratum_build_request_line("mining.extranonce.subscribe",
                                      STRATUM_REQUEST_EXTRANONCE_SUBSCRIBE, params);
}

static bool stratum_reply_has_rpc_error(json_t *reply, bool allow_false_result, json_t **result_out,
    json_t **error_out)
{
    json_t *result = json_object_get(reply, "result");
    json_t *error = json_object_get(reply, "error");
    bool result_failed = !result || json_is_null(result) ||
        (!allow_false_result && json_is_false(result));

    if (result_out)
        *result_out = result;
    if (error_out)
        *error_out = error;

    return result_failed || (error && !json_is_null(error));
}

static void stratum_log_rpc_error(json_t *err_val)
{
    char *dump = NULL;

    if (err_val)
        dump = json_dumps(err_val, JSON_INDENT(3));
    if (!dump)
        dump = strdup("(unknown reason)");

    applog(LOG_ERR, "JSON-RPC call failed: %s", dump ? dump : "(oom)");
    free(dump);
}

static const char *get_stratum_session_id(json_t *val)
{
    json_t *arr_val = json_array_get(val, 0);
    if (!arr_val || !json_is_array(arr_val))
        return NULL;

    int n = (int)json_array_size(arr_val);
    for (int i = 0; i < n; i++) {
        json_t *arr = json_array_get(arr_val, i);
        if (!arr || !json_is_array(arr))
            break;
        const char *notify = json_string_value(json_array_get(arr, 0));
        if (!notify)
            continue;
        if (!strcasecmp(notify, "mining.notify"))
            return json_string_value(json_array_get(arr, 1));
    }
    return NULL;
}

bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx)
{
    const char *xnonce1 = json_string_value(json_array_get(params, pndx));
    json_t *xn2_val = json_array_get(params, pndx + 1);
    size_t xnonce1_hex_len = xnonce1 ? strlen(xnonce1) : 0;
    int xn1_size = (int)(xnonce1_hex_len / 2);
    int xn2_size = 0;
    bool is_verus = (opt_algo == ALGO_VERUS || stratum_is_verus_protocol_load(sctx));
    bool xn2_present = xn2_val && !json_is_null(xn2_val);
    bool xn2_valid = false;

    if (!xnonce1) {
        applog(LOG_ERR, "Failed to get extranonce1");
        goto out;
    }
    if ((xnonce1_hex_len & 1u) != 0) {
        applog(LOG_ERR, "Invalid extranonce1 hex length");
        goto out;
    }
    if (xn1_size < 1 || xn1_size > 32) {
        applog(LOG_ERR, "Unsupported extranonce1 size of %d", xn1_size);
        goto out;
    }

    if (json_is_integer(xn2_val)) {
        json_int_t parsed = json_integer_value(xn2_val);
        if (parsed >= 0 && parsed <= 32) {
            xn2_size = (int)parsed;
            xn2_valid = true;
        }
    } else if (json_is_string(xn2_val)) {
        const char *xn2_str = json_string_value(xn2_val);
        char *end = NULL;
        long parsed = 0;

        if (xn2_str && xn2_str[0]) {
            errno = 0;
            parsed = strtol(xn2_str, &end, 10);
            if (errno == 0 && end && *end == '\0' && parsed >= 0 && parsed <= 32) {
                xn2_size = (int)parsed;
                xn2_valid = true;
            }
        }
    }

    if (xn2_present && !xn2_valid) {
        applog(LOG_ERR, "Failed to get valid extranonce2_size");
        goto out;
    }

    if (xn2_size == 0) {
        if (!is_verus) {
            applog(LOG_ERR, "Failed to get extranonce2_size");
            goto out;
        }

        xn2_size = 32 - xn1_size;
        if (xn2_size < 1) {
            applog(LOG_ERR, "Failed to derive a valid Verus extranonce2 size");
            goto out;
        }
    }

    if (is_verus) {
        if (xn2_size < 1 || xn1_size + xn2_size != 32) {
            applog(LOG_ERR, "Invalid Verus nonce layout (xnonce1=%d, xnonce2=%d)",
                   xn1_size, xn2_size);
            goto out;
        }
    } else if (xn2_size < 2 || xn2_size > 16) {
        applog(LOG_ERR, "Failed to get valid n2size in parse_extranonce (%d)", xn2_size);
        goto out;
    } else if (xn1_size < 3 || xn1_size > 12) {
        applog(LOG_ERR, "Unsupported extranonce size of %d (12 maxi)", xn1_size);
        goto out;
    }

    if (!stratum_set_extranonce(sctx, xnonce1, xn2_size))
        goto out;

    if (opt_debug) {
        applog(LOG_DEBUG, "Stratum extranonce1: %s (size=%zu), extranonce2_size=%d",
               xnonce1, sctx->xnonce1_size, xn2_size);
    }

    return true;

out:
    return false;
}

static bool stratum_apply_subscribe_reply(struct stratum_ctx *sctx, json_t *reply)
{
    json_t *res_val = json_object_get(reply, "result");
    const char *sid;

    if (!stratum_parse_extranonce(sctx, res_val, 1))
        return false;

    sid = get_stratum_session_id(res_val);
    if (opt_debug && sid)
        applog(LOG_DEBUG, "Stratum session id: %s", sid);
    stratum_store_session_id(sctx, sid);

    return true;
}

bool stratum_subscribe(struct stratum_ctx *sctx)
{
    json_t *val = NULL;
    bool ret = false;
    int attempt;

    for (attempt = 0; attempt < 2 && !ret; attempt++) {
        char *request = stratum_build_subscribe_request(sctx, attempt > 0);
        enum stratum_wait_status wait_status;
        json_t *err_val = NULL;

        if (!request)
            goto out;

        wait_status = stratum_send_request_and_wait(sctx, request, STRATUM_REQUEST_SUBSCRIBE, 30,
                                                    50000, &val, true);
        free(request);
        if (wait_status == STRATUM_WAIT_SEND_ERROR)
            goto out;

        if (wait_status == STRATUM_WAIT_TIMEOUT) {
            applog(LOG_ERR, "stratum_subscribe timed out");
            goto out;
        }
        if (wait_status != STRATUM_WAIT_OK)
            goto out;

        if (stratum_reply_has_rpc_error(val, true, NULL, &err_val)) {
            if (opt_debug || attempt > 0)
                stratum_log_rpc_error(err_val);
            json_decref(val);
            val = NULL;
            continue;
        }
        if (!stratum_apply_subscribe_reply(sctx, val))
            goto out;

        ret = true;
    }

out:
    if (val)
        json_decref(val);

    return ret;
}

static bool stratum_apply_authorize_reply(struct stratum_ctx *sctx, json_t *reply, const char *user)
{
    json_t *err_val;

    if (stratum_reply_has_rpc_error(reply, false, NULL, &err_val)) {
        if (err_val && json_is_array(err_val)) {
            const char *reason = json_string_value(json_array_get(err_val, 1));
            applog(LOG_ERR, "Stratum authentication failed (%s)", reason);
        } else {
            applog(LOG_ERR, "Stratum authentication failed");
        }
        stratum_set_authenticated(sctx, false);
        return false;
    }

    applog(LOG_INFO, "Stratum authorization succeeded for %s", user);
    stratum_set_authenticated(sctx, true);
    return true;
}

static void stratum_try_extranonce_subscribe(struct stratum_ctx *sctx)
{
    json_t *extra = NULL;
    json_t *res_val;
    char *request = stratum_build_extranonce_subscribe_request();
    enum stratum_wait_status wait_status;

    if (!request)
        return;

    wait_status = stratum_send_request_and_wait(sctx, request, STRATUM_REQUEST_EXTRANONCE_SUBSCRIBE, 2,
                                                0, &extra, false);
    free(request);

    if (wait_status == STRATUM_WAIT_SEND_ERROR) {
        if (opt_debug)
            applog(LOG_DEBUG, "Failed to send extranonce subscribe, continuing...");
        return;
    }
    if (wait_status == STRATUM_WAIT_TIMEOUT) {
        if (opt_debug)
            applog(LOG_DEBUG, "stratum extranonce subscribe timed out, continuing...");
        return;
    }
    if (wait_status != STRATUM_WAIT_OK)
        return;

    res_val = json_object_get(extra, "result");
    if (opt_debug && (!res_val || json_is_false(res_val)))
        applog(LOG_DEBUG, "extranonce subscribe not supported");
    json_decref(extra);
}

bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
    json_t *val = NULL;
    char *request;
    bool ret = false;
    enum stratum_wait_status wait_status;

    request = stratum_build_authorize_request(user, pass);
    if (!request)
        goto out;

    wait_status = stratum_send_request_and_wait(sctx, request, STRATUM_REQUEST_AUTHORIZE, 0, 0, &val,
                                                true);
    free(request);

    if (wait_status == STRATUM_WAIT_SEND_ERROR)
        goto out;
    if (wait_status == STRATUM_WAIT_TIMEOUT)
        applog(LOG_ERR, "stratum_authorize timed out");
    if (wait_status != STRATUM_WAIT_OK)
        goto out;

    if (!stratum_apply_authorize_reply(sctx, val, user))
        goto out;
    ret = true;

    stratum_try_extranonce_subscribe(sctx);

out:
    if (val)
        json_decref(val);

    return ret;
}
