#ifndef STRATUM_INTERNAL_H
#define STRATUM_INTERNAL_H

#include <stddef.h>

#include "miner.h"

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#endif

extern pthread_mutex_t stratum_work_lock;
extern pthread_mutex_t stratum_sock_lock;

static inline uint32_t stratum_bswap32(uint32_t v)
{
    return __builtin_bswap32(v);
}

struct stratum_protocol_ops {
    bool (*handle_notify)(struct stratum_ctx *sctx, json_t *params);
    bool (*handle_set_target)(struct stratum_ctx *sctx, json_t *params);
    bool (*submit_share)(struct pool_infos *pool, struct work *work);
    /* Optional: ping the pool when the message loop has received nothing for
     * STRATUM_IDLE_KEEPALIVE_SEC. NULL = protocol needs no keepalive. */
    bool (*idle_keepalive)(struct stratum_ctx *sctx);
};

/* Idle interval before idle_keepalive fires. Monero pools drop connections
 * quiet for a few minutes; jobs normally arrive well inside this bound. */
#define STRATUM_IDLE_KEEPALIVE_SEC 60

struct stratum_runtime_stats {
    uint64_t work_updates_total;
    uint64_t work_updates_clean;
    uint64_t work_restart_total;
    uint64_t work_restart_clean;
    uint64_t work_restart_height;
    uint64_t work_restart_target;
    uint32_t share_accepted_total;
    uint32_t share_rejected_total;
};

struct stratum_api_work_snapshot {
    char job_id[128];
    size_t xnonce2_len;
    uint8_t xnonce2[32];
    double targetdiff;
    uint32_t height;
};

struct stratum_api_pool_snapshot {
    bool work_ready;
    struct stratum_api_work_snapshot current_work;
    struct stratum_runtime_stats runtime_stats; /* global totals across all pools */
    uint32_t accepted_count;  /* per-pool accepted count for this pool index */
    uint32_t rejected_count;  /* per-pool rejected count for this pool index */
    time_t last_share_time;
    double best_share;
};

typedef bool (*stratum_job_apply_fn)(struct stratum_ctx *sctx, void *opaque);
typedef void (*stratum_work_build_fn)(const struct stratum_ctx *sctx, struct work *new_work);

bool stratum_notify_standard(struct stratum_ctx *sctx, json_t *params);
#ifdef PRIMO_RANDOMX
/* Monero/RandomX dialect (stratum_xmr.cpp + login in stratum_handshake.cpp) */
bool xmr_stratum_handle_job(struct stratum_ctx *sctx, json_t *params);
bool xmr_stratum_submit(struct pool_infos *pool, struct work *work);
char *xmr_build_request_line(const char *method, uint32_t id, json_t *params);
bool xmr_stratum_login(struct stratum_ctx *sctx, const char *user, const char *pass);
bool xmr_stratum_keepalive(struct stratum_ctx *sctx);
#endif
bool verus_stratum_notify(struct stratum_ctx *sctx, json_t *params);
bool verus_stratum_set_target(struct stratum_ctx *sctx, json_t *params);
bool verus_stratum_submit(struct pool_infos *pool, struct work *work);
const struct stratum_protocol_ops *stratum_get_protocol_ops(const struct stratum_ctx *sctx);
bool stratum_handle_json_message(struct stratum_ctx *sctx, json_t *val);
bool stratum_parse_rpc_id(json_t *id_val, uint32_t *id_out);
char *stratum_build_request_line(const char *method, uint32_t id, json_t *params);
char *stratum_build_submit_request_line(uint32_t submit_id, const char *user, const char *job_id,
    const char *param2, const char *param3, const char *param4);
bool stratum_json_array_append_string(json_t *array, const char *value);
bool stratum_decode_hex_field(void *output, const char *hexstr, size_t len, const char *context,
    const char *field_name);
bool stratum_check_job_id_length(const char *job_id, const char *context);
bool stratum_update_time_offset(struct stratum_ctx *sctx, const char *stime, bool swap32);
void stratum_free_merkle(unsigned char **merkle, int merkle_count);
void stratum_job_clear_merkle(struct stratum_job *job);
void stratum_free_job(struct stratum_ctx *sctx);
void stratum_capture_next_diff_locked(struct stratum_ctx *sctx);
bool stratum_decode_merkle_array(json_t *merkle_arr, unsigned char ***merkle_out, int *merkle_count_out);
bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx);
bool stratum_set_extranonce(struct stratum_ctx *sctx, const char *xnonce1, int xn2_size);
bool stratum_set_url(struct stratum_ctx *sctx, const char *url);
void stratum_store_session_id(struct stratum_ctx *sctx, const char *session_id);
void stratum_store_next_diff(struct stratum_ctx *sctx, double diff);
void stratum_set_authenticated(struct stratum_ctx *sctx, bool authenticated);
bool stratum_is_authenticated(const struct stratum_ctx *sctx);
void stratum_close_transport(struct stratum_ctx *sctx);
void stratum_request_shutdown(struct stratum_ctx *sctx);
void stratum_reset_session_runtime(struct stratum_ctx *sctx);
bool stratum_socket_full(curl_socket_t sock, int timeout);
char *stratum_recv_line_timeout(struct stratum_ctx *sctx, int timeout, bool *timed_out, bool log_timeout);
bool stratum_copy_work(struct work *work_out);
bool stratum_has_published_work(void);
void stratum_reset_work_state(void);
void stratum_reset_runtime_state(void);
void stratum_get_runtime_stats(struct stratum_runtime_stats *stats_out);
void stratum_record_share_submit(int pooln, double sharediff);
void stratum_get_api_pool_snapshot(int pooln, struct stratum_api_pool_snapshot *snapshot);
bool stratum_update_active_work_height_locked(int pooln, const char *job_id, uint32_t height);
bool stratum_start_service(struct pool_infos *pool);
bool stratum_wait_ready(int timeout_seconds, bool *work_ready_out);
void stratum_stop_service(struct stratum_ctx *sctx);
void stratum_join_service_thread(void);
bool stratum_open_pool_connection(struct pool_infos *pool);
void stratum_run_message_loop(struct stratum_ctx *sctx);
void stratum_init_context(struct stratum_ctx *sctx, int pooln, bool is_verus_protocol);
void stratum_destroy_context(struct stratum_ctx *sctx);

uint32_t stratum_submit_id_next(struct stratum_ctx *sctx);
bool stratum_send_submit(struct stratum_ctx *sctx, const char *line, uint32_t submit_id, double sharediff,
    int thread_id, const char *label);
void stratum_publish_work(const struct work *new_work, bool clean);
bool stratum_commit_job_update(struct stratum_ctx *sctx, stratum_job_apply_fn apply_job_locked,
    stratum_work_build_fn build_work_locked, void *opaque, bool clean);
void stratum_update_share_stats(int pooln, bool accepted, uint32_t *accepted_out, uint32_t *rejected_out);

bool stratum_submit_standard(struct pool_infos *pool, struct work *work);
void diff_to_target_verus(uint32_t *target, double diff);

#endif
