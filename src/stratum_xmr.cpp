/*
 * Monero/RandomX stratum dialect for Primo ARM Miner.
 * Copyright (C) 2026 primo-arm-miner contributors.
 *
 * Monero pools do not speak bitcoin-style stratum: there is a single "login"
 * call (handled in stratum_handshake.cpp) whose reply carries the first job,
 * new work arrives as "job" notifications with the params being the job
 * object itself, and shares are submitted as {id, job_id, nonce, result}
 * where result is the full 32-byte RandomX hash. The nonce lives at byte
 * offset 39 of the hashing blob. See docs/RANDOMX_M2_PLAN.md.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"
#include "stratum_internal.h"

#ifdef PRIMO_RANDOMX

#include "randomx_algo.h"

/* Like stratum_build_request_line but with the "jsonrpc":"2.0" member the
 * Monero pool dialect expects. Steals the params reference. */
char *xmr_build_request_line(const char *method, uint32_t id, json_t *params)
{
    json_t *req = json_object();
    char *line = NULL;

    if (!req) {
        if (params)
            json_decref(params);
        return NULL;
    }
    json_object_set_new(req, "id", json_integer(id));
    json_object_set_new(req, "jsonrpc", json_string("2.0"));
    json_object_set_new(req, "method", json_string(method));
    json_object_set_new(req, "params", params ? params : json_object());
    line = json_dumps(req, 0);
    json_decref(req);
    return line;
}

struct xmr_job_view {
    char *job_id;
    uint8_t blob[RANDOMX_BLOB_MAX];
    size_t blob_len;
    uint64_t target64;
    double diff;
    uint8_t seed[32];
    bool have_seed;
    uint32_t height;
};

/*
 * Pool "target" is compact hex: 8 chars = 4 LE bytes (the high 32 bits of
 * the 256-bit boundary), or 16 chars = 8 LE bytes. Expand to a 64-bit
 * boundary on the hash's top 8 bytes (the xmrig-compatible convention).
 */
static bool xmr_parse_target(const char *tstr, uint64_t *t64_out, double *diff_out)
{
    size_t len = tstr ? strlen(tstr) : 0;
    uint8_t raw[8];

    if (len == 8) {
        uint32_t t32;
        if (!hex2bin(raw, tstr, 4))
            return false;
        t32 = (uint32_t)raw[0] | ((uint32_t)raw[1] << 8) |
              ((uint32_t)raw[2] << 16) | ((uint32_t)raw[3] << 24);
        if (t32 == 0)
            return false;
        *t64_out = 0xFFFFFFFFFFFFFFFFULL / (0xFFFFFFFFULL / t32);
    } else if (len == 16) {
        if (!hex2bin(raw, tstr, 8))
            return false;
        uint64_t t = 0;
        for (int i = 7; i >= 0; i--)
            t = (t << 8) | raw[i];
        if (t == 0)
            return false;
        *t64_out = t;
    } else {
        return false;
    }

    *diff_out = 18446744073709551616.0 / (double)*t64_out;
    return true;
}

static bool xmr_parse_job_view(json_t *job, struct xmr_job_view *v)
{
    memset(v, 0, sizeof(*v));

    const char *job_id = json_string_value(json_object_get(job, "job_id"));
    const char *blob = json_string_value(json_object_get(job, "blob"));
    const char *target = json_string_value(json_object_get(job, "target"));
    const char *seed = json_string_value(json_object_get(job, "seed_hash"));
    json_t *height_val = json_object_get(job, "height");

    if (!job_id || !job_id[0] || !blob || !target) {
        applog(LOG_ERR, "RandomX job: missing job_id/blob/target");
        return false;
    }
    if (!stratum_check_job_id_length(job_id, "RandomX job"))
        return false;

    size_t blob_hex_len = strlen(blob);
    if ((blob_hex_len & 1) != 0 || blob_hex_len / 2 > sizeof(v->blob) ||
        blob_hex_len / 2 > RANDOMX_BLOB_MAX || blob_hex_len / 2 < 43) {
        applog(LOG_ERR, "RandomX job: bad blob length %zu", blob_hex_len / 2);
        return false;
    }
    v->blob_len = blob_hex_len / 2;
    if (!stratum_decode_hex_field(v->blob, blob, v->blob_len, "RandomX job", "blob"))
        return false;

    if (!xmr_parse_target(target, &v->target64, &v->diff)) {
        applog(LOG_ERR, "RandomX job: bad target '%s'", target);
        return false;
    }

    /* rx/0 REQUIRES a valid seed per job: silently accepting a job without
     * one meant hashing against the benchmark key (first job) or a stale
     * previous seed — 100% bad shares with no error. A malformed length was
     * equally silent. Ecosystem behavior (xmrig) also treats a seedless
     * RandomX job as invalid, and a global "seed already seen" carve-out
     * would be wrong across pool switches to a different rx/0 chain. */
    if (!seed || strlen(seed) != 64) {
        applog(LOG_ERR, "RandomX job: missing or malformed seed_hash — rejecting job");
        return false;
    }
    if (!stratum_decode_hex_field(v->seed, seed, 32, "RandomX job", "seed_hash"))
        return false;
    v->have_seed = true;

    if (json_is_integer(height_val))
        v->height = (uint32_t)json_integer_value(height_val);

    v->job_id = strdup(job_id);
    return v->job_id != NULL;
}

static bool xmr_apply_job_locked(struct stratum_ctx *sctx, void *opaque)
{
    struct xmr_job_view *v = (struct xmr_job_view *)opaque;

    free(sctx->job.job_id);
    sctx->job.job_id = v->job_id;
    v->job_id = NULL;  /* ownership moved into the job */

    memcpy(sctx->job.rx_blob, v->blob, v->blob_len);
    sctx->job.rx_blob_len = (uint16_t)v->blob_len;
    sctx->job.rx_target64 = v->target64;
    sctx->job.diff = v->diff;
    sctx->job.height = v->height;
    return true;
}

static void build_xmr_work(const struct stratum_ctx *sctx, struct work *new_work)
{
    memset(new_work->data, 0, sizeof(new_work->data));
    memcpy(new_work->data, sctx->job.rx_blob, sctx->job.rx_blob_len);
    new_work->rx_blob_len = sctx->job.rx_blob_len;

    /* Boundary on the hash's top 8 bytes; lower words saturated so the full
     * 256-bit LE compare in scanhash_randomx reduces to top64 <= target64. */
    for (int i = 0; i < 6; i++)
        new_work->target[i] = 0xFFFFFFFFu;
    new_work->target[6] = (uint32_t)sctx->job.rx_target64;
    new_work->target[7] = (uint32_t)(sctx->job.rx_target64 >> 32);

    snprintf(new_work->job_id, sizeof(new_work->job_id), "%s",
             sctx->job.job_id ? sctx->job.job_id : "");
    new_work->targetdiff = sctx->job.diff;
    new_work->height = sctx->job.height;
    /* Like the standard/Verus builders, stamp which pool this work belongs
     * to: submit_ready_share() routes the share through pools[work->pooln].
     * Without this every RandomX share went through pool 0's stratum context
     * — silently dropped as unauthenticated whenever the active pool was a
     * failover pool or (once enabled) the hidden dev fee slot. */
    new_work->pooln = (uint8_t)sctx->pooln;
    new_work->xnonce2_len = 0;
}

bool xmr_stratum_handle_job(struct stratum_ctx *sctx, json_t *params)
{
    struct xmr_job_view v;

    if (!xmr_parse_job_view(params, &v))
        return false;

    /* Re-key BEFORE taking the work lock: a seed change rebuilds the 2 GiB
     * dataset (~14 s, rare — every ~2.8 days). randomx_set_seed is a no-op
     * for an unchanged seed; on a real change it quiesces mining threads
     * itself (work-generation bump + they block on the rx lock). */
    if (v.have_seed)
        randomx_set_seed(v.seed, 32);

    bool ok = stratum_commit_job_update(sctx, xmr_apply_job_locked, build_xmr_work,
                                        &v, true);
    if (ok)
        applog(LOG_INFO, "New RandomX job %s, diff %.0f%s%u",
               sctx->job.job_id ? sctx->job.job_id : "?", sctx->job.diff,
               v.height ? ", height " : "", v.height);

    free(v.job_id);  /* NULL if ownership moved */
    return ok;
}

bool xmr_stratum_submit(struct pool_infos *pool, struct work *work)
{
    struct stratum_ctx *sctx = &pool->stratum;
    int nonce_id = work->submit_nonce_id;
    uint32_t nonce = work->nonces[nonce_id];
    uint8_t nonce_bytes[4];
    char nonce_hex[9];
    char result_hex[65];
    json_t *params;
    char *line;
    uint32_t submit_id;
    bool ok;

    /* Nonce hex mirrors the LE bytes exactly as they sit in the blob. */
    nonce_bytes[0] = (uint8_t)nonce;
    nonce_bytes[1] = (uint8_t)(nonce >> 8);
    nonce_bytes[2] = (uint8_t)(nonce >> 16);
    nonce_bytes[3] = (uint8_t)(nonce >> 24);
    cbin2hex(nonce_hex, (const char *)nonce_bytes, 4);
    cbin2hex(result_hex, (const char *)work->rx_hash[nonce_id], 32);

    params = json_object();
    if (!params)
        return false;
    json_object_set_new(params, "id",
                        json_string(sctx->session_id ? sctx->session_id : ""));
    json_object_set_new(params, "job_id", json_string(work->job_id));
    json_object_set_new(params, "nonce", json_string(nonce_hex));
    json_object_set_new(params, "result", json_string(result_hex));

    submit_id = stratum_submit_id_next(sctx);
    line = xmr_build_request_line("submit", submit_id, params);
    if (!line)
        return false;

    ok = stratum_send_submit(sctx, line, submit_id, work->sharediff[nonce_id],
                             work->thread_id, "randomx");
    free(line);
    return ok;
}

/* Idle ping (Monero "keepalived") so quiet pools don't drop us between jobs.
 * Request id 5 sits in the reserved <10 range, so the {"status":"KEEPALIVED"}
 * reply is ignored by the response dispatch instead of being miscounted as a
 * share result. */
bool xmr_stratum_keepalive(struct stratum_ctx *sctx)
{
    json_t *params = json_object();
    char *line;
    bool ok;

    if (!params)
        return false;
    json_object_set_new(params, "id",
                        json_string(sctx->session_id ? sctx->session_id : ""));
    line = xmr_build_request_line("keepalived", 5, params);
    if (!line)
        return false;
    ok = stratum_send_line(sctx, line);
    free(line);
    if (opt_debug && ok)
        applog(LOG_DEBUG, "randomx: sent keepalived (idle pool)");
    return ok;
}

#endif /* PRIMO_RANDOMX */
