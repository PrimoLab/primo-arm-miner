#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stratum_internal.h"
#include "sha256_neon.h"
#include "byteorder.h"

struct standard_notify_view {
    const char *job_id;
    const char *prevhash;
    const char *coinb1;
    const char *coinb2;
    const char *version;
    const char *nbits;
    const char *stime;
    json_t *merkle_arr;
    bool clean;
};

struct standard_submit_view {
    char *xnonce2str;
    char ntimestr[9];
    char noncestr[9];
    uint32_t nonce;
};

struct standard_job_update {
    const struct standard_notify_view *msg;
    char *job_id;
    unsigned char **merkle;
    int merkle_count;
    unsigned char *new_coinbase;  /* pre-allocated outside lock; ownership transfers into _locked */
};

static void build_standard_work(const struct stratum_ctx *sctx, struct work *new_work);

/**
 * Extract block height     L H... here len=3, height=0x1333e8
 * "...0000000000ffffffff2703e83313062f503253482f043d61105408"
 */
static uint32_t get_block_height(const uint8_t *coinbase, size_t coinbase_size)
{
    uint32_t height = 0;
    uint8_t hlen = 0;
    const uint8_t *p;
    const uint8_t *scan_end;
    size_t scan_len;

    if (!coinbase || coinbase_size <= 32)
        return 0;

    p = coinbase + 32;
    scan_len = coinbase_size - 32;
    if (scan_len > 128)
        scan_len = 128;
    scan_end = p + scan_len;

    while (p < scan_end && *p != 0xff)
        p++;
    while (p < scan_end && *p == 0xff)
        p++;

    if (p < coinbase + 34 || p >= scan_end)
        return 0;

    if (*(p - 1) == 0xff && *(p - 2) == 0xff) {
        if ((size_t)(scan_end - p) < 4)
            return 0;

        p++;
        hlen = *p;
        p++;
        height = le16dec(p);
        p += 2;
        switch (hlen) {
        case 4:
            if ((size_t)(scan_end - p) < 2)
                return 0;
            height += 0x10000UL * le16dec(p);
            break;
        case 3:
            if (p >= scan_end)
                return 0;
            height += 0x10000UL * (*p);
            break;
        }
    }
    return height;
}

static bool apply_standard_job_locked(struct stratum_ctx *sctx, void *opaque)
{
    struct standard_job_update *update = (struct standard_job_update *)opaque;
    const struct standard_notify_view *msg = update->msg;
    size_t coinb1_size = strlen(msg->coinb1) / 2;
    size_t coinb2_size = strlen(msg->coinb2) / 2;
    size_t coinbase_size = coinb1_size + sctx->xnonce1_size + sctx->xnonce2_size + coinb2_size;
    unsigned char *new_coinbase = NULL;
    unsigned char *new_xnonce2;
    unsigned char prevhash[32];
    unsigned char version[4];
    unsigned char nbits[4];
    unsigned char ntime[4];
    uint32_t height;
    bool job_changed = !sctx->job.job_id || strcmp(sctx->job.job_id, msg->job_id) != 0;

    new_coinbase = update->new_coinbase;
    update->new_coinbase = NULL;
    if (!new_coinbase) {
        applog(LOG_ERR, "Failed to allocate coinbase buffer");
        return false;
    }

    if (!stratum_decode_hex_field(new_coinbase, msg->coinb1, coinb1_size, "Stratum notify", "coinb1"))
        goto out;
    memcpy(new_coinbase + coinb1_size, sctx->xnonce1, sctx->xnonce1_size);
    new_xnonce2 = new_coinbase + coinb1_size + sctx->xnonce1_size;
    if (job_changed || !sctx->job.xnonce2)
        memset(new_xnonce2, 0, sctx->xnonce2_size);
    else
        memcpy(new_xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);
    if (!stratum_decode_hex_field(new_xnonce2 + sctx->xnonce2_size, msg->coinb2,
                                  coinb2_size, "Stratum notify", "coinb2")) {
        goto out;
    }
    if (!stratum_decode_hex_field(prevhash, msg->prevhash, sizeof(prevhash), "Stratum notify", "prevhash"))
        goto out;
    if (!stratum_decode_hex_field(version, msg->version, sizeof(version), "Stratum notify", "version"))
        goto out;
    if (!stratum_decode_hex_field(nbits, msg->nbits, sizeof(nbits), "Stratum notify", "nbits"))
        goto out;
    if (!stratum_decode_hex_field(ntime, msg->stime, sizeof(ntime), "Stratum notify", "ntime"))
        goto out;
    height = get_block_height(new_coinbase, coinbase_size);

    free(sctx->job.job_id);
    sctx->job.job_id = update->job_id;
    update->job_id = NULL;
    free(sctx->job.coinbase);
    sctx->job.coinbase = new_coinbase;
    sctx->job.coinbase_size = coinbase_size;
    sctx->job.xnonce2 = new_xnonce2;
    new_coinbase = NULL;
    memcpy(sctx->job.prevhash, prevhash, sizeof(prevhash));

    if (opt_debug)
        applog(LOG_DEBUG, "Pool prevhash: %s", msg->prevhash);

    sctx->job.height = height;

    stratum_job_clear_merkle(&sctx->job);
    sctx->job.merkle = update->merkle;
    sctx->job.merkle_count = update->merkle_count;
    update->merkle = NULL;
    update->merkle_count = 0;

    memcpy(sctx->job.version, version, sizeof(version));
    memcpy(sctx->job.nbits, nbits, sizeof(nbits));
    memcpy(sctx->job.ntime, ntime, sizeof(ntime));
    stratum_capture_next_diff_locked(sctx);

    return true;

out:
    free(new_coinbase);
    return false;
}

static bool parse_standard_notify(json_t *params, struct standard_notify_view *msg)
{
    int p = 0;

    memset(msg, 0, sizeof(*msg));

    msg->job_id = json_string_value(json_array_get(params, p++));
    msg->prevhash = json_string_value(json_array_get(params, p++));
    msg->coinb1 = json_string_value(json_array_get(params, p++));
    msg->coinb2 = json_string_value(json_array_get(params, p++));
    msg->merkle_arr = json_array_get(params, p++);
    msg->version = json_string_value(json_array_get(params, p++));
    msg->nbits = json_string_value(json_array_get(params, p++));
    msg->stime = json_string_value(json_array_get(params, p++));
    msg->clean = json_is_true(json_array_get(params, p));

    if (!msg->merkle_arr || !json_is_array(msg->merkle_arr))
        return false;
    if (!msg->job_id || !msg->prevhash || !msg->coinb1 || !msg->coinb2 ||
        !msg->version || !msg->nbits || !msg->stime)
        return false;
    if ((strlen(msg->coinb1) & 1u) != 0 || (strlen(msg->coinb2) & 1u) != 0)
        return false;
    if (strlen(msg->prevhash) != 64 || strlen(msg->version) != 8 ||
        strlen(msg->nbits) != 8 || strlen(msg->stime) != 8)
        return false;

    return true;
}

static bool apply_standard_notify(struct stratum_ctx *sctx, const struct standard_notify_view *msg)
{
    bool ret = false;
    int merkle_count = 0;
    unsigned char **merkle = NULL;
    char *new_job_id = NULL;
    struct standard_job_update update = {0};
    /* Pre-allocate coinbase outside the lock. Use coinb1+coinb2 sizes plus 32 bytes of
     * headroom for the extranonce fields (xnonce1_size + xnonce2_size <= 32). The exact
     * coinbase_size is computed inside the lock using the live xnonce sizes. */
    size_t coinbase_prealloc = strlen(msg->coinb1) / 2 + 32 + strlen(msg->coinb2) / 2;
    unsigned char *new_coinbase = (unsigned char *)malloc(coinbase_prealloc);

    if (!new_coinbase) {
        applog(LOG_ERR, "Stratum notify: failed to allocate coinbase buffer");
        goto out;
    }

    if (!stratum_update_time_offset(sctx, msg->stime, true))
        goto out;
    if (!stratum_decode_merkle_array(msg->merkle_arr, &merkle, &merkle_count))
        goto out;

    if (!stratum_check_job_id_length(msg->job_id, "Stratum notify"))
        goto out;

    new_job_id = strdup(msg->job_id);
    if (!new_job_id) {
        applog(LOG_ERR, "Stratum notify: failed to duplicate job id");
        goto out;
    }

    update.msg = msg;
    update.job_id = new_job_id;
    update.merkle = merkle;
    update.merkle_count = merkle_count;
    update.new_coinbase = new_coinbase;
    new_coinbase = NULL;

    if (!stratum_commit_job_update(sctx, apply_standard_job_locked, build_standard_work, &update,
                                   msg->clean)) {
        goto out;
    }
    new_job_id = update.job_id;
    merkle = update.merkle;
    merkle_count = update.merkle_count;
    ret = true;

out:
    free(new_coinbase);
    free(update.new_coinbase);
    free(new_job_id);
    stratum_free_merkle(merkle, merkle_count);
    return ret;
}

bool stratum_notify_standard(struct stratum_ctx *sctx, json_t *params)
{
    struct standard_notify_view msg;

    if (!parse_standard_notify(params, &msg)) {
        applog(LOG_ERR, "Stratum notify: invalid parameters");
        return false;
    }

    return apply_standard_notify(sctx, &msg);
}

static void free_standard_submit_view(struct standard_submit_view *msg)
{
    free(msg->xnonce2str);
    msg->xnonce2str = NULL;
}

static bool build_standard_submit_view(struct work *work, struct standard_submit_view *msg)
{
    memset(msg, 0, sizeof(*msg));

    msg->nonce = work->nonces[work->submit_nonce_id];

    msg->xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);
    if (!msg->xnonce2str) {
        applog(LOG_ERR, "Failed to allocate xnonce2 string");
        return false;
    }

    cbin2hex(msg->ntimestr, (char *)&work->data[17], 4);
    cbin2hex(msg->noncestr, (char *)&work->data[19], 4);
    msg->ntimestr[8] = '\0';
    msg->noncestr[8] = '\0';

    return true;
}

static void log_standard_submit_debug(const struct work *work, const struct standard_submit_view *msg)
{
    char *header_hex = bin2hex((const unsigned char *)work->data, 80);

    applog(LOG_DEBUG, "=== SUBMIT DEBUG ===");
    applog(LOG_DEBUG, "Job ID: %s, Extranonce2: %s, nTime: %s, Nonce: %s (raw: %08x)",
        work->job_id, msg->xnonce2str, msg->ntimestr, msg->noncestr, msg->nonce);
    applog(LOG_DEBUG, "Block header: %s", header_hex);

    free(header_hex);
}

static void build_merkle_root(unsigned char *merkle_root, const struct stratum_ctx *sctx)
{
    unsigned char hash[32];

    sha256d_neon(sctx->job.coinbase, sctx->job.coinbase_size, hash);

    if (opt_debug) {
        char *cb_hex = bin2hex(sctx->job.coinbase, sctx->job.coinbase_size);
        char *cb_hash_hex = bin2hex(hash, 32);
        applog(LOG_DEBUG, "=== MERKLE DEBUG ===");
        applog(LOG_DEBUG, "Coinbase (%zu bytes): %s", sctx->job.coinbase_size, cb_hex);
        applog(LOG_DEBUG, "Coinbase hash: %s", cb_hash_hex);
        applog(LOG_DEBUG, "Merkle branches: %d", sctx->job.merkle_count);
        free(cb_hex);
        free(cb_hash_hex);
    }

    for (int i = 0; i < sctx->job.merkle_count; i++) {
        unsigned char concat[64];
        memcpy(concat, hash, 32);
        memcpy(concat + 32, sctx->job.merkle[i], 32);

        if (opt_debug) {
            char *branch_hex = bin2hex(sctx->job.merkle[i], 32);
            applog(LOG_DEBUG, "Branch[%d]: %s", i, branch_hex);
            free(branch_hex);
        }

        sha256d_neon(concat, 64, hash);
    }

    memcpy(merkle_root, hash, 32);

    if (opt_debug) {
        char *final_hex = bin2hex(merkle_root, 32);
        applog(LOG_DEBUG, "Final merkle: %s", final_hex);
        free(final_hex);
    }
}

static void build_standard_work(const struct stratum_ctx *sctx, struct work *new_work)
{
    miner_work_reset(new_work);

    if (sctx->job.job_id)
        snprintf(new_work->job_id, sizeof(new_work->job_id), "%s", sctx->job.job_id);
    new_work->height = sctx->job.height;
    new_work->pooln = sctx->pooln;

    unsigned char merkle_root[32];
    build_merkle_root(merkle_root, sctx);

    if (opt_debug) {
        char *merkle_hex = bin2hex(merkle_root, 32);
        char *xnonce2_hex = bin2hex(sctx->job.xnonce2, sctx->xnonce2_size);
        applog(LOG_DEBUG, "Extranonce2: %s", xnonce2_hex);
        applog(LOG_DEBUG, "Merkle root: %s", merkle_hex);
        free(merkle_hex);
        free(xnonce2_hex);
    }

    new_work->data[0] = le32dec(sctx->job.version);
    for (int i = 0; i < 8; i++)
        new_work->data[1 + i] = le32dec(sctx->job.prevhash + i * 4);
    for (int i = 0; i < 8; i++)
        new_work->data[9 + i] = le32dec(merkle_root + i * 4);
    new_work->data[17] = le32dec(sctx->job.ntime);
    new_work->data[18] = le32dec(sctx->job.nbits);
    new_work->data[19] = 0;

    memcpy(new_work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);
    new_work->xnonce2_len = sctx->xnonce2_size;

    double target_diff = (opt_algo == ALGO_SCRYPT) ? (sctx->job.diff / 65536.0) : sctx->job.diff;
    diff_to_target(new_work->target, target_diff);
    new_work->targetdiff = sctx->job.diff;

    if (opt_debug) {
        char *header_hex = bin2hex((const unsigned char *)new_work->data, 80);
        applog(LOG_DEBUG, "Block header (80 bytes): %s", header_hex);
        free(header_hex);
    }
}

bool stratum_submit_standard(struct pool_infos *pool, struct work *work)
{
    char *request = NULL;
    struct standard_submit_view msg;
    struct stratum_ctx *sctx = &pool->stratum;
    uint32_t submit_id;
    bool ret;

    work->data[19] = work->nonces[work->submit_nonce_id];

    if (!build_standard_submit_view(work, &msg))
        return false;

    if (opt_debug)
        log_standard_submit_debug(work, &msg);

    submit_id = stratum_submit_id_next(sctx);
    request = stratum_build_submit_request_line(submit_id, pool->user, work->job_id,
                                                msg.xnonce2str, msg.ntimestr, msg.noncestr);
    if (!request) {
        applog(LOG_ERR, "Failed to build standard submit request");
        free_standard_submit_view(&msg);
        return false;
    }

    ret = stratum_send_submit(sctx, request, submit_id, work->sharediff[work->submit_nonce_id],
                              work->thread_id, __func__);
    free(request);
    free_standard_submit_view(&msg);
    return ret;
}
