#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stratum_internal.h"

#define EQNONCE_OFFSET 30
#define VERUS_NONCE_FIELD_BYTES 32
#define VERUS_SUBMIT_SOLUTION_SIZE 1347
#define VERUS_RESTORED_SOLUTION_OFFSET 8
#define VERUS_RESTORED_SOLUTION_BYTES 64

struct verus_notify_view {
    const char *job_id;
    const char *version;
    const char *prevhash;
    const char *coinb1;
    const char *coinb2;
    const char *stime;
    const char *nbits;
    const char *solution;
    bool clean;
};

struct verus_submit_view {
    char *noncestr;
    char *solhex;
    char timehex[16];
};

struct verus_job_update {
    const struct verus_notify_view *msg;
    char *job_id;
    const uint8_t *decoded_solution;
    bool await_height_message;
    unsigned char *new_coinbase;  /* pre-allocated outside lock; ownership transfers into _locked */
};

static void build_verus_work(const struct stratum_ctx *sctx, struct work *new_work);

static bool decode_verus_solution_field(uint8_t *output, size_t output_size, const char *hexstr)
{
    size_t hex_len;
    size_t solution_size;

    if (!output || !hexstr)
        return false;

    hex_len = strlen(hexstr);
    if ((hex_len & 1u) != 0) {
        applog(LOG_ERR, "Stratum notify: invalid solution length");
        return false;
    }

    solution_size = hex_len / 2;
    if (solution_size > output_size) {
        applog(LOG_ERR, "Stratum notify: solution too large (%zu bytes)", solution_size);
        return false;
    }

    memset(output, 0, output_size);
    if (solution_size == 0)
        return true;

    if (!hex2bin(output, hexstr, solution_size)) {
        applog(LOG_ERR, "Stratum notify: invalid solution");
        return false;
    }

    return true;
}

static bool verus_validate_nonce_layout(const struct stratum_ctx *sctx)
{
    if (sctx->xnonce1_size > VERUS_NONCE_FIELD_BYTES) {
        applog(LOG_ERR, "Verus extranonce1 exceeds the %d-byte nonce field (%zu)",
               VERUS_NONCE_FIELD_BYTES, sctx->xnonce1_size);
        return false;
    }
    if (sctx->xnonce1_size + sctx->xnonce2_size != VERUS_NONCE_FIELD_BYTES) {
        applog(LOG_ERR, "Verus nonce layout is invalid (xnonce1=%zu, xnonce2=%zu, total=%zu)",
               sctx->xnonce1_size, sctx->xnonce2_size,
               sctx->xnonce1_size + sctx->xnonce2_size);
        return false;
    }
    return true;
}

static double target_to_diff_equi(uint32_t *target)
{
    unsigned char *tgt = (unsigned char *)target;
    uint64_t m =
        (uint64_t)tgt[30] << 24 |
        (uint64_t)tgt[29] << 16 |
        (uint64_t)tgt[28] << 8 |
        (uint64_t)tgt[27] << 0;

    if (!m)
        return 0.;
    else
        return (double)0xffff0000UL / m;
}

static void verus_store_target_payload(uint8_t *target_bytes, int word_index, uint64_t value)
{
    size_t offset = (size_t)word_index * sizeof(uint32_t);

    if (offset >= 32)
        return;

    for (size_t byte_index = 0; byte_index < sizeof(value) && offset + byte_index < 32; byte_index++) {
        target_bytes[offset + byte_index] = (uint8_t)(value >> (byte_index * 8));
    }
}

void diff_to_target_verus(uint32_t *target, double diff)
{
    uint8_t *target_bytes = (uint8_t *)target;
    uint64_t m;
    int k;

    if (!target)
        return;

    if (diff <= 0.0) {
        memset(target, 0xff, 32);
        return;
    }

    for (k = 6; k > 0 && diff > 1.0; k--)
        diff /= 4294967296.0;
    /* Clamp in double space before the uint64_t cast — an out-of-range
     * double-to-unsigned cast is UB (see diff_to_target in stratum.cpp). */
    double m_value = 4294901760.0 / diff;
    if (m_value >= 18446744073709551616.0 /* 2^64 */)
        m = UINT64_MAX;
    else
        m = (uint64_t)m_value;
    if (m == 0 && k == 6)
        memset(target, 0xff, 32);
    else {
        memset(target, 0, 32);
        verus_store_target_payload(target_bytes, k + 1, m >> 8);
        for (k = 0; k < 28 && target_bytes[k] == 0; k++)
            target_bytes[k] = 0xff;
    }
}

bool verus_stratum_set_target(struct stratum_ctx *sctx, json_t *params)
{
    uint8_t target_bin[32];
    uint8_t target_be[32];
    double diff;

    const char *target_hex = json_string_value(json_array_get(params, 0));
    if (!target_hex || strlen(target_hex) == 0)
        return false;

    if (!hex2bin(target_bin, target_hex, 32))
        return false;
    /* Verus pool targets fit in 3 significant bytes at current difficulty
     * ranges. Copy pool target bytes MSB-first until 3 non-zero bytes are
     * collected; remaining bytes stay 0xff (minimum difficulty contribution
     * from those positions). If difficulty ever grows to require a 4th
     * significant byte this loop must be extended. */
    memset(target_be, 0xff, 32);
    int filled = 0;
    for (int i = 0; i < 32; i++) {
        if (filled == 3)
            break;
        target_be[31 - i] = target_bin[i];
        if (target_bin[i])
            filled++;
    }

    diff = target_to_diff_equi((uint32_t *)&target_be);
    if (diff <= 0.0)
        return false;

    stratum_store_next_diff(sctx, diff);
    return true;
}

static bool apply_verus_job_locked(struct stratum_ctx *sctx, void *opaque)
{
    struct verus_job_update *update = (struct verus_job_update *)opaque;
    const struct verus_notify_view *msg = update->msg;
    size_t coinb1_size = strlen(msg->coinb1) / 2;
    size_t coinb2_size = strlen(msg->coinb2) / 2;
    size_t coinbase_size = coinb1_size + coinb2_size + sctx->xnonce1_size + sctx->xnonce2_size;
    unsigned char *new_coinbase = NULL;
    unsigned char version[4];
    unsigned char prevhash[32];
    unsigned char nbits[4];
    unsigned char ntime[4];
    uint32_t preserved_height = sctx->job.height;

    if (!verus_validate_nonce_layout(sctx))
        return false;
    if (!stratum_decode_hex_field(version, msg->version, sizeof(version), "Stratum notify", "version"))
        return false;
    if (!stratum_decode_hex_field(prevhash, msg->prevhash, sizeof(prevhash), "Stratum notify", "prevhash"))
        return false;
    if (!stratum_decode_hex_field(nbits, msg->nbits, sizeof(nbits), "Stratum notify", "nbits"))
        return false;
    if (!stratum_decode_hex_field(ntime, msg->stime, sizeof(ntime), "Stratum notify", "ntime"))
        return false;
    if (!sctx->job.job_id ||
        memcmp(sctx->job.version, version, sizeof(version)) != 0 ||
        memcmp(sctx->job.prevhash, prevhash, sizeof(prevhash)) != 0) {
        preserved_height = 0;
        update->await_height_message = true;
    }

    new_coinbase = update->new_coinbase;
    update->new_coinbase = NULL;
    if (!new_coinbase) {
        applog(LOG_ERR, "Failed to allocate coinbase buffer");
        return false;
    }
    if (!stratum_decode_hex_field(new_coinbase, msg->coinb1, coinb1_size, "Stratum notify", "coinb1"))
        goto out;
    if (!stratum_decode_hex_field(new_coinbase + coinb1_size, msg->coinb2, coinb2_size,
                                  "Stratum notify", "coinb2"))
        goto out;
    memcpy(new_coinbase + coinb1_size + coinb2_size, sctx->xnonce1, sctx->xnonce1_size);
    /* The trailing xnonce2_size bytes of the coinbase buffer are allocated
     * (coinbase_prealloc reserves coinb1 + 32 + coinb2) but never read back:
     * build_verus_work() below only ever copies the leading 64 bytes of
     * sctx->job.coinbase into the header, and unlike standard stratum (see
     * stratum_standard.cpp's sha256d_neon() merkle computation over the
     * full coinbase), Verus never reconstructs a merkle root client-side.
     * Leave those bytes as whatever malloc handed back rather than
     * preserving/resetting a value nothing consumes. */

    stratum_job_clear_merkle(&sctx->job);

    free(sctx->job.job_id);
    sctx->job.job_id = update->job_id;
    update->job_id = NULL;
    free(sctx->job.coinbase);
    sctx->job.coinbase = new_coinbase;
    sctx->job.coinbase_size = coinbase_size;
    new_coinbase = NULL;
    memcpy(sctx->job.solution, update->decoded_solution, sizeof(sctx->job.solution));
    memcpy(sctx->job.version, version, sizeof(version));
    memcpy(sctx->job.prevhash, prevhash, sizeof(prevhash));
    memcpy(sctx->job.nbits, nbits, sizeof(nbits));
    memcpy(sctx->job.ntime, ntime, sizeof(ntime));
    sctx->job.height = preserved_height;
    stratum_capture_next_diff_locked(sctx);

    return true;

out:
    free(new_coinbase);
    return false;
}

static bool parse_verus_notify(json_t *params, struct verus_notify_view *msg)
{
    int p = 0;

    memset(msg, 0, sizeof(*msg));

    msg->job_id = json_string_value(json_array_get(params, p++));
    msg->version = json_string_value(json_array_get(params, p++));
    msg->prevhash = json_string_value(json_array_get(params, p++));
    msg->coinb1 = json_string_value(json_array_get(params, p++));
    msg->coinb2 = json_string_value(json_array_get(params, p++));
    msg->stime = json_string_value(json_array_get(params, p++));
    msg->nbits = json_string_value(json_array_get(params, p++));
    msg->clean = json_is_true(json_array_get(params, p));
    p++;
    msg->solution = json_string_value(json_array_get(params, p++));

    if (!msg->job_id || !msg->prevhash || !msg->coinb1 || !msg->coinb2 ||
        !msg->version || !msg->nbits || !msg->stime)
        return false;
    if (msg->solution && (strlen(msg->solution) & 1u) != 0)
        return false;
    if (strlen(msg->prevhash) != 64 || strlen(msg->version) != 8 ||
        strlen(msg->coinb1) != 64 || strlen(msg->coinb2) != 64 ||
        strlen(msg->nbits) != 8 || strlen(msg->stime) != 8)
        return false;

    return true;
}

static bool apply_verus_notify(struct stratum_ctx *sctx, const struct verus_notify_view *msg)
{
    bool ret = false;
    char *new_job_id = NULL;
    uint8_t decoded_solution[1344];
    struct verus_job_update update = {0};
    /* Pre-allocate coinbase outside the lock. Verus always uses exactly 32 bytes of extranonce
     * (xnonce1 + xnonce2 == 32), so coinb1 + 32 + coinb2 is the exact allocation size. */
    size_t coinbase_prealloc = strlen(msg->coinb1) / 2 + 32 + strlen(msg->coinb2) / 2;
    unsigned char *new_coinbase = (unsigned char *)malloc(coinbase_prealloc);

    if (!new_coinbase) {
        applog(LOG_ERR, "Stratum notify: failed to allocate coinbase buffer");
        goto out;
    }

    if (!stratum_update_time_offset(sctx, msg->stime, false))
        goto out;
    if (msg->solution && msg->solution[0] &&
        !decode_verus_solution_field(decoded_solution, sizeof(decoded_solution),
                                     msg->solution)) {
        goto out;
    }
    if (!msg->solution || !msg->solution[0])
        memset(decoded_solution, 0, sizeof(decoded_solution));

    if (!stratum_check_job_id_length(msg->job_id, "Stratum notify"))
        goto out;

    new_job_id = strdup(msg->job_id);
    if (!new_job_id) {
        applog(LOG_ERR, "Stratum notify: failed to duplicate job id");
        goto out;
    }

    update.msg = msg;
    update.job_id = new_job_id;
    update.decoded_solution = decoded_solution;
    update.new_coinbase = new_coinbase;
    new_coinbase = NULL;

    if (!stratum_commit_job_update(sctx, apply_verus_job_locked, build_verus_work, &update,
                                   msg->clean)) {
        goto out;
    }
    if (update.await_height_message && opt_debug) {
        applog(LOG_DEBUG, "Verus notify: block height for job %s pending show_message",
               msg->job_id);
    }
    new_job_id = update.job_id;
    ret = true;

out:
    free(new_coinbase);
    free(update.new_coinbase);
    free(new_job_id);
    return ret;
}

static void build_verus_work(const struct stratum_ctx *sctx, struct work *new_work)
{
    uint8_t *solution;

    miner_work_reset(new_work);

    snprintf(new_work->job_id, sizeof(new_work->job_id), "%s",
             sctx->job.job_id ? sctx->job.job_id : "");
    new_work->height = sctx->job.height;
    new_work->pooln = sctx->pooln;

    memcpy(&new_work->data[0], sctx->job.version, 4);
    memcpy(&new_work->data[1], sctx->job.prevhash, 32);
    memcpy(&new_work->data[9], sctx->job.coinbase, 64);
    memcpy(&new_work->data[25], sctx->job.ntime, 4);
    solution = miner_work_solution(new_work);
    if (solution)
        memcpy(solution, sctx->job.solution, VERUS_WORK_SOLUTION_SIZE);
    memcpy(&new_work->data[26], sctx->job.nbits, 4);
    memcpy(&new_work->data[27], sctx->xnonce1, sctx->xnonce1_size);
    new_work->data[35] = 0x80;

    diff_to_target_verus(new_work->target, sctx->job.diff);
    new_work->targetdiff = sctx->job.diff;
}

bool verus_stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
    struct verus_notify_view msg;

    if (!parse_verus_notify(params, &msg)) {
        applog(LOG_ERR, "Stratum notify: invalid parameters");
        return false;
    }

    return apply_verus_notify(sctx, &msg);
}

static void free_verus_submit_view(struct verus_submit_view *msg)
{
    free(msg->noncestr);
    free(msg->solhex);
    msg->noncestr = NULL;
    msg->solhex = NULL;
}

static bool build_verus_submit_view(struct stratum_ctx *sctx, struct work *work,
    struct verus_submit_view *msg)
{
    unsigned char *nonce;
    size_t nonce_len;
    char *solhex_restore;
    const uint8_t *work_extra;
    const uint8_t *work_solution;

    memset(msg, 0, sizeof(*msg));
    if (!verus_validate_nonce_layout(sctx))
        return false;

    nonce = (unsigned char *)(&work->data[27]);
    nonce_len = VERUS_NONCE_FIELD_BYTES - sctx->xnonce1_size;
    msg->noncestr = bin2hex(&nonce[sctx->xnonce1_size], nonce_len);

    msg->solhex = (char *)calloc(1, 1344 * 2 + 64);
    if (!msg->solhex || !msg->noncestr) {
        applog(LOG_ERR, "unable to alloc share memory");
        free_verus_submit_view(msg);
        return false;
    }
    work_extra = miner_work_extra_const(work);
    work_solution = miner_work_solution_const(work);
    if (!work_extra || !work_solution) {
        applog(LOG_ERR, "Verus submit missing work payload");
        free_verus_submit_view(msg);
        return false;
    }
    // Verus pools expect the CompactSize prefix plus the 1344-byte solution.
    cbin2hex(msg->solhex, (const char *)work_extra, VERUS_SUBMIT_SOLUTION_SIZE);

    solhex_restore = (char *)calloc(129, 1);
    if (!solhex_restore) {
        applog(LOG_ERR, "unable to alloc solution restore buffer");
        free_verus_submit_view(msg);
        return false;
    }
    cbin2hex(solhex_restore,
             (const char *)&work_solution[VERUS_RESTORED_SOLUTION_OFFSET],
             VERUS_RESTORED_SOLUTION_BYTES);
    memcpy(&msg->solhex[6 + 16],
           solhex_restore,
           VERUS_RESTORED_SOLUTION_BYTES * 2);
    free(solhex_restore);

    snprintf(msg->timehex, sizeof(msg->timehex), "%08x", stratum_bswap32(work->data[25]));
    return true;
}

bool verus_stratum_submit(struct pool_infos *pool, struct work *work)
{
    char *request = NULL;
    struct verus_submit_view msg;
    uint32_t submit_id;
    struct stratum_ctx *sctx = &pool->stratum;
    bool ret;

    work->data[EQNONCE_OFFSET] = work->nonces[work->submit_nonce_id];

    if (!build_verus_submit_view(sctx, work, &msg))
        return false;
    submit_id = stratum_submit_id_next(sctx);
    request = stratum_build_submit_request_line(submit_id, pool->user, work->job_id,
                                                msg.timehex, msg.noncestr, msg.solhex);
    if (!request) {
        applog(LOG_ERR, "Failed to build Verus submit request");
        free_verus_submit_view(&msg);
        return false;
    }

    ret = stratum_send_submit(sctx, request, submit_id, work->sharediff[work->submit_nonce_id],
                              work->thread_id, __func__);
    free(request);
    free_verus_submit_view(&msg);
    return ret;
}
