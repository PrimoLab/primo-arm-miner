#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "stratum_internal.h"

bool stratum_update_time_offset(struct stratum_ctx *sctx, const char *stime, bool swap32)
{
    uint32_t raw_time = 0;
    int delta;

    if (!stime || strlen(stime) != 8)
        return false;
    if (!hex2bin(&raw_time, stime, 4))
        return false;

    delta = (int)(swap32 ? stratum_bswap32(raw_time) : raw_time) - (int)time(0);
    if (delta > sctx->srvtime_diff) {
        sctx->srvtime_diff = delta;
        if (opt_protocol && delta > 20)
            applog(LOG_INFO, "stratum time is at least %ds in the future", delta);
    }

    return true;
}

void stratum_free_merkle(unsigned char **merkle, int merkle_count)
{
    if (!merkle)
        return;

    for (int i = 0; i < merkle_count; i++)
        free(merkle[i]);
    free(merkle);
}

void stratum_job_clear_merkle(struct stratum_job *job)
{
    stratum_free_merkle(job->merkle, job->merkle_count);
    job->merkle = NULL;
    job->merkle_count = 0;
}

void stratum_capture_next_diff_locked(struct stratum_ctx *sctx)
{
    sctx->job.diff = sctx->next_diff;
}

bool stratum_decode_merkle_array(json_t *merkle_arr, unsigned char ***merkle_out, int *merkle_count_out)
{
    unsigned char **merkle = NULL;
    int merkle_count;

    if (!merkle_arr || !json_is_array(merkle_arr))
        return false;

    merkle_count = (int)json_array_size(merkle_arr);
    if (merkle_count > 0) {
        merkle = (unsigned char **)calloc((size_t)merkle_count, sizeof(*merkle));
        if (!merkle) {
            applog(LOG_ERR, "Failed to allocate Merkle array");
            return false;
        }
    }

    for (int i = 0; i < merkle_count; i++) {
        const char *branch = json_string_value(json_array_get(merkle_arr, i));
        if (!branch || strlen(branch) != 64) {
            applog(LOG_ERR, "Stratum notify: invalid Merkle branch");
            stratum_free_merkle(merkle, merkle_count);
            return false;
        }

        merkle[i] = (unsigned char *)malloc(32);
        if (!merkle[i]) {
            applog(LOG_ERR, "Failed to allocate Merkle branch");
            stratum_free_merkle(merkle, merkle_count);
            return false;
        }
        if (!hex2bin(merkle[i], branch, 32)) {
            stratum_free_merkle(merkle, merkle_count);
            return false;
        }
    }

    *merkle_out = merkle;
    *merkle_count_out = merkle_count;
    return true;
}

static void stratum_free_job_locked(struct stratum_ctx *sctx)
{
    free(sctx->job.job_id);
    stratum_job_clear_merkle(&sctx->job);
    sctx->job.xnonce2 = NULL;
    free(sctx->job.coinbase);
    memset(&sctx->job, 0, sizeof(struct stratum_job));
}

void stratum_free_job(struct stratum_ctx *sctx)
{
    pthread_mutex_lock(&stratum_work_lock);
    stratum_free_job_locked(sctx);
    pthread_mutex_unlock(&stratum_work_lock);
}

bool stratum_commit_job_update(struct stratum_ctx *sctx, stratum_job_apply_fn apply_job_locked,
    stratum_work_build_fn build_work_locked, void *opaque, bool clean)
{
    struct work new_work;
    bool should_restart;

    if (!miner_work_init(&new_work))
        return false;

    pthread_mutex_lock(&stratum_work_lock);
    if (!apply_job_locked(sctx, opaque)) {
        pthread_mutex_unlock(&stratum_work_lock);
        miner_work_cleanup(&new_work);
        return false;
    }

    build_work_locked(sctx, &new_work);
    should_restart = stratum_prepare_work_update_locked(&new_work, clean);
    pthread_mutex_unlock(&stratum_work_lock);

    stratum_publish_work(&new_work, should_restart);
    miner_work_cleanup(&new_work);
    return true;
}
