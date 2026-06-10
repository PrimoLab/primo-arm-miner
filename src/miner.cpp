/*
 * Mining coordination runtime for Primo ARM Miner.
 * Copyright (C) 2026 primo-arm-miner contributors.
 *
 * Coordinates work handoff, share submission, worker lifecycle, and
 * runtime statistics for the ARM-native mining threads.
 * Substantially rewritten on 2026-03-16 from earlier GPL-licensed mining
 * software ancestry. See LICENSE and PROVENANCE.md.
 */

#include <errno.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "cpu_features.h"
#include "dev_fee.h"
#include "miner.h"
#include "scrypt_neon.h"
#include "stratum_internal.h"

// Global state
struct thr_info *thr_info = NULL;
uint32_t g_miner_work_generation = 0;
int abort_flag = 0;
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t shutdown_signal = 0;

// Stratum locks (needed by stratum.cpp)
pthread_mutex_t stratum_sock_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t stratum_work_lock = PTHREAD_MUTEX_INITIALIZER;

// Statistics
static double global_hashrate = 0.0;
static time_t start_time = 0;
static time_t last_stats_time = 0;
static const int hashrate_warmup_sec = 10;
static int hashrate_reporter_stop_requested = 0;

struct miner_hashrate_report {
    int thread_count;
    double thread_hashrates[MAX_THREADS];
    double total_hashrate;
};

bool miner_should_abort(void)
{
    return __atomic_load_n(&abort_flag, __ATOMIC_ACQUIRE) != 0;
}

void miner_request_abort(void)
{
    __atomic_store_n(&abort_flag, 1, __ATOMIC_RELEASE);
}

void miner_clear_abort_flag(void)
{
    __atomic_store_n(&abort_flag, 0, __ATOMIC_RELEASE);
}

void miner_work_generation_reset(void)
{
    __atomic_store_n(&g_miner_work_generation, 0, __ATOMIC_RELEASE);
}

static bool miner_work_ensure_verus_payload(struct work *work)
{
    if (!work)
        return false;

    if (work->verus || opt_algo != ALGO_VERUS)
        return true;

    work->verus = (struct verus_work_payload *)calloc(1, sizeof(*work->verus));
    if (!work->verus) {
        applog(LOG_ERR, "Failed to allocate Verus work payload");
        return false;
    }

    return true;
}

bool miner_work_init(struct work *work)
{
    if (!work)
        return false;

    memset(work, 0, sizeof(*work));
    return miner_work_ensure_verus_payload(work);
}

void miner_work_reset(struct work *work)
{
    struct verus_work_payload *verus;

    if (!work)
        return;

    verus = work->verus;
    memset(work, 0, sizeof(*work));
    work->verus = verus;
    if (verus)
        memset(verus, 0, sizeof(*verus));
}

void miner_work_cleanup(struct work *work)
{
    if (!work)
        return;

    free(work->verus);
    work->verus = NULL;
}

bool miner_work_copy(struct work *dst, const struct work *src)
{
    struct verus_work_payload *dst_verus;

    if (!dst || !src)
        return false;

    dst_verus = dst->verus;
    *dst = *src;
    dst->verus = dst_verus;

    if (!src->verus) {
        if (dst->verus)
            memset(dst->verus, 0, sizeof(*dst->verus));
        return true;
    }

    if (!dst->verus) {
        dst->verus = (struct verus_work_payload *)calloc(1, sizeof(*dst->verus));
        if (!dst->verus) {
            applog(LOG_ERR, "Failed to allocate Verus work payload");
            memset(dst, 0, sizeof(*dst));
            dst->verus = dst_verus;
            if (dst->verus)
                memset(dst->verus, 0, sizeof(*dst->verus));
            return false;
        }
    }

    memcpy(dst->verus, src->verus, sizeof(*dst->verus));
    return true;
}

uint8_t *miner_work_solution(struct work *work)
{
    return (work && work->verus) ? work->verus->solution : NULL;
}

const uint8_t *miner_work_solution_const(const struct work *work)
{
    return (work && work->verus) ? work->verus->solution : NULL;
}

uint8_t *miner_work_extra(struct work *work)
{
    return (work && work->verus) ? work->verus->extra : NULL;
}

const uint8_t *miner_work_extra_const(const struct work *work)
{
    return (work && work->verus) ? work->verus->extra : NULL;
}

static int priority_to_nice_value(int priority_level)
{
    switch (priority_level) {
        case 0: return 15;
        case 1: return 5;
        case 2: return 0;
        case 3: return -1;
        case 4: return -10;
        case 5: return -15;
        default: return 0;
    }
}

static cpu_core_info_t *find_cpu_core_info(int cpu_id)
{
    for (int i = 0; i < g_num_cpus; i++) {
        if (g_cpu_cores[i].cpu_id == cpu_id)
            return &g_cpu_cores[i];
    }
    return NULL;
}

static int select_affinity_cpu_for_thread(int thread_id)
{
    int mask_bits = (int)(sizeof(unsigned long) * 8);
    int selected_count = 0;

    if (!opt_affinity_set || g_num_cpus <= 0)
        return -1;

    // Preserve the user-selected CPU set, but iterate that set in the same
    // topology order used by automatic pinning so heterogeneous cores prefer
    // the faster cluster first when the mask spans big and LITTLE CPUs.
    if (g_core_order_count > 0) {
        for (int order_index = 0; order_index < g_core_order_count; order_index++) {
            int cpu_id = g_core_order[order_index];

            if (cpu_id < 0 || cpu_id >= mask_bits)
                continue;
            if ((opt_affinity_mask >> cpu_id) & 1UL)
                selected_count++;
        }

        if (selected_count > 0) {
            int target_index = thread_id % selected_count;

            for (int order_index = 0; order_index < g_core_order_count; order_index++) {
                int cpu_id = g_core_order[order_index];

                if (cpu_id < 0 || cpu_id >= mask_bits)
                    continue;
                if (!((opt_affinity_mask >> cpu_id) & 1UL))
                    continue;
                if (target_index-- == 0)
                    return cpu_id;
            }
        }
    }

    selected_count = 0;
    for (int cpu_id = 0; cpu_id < g_num_cpus && cpu_id < mask_bits; cpu_id++) {
        if ((opt_affinity_mask >> cpu_id) & 1UL)
            selected_count++;
    }

    if (selected_count > 0) {
        int target_index = thread_id % selected_count;

        for (int cpu_id = 0; cpu_id < g_num_cpus && cpu_id < mask_bits; cpu_id++) {
            if (!((opt_affinity_mask >> cpu_id) & 1UL))
                continue;
            if (target_index-- == 0)
                return cpu_id;
        }
    }

    return -1;
}

static void miner_get_thread_nonce_range(int thread_id, uint64_t *range_start_out,
                                         uint64_t *range_end_out)
{
    const uint64_t total_nonce_space = UINT64_C(1) << 32;
    const uint64_t thread_index = (uint64_t)thread_id;
    const uint64_t thread_count = (uint64_t)opt_n_threads;

    if (range_start_out) {
        *range_start_out = (thread_index * total_nonce_space) / thread_count;
    }
    if (range_end_out) {
        *range_end_out = ((thread_index + 1) * total_nonce_space) / thread_count;
    }
}

static void recalculate_global_hashrate_locked(void)
{
    global_hashrate = 0.0;
    for (int thread_index = 0; thread_index < opt_n_threads; thread_index++) {
        global_hashrate += miner_thread_hashrate_load(&thr_info[thread_index]);
    }
}

static bool miner_hashrate_reporter_should_stop(void)
{
    return __atomic_load_n(&hashrate_reporter_stop_requested, __ATOMIC_ACQUIRE) != 0;
}

static void miner_hashrate_reporter_request_stop(void)
{
    __atomic_store_n(&hashrate_reporter_stop_requested, 1, __ATOMIC_RELEASE);
}

static void miner_hashrate_reporter_reset_stop_request(void)
{
    __atomic_store_n(&hashrate_reporter_stop_requested, 0, __ATOMIC_RELEASE);
}

static bool miner_snapshot_hashrate_report(time_t now, struct miner_hashrate_report *report_out)
{
    int ready_threads = 0;
    bool warmup_done;
    int thread_count;

    if (!report_out)
        return false;

    memset(report_out, 0, sizeof(*report_out));

    pthread_mutex_lock(&stats_lock);
    if (!thr_info || start_time == 0 || opt_n_threads <= 0 ||
        difftime(now, last_stats_time) < opt_statsavg) {
        pthread_mutex_unlock(&stats_lock);
        return false;
    }

    thread_count = opt_n_threads;
    if (thread_count > MAX_THREADS)
        thread_count = MAX_THREADS;

    for (int thread_index = 0; thread_index < thread_count; thread_index++) {
        double thread_hashrate = miner_thread_hashrate_load(&thr_info[thread_index]);
        report_out->thread_hashrates[thread_index] = thread_hashrate;
        if (thread_hashrate > 0.0)
            ready_threads++;
    }

    warmup_done = difftime(now, start_time) >= hashrate_warmup_sec;
    if (!warmup_done && ready_threads < thread_count) {
        pthread_mutex_unlock(&stats_lock);
        return false;
    }

    report_out->thread_count = thread_count;
    report_out->total_hashrate = global_hashrate;
    last_stats_time = now;
    pthread_mutex_unlock(&stats_lock);

    return true;
}

static __attribute__((noinline, cold)) void miner_thread_governor_warmup(void)
{
    /* schedutil ramps CPU frequency in response to observed load. Without a
     * warm-up, threads start hashing while the governor is still at idle
     * frequency, producing lower (and variable) hashrate for the first few
     * seconds. A 50ms busy-spin triggers the ramp-up so the core reaches max
     * frequency before the first hash is computed. No root required. */
    struct timespec end, now;
    volatile uint32_t sink = 0;

    clock_gettime(CLOCK_MONOTONIC, &end);
    end.tv_nsec += 50 * 1000000L;
    if (end.tv_nsec >= 1000000000L) {
        end.tv_sec++;
        end.tv_nsec -= 1000000000L;
    }
    do {
        for (int i = 0; i < 1000; i++)
            sink += (uint32_t)i * 2654435761u;
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (now.tv_sec < end.tv_sec ||
             (now.tv_sec == end.tv_sec && now.tv_nsec < end.tv_nsec));
    (void)sink;
}

void miner_configure_current_thread(struct thr_info *thread_ctx)
{
    int thread_id;

    if (!thread_ctx)
        return;

    thread_id = thread_ctx->id;

    // Preserve the existing CLI priority scale (0..5).
    if (opt_priority > 0) {
        if (setpriority(PRIO_PROCESS, 0, priority_to_nice_value(opt_priority)) != 0 && opt_debug)
            applog(LOG_DEBUG, "setpriority failed: %s", strerror(errno));
    }

    // Pin thread to a specific CPU core. Remember which core we asked for so the
    // post-warmup readback below can tell whether the platform actually honored
    // it (Android cpuset cgroups can clamp a "successful" pin to another cluster).
    int intended_cpu = -1;

    if (opt_affinity_set && g_num_cpus > 0) {
        cpu_set_t cpuset;
        int selected_cpu = select_affinity_cpu_for_thread(thread_id);

        CPU_ZERO(&cpuset);
        if (selected_cpu >= 0)
            CPU_SET(selected_cpu, &cpuset);

        if (selected_cpu >= 0 &&
            sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0) {
            intended_cpu = selected_cpu;
            cpu_core_info_t *core = find_cpu_core_info(selected_cpu);
            if (core) {
                applog(LOG_INFO, "Thread %d pinned to CPU %d via affinity mask 0x%lx (%s @ %d MHz)",
                       thread_id, selected_cpu, opt_affinity_mask,
                       core->is_big ? "big" : "LITTLE", core->max_freq_khz / 1000);
            } else {
                applog(LOG_INFO, "Thread %d pinned to CPU %d via affinity mask 0x%lx",
                       thread_id, selected_cpu, opt_affinity_mask);
            }
        } else {
            applog(LOG_WARNING, "Thread %d: affinity-mask pin unavailable (mask 0x%lx) — leaving to scheduler",
                   thread_id, opt_affinity_mask);
        }
    } else if (g_core_order_count > 0) {
        int cpu_id = get_cpu_for_thread(thread_id);
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(cpu_id, &cpuset);
        if (sched_setaffinity(0, sizeof(cpuset), &cpuset) == 0) {
            intended_cpu = cpu_id;
            cpu_core_info_t *core = find_cpu_core_info(cpu_id);
            if (core) {
                applog(LOG_INFO, "Thread %d pinned to CPU %d (%s @ %d MHz)",
                       thread_id, cpu_id,
                       core->is_big ? "big" : "LITTLE",
                       core->max_freq_khz / 1000);
            } else {
                applog(LOG_INFO, "Thread %d pinned to CPU %d", thread_id, cpu_id);
            }
        } else {
            /* A single-core pin is commonly rejected under Android cpuset
             * confinement (EINVAL when the target core is outside the app's
             * allowed set). Fall back to the whole big-core set so the thread at
             * least stays on a fast core within whatever the platform permits,
             * instead of silently dropping to a default (often LITTLE) core. */
            int pin_errno = errno;
            cpu_set_t big_set;
            int big_count = 0;
            CPU_ZERO(&big_set);
            for (int i = 0; i < g_num_cpus; i++) {
                if (g_cpu_cores[i].is_big) {
                    CPU_SET(g_cpu_cores[i].cpu_id, &big_set);
                    big_count++;
                }
            }
            if (big_count > 0 && sched_setaffinity(0, sizeof(big_set), &big_set) == 0) {
                applog(LOG_WARNING,
                       "Thread %d: per-core pin to CPU %d rejected (%s); pinned to big-core set instead",
                       thread_id, cpu_id, strerror(pin_errno));
            } else {
                applog(LOG_WARNING,
                       "Thread %d: CPU pin to %d failed (%s); leaving placement to scheduler",
                       thread_id, cpu_id, strerror(pin_errno));
            }
        }
    } else {
        applog(LOG_INFO, "Thread %d started (no CPU pinning)", thread_id);
    }

    miner_thread_governor_warmup();

    /* Verify where we actually landed. The warm-up spin forces a reschedule, so
     * sched_getcpu() now reflects the real core. On Android a cpuset cgroup can
     * clamp a "successful" pin onto a different (slower) cluster, so this readback
     * is the ground truth when diagnosing low hashrate on a phone. */
    int actual_cpu = sched_getcpu();
    if (actual_cpu >= 0) {
        cpu_core_info_t *core = find_cpu_core_info(actual_cpu);
        const char *cls = core ? (core->is_big ? "big" : "LITTLE") : "unknown";
        if (intended_cpu >= 0 && actual_cpu != intended_cpu) {
            applog(LOG_WARNING,
                   "Thread %d: requested CPU %d but running on CPU %d (%s) — platform overrode affinity",
                   thread_id, intended_cpu, actual_cpu, cls);
        } else if (core && !core->is_big) {
            applog(LOG_WARNING, "Thread %d running on LITTLE CPU %d — expect reduced hashrate",
                   thread_id, actual_cpu);
        } else if (opt_debug) {
            applog(LOG_DEBUG, "Thread %d running on CPU %d (%s)", thread_id, actual_cpu, cls);
        }
    }
}

static void miner_log_hashrate_report(const struct miner_hashrate_report *report)
{
    char line[MAX_THREADS * 24 + 64];
    size_t pos = 0;
    int temp;

    if (!report || report->thread_count <= 0)
        return;

    line[0] = '\0';

    for (int thread_index = 0; thread_index < report->thread_count; thread_index++) {
        char thr_str[32];
        int written;

        format_hashrate(report->thread_hashrates[thread_index], thr_str, sizeof(thr_str));
        if (pos >= sizeof(line) - 1)
            break;
        if (thread_index > 0) {
            written = snprintf(line + pos, sizeof(line) - pos, "  ");
            if (written < 0)
                break;
            if ((size_t)written >= sizeof(line) - pos) {
                pos = sizeof(line) - 1;
                break;
            }
            pos += (size_t)written;
        }
        written = snprintf(line + pos, sizeof(line) - pos, "#%d: %s", thread_index, thr_str);
        if (written < 0)
            break;
        if ((size_t)written >= sizeof(line) - pos) {
            pos = sizeof(line) - 1;
            break;
        }
        pos += (size_t)written;
    }

    char total_str[32];
    format_hashrate(report->total_hashrate, total_str, sizeof(total_str));
    if (pos < sizeof(line) - 1) {
        int written = snprintf(line + pos, sizeof(line) - pos, " | Total: %s", total_str);
        if (written >= 0) {
            if ((size_t)written >= sizeof(line) - pos)
                pos = sizeof(line) - 1;
            else
                pos += (size_t)written;
        }
    }

    temp = get_cpu_temp();
    if (temp > 0 && pos < sizeof(line) - 1)
        snprintf(line + pos, sizeof(line) - pos, " | Temp: %dc", temp);

    applog(LOG_INFO, "%s", line);
}

static void *miner_hashrate_reporter_thread(void *userdata)
{
    (void)userdata;

    while (!miner_should_abort() && !miner_hashrate_reporter_should_stop()) {
        struct miner_hashrate_report report;
        time_t now = time(NULL);

        if (miner_snapshot_hashrate_report(now, &report))
            miner_log_hashrate_report(&report);

        for (int i = 0; i < 10; i++) {
            if (miner_should_abort() || miner_hashrate_reporter_should_stop())
                break;
            usleep(100000);
        }
    }

    return NULL;
}

static void log_pending_shutdown_signal(void)
{
    sig_atomic_t sig = shutdown_signal;
    shutdown_signal = 0;

    switch (sig) {
    case SIGINT:
        applog(LOG_INFO, "SIGINT received, exiting");
        break;
    case SIGTERM:
        applog(LOG_INFO, "SIGTERM received, exiting");
        break;
    default:
        break;
    }
}

void miner_runtime_begin(void)
{
    pthread_mutex_lock(&stats_lock);
    start_time = time(NULL);
    global_hashrate = 0.0;
    last_stats_time = 0;
    pthread_mutex_unlock(&stats_lock);
    miner_hashrate_reporter_reset_stop_request();
}

void miner_runtime_end(void)
{
    miner_hashrate_reporter_request_stop();
    pthread_mutex_lock(&stats_lock);
    start_time = 0;
    global_hashrate = 0.0;
    last_stats_time = 0;
    pthread_mutex_unlock(&stats_lock);
}

void miner_runtime_publish_global_hashrate(double hashrate)
{
    pthread_mutex_lock(&stats_lock);
    global_hashrate = hashrate;
    pthread_mutex_unlock(&stats_lock);
}

void miner_record_thread_share_result(int thread_id, bool accepted)
{
    if (!thr_info || thread_id < 0 || thread_id >= opt_n_threads)
        return;

    if (accepted)
        miner_thread_accepted_inc(&thr_info[thread_id]);
    else
        miner_thread_rejected_inc(&thr_info[thread_id]);
}

bool miner_init_algorithm_runtime(bool *algorithm_ready_out)
{
    bool algorithm_ready = false;

    if (opt_algo == ALGO_VERUS) {
        algorithm_ready = verus_init_runtime();
    } else if (opt_algo == ALGO_SHA256D) {
        algorithm_ready = true;
    } else if (opt_algo == ALGO_SCRYPT) {
        int selftest_result;

        if (scrypt_init(opt_n_threads) != 0) {
            applog(LOG_ERR, "Failed to initialize scrypt scratchpads");
            goto out;
        }

        selftest_result = scrypt_selftest();
        if (selftest_result != 0) {
            applog(LOG_ERR, "Scrypt self-test FAILED (error %d)!", selftest_result);
            goto out;
        }

        applog(LOG_INFO, "Scrypt self-test passed");
        algorithm_ready = true;
    } else {
        applog(LOG_ERR, "No init handler for algorithm %d", (int)opt_algo);
    }

out:
    if (algorithm_ready_out)
        *algorithm_ready_out = algorithm_ready;
    return algorithm_ready;
}

void miner_cleanup_algorithm_runtime(bool algorithm_ready)
{
    if (!algorithm_ready)
        return;

    if (opt_algo == ALGO_SCRYPT)
        scrypt_cleanup();
}

void miner_get_api_snapshot(struct miner_api_snapshot *snapshot)
{
    if (!snapshot)
        return;

    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->cpu_temp = get_cpu_temp();

    pthread_mutex_lock(&stats_lock);
    snapshot->runtime_active = (start_time != 0);
    snapshot->start_time = start_time;
    snapshot->global_hashrate = global_hashrate;

    if (thr_info) {
        int snapshot_threads = opt_n_threads;
        if (snapshot_threads > MAX_THREADS)
            snapshot_threads = MAX_THREADS;
        snapshot->thread_count = snapshot_threads;

        for (int thread_index = 0; thread_index < snapshot->thread_count; thread_index++) {
            struct miner_thread_api_stats *thread_stats = &snapshot->threads[thread_index];
            cpu_core_info_t *core;
            int cpu_id = get_cpu_for_thread(thread_index);

            thread_stats->hashrate = miner_thread_hashrate_load(&thr_info[thread_index]);
            thread_stats->hashes_done_total = miner_thread_hashes_done_load(&thr_info[thread_index]);
            thread_stats->accepted = miner_thread_accepted_load(&thr_info[thread_index]);
            thread_stats->rejected = miner_thread_rejected_load(&thr_info[thread_index]);
            thread_stats->cpu_id = cpu_id;

            core = find_cpu_core_info(cpu_id);
            if (core) {
                thread_stats->cpu_max_freq_mhz = core->max_freq_khz / 1000;
                thread_stats->cpu_is_big = core->is_big;
            }

            snapshot->total_hashes_done += thread_stats->hashes_done_total;
        }
    }
    pthread_mutex_unlock(&stats_lock);
}

static bool work_is_new_job(const struct work *current_work,
                            const uint32_t *previous_verus_header,
                            bool have_previous_verus_header,
                            bool is_first_work,
                            const char *previous_job_id)
{
    if (opt_algo == ALGO_VERUS) {
        // 36 bytes = version (word 0) + prevhash (words 1-8)
        return is_first_work ||
               !have_previous_verus_header ||
               memcmp(&current_work->data[0], previous_verus_header, 36) != 0;
    }

    return is_first_work || strcmp(current_work->job_id, previous_job_id) != 0;
}

// Share-difficulty helper used by the hashing back ends.
extern "C" void bn_store_share_difficulty(uint32_t* hash, uint32_t* target, struct work* work, int nonce)
{
    if (nonce < 0 || nonce >= MAX_NONCES)
        return;

    // Compute target/hash as floating point for share difficulty display.
    // Both are LE 256-bit: word 0 = LSW, word 7 = MSW.
    const double word_base = 4294967296.0;
    double target_value = 0.0;
    double hash_value = 0.0;

    for (int word_index = 7; word_index >= 0; word_index--) {
        target_value = target_value * word_base + (double)target[word_index];
        hash_value = hash_value * word_base + (double)hash[word_index];
    }

    work->sharediff[nonce] = (hash_value > 0.0) ? target_value / hash_value : 0.0;
}

int scanhash_dispatch(int thr_id, struct work *work, uint32_t max_hashes, unsigned long *hashes_done)
{
    switch (opt_algo) {
        case ALGO_VERUS:
            return scanhash_verus(thr_id, work, max_hashes, hashes_done);
        case ALGO_SHA256D:
            return scanhash_sha256d(thr_id, work, max_hashes, hashes_done);
        case ALGO_SCRYPT:
            return scanhash_scrypt(thr_id, work, max_hashes, hashes_done);
        default:
            applog(LOG_ERR, "Unsupported algorithm id %d in scanhash_dispatch", (int)opt_algo);
            miner_request_abort();
            return 0;
    }
}

static bool submit_ready_share(struct work *work)
{
    struct pool_infos *pool = &pools[work->pooln];
    struct stratum_ctx *sctx = &pool->stratum;

    // A reconnect or failover invalidates the work generation before fresh work arrives.
    // Never submit shares from a stale generation, even if the pool has re-authenticated.
    if (miner_work_restart_requested(work->restart_generation)) {
        if (opt_debug)
            applog(LOG_DEBUG, "Dropping stale share from expired work generation");
        return false;
    }

    // Don't submit if not authenticated
    if (!stratum_is_authenticated(sctx)) {
        if (opt_debug)
            applog(LOG_DEBUG, "Not submitting work - not authenticated");
        return false;
    }

    // Let the stratum layer select the correct protocol-specific submit path.
    // Share results come back asynchronously on the stratum receive loop.
    if (stratum_submit(pool, work)) {
        stratum_record_share_submit(work->pooln, work->sharediff[work->submit_nonce_id]);
        if (opt_debug)
            applog(LOG_DEBUG, "Share submitted (diff %.3f)", work->sharediff[work->submit_nonce_id]);
        return true;
    }

    applog(LOG_WARNING, "Failed to submit share");
    return false;
}

static void wait_for_work_restart_after_nonce_exhaustion(int thread_id,
                                                         uint32_t restart_generation,
                                                         struct timespec *rate_window_start,
                                                         unsigned long *rate_window_hashes,
                                                         double *rate_window_scan_sec)
{
    if (opt_debug)
        applog(LOG_DEBUG, "Thread %d: nonce range exhausted, waiting for new work", thread_id);

    while (!miner_work_restart_requested(restart_generation) && !miner_should_abort()) {
        usleep(50000);  // 50ms
    }

    // Reset the sample window after idle time so the next update reflects
    // active hashing instead of time spent waiting on a new job.
    clock_gettime(CLOCK_MONOTONIC, rate_window_start);
    *rate_window_hashes = 0;
    *rate_window_scan_sec = 0.0;
}

void *miner_thread(void *userdata)
{
    struct thr_info *thread_ctx = (struct thr_info *)userdata;
    int thread_id = thread_ctx->id;
    struct work work;
    uint32_t previous_verus_header[9];
    unsigned long hashes_done = 0;
    uint64_t thread_nonce_start = 0;
    uint64_t thread_nonce_end = 0;

    // High-resolution timing for accurate hashrate
    struct timespec rate_window_start, rate_sample_time;
    clock_gettime(CLOCK_MONOTONIC, &rate_window_start);
    unsigned long rate_window_hashes = 0;
    // Time actually spent inside scanhash this window. The displayed rate is
    // hashes/scan_time, not hashes/wall-clock: wall-clock includes per-chunk
    // overhead (stratum_copy_work, submit, job handling) where the CPU isn't
    // hashing, which under-reported the live rate ~3% vs the benchmark path and
    // vs ccminer (both of which report pure hashing rate).
    double rate_window_scan_sec = 0.0;
    double chunk_hashrate = 0.0;

    // Track nonce position separately (not relying on work structure which gets overwritten)
    uint64_t next_nonce_index = 0;
    bool first_work = true;
    bool have_previous_verus_header = false;
    char previous_job_id[128] = "";
    // Dual EMA: fast (α=0.3) for chunk_size adaptation, slow (α=0.1) for stable display.
    // Thermal oscillations at 61°C vary rate by ±3% on ~10–30s cycles; α=0.1 attenuates
    // these by ~3× vs α=0.3 while still converging to the true rate within ~90 seconds.
    double display_hashrate = 0.0;

    if (!miner_work_init(&work))
        return NULL;
    memset(previous_verus_header, 0, sizeof(previous_verus_header));
    miner_get_thread_nonce_range(thread_id, &thread_nonce_start, &thread_nonce_end);
    next_nonce_index = thread_nonce_start;

    miner_configure_current_thread(thread_ctx);

    while (!miner_should_abort()) {
        // Get work from stratum
        if (!stratum_copy_work(&work)) {
            sleep(1);
            continue;
        }

        work.valid_nonces = 0;  // Reset nonce count before each scan

        // Nonce pointer - different offset for different algorithms
        // Verus: offset 30 (EQNONCE_OFFSET)
        // SHA256d/Scrypt: offset 19 (standard 80-byte header, nonce at bytes 76-79)
        int nonce_offset = (opt_algo == ALGO_VERUS) ? 30 : 19;
        uint32_t *nonce_word = &work.data[nonce_offset];

        // Handle nonce progression:
        // Only reset scan_nonce when the block actually changes (new prevhash).
        // Coinbase refreshes (same prevhash, updated merkle/ntime) don't need a
        // nonce reset — the nonce space is independent of coinbase content, and
        // continuing from the current position avoids duplicate-share risk.
        //
        // For Verus: compare only version(4) + prevhash(32) = 36 bytes (words 0-8).
        //   Including the merkle root (old 68-byte compare) was wrong — it caused
        //   scan_nonce and the EMA interval to reset on every coinbase refresh,
        //   fragmenting the EMA accumulation window and showing spuriously low rates
        //   during active pool periods that send frequent job updates.
        // For SHA256d/Scrypt: job_id changes only on true block changes (pools
        //   keep the same job_id for coinbase refreshes), so strcmp is sufficient.
        bool new_job = work_is_new_job(&work, previous_verus_header, have_previous_verus_header,
                                       first_work, previous_job_id);

        if (new_job) {
            // Partition the full 2^32 nonce space exactly using 64-bit arithmetic.
            // Each thread owns [start, end) with no gaps and no overlap.
            next_nonce_index = thread_nonce_start;
            if (opt_algo == ALGO_VERUS) {
                memcpy(previous_verus_header, &work.data[0], sizeof(previous_verus_header));
                have_previous_verus_header = true;
            }
            snprintf(previous_job_id, sizeof(previous_job_id), "%s", work.job_id);
            first_work = false;

            // Reset hashrate interval on new job to prevent stale measurements
            clock_gettime(CLOCK_MONOTONIC, &rate_window_start);
            rate_window_hashes = 0;
            rate_window_scan_sec = 0.0;
        }
        // Otherwise keep next_nonce_index where it was (already advanced locally)

        if (next_nonce_index >= thread_nonce_end) {
            wait_for_work_restart_after_nonce_exhaustion(thread_id, work.restart_generation,
                                                         &rate_window_start, &rate_window_hashes,
                                                         &rate_window_scan_sec);
            continue;
        }

        // Set the nonce position for this scan
        *nonce_word = (uint32_t)next_nonce_index;
        work.thread_id = (uint8_t)thread_id;

        // Adaptive chunk size targeting ~5 seconds per chunk.
        // Default 3M ensures A55 threads (516 kH/s) complete in ~5.8s — before
        // the 10s warmup fires.  Once smoothed_hashrate is calibrated, the chunk
        // scales to whichever speed the core actually runs at (A76 ≈ 5.5M, A55 ≈
        // 2.6M), keeping display lag consistently under ~5 seconds.
        uint32_t chunk_size;
        if (chunk_hashrate > 100000.0) {
            chunk_size = (uint32_t)(chunk_hashrate * 5.0);
            if (chunk_size > 0x1000000) chunk_size = 0x1000000;  // cap: 16M
            if (chunk_size < 0x100000)  chunk_size = 0x100000;   // min:  1M
        } else {
            chunk_size = 0x300000;  // 3M default (fits in A55 warmup window)
        }
        uint64_t remaining_nonces = thread_nonce_end - next_nonce_index;
        uint32_t scan_count = chunk_size;
        if ((uint64_t)scan_count > remaining_nonces)
            scan_count = (uint32_t)remaining_nonces;

        // Mine!
        if (opt_debug)
            applog(LOG_DEBUG, "Thread %d: scanning with nonce start %08x", thread_id, *nonce_word);

        struct timespec scan_t0, scan_t1;
        clock_gettime(CLOCK_MONOTONIC, &scan_t0);
        int nonces_found = scanhash_dispatch(thread_id, &work, scan_count, &hashes_done);
        clock_gettime(CLOCK_MONOTONIC, &scan_t1);
        if ((uint64_t)hashes_done > (uint64_t)scan_count) {
            applog(LOG_ERR,
                   "Thread %d: scan backend exceeded requested nonce count (%lu > %u)",
                   thread_id, hashes_done, scan_count);
            miner_request_abort();
            break;
        }
        rate_window_hashes += hashes_done;
        rate_window_scan_sec += (scan_t1.tv_sec - scan_t0.tv_sec) +
                                (scan_t1.tv_nsec - scan_t0.tv_nsec) / 1e9;
        miner_thread_hashes_done_add(thread_ctx, hashes_done);

        // Advance through the absolute thread partition using the backend's reported progress.
        next_nonce_index += (uint64_t)hashes_done;

        if (opt_debug && nonces_found > 0)
            applog(LOG_DEBUG, "Thread %d: found %d nonces", thread_id, nonces_found);

        // Submit found nonces immediately.
        for (int i = 0; i < nonces_found && i < MAX_NONCES; i++) {
            work.submit_nonce_id = i;
            submit_ready_share(&work);
        }

        // If nonce range exhausted, wait for new work instead of
        // scanning into other threads' ranges (causes duplicate shares)
        if (nonces_found == 0 && next_nonce_index >= thread_nonce_end) {
            wait_for_work_restart_after_nonce_exhaustion(thread_id, work.restart_generation,
                                                         &rate_window_start, &rate_window_hashes,
                                                         &rate_window_scan_sec);
            continue;  // Skip hashrate update, go back to get_work
        }

        // Calculate hashrate using high-resolution timer and EMA smoothing
        clock_gettime(CLOCK_MONOTONIC, &rate_sample_time);
        double interval_sec = (rate_sample_time.tv_sec - rate_window_start.tv_sec) +
                              (rate_sample_time.tv_nsec - rate_window_start.tv_nsec) / 1e9;

        // Update rate every ~2 seconds for responsive but stable readings
        // Use shorter threshold (1s) for first update to show initial hashrate faster
        double update_threshold = (chunk_hashrate < 1.0) ? 1.0 : 2.0;
        if (interval_sec >= update_threshold && rate_window_hashes > 0 && rate_window_scan_sec > 0.0) {
            // Pure hashing rate: hashes / time-spent-in-scanhash (not wall-clock).
            double current_rate = (double)rate_window_hashes / rate_window_scan_sec;

            // Fast EMA (α=0.3): tracks actual speed for chunk_size adaptation.
            // Converges quickly to real rate, intentionally tracks thermal changes.
            if (chunk_hashrate < 1.0) {
                chunk_hashrate = current_rate;  // First sample
            } else {
                chunk_hashrate = 0.3 * current_rate + 0.7 * chunk_hashrate;
            }

            // Slow EMA (α=0.1, τ≈47s): attenuates short-term thermal oscillations
            // by ~3× for a stable displayed hashrate.  Initialized from first sample
            // so the display is immediate — only the smoothing is slow.
            if (display_hashrate < 1.0) {
                display_hashrate = current_rate;   // First sample: initialize directly
            } else {
                display_hashrate = 0.1 * current_rate + 0.9 * display_hashrate;
            }

            pthread_mutex_lock(&stats_lock);
            miner_thread_hashrate_store(thread_ctx, display_hashrate);
            rate_window_hashes = 0;
            rate_window_scan_sec = 0.0;
            rate_window_start = rate_sample_time;
            recalculate_global_hashrate_locked();
            pthread_mutex_unlock(&stats_lock);
        }
    }

    miner_work_cleanup(&work);
    applog(LOG_INFO, "Thread %d stopped", thread_id);
    return NULL;
}

static void signal_handler(int sig)
{
    switch (sig) {
    case SIGINT:
        shutdown_signal = SIGINT;
        break;
    case SIGTERM:
        shutdown_signal = SIGTERM;
        break;
    }
    miner_request_abort();
}

struct mining_runtime {
    int initialized_pools;
    int started_threads;
    bool algorithm_runtime_ready;
    bool pool_services_stopped;
    bool hashrate_reporter_started;
    pthread_t hashrate_reporter_thread;
    struct pool_infos *pool;
};

static void init_mining_runtime(struct mining_runtime *runtime)
{
    memset(runtime, 0, sizeof(*runtime));
    runtime->pool = &pools[miner_get_current_pool_index()];
    stratum_reset_runtime_state();
    miner_runtime_end();
}

static int start_worker_threads(void)
{
    int started = 0;

    for (int i = 0; i < opt_n_threads; i++) {
        struct thr_info *thread_slot = &thr_info[i];
        thread_slot->id = i;

        if (pthread_create(&thread_slot->pth, NULL, miner_thread, thread_slot)) {
            applog(LOG_ERR, "Failed to create thread %d", i);
            miner_request_abort();
            break;
        }

        started++;
    }

    return started;
}

static void join_worker_threads(int started_threads)
{
    for (int i = 0; i < started_threads; i++) {
        pthread_join(thr_info[i].pth, NULL);
    }
}

static void destroy_pool_contexts(int initialized_pools)
{
    for (int i = 0; i < initialized_pools; i++) {
        stratum_destroy_context(&pools[i].stratum);
    }
}

static void stop_all_pool_services(int initialized_pools)
{
    for (int i = 0; i < initialized_pools; i++) {
        stratum_stop_service(&pools[i].stratum);
    }
}

static void stop_pool_runtime_services(struct mining_runtime *runtime)
{
    if (runtime->pool_services_stopped)
        return;

    stop_all_pool_services(runtime->initialized_pools);
    runtime->pool_services_stopped = true;
}

static void cleanup_mining_runtime(struct mining_runtime *runtime)
{
    api_stop_service();

    if (runtime->hashrate_reporter_started) {
        miner_hashrate_reporter_request_stop();
        pthread_join(runtime->hashrate_reporter_thread, NULL);
        runtime->hashrate_reporter_started = false;
    }

    if (runtime->started_threads > 0) {
        join_worker_threads(runtime->started_threads);
        runtime->started_threads = 0;
    }

    stop_pool_runtime_services(runtime);

    miner_cleanup_algorithm_runtime(runtime->algorithm_runtime_ready);
    runtime->algorithm_runtime_ready = false;

    destroy_pool_contexts(runtime->initialized_pools);
    runtime->initialized_pools = 0;

    miner_runtime_end();
    free(thr_info);
    thr_info = NULL;
}

static void install_miner_signal_handlers(void)
{
    struct sigaction sa;
    struct sigaction ignore_sa;

    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // No SA_RESTART — allows select() to be interrupted
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    ignore_sa.sa_handler = SIG_IGN;
    sigemptyset(&ignore_sa.sa_mask);
    ignore_sa.sa_flags = 0;
    sigaction(SIGPIPE, &ignore_sa, NULL);
}

static void log_miner_startup(void)
{
    detect_cpu_topology();
    if (g_num_cpus > 0) {
        applog(LOG_INFO, "CPU topology: %d cores (%d big + %d LITTLE)",
               g_num_cpus, g_num_big_cores, g_num_little_cores);
    }

    applog(LOG_INFO, "Using algorithm: %s", algo_names[opt_algo]);
}

static bool allocate_mining_runtime_state(void)
{
    thr_info = (struct thr_info *)calloc(opt_n_threads, sizeof(*thr_info));

    if (thr_info) {
        return true;
    }

    applog(LOG_ERR, "Failed to allocate thread structures");
    return false;
}

static void init_pool_runtime(struct mining_runtime *runtime)
{
    /* Claims the hidden slot above the user pools (no-op when the fee is
     * disabled for this algo). Must run before contexts are initialized so
     * the dev slot gets a stratum context like any other pool. */
    devfee_install_pool();

    for (int i = 0; i < num_pools; i++) {
        stratum_init_context(&pools[i].stratum, i, opt_algo == ALGO_VERUS);
        runtime->initialized_pools++;
    }
}

static bool start_stratum_runtime(struct mining_runtime *runtime)
{
    bool work_ready = false;

    miner_runtime_begin();
    devfee_runtime_begin();

    if (!stratum_start_service(runtime->pool)) {
        return false;
    }

    // Startup should honor the same retry/retry-pause policy as steady-state reconnects.
    if (!stratum_wait_ready(0, &work_ready)) {
        if (!miner_should_abort()) {
            applog(LOG_ERR, "Failed to authenticate with pool - cannot start mining");
            miner_request_abort();
        }
        return false;
    }

    if (!work_ready) {
        applog(LOG_WARNING, "No work received yet, starting anyway...");
    }

    return true;
}

static bool run_mining_workers(struct mining_runtime *runtime)
{
    runtime->started_threads = start_worker_threads();
    if (runtime->started_threads != opt_n_threads) {
        return false;
    }

    if (!opt_quiet) {
        miner_hashrate_reporter_reset_stop_request();
        if (pthread_create(&runtime->hashrate_reporter_thread, NULL,
                           miner_hashrate_reporter_thread, NULL)) {
            applog(LOG_ERR, "Failed to create hashrate reporter thread");
            miner_hashrate_reporter_request_stop();
            miner_request_abort();
            return false;
        }
        runtime->hashrate_reporter_started = true;
    }

    join_worker_threads(runtime->started_threads);
    runtime->started_threads = 0;
    if (runtime->hashrate_reporter_started) {
        miner_hashrate_reporter_request_stop();
        pthread_join(runtime->hashrate_reporter_thread, NULL);
        runtime->hashrate_reporter_started = false;
    }
    return true;
}

static void finish_stratum_runtime(struct mining_runtime *runtime)
{
    // Shutdown the stratum socket to unblock the service thread's socket wait.
    // In multi-threaded programs, SIGINT is delivered to an arbitrary thread,
    // so the stratum thread's blocking receive path is never interrupted by the
    // signal directly. shutdown() makes that wait return immediately.
    stop_pool_runtime_services(runtime);
}

static void print_final_stats(void)
{
    struct stratum_runtime_stats runtime_stats;
    time_t runtime_start = 0;
    double instant_hashrate = 0.0;
    uint64_t total_hashes_done = 0;

    pthread_mutex_lock(&stats_lock);
    runtime_start = start_time;
    instant_hashrate = global_hashrate;
    pthread_mutex_unlock(&stats_lock);

    double elapsed = difftime(time(NULL), runtime_start);

    for (int i = 0; i < opt_n_threads; i++) {
        total_hashes_done += miner_thread_hashes_done_load(&thr_info[i]);
    }

    double avg_hashrate = (elapsed > 0.0) ? ((double)total_hashes_done / elapsed) : 0.0;
    char rate_str[32];
    char inst_rate_str[32];
    format_hashrate(avg_hashrate, rate_str, sizeof(rate_str));
    format_hashrate(instant_hashrate, inst_rate_str, sizeof(inst_rate_str));
    stratum_get_runtime_stats(&runtime_stats);

    applog(LOG_INFO, "");
    applog(LOG_INFO, "=== Final Statistics ===");
    applog(LOG_INFO, "Algorithm: %s", algo_names[opt_algo]);
    applog(LOG_INFO, "Runtime: %.0f seconds", elapsed);
    applog(LOG_INFO, "Hashrate: %s", rate_str);
    applog(LOG_INFO, "Instant: %s", inst_rate_str);
    uint32_t total_accepted = runtime_stats.share_accepted_total;
    uint32_t total_rejected = runtime_stats.share_rejected_total;
    applog(LOG_INFO, "Accepted: %u", total_accepted);
    applog(LOG_INFO, "Rejected: %u", total_rejected);
    if (total_accepted + total_rejected > 0) {
        applog(LOG_INFO, "Efficiency: %.1f%%",
               100.0 * total_accepted / (total_accepted + total_rejected));
    }
    applog(LOG_INFO,
           "Work updates: total=%" PRIu64 " clean=%" PRIu64
           " | restarts=%" PRIu64 " (clean=%" PRIu64
           ", height=%" PRIu64 ", target=%" PRIu64 ")",
           runtime_stats.work_updates_total, runtime_stats.work_updates_clean,
           runtime_stats.work_restart_total, runtime_stats.work_restart_clean,
           runtime_stats.work_restart_height, runtime_stats.work_restart_target);
}

int start_mining(void)
{
    struct mining_runtime runtime;
    int rc = 1;

    miner_clear_abort_flag();
    init_mining_runtime(&runtime);

    install_miner_signal_handlers();
    log_miner_startup();

    if (!allocate_mining_runtime_state()) {
        goto cleanup;
    }

    miner_work_generation_reset();

    if (!miner_init_algorithm_runtime(&runtime.algorithm_runtime_ready)) {
        goto cleanup;
    }

    init_pool_runtime(&runtime);

    if (!start_stratum_runtime(&runtime)) {
        goto cleanup;
    }

    api_start_service();

    if (!run_mining_workers(&runtime)) {
        goto cleanup;
    }

    finish_stratum_runtime(&runtime);
    print_final_stats();
    rc = 0;

cleanup:
    log_pending_shutdown_signal();
    cleanup_mining_runtime(&runtime);
    return rc;
}
