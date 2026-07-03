/*
 * RandomX (Monero rx/0) runtime — thin orchestration around the vendored
 * reference library (third_party/RandomX, BSD-3, built with ITS OWN flags —
 * see the Makefile notes: our -ffast-math must never touch library code).
 * This wrapper does no floating-point math of its own: everything
 * consensus-critical happens inside librandomx.
 *
 * Memory model: ONE shared 2080 MiB dataset (fast mode) or 256 MiB cache
 * (light mode) + a per-thread VM with a 2 MiB scratchpad. Light mode is
 * selected by PRIMO_RANDOMX_LIGHT=1 or automatically when the dataset
 * allocation fails (low-RAM devices).
 */

#include "miner.h"
#include "randomx_algo.h"

#include "randomx.h"

#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <thread>

/* Built-in key for --benchmark (no pool / no seed_hash). The key only selects
 * the dataset contents; throughput is key-independent. */
static const char k_benchmark_key[] = "primo-arm-miner randomx benchmark key";

/* Reference vector from third_party/RandomX/src/tests/tests.cpp — guards
 * against miscompilation (fast-math leaking in), JIT breakage, or bad flags. */
static const char k_selftest_key[] = "test key 000";
static const char k_selftest_input[] = "This is a test";
static const char k_selftest_hex[] =
    "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f";

static pthread_mutex_t g_rx_lock = PTHREAD_MUTEX_INITIALIZER;
static randomx_flags g_flags = RANDOMX_FLAG_DEFAULT;  /* resolved base flags */
static bool g_light_mode = false;
static bool g_runtime_ready = false;
static int g_n_threads = 0;

static randomx_cache *g_cache = NULL;
static randomx_dataset *g_dataset = NULL;
static uint8_t g_seed[64];
static size_t g_seed_len = 0;      /* 0 = no seed yet (benchmark key used) */
static int g_epoch = 0;            /* bumped on every re-key */

static randomx_vm *g_vm[MAX_THREADS];
static int g_vm_epoch[MAX_THREADS];

/* ---- helpers ---------------------------------------------------------- */

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hash_equals_hex(const uint8_t *hash, const char *hex)
{
    for (int i = 0; i < RANDOMX_HASH_SIZE; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0 || hash[i] != (uint8_t)((hi << 4) | lo))
            return false;
    }
    return true;
}

/* LE 256-bit compare: hash <= target (Monero share rule). target[] is the
 * miner's uint32[8] with word i = bits [32i, 32i+32) of the LE value. */
static bool rx_hash_le_target(const uint8_t *hash, const uint32_t *target)
{
    for (int i = 7; i >= 0; i--) {
        uint32_t h = (uint32_t)hash[i * 4] |
                     ((uint32_t)hash[i * 4 + 1] << 8) |
                     ((uint32_t)hash[i * 4 + 2] << 16) |
                     ((uint32_t)hash[i * 4 + 3] << 24);
        if (h < target[i]) return true;
        if (h > target[i]) return false;
    }
    return true;
}

/* Dataset-init workers are spawned from a mining thread that is already
 * PINNED to one core — inherited affinity would serialize the whole 2 GiB
 * init onto that core (~16x slower, observed). Spread each worker back over
 * every CPU; best-effort (the kernel/cpuset may filter). */
static void rx_unpin_current_thread(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    long n = sysconf(_SC_NPROCESSORS_CONF);
    if (n < 1) n = 1;
    if (n > CPU_SETSIZE) n = CPU_SETSIZE;
    for (long i = 0; i < n; i++)
        CPU_SET((int)i, &set);
    sched_setaffinity(0, sizeof(set), &set);
}

/* Multi-threaded dataset init (13.8s with 8 threads on RK3588; single
 * thread would take ~2 minutes). */
static void rx_init_dataset_mt(void)
{
    unsigned n = std::thread::hardware_concurrency();
    if (n < 1) n = 4;
    if (n > 16) n = 16;

    unsigned long total = randomx_dataset_item_count();
    std::vector<std::thread> workers;
    unsigned long chunk = total / n;
    unsigned long start = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned long count = (i == n - 1) ? (total - start) : chunk;
        workers.emplace_back([start, count]() {
            rx_unpin_current_thread();
            randomx_init_dataset(g_dataset, g_cache, start, count);
        });
        start += count;
    }
    for (auto &w : workers) w.join();
}

/* (Re-)key the cache and, in fast mode, rebuild the dataset.
 * Caller holds g_rx_lock. */
static bool rx_apply_seed_locked(const void *seed, size_t seed_len)
{
    time_t t0 = time(NULL);

    randomx_init_cache(g_cache, seed, seed_len);
    if (!g_light_mode)
        rx_init_dataset_mt();

    g_epoch++;
    applog(LOG_INFO, "RandomX %s initialized in %ld s (epoch %d)",
           g_light_mode ? "cache" : "dataset", (long)(time(NULL) - t0), g_epoch);
    return true;
}

/* Allocate cache (+ dataset in fast mode), preferring large pages, falling
 * back to light mode if the dataset cannot be allocated.
 * Caller holds g_rx_lock. */
static bool rx_alloc_memory_locked(void)
{
    randomx_flags cache_flags = g_flags | RANDOMX_FLAG_LARGE_PAGES;
    g_cache = randomx_alloc_cache(cache_flags);
    if (!g_cache)
        g_cache = randomx_alloc_cache(g_flags);
    if (!g_cache) {
        applog(LOG_ERR, "RandomX: cache allocation failed (need 256 MiB)");
        return false;
    }

    if (!g_light_mode) {
        g_dataset = randomx_alloc_dataset(g_flags | RANDOMX_FLAG_LARGE_PAGES);
        if (!g_dataset)
            g_dataset = randomx_alloc_dataset(g_flags);
        if (!g_dataset) {
            applog(LOG_WARNING,
                   "RandomX: dataset allocation failed (needs ~2.1 GiB) — "
                   "falling back to LIGHT mode (~5x slower)");
            g_light_mode = true;
        }
    }
    return true;
}

/* Create one VM. Tries JIT, then JIT|SECURE (hardened kernels / Android W^X),
 * then interpreter as a last resort. Returns the flags that worked via
 * *used_flags so subsequent VMs skip the failing steps. */
static randomx_vm *rx_create_vm(randomx_flags *used_flags)
{
    randomx_flags base = *used_flags;
    randomx_cache *cache = g_light_mode ? g_cache : NULL;
    randomx_dataset *dataset = g_light_mode ? NULL : g_dataset;
    randomx_flags fm = g_light_mode ? RANDOMX_FLAG_DEFAULT : RANDOMX_FLAG_FULL_MEM;

    randomx_vm *vm = randomx_create_vm(base | fm, cache, dataset);
    if (vm)
        return vm;

    if ((base & RANDOMX_FLAG_JIT) && !(base & RANDOMX_FLAG_SECURE)) {
        vm = randomx_create_vm(base | RANDOMX_FLAG_SECURE | fm, cache, dataset);
        if (vm) {
            applog(LOG_INFO, "RandomX: JIT needs SECURE mode (W^X) on this system");
            *used_flags = base | RANDOMX_FLAG_SECURE;
            return vm;
        }
        vm = randomx_create_vm((randomx_flags)(base & ~RANDOMX_FLAG_JIT) | fm, cache, dataset);
        if (vm) {
            applog(LOG_WARNING, "RandomX: JIT unavailable — using interpreter (slow)");
            *used_flags = (randomx_flags)(base & ~RANDOMX_FLAG_JIT);
            return vm;
        }
    }
    return NULL;
}

/* ---- public API ------------------------------------------------------- */

extern "C" int randomx_init_runtime(int n_threads)
{
    pthread_mutex_lock(&g_rx_lock);

    g_n_threads = n_threads;
    g_flags = randomx_get_flags();  /* autodetect: JIT, HARD_AES, argon2 impl */

    const char *light_env = getenv("PRIMO_RANDOMX_LIGHT");
    g_light_mode = (light_env && light_env[0] == '1');

    /* Self-test with a throwaway light setup — cheap (no dataset), and it
     * exercises cache init + VM + hashing, resolving the JIT/SECURE flags
     * once for all later VMs. A wrong hash here means a broken build
     * (fast-math contamination, JIT bug): never mine with it. */
    randomx_cache *test_cache = randomx_alloc_cache(g_flags);
    if (!test_cache) {
        pthread_mutex_unlock(&g_rx_lock);
        applog(LOG_ERR, "RandomX: self-test cache allocation failed");
        return 0;
    }
    randomx_init_cache(test_cache, k_selftest_key, sizeof(k_selftest_key) - 1);

    randomx_flags vm_flags = g_flags;
    randomx_vm *test_vm = randomx_create_vm(vm_flags, test_cache, NULL);
    if (!test_vm && (vm_flags & RANDOMX_FLAG_JIT)) {
        test_vm = randomx_create_vm(vm_flags | RANDOMX_FLAG_SECURE, test_cache, NULL);
        if (test_vm) {
            applog(LOG_INFO, "RandomX: JIT needs SECURE mode (W^X) on this system");
            g_flags = vm_flags | RANDOMX_FLAG_SECURE;
        } else {
            test_vm = randomx_create_vm((randomx_flags)(vm_flags & ~RANDOMX_FLAG_JIT), test_cache, NULL);
            if (test_vm) {
                applog(LOG_WARNING, "RandomX: JIT unavailable — interpreter mode (slow)");
                g_flags = (randomx_flags)(vm_flags & ~RANDOMX_FLAG_JIT);
            }
        }
    }
    if (!test_vm) {
        randomx_release_cache(test_cache);
        pthread_mutex_unlock(&g_rx_lock);
        applog(LOG_ERR, "RandomX: could not create a VM");
        return 0;
    }

    uint8_t hash[RANDOMX_HASH_SIZE];
    randomx_calculate_hash(test_vm, k_selftest_input, sizeof(k_selftest_input) - 1, hash);
    randomx_destroy_vm(test_vm);
    randomx_release_cache(test_cache);

    if (!hash_equals_hex(hash, k_selftest_hex)) {
        pthread_mutex_unlock(&g_rx_lock);
        applog(LOG_ERR, "RandomX self-test FAILED — refusing to mine (broken build?)");
        return 0;
    }
    applog(LOG_INFO, "RandomX self-test passed (%s%s%s)",
           (g_flags & RANDOMX_FLAG_JIT) ? "JIT" : "interpreter",
           (g_flags & RANDOMX_FLAG_SECURE) ? "+secure" : "",
           (g_flags & RANDOMX_FLAG_HARD_AES) ? ", hardware AES" : ", soft AES");

    if (!rx_alloc_memory_locked()) {
        pthread_mutex_unlock(&g_rx_lock);
        return 0;
    }
    if (g_light_mode)
        applog(LOG_INFO, "RandomX: LIGHT mode (256 MiB cache, ~5x slower than fast mode)");

    memset(g_vm, 0, sizeof(g_vm));
    memset(g_vm_epoch, 0, sizeof(g_vm_epoch));
    g_seed_len = 0;
    g_epoch = 0;
    g_runtime_ready = true;

    pthread_mutex_unlock(&g_rx_lock);
    return 1;
}

extern "C" void randomx_cleanup_runtime(void)
{
    pthread_mutex_lock(&g_rx_lock);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (g_vm[i]) {
            randomx_destroy_vm(g_vm[i]);
            g_vm[i] = NULL;
        }
    }
    if (g_dataset) { randomx_release_dataset(g_dataset); g_dataset = NULL; }
    if (g_cache) { randomx_release_cache(g_cache); g_cache = NULL; }
    g_runtime_ready = false;
    pthread_mutex_unlock(&g_rx_lock);
}

extern "C" void randomx_set_seed(const void *seed, size_t seed_len)
{
    if (seed_len > sizeof(g_seed))
        seed_len = sizeof(g_seed);

    pthread_mutex_lock(&g_rx_lock);
    if (g_runtime_ready &&
        (g_seed_len != seed_len || memcmp(g_seed, seed, seed_len) != 0)) {
        /* NOTE (Phase B): callers must quiesce scanhash threads before
         * re-keying — VMs reference the dataset being rebuilt. Fine today:
         * the first seed is applied before mining threads start hashing. */
        memcpy(g_seed, seed, seed_len);
        g_seed_len = seed_len;
        rx_apply_seed_locked(g_seed, g_seed_len);
    }
    pthread_mutex_unlock(&g_rx_lock);
}

/* Make sure a key is applied and this thread's VM exists and matches the
 * current epoch. Returns the VM or NULL. */
static randomx_vm *rx_thread_vm(int thr_id)
{
    if (thr_id < 0 || thr_id >= MAX_THREADS)
        return NULL;

    pthread_mutex_lock(&g_rx_lock);
    if (!g_runtime_ready) {
        pthread_mutex_unlock(&g_rx_lock);
        return NULL;
    }
    if (g_epoch == 0 && g_seed_len == 0) {
        /* benchmark / no pool seed yet */
        memcpy(g_seed, k_benchmark_key, sizeof(k_benchmark_key) - 1);
        g_seed_len = sizeof(k_benchmark_key) - 1;
        rx_apply_seed_locked(g_seed, g_seed_len);
    }

    randomx_vm *vm = g_vm[thr_id];
    if (!vm) {
        randomx_flags flags = g_flags;
        vm = rx_create_vm(&flags);
        g_flags = flags;  /* remember SECURE/no-JIT resolution */
        g_vm[thr_id] = vm;
        g_vm_epoch[thr_id] = g_epoch;
        if (!vm)
            applog(LOG_ERR, "RandomX: VM creation failed for thread %d "
                            "(out of memory?)", thr_id);
    } else if (g_vm_epoch[thr_id] != g_epoch) {
        if (g_light_mode)
            randomx_vm_set_cache(vm, g_cache);
        else
            randomx_vm_set_dataset(vm, g_dataset);
        g_vm_epoch[thr_id] = g_epoch;
    }
    pthread_mutex_unlock(&g_rx_lock);
    return vm;
}

extern "C" int scanhash_randomx(int thr_id, struct work *work,
                                uint32_t max_hashes, unsigned long *hashes_done)
{
    *hashes_done = 0;
    work->valid_nonces = 0;

    randomx_vm *vm = rx_thread_vm(thr_id);
    if (!vm)
        return 0;

    /* Hashing blob lives at the head of work->data; rx_blob_len is set by
     * build_xmr_work (0 in benchmark mode = default 76 bytes). */
    uint8_t blob[RANDOMX_BLOB_MAX];
    size_t blob_len = work->rx_blob_len ? work->rx_blob_len : 76;
    if (blob_len > RANDOMX_BLOB_MAX)
        blob_len = RANDOMX_BLOB_MAX;
    memcpy(blob, work->data, blob_len);

    uint32_t n = work->data[RANDOMX_NONCE_WORD];
    uint32_t first = n;
    uint8_t hash[RANDOMX_HASH_SIZE];

    /* One RandomX hash is ~5-12 ms — checking restart/abort every iteration
     * is free relative to the hash and keeps job-switch latency low. */
    while ((uint32_t)(n - first) < max_hashes &&
           !miner_work_restart_requested(work->restart_generation) &&
           !miner_should_abort()) {
        blob[39] = (uint8_t)n;
        blob[40] = (uint8_t)(n >> 8);
        blob[41] = (uint8_t)(n >> 16);
        blob[42] = (uint8_t)(n >> 24);

        randomx_calculate_hash(vm, blob, blob_len, hash);

        if (rx_hash_le_target(hash, work->target) &&
            work->valid_nonces < MAX_NONCES) {
            work->nonces[work->valid_nonces] = n;
            /* Result hash travels with the work — Monero submits the full
             * 32-byte hash, not just the nonce (see xmr_stratum_submit). */
            memcpy(work->rx_hash[work->valid_nonces], hash, RANDOMX_HASH_SIZE);
            /* Share difficulty from the hash's top 8 LE bytes (display). */
            uint64_t h64 = 0;
            for (int b = 31; b >= 24; b--)
                h64 = (h64 << 8) | hash[b];
            work->sharediff[work->valid_nonces] =
                h64 ? 18446744073709551616.0 / (double)h64 : 0.0;
            work->valid_nonces++;
            n++;
            break;  /* submit immediately (same rationale as scrypt) */
        }
        n++;
    }

    *hashes_done = (unsigned long)(n - first);
    work->data[RANDOMX_NONCE_WORD] = n;
    return work->valid_nonces;
}
