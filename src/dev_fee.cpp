/*
 * Dev fee scheduling for Primo ARM Miner.
 * Copyright (C) 2026 primo-arm-miner contributors.
 *
 * See include/dev_fee.h for the model. All state lives here and is only
 * mutated from the single stratum service thread; reads from the message
 * loop happen on the same thread, so no locking is needed.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dev_fee.h"

/* Dev fee targets per algorithm. An empty URL disables the fee for that
 * algorithm. The wallets/accounts below are the developer's; if you fork
 * this miner, change them or set the URLs empty.
 *
 * Scrypt mines to a litecoinpool.org account worker (account login, not
 * wallet) — LTC payout address is configured pool-side. */
/* Verus carries 2% (this miner is ~10%+ faster than the ccminer ARM builds,
 * and field testers called 1-2% reasonable for a release); the other
 * algorithms stay at 1%. */
static const struct dev_fee_target k_dev_fee_targets[ALGO_COUNT] = {
    /* ALGO_VERUS   */ { "stratum+tcp://pool.verus.io:9998",
                         "RDArJkrPSKPhX8zwUJHLu2SJWrL4GwCgKz.devfee", "x", 2.0 },
    /* ALGO_SHA256D */ { "stratum+tcp://parasite.wtf:42069",
                         "15nR6PuUkjTyjv9dnkYd2GbjbgiMxs4dLi.devfee", "x", 1.0 },
    /* ALGO_SCRYPT  */ { "stratum+tcp://us.litecoinpool.org:3333",
                         /* ",d=16" asks for a CPU-scale share difficulty —
                          * litecoinpool's adaptive vardiff starts at ASIC
                          * levels and can't converge within a 60s slice. */
                         "PrimoDev.1", "x,d=16", 1.0 },
};

/* The slice is always 60s; the per-algo percent sets the cycle length
 * (1% = one slice per 100 min, 2% = one per 50). PRIMO_DEVFEE_TEST=1
 * shrinks the cycle for functional testing (slice timing only — it cannot
 * change the fee percentage, targets, or duty ratio). */
static const int k_slice_seconds_default = 60;

struct devfee_state {
    bool enabled;
    bool in_slice;
    int dev_pool_index;
    int user_pool_index;     /* return target while a slice runs */
    time_t next_transition;  /* slice start when !in_slice, slice end when in_slice */
    int slice_seconds;
    int cycle_seconds;
    double percent;          /* active algo's duty cycle, for logging */
};

static struct devfee_state g_devfee = { false, false, -1, -1, 0, 0, 0, 0.0 };

const struct dev_fee_target *dev_fee_target_for_algo(algo_t algo)
{
    if (algo < 0 || algo >= ALGO_COUNT)
        return NULL;

    const struct dev_fee_target *target = &k_dev_fee_targets[algo];
    if (!target->url[0] || !target->user[0] || target->percent <= 0.0)
        return NULL;

    return target;
}

int devfee_install_pool(void)
{
    const struct dev_fee_target *target = dev_fee_target_for_algo(opt_algo);
    int pool_index;

    g_devfee.enabled = false;
    g_devfee.dev_pool_index = -1;

    if (!target || opt_benchmark)
        return -1;

    if (num_pools >= MAX_POOLS) {
        /* Cannot happen with MAX_USER_POOLS < MAX_POOLS, but stay safe. */
        applog(LOG_WARNING, "No free pool slot for the dev fee; fee disabled");
        return -1;
    }

    pool_index = num_pools;
    memset(&pools[pool_index], 0, sizeof(pools[pool_index]));
    snprintf(pools[pool_index].name, sizeof(pools[pool_index].name), "dev fee");
    snprintf(pools[pool_index].url, sizeof(pools[pool_index].url), "%s", target->url);
    snprintf(pools[pool_index].user, sizeof(pools[pool_index].user), "%s", target->user);
    snprintf(pools[pool_index].pass, sizeof(pools[pool_index].pass), "%s",
             target->pass && target->pass[0] ? target->pass : "x");
    pools[pool_index].configured = true;
    /* disabled keeps the slot out of failover rotation and out of the
     * "first usable pool" startup selection; the dev fee scheduler switches
     * to it explicitly by index. */
    pools[pool_index].disabled = true;
    num_pools = pool_index + 1;

    g_devfee.dev_pool_index = pool_index;
    g_devfee.percent = target->percent;
    g_devfee.slice_seconds = k_slice_seconds_default;
    g_devfee.cycle_seconds =
        (int)((double)k_slice_seconds_default * 100.0 / target->percent);

    const char *test_env = getenv("PRIMO_DEVFEE_TEST");
    if (test_env && test_env[0] == '1') {
        /* Functional-test cadence for validating the pool-switch machinery.
         * Deliberately NOT 1% — a slice must be long enough to authorize
         * and receive work. Timing only; targets cannot be overridden. */
        g_devfee.slice_seconds = 20;
        g_devfee.cycle_seconds = 120;
        applog(LOG_WARNING, "Dev fee TEST cadence active: %ds slice per %ds cycle",
               g_devfee.slice_seconds, g_devfee.cycle_seconds);
    }

    g_devfee.enabled = true;
    applog(LOG_INFO, "Dev fee: %.1f%% (%ds per %d min) for %s",
           g_devfee.percent, g_devfee.slice_seconds,
           g_devfee.cycle_seconds / 60, algo_names[opt_algo]);

    return pool_index;
}

void devfee_runtime_begin(void)
{
    if (!g_devfee.enabled)
        return;

    g_devfee.in_slice = false;

    /* First slice at a uniformly random point within the first cycle,
     * re-drawn every start. A deterministic first transition (the old
     * "exactly one cycle in") lets a scheduled restart just before that
     * mark skip the fee forever; with a uniform draw the only winning
     * restart cadence is more often than one slice length, where reconnect
     * and warmup overhead cost far more than the fee. Long-run duty cycle
     * is unchanged. Deliberately NOT logged: randomization only deters
     * gaming while the scheduled time is unobservable — slices announce
     * themselves when they begin, never in advance. */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned seed = (unsigned)ts.tv_nsec ^ (unsigned)ts.tv_sec ^
                    ((unsigned)getpid() << 16) ^ (unsigned)time(NULL);
    int first_delay = g_devfee.slice_seconds;
    int span = g_devfee.cycle_seconds - g_devfee.slice_seconds;
    if (span > 0)
        first_delay += (int)(rand_r(&seed) % (unsigned)(span + 1));

    g_devfee.next_transition = time(NULL) + first_delay;
}

bool devfee_is_dev_pool(int pool_index)
{
    return g_devfee.enabled && pool_index == g_devfee.dev_pool_index;
}

int devfee_seconds_until_transition(void)
{
    if (!g_devfee.enabled)
        return -1;

    time_t now = time(NULL);
    if (now >= g_devfee.next_transition)
        return 0;

    return (int)(g_devfee.next_transition - now);
}

bool devfee_transition_due(void)
{
    return devfee_seconds_until_transition() == 0;
}

int devfee_take_transition(int current_pool_index)
{
    time_t now = time(NULL);

    if (!g_devfee.in_slice) {
        g_devfee.in_slice = true;
        g_devfee.user_pool_index = current_pool_index;
        g_devfee.next_transition = now + g_devfee.slice_seconds;
        applog(LOG_NOTICE, "Dev fee: mining %ds slice (%.1f%% of runtime)",
               g_devfee.slice_seconds, g_devfee.percent);
        return g_devfee.dev_pool_index;
    }

    g_devfee.in_slice = false;
    g_devfee.next_transition = now + g_devfee.cycle_seconds;
    applog(LOG_NOTICE, "Dev fee: slice complete, returning to %s",
           pools[g_devfee.user_pool_index].url);
    return g_devfee.user_pool_index;
}

int devfee_abort_slice(void)
{
    /* Dev pool unreachable: never cost the user mining time. Skip this
     * slice entirely and try again a full cycle from now. */
    g_devfee.in_slice = false;
    g_devfee.next_transition = time(NULL) + g_devfee.cycle_seconds;
    return g_devfee.user_pool_index;
}
