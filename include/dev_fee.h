/*
 * Dev fee scheduling for Primo ARM Miner.
 *
 * xmrig-style time slicing: a per-algorithm percentage of wall-clock mining
 * time goes to the developer wallet on a fixed pool, the rest to the user.
 * The slice is always 60 seconds; the percentage sets the cycle length
 * (1% = one slice per 100 minutes, 2% = one per 50). Sessions shorter than
 * one cycle pay nothing.
 *
 * The fee rides the existing stratum pool-switch machinery: a hidden pool
 * slot (never part of failover) that the service thread switches to when a
 * slice begins and away from when it ends. A dev pool that is down can
 * never cost the user mining time — the slice is skipped immediately.
 */

#ifndef DEV_FEE_H
#define DEV_FEE_H

#include "miner.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dev_fee_target {
    const char *url;   /* stratum URL of the dev pool for this algorithm */
    const char *user;  /* dev wallet or account login (+ optional worker) */
    const char *pass;  /* stratum password — account pools use this for coin
                          selection (e.g. zergpool "c=LTC"); plain pools "x" */
    double percent;    /* share of wall-clock mining time (duty cycle), >0 */
};

/* Target for the given algorithm, or NULL when no dev wallet is configured
 * for it (fee disabled for that algorithm). */
const struct dev_fee_target *dev_fee_target_for_algo(algo_t algo);

/* Install the hidden dev pool slot after user pools are configured and
 * before stratum contexts are initialized. Returns the dev pool index, or
 * -1 when the fee is disabled (no target for this algo / benchmark mode). */
int devfee_install_pool(void);

/* Start the fee clock (call when mining starts). */
void devfee_runtime_begin(void);

/* True if pool_index is the hidden dev slot. */
bool devfee_is_dev_pool(int pool_index);

/* Seconds until the next slice boundary, or -1 when the fee is inactive.
 * The stratum message loop bounds its receive timeout with this so slice
 * transitions happen on time. */
int devfee_seconds_until_transition(void);

/* True when a slice boundary has been reached and the service thread
 * should switch pools. */
bool devfee_transition_due(void);

/* Consume the pending transition. Flips slice state and returns the pool
 * index to mine on next: the dev slot at slice start, the remembered user
 * pool at slice end. current_pool_index is recorded as the return target
 * when a slice begins. */
int devfee_take_transition(int current_pool_index);

/* Abandon the current/pending slice without mining it (dev pool down).
 * Reschedules the next attempt a full cycle out and returns the user pool
 * index to switch back to. */
int devfee_abort_slice(void);

#ifdef __cplusplus
}
#endif

#endif /* DEV_FEE_H */
