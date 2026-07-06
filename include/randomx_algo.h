#ifndef RANDOMX_ALGO_H
#define RANDOMX_ALGO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct work;

/*
 * RandomX (Monero rx/0) algorithm runtime — wraps the vendored reference
 * library (third_party/RandomX, BSD-3). See docs/RANDOMX_M2_PLAN.md.
 *
 * Nonce convention: the 4-byte nonce lives at BYTE offset 39 of the hashing
 * blob (not word-aligned). The miner's per-thread nonce COUNTER therefore
 * uses work->data[RANDOMX_NONCE_WORD], which MUST sit beyond
 * RANDOMX_BLOB_MAX (word 64 = bytes 256-259) so it can never overlap blob
 * bytes; scanhash_randomx() writes the actual nonce bytes into the blob
 * itself. (It was word 39 = bytes 156-159 when only Monero's 76-byte blob
 * existed — Zephyr's 220-byte blob reaches those bytes, and the counter
 * silently corrupted the hashed blob: every share rejected.)
 */
#define RANDOMX_NONCE_WORD 64
/* Monero's hashing blob is 76 bytes, but RandomX forks extend the header:
 * Zephyr appends its oracle pricing record, giving 220-byte blobs (nonce
 * offset unchanged — everything before it is Monero-layout). Buffers that
 * carry the blob (work.data, stratum_job.rx_blob, xmr_job_view.blob) must
 * hold at least this many bytes. */
#define RANDOMX_BLOB_MAX 256

/* Initialize flags (JIT/AES autodetect, large-pages and SECURE fallbacks),
 * run the reference-vector self-test, and prepare per-thread VM slots.
 * Returns false if the self-test fails (wrong hashes — never mine). */
int randomx_init_runtime(int n_threads);
void randomx_cleanup_runtime(void);

/* Set the RandomX key (Monero seed_hash). Triggers cache (+ dataset in fast
 * mode) re-initialization on change. Phase A: benchmark uses a built-in key
 * when this was never called. NOT yet safe to call while scanhash threads
 * are mid-chunk (Phase B adds the pause-and-rekey protocol). */
void randomx_set_seed(const void *seed, size_t seed_len);

int scanhash_randomx(int thr_id, struct work *work, uint32_t max_hashes,
                     unsigned long *hashes_done);

#ifdef __cplusplus
}
#endif

#endif /* RANDOMX_ALGO_H */
