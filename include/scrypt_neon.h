/*
 * scrypt_neon.h - ARM NEON scrypt for cryptocurrency mining
 *
 * Optimized for ARM SBCs (Raspberry Pi, Orange Pi, etc.) and
 * mobile phones running Termux.
 *
 * Based on Colin Percival's scrypt (RFC 7914)
 */

#ifndef SCRYPT_NEON_H
#define SCRYPT_NEON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Litecoin scrypt parameters: N=1024, r=1, p=1 */
#define SCRYPT_N 1024
#define SCRYPT_R 1
#define SCRYPT_P 1

/* Block size for r=1: 128 bytes */
#define SCRYPT_BLOCK_SIZE (128 * SCRYPT_R)

/**
 * scrypt_1024_1_1_256 - Direct scrypt(N=1024, r=1, p=1) with 256-bit output
 * @input: 80-byte input
 * @output: 32-byte output
 * @midstate: Optional precomputed SHA256 midstate (NULL if not used)
 * @scratchpad: 128KB scratchpad
 *
 * Optimized entry point for Litecoin mining.
 */
void scrypt_1024_1_1_256(const uint8_t *input, uint8_t *output,
                         const uint8_t *midstate, uint8_t *scratchpad);

/**
 * scanhash_scrypt - Mining scan function for scrypt
 * @thr_id: Thread ID
 * @work: Work structure with block data and target
 * @max_hashes: Maximum number of sequential nonces to scan
 * @hashes_done: Output - number of hashes computed
 *
 * Returns number of valid nonces found (0-2)
 */
struct work;
int scanhash_scrypt(int thr_id, struct work *work, uint32_t max_hashes,
                    unsigned long *hashes_done);

/**
 * scrypt_init - Initialize scrypt subsystem
 * Allocates thread-local scratchpads. Call once at startup.
 * @num_threads: Number of mining threads
 * Returns 0 on success, -1 on error
 */
int scrypt_init(int num_threads);

/**
 * scrypt_cleanup - Free scrypt resources
 * Call at shutdown to free scratchpads.
 */
void scrypt_cleanup(void);

/**
 * scrypt_selftest - Verify scrypt implementation is working
 * Returns 0 on success, negative on failure
 */
int scrypt_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_NEON_H */
