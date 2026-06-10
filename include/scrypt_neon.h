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

/* Memory required: 128 * r * N = 128 KB for Litecoin */
#define SCRYPT_SCRATCHPAD_SIZE (128 * SCRYPT_R * SCRYPT_N)

/* Block size for r=1: 128 bytes */
#define SCRYPT_BLOCK_SIZE (128 * SCRYPT_R)

/**
 * scrypt_hash - Calculate scrypt hash for mining
 * @input: 80-byte block header
 * @output: 32-byte hash result
 * @scratchpad: Pre-allocated 128KB scratchpad (or NULL to allocate internally)
 *
 * Uses Litecoin parameters: N=1024, r=1, p=1
 * Returns 0 on success, -1 on error
 */
int scrypt_hash(const uint8_t *input, uint8_t *output, uint8_t *scratchpad);

/**
 * scrypt_hash_sp - Calculate scrypt hash with custom scratchpad
 * @input: Input data
 * @input_len: Length of input (typically 80 bytes for mining)
 * @output: 32-byte hash result
 * @scratchpad: Pre-allocated scratchpad of SCRYPT_SCRATCHPAD_SIZE bytes
 *
 * This version requires caller to provide scratchpad for better performance
 * when hashing multiple blocks (avoids repeated allocation).
 */
void scrypt_hash_sp(const uint8_t *input, size_t input_len,
                    uint8_t *output, uint8_t *scratchpad);

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

/* Check if ARM NEON is available at runtime */
int scrypt_has_neon(void);

/**
 * scrypt_selftest - Verify scrypt implementation is working
 * Returns 0 on success, negative on failure
 */
int scrypt_selftest(void);

/* Internal functions (exposed for testing) */

/**
 * salsa20_8_neon - Salsa20/8 core function with NEON optimization
 * @B: 64-byte block (16 x uint32_t), modified in place
 *
 * Performs 8 rounds of Salsa20 mixing.
 */
void salsa20_8_neon(uint32_t B[16]);

/**
 * scrypt_block_mix_neon - scryptBlockMix function
 * @B: Input/output block (128*r bytes for r=1)
 * @Y: Temporary buffer (128*r bytes)
 * @r: Block size parameter (typically 1)
 */
void scrypt_block_mix_neon(uint32_t *B, uint32_t *Y, int r);

/**
 * scrypt_romix_neon - scryptROMix function (memory-hard)
 * @B: Input/output block (128*r bytes)
 * @V: Scratchpad (128*r*N bytes)
 * @Y: Temporary buffer (128*r bytes)
 * @N: Cost parameter (typically 1024)
 * @r: Block size parameter (typically 1)
 */
void scrypt_romix_neon(uint32_t *B, uint32_t *V, uint32_t *Y, int N, int r);

#ifdef __cplusplus
}
#endif

#endif /* SCRYPT_NEON_H */
