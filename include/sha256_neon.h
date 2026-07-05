/*
 * sha256_neon.h - ARM NEON SHA256 for Bitcoin mining
 *
 * Optimized for ARM SBCs (Raspberry Pi, Orange Pi, etc.) and
 * mobile phones running Termux.
 *
 * Supports:
 * - ARMv8 SHA256 crypto extensions (hardware acceleration)
 * - ARM NEON SIMD fallback for older devices
 *
 * Bitcoin uses SHA256d (double SHA256) on 80-byte block headers.
 */

#ifndef SHA256_NEON_H
#define SHA256_NEON_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA256 block and digest sizes */
#define SHA256_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32

/* SHA256 context for incremental hashing */
typedef struct {
    uint32_t state[8];      /* Hash state */
    uint64_t count;         /* Number of bits processed */
    uint8_t buffer[64];     /* Input buffer */
} sha256_neon_ctx;

/**
 * sha256_neon_init - Initialize SHA256 context
 * @ctx: Context to initialize
 */
void sha256_neon_init(sha256_neon_ctx *ctx);

/**
 * sha256_neon_update - Add data to hash
 * @ctx: SHA256 context
 * @data: Input data
 * @len: Length of input data
 */
void sha256_neon_update(sha256_neon_ctx *ctx, const uint8_t *data, size_t len);

/**
 * sha256_neon_final - Finalize hash and get digest
 * @ctx: SHA256 context
 * @digest: Output buffer (32 bytes)
 */
void sha256_neon_final(sha256_neon_ctx *ctx, uint8_t *digest);

/**
 * sha256_neon - Single-call SHA256 hash
 * @data: Input data
 * @len: Length of input
 * @digest: Output buffer (32 bytes)
 */
void sha256_neon(const uint8_t *data, size_t len, uint8_t *digest);

/**
 * sha256d_neon - Double SHA256 (Bitcoin style)
 * @data: Input data
 * @len: Length of input
 * @digest: Output buffer (32 bytes)
 *
 * Computes SHA256(SHA256(data))
 */
void sha256d_neon(const uint8_t *data, size_t len, uint8_t *digest);

/**
 * sha256d_80_neon - Optimized double SHA256 for 80-byte Bitcoin headers
 * @header: 80-byte block header
 * @digest: Output buffer (32 bytes)
 *
 * Optimized path for Bitcoin mining - uses midstate optimization.
 */
void sha256d_80_neon(const uint8_t *header, uint8_t *digest);

/**
 * sha256_midstate_neon - Compute SHA256 midstate for first 64 bytes
 * @data: First 64 bytes of block header
 * @midstate: Output midstate (32 bytes / 8 uint32_t)
 *
 * For Bitcoin mining optimization - the first 64 bytes rarely change,
 * so we can precompute the midstate and only hash the last 16 bytes + nonce.
 */
void sha256_midstate_neon(const uint8_t *data, uint32_t *midstate);

/**
 * sha256d_ms_neon - Double SHA256 using precomputed midstate
 * @midstate: Precomputed midstate from first 64 bytes
 * @tail: Last 16 bytes of header (bytes 64-79)
 * @digest: Output buffer (32 bytes)
 *
 * Optimized for mining - uses midstate to avoid rehashing first 64 bytes.
 */
void sha256d_ms_neon(const uint32_t *midstate, const uint8_t *tail, uint8_t *digest);

/**
 * scanhash_sha256d - Mining scan function for Bitcoin SHA256d
 * @thr_id: Thread ID
 * @work: Work structure with block data and target
 * @max_hashes: Maximum number of sequential nonces to scan
 * @hashes_done: Output - number of hashes computed
 *
 * Returns number of valid nonces found (0-2)
 */
struct work;
int scanhash_sha256d(int thr_id, struct work *work, uint32_t max_hashes,
                     unsigned long *hashes_done);

/**
 * sha256_has_crypto - Check if ARMv8 SHA256 crypto extensions are available
 * Returns 1 if hardware SHA256 is available, 0 otherwise
 */
int sha256_has_crypto(void);

/**
 * sha256_neon_selftest - Run self-test to verify implementation
 * Returns 0 on success, -1 on failure
 */
int sha256_neon_selftest(void);

/**
 * sha256d_scan_selftest - Cross-check the dual-nonce mining path (hand-asm
 * sha256d_dual_asm when the SHA2 ISA is present, plus the portable dual
 * fallback) against sha256d_neon() over full 80-byte headers.
 * Returns 0 on success, negative error code on mismatch.
 */
int sha256d_scan_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_NEON_H */
