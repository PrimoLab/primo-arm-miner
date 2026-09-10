/*
 * scrypt_neon.c - ARMv8 optimized scrypt for cryptocurrency mining
 *
 * Optimized for ARM SBCs and Termux with:
 * - ARMv8 SHA256 crypto extensions (hardware SHA)
 * - NEON SIMD for Salsa20/8
 * - Cache prefetching for memory-hard operations
 * - Aggressive inlining and loop unrolling
 */

/* _GNU_SOURCE (superset of the POSIX feature set below) for sched_getcpu(). */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200112L

#include "scrypt_neon.h"
#include <string.h>
#include <stdlib.h>
#include <arm_neon.h>
#include "byteorder.h"

/* ARMv8 crypto extensions for SHA256 */
#ifdef __ARM_FEATURE_CRYPTO
#define USE_ARM_SHA256 1
#else
#define USE_ARM_SHA256 0
#endif

/* Force inline for hot functions */
#define ALWAYS_INLINE __attribute__((always_inline)) inline
#define HOT __attribute__((hot))

/* Fused BlockMix assembly: Salsa20/8(B[0..15]) + B[16..31]^=B[0..15] + Salsa20/8(B[16..31])
 * Eliminates 16 redundant loads at the Salsa boundary by keeping state in registers. */
extern void scrypt_blockmix_asm(uint32_t *B);



/*============================================================================
 * ARMv8 Hardware SHA-256 (when available)
 *============================================================================*/

#if USE_ARM_SHA256

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

typedef struct { uint32x4_t state[2]; uint64_t count; uint8_t buf[64]; } sha256_ctx;

/* ARMv8 SHA256 hardware acceleration */
static HOT void sha256_transform_arm(uint32x4_t state[2], const uint8_t *data) {
    uint32x4_t state0, state1, state0_save, state1_save;
    uint32x4_t msg0, msg1, msg2, msg3;
    uint32x4_t tmp0, tmp1;
    
    /* Load state */
    state0 = state[0];
    state1 = state[1];
    state0_save = state0;
    state1_save = state1;
    
    /* Load message (big-endian) */
    msg0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data)));
    msg1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 16)));
    msg2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 32)));
    msg3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(data + 48)));
    
    /* Rounds 0-3 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&sha256_k[0]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg0 = vsha256su0q_u32(msg0, msg1);
    
    /* Rounds 4-7 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&sha256_k[4]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);
    msg1 = vsha256su0q_u32(msg1, msg2);
    
    /* Rounds 8-11 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&sha256_k[8]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);
    msg2 = vsha256su0q_u32(msg2, msg3);
    
    /* Rounds 12-15 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&sha256_k[12]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);
    msg3 = vsha256su0q_u32(msg3, msg0);
    
    /* Rounds 16-19 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&sha256_k[16]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);
    msg0 = vsha256su0q_u32(msg0, msg1);
    
    /* Rounds 20-23 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&sha256_k[20]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);
    msg1 = vsha256su0q_u32(msg1, msg2);
    
    /* Rounds 24-27 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&sha256_k[24]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);
    msg2 = vsha256su0q_u32(msg2, msg3);
    
    /* Rounds 28-31 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&sha256_k[28]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);
    msg3 = vsha256su0q_u32(msg3, msg0);
    
    /* Rounds 32-35 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&sha256_k[32]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);
    msg0 = vsha256su0q_u32(msg0, msg1);
    
    /* Rounds 36-39 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&sha256_k[36]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg0 = vsha256su1q_u32(msg0, msg2, msg3);
    msg1 = vsha256su0q_u32(msg1, msg2);
    
    /* Rounds 40-43 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&sha256_k[40]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg1 = vsha256su1q_u32(msg1, msg3, msg0);
    msg2 = vsha256su0q_u32(msg2, msg3);
    
    /* Rounds 44-47 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&sha256_k[44]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg2 = vsha256su1q_u32(msg2, msg0, msg1);
    msg3 = vsha256su0q_u32(msg3, msg0);
    
    /* Rounds 48-51 */
    tmp0 = vaddq_u32(msg0, vld1q_u32(&sha256_k[48]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    msg3 = vsha256su1q_u32(msg3, msg1, msg2);
    
    /* Rounds 52-55 */
    tmp0 = vaddq_u32(msg1, vld1q_u32(&sha256_k[52]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    
    /* Rounds 56-59 */
    tmp0 = vaddq_u32(msg2, vld1q_u32(&sha256_k[56]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    
    /* Rounds 60-63 */
    tmp0 = vaddq_u32(msg3, vld1q_u32(&sha256_k[60]));
    tmp1 = state0;
    state0 = vsha256hq_u32(state0, state1, tmp0);
    state1 = vsha256h2q_u32(state1, tmp1, tmp0);
    
    /* Add saved state */
    state[0] = vaddq_u32(state0, state0_save);
    state[1] = vaddq_u32(state1, state1_save);
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->state[0] = vld1q_u32(&sha256_h0[0]);
    ctx->state[1] = vld1q_u32(&sha256_h0[4]);
    ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0, index = (ctx->count >> 3) & 0x3f;
    ctx->count += len << 3;
    if (index) {
        size_t left = 64 - index;
        if (len < left) { memcpy(ctx->buf + index, data, len); return; }
        memcpy(ctx->buf + index, data, left);
        sha256_transform_arm(ctx->state, ctx->buf);
        i = left;
    }
    for (; i + 64 <= len; i += 64)
        sha256_transform_arm(ctx->state, data + i);
    if (i < len) memcpy(ctx->buf, data + i, len - i);
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) finalcount[i] = (ctx->count >> (56 - i * 8)) & 0xff;
    sha256_update(ctx, (const uint8_t *)"\x80", 1);
    while (((ctx->count >> 3) & 0x3f) != 56)
        sha256_update(ctx, (const uint8_t *)"\x00", 1);
    sha256_update(ctx, finalcount, 8);
    /* Store in big-endian byte order (standard SHA256 output format).
     * SHA256 transform reads message bytes as BE words, so output must also
     * be BE-per-word for HMAC consistency (inner hash fed back as outer input). */
    vst1q_u8(digest, vrev32q_u8(vreinterpretq_u8_u32(ctx->state[0])));
    vst1q_u8(digest + 16, vrev32q_u8(vreinterpretq_u8_u32(ctx->state[1])));
}

static void sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

#else /* Software SHA256 fallback */


static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint32_t sha256_h0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x)       (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x)      (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static inline uint32_t be32dec(const void *pp) {
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void be32enc(void *pp, uint32_t x) {
    uint8_t *p = (uint8_t *)pp;
    p[0] = (x >> 24) & 0xff; p[1] = (x >> 16) & 0xff;
    p[2] = (x >> 8) & 0xff;  p[3] = x & 0xff;
}

/* Little-endian encoding for mining hash output */
static inline void le32enc(void *pp, uint32_t x) {
    uint8_t *p = (uint8_t *)pp;
    p[0] = x & 0xff;         p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff; p[3] = (x >> 24) & 0xff;
}

typedef struct { uint32_t state[8]; uint64_t count; uint8_t buf[64]; } sha256_ctx;

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
    uint32_t W[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++) W[i] = be32dec(block + i * 4);
    for (i = 16; i < 64; i++) W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + sha256_k[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    memcpy(ctx->state, sha256_h0, sizeof(sha256_h0)); ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i = 0, index = (ctx->count >> 3) & 0x3f;
    ctx->count += len << 3;
    if (index) {
        size_t left = 64 - index;
        if (len < left) { memcpy(ctx->buf + index, data, len); return; }
        memcpy(ctx->buf + index, data, left);
        sha256_transform(ctx->state, ctx->buf); i = left;
    }
    for (; i + 64 <= len; i += 64) sha256_transform(ctx->state, data + i);
    if (i < len) memcpy(ctx->buf, data + i, len - i);
}

static void sha256_final(sha256_ctx *ctx, uint8_t digest[32]) {
    uint8_t finalcount[8]; int i;
    for (i = 0; i < 8; i++) finalcount[i] = (ctx->count >> (56 - i * 8)) & 0xff;
    sha256_update(ctx, (const uint8_t *)"\x80", 1);
    while (((ctx->count >> 3) & 0x3f) != 56) sha256_update(ctx, (const uint8_t *)"\x00", 1);
    sha256_update(ctx, finalcount, 8);
    /* Output state in big-endian byte order (standard SHA256 output format).
     * SHA256 transform reads message bytes as BE words, so output must also
     * be BE-per-word for HMAC consistency (inner hash fed back as outer input). */
    for (int i = 0; i < 8; i++)
        be32enc(digest + i * 4, ctx->state[i]);
}

static void sha256(const uint8_t *data, size_t len, uint8_t digest[32]) {
    sha256_ctx ctx; sha256_init(&ctx); sha256_update(&ctx, data, len); sha256_final(&ctx, digest);
}

#endif /* USE_ARM_SHA256 */

/*============================================================================
 * HMAC-SHA256 and PBKDF2
 *============================================================================*/

static void hmac_sha256_init(sha256_ctx *ctx, const uint8_t *key, size_t keylen) {
    uint8_t k_ipad[64], tk[32]; int i;
    if (keylen > 64) { sha256(key, keylen, tk); key = tk; keylen = 32; }
    memset(k_ipad, 0x36, 64);
    for (i = 0; i < (int)keylen; i++) k_ipad[i] ^= key[i];
    sha256_init(ctx); sha256_update(ctx, k_ipad, 64);
}

static void hmac_sha256_final(sha256_ctx *ctx, const uint8_t *key, size_t keylen, uint8_t digest[32]) {
    uint8_t k_opad[64], tk[32], inner_hash[32]; sha256_ctx outer_ctx; int i;
    sha256_final(ctx, inner_hash);
    if (keylen > 64) { sha256(key, keylen, tk); key = tk; keylen = 32; }
    memset(k_opad, 0x5c, 64);
    for (i = 0; i < (int)keylen; i++) k_opad[i] ^= key[i];
    sha256_init(&outer_ctx); sha256_update(&outer_ctx, k_opad, 64);
    sha256_update(&outer_ctx, inner_hash, 32); sha256_final(&outer_ctx, digest);
}

static void pbkdf2_sha256(const uint8_t *password, size_t password_len,
                          const uint8_t *salt, size_t salt_len,
                          uint32_t iterations, uint8_t *dk, size_t dk_len) {
    sha256_ctx ctx; uint8_t U[32], T[32];
    uint32_t i, j, k, blocks = (dk_len + 31) / 32;
    uint8_t count_be[4];
    for (i = 1; i <= blocks; i++) {
        count_be[0] = (i >> 24) & 0xff; count_be[1] = (i >> 16) & 0xff;
        count_be[2] = (i >> 8) & 0xff;  count_be[3] = i & 0xff;
        hmac_sha256_init(&ctx, password, password_len);
        sha256_update(&ctx, salt, salt_len);
        sha256_update(&ctx, count_be, 4);
        hmac_sha256_final(&ctx, password, password_len, U);
        memcpy(T, U, 32);
        for (j = 2; j <= iterations; j++) {
            hmac_sha256_init(&ctx, password, password_len);
            sha256_update(&ctx, U, 32);
            hmac_sha256_final(&ctx, password, password_len, U);
            for (k = 0; k < 32; k++) T[k] ^= U[k];
        }
        size_t copy_len = (i == blocks) ? (dk_len - (i - 1) * 32) : 32;
        memcpy(dk + (i - 1) * 32, T, copy_len);
    }
}


/* Scalar Salsa20/8 lives in scrypt_blockmix_asm.S (fused with the BlockMix
 * XOR); the 4-lane NEON variant is salsa208_soa below. The former standalone
 * C Salsa + generic r>1 BlockMix/ROMix fallback were removed as unreachable:
 * the miner is hardwired to r=1 (Litecoin), so every live path goes through
 * the asm or the SoA kernel. */

/*============================================================================
 * Specialized r=1 ROMix — eliminates Y buffer and rearrangement
 *
 * For r=1 (Litecoin): BlockMix has only 2 Salsa20/8 calls and the output
 * rearrangement is identity (even block 0, odd block 1 → same order).
 * This eliminates the Y buffer, rearrangement memcpy, NEON load/store
 * wrapper, and generic loop overhead.
 *============================================================================*/

static HOT void scrypt_romix_r1_fast(uint32_t *B, uint32_t *V, int N) {
    const int bs = 32; /* words per 128-byte block */
    int i, k;

    /* Phase 1: fill V array with sequential writes (cache-friendly) */
    for (i = 0; i < N; i++) {
        uint32_t *Vi = V + (size_t)i * bs;

        /* Fused V-save + BlockMix XOR: read each B word once, save to V,
         * and compute B[0..15] ^= B[16..31] for BlockMix input.
         * All scalar to avoid NEON↔scalar store forwarding penalty. */
        for (k = 0; k < 16; k++) {
            uint32_t bk = B[k], bk16 = B[k + 16];
            Vi[k] = bk;
            Vi[k + 16] = bk16;
            B[k] = bk ^ bk16;
        }
        scrypt_blockmix_asm(B);
    }

    /* Phase 2: random reads from V (memory-hard) */
    for (i = 0; i < N; i++) {
        int j = B[16] & (N - 1);
        uint32_t *Vj = V + (size_t)j * bs;

        __builtin_prefetch(Vj, 0, 0);
        __builtin_prefetch(Vj + 16, 0, 0);

        /* Fused B^=V[j] + BlockMix XOR: merge the 32-word V[j] XOR with
         * the 16-word BlockMix XOR into one pass over 16 words.
         * B[k] = B[k] ^ Vj[k] ^ (B[k+16] ^ Vj[k+16])
         * B[k+16] = B[k+16] ^ Vj[k+16]
         * Saves 16 stores (B[0..15] written once instead of twice). */
        for (k = 0; k < 16; k++) {
            uint32_t bk16 = B[k + 16] ^ Vj[k + 16];
            B[k] = B[k] ^ Vj[k] ^ bk16;
            B[k + 16] = bk16;
        }
        scrypt_blockmix_asm(B);
    }
}

/*============================================================================
 * Dual-nonce scalar ROMix — hides L2 latency via interleaving
 *
 * Phase 1: Sequential per nonce (cache-friendly sequential V writes).
 * Phase 2: Interleaved — nonce B's V[j] prefetch gets ~240 cycles of
 *          lead time while nonce A's Salsa calls execute, completely
 *          hiding L2 cache miss latency for every other V lookup.
 *
 * Uses external scrypt_blockmix_asm (fused BlockMix) to avoid forwarding penalties.
 * Total V footprint: 2 × 128KB = 256KB, fits in 512KB per-core L2.
 *============================================================================*/

static HOT void scrypt_romix_dual_scalar(uint32_t *Ba, uint32_t *Va,
                                          uint32_t *Bb, uint32_t *Vb,
                                          int N) {
    const int bs = 32; /* 128 bytes / 4 = 32 words per V entry */
    int i, k;

    /* Phase 1a: fill Va with sequential writes */
    for (i = 0; i < N; i++) {
        uint32_t *Vi = Va + (size_t)i * bs;
        for (k = 0; k < 16; k++) {
            uint32_t bk = Ba[k], bk16 = Ba[k + 16];
            Vi[k] = bk;
            Vi[k + 16] = bk16;
            Ba[k] = bk ^ bk16;
        }
        scrypt_blockmix_asm(Ba);
    }

    /* Phase 1b: fill Vb with sequential writes */
    for (i = 0; i < N; i++) {
        uint32_t *Vi = Vb + (size_t)i * bs;
        for (k = 0; k < 16; k++) {
            uint32_t bk = Bb[k], bk16 = Bb[k + 16];
            Vi[k] = bk;
            Vi[k + 16] = bk16;
            Bb[k] = bk ^ bk16;
        }
        scrypt_blockmix_asm(Bb);
    }

    /* Phase 2: random V reads, interleaved per iteration.
     * Prefetch both V[ja] and V[jb] up front, then process nonce A.
     * By the time we reach nonce B's XOR loop, V[jb] has had ~240 cycles
     * (A's full BlockMix) to migrate from L2 to L1d. */
    for (i = 0; i < N; i++) {
        int ja = Ba[16] & (N - 1);
        int jb = Bb[16] & (N - 1);
        uint32_t *Vja = Va + (size_t)ja * bs;
        uint32_t *Vjb = Vb + (size_t)jb * bs;

        /* Prefetch both — Vjb gets ~240 cycle head start */
        __builtin_prefetch(Vja, 0, 0);
        __builtin_prefetch(Vja + 16, 0, 0);
        __builtin_prefetch(Vjb, 0, 0);
        __builtin_prefetch(Vjb + 16, 0, 0);

        /* Nonce A: fused XOR + BlockMix */
        for (k = 0; k < 16; k++) {
            uint32_t bk16 = Ba[k + 16] ^ Vja[k + 16];
            Ba[k] = Ba[k] ^ Vja[k] ^ bk16;
            Ba[k + 16] = bk16;
        }
        scrypt_blockmix_asm(Ba);

        /* Nonce B: fused XOR + BlockMix (Vjb now in L1d) */
        for (k = 0; k < 16; k++) {
            uint32_t bk16 = Bb[k + 16] ^ Vjb[k + 16];
            Bb[k] = Bb[k] ^ Vjb[k] ^ bk16;
            Bb[k + 16] = bk16;
        }
        scrypt_blockmix_asm(Bb);
    }
}

/*============================================================================
 * 4-lane SoA NEON ROMix
 *
 * Four independent nonces packed lane-wise into uint32x4_t state: every NEON
 * instruction performs one Salsa step for all 4 blocks at once. The SoA
 * kernel has zero shuffles and needs ~1 instruction per block per ARX step
 * vs 2 for scalar — measured +25% over the dual-scalar path on A76 and +14%
 * on A55 (no cross-lane dependencies suits the in-order pipe too).
 *
 * V is kept per-lane (AoS): phase 2 reads V[j] at a *different* j per lane,
 * so per-lane blocks must stay contiguous. SoA<->lanes transpose runs at the
 * V boundary each iteration (~15% overhead, already included in the numbers
 * above). Total V footprint: 4 x 128KB = 512KB.
 *============================================================================*/

#define SCRYPT_ROTL4(x, n) vsriq_n_u32(vshlq_n_u32((x), (n)), (x), 32 - (n))

static HOT void salsa208_soa(uint32x4_t B[16]) {
    uint32x4_t x[16];
    for (int i = 0; i < 16; i++) x[i] = B[i];
#define SCRYPT_QR4(a, b, c, d) do {                                          \
        x[b] = veorq_u32(x[b], SCRYPT_ROTL4(vaddq_u32(x[a], x[d]), 7));      \
        x[c] = veorq_u32(x[c], SCRYPT_ROTL4(vaddq_u32(x[b], x[a]), 9));      \
        x[d] = veorq_u32(x[d], SCRYPT_ROTL4(vaddq_u32(x[c], x[b]), 13));     \
        x[a] = veorq_u32(x[a], SCRYPT_ROTL4(vaddq_u32(x[d], x[c]), 18));     \
    } while (0)
    for (int i = 0; i < 8; i += 2) {
        SCRYPT_QR4(0, 4, 8, 12); SCRYPT_QR4(5, 9, 13, 1);
        SCRYPT_QR4(10, 14, 2, 6); SCRYPT_QR4(15, 3, 7, 11);
        SCRYPT_QR4(0, 1, 2, 3);  SCRYPT_QR4(5, 6, 7, 4);
        SCRYPT_QR4(10, 11, 8, 9); SCRYPT_QR4(15, 12, 13, 14);
    }
#undef SCRYPT_QR4
    for (int i = 0; i < 16; i++) B[i] = vaddq_u32(B[i], x[i]);
}

static HOT void blockmix_soa(uint32x4_t B0[16], uint32x4_t B1[16]) {
    uint32x4_t X[16];
    for (int k = 0; k < 16; k++) X[k] = veorq_u32(B1[k], B0[k]);
    salsa208_soa(X);
    for (int k = 0; k < 16; k++) B0[k] = X[k];
    for (int k = 0; k < 16; k++) X[k] = veorq_u32(X[k], B1[k]);
    salsa208_soa(X);
    for (int k = 0; k < 16; k++) B1[k] = X[k];
}

/* 4x4 word transpose between SoA vectors and 4 per-lane streams.
 * vtrnq pairing must be (0,1)/(2,3) in BOTH directions — mismatched pairing
 * silently swaps lanes 1 and 2 through a round trip. */
static inline void soa_to_lanes(const uint32x4_t v[4],
                                uint32_t *l0, uint32_t *l1,
                                uint32_t *l2, uint32_t *l3) {
    uint32x4x2_t t0 = vtrnq_u32(v[0], v[1]);
    uint32x4x2_t t1 = vtrnq_u32(v[2], v[3]);
    vst1q_u32(l0, vcombine_u32(vget_low_u32(t0.val[0]),  vget_low_u32(t1.val[0])));
    vst1q_u32(l1, vcombine_u32(vget_low_u32(t0.val[1]),  vget_low_u32(t1.val[1])));
    vst1q_u32(l2, vcombine_u32(vget_high_u32(t0.val[0]), vget_high_u32(t1.val[0])));
    vst1q_u32(l3, vcombine_u32(vget_high_u32(t0.val[1]), vget_high_u32(t1.val[1])));
}

static inline void lanes_to_soa(uint32x4_t v[4],
                                const uint32_t *l0, const uint32_t *l1,
                                const uint32_t *l2, const uint32_t *l3) {
    uint32x4_t a = vld1q_u32(l0), b = vld1q_u32(l1), c = vld1q_u32(l2), d = vld1q_u32(l3);
    uint32x4x2_t t0 = vtrnq_u32(a, b);
    uint32x4x2_t t1 = vtrnq_u32(c, d);
    v[0] = vcombine_u32(vget_low_u32(t0.val[0]),  vget_low_u32(t1.val[0]));
    v[1] = vcombine_u32(vget_low_u32(t0.val[1]),  vget_low_u32(t1.val[1]));
    v[2] = vcombine_u32(vget_high_u32(t0.val[0]), vget_high_u32(t1.val[0]));
    v[3] = vcombine_u32(vget_high_u32(t0.val[1]), vget_high_u32(t1.val[1]));
}

static HOT void scrypt_romix_soa4(uint32_t *Bl[4], uint32_t *Vl[4], int N) {
    const int bs = 32; /* words per V element (r=1: 128 bytes) */
    uint32x4_t B0[16], B1[16];

    /* pack 4 lanes into SoA */
    for (int g = 0; g < 4; g++) {
        uint32x4_t v[4];
        lanes_to_soa(v, Bl[0] + g*4, Bl[1] + g*4, Bl[2] + g*4, Bl[3] + g*4);
        for (int t = 0; t < 4; t++) B0[g*4 + t] = v[t];
        lanes_to_soa(v, Bl[0] + 16 + g*4, Bl[1] + 16 + g*4,
                        Bl[2] + 16 + g*4, Bl[3] + 16 + g*4);
        for (int t = 0; t < 4; t++) B1[g*4 + t] = v[t];
    }

    /* phase 1: V[i] = B (per-lane), B = BlockMix(B) */
    for (int i = 0; i < N; i++) {
        for (int g = 0; g < 4; g++) {
            uint32x4_t v[4];
            for (int t = 0; t < 4; t++) v[t] = B0[g*4 + t];
            soa_to_lanes(v, Vl[0] + (size_t)i*bs + g*4, Vl[1] + (size_t)i*bs + g*4,
                            Vl[2] + (size_t)i*bs + g*4, Vl[3] + (size_t)i*bs + g*4);
            for (int t = 0; t < 4; t++) v[t] = B1[g*4 + t];
            soa_to_lanes(v, Vl[0] + (size_t)i*bs + 16 + g*4, Vl[1] + (size_t)i*bs + 16 + g*4,
                            Vl[2] + (size_t)i*bs + 16 + g*4, Vl[3] + (size_t)i*bs + 16 + g*4);
        }
        blockmix_soa(B0, B1);
    }

    /* phase 2: per-lane j, gather + transpose + XOR, BlockMix */
    for (int i = 0; i < N; i++) {
        uint32_t j0 = vgetq_lane_u32(B1[0], 0) & (uint32_t)(N - 1);
        uint32_t j1 = vgetq_lane_u32(B1[0], 1) & (uint32_t)(N - 1);
        uint32_t j2 = vgetq_lane_u32(B1[0], 2) & (uint32_t)(N - 1);
        uint32_t j3 = vgetq_lane_u32(B1[0], 3) & (uint32_t)(N - 1);
        const uint32_t *p0 = Vl[0] + (size_t)j0 * bs;
        const uint32_t *p1 = Vl[1] + (size_t)j1 * bs;
        const uint32_t *p2 = Vl[2] + (size_t)j2 * bs;
        const uint32_t *p3 = Vl[3] + (size_t)j3 * bs;
        __builtin_prefetch(p0, 0, 0); __builtin_prefetch(p0 + 16, 0, 0);
        __builtin_prefetch(p1, 0, 0); __builtin_prefetch(p1 + 16, 0, 0);
        __builtin_prefetch(p2, 0, 0); __builtin_prefetch(p2 + 16, 0, 0);
        __builtin_prefetch(p3, 0, 0); __builtin_prefetch(p3 + 16, 0, 0);
        for (int g = 0; g < 4; g++) {
            uint32x4_t v[4];
            lanes_to_soa(v, p0 + g*4, p1 + g*4, p2 + g*4, p3 + g*4);
            for (int t = 0; t < 4; t++) B0[g*4 + t] = veorq_u32(B0[g*4 + t], v[t]);
            lanes_to_soa(v, p0 + 16 + g*4, p1 + 16 + g*4, p2 + 16 + g*4, p3 + 16 + g*4);
            for (int t = 0; t < 4; t++) B1[g*4 + t] = veorq_u32(B1[g*4 + t], v[t]);
        }
        blockmix_soa(B0, B1);
    }

    /* unpack back to lanes */
    for (int g = 0; g < 4; g++) {
        uint32x4_t v[4];
        for (int t = 0; t < 4; t++) v[t] = B0[g*4 + t];
        soa_to_lanes(v, Bl[0] + g*4, Bl[1] + g*4, Bl[2] + g*4, Bl[3] + g*4);
        for (int t = 0; t < 4; t++) v[t] = B1[g*4 + t];
        soa_to_lanes(v, Bl[0] + 16 + g*4, Bl[1] + 16 + g*4,
                        Bl[2] + 16 + g*4, Bl[3] + 16 + g*4);
    }
}

/*============================================================================
 * Main scrypt and Public API
 *============================================================================*/

/* r must be 1: the generic r>1 BlockMix/ROMix fallback was removed as
 * unreachable (the miner is hardwired to Litecoin's N=1024, r=1, p=1). */
static void scrypt_core(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        int N, int r, int p, uint8_t *dk, size_t dk_len,
                        uint8_t *scratchpad) {
    size_t block_size = 128 * r;
    size_t B_size = p * block_size;
    uint8_t *B = scratchpad;
    uint8_t *V = scratchpad + B_size;

    pbkdf2_sha256(password, password_len, salt, salt_len, 1, B, B_size);

    for (int i = 0; i < p; i++) {
        scrypt_romix_r1_fast((uint32_t *)(B + i * block_size),
                             (uint32_t *)V, N);
    }

    pbkdf2_sha256(password, password_len, B, B_size, 1, dk, dk_len);
}

/*============================================================================
 * Dual scrypt core - processes 2 headers at once
 *============================================================================*/

static void scrypt_core_dual(const uint8_t *pass_a, const uint8_t *pass_b,
                              uint8_t *hash_a, uint8_t *hash_b,
                              uint8_t *scratchpad) {
    /* Scratchpad layout for dual mode (r=1, p=1, N=1024):
     * Ba:  128 bytes (offset 0)
     * Va:  128*1024 = 131072 bytes
     * Ya:  128 bytes
     * Bb:  128 bytes
     * Vb:  131072 bytes
     * Yb:  128 bytes
     */
    const size_t block_sz = SCRYPT_BLOCK_SIZE;  /* 128 */
    const size_t v_sz = SCRYPT_N * block_sz;    /* 131072 */

    uint8_t *Ba = scratchpad;
    uint8_t *Va = Ba + block_sz;
    uint8_t *Ya = Va + v_sz;
    uint8_t *Bb = Ya + block_sz;
    uint8_t *Vb = Bb + block_sz;

    /* PBKDF2 initial — sequential, <0.2% of time */
    pbkdf2_sha256(pass_a, 80, pass_a, 80, 1, Ba, block_sz);
    pbkdf2_sha256(pass_b, 80, pass_b, 80, 1, Bb, block_sz);

    /* Dual scalar ROMix: Phase 2 interleaving hides L2 cache latency */
    scrypt_romix_dual_scalar((uint32_t *)Ba, (uint32_t *)Va,
                              (uint32_t *)Bb, (uint32_t *)Vb,
                              SCRYPT_N);

    /* PBKDF2 final */
    pbkdf2_sha256(pass_a, 80, Ba, block_sz, 1, hash_a, 32);
    pbkdf2_sha256(pass_b, 80, Bb, block_sz, 1, hash_b, 32);
}

static void scrypt_1024_1_1_256_dual(const uint8_t *input_a, const uint8_t *input_b,
                                      uint8_t *output_a, uint8_t *output_b,
                                      uint8_t *scratchpad) {
    scrypt_core_dual(input_a, input_b, output_a, output_b, scratchpad);
}

/*============================================================================
 * SoA-4 scrypt core - processes 4 headers at once
 *============================================================================*/

static void scrypt_core_soa4(const uint8_t *pass[4], uint8_t *hash[4],
                             uint8_t *scratchpad) {
    /* Scratchpad layout for SoA-4 mode (r=1, p=1, N=1024):
     * B0..B3: 4 x 128 bytes  (offset 0)
     * V0..V3: 4 x 131072 bytes
     */
    const size_t block_sz = SCRYPT_BLOCK_SIZE;  /* 128 */
    const size_t v_sz = SCRYPT_N * block_sz;    /* 131072 */

    uint32_t *Bl[4], *Vl[4];
    for (int l = 0; l < 4; l++) {
        Bl[l] = (uint32_t *)(scratchpad + (size_t)l * block_sz);
        Vl[l] = (uint32_t *)(scratchpad + 4 * block_sz + (size_t)l * v_sz);
    }

    /* PBKDF2 initial — sequential, <0.2% of time */
    for (int l = 0; l < 4; l++)
        pbkdf2_sha256(pass[l], 80, pass[l], 80, 1, (uint8_t *)Bl[l], block_sz);

    scrypt_romix_soa4(Bl, Vl, SCRYPT_N);

    /* PBKDF2 final */
    for (int l = 0; l < 4; l++)
        pbkdf2_sha256(pass[l], 80, (uint8_t *)Bl[l], block_sz, 1, hash[l], 32);
}

/* Scratchpad size for SoA-4 mode: 4 * (B + V) — the largest layout (dual
 * mode fits inside), so per-thread scratchpads are sized for it. */
#define SCRYPT_SOA4_SCRATCHPAD_SIZE (4 * (SCRYPT_BLOCK_SIZE + SCRYPT_N * SCRYPT_BLOCK_SIZE))

static uint8_t **thread_scratchpads = NULL;
static int num_scratchpads = 0;

int scrypt_init(int num_threads) {
    if (thread_scratchpads) scrypt_cleanup();
    thread_scratchpads = (uint8_t **)calloc(num_threads, sizeof(uint8_t *));
    if (!thread_scratchpads) return -1;
    num_scratchpads = num_threads;

    /* Sized for SoA-4 mode (largest); dual mode fits inside */
    size_t scratchpad_size = SCRYPT_SOA4_SCRATCHPAD_SIZE;

    for (int i = 0; i < num_threads; i++) {
        /* 64-byte alignment for NEON */
        if (posix_memalign((void **)&thread_scratchpads[i], 64, scratchpad_size) != 0) {
            scrypt_cleanup();
            return -1;
        }
    }
    return 0;
}

void scrypt_cleanup(void) {
    if (thread_scratchpads) {
        for (int i = 0; i < num_scratchpads; i++)
            if (thread_scratchpads[i]) free(thread_scratchpads[i]);
        free(thread_scratchpads);
        thread_scratchpads = NULL;
        num_scratchpads = 0;
    }
}

/* Self-test: CONSISTENCY check between the miner's own scrypt paths on a
 * synthetic header — it is NOT an external known-answer vector, so a mistake
 * shared by every in-tree implementation would pass. (Real cross-checks: the
 * SoA-4 kernel is verified against the single path at startup, and live
 * share acceptance validates end-to-end correctness.) */
int scrypt_selftest(void) {
    static const uint8_t test_header[80] = {
        0x01, 0x00, 0x00, 0x00, /* version */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* prevhash (zeros for genesis) */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* merkle (zeros for test) */
        0x00, 0x00, 0x00, 0x00, /* ntime */
        0xff, 0xff, 0x00, 0x1d, /* nbits */
        0x00, 0x00, 0x00, 0x00  /* nonce */
    };

    uint8_t hash[32], hash2[32];
    uint8_t hash_dual_a[32], hash_dual_b[32];
    uint8_t *scratchpad;
    size_t scratchpad_size = SCRYPT_SOA4_SCRATCHPAD_SIZE;

    if (posix_memalign((void **)&scratchpad, 64, scratchpad_size) != 0)
        return -1;

    /* Hash twice with same input - should get same output */
    scrypt_core(test_header, 80, test_header, 80, 1024, 1, 1, hash, 32, scratchpad);
    scrypt_core(test_header, 80, test_header, 80, 1024, 1, 1, hash2, 32, scratchpad);

    /* Verify consistency */
    if (memcmp(hash, hash2, 32) != 0) { free(scratchpad); return -2; }

    /* Verify hash is non-zero (sanity check) */
    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != 0) { all_zero = 0; break; }
    }
    if (all_zero) { free(scratchpad); return -3; }

    /* Verify dual path matches single path */
    scrypt_1024_1_1_256_dual(test_header, test_header,
                              hash_dual_a, hash_dual_b, scratchpad);
    if (memcmp(hash, hash_dual_a, 32) != 0) { free(scratchpad); return -4; }
    if (memcmp(hash, hash_dual_b, 32) != 0) { free(scratchpad); return -5; }

    /* Verify dual with different inputs produces different outputs */
    uint8_t test_header2[80];
    memcpy(test_header2, test_header, 80);
    test_header2[79] = 0x01;  /* Different nonce */
    scrypt_1024_1_1_256_dual(test_header, test_header2,
                              hash_dual_a, hash_dual_b, scratchpad);
    if (memcmp(hash, hash_dual_a, 32) != 0) { free(scratchpad); return -6; }
    if (memcmp(hash_dual_a, hash_dual_b, 32) == 0) { free(scratchpad); return -7; }

    /* Verify SoA-4 path: 4 distinct nonces must each match the single path */
    {
        uint8_t headers[4][80];
        uint8_t soa_hashes[4][32], ref_hash[32];
        const uint8_t *pass[4];
        uint8_t *hout[4];
        for (int l = 0; l < 4; l++) {
            memcpy(headers[l], test_header, 80);
            headers[l][76] = (uint8_t)l;  /* nonce LSB */
            pass[l] = headers[l];
            hout[l] = soa_hashes[l];
        }
        scrypt_core_soa4(pass, hout, scratchpad);
        for (int l = 0; l < 4; l++) {
            scrypt_core(headers[l], 80, headers[l], 80, 1024, 1, 1,
                        ref_hash, 32, scratchpad);
            if (memcmp(ref_hash, soa_hashes[l], 32) != 0) {
                free(scratchpad);
                return -8 - l;
            }
        }
    }

    free(scratchpad);
    return 0; /* Success */
}

void scrypt_1024_1_1_256(const uint8_t *input, uint8_t *output,
                         const uint8_t *midstate, uint8_t *scratchpad) {
    (void)midstate;
    scrypt_core(input, 80, input, 80, 1024, 1, 1, output, 32, scratchpad);
}

/*============================================================================
 * Mining Scan Function
 *============================================================================*/

#ifndef SCRYPT_STANDALONE

#include <sched.h>
#include "sched_compat.h"

#include "miner.h"
#include "cpu_features.h"

/* Debug flag - reset when job changes */
static int scrypt_debug_printed = 0;
static char scrypt_last_job[128] = "";

/* Record a found share. Mirrors the historical inline block exactly. */
static void scrypt_record_share(struct work *work, uint32_t *pdata,
                                uint32_t *ptarget, uint32_t *hash, uint32_t nonce) {
    pdata[19] = nonce;
    work->nonces[work->valid_nonces] = nonce;
    bn_store_share_difficulty(hash, ptarget, work, work->valid_nonces);
    applog(LOG_INFO, "Found nonce %08x: hash[7..4]=%08x %08x %08x %08x target[7..4]=%08x %08x %08x %08x",
           nonce, hash[7], hash[6], hash[5], hash[4],
           ptarget[7], ptarget[6], ptarget[5], ptarget[4]);
    work->valid_nonces++;
}

int scanhash_scrypt(int thr_id, struct work *work, uint32_t max_hashes,
                    unsigned long *hashes_done) {
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t hash_a[8], hash_b[8];
    uint32_t n = pdata[19];
    uint32_t first_nonce = n;
    uint8_t *scratchpad = NULL;
    uint8_t header_a[80], header_b[80];

    if (thread_scratchpads && thr_id < num_scratchpads) {
        scratchpad = thread_scratchpads[thr_id];
    } else {
        size_t scratchpad_size = SCRYPT_SOA4_SCRATCHPAD_SIZE;
        if (posix_memalign((void **)&scratchpad, 64, scratchpad_size) != 0) {
            *hashes_done = 0;
            return 0;
        }
    }

    work->valid_nonces = 0;

    /* Construct 80-byte block header templates (nonce patched per iteration) */
    for (int i = 0; i < 9; i++)
        be32enc(header_a + i * 4, pdata[i]);
    for (int i = 9; i < 17; i++)
        le32enc(header_a + i * 4, pdata[i]);
    for (int i = 17; i < 20; i++)
        be32enc(header_a + i * 4, pdata[i]);
    memcpy(header_b, header_a, 80);

    /* Debug: print first hash and target once per job (only if -D flag) */
    if (opt_debug && thr_id == 0 && !scrypt_debug_printed) {
        if (strcmp(scrypt_last_job, work->job_id) != 0) {
            snprintf(scrypt_last_job, sizeof(scrypt_last_job), "%s", work->job_id);
            scrypt_debug_printed = 0;
        }
        if (!scrypt_debug_printed) {
            char hexheader[161];
            for (int i = 0; i < 80; i++)
                snprintf(hexheader + i * 2, sizeof(hexheader) - (size_t)(i * 2), "%02x", header_a[i]);
            applog(LOG_DEBUG, "Scrypt header (80 bytes): %s", hexheader);
            scrypt_1024_1_1_256(header_a, (uint8_t *)hash_a, NULL, scratchpad);
            applog(LOG_DEBUG, "Scrypt debug - Target[7..0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                   ptarget[7], ptarget[6], ptarget[5], ptarget[4],
                   ptarget[3], ptarget[2], ptarget[1], ptarget[0]);
            applog(LOG_DEBUG, "Scrypt debug - Hash[7..0]:   %08x %08x %08x %08x %08x %08x %08x %08x",
                   hash_a[7], hash_a[6], hash_a[5], hash_a[4],
                   hash_a[3], hash_a[2], hash_a[1], hash_a[0]);
            scrypt_debug_printed = 1;
        }
    }

    /* SoA-4 on big cores only (in-miner measured, RK3588, LTO build):
     * A76 +5% (4.59 -> 4.82 kH/s), A55 -7% — the standalone prototype's
     * bigger margins shrink under LTO, which speeds the dual-scalar path.
     * Big-only also caps total V footprint at 4x512KB + 4x256KB = 3MB = L3.
     * SCRYPT_SOA=0/1 forces; unknown/homogeneous topology stays dual (the
     * win is small and the downside on in-order cores is real).
     * sched_getcpu() (not the intended pin order) is the ground truth: with
     * --cpu-affinity masks, failed pins, or Android cpuset overrides the
     * thread may not be on the core get_cpu_for_thread() would predict. */
    int use_soa4 = 0;
    const char *soa_env = getenv("SCRYPT_SOA");
    if (soa_env && soa_env[0]) {
        use_soa4 = soa_env[0] != '0';
    } else if (g_num_big_cores > 0 && g_num_little_cores > 0) {
        int cpu_id = sched_getcpu();
        if (cpu_id >= 0) {
            for (int i = 0; i < g_num_cpus; i++) {
                if (g_cpu_cores[i].cpu_id == cpu_id) {
                    use_soa4 = g_cpu_cores[i].is_big;
                    break;
                }
            }
        }
    }

    uint32_t remaining_hashes = max_hashes;

    if (use_soa4) {
        uint8_t header_c[80], header_d[80];
        uint32_t hash_c[8], hash_d[8];
        memcpy(header_c, header_a, 80);
        memcpy(header_d, header_a, 80);
        const uint8_t *pass[4] = { header_a, header_b, header_c, header_d };
        uint8_t *hout[4] = { (uint8_t *)hash_a, (uint8_t *)hash_b,
                             (uint8_t *)hash_c, (uint8_t *)hash_d };
        uint32_t *hashes[4] = { hash_a, hash_b, hash_c, hash_d };

        while (remaining_hashes >= 4 &&
               !miner_work_restart_requested(work->restart_generation) &&
               !miner_should_abort()) {
            be32enc(header_a + 76, n);
            be32enc(header_b + 76, n + 1);
            be32enc(header_c + 76, n + 2);
            be32enc(header_d + 76, n + 3);

            scrypt_core_soa4(pass, hout, scratchpad);

            for (int l = 0; l < 4; l++) {
                if (hashes[l][7] <= ptarget[7] &&
                    hash_le_target(hashes[l], ptarget) &&
                    work->valid_nonces < MAX_NONCES) {
                    scrypt_record_share(work, pdata, ptarget, hashes[l], n + (uint32_t)l);
                }
            }

            n += 4;
            /* Return immediately after finding any nonce so miner_thread can
             * submit the share before the pool moves to a new job. */
            remaining_hashes -= 4;
            if (work->valid_nonces) break;
        }
    }

    /* Dual-nonce mode: fallback path and the 2-3 hash remainder of the
     * SoA-4 loop. Phase 2 interleaving hides L3 cache latency for
     * V[j] reads. */
    while (remaining_hashes >= 2 && work->valid_nonces == 0 &&
           !miner_work_restart_requested(work->restart_generation) &&
           !miner_should_abort()) {
        be32enc(header_a + 76, n);
        be32enc(header_b + 76, n + 1);
        scrypt_1024_1_1_256_dual(header_a, header_b,
                                  (uint8_t *)hash_a, (uint8_t *)hash_b,
                                  scratchpad);

        if (hash_a[7] <= ptarget[7] && hash_le_target(hash_a, ptarget)) {
            scrypt_record_share(work, pdata, ptarget, hash_a, n);
        }

        if (hash_b[7] <= ptarget[7] && hash_le_target(hash_b, ptarget) &&
            work->valid_nonces < MAX_NONCES) {
            scrypt_record_share(work, pdata, ptarget, hash_b, n + 1);
        }

        n += 2;
        /* Return immediately after finding any nonce so miner_thread can
         * submit the share before the pool moves to a new job. */
        remaining_hashes -= 2;
        if (work->valid_nonces) break;
    }

    /* Handle remaining odd nonce with single path */
    if (remaining_hashes > 0 &&
        !miner_work_restart_requested(work->restart_generation) &&
        !miner_should_abort() && work->valid_nonces == 0) {
        be32enc(header_a + 76, n);
        scrypt_1024_1_1_256(header_a, (uint8_t *)hash_a, NULL, scratchpad);
        if (hash_a[7] <= ptarget[7] && hash_le_target(hash_a, ptarget)) {
            scrypt_record_share(work, pdata, ptarget, hash_a, n);
        }
        n++;
        remaining_hashes--;
    }

    *hashes_done = n - first_nonce;
    pdata[19] = n;

    if (!thread_scratchpads || thr_id >= num_scratchpads)
        free(scratchpad);

    return work->valid_nonces;
}

#endif /* SCRYPT_STANDALONE */
