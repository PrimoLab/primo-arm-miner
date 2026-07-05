/*
 * sha256_neon.c - ARM NEON SHA256 for Bitcoin mining
 *
 * Optimized for ARM SBCs (Raspberry Pi, Orange Pi, etc.) and
 * mobile phones running Termux.
 *
 * Features:
 * - ARMv8 SHA256 crypto extensions (when available)
 * - ARM NEON SIMD fallback
 * - Midstate optimization for Bitcoin mining
 *
 * Based on public domain implementations by:
 * - Jeffrey Walton (noloader/SHA-Intrinsics)
 * - Colin Percival (scrypt)
 *
 * This implementation is placed in the public domain.
 */

#include <sha256_neon.h>
#include <byteorder.h>
#include <string.h>
#include <arm_neon.h>
#if defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

/* Check for ARMv8 crypto extensions at compile time */
#if defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_SHA2)
#define HAVE_ARM_CRYPTO 1
#include <arm_acle.h>
#else
#define HAVE_ARM_CRYPTO 0
#endif

/*============================================================================
 * SHA-256 Constants
 *============================================================================*/

static const uint32_t K256[64] = {
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

static const uint32_t H256_INIT[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/*============================================================================
 * Utility Functions
 *============================================================================*/

/*============================================================================
 * SHA-256 Core Functions (Software Implementation)
 *============================================================================*/

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x)       (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x)      (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

/* Software SHA256 transform - processes one 64-byte block */
static void sha256_transform_sw(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Prepare message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = be32dec(block + i * 4);
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* Add to state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


/* Software SHA256 transform - takes uint32_t words directly (no byte-swap) */
static inline __attribute__((always_inline))
void sha256_transform_u32_sw(uint32_t state[8], const uint32_t words[16])
{
    uint32_t W[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    /* Message words already in big-endian uint32 format */
    for (i = 0; i < 16; i++) {
        W[i] = words[i];
    }
    for (i = 16; i < 64; i++) {
        W[i] = SIG1(W[i-2]) + W[i-7] + SIG0(W[i-15]) + W[i-16];
    }

    /* Initialize working variables */
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    /* Main loop */
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + W[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* Add to state */
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


/*============================================================================
 * ARMv8 SHA256 Crypto Extensions Implementation
 *============================================================================*/

#if HAVE_ARM_CRYPTO

/* ARMv8 hardware-accelerated SHA256 transform */
static void sha256_transform_arm(uint32_t state[8], const uint8_t block[64])
{
    uint32x4_t STATE0, STATE1;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;
    uint32x4_t ABEF_SAVE, CDGH_SAVE;

    /* Load state */
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    /* Save state for final addition */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Load and reverse message bytes for big-endian */
    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    /* Rounds 0-3 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[0]));
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[4]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 4-7 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[8]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 8-11 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[12]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 12-15 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[16]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 16-19 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[20]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 20-23 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[24]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 24-27 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[28]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 28-31 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[32]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 32-35 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[36]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 36-39 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[40]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 40-43 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[44]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 44-47 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[48]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 48-51 */
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[52]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 52-55 */
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[56]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Rounds 56-59 */
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[60]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 60-63 */
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Add saved state */
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    /* Store state */
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

/* ARMv8 hardware-accelerated SHA256 transform - takes uint32_t words directly */
static inline __attribute__((always_inline))
void sha256_transform_u32_arm(uint32_t state[8], const uint32_t words[16])
{
    uint32x4_t STATE0, STATE1;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;
    uint32x4_t ABEF_SAVE, CDGH_SAVE;

    /* Load state */
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    /* Save state for final addition */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Load message words directly - no byte reversal needed */
    MSG0 = vld1q_u32(&words[0]);
    MSG1 = vld1q_u32(&words[4]);
    MSG2 = vld1q_u32(&words[8]);
    MSG3 = vld1q_u32(&words[12]);

    /* Rounds 0-3 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[0]));
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[4]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 4-7 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[8]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 8-11 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[12]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 12-15 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[16]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 16-19 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[20]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 20-23 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[24]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 24-27 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[28]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 28-31 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[32]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 32-35 */
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[36]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    /* Rounds 36-39 */
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[40]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    /* Rounds 40-43 */
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[44]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    /* Rounds 44-47 */
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K256[48]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    /* Rounds 48-51 */
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K256[52]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 52-55 */
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K256[56]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Rounds 56-59 */
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K256[60]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    /* Rounds 60-63 */
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    /* Add saved state */
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    /* Store state */
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

/* ARMv8 dual-nonce interleaved SHA256 transform.
 * Processes two independent hashes simultaneously to hide pipeline latency.
 * On Cortex-A76, sha256h has 4-cycle latency but 1-cycle throughput on V0.
 * Interleaving A and B round groups fills the latency gap between consecutive
 * sha256h calls for the same hash, eliminating pipeline stalls. */
static inline __attribute__((always_inline))
void sha256_transform_u32_dual_arm(
    uint32_t stateA[8], const uint32_t wordsA[16],
    uint32_t stateB[8], const uint32_t wordsB[16])
{
    /* Hash A registers */
    uint32x4_t A_STATE0, A_STATE1;
    uint32x4_t A_MSG0, A_MSG1, A_MSG2, A_MSG3;
    uint32x4_t A_TMP0, A_TMP1, A_TMP2;
    uint32x4_t A_ABEF_SAVE, A_CDGH_SAVE;

    /* Hash B registers */
    uint32x4_t B_STATE0, B_STATE1;
    uint32x4_t B_MSG0, B_MSG1, B_MSG2, B_MSG3;
    uint32x4_t B_TMP0, B_TMP1, B_TMP2;
    uint32x4_t B_ABEF_SAVE, B_CDGH_SAVE;

    /* Load states */
    A_STATE0 = vld1q_u32(&stateA[0]);
    A_STATE1 = vld1q_u32(&stateA[4]);
    B_STATE0 = vld1q_u32(&stateB[0]);
    B_STATE1 = vld1q_u32(&stateB[4]);

    A_ABEF_SAVE = A_STATE0;
    A_CDGH_SAVE = A_STATE1;
    B_ABEF_SAVE = B_STATE0;
    B_CDGH_SAVE = B_STATE1;

    /* Load messages */
    A_MSG0 = vld1q_u32(&wordsA[0]);
    A_MSG1 = vld1q_u32(&wordsA[4]);
    A_MSG2 = vld1q_u32(&wordsA[8]);
    A_MSG3 = vld1q_u32(&wordsA[12]);
    B_MSG0 = vld1q_u32(&wordsB[0]);
    B_MSG1 = vld1q_u32(&wordsB[4]);
    B_MSG2 = vld1q_u32(&wordsB[8]);
    B_MSG3 = vld1q_u32(&wordsB[12]);

    /* Rounds 0-3: A then B */
    A_TMP0 = vaddq_u32(A_MSG0, vld1q_u32(&K256[0]));
    A_MSG0 = vsha256su0q_u32(A_MSG0, A_MSG1);
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG1, vld1q_u32(&K256[4]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);
    A_MSG0 = vsha256su1q_u32(A_MSG0, A_MSG2, A_MSG3);

    B_TMP0 = vaddq_u32(B_MSG0, vld1q_u32(&K256[0]));
    B_MSG0 = vsha256su0q_u32(B_MSG0, B_MSG1);
    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG1, vld1q_u32(&K256[4]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);
    B_MSG0 = vsha256su1q_u32(B_MSG0, B_MSG2, B_MSG3);

    /* Rounds 4-7 */
    A_MSG1 = vsha256su0q_u32(A_MSG1, A_MSG2);
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG2, vld1q_u32(&K256[8]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);
    A_MSG1 = vsha256su1q_u32(A_MSG1, A_MSG3, A_MSG0);

    B_MSG1 = vsha256su0q_u32(B_MSG1, B_MSG2);
    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG2, vld1q_u32(&K256[8]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);
    B_MSG1 = vsha256su1q_u32(B_MSG1, B_MSG3, B_MSG0);

    /* Rounds 8-11 */
    A_MSG2 = vsha256su0q_u32(A_MSG2, A_MSG3);
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG3, vld1q_u32(&K256[12]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);
    A_MSG2 = vsha256su1q_u32(A_MSG2, A_MSG0, A_MSG1);

    B_MSG2 = vsha256su0q_u32(B_MSG2, B_MSG3);
    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG3, vld1q_u32(&K256[12]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);
    B_MSG2 = vsha256su1q_u32(B_MSG2, B_MSG0, B_MSG1);

    /* Rounds 12-15 */
    A_MSG3 = vsha256su0q_u32(A_MSG3, A_MSG0);
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG0, vld1q_u32(&K256[16]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);
    A_MSG3 = vsha256su1q_u32(A_MSG3, A_MSG1, A_MSG2);

    B_MSG3 = vsha256su0q_u32(B_MSG3, B_MSG0);
    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG0, vld1q_u32(&K256[16]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);
    B_MSG3 = vsha256su1q_u32(B_MSG3, B_MSG1, B_MSG2);

    /* Rounds 16-19 */
    A_MSG0 = vsha256su0q_u32(A_MSG0, A_MSG1);
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG1, vld1q_u32(&K256[20]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);
    A_MSG0 = vsha256su1q_u32(A_MSG0, A_MSG2, A_MSG3);

    B_MSG0 = vsha256su0q_u32(B_MSG0, B_MSG1);
    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG1, vld1q_u32(&K256[20]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);
    B_MSG0 = vsha256su1q_u32(B_MSG0, B_MSG2, B_MSG3);

    /* Rounds 20-23 */
    A_MSG1 = vsha256su0q_u32(A_MSG1, A_MSG2);
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG2, vld1q_u32(&K256[24]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);
    A_MSG1 = vsha256su1q_u32(A_MSG1, A_MSG3, A_MSG0);

    B_MSG1 = vsha256su0q_u32(B_MSG1, B_MSG2);
    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG2, vld1q_u32(&K256[24]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);
    B_MSG1 = vsha256su1q_u32(B_MSG1, B_MSG3, B_MSG0);

    /* Rounds 24-27 */
    A_MSG2 = vsha256su0q_u32(A_MSG2, A_MSG3);
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG3, vld1q_u32(&K256[28]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);
    A_MSG2 = vsha256su1q_u32(A_MSG2, A_MSG0, A_MSG1);

    B_MSG2 = vsha256su0q_u32(B_MSG2, B_MSG3);
    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG3, vld1q_u32(&K256[28]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);
    B_MSG2 = vsha256su1q_u32(B_MSG2, B_MSG0, B_MSG1);

    /* Rounds 28-31 */
    A_MSG3 = vsha256su0q_u32(A_MSG3, A_MSG0);
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG0, vld1q_u32(&K256[32]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);
    A_MSG3 = vsha256su1q_u32(A_MSG3, A_MSG1, A_MSG2);

    B_MSG3 = vsha256su0q_u32(B_MSG3, B_MSG0);
    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG0, vld1q_u32(&K256[32]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);
    B_MSG3 = vsha256su1q_u32(B_MSG3, B_MSG1, B_MSG2);

    /* Rounds 32-35 */
    A_MSG0 = vsha256su0q_u32(A_MSG0, A_MSG1);
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG1, vld1q_u32(&K256[36]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);
    A_MSG0 = vsha256su1q_u32(A_MSG0, A_MSG2, A_MSG3);

    B_MSG0 = vsha256su0q_u32(B_MSG0, B_MSG1);
    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG1, vld1q_u32(&K256[36]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);
    B_MSG0 = vsha256su1q_u32(B_MSG0, B_MSG2, B_MSG3);

    /* Rounds 36-39 */
    A_MSG1 = vsha256su0q_u32(A_MSG1, A_MSG2);
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG2, vld1q_u32(&K256[40]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);
    A_MSG1 = vsha256su1q_u32(A_MSG1, A_MSG3, A_MSG0);

    B_MSG1 = vsha256su0q_u32(B_MSG1, B_MSG2);
    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG2, vld1q_u32(&K256[40]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);
    B_MSG1 = vsha256su1q_u32(B_MSG1, B_MSG3, B_MSG0);

    /* Rounds 40-43 */
    A_MSG2 = vsha256su0q_u32(A_MSG2, A_MSG3);
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG3, vld1q_u32(&K256[44]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);
    A_MSG2 = vsha256su1q_u32(A_MSG2, A_MSG0, A_MSG1);

    B_MSG2 = vsha256su0q_u32(B_MSG2, B_MSG3);
    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG3, vld1q_u32(&K256[44]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);
    B_MSG2 = vsha256su1q_u32(B_MSG2, B_MSG0, B_MSG1);

    /* Rounds 44-47 */
    A_MSG3 = vsha256su0q_u32(A_MSG3, A_MSG0);
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG0, vld1q_u32(&K256[48]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);
    A_MSG3 = vsha256su1q_u32(A_MSG3, A_MSG1, A_MSG2);

    B_MSG3 = vsha256su0q_u32(B_MSG3, B_MSG0);
    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG0, vld1q_u32(&K256[48]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);
    B_MSG3 = vsha256su1q_u32(B_MSG3, B_MSG1, B_MSG2);

    /* Rounds 48-51 (no more message schedule) */
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG1, vld1q_u32(&K256[52]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);

    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG1, vld1q_u32(&K256[52]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);

    /* Rounds 52-55 */
    A_TMP2 = A_STATE0;
    A_TMP0 = vaddq_u32(A_MSG2, vld1q_u32(&K256[56]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);

    B_TMP2 = B_STATE0;
    B_TMP0 = vaddq_u32(B_MSG2, vld1q_u32(&K256[56]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);

    /* Rounds 56-59 */
    A_TMP2 = A_STATE0;
    A_TMP1 = vaddq_u32(A_MSG3, vld1q_u32(&K256[60]));
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP0);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP0);

    B_TMP2 = B_STATE0;
    B_TMP1 = vaddq_u32(B_MSG3, vld1q_u32(&K256[60]));
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP0);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP0);

    /* Rounds 60-63 */
    A_TMP2 = A_STATE0;
    A_STATE0 = vsha256hq_u32(A_STATE0, A_STATE1, A_TMP1);
    A_STATE1 = vsha256h2q_u32(A_STATE1, A_TMP2, A_TMP1);

    B_TMP2 = B_STATE0;
    B_STATE0 = vsha256hq_u32(B_STATE0, B_STATE1, B_TMP1);
    B_STATE1 = vsha256h2q_u32(B_STATE1, B_TMP2, B_TMP1);

    /* Add saved states */
    A_STATE0 = vaddq_u32(A_STATE0, A_ABEF_SAVE);
    A_STATE1 = vaddq_u32(A_STATE1, A_CDGH_SAVE);
    B_STATE0 = vaddq_u32(B_STATE0, B_ABEF_SAVE);
    B_STATE1 = vaddq_u32(B_STATE1, B_CDGH_SAVE);

    /* Store states */
    vst1q_u32(&stateA[0], A_STATE0);
    vst1q_u32(&stateA[4], A_STATE1);
    vst1q_u32(&stateB[0], B_STATE0);
    vst1q_u32(&stateB[4], B_STATE1);
}

#endif /* HAVE_ARM_CRYPTO */

/*============================================================================
 * Runtime Detection and Transform Selection
 *============================================================================*/

static int g_has_arm_crypto = -1;  /* -1 = not checked, 0 = no, 1 = yes */

int sha256_has_crypto(void)
{
    if (g_has_arm_crypto < 0) {
#if HAVE_ARM_CRYPTO
#if defined(__linux__) && defined(HWCAP_SHA2)
        unsigned long hwcap = getauxval(AT_HWCAP);
        g_has_arm_crypto = (hwcap & HWCAP_SHA2) ? 1 : 0;
#else
        /* Non-Linux (or missing HWCAP definitions): best effort fallback */
        g_has_arm_crypto = 1;
#endif
#else
        g_has_arm_crypto = 0;
#endif
    }
    return g_has_arm_crypto;
}

/* Select the best transform function */
static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
#if HAVE_ARM_CRYPTO
    if (sha256_has_crypto()) {
        sha256_transform_arm(state, block);
        return;
    }
#endif
    sha256_transform_sw(state, block);
}

/* Select the best u32 transform function (no byte-swap on input) */
static inline __attribute__((always_inline))
void sha256_transform_u32(uint32_t state[8], const uint32_t words[16])
{
#if HAVE_ARM_CRYPTO
    if (sha256_has_crypto()) {
        sha256_transform_u32_arm(state, words);
        return;
    }
#endif
    sha256_transform_u32_sw(state, words);
}

/* Dual-nonce transform dispatcher */
static inline __attribute__((always_inline))
void sha256_transform_u32_dual(
    uint32_t stateA[8], const uint32_t wordsA[16],
    uint32_t stateB[8], const uint32_t wordsB[16])
{
#if HAVE_ARM_CRYPTO
    if (sha256_has_crypto()) {
        sha256_transform_u32_dual_arm(stateA, wordsA, stateB, wordsB);
        return;
    }
#endif
    sha256_transform_u32_sw(stateA, wordsA);
    sha256_transform_u32_sw(stateB, wordsB);
}


/*============================================================================
 * Public SHA256 API
 *============================================================================*/

void sha256_neon_init(sha256_neon_ctx *ctx)
{
    memcpy(ctx->state, H256_INIT, sizeof(H256_INIT));
    ctx->count = 0;
}

void sha256_neon_update(sha256_neon_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t i = 0;
    size_t index = (ctx->count >> 3) & 0x3f;

    ctx->count += (uint64_t)len << 3;

    /* Handle any pending data in buffer */
    if (index) {
        size_t left = 64 - index;
        if (len < left) {
            memcpy(ctx->buffer + index, data, len);
            return;
        }
        memcpy(ctx->buffer + index, data, left);
        sha256_transform(ctx->state, ctx->buffer);
        i = left;
    }

    /* Process full blocks */
    for (; i + 64 <= len; i += 64) {
        sha256_transform(ctx->state, data + i);
    }

    /* Save remaining data */
    if (i < len) {
        memcpy(ctx->buffer, data + i, len - i);
    }
}

void sha256_neon_final(sha256_neon_ctx *ctx, uint8_t *digest)
{
    uint8_t finalcount[8];
    int i;

    /* Store bit count in big-endian */
    for (i = 0; i < 8; i++) {
        finalcount[i] = (ctx->count >> (56 - i * 8)) & 0xff;
    }

    /* Pad to 56 mod 64 */
    sha256_neon_update(ctx, (const uint8_t *)"\x80", 1);
    while (((ctx->count >> 3) & 0x3f) != 56) {
        sha256_neon_update(ctx, (const uint8_t *)"\x00", 1);
    }

    /* Append length */
    sha256_neon_update(ctx, finalcount, 8);

    /* Output digest in big-endian */
    for (i = 0; i < 8; i++) {
        be32enc(digest + i * 4, ctx->state[i]);
    }
}

void sha256_neon(const uint8_t *data, size_t len, uint8_t *digest)
{
    sha256_neon_ctx ctx;
    sha256_neon_init(&ctx);
    sha256_neon_update(&ctx, data, len);
    sha256_neon_final(&ctx, digest);
}

void sha256d_neon(const uint8_t *data, size_t len, uint8_t *digest)
{
    uint8_t hash1[32];
    sha256_neon(data, len, hash1);
    sha256_neon(hash1, 32, digest);
}

/*============================================================================
 * Bitcoin Mining Optimizations
 *============================================================================*/

void sha256_midstate_neon(const uint8_t *data, uint32_t *midstate)
{
    /* Initialize state */
    memcpy(midstate, H256_INIT, sizeof(H256_INIT));

    /* Process first 64 bytes */
    sha256_transform(midstate, data);
}

/*============================================================================
 * Self-Test
 *============================================================================*/

int sha256_neon_selftest(void)
{
    /* Test vector: SHA256("abc") */
    static const uint8_t test_input[] = "abc";
    static const uint8_t expected_sha256[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    /* Test vector: SHA256d("abc") = SHA256(SHA256("abc")) */
    static const uint8_t expected_sha256d[32] = {
        0x4f, 0x8b, 0x42, 0xc2, 0x2d, 0xd3, 0x72, 0x9b,
        0x51, 0x9b, 0xa6, 0xf6, 0x8d, 0x2d, 0xa7, 0xcc,
        0x5b, 0x2d, 0x60, 0x6d, 0x05, 0xda, 0xed, 0x5a,
        0xd5, 0x12, 0x8c, 0xc0, 0x3e, 0x6c, 0x63, 0x58
    };

    uint8_t digest[32];

    /* Test SHA256 */
    sha256_neon(test_input, 3, digest);
    if (memcmp(digest, expected_sha256, 32) != 0) {
        return -1;
    }

    /* Test SHA256d */
    sha256d_neon(test_input, 3, digest);
    if (memcmp(digest, expected_sha256d, 32) != 0) {
        return -1;
    }

    return 0;
}

/*============================================================================
 * Mining Scan Function
 *============================================================================*/

#ifndef SHA256_STANDALONE

#include "miner.h"


/* Hand-tuned assembly dual-nonce SHA256d (both passes, zero memcpy) */
extern void sha256d_dual_asm(
    const uint32_t midstate[8],
    const uint32_t W1_template[16],
    const uint32_t W2_pad[8],
    uint32_t nonceA,
    uint32_t nonceB,
    uint32_t stateA_out[8],
    uint32_t stateB_out[8]);

/* Portable dual-nonce SHA256d fallback used when SHA2 ISA is unavailable. */
static inline __attribute__((always_inline))
void sha256d_dual_fallback(
    const uint32_t midstate[8],
    const uint32_t W1_template[16],
    const uint32_t W2_pad[8],
    uint32_t nonceA,
    uint32_t nonceB,
    uint32_t stateA_out[8],
    uint32_t stateB_out[8])
{
    uint32_t W1A[16], W1B[16];
    uint32_t W2A[16], W2B[16];

    memcpy(stateA_out, midstate, 32);
    memcpy(stateB_out, midstate, 32);
    memcpy(W1A, W1_template, sizeof(W1A));
    memcpy(W1B, W1_template, sizeof(W1B));
    W1A[3] = nonceA;
    W1B[3] = nonceB;

    sha256_transform_u32_dual(stateA_out, W1A, stateB_out, W1B);

    memcpy(W2A, stateA_out, 32);
    memcpy(W2B, stateB_out, 32);
    memcpy(W2A + 8, W2_pad, 32);
    memcpy(W2B + 8, W2_pad, 32);
    memcpy(stateA_out, H256_INIT, 32);
    memcpy(stateB_out, H256_INIT, 32);

    sha256_transform_u32_dual(stateA_out, W2A, stateB_out, W2B);
}

/* Cross-check the dual-nonce mining path against the straightforward
 * sha256d_neon() over full 80-byte headers. This is the ONLY test that ever
 * executes sha256d_dual_asm (and the intrinsics/sw dual fallback): the "abc"
 * vectors in sha256_neon_selftest cover the generic C path the reference
 * below uses, but not the hand asm, the midstate split, or the W1/W2
 * pre-built message-word layout the scan loop feeds them. Mirrors how
 * scanhash_sha256d builds midstate/W1/W2_pad, so a regression in that
 * contract (or a miscompiled/broken .S) refuses to mine instead of
 * silently submitting garbage. Returns 0 on success. */
int sha256d_scan_selftest(void)
{
    uint8_t header[80], headerB[80];
    uint8_t refA[32], refB[32], out[32];
    uint32_t midstate[8], W1[16];
    uint32_t stateA[8], stateB[8];
    static const uint32_t W2_pad[8] = {
        0x80000000, 0, 0, 0, 0, 0, 0, 0x00000100
    };
    int i;

    /* Deterministic synthetic header; nonce B differs from nonce A. */
    for (i = 0; i < 80; i++)
        header[i] = (uint8_t)(i * 7 + 1);
    const uint32_t nonceA = be32dec(header + 76);
    const uint32_t nonceB = nonceA ^ 0xA5A5A5A5u;
    memcpy(headerB, header, 80);
    be32enc(headerB + 76, nonceB);

    /* Reference digests via the plain full-header path. */
    sha256d_neon(header, 80, refA);
    sha256d_neon(headerB, 80, refB);

    /* Build midstate + message words exactly like scanhash_sha256d. */
    sha256_midstate_neon(header, midstate);
    memset(W1, 0, sizeof(W1));
    W1[0] = be32dec(header + 64);
    W1[1] = be32dec(header + 68);
    W1[2] = be32dec(header + 72);
    W1[4] = 0x80000000;
    W1[15] = 0x00000280;

    /* Portable dual path (intrinsics dual when SHA2 ISA is up, sw otherwise). */
    sha256d_dual_fallback(midstate, W1, W2_pad, nonceA, nonceB, stateA, stateB);
    for (i = 0; i < 8; i++)
        be32enc(out + i * 4, stateA[i]);
    if (memcmp(out, refA, 32) != 0)
        return -1;
    for (i = 0; i < 8; i++)
        be32enc(out + i * 4, stateB[i]);
    if (memcmp(out, refB, 32) != 0)
        return -2;

    /* Hand-tuned assembly path (the one live mining actually runs). */
    if (sha256_has_crypto()) {
        sha256d_dual_asm(midstate, W1, W2_pad, nonceA, nonceB, stateA, stateB);
        for (i = 0; i < 8; i++)
            be32enc(out + i * 4, stateA[i]);
        if (memcmp(out, refA, 32) != 0)
            return -3;
        for (i = 0; i < 8; i++)
            be32enc(out + i * 4, stateB[i]);
        if (memcmp(out, refB, 32) != 0)
            return -4;
    }

    return 0;
}

/* Record a found SHA256d share. `state` is the raw big-endian SHA256d output,
 * `hash_le` its little-endian form. Cold path (only runs on a winning nonce);
 * factored from the previously-duplicated nonce-A/B blocks. */
static void sha256d_record_share(struct work *work, uint32_t *pdata, uint32_t *ptarget,
                                 const uint32_t *state, uint32_t *hash_le,
                                 uint8_t *header, uint32_t nonce)
{
    pdata[19] = nonce;
    work->nonces[work->valid_nonces] = nonce;
    bn_store_share_difficulty(hash_le, ptarget, work, work->valid_nonces);
    applog(LOG_INFO, "SHA256d: Found nonce %08x!", nonce);

    if (opt_debug) {
        uint8_t hash_bytes[32];
        for (int i = 0; i < 8; i++)
            be32enc(hash_bytes + i * 4, state[i]);
        be32enc(header + 76, nonce);
        char *hash_hex = bin2hex(hash_bytes, 32);
        char *header_hex = bin2hex(header, 80);
        applog(LOG_DEBUG, "  Header (80 bytes): %s", header_hex);
        applog(LOG_DEBUG, "  Hash (raw): %s", hash_hex);
        applog(LOG_DEBUG, "  hash[7..4]=%08x %08x %08x %08x target[7..4]=%08x %08x %08x %08x",
               hash_le[7], hash_le[6], hash_le[5], hash_le[4],
               ptarget[7], ptarget[6], ptarget[5], ptarget[4]);
        free(hash_hex);
        free(header_hex);
    }

    work->valid_nonces++;
}

int scanhash_sha256d(int thr_id, struct work *work, uint32_t max_hashes,
                     unsigned long *hashes_done)
{
    (void)thr_id;

    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint8_t header[80];
    uint32_t midstate[8];
    uint32_t n = pdata[19];  /* Nonce is at offset 76 (word 19) */
    uint32_t first_nonce = n;

    work->valid_nonces = 0;

    /* Construct correct 80-byte block header for SHA256 hashing.
     *
     * work->data[] stores values as le32dec() of stratum hex-decoded bytes.
     * The stratum protocol sends all 32-bit fields byte-swapped per word
     * compared to actual Bitcoin block header bytes. To get the real header
     * bytes, we use be32enc() which reverses the per-word swap.
     *
     * EXCEPTION: The merkle root (words 9-16) is computed internally from
     * sha256d of coinbase + merkle branches. Its bytes are already in the
     * correct "internal byte order" for the block header, stored via
     * le32dec() which preserves them. So we use le32enc() (identity) for
     * the merkle root to keep the raw hash bytes unchanged.
     */

    /* Version (word 0) + Previous block hash (words 1-8): byte-swap */
    for (int i = 0; i < 9; i++) {
        be32enc(header + i * 4, pdata[i]);
    }
    /* Merkle root (words 9-16): already in correct byte order */
    for (int i = 9; i < 17; i++) {
        le32enc(header + i * 4, pdata[i]);
    }
    /* nTime (word 17) + nBits (word 18) + nonce (word 19): byte-swap */
    for (int i = 17; i < 20; i++) {
        be32enc(header + i * 4, pdata[i]);
    }

    /* DEBUG: Log work->data for comparison */
    if (opt_debug && first_nonce == 0) {
        char *workdata_hex = bin2hex((unsigned char *)pdata, 80);
        char *header_hex = bin2hex(header, 80);
        applog(LOG_DEBUG, "work->data (raw): %s", workdata_hex);
        applog(LOG_DEBUG, "header (for SHA256): %s", header_hex);
        free(workdata_hex);
        free(header_hex);
    }

    /* Compute midstate for first 64 bytes (doesn't include nonce) */
    sha256_midstate_neon(header, midstate);

    /* Pre-build first-pass message words as uint32 (big-endian values).
     *
     * SHA256 works on big-endian uint32 words. The old code path was:
     *   be32enc(header+76, n) → sha256_transform reads via be32dec/vrev32q_u8
     * This round-trips through bytes needlessly. Instead, we compute the
     * big-endian uint32 words directly:
     *
     *   W1[0] = be32dec(header+64) = last merkle word (was le32enc'd, so bswap)
     *   W1[1] = be32dec(header+68) = ntime (was be32enc'd, so identity = pdata[17])
     *   W1[2] = be32dec(header+72) = nbits (was be32enc'd, so identity = pdata[18])
     *   W1[3] = nonce (set per iteration)
     *   W1[4] = 0x80000000 (SHA256 padding bit)
     *   W1[15] = 0x00000280 (message length = 640 bits)
     */
    uint32_t W1[16];
    memset(W1, 0, sizeof(W1));
    W1[0] = __builtin_bswap32(pdata[16]);  /* last merkle root word */
    W1[1] = pdata[17];                      /* ntime */
    W1[2] = pdata[18];                      /* nbits */
    /* W1[3] = nonce, set in loop */
    W1[4] = 0x80000000;                     /* SHA256 padding */
    W1[15] = 0x00000280;                    /* 640 bits (80 bytes) */

    /* Pre-build second-pass constant words (padding portion).
     * W2[0..7] = first SHA256 output (set in loop)
     * W2[8] = 0x80000000 (padding)
     * W2[15] = 0x00000100 (256 bits)
     */
    static const uint32_t W2_pad[8] = {
        0x80000000, 0, 0, 0, 0, 0, 0, 0x00000100
    };

    const int use_dual_asm = sha256_has_crypto();

    /* Dual-nonce mining loop using hand-tuned assembly.
     *
     * sha256d_dual_asm() performs complete SHA256d (both passes) for two
     * nonces with optimal A/B interleaving and zero memcpy between passes.
     * Pass 1 output stays in NEON registers and feeds directly into pass 2.
     */
    uint32_t remaining_hashes = max_hashes;
    while (remaining_hashes >= 2 &&
           !miner_work_restart_requested(work->restart_generation) && !miner_should_abort()) {
        uint32_t stateA[8], stateB[8];

        if (use_dual_asm) {
            sha256d_dual_asm(midstate, W1, W2_pad, n, n + 1, stateA, stateB);
        } else {
            sha256d_dual_fallback(midstate, W1, W2_pad, n, n + 1, stateA, stateB);
        }

        /* Check nonce A */
        if (__builtin_bswap32(stateA[7]) <= ptarget[7]) {
            uint32_t hash_le[8];
            for (int i = 0; i < 8; i++)
                hash_le[i] = __builtin_bswap32(stateA[i]);

            if (hash_le_target(hash_le, ptarget))
                sha256d_record_share(work, pdata, ptarget, stateA, hash_le, header, n);
        }

        /* Check nonce B */
        if (__builtin_bswap32(stateB[7]) <= ptarget[7]) {
            uint32_t hash_le[8];
            for (int i = 0; i < 8; i++)
                hash_le[i] = __builtin_bswap32(stateB[i]);

            if (hash_le_target(hash_le, ptarget) && work->valid_nonces < MAX_NONCES)
                sha256d_record_share(work, pdata, ptarget, stateB, hash_le, header, n + 1);
        }

        n += 2;
        remaining_hashes -= 2;
        if (work->valid_nonces) break;
    }

    /* Handle remaining odd nonce with single-nonce path */
    if (!work->valid_nonces && remaining_hashes > 0 &&
        !miner_work_restart_requested(work->restart_generation) && !miner_should_abort()) {
        uint32_t state[8];
        uint32_t W2[16];

        W1[3] = n;
        memcpy(state, midstate, 32);
        sha256_transform_u32(state, W1);

        memcpy(W2, state, 32);
        memcpy(W2 + 8, W2_pad, 32);
        memcpy(state, H256_INIT, 32);
        sha256_transform_u32(state, W2);

        if (__builtin_bswap32(state[7]) <= ptarget[7]) {
            uint32_t hash_le[8];
            for (int i = 0; i < 8; i++)
                hash_le[i] = __builtin_bswap32(state[i]);

            if (hash_le_target(hash_le, ptarget)) {
                pdata[19] = n;
                work->nonces[work->valid_nonces] = n;
                bn_store_share_difficulty(hash_le, ptarget, work, work->valid_nonces);
                work->valid_nonces++;
            }
        }
        n++;
        remaining_hashes--;
    }

    *hashes_done = n - first_nonce;
    pdata[19] = n;

    return work->valid_nonces;
}

#endif /* SHA256_STANDALONE */
