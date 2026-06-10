#include "haraka_native.h"
#include "cpu_features.h"
#include <string.h>
#include <stdio.h>

#ifdef __aarch64__

// Round constants - same as portable version
static const unsigned char haraka_rc[40][16] = {
    {0x9d, 0x7b, 0x81, 0x75, 0xf0, 0xfe, 0xc5, 0xb2, 0x0a, 0xc0, 0x20, 0xe6, 0x4c, 0x70, 0x84, 0x06},
    {0x17, 0xf7, 0x08, 0x2f, 0xa4, 0x6b, 0x0f, 0x64, 0x6b, 0xa0, 0xf3, 0x88, 0xe1, 0xb4, 0x66, 0x8b},
    {0x14, 0x91, 0x02, 0x9f, 0x60, 0x9d, 0x02, 0xcf, 0x98, 0x84, 0xf2, 0x53, 0x2d, 0xde, 0x02, 0x34},
    {0x79, 0x4f, 0x5b, 0xfd, 0xaf, 0xbc, 0xf3, 0xbb, 0x08, 0x4f, 0x7b, 0x2e, 0xe6, 0xea, 0xd6, 0x0e},
    {0x44, 0x70, 0x39, 0xbe, 0x1c, 0xcd, 0xee, 0x79, 0x8b, 0x44, 0x72, 0x48, 0xcb, 0xb0, 0xcf, 0xcb},
    {0x7b, 0x05, 0x8a, 0x2b, 0xed, 0x35, 0x53, 0x8d, 0xb7, 0x32, 0x90, 0x6e, 0xee, 0xcd, 0xea, 0x7e},
    {0x1b, 0xef, 0x4f, 0xda, 0x61, 0x27, 0x41, 0xe2, 0xd0, 0x7c, 0x2e, 0x5e, 0x43, 0x8f, 0xc2, 0x67},
    {0x3b, 0x0b, 0xc7, 0x1f, 0xe2, 0xfd, 0x5f, 0x67, 0x07, 0xcc, 0xca, 0xaf, 0xb0, 0xd9, 0x24, 0x29},
    {0xee, 0x65, 0xd4, 0xb9, 0xca, 0x8f, 0xdb, 0xec, 0xe9, 0x7f, 0x86, 0xe6, 0xf1, 0x63, 0x4d, 0xab},
    {0x33, 0x7e, 0x03, 0xad, 0x4f, 0x40, 0x2a, 0x5b, 0x64, 0xcd, 0xb7, 0xd4, 0x84, 0xbf, 0x30, 0x1c},
    {0x00, 0x98, 0xf6, 0x8d, 0x2e, 0x8b, 0x02, 0x69, 0xbf, 0x23, 0x17, 0x94, 0xb9, 0x0b, 0xcc, 0xb2},
    {0x8a, 0x2d, 0x9d, 0x5c, 0xc8, 0x9e, 0xaa, 0x4a, 0x72, 0x55, 0x6f, 0xde, 0xa6, 0x78, 0x04, 0xfa},
    {0xd4, 0x9f, 0x12, 0x29, 0x2e, 0x4f, 0xfa, 0x0e, 0x12, 0x2a, 0x77, 0x6b, 0x2b, 0x9f, 0xb4, 0xdf},
    {0xee, 0x12, 0x6a, 0xbb, 0xae, 0x11, 0xd6, 0x32, 0x36, 0xa2, 0x49, 0xf4, 0x44, 0x03, 0xa1, 0x1e},
    {0xa6, 0xec, 0xa8, 0x9c, 0xc9, 0x00, 0x96, 0x5f, 0x84, 0x00, 0x05, 0x4b, 0x88, 0x49, 0x04, 0xaf},
    {0xec, 0x93, 0xe5, 0x27, 0xe3, 0xc7, 0xa2, 0x78, 0x4f, 0x9c, 0x19, 0x9d, 0xd8, 0x5e, 0x02, 0x21},
    {0x73, 0x01, 0xd4, 0x82, 0xcd, 0x2e, 0x28, 0xb9, 0xb7, 0xc9, 0x59, 0xa7, 0xf8, 0xaa, 0x3a, 0xbf},
    {0x6b, 0x7d, 0x30, 0x10, 0xd9, 0xef, 0xf2, 0x37, 0x17, 0xb0, 0x86, 0x61, 0x0d, 0x70, 0x60, 0x62},
    {0xc6, 0x9a, 0xfc, 0xf6, 0x53, 0x91, 0xc2, 0x81, 0x43, 0x04, 0x30, 0x21, 0xc2, 0x45, 0xca, 0x5a},
    {0x3a, 0x94, 0xd1, 0x36, 0xe8, 0x92, 0xaf, 0x2c, 0xbb, 0x68, 0x6b, 0x22, 0x3c, 0x97, 0x23, 0x92},
    {0xb4, 0x71, 0x10, 0xe5, 0x58, 0xb9, 0xba, 0x6c, 0xeb, 0x86, 0x58, 0x22, 0x38, 0x92, 0xbf, 0xd3},
    {0x8d, 0x12, 0xe1, 0x24, 0xdd, 0xfd, 0x3d, 0x93, 0x77, 0xc6, 0xf0, 0xae, 0xe5, 0x3c, 0x86, 0xdb},
    {0xb1, 0x12, 0x22, 0xcb, 0xe3, 0x8d, 0xe4, 0x83, 0x9c, 0xa0, 0xeb, 0xff, 0x68, 0x62, 0x60, 0xbb},
    {0x7d, 0xf7, 0x2b, 0xc7, 0x4e, 0x1a, 0xb9, 0x2d, 0x9c, 0xd1, 0xe4, 0xe2, 0xdc, 0xd3, 0x4b, 0x73},
    {0x4e, 0x92, 0xb3, 0x2c, 0xc4, 0x15, 0x14, 0x4b, 0x43, 0x1b, 0x30, 0x61, 0xc3, 0x47, 0xbb, 0x43},
    {0x99, 0x68, 0xeb, 0x16, 0xdd, 0x31, 0xb2, 0x03, 0xf6, 0xef, 0x07, 0xe7, 0xa8, 0x75, 0xa7, 0xdb},
    {0x2c, 0x47, 0xca, 0x7e, 0x02, 0x23, 0x5e, 0x8e, 0x77, 0x59, 0x75, 0x3c, 0x4b, 0x61, 0xf3, 0x6d},
    {0xf9, 0x17, 0x86, 0xb8, 0xb9, 0xe5, 0x1b, 0x6d, 0x77, 0x7d, 0xde, 0xd6, 0x17, 0x5a, 0xa7, 0xcd},
    {0x5d, 0xee, 0x46, 0xa9, 0x9d, 0x06, 0x6c, 0x9d, 0xaa, 0xe9, 0xa8, 0x6b, 0xf0, 0x43, 0x6b, 0xec},
    {0xc1, 0x27, 0xf3, 0x3b, 0x59, 0x11, 0x53, 0xa2, 0x2b, 0x33, 0x57, 0xf9, 0x50, 0x69, 0x1e, 0xcb},
    {0xd9, 0xd0, 0x0e, 0x60, 0x53, 0x03, 0xed, 0xe4, 0x9c, 0x61, 0xda, 0x00, 0x75, 0x0c, 0xee, 0x2c},
    {0x50, 0xa3, 0xa4, 0x63, 0xbc, 0xba, 0xbb, 0x80, 0xab, 0x0c, 0xe9, 0x96, 0xa1, 0xa5, 0xb1, 0xf0},
    {0x39, 0xca, 0x8d, 0x93, 0x30, 0xde, 0x0d, 0xab, 0x88, 0x29, 0x96, 0x5e, 0x02, 0xb1, 0x3d, 0xae},
    {0x42, 0xb4, 0x75, 0x2e, 0xa8, 0xf3, 0x14, 0x88, 0x0b, 0xa4, 0x54, 0xd5, 0x38, 0x8f, 0xbb, 0x17},
    {0xf6, 0x16, 0x0a, 0x36, 0x79, 0xb7, 0xb6, 0xae, 0xd7, 0x7f, 0x42, 0x5f, 0x5b, 0x8a, 0xbb, 0x34},
    {0xde, 0xaf, 0xba, 0xff, 0x18, 0x59, 0xce, 0x43, 0x38, 0x54, 0xe5, 0xcb, 0x41, 0x52, 0xf6, 0x26},
    {0x78, 0xc9, 0x9e, 0x83, 0xf7, 0x9c, 0xca, 0xa2, 0x6a, 0x02, 0xf3, 0xb9, 0x54, 0x9a, 0xe9, 0x4c},
    {0x35, 0x12, 0x90, 0x22, 0x28, 0x6e, 0xc0, 0x40, 0xbe, 0xf7, 0xdf, 0x1b, 0x1a, 0xa5, 0x51, 0xae},
    {0xcf, 0x59, 0xa6, 0x48, 0x0f, 0xbc, 0x73, 0xc1, 0x2b, 0xd2, 0x7e, 0xba, 0x3c, 0x61, 0xc1, 0xa0},
    {0xa1, 0x9d, 0xc5, 0xe9, 0xfd, 0xbd, 0xd6, 0x4a, 0x88, 0x82, 0x28, 0x02, 0x03, 0xcc, 0x6a, 0x75}
};

// Native round constants converted to NEON format
static uint8x16_t rc_native[40];

void load_constants_native(void) {
    // Convert portable constants to NEON format
    for (int i = 0; i < 40; i++) {
        rc_native[i] = vld1q_u8(haraka_rc[i]);
    }
}

// Native AES round function is defined in header

// Native NEON unpack operations (optimized for common patterns)
// ORIGINAL: Used vzip1q_u32/vzip2q_u32 (backup_originals/haraka_native.c)
static inline uint8x16_t unpack_lo_epi32_native(uint8x16_t a, uint8x16_t b) {
    // Convert to 32-bit view and use native NEON zip
    uint32x4_t a32 = vreinterpretq_u32_u8(a);
    uint32x4_t b32 = vreinterpretq_u32_u8(b);
    return vreinterpretq_u8_u32(vzip1q_u32(a32, b32));
}

static inline uint8x16_t unpack_hi_epi32_native(uint8x16_t a, uint8x16_t b) {
    // Convert to 32-bit view and use native NEON zip
    uint32x4_t a32 = vreinterpretq_u32_u8(a);
    uint32x4_t b32 = vreinterpretq_u32_u8(b);
    return vreinterpretq_u8_u32(vzip2q_u32(a32, b32));
}

// PERFORMANCE: Mark as hot to optimize for speed
__attribute__((hot))
void haraka256_native(unsigned char *out, const unsigned char *in) {
    uint8x16_t s0, s1, tmp;

    // Load 32-byte input as two 16-byte blocks
    s0 = vld1q_u8(in);
    s1 = vld1q_u8(in + 16);

    // 5 rounds of Haraka256
    for (int i = 0; i < 5; i++) {
        // 2 AES rounds per 16-byte block
        for (int j = 0; j < 2; j++) {
            s0 = aes_encrypt_round_native(s0, rc_native[2*2*i + 2*j]);
            s1 = aes_encrypt_round_native(s1, rc_native[2*2*i + 2*j + 1]);
        }

        // Mixing step
        tmp = unpack_lo_epi32_native(s0, s1);
        s1 = unpack_hi_epi32_native(s0, s1);
        s0 = tmp;
    }

    // Feed-forward: XOR with original input
    uint8x16_t in0 = vld1q_u8(in);
    uint8x16_t in1 = vld1q_u8(in + 16);
    s0 = veorq_u8(s0, in0);
    s1 = veorq_u8(s1, in1);

    // Store result
    vst1q_u8(out, s0);
    vst1q_u8(out + 16, s1);
}

void haraka256_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc) {
    uint8x16_t s0, s1, tmp;
    
    // Load 32-byte input
    s0 = vld1q_u8(in);
    s1 = vld1q_u8(in + 16);
    
    // 5 rounds with custom key
    for (int i = 0; i < 5; i++) {
        // 2 AES rounds per block
        for (int j = 0; j < 2; j++) {
            s0 = aes_encrypt_round_native(s0, rc[2*2*i + 2*j]);
            s1 = aes_encrypt_round_native(s1, rc[2*2*i + 2*j + 1]);
        }

        // Mixing step
        tmp = unpack_lo_epi32_native(s0, s1);
        s1 = unpack_hi_epi32_native(s0, s1);
        s0 = tmp;
    }

    // Feed-forward
    uint8x16_t in0 = vld1q_u8(in);
    uint8x16_t in1 = vld1q_u8(in + 16);
    s0 = veorq_u8(s0, in0);
    s1 = veorq_u8(s1, in1);

    // Store result
    vst1q_u8(out, s0);
    vst1q_u8(out + 16, s1);
}

// Haraka512 permutation implementation
static void haraka512_perm_native(unsigned char *out, const unsigned char *in) {
    uint8x16_t s0, s1, s2, s3, tmp;
    
    // Load 64-byte input as four 16-byte blocks
    s0 = vld1q_u8(in);
    s1 = vld1q_u8(in + 16);
    s2 = vld1q_u8(in + 32);
    s3 = vld1q_u8(in + 48);
    
    // 5 rounds of Haraka512
    for (int i = 0; i < 5; i++) {
        // 2 AES rounds per block (8 total AES operations)
        for (int j = 0; j < 2; j++) {
            s0 = aes_encrypt_round_native(s0, rc_native[4*2*i + 4*j]);
            s1 = aes_encrypt_round_native(s1, rc_native[4*2*i + 4*j + 1]);
            s2 = aes_encrypt_round_native(s2, rc_native[4*2*i + 4*j + 2]);
            s3 = aes_encrypt_round_native(s3, rc_native[4*2*i + 4*j + 3]);
        }

        // Complex mixing step (matches portable version exactly)
        tmp = unpack_lo_epi32_native(s0, s1);
        s0 = unpack_hi_epi32_native(s0, s1);
        s1 = unpack_lo_epi32_native(s2, s3);
        s2 = unpack_hi_epi32_native(s2, s3);
        s3 = unpack_lo_epi32_native(s0, s2);
        s0 = unpack_hi_epi32_native(s0, s2);
        s2 = unpack_hi_epi32_native(s1, tmp);
        s1 = unpack_lo_epi32_native(s1, tmp);
    }
    
    // Store result
    vst1q_u8(out, s0);
    vst1q_u8(out + 16, s1);
    vst1q_u8(out + 32, s2);
    vst1q_u8(out + 48, s3);
}

void haraka512_native(unsigned char *out, const unsigned char *in) {
    unsigned char buf[64];

    // Apply permutation
    haraka512_perm_native(buf, in);

    // Feed-forward: XOR with original input
    for (int i = 0; i < 64; i++) {
        buf[i] = buf[i] ^ in[i];
    }

    // Truncated output (same offsets as portable version)
    memcpy(out,      buf + 8,  8);
    memcpy(out + 8,  buf + 24, 8);
    memcpy(out + 16, buf + 32, 8);
    memcpy(out + 24, buf + 48, 8);
}

// PERFORMANCE: Optimized partial computation - only computes the 4 bytes needed
// for difficulty checking (vhash[7] = out[28..31]).
// Matches the portable oink70 optimization in haraka.c:40-76.
//
// Savings vs full computation:
//   Round 4 MIX: only 1 vector (MIX4_LAST) instead of 4 (full MIX4)
//   Round 5 AES: only 2 ops (AES4_LAST) instead of 8 (full AES4)
//   Feed-forward: only 4 bytes XOR instead of 64 bytes
//   Output: only 4 bytes instead of 32 bytes via 4x memcpy
__attribute__((hot))
void haraka512_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc) {
    struct int64x2x4_t s;
    struct int64x2x4_t n;

#define AES4_NATIVE(s0, s1, s2, s3, rci) \
    s0 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s0), rc[(rci)])); \
    s1 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s1), rc[(rci) + 1])); \
    s2 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s2), rc[(rci) + 2])); \
    s3 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s3), rc[(rci) + 3])); \
    s0 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s0), rc[(rci) + 4])); \
    s1 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s1), rc[(rci) + 5])); \
    s2 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s2), rc[(rci) + 6])); \
    s3 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s3), rc[(rci) + 7]));

#define AES4_LAST_NATIVE(s0, s1, s2, s3, rci) \
    s2 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s2), rc[(rci) + 2])); \
    s2 = vreinterpretq_s64_u8(aes_encrypt_round_native(vreinterpretq_u8_s64(s2), rc[(rci) + 6]));

#define MIX4A_NATIVE(s0, s1, s2, s3) \
    n.val[0] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(n.val[0]), 0, vreinterpretq_s32_s64(s0), 3), 1, vreinterpretq_s32_s64(s2), 3), 2, vreinterpretq_s32_s64(s1), 3), 3, vreinterpretq_s32_s64(s3), 3)); \
    n.val[1] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(n.val[1]), 0, vreinterpretq_s32_s64(s2), 0), 1, vreinterpretq_s32_s64(s0), 0), 2, vreinterpretq_s32_s64(s3), 0), 3, vreinterpretq_s32_s64(s1), 0)); \
    n.val[2] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(n.val[2]), 0, vreinterpretq_s32_s64(s2), 1), 1, vreinterpretq_s32_s64(s0), 1), 2, vreinterpretq_s32_s64(s3), 1), 3, vreinterpretq_s32_s64(s1), 1)); \
    n.val[3] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(n.val[3]), 0, vreinterpretq_s32_s64(s0), 2), 1, vreinterpretq_s32_s64(s2), 2), 2, vreinterpretq_s32_s64(s1), 2), 3, vreinterpretq_s32_s64(s3), 2));

#define MIX4B_NATIVE(s0, s1, s2, s3) \
    s.val[0] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(s.val[0]), 0, vreinterpretq_s32_s64(s0), 3), 1, vreinterpretq_s32_s64(s2), 3), 2, vreinterpretq_s32_s64(s1), 3), 3, vreinterpretq_s32_s64(s3), 3)); \
    s.val[1] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(s.val[1]), 0, vreinterpretq_s32_s64(s2), 0), 1, vreinterpretq_s32_s64(s0), 0), 2, vreinterpretq_s32_s64(s3), 0), 3, vreinterpretq_s32_s64(s1), 0)); \
    s.val[2] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(s.val[2]), 0, vreinterpretq_s32_s64(s2), 1), 1, vreinterpretq_s32_s64(s0), 1), 2, vreinterpretq_s32_s64(s3), 1), 3, vreinterpretq_s32_s64(s1), 1)); \
    s.val[3] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(s.val[3]), 0, vreinterpretq_s32_s64(s0), 2), 1, vreinterpretq_s32_s64(s2), 2), 2, vreinterpretq_s32_s64(s1), 2), 3, vreinterpretq_s32_s64(s3), 2));

#define MIX4_LAST_NATIVE(s0, s1, s2, s3) \
    s.val[1] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(s.val[1]), 0, vreinterpretq_s32_s64(s2), 0), 1, vreinterpretq_s32_s64(s3), 0), 2, vreinterpretq_s32_s64(s2), 1), 3, vreinterpretq_s32_s64(s3), 1)); \
    s.val[2] = vreinterpretq_s64_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vcopyq_laneq_s32(vreinterpretq_s32_s64(s.val[2]), 0, vreinterpretq_s32_s64(s2), 1), 1, vreinterpretq_s32_s64(s0), 1), 2, vreinterpretq_s32_s64(s3), 1), 3, vreinterpretq_s32_s64(s1), 1));

    // Keep structure aligned with the portable implementation to preserve
    // codegen behavior in this hot keyed path.
    s = vld1q_s64_x4((const int64_t *)in);

    AES4_NATIVE(s.val[0], s.val[1], s.val[2], s.val[3], 0);
    MIX4A_NATIVE(s.val[0], s.val[1], s.val[2], s.val[3]);

    AES4_NATIVE(n.val[0], n.val[1], n.val[2], n.val[3], 8);
    MIX4B_NATIVE(n.val[0], n.val[1], n.val[2], n.val[3]);

    AES4_NATIVE(s.val[0], s.val[1], s.val[2], s.val[3], 16);
    MIX4A_NATIVE(s.val[0], s.val[1], s.val[2], s.val[3]);

    AES4_NATIVE(n.val[0], n.val[1], n.val[2], n.val[3], 24);
    MIX4_LAST_NATIVE(n.val[0], n.val[1], n.val[2], n.val[3]);

    AES4_LAST_NATIVE(n.val[0], s.val[1], s.val[2], n.val[3], 32);

    ((uint32_t*)&out[0])[7] = ((uint32_t*)&s.val[0])[10] ^ ((const uint32_t*)&in[52])[0];

#undef MIX4_LAST_NATIVE
#undef MIX4B_NATIVE
#undef MIX4A_NATIVE
#undef AES4_LAST_NATIVE
#undef AES4_NATIVE
}

#else

// Fallback implementations for non-ARM64 systems
void load_constants_native(void) {
    // No-op on non-ARM systems
}

void haraka256_native(unsigned char *out, const unsigned char *in) {
    // Should never be called on non-ARM systems
    memset(out, 0, 32);
}

void haraka256_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc) {
    memset(out, 0, 32);
}

void haraka512_native(unsigned char *out, const unsigned char *in) {
    memset(out, 0, 32);
}

void haraka512_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc) {
    memset(out, 0, 32);
}

#endif // __aarch64__
