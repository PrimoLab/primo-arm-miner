#ifndef HARAKA_NATIVE_H_
#define HARAKA_NATIVE_H_

#ifdef __aarch64__
#include <arm_neon.h>
#endif

// Use same types as portable version for compatibility
#ifdef _WIN32
typedef unsigned long long u64;
#else  
typedef unsigned long u64;
#endif

// Native code uses ARM NEON vector types directly.

#ifdef __cplusplus
extern "C" {
#endif

// Native ARMv8 implementations - exact same signatures as portable versions
void load_constants_native(void);

// Haraka256 variants
void haraka256_native(unsigned char *out, const unsigned char *in);
void haraka256_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc);

// Haraka512 variants  
void haraka512_native(unsigned char *out, const unsigned char *in);
void haraka512_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc);

// Test/verification functions

#ifdef __cplusplus
}
#endif

// Native ARMv8 crypto macros and inline functions
#ifdef __aarch64__

// Load/Store operations (compatible with SSE2NEON interface)
#define LOAD_NATIVE(src) vld1q_u8((const uint8_t *)(src))
#define STORE_NATIVE(dest, src) vst1q_u8((uint8_t *)(dest), (src))

// AES round function using ARMv8 crypto extensions
// PERFORMANCE: Force inline to eliminate function call overhead
static inline uint8x16_t aes_encrypt_round_native(uint8x16_t state, uint8x16_t round_key) __attribute__((always_inline));
static inline uint8x16_t aes_encrypt_round_native(uint8x16_t state, uint8x16_t round_key) {
    // ARMv8 AES: SubBytes + ShiftRows + MixColumns + AddRoundKey
    return vaesmcq_u8(vaeseq_u8(state, (uint8x16_t){})) ^ round_key;
}

// Native NEON shuffle operations (optimized for common Haraka patterns)
// PERFORMANCE: Force inline to eliminate function call overhead
static inline uint32x4_t neon_unpack_lo_epi32(uint32x4_t a, uint32x4_t b) __attribute__((always_inline));
static inline uint32x4_t neon_unpack_lo_epi32(uint32x4_t a, uint32x4_t b) {
    return vzip1q_u32(a, b);
}

static inline uint32x4_t neon_unpack_hi_epi32(uint32x4_t a, uint32x4_t b) __attribute__((always_inline));
static inline uint32x4_t neon_unpack_hi_epi32(uint32x4_t a, uint32x4_t b) {
    return vzip2q_u32(a, b);
}

// Efficient lane copy operations (already optimal in current implementation)
#define COPY_LANE_NATIVE(dst, dst_lane, src, src_lane) \
    vsetq_lane_s32(vgetq_lane_s32(src, src_lane), dst, dst_lane)

#endif // __aarch64__

#endif // HARAKA_NATIVE_H_
