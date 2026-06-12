#ifndef CLHASH_NATIVE_H_
#define CLHASH_NATIVE_H_

#include <stdint.h>
#include <arm_neon.h>

#ifndef USE_A76_ASM_AES_MIX2
#define USE_A76_ASM_AES_MIX2 1
#endif

#ifndef USE_A76_ASM_CASE18_CLMUL
#define USE_A76_ASM_CASE18_CLMUL 1
#endif

#ifndef USE_A76_CASE18_CLMUL_MEM_BARRIER
#define USE_A76_CASE18_CLMUL_MEM_BARRIER 0
#endif

#ifndef USE_A76_ASM_XOR_LOW32
#define USE_A76_ASM_XOR_LOW32 1
#endif

#ifndef USE_A76_CASE18_FIXEDCOUNT
#define USE_A76_CASE18_FIXEDCOUNT 1
#endif

#ifndef USE_A76_CASE18_MASK_PTRS
#define USE_A76_CASE18_MASK_PTRS 1
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Native CLHash using ARMv8 PMULL instructions
// Replacement for verusclhash_port2_2 with native polynomial multiplication

// Core polynomial multiplication function matching the original portable lane
// selection used by the Verus reference path: High(A) x Low(B).
static inline uint64x2_t clmul_native(uint64x2_t a, uint64x2_t b, int selector) __attribute__((always_inline));
static inline uint64x2_t clmul_native(uint64x2_t a, uint64x2_t b, int selector) {
    // Step 1: Extract high part of a and low part of b as uint64x1_t vectors
    uint64x1_t a_high_vec = vget_high_u64(a);
    uint64x1_t b_low_vec = vget_low_u64(b);
    // Step 2: Convert to poly64_t for polynomial multiplication
    poly64_t a_high = vget_lane_p64(vreinterpret_p64_u64(a_high_vec), 0);
    poly64_t b_low = vget_lane_p64(vreinterpret_p64_u64(b_low_vec), 0);
    // Step 3: Perform polynomial multiplication and return as uint64x2_t
    return vreinterpretq_u64_p128(vmull_p64(a_high, b_low));
}

// Removed clmul_reduction_native - it's identical to clmul_native, using that instead

// Polynomial reduction for GF(2^64) matching the original portable algorithm
// Implements reduction modulo 2^64 + 2^4 + 2^3 + 2^1 + 1
// PERFORMANCE: Force inline to eliminate function call overhead
static inline uint64_t precompReduction64_native(uint64x2_t A) __attribute__((always_inline));
static inline uint64_t precompReduction64_native(uint64x2_t A) {
    // Reduction polynomial: (1<<4)+(1<<3)+(1<<1)+(1<<0) = 0x1B
    // CRITICAL CONSENSUS FIX: Create C vector exactly like portable version
    // _mm_cvtsi64_si128_emu(0x1B) puts 0x1B in LOW position: [0x1B, 0x0]
    // Since clmul_reduction_native always does High(A) × Low(C), we need 0x1B in LOW position
    uint64x2_t C = vcombine_u64(vcreate_u64(0x1B), vcreate_u64(0));
    
    // Q2 = _mm_clmulepi64_si128_emu(A, C, 0x01); // Low of A × High of C
    // CRITICAL BUG FIX: The portable _mm_clmulepi64_si128_emu IGNORES the imm parameter!
    // It always does: vmull_p64(vgetq_lane_u64(a, 1), vgetq_lane_u64(b,0))
    // This is High(A) × Low(C), which is exactly what clmul_reduction_native does!
    uint64x2_t Q2 = clmul_native(A, C, 0x01);
    
    // PURE NEON: Table lookup for reduction (replaces _mm_shuffle_epi8)
    // Original: _mm_shuffle_epi8(table, _mm_srli_si128(Q2, 8))
    // _mm_srli_si128(Q2, 8) extracts high 64 bits of Q2
    // _mm_shuffle_epi8 does table lookup

    // Shuffle table for GF(2^64) reduction
    static const int8x16_t shuffle_table = (int8x16_t){0, 27, 54, 45, 108, 119, 90, 65,
                                                        (int8_t)216, (int8_t)195, (int8_t)238, (int8_t)245,
                                                        (int8_t)180, (int8_t)175, (int8_t)130, (int8_t)153};

    // Extract high 64 bits of Q2 as index (replaces _mm_srli_si128)
    // Shift right 8 bytes = move high 64 bits to low position
    uint8x16_t Q2_shifted = vextq_u8(vreinterpretq_u8_u64(Q2), vdupq_n_u8(0), 8);

    // Table lookup (replaces _mm_shuffle_epi8)
    // Mask index to keep only the bits used by the original table lookup
    uint8x16_t idx_masked = vandq_u8(Q2_shifted, vdupq_n_u8(0x8F));
    int8x16_t Q3_s8 = vqtbl1q_s8(shuffle_table, idx_masked);
    uint64x2_t Q3 = vreinterpretq_u64_s8(Q3_s8);
    
    // Q4 = _mm_xor_si128_emu(Q2, A);
    uint64x2_t Q4 = veorq_u64(Q2, A);
    
    // final = _mm_xor_si128_emu(Q3, Q4);
    uint64x2_t final = veorq_u64(Q3, Q4);
    
    // Return low 64 bits (high 64 bits contain garbage as per portable version)
    return vgetq_lane_u64(final, 0);
}

// Core CLHash implementation matching portable algorithm exactly
uint64x2_t __verusclmulwithoutreduction64alignedrepeat_port2_2_native(uint64x2_t *randomsource, const uint64x2_t buf[4], uint64_t keyMask,
                                                                       uint16_t *__restrict fixrand, uint16_t *__restrict fixrandex,
                                                                       uint64x2_t *g_prand, uint64x2_t *g_prandex);

uint64_t verusclhash_port2_2_native(void *random, const unsigned char buf[64], uint64_t keyMask,
                                    uint16_t *__restrict fixrand, uint16_t *__restrict fixrandex,
                                    uint64x2_t *g_prand, uint64x2_t *g_prandex);

// Two-nonce interleaved CLHash: two independent chains (separate key buffers)
// run through the same loop so an OoO core overlaps their latency chains.
// Results are the fully reduced 64-bit intermediates, bit-identical per chain
// to verusclhash_port2_2_native.
void verusclhash_port2_2_x2_native(void * __restrict random1, void * __restrict random2,
                                   const unsigned char buf1[64], const unsigned char buf2[64],
                                   uint64_t keyMask,
                                   uint16_t * __restrict fixrand1, uint16_t * __restrict fixrandex1,
                                   uint64x2_t * __restrict g_prand1, uint64x2_t * __restrict g_prandex1,
                                   uint16_t * __restrict fixrand2, uint16_t * __restrict fixrandex2,
                                   uint64x2_t * __restrict g_prand2, uint64x2_t * __restrict g_prandex2,
                                   uint64_t * __restrict result1, uint64_t * __restrict result2);

// Fused-dispatch two-nonce CLHash (experimental, VERUS_FUSE=1). Same contract
// as the x2 entry point; both chains' case dispatches share one 64-way switch.
void verusclhash_port2_2_x2f_native(void * __restrict random1, void * __restrict random2,
                                    const unsigned char buf1[64], const unsigned char buf2[64],
                                    uint64_t keyMask,
                                    uint16_t * __restrict fixrand1, uint16_t * __restrict fixrandex1,
                                    uint64x2_t * __restrict g_prand1, uint64x2_t * __restrict g_prandex1,
                                    uint16_t * __restrict fixrand2, uint16_t * __restrict fixrandex2,
                                    uint64x2_t * __restrict g_prand2, uint64x2_t * __restrict g_prandex2,
                                    uint64_t * __restrict result1, uint64_t * __restrict result2);

// Three-nonce interleaved CLHash (experimental, VERUS_X3=1). Same contract as
// the x2 entry point with a third independent chain.
void verusclhash_port2_2_x3_native(void * __restrict random1, void * __restrict random2,
                                   void * __restrict random3,
                                   const unsigned char buf1[64], const unsigned char buf2[64],
                                   const unsigned char buf3[64],
                                   uint64_t keyMask,
                                   uint16_t * __restrict fixrand1, uint16_t * __restrict fixrandex1,
                                   uint64x2_t * __restrict g_prand1, uint64x2_t * __restrict g_prandex1,
                                   uint16_t * __restrict fixrand2, uint16_t * __restrict fixrandex2,
                                   uint64x2_t * __restrict g_prand2, uint64x2_t * __restrict g_prandex2,
                                   uint16_t * __restrict fixrand3, uint16_t * __restrict fixrandex3,
                                   uint64x2_t * __restrict g_prand3, uint64x2_t * __restrict g_prandex3,
                                   uint64_t * __restrict result1, uint64_t * __restrict result2,
                                   uint64_t * __restrict result3);

// Initialize CLHash constants for native implementation
void load_clhash_constants_native(void);

// =============================================================================
// PHASE 1 OPTIMIZATION: Code size reduction helpers
// =============================================================================

// Need aes_encrypt_round_native from haraka_native.h for AES helper
#ifndef HARAKA_NATIVE_H_
// Define inline if haraka_native.h not included yet
static inline uint8x16_t aes_encrypt_round_native_inline(uint8x16_t state, uint8x16_t round_key) {
    return vaesmcq_u8(vaeseq_u8(state, (uint8x16_t){})) ^ round_key;
}
#define AES_ROUND aes_encrypt_round_native_inline
#else
#define AES_ROUND aes_encrypt_round_native
#endif

// ARM-specific: Extract duplicate AES round sequences to reduce i-cache pressure
// Forces inline to avoid call overhead while reducing duplicate code in switch cases
static inline void aes_rounds_4_native(uint64x2_t *temp1, uint64x2_t *temp2,
                                       const uint8x16_t *rc, uint64_t round_block)
    __attribute__((always_inline));
static inline void aes_rounds_4_native(uint64x2_t *temp1, uint64x2_t *temp2,
                                       const uint8x16_t *rc, uint64_t round_block) {
    // Pre-compute pointer so compiler can use LDP (load pair) instead of
    // BFI+LDR for each key. This matches how portable accesses round keys.
    const uint8x16_t *rk = rc + (round_block << 2);
    *temp1 = vreinterpretq_u64_u8(AES_ROUND(vreinterpretq_u8_u64(*temp1), rk[0]));
    *temp2 = vreinterpretq_u64_u8(AES_ROUND(vreinterpretq_u8_u64(*temp2), rk[1]));
    *temp1 = vreinterpretq_u64_u8(AES_ROUND(vreinterpretq_u8_u64(*temp1), rk[2]));
    *temp2 = vreinterpretq_u64_u8(AES_ROUND(vreinterpretq_u8_u64(*temp2), rk[3]));
}

// ARM-specific: MIX2_EMU pattern extraction for case 0x10/0x14
// Uses ARM vzip1q/vzip2q (unpack lo/hi) matching portable's _mm_unpacklo/hi_epi32
// Note: portable's "best" __builtin_shufflevector version compiles to identical zip1/zip2
// instructions, confirmed by disassembly comparison of both binaries
static inline void mix2_emu_simple_native(uint64x2_t *temp1, uint64x2_t *temp2)
    __attribute__((always_inline));
static inline void mix2_emu_simple_native(uint64x2_t *temp1, uint64x2_t *temp2) {
    uint64x2_t tmp = vreinterpretq_u64_u32(vzip1q_u32(vreinterpretq_u32_u64(*temp1),
                                                       vreinterpretq_u32_u64(*temp2)));
    *temp2 = vreinterpretq_u64_u32(vzip2q_u32(vreinterpretq_u32_u64(*temp1),
                                               vreinterpretq_u32_u64(*temp2)));
    *temp1 = tmp;
}

// Hand-tuned A76 path for one AES2 + MIX2 block used in case 0x14.
// Returns MIX2(temp1, temp2) lane-wise XOR (i.e., zip1 ^ zip2) directly.
// This matches the case 0x14 usage pattern (acc ^= onekey ^ temp2) while
// avoiding an extra move/combine sequence in the hot loop.
static inline uint64x2_t aes_rounds_4_mix2_xor_native_a76(uint64x2_t temp1, uint64x2_t temp2,
                                                           const uint8x16_t *rk)
    __attribute__((always_inline));
static inline uint64x2_t aes_rounds_4_mix2_xor_native_a76(uint64x2_t temp1, uint64x2_t temp2,
                                                           const uint8x16_t *rk) {
#if USE_A76_ASM_AES_MIX2 && defined(__aarch64__) && (defined(__clang__) || defined(__GNUC__))
    uint8x16_t s0 = vreinterpretq_u8_u64(temp1);
    uint8x16_t s1 = vreinterpretq_u8_u64(temp2);
    const uint8x16_t z = vdupq_n_u8(0);
    uint8x16_t k0, k1, k2, k3, t;

    asm volatile(
        "ldp %q[k0], %q[k1], [%[rk]]\n\t"
        "aese %[s0].16b, %[z].16b\n\t"
        "aesmc %[s0].16b, %[s0].16b\n\t"
        "aese %[s1].16b, %[z].16b\n\t"
        "aesmc %[s1].16b, %[s1].16b\n\t"
        // Fold round-1 key into round-2 AESE (compiler does this automatically in C path).
        "aese %[s0].16b, %[k0].16b\n\t"
        "aesmc %[s0].16b, %[s0].16b\n\t"
        "ldp %q[k2], %q[k3], [%[rk], #32]\n\t"
        "aese %[s1].16b, %[k1].16b\n\t"
        "aesmc %[s1].16b, %[s1].16b\n\t"
        "eor %[s0].16b, %[s0].16b, %[k2].16b\n\t"
        "eor %[s1].16b, %[s1].16b, %[k3].16b\n\t"
        // Preserve source regs for both ZIP ops and fold zip1^zip2 here.
        "zip2 %[t].4s, %[s0].4s, %[s1].4s\n\t"
        "zip1 %[s0].4s, %[s0].4s, %[s1].4s\n\t"
        "eor %[s0].16b, %[s0].16b, %[t].16b\n\t"
        : [s0] "+w"(s0), [s1] "+w"(s1), [k0] "=&w"(k0), [k1] "=&w"(k1),
          [k2] "=&w"(k2), [k3] "=&w"(k3), [t] "=&w"(t)
        : [rk] "r"(rk), [z] "w"(z)
        : "memory");

    return vreinterpretq_u64_u8(s0);
#else
    aes_rounds_4_native(&temp1, &temp2, rk, 0);
    mix2_emu_simple_native(&temp1, &temp2);
    return veorq_u64(temp1, temp2);
#endif
}

// XOR a 32-bit scalar into low 32 bits of acc with minimal lane traffic.
// Bit-for-bit equivalent to: acc ^= cvtsi32_si128(modulo_result)
static inline uint64x2_t xor_low32_lane_native_a76(uint64x2_t acc, uint32_t x)
    __attribute__((always_inline));
static inline uint64x2_t xor_low32_lane_native_a76(uint64x2_t acc, uint32_t x) {
#if USE_A76_ASM_XOR_LOW32 && defined(__aarch64__) && (defined(__clang__) || defined(__GNUC__))
    uint32_t t;
    asm volatile(
        "umov %w[t], %[acc].s[0]\n\t"
        "eor %w[t], %w[t], %w[x]\n\t"
        "ins %[acc].s[0], %w[t]\n\t"
        : [acc] "+w"(acc), [t] "=&r"(t)
        : [x] "r"(x));
    return acc;
#else
    uint32x4_t a = vreinterpretq_u32_u64(acc);
    a = vsetq_lane_u32(vgetq_lane_u32(a, 0) ^ x, a, 0);
    return vreinterpretq_u64_u32(a);
#endif
}

// Hand-tuned CLMUL + mulhrs + xor block for case 0x18 non-division branch.
// Computes:
//   onekey = clmul((onekey ^ temp), (onekey ^ temp))
//   acc ^= mulhrs(acc, onekey)
// Returns updated onekey and updates *acc in place.
static inline uint64x2_t case18_clmul_mulhrs_xor_native_a76(uint64x2_t *acc,
                                                             uint64x2_t onekey,
                                                             uint64x2_t temp)
    __attribute__((always_inline));
static inline uint64x2_t case18_clmul_mulhrs_xor_native_a76(uint64x2_t *acc,
                                                             uint64x2_t onekey,
                                                             uint64x2_t temp) {
#if USE_A76_ASM_CASE18_CLMUL && defined(__aarch64__) && (defined(__clang__) || defined(__GNUC__))
    uint64x2_t a = *acc;
    uint64x2_t t;
#if USE_A76_CASE18_CLMUL_MEM_BARRIER
    asm volatile(
        "eor %[k].16b, %[k].16b, %[tmp].16b\n\t"
        "dup %[t].2d, %[k].d[0]\n\t"
        "pmull2 %[k].1q, %[k].2d, %[t].2d\n\t"
        "sqrdmulh %[t].8h, %[a].8h, %[k].8h\n\t"
        "eor %[a].16b, %[a].16b, %[t].16b\n\t"
        : [a] "+w"(a), [k] "+w"(onekey), [t] "=&w"(t)
        : [tmp] "w"(temp)
        : "memory");
#else
    asm volatile(
        "eor %[k].16b, %[k].16b, %[tmp].16b\n\t"
        "dup %[t].2d, %[k].d[0]\n\t"
        "pmull2 %[k].1q, %[k].2d, %[t].2d\n\t"
        "sqrdmulh %[t].8h, %[a].8h, %[k].8h\n\t"
        "eor %[a].16b, %[a].16b, %[t].16b\n\t"
        : [a] "+w"(a), [k] "+w"(onekey), [t] "=&w"(t)
        : [tmp] "w"(temp));
#endif
    *acc = a;
    return onekey;
#else
    const uint64x2_t add1 = veorq_u64(onekey, temp);
    onekey = clmul_native(add1, add1, 0x10);
    *acc = veorq_u64(vreinterpretq_u64_s16(
        vqrdmulhq_s16(vreinterpretq_s16_u64(*acc), vreinterpretq_s16_u64(onekey))), *acc);
    return onekey;
#endif
}

// Inner loop helper for case 0x18 (branch/control + compute path).
// Updates *acc and returns the final onekey for post-loop stores.
static inline uint64x2_t case18_inner_loop_native_a76(uint64x2_t *acc,
                                                       uint64x2_t *rc,
                                                       int64_t rounds,
                                                       uint64_t selector,
                                                       const uint64x2_t *pbuf,
                                                       const uint64x2_t *pbsf)
    __attribute__((always_inline));
static inline uint64x2_t case18_inner_loop_native_a76(uint64x2_t *acc,
                                                       uint64x2_t *rc,
                                                       int64_t rounds,
                                                       uint64_t selector,
                                                       const uint64x2_t *pbuf,
                                                       const uint64x2_t *pbsf) {
    uint64x2_t onekey = vdupq_n_u64(0);

#if USE_A76_CASE18_FIXEDCOUNT
#if USE_A76_CASE18_MASK_PTRS
    const int32_t divisor = (uint32_t)selector;
    uint64_t mask = (0x10000000ULL << rounds);
    const uint64x2_t * __restrict sel_div = (rounds & 1) ? pbuf : pbsf;
    const uint64x2_t * __restrict sel_cl = (rounds & 1) ? pbsf : pbuf;
#pragma clang loop unroll(full)
    for (uint64_t count = 8; count--; ) {
        if (rounds >= 0) {
            onekey = *rc++;

            if (selector & mask) {
                const uint64x2_t temp2 = *sel_div;
                onekey = veorq_u64(onekey, temp2);
                const int64_t dividend2 = vgetq_lane_s64(vreinterpretq_s64_u64(onekey), 0);
                const int32_t modulo_result = (int32_t)(dividend2 % divisor);
                *acc = xor_low32_lane_native_a76(*acc, (uint32_t)modulo_result);
            } else {
                onekey = case18_clmul_mulhrs_xor_native_a76(acc, onekey, *sel_cl);
            }
            rounds--;
            mask >>= 1;
            const uint64x2_t *tmp = sel_div;
            sel_div = sel_cl;
            sel_cl = tmp;
        }
    }
#else
#pragma clang loop unroll(full)
    for (uint64_t count = 8; count--; ) {
        if (rounds >= 0) {
            onekey = *rc++;
            const uint64x2_t * __restrict sel_div = (rounds & 1) ? pbuf : pbsf;
            const uint64x2_t * __restrict sel_cl = (rounds & 1) ? pbsf : pbuf;

            if (selector & (0x10000000L << rounds)) {
                const uint64x2_t temp2 = *sel_div;
                onekey = veorq_u64(onekey, temp2);
                const int32_t divisor = (uint32_t)selector;
                const int64_t dividend2 = vgetq_lane_s64(vreinterpretq_s64_u64(onekey), 0);
                const int32_t modulo_result = (int32_t)(dividend2 % divisor);
                *acc = xor_low32_lane_native_a76(*acc, (uint32_t)modulo_result);
            } else {
                onekey = case18_clmul_mulhrs_xor_native_a76(acc, onekey, *sel_cl);
            }
            rounds--;
        }
    }
#endif
#else
    for (; rounds >= 0; rounds--) {
        onekey = *rc++;
        const uint64x2_t * __restrict sel_div = (rounds & 1) ? pbuf : pbsf;
        const uint64x2_t * __restrict sel_cl = (rounds & 1) ? pbsf : pbuf;

        if (selector & (0x10000000L << rounds)) {
                const uint64x2_t temp2 = *sel_div;
                onekey = veorq_u64(onekey, temp2);
                const int32_t divisor = (uint32_t)selector;
                const int64_t dividend2 = vgetq_lane_s64(vreinterpretq_s64_u64(onekey), 0);
                const int32_t modulo_result = (int32_t)(dividend2 % divisor);
                *acc = xor_low32_lane_native_a76(*acc, (uint32_t)modulo_result);
        } else {
            onekey = case18_clmul_mulhrs_xor_native_a76(acc, onekey, *sel_cl);
        }
    }
#endif

    return onekey;
}

#ifdef __cplusplus
}
#endif

#endif // CLHASH_NATIVE_H_
