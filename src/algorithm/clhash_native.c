#include "clhash_native.h"
#include "haraka_native.h"  // For aes_encrypt_round_native()
#include "cpu_features.h"
#include <string.h>


// Load CLHash constants for native implementation
void load_clhash_constants_native(void) {
    // No special constants needed for native PMULL implementation
    // Hardware handles polynomial arithmetic directly
}

// Per-iteration context computed before the case dispatch: selector, the two
// random key slots (journaled for FixKey), and the pbuf/pbsf input pointers.
typedef struct {
    uint64_t selector;
    uint64x2_t *prand;
    uint64x2_t *prandex;
    const uint64x2_t *pbuf;
    const uint64x2_t *pbsf;
} verus_iter_ctx_t;

static inline verus_iter_ctx_t verus_clhash_prologue(uint64x2_t acc,
        uint64x2_t * __restrict randomsource,
        const uint64x2_t * __restrict pbuf_copy,
        uint64_t keyMask,
        uint16_t * __restrict fixrand_slot, uint16_t * __restrict fixrandex_slot,
        uint64x2_t * __restrict g_prand_slot, uint64x2_t * __restrict g_prandex_slot)
    __attribute__((always_inline));
static inline verus_iter_ctx_t verus_clhash_prologue(uint64x2_t acc,
        uint64x2_t * __restrict randomsource,
        const uint64x2_t * __restrict pbuf_copy,
        uint64_t keyMask,
        uint16_t * __restrict fixrand_slot, uint16_t * __restrict fixrandex_slot,
        uint64x2_t * __restrict g_prand_slot, uint64x2_t * __restrict g_prandex_slot)
{
        verus_iter_ctx_t ctx;

        // Extract selector from accumulator (same as portable)
        const uint64_t selector = vgetq_lane_u64(acc, 0);
        const int64_t selector_fudge = selector & 1 ? 1 : -1;

        // Calculate random locations in key (same as portable)
        const uint16_t fixrand_val = (uint16_t)((selector >> 5) & keyMask);
        const uint16_t fixrandex_val = (uint16_t)((selector >> 32) & keyMask);
        *fixrand_slot = fixrand_val;
        *fixrandex_slot = fixrandex_val;

        // Get pointers to random locations.
        // NOTE: prand and prandex CAN alias (fixrand_val == fixrandex_val when
        // selector bits 5..13 equal bits 32..40 — ~6% of hashes hit this on
        // some iteration), so they must NOT be __restrict-qualified.
        ctx.prand = randomsource + fixrand_val;
        ctx.prandex = randomsource + fixrandex_val;

        // CRITICAL FIX: Must store to g_prand/g_prandex for FixKey to work!
        // These arrays hold the original values before modification so FixKey can restore them
        // PERFORMANCE FIX: Use explicit vld1q loads like portable version for better scheduling
        *g_prand_slot = vld1q_u64((uint64_t*)ctx.prand);
        *g_prandex_slot = vld1q_u64((uint64_t*)ctx.prandex);

        // CRITICAL FIX: Use pbuf_copy like portable, NOT original buf!
        // Portable accesses pbuf_copy, not original buf
        // PERFORMANCE: Calculate indices once
        const uint64_t pbuf_idx = selector & 3;
        ctx.pbuf = pbuf_copy + pbuf_idx;
        ctx.pbsf = ctx.pbuf - selector_fudge;
        ctx.selector = selector;

        return ctx;
}

// One case body of the CLHash repeat loop. switch_val is a runtime value on
// the classic paths; the fused-dispatch path passes a compile-time constant so
// the switch folds to a straight-line body per fused case.
static inline uint64x2_t verus_clhash_case(uint64_t switch_val, uint64x2_t acc,
        uint64_t selector,
        uint64x2_t *prand, uint64x2_t *prandex,
        const uint64x2_t * __restrict pbuf, const uint64x2_t * __restrict pbsf)
    __attribute__((always_inline));
static inline uint64x2_t verus_clhash_case(uint64_t switch_val, uint64x2_t acc,
        uint64_t selector,
        uint64x2_t *prand, uint64x2_t *prandex,
        const uint64x2_t * __restrict pbuf, const uint64x2_t * __restrict pbsf)
{
        // Process switch cases exactly like portable version
        switch (switch_val) {
            case 0: {
                // MATCH PORTABLE CASE 0 EXACTLY!
                const uint64x2_t temp1 = vld1q_u64((uint64_t*)prandex);
                const uint64x2_t temp2 = vld1q_u64((uint64_t*)pbsf);
                const uint64x2_t add1 = veorq_u64(temp1, temp2);
                const uint64x2_t clprod1 = clmul_native(add1, add1, 0x10);
                acc = veorq_u64(clprod1, acc);
                
                // Step 2: tempa1 = mulhrs(acc, temp1)
                const int16x8_t tempa1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc), 
                                                       vreinterpretq_s16_u64(temp1));
                
                // Step 3: tempa2 = tempa1 ^ temp1  
                const uint64x2_t tempa2 = veorq_u64(vreinterpretq_u64_s16(tempa1), temp1);
                
                // Step 4: temp12 = *prand
                const uint64x2_t temp12 = vld1q_u64((uint64_t*)prand);
                
                // CRITICAL FIX: Match portable exactly!
                // Step 7: temp12 = *prand (already done above)
                // Step 8: vst1q_u64((uint64_t*)prand, tempa2 (CRITICAL - was wrong before!)
                vst1q_u64((uint64_t*)prand, tempa2);
                
                // Continue with second part of case 0
                const uint64x2_t temp22 = vld1q_u64((uint64_t*)pbuf);
                const uint64x2_t add12 = veorq_u64(temp12, temp22);
                const uint64x2_t clprod12 = clmul_native(add12, add12, 0x10);
                acc = veorq_u64(clprod12, acc);
                
                // Step 9: tempb1 = mulhrs(acc, temp12)
                const int16x8_t tempb1_new = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                           vreinterpretq_s16_u64(temp12));
                
                // Step 10: vst1q_u64((uint64_t*)prandex, tempb1 ^ temp12 (CRITICAL - match portable exactly!)
                vst1q_u64((uint64_t*)prandex, veorq_u64(vreinterpretq_u64_s16(tempb1_new), temp12));
                break;
            }

            case 4: {
                // Case 4: Load temp1 from prand, temp2 from pbuf (exactly like portable)
                const uint64x2_t temp1 = vld1q_u64((uint64_t*)prand);
                const uint64x2_t temp2 = vld1q_u64((uint64_t*)pbuf);
                const uint64x2_t add1 = veorq_u64(temp1, temp2);
                const uint64x2_t clprod1 = clmul_native(add1, add1, 0x10);
                acc = veorq_u64(clprod1, acc);
                const uint64x2_t clprod2 = clmul_native(temp2, temp2, 0x10);
                acc = veorq_u64(clprod2, acc);

                const int16x8_t tempa1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                       vreinterpretq_s16_u64(temp1));
                const uint64x2_t tempa2 = veorq_u64(vreinterpretq_u64_s16(tempa1), temp1);

                const uint64x2_t temp12 = vld1q_u64((uint64_t*)prandex);
                vst1q_u64((uint64_t*)prandex, tempa2);

                // CRITICAL: temp22 loads from pbsf, not pbuf (matches portable Case 4)!
                const uint64x2_t temp22 = vld1q_u64((uint64_t*)pbsf);
                const uint64x2_t add12 = veorq_u64(temp12, temp22);
                acc = veorq_u64(add12, acc);

                const int16x8_t tempb1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                       vreinterpretq_s16_u64(temp12));
                const uint64x2_t tempb2 = veorq_u64(vreinterpretq_u64_s16(tempb1), temp12);
                vst1q_u64((uint64_t*)prand, tempb2);
                break;
            }

            case 8: {
                const uint64x2_t temp1 = vld1q_u64((uint64_t*)prandex);
                const uint64x2_t temp2 = vld1q_u64((uint64_t*)pbuf);
                const uint64x2_t add1 = veorq_u64(temp1, temp2);
                acc = veorq_u64(add1, acc);
                
                const int16x8_t tempa1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                       vreinterpretq_s16_u64(temp1));
                const uint64x2_t tempa2 = veorq_u64(vreinterpretq_u64_s16(tempa1), temp1);
                
                const uint64x2_t temp12 = vld1q_u64((uint64_t*)prand);
                vst1q_u64((uint64_t*)prand, tempa2);
                
                const uint64x2_t temp22 = vld1q_u64((uint64_t*)pbsf);
                const uint64x2_t add12 = veorq_u64(temp12, temp22);
                const uint64x2_t clprod12 = clmul_native(add12, add12, 0x10);
                acc = veorq_u64(clprod12, acc);
                const uint64x2_t clprod22 = clmul_native(temp22, temp22, 0x10);
                acc = veorq_u64(clprod22, acc);
                
                const int16x8_t tempb1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                       vreinterpretq_s16_u64(temp12));
                const uint64x2_t tempb2 = veorq_u64(vreinterpretq_u64_s16(tempb1), temp12);
                vst1q_u64((uint64_t*)prandex, tempb2);
                break;
            }
            
            case 0xc: {
                const uint64x2_t temp1 = vld1q_u64((uint64_t*)prand);
                const uint64x2_t temp2 = vld1q_u64((uint64_t*)pbsf);
                const uint64x2_t add1 = veorq_u64(temp1, temp2);

                // Division operation matching portable version exactly
                // CRITICAL FIX: portable uses int32_t, not uint32_t!
                const int32_t divisor = (uint32_t)selector;

                acc = veorq_u64(add1, acc);

                const int64_t dividend = vgetq_lane_s64(vreinterpretq_s64_u64(acc), 0);
                // CRITICAL: Result can be negative! Must use SIGNED int32_t, not unsigned uint32_t!
                const int32_t modulo_result = (int32_t)(dividend % divisor);
                acc = xor_low32_lane_native_a76(acc, (uint32_t)modulo_result);
                
                const int16x8_t tempa1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                       vreinterpretq_s16_u64(temp1));
                const uint64x2_t tempa2 = veorq_u64(vreinterpretq_u64_s16(tempa1), temp1);

                // Branch based on dividend parity (same as portable)
                if (dividend & 1) {
                    const uint64x2_t temp12 = vld1q_u64((uint64_t*)prandex);
                    vst1q_u64((uint64_t*)prandex, tempa2);

                    const uint64x2_t temp22 = vld1q_u64((uint64_t*)pbuf);
                    const uint64x2_t add12 = veorq_u64(temp12, temp22);
                    const uint64x2_t clprod12 = clmul_native(add12, add12, 0x10);
                    acc = veorq_u64(clprod12, acc);
                    const uint64x2_t clprod22 = clmul_native(temp22, temp22, 0x10);
                    acc = veorq_u64(clprod22, acc);

                    const int16x8_t tempb1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc),
                                                           vreinterpretq_s16_u64(temp12));
                    const uint64x2_t tempb2 = veorq_u64(vreinterpretq_u64_s16(tempb1), temp12);
                    vst1q_u64((uint64_t*)prand, tempb2);
                } else {
                    vst1q_u64((uint64_t*)prand, vld1q_u64((uint64_t*)prandex));
                    vst1q_u64((uint64_t*)prandex, tempa2);
                    const uint64x2_t tempb4 = vld1q_u64((uint64_t*)pbuf);
                    acc = veorq_u64(tempb4, acc);
                }
                break;
            }

            case 0x10: {
                const uint8x16_t *rc = (const uint8x16_t *)prand;
                uint64x2_t temp1 = vld1q_u64((const uint64_t*)pbsf);
                uint64x2_t temp2 = vld1q_u64((const uint64_t*)pbuf);

                aes_rounds_4_native(&temp1, &temp2, rc, 0);
                mix2_emu_simple_native(&temp1, &temp2);
                aes_rounds_4_native(&temp1, &temp2, rc, 1);
                mix2_emu_simple_native(&temp1, &temp2);
                aes_rounds_4_native(&temp1, &temp2, rc, 2);
                mix2_emu_simple_native(&temp1, &temp2);

                acc = veorq_u64(acc, temp1);
                acc = veorq_u64(acc, temp2);

                const uint64x2_t tempa1 = vld1q_u64((const uint64_t *)prand);
                const int16x8_t tempa2 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc), vreinterpretq_s16_u64(tempa1));
                vst1q_u64((uint64_t *)prand, vld1q_u64((const uint64_t *)prandex));
                vst1q_u64((uint64_t *)prandex, veorq_u64(tempa1, vreinterpretq_u64_s16(tempa2)));
                break;
            }

            case 0x14: {
                // CRITICAL BUG FIX: Case 0x14 uses complex 8-iteration loop, not simple operations!
                // Must match portable exactly: unrolled 8-iteration loop with conditional logic
                int64_t rounds = selector >> 61;  // loop randomly between 1 and 8 times
                uint64x2_t *rc = prand;
                uint64_t aesround = 0;
                uint64x2_t onekey;

                // 8-iteration unrolled loop matching portable exactly
#pragma clang loop unroll(full)
                for (uint64_t count = 8; count--; ) {
                    if (rounds >= 0) {
                        onekey = *rc++;
                        const uint64x2_t * __restrict sel_cl = (rounds & 1) ? pbuf : pbsf;
                        const uint64x2_t * __restrict sel_aes = (rounds & 1) ? pbsf : pbuf;

                        if (selector & (0x10000000L << rounds)) {
                            // CLHash path
                            const uint64x2_t temp2 = *sel_cl;
                            const uint64x2_t add1 = veorq_u64(onekey, temp2);
                            const uint64x2_t clprod1 = clmul_native(add1, add1, 0x10);
                            acc = veorq_u64(clprod1, acc);
                        } else {
                            // AES path
                            uint64x2_t temp2 = *sel_aes;
                            const uint64_t round_block = aesround++;

                            const uint8x16_t *rk = ((const uint8x16_t*)rc) + (round_block << 2);
                            const uint64x2_t mixxor = aes_rounds_4_mix2_xor_native_a76(onekey, temp2, rk);
                            acc = veorq_u64(acc, mixxor);
                        }
                        rounds--;
                    }
                }
                
                // Final operations matching portable exactly!
                // Portable: const __m128i tempa1 = _mm_load_si128_emu(prand);
                // Portable: const __m128i tempa2 = _mm_mulhrs_epi16_emu(acc, tempa1);
                // Portable: vst1q_u64((uint64_t*)prand, vld1q_u64((uint64_t*)prandex);
                // Portable: vst1q_u64((uint64_t*)prandex, _mm_xor_si128_emu(tempa1, tempa2);
                const uint64x2_t tempa1 = vld1q_u64((uint64_t*)prand);
                const int16x8_t tempa2 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc), 
                                                       vreinterpretq_s16_u64(tempa1));
                vst1q_u64((uint64_t*)prand, vld1q_u64((uint64_t*)prandex));
                vst1q_u64((uint64_t*)prandex, veorq_u64(tempa1, vreinterpretq_u64_s16(tempa2)));
                break;
            }
            
            case 0x18: {
                // CRITICAL BUG FIX: Case 0x18 uses complex 8-iteration loop with division operations!
                // Must match portable exactly: unrolled 8-iteration loop with conditional division/clmul paths
                const int64_t rounds = (int64_t)(selector >> 61);
                uint64x2_t *rc = prand;
                const uint64x2_t onekey = case18_inner_loop_native_a76(&acc, rc, rounds, selector, pbuf, pbsf);

                // Final operations matching portable EXACTLY
                // Portable lines 1000-1004:
                // const __m128i tempa3 = _mm_load_si128_emu(prandex);
                // const __m128i tempa4 = _mm_xor_si128_emu(tempa3, acc);
                // _mm_store_si128_emu(prandex, onekey);
                // _mm_store_si128_emu(prand, tempa4);
                const uint64x2_t tempa3 = vld1q_u64((uint64_t*)prandex);
                const uint64x2_t tempa4 = veorq_u64(tempa3, acc);
                vst1q_u64((uint64_t*)prandex, onekey);
                vst1q_u64((uint64_t*)prand, tempa4);
                break;
            }

            default: {
                // Default case - handles both 0x1c and other unhandled cases
                // Matches portable default case (lines 1007-1028)
                const uint64x2_t temp1 = vld1q_u64((uint64_t*)pbuf);
                const uint64x2_t temp2 = vld1q_u64((uint64_t*)prandex);
                const uint64x2_t add1 = veorq_u64(temp1, temp2);
                const uint64x2_t clprod1 = clmul_native(add1, add1, 0x10);
                acc = veorq_u64(clprod1, acc);
                
                const int16x8_t tempa1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc), vreinterpretq_s16_u64(temp2));
                const uint64x2_t tempa2 = veorq_u64(vreinterpretq_u64_s16(tempa1), temp2);
                
                const uint64x2_t tempa3 = vld1q_u64((uint64_t*)prand);
                vst1q_u64((uint64_t*)prand, tempa2);
                
                acc = veorq_u64(tempa3, acc);
                const uint64x2_t temp4 = vld1q_u64((uint64_t*)pbsf);
                acc = veorq_u64(temp4, acc);
                const int16x8_t tempb1 = vqrdmulhq_s16(vreinterpretq_s16_u64(acc), vreinterpretq_s16_u64(tempa3));
                const uint64x2_t tempb2 = veorq_u64(vreinterpretq_u64_s16(tempb1), tempa3);
                vst1q_u64((uint64_t*)prandex, tempb2);
                break;
            }
        }

        return acc;
}

// One iteration of the CLHash repeat loop, factored out so the x2 path can
// interleave two independent accumulator chains through the same case bodies.
// always_inline: this must collapse back into the caller's loop exactly as the
// previous hand-laid loop body did.
static inline uint64x2_t verus_clhash_iter(uint64x2_t acc,
        uint64x2_t * __restrict randomsource,
        const uint64x2_t * __restrict pbuf_copy,
        uint64_t keyMask,
        uint16_t * __restrict fixrand_slot, uint16_t * __restrict fixrandex_slot,
        uint64x2_t * __restrict g_prand_slot, uint64x2_t * __restrict g_prandex_slot)
    __attribute__((always_inline));
static inline uint64x2_t verus_clhash_iter(uint64x2_t acc,
        uint64x2_t * __restrict randomsource,
        const uint64x2_t * __restrict pbuf_copy,
        uint64_t keyMask,
        uint16_t * __restrict fixrand_slot, uint16_t * __restrict fixrandex_slot,
        uint64x2_t * __restrict g_prand_slot, uint64x2_t * __restrict g_prandex_slot)
{
        const verus_iter_ctx_t ctx = verus_clhash_prologue(acc, randomsource, pbuf_copy,
                keyMask, fixrand_slot, fixrandex_slot, g_prand_slot, g_prandex_slot);
        return verus_clhash_case(ctx.selector & 0x1c, acc, ctx.selector,
                ctx.prand, ctx.prandex, ctx.pbuf, ctx.pbsf);
}

// Core native CLHash implementation matching __verusclmulwithoutreduction64alignedrepeat_port2_2
uint64x2_t __verusclmulwithoutreduction64alignedrepeat_port2_2_native(uint64x2_t *randomsource, const uint64x2_t buf[4], uint64_t keyMask,
                                                                       uint16_t *__restrict fixrand, uint16_t *__restrict fixrandex,
                                                                       uint64x2_t *g_prand, uint64x2_t *g_prandex) {

    // Create pbuf_copy matching portable version exactly
    const uint64x2_t pbuf_copy[4] = {
        veorq_u64(buf[0], buf[2]),
        veorq_u64(buf[1], buf[3]),
        buf[2],
        buf[3]
    };

    // Initialize accumulator from randomsource + (keyMask + 2)
    uint64x2_t acc = randomsource[keyMask + 2];

    // Main loop - 32 iterations matching portable version exactly
    for (uint64_t i = 0; i < 32; i++) {
        acc = verus_clhash_iter(acc, randomsource, pbuf_copy, keyMask,
                                fixrand + i, fixrandex + i, g_prand + i, g_prandex + i);
    }


    // Return unreduced accumulator (this function should return uint64x2_t)
    // NOTE: 0x10000 constant is applied in the wrapper function, not here
    return acc;
}

// Two-nonce interleaved CLHash. Runs two fully independent accumulator chains
// (separate key buffers, separate bufs) through the same 32-iteration loop.
// Each chain's iteration is a serial selector->load->pmull->eor latency chain;
// interleaving two of them lets an out-of-order core overlap the stalls of one
// chain with the compute of the other. Each chain's result is bit-identical to
// the single-chain path. Reduction is folded in here so callers get the final
// 64-bit intermediates directly.
__attribute__((noinline))
void verusclhash_port2_2_x2_native(void * __restrict random1, void * __restrict random2,
                                   const unsigned char buf1[64], const unsigned char buf2[64],
                                   uint64_t keyMask,
                                   uint16_t * __restrict fixrand1, uint16_t * __restrict fixrandex1,
                                   uint64x2_t * __restrict g_prand1, uint64x2_t * __restrict g_prandex1,
                                   uint16_t * __restrict fixrand2, uint16_t * __restrict fixrandex2,
                                   uint64x2_t * __restrict g_prand2, uint64x2_t * __restrict g_prandex2,
                                   uint64_t * __restrict result1, uint64_t * __restrict result2) {

    uint64x2_t * __restrict rs1 = (uint64x2_t *)random1;
    uint64x2_t * __restrict rs2 = (uint64x2_t *)random2;
    const uint64x2_t *b1 = (const uint64x2_t *)buf1;
    const uint64x2_t *b2 = (const uint64x2_t *)buf2;

    const uint64x2_t pbuf_copy1[4] = {
        veorq_u64(b1[0], b1[2]),
        veorq_u64(b1[1], b1[3]),
        b1[2],
        b1[3]
    };
    const uint64x2_t pbuf_copy2[4] = {
        veorq_u64(b2[0], b2[2]),
        veorq_u64(b2[1], b2[3]),
        b2[2],
        b2[3]
    };

    uint64x2_t acc1 = rs1[keyMask + 2];
    uint64x2_t acc2 = rs2[keyMask + 2];

    for (uint64_t i = 0; i < 32; i++) {
        acc1 = verus_clhash_iter(acc1, rs1, pbuf_copy1, keyMask,
                                 fixrand1 + i, fixrandex1 + i, g_prand1 + i, g_prandex1 + i);
        acc2 = verus_clhash_iter(acc2, rs2, pbuf_copy2, keyMask,
                                 fixrand2 + i, fixrandex2 + i, g_prand2 + i, g_prandex2 + i);
    }


    const uint64x2_t fold = vcombine_u64(vcreate_u64(0x10000), vcreate_u64(0));
    *result1 = precompReduction64_native(veorq_u64(acc1, fold));
    *result2 = precompReduction64_native(veorq_u64(acc2, fold));
}

// Fused-dispatch two-nonce CLHash. Identical work to the x2 path, but both
// chains' case dispatches are fused into ONE 64-way switch on the
// concatenated selector bits. Rationale (perf-counter measured): each chain's
// 3 dispatch bits are cryptographically random, so both per-chain indirect
// branches mispredict nearly every iteration and their flush bubbles
// serialize (~2x11 cycles/iter on A76 — about a third of all Verus cycles).
// One fused dispatch carries the same 6 bits of entropy but pays ONE bubble.
// Cost: 64 stamped case-pair bodies (~37KB of code, exactly 1 indirect br) —
// wins on ARM A75+ front-ends (+6-9%), loses badly on Samsung Mongoose M4
// (-24%), so it is auto-selected per core (verus_use_fused_for_current_cpu
// in verus.cpp); VERUS_FUSE=0/1 forces.
__attribute__((noinline))
void verusclhash_port2_2_x2f_native(void * __restrict random1, void * __restrict random2,
                                    const unsigned char buf1[64], const unsigned char buf2[64],
                                    uint64_t keyMask,
                                    uint16_t * __restrict fixrand1, uint16_t * __restrict fixrandex1,
                                    uint64x2_t * __restrict g_prand1, uint64x2_t * __restrict g_prandex1,
                                    uint16_t * __restrict fixrand2, uint16_t * __restrict fixrandex2,
                                    uint64x2_t * __restrict g_prand2, uint64x2_t * __restrict g_prandex2,
                                    uint64_t * __restrict result1, uint64_t * __restrict result2) {

    uint64x2_t * __restrict rs1 = (uint64x2_t *)random1;
    uint64x2_t * __restrict rs2 = (uint64x2_t *)random2;
    const uint64x2_t *b1 = (const uint64x2_t *)buf1;
    const uint64x2_t *b2 = (const uint64x2_t *)buf2;

    const uint64x2_t pbuf_copy1[4] = {
        veorq_u64(b1[0], b1[2]),
        veorq_u64(b1[1], b1[3]),
        b1[2],
        b1[3]
    };
    const uint64x2_t pbuf_copy2[4] = {
        veorq_u64(b2[0], b2[2]),
        veorq_u64(b2[1], b2[3]),
        b2[2],
        b2[3]
    };

    uint64x2_t acc1 = rs1[keyMask + 2];
    uint64x2_t acc2 = rs2[keyMask + 2];

    for (uint64_t i = 0; i < 32; i++) {
        const verus_iter_ctx_t c1 = verus_clhash_prologue(acc1, rs1, pbuf_copy1, keyMask,
                fixrand1 + i, fixrandex1 + i, g_prand1 + i, g_prandex1 + i);
        const verus_iter_ctx_t c2 = verus_clhash_prologue(acc2, rs2, pbuf_copy2, keyMask,
                fixrand2 + i, fixrandex2 + i, g_prand2 + i, g_prandex2 + i);

        // 6-bit fused dispatch index: chain1's case in bits [5:3], chain2's in [2:0]
        const uint32_t fused = (uint32_t)(((c1.selector & 0x1c) << 1) |
                                          ((c2.selector & 0x1c) >> 2));

#define VERUS_FUSE_CASE(I, J)                                                  \
        case (((I) << 3) | (J)):                                              \
            acc1 = verus_clhash_case((uint64_t)(I) << 2, acc1, c1.selector,   \
                    c1.prand, c1.prandex, c1.pbuf, c1.pbsf);                  \
            acc2 = verus_clhash_case((uint64_t)(J) << 2, acc2, c2.selector,   \
                    c2.prand, c2.prandex, c2.pbuf, c2.pbsf);                  \
            break;
#define VERUS_FUSE_ROW(I)                                                      \
        VERUS_FUSE_CASE(I, 0) VERUS_FUSE_CASE(I, 1) VERUS_FUSE_CASE(I, 2)     \
        VERUS_FUSE_CASE(I, 3) VERUS_FUSE_CASE(I, 4) VERUS_FUSE_CASE(I, 5)     \
        VERUS_FUSE_CASE(I, 6) VERUS_FUSE_CASE(I, 7)

        switch (fused) {
        VERUS_FUSE_ROW(0) VERUS_FUSE_ROW(1) VERUS_FUSE_ROW(2) VERUS_FUSE_ROW(3)
        VERUS_FUSE_ROW(4) VERUS_FUSE_ROW(5) VERUS_FUSE_ROW(6) VERUS_FUSE_ROW(7)
        }
#undef VERUS_FUSE_ROW
#undef VERUS_FUSE_CASE
    }

    const uint64x2_t fold = vcombine_u64(vcreate_u64(0x10000), vcreate_u64(0));
    *result1 = precompReduction64_native(veorq_u64(acc1, fold));
    *result2 = precompReduction64_native(veorq_u64(acc2, fold));
}

__attribute__((noinline))
uint64_t verusclhash_port2_2_native(void *random, const unsigned char buf[64], uint64_t keyMask,
                                    uint16_t *__restrict fixrand, uint16_t *__restrict fixrandex,
                                    uint64x2_t *g_prand, uint64x2_t *g_prandex) {

    uint64x2_t *rs64 = (uint64x2_t *)random;
    const uint64x2_t *string = (const uint64x2_t *)buf;

    uint64x2_t acc = __verusclmulwithoutreduction64alignedrepeat_port2_2_native(rs64, string, keyMask, fixrand, fixrandex, g_prand, g_prandex);

    acc = veorq_u64(acc, vcombine_u64(vcreate_u64(0x10000), vcreate_u64(0)));

    return precompReduction64_native(acc);
}
