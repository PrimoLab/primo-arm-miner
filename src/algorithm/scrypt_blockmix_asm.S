/*
 * scrypt_blockmix_asm.S - Fused BlockMix for scrypt (r=1)
 *
 * Performs: Salsa20/8(B[0..15]) + B[16..31]^=B[0..15] + Salsa20/8(B[16..31])
 * in a single function call, eliminating 16 redundant loads at the
 * Salsa #1 → XOR → Salsa #2 boundary.
 *
 * Current (3 separate steps):
 *   Salsa #1 stores B[0..15] to memory
 *   XOR loop loads B[0..15] back, loads B[16..31], XORs, stores B[16..31]
 *   Salsa #2 loads B[16..31] back
 *   = 48 LDP total for non-core operations
 *
 * Fused (this file):
 *   Salsa #1 result stays in registers
 *   Fused epilogue: add-back + store B[0..15] + load B[16..31] + XOR in one pass
 *   Salsa #2 input already in w1-w16, skip prologue entirely
 *   = 32 LDP total for non-core operations (16 fewer loads)
 *
 * Register map:
 *   x0       = B pointer (uint32_t *B, 32 words = 128 bytes)
 *   w1-w16   = Salsa state (maps to B[0]-B[15] or B[16]-B[31])
 *   w17, w18 = temporaries (for Salsa QR interleaving and transitions)
 *
 * ARM64 ABI: w0-w18 are caller-saved, x0 is parameter/return.
 * Since w1-w16 map to x1-x16 (bottom 32 bits), and we never touch x0/w0,
 * the B pointer in x0 is preserved throughout.
 */

    .text
    .align 6            /* 64-byte = cache line alignment */

/*============================================================================
 * Salsa20/8 double-round macro (column round + row round)
 * 64 instructions: 32 ADD + 32 EOR with fused rotate (ROR immediate)
 * Full 4-way QR interleaving for maximum A76 dual-issue throughput.
 *============================================================================*/
.macro salsa_double_round
    /* Column round: QR(0,4,8,12) QR(5,9,13,1) QR(10,14,2,6) QR(15,3,7,11) */
    /* Step 1: b ^= rotl(a+d, 7) — rotl(x,7) = ror(x,25) */
    add     w17, w1, w13
    add     w18, w6, w2
    eor     w5, w5, w17, ror #25
    eor     w10, w10, w18, ror #25
    add     w17, w11, w7
    add     w18, w16, w12
    eor     w15, w15, w17, ror #25
    eor     w4, w4, w18, ror #25
    /* Step 2: c ^= rotl(b+a, 9) — rotl(x,9) = ror(x,23) */
    add     w17, w5, w1
    add     w18, w10, w6
    eor     w9, w9, w17, ror #23
    eor     w14, w14, w18, ror #23
    add     w17, w15, w11
    add     w18, w4, w16
    eor     w3, w3, w17, ror #23
    eor     w8, w8, w18, ror #23
    /* Step 3: d ^= rotl(c+b, 13) — rotl(x,13) = ror(x,19) */
    add     w17, w9, w5
    add     w18, w14, w10
    eor     w13, w13, w17, ror #19
    eor     w2, w2, w18, ror #19
    add     w17, w3, w15
    add     w18, w8, w4
    eor     w7, w7, w17, ror #19
    eor     w12, w12, w18, ror #19
    /* Step 4: a ^= rotl(d+c, 18) — rotl(x,18) = ror(x,14) */
    add     w17, w13, w9
    add     w18, w2, w14
    eor     w1, w1, w17, ror #14
    eor     w6, w6, w18, ror #14
    add     w17, w7, w3
    add     w18, w12, w8
    eor     w11, w11, w17, ror #14
    eor     w16, w16, w18, ror #14

    /* Row round: QR(0,1,2,3) QR(5,6,7,4) QR(10,11,8,9) QR(15,12,13,14) */
    /* Step 1: b ^= rotl(a+d, 7) */
    add     w17, w1, w4
    add     w18, w6, w5
    eor     w2, w2, w17, ror #25
    eor     w7, w7, w18, ror #25
    add     w17, w11, w10
    add     w18, w16, w15
    eor     w12, w12, w17, ror #25
    eor     w13, w13, w18, ror #25
    /* Step 2: c ^= rotl(b+a, 9) */
    add     w17, w2, w1
    add     w18, w7, w6
    eor     w3, w3, w17, ror #23
    eor     w8, w8, w18, ror #23
    add     w17, w12, w11
    add     w18, w13, w16
    eor     w9, w9, w17, ror #23
    eor     w14, w14, w18, ror #23
    /* Step 3: d ^= rotl(c+b, 13) */
    add     w17, w3, w2
    add     w18, w8, w7
    eor     w4, w4, w17, ror #19
    eor     w5, w5, w18, ror #19
    add     w17, w9, w12
    add     w18, w14, w13
    eor     w10, w10, w17, ror #19
    eor     w15, w15, w18, ror #19
    /* Step 4: a ^= rotl(d+c, 18) */
    add     w17, w4, w3
    add     w18, w5, w8
    eor     w1, w1, w17, ror #14
    eor     w6, w6, w18, ror #14
    add     w17, w10, w9
    add     w18, w15, w14
    eor     w11, w11, w17, ror #14
    eor     w16, w16, w18, ror #14
.endm

/*============================================================================
 * scrypt_blockmix_asm - Fused Salsa20/8 BlockMix for r=1
 *
 * void scrypt_blockmix_asm(uint32_t *B)
 *
 * Performs the complete BlockMix operation for scrypt r=1:
 *   1. Salsa20/8(B[0..15])   — in-place
 *   2. B[16..31] ^= B[0..15]
 *   3. Salsa20/8(B[16..31])  — in-place
 *
 * Steps 1-3 are fused: Salsa #1 result stays in registers for the XOR,
 * and XOR result stays in registers for Salsa #2 (no redundant loads).
 *============================================================================*/
    .global scrypt_blockmix_asm
    .type   scrypt_blockmix_asm, %function
scrypt_blockmix_asm:
    .cfi_startproc

    /* ====== Salsa #1 prologue: load B[0..15] into w1-w16 ====== */
    ldp     w1, w2, [x0]
    ldp     w3, w4, [x0, #8]
    ldp     w5, w6, [x0, #16]
    ldp     w7, w8, [x0, #24]
    ldp     w9, w10, [x0, #32]
    ldp     w11, w12, [x0, #40]
    ldp     w13, w14, [x0, #48]
    ldp     w15, w16, [x0, #56]

    /* ====== Salsa #1 core: 4 double-rounds (8 rounds total) ====== */
    salsa_double_round
    salsa_double_round
    salsa_double_round
    salsa_double_round

    /* ====== Fused: Salsa #1 epilogue + XOR + Salsa #2 prologue ======
     *
     * For each word pair [k, k+1]:
     *   1. Reload original B[k], B[k+1] from memory (unchanged during Salsa)
     *   2. Add to Salsa state → final B[k], B[k+1]
     *   3. Store final B[k], B[k+1] to memory
     *   4. Load B[k+16], B[k+17] from memory
     *   5. XOR: B[k+16] ^= B[k] → new Salsa #2 input in w registers
     *   6. Store XOR'd B[k+16], B[k+17] (for Salsa #2 epilogue reload)
     *
     * After all pairs: w1-w16 = Salsa #2 input. Salsa #2 skips prologue!
     */

    /* Pair 0-1 */
    ldp     w17, w18, [x0]
    add     w1, w1, w17
    add     w2, w2, w18
    stp     w1, w2, [x0]
    ldp     w17, w18, [x0, #64]
    eor     w1, w17, w1
    eor     w2, w18, w2
    stp     w1, w2, [x0, #64]

    /* Pair 2-3 */
    ldp     w17, w18, [x0, #8]
    add     w3, w3, w17
    add     w4, w4, w18
    stp     w3, w4, [x0, #8]
    ldp     w17, w18, [x0, #72]
    eor     w3, w17, w3
    eor     w4, w18, w4
    stp     w3, w4, [x0, #72]

    /* Pair 4-5 */
    ldp     w17, w18, [x0, #16]
    add     w5, w5, w17
    add     w6, w6, w18
    stp     w5, w6, [x0, #16]
    ldp     w17, w18, [x0, #80]
    eor     w5, w17, w5
    eor     w6, w18, w6
    stp     w5, w6, [x0, #80]

    /* Pair 6-7 */
    ldp     w17, w18, [x0, #24]
    add     w7, w7, w17
    add     w8, w8, w18
    stp     w7, w8, [x0, #24]
    ldp     w17, w18, [x0, #88]
    eor     w7, w17, w7
    eor     w8, w18, w8
    stp     w7, w8, [x0, #88]

    /* Pair 8-9 */
    ldp     w17, w18, [x0, #32]
    add     w9, w9, w17
    add     w10, w10, w18
    stp     w9, w10, [x0, #32]
    ldp     w17, w18, [x0, #96]
    eor     w9, w17, w9
    eor     w10, w18, w10
    stp     w9, w10, [x0, #96]

    /* Pair 10-11 */
    ldp     w17, w18, [x0, #40]
    add     w11, w11, w17
    add     w12, w12, w18
    stp     w11, w12, [x0, #40]
    ldp     w17, w18, [x0, #104]
    eor     w11, w17, w11
    eor     w12, w18, w12
    stp     w11, w12, [x0, #104]

    /* Pair 12-13 */
    ldp     w17, w18, [x0, #48]
    add     w13, w13, w17
    add     w14, w14, w18
    stp     w13, w14, [x0, #48]
    ldp     w17, w18, [x0, #112]
    eor     w13, w17, w13
    eor     w14, w18, w14
    stp     w13, w14, [x0, #112]

    /* Pair 14-15 */
    ldp     w17, w18, [x0, #56]
    add     w15, w15, w17
    add     w16, w16, w18
    stp     w15, w16, [x0, #56]
    ldp     w17, w18, [x0, #120]
    eor     w15, w17, w15
    eor     w16, w18, w16
    stp     w15, w16, [x0, #120]

    /* ====== Salsa #2 core: w1-w16 already loaded! ====== */
    salsa_double_round
    salsa_double_round
    salsa_double_round
    salsa_double_round

    /* ====== Salsa #2 epilogue: reload XOR'd B[16..31], add, store ====== */
    ldp     w17, w18, [x0, #64]
    add     w1, w1, w17
    add     w2, w2, w18
    stp     w1, w2, [x0, #64]

    ldp     w17, w18, [x0, #72]
    add     w3, w3, w17
    add     w4, w4, w18
    stp     w3, w4, [x0, #72]

    ldp     w17, w18, [x0, #80]
    add     w5, w5, w17
    add     w6, w6, w18
    stp     w5, w6, [x0, #80]

    ldp     w17, w18, [x0, #88]
    add     w7, w7, w17
    add     w8, w8, w18
    stp     w7, w8, [x0, #88]

    ldp     w17, w18, [x0, #96]
    add     w9, w9, w17
    add     w10, w10, w18
    stp     w9, w10, [x0, #96]

    ldp     w17, w18, [x0, #104]
    add     w11, w11, w17
    add     w12, w12, w18
    stp     w11, w12, [x0, #104]

    ldp     w17, w18, [x0, #112]
    add     w13, w13, w17
    add     w14, w14, w18
    stp     w13, w14, [x0, #112]

    ldp     w17, w18, [x0, #120]
    add     w15, w15, w17
    add     w16, w16, w18
    stp     w15, w16, [x0, #120]

    ret
    .cfi_endproc
    .size   scrypt_blockmix_asm, .-scrypt_blockmix_asm

/* Mark stack as non-executable */
    .section .note.GNU-stack,"",%progbits
