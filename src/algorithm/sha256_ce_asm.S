/*
 * sha256_ce_asm.S - Hand-tuned dual-nonce SHA256d for ARMv8 crypto extensions
 *
 * Performs complete SHA256d (double SHA256) for two nonces simultaneously,
 * with optimal instruction interleaving to hide pipeline latency.
 *
 * On Cortex-A76: sha256h has 4-cycle latency, V0-only execution.
 * On Cortex-A55: sha256h has 4-cycle latency, in-order pipeline.
 * Interleaving two independent hashes fills the latency gaps.
 *
 * Zero memcpy between passes: pass 1 output stays in registers and
 * feeds directly into pass 2 as message words.
 *
 * void sha256d_dual_asm(
 *     const uint32_t midstate[8],     // x0
 *     const uint32_t W1_template[16], // x1
 *     const uint32_t W2_pad[8],       // x2: padding words for pass 2 (words 8-15)
 *     uint32_t nonceA,                // w3
 *     uint32_t nonceB,                // w4
 *     uint32_t stateA_out[8],         // x5
 *     uint32_t stateB_out[8]          // x6
 * );
 */

    .arch armv8.2-a+crypto

    .text
    .balign 64
    .global sha256d_dual_asm
    .type sha256d_dual_asm, %function

sha256d_dual_asm:
    /*
     * Register allocation:
     *
     * Permanent (loaded once, kept across both passes):
     *   v24, v25 = midstate[0..3], midstate[4..7]
     *   v26, v27 = H256_INIT[0..3], H256_INIT[4..7]
     *   v28, v29 = W2_pad[0..3], W2_pad[4..7]
     *   x9, x10  = output pointers (stateA_out/stateB_out)
     *
     * Working (reused for each pass):
     *   v0, v1   = STATE0_A, STATE1_A
     *   v2-v5    = MSG0_A .. MSG3_A
     *   v6, v7   = STATE0_B, STATE1_B
     *   v8-v11   = MSG0_B .. MSG3_B
     *   v12      = TMP_A (MSG+K result)
     *   v13      = DG_SAVE_A (state save for sha256h2)
     *   v14      = TMP_B
     *   v15      = DG_SAVE_B
     *   v16, v17 = K256 constants (current round pair)
     *   v18, v19 = K256 constants (next round pair / spare)
     *   v20-v23  = spare temporaries
     */

    /* Save callee-saved NEON regs v8-v15 */
    stp     q8, q9, [sp, #-128]!
    stp     q10, q11, [sp, #32]
    stp     q12, q13, [sp, #64]
    stp     q14, q15, [sp, #96]

    /* Preserve output pointers in caller-clobbered GPRs (no stack spill). */
    mov     x9, x5
    mov     x10, x6

    /* Load permanent values */
    ld1     {v24.4s, v25.4s}, [x0]          /* midstate */
    adrp    x7, K256_asm
    add     x7, x7, :lo12:K256_asm
    adrp    x8, H256_INIT_asm
    add     x8, x8, :lo12:H256_INIT_asm
    ld1     {v26.4s, v27.4s}, [x8]          /* H256_INIT */
    ld1     {v28.4s, v29.4s}, [x2]          /* W2_pad */

    /* ============================================================
     * PASS 1: SHA256(block2) with midstate as initial state
     * ============================================================ */

    /* Load W1 template for nonce A */
    ld1     {v2.4s, v3.4s, v4.4s, v5.4s}, [x1]

    /* Copy for nonce B */
    mov     v8.16b, v2.16b
    mov     v9.16b, v3.16b
    mov     v10.16b, v4.16b
    mov     v11.16b, v5.16b

    /* Set nonces: word [3] of MSG0 */
    mov     v2.s[3], w3                     /* A nonce */
    mov     v8.s[3], w4                     /* B nonce */

    /* Init states from midstate */
    mov     v0.16b, v24.16b                 /* STATE0_A */
    mov     v1.16b, v25.16b                 /* STATE1_A */
    mov     v6.16b, v24.16b                 /* STATE0_B */
    mov     v7.16b, v25.16b                 /* STATE1_B */

    /* ---- Rounds 0-3 ---- */
    ldr     q16, [x7, #0]                   /* K[0..3] */
    ldr     q17, [x7, #16]                  /* K[4..7] */

    /* A: round prep */
    add     v12.4s, v2.4s, v16.4s           /* TMP_A = MSG0_A + K[0..3] */
    mov     v13.16b, v0.16b                 /* save STATE0_A */
    sha256su0 v2.4s, v3.4s                  /* A: msg schedule su0 */

    /* B: round prep (fills A's crypto latency) */
    add     v14.4s, v8.4s, v16.4s           /* TMP_B = MSG0_B + K[0..3] */
    mov     v15.16b, v6.16b                 /* save STATE0_B */
    sha256su0 v8.4s, v9.4s                  /* B: msg schedule su0 */

    /* A: hash compression */
    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    /* B: hash compression */
    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* A+B: complete message schedule */
    sha256su1 v2.4s, v4.4s, v5.4s
    sha256su1 v8.4s, v10.4s, v11.4s

    /* ---- Rounds 4-7 ---- */
    ldr     q16, [x7, #32]                  /* K[8..11] */

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v3.4s, v4.4s

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v9.4s, v10.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v3.4s, v5.4s, v2.4s
    sha256su1 v9.4s, v11.4s, v8.4s

    /* ---- Rounds 8-11 ---- */
    ldr     q17, [x7, #48]                  /* K[12..15] */

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v4.4s, v5.4s

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v10.4s, v11.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v4.4s, v2.4s, v3.4s
    sha256su1 v10.4s, v8.4s, v9.4s

    /* ---- Rounds 12-15 ---- */
    ldr     q16, [x7, #64]                  /* K[16..19] */

    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v5.4s, v2.4s

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v11.4s, v8.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v5.4s, v3.4s, v4.4s
    sha256su1 v11.4s, v9.4s, v10.4s

    /* ---- Rounds 16-19 ---- */
    ldr     q17, [x7, #80]                  /* K[20..23] */

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v2.4s, v3.4s

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v8.4s, v9.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v2.4s, v4.4s, v5.4s
    sha256su1 v8.4s, v10.4s, v11.4s

    /* ---- Rounds 20-23 ---- */
    ldr     q16, [x7, #96]                  /* K[24..27] */

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v3.4s, v4.4s

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v9.4s, v10.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v3.4s, v5.4s, v2.4s
    sha256su1 v9.4s, v11.4s, v8.4s

    /* ---- Rounds 24-27 ---- */
    ldr     q17, [x7, #112]                 /* K[28..31] */

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v4.4s, v5.4s

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v10.4s, v11.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v4.4s, v2.4s, v3.4s
    sha256su1 v10.4s, v8.4s, v9.4s

    /* ---- Rounds 28-31 ---- */
    ldr     q16, [x7, #128]                 /* K[32..35] */

    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v5.4s, v2.4s

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v11.4s, v8.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v5.4s, v3.4s, v4.4s
    sha256su1 v11.4s, v9.4s, v10.4s

    /* ---- Rounds 32-35 ---- */
    ldr     q17, [x7, #144]                 /* K[36..39] */

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v2.4s, v3.4s

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v8.4s, v9.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v2.4s, v4.4s, v5.4s
    sha256su1 v8.4s, v10.4s, v11.4s

    /* ---- Rounds 36-39 ---- */
    ldr     q16, [x7, #160]                 /* K[40..43] */

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v3.4s, v4.4s

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v9.4s, v10.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v3.4s, v5.4s, v2.4s
    sha256su1 v9.4s, v11.4s, v8.4s

    /* ---- Rounds 40-43 ---- */
    ldr     q17, [x7, #176]                 /* K[44..47] */

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v4.4s, v5.4s

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v10.4s, v11.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v4.4s, v2.4s, v3.4s
    sha256su1 v10.4s, v8.4s, v9.4s

    /* ---- Rounds 44-47 ---- */
    ldr     q16, [x7, #192]                 /* K[48..51] */

    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v5.4s, v2.4s

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v11.4s, v8.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v5.4s, v3.4s, v4.4s
    sha256su1 v11.4s, v9.4s, v10.4s

    /* ---- Rounds 48-51 (no more message schedule) ---- */
    ldr     q17, [x7, #208]                 /* K[52..55] */

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* ---- Rounds 52-55 ---- */
    ldr     q16, [x7, #224]                 /* K[56..59] */

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* ---- Rounds 56-59 ---- */
    ldr     q17, [x7, #240]                 /* K[60..63] */

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* ---- Rounds 60-63 ---- */
    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* Pass 1 finalize: state += midstate */
    add     v0.4s, v0.4s, v24.4s
    add     v1.4s, v1.4s, v25.4s
    add     v6.4s, v6.4s, v24.4s
    add     v7.4s, v7.4s, v25.4s

    /* ============================================================
     * PASS 2: SHA256(pass1_output) with H256_INIT
     * Register-to-register transfer - NO memcpy!
     *
     * Pass 1 output (v0,v1 for A; v6,v7 for B) becomes
     * message words for pass 2.
     * MSG0 = state[0..3], MSG1 = state[4..7]
     * MSG2 = W2_pad[0..3], MSG3 = W2_pad[4..7]
     * ============================================================ */

    /* A messages: pass 1 output + padding */
    mov     v2.16b, v0.16b                  /* MSG0_A = pass1 stateA[0..3] */
    mov     v3.16b, v1.16b                  /* MSG1_A = pass1 stateA[4..7] */
    mov     v4.16b, v28.16b                 /* MSG2_A = W2_pad[0..3] */
    mov     v5.16b, v29.16b                 /* MSG3_A = W2_pad[4..7] */

    /* B messages: pass 1 output + padding */
    mov     v8.16b, v6.16b                  /* MSG0_B = pass1 stateB[0..3] */
    mov     v9.16b, v7.16b                  /* MSG1_B = pass1 stateB[4..7] */
    mov     v10.16b, v28.16b                /* MSG2_B = W2_pad[0..3] */
    mov     v11.16b, v29.16b                /* MSG3_B = W2_pad[4..7] */

    /* Init states from H256_INIT */
    mov     v0.16b, v26.16b                 /* STATE0_A */
    mov     v1.16b, v27.16b                 /* STATE1_A */
    mov     v6.16b, v26.16b                 /* STATE0_B */
    mov     v7.16b, v27.16b                 /* STATE1_B */

    /* ---- Pass 2: Rounds 0-3 ---- */
    ldr     q16, [x7, #0]
    ldr     q17, [x7, #16]

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v2.4s, v3.4s

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v8.4s, v9.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v2.4s, v4.4s, v5.4s
    sha256su1 v8.4s, v10.4s, v11.4s

    /* ---- Pass 2: Rounds 4-7 ---- */
    ldr     q16, [x7, #32]

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v3.4s, v4.4s

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v9.4s, v10.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v3.4s, v5.4s, v2.4s
    sha256su1 v9.4s, v11.4s, v8.4s

    /* ---- Pass 2: Rounds 8-11 ---- */
    ldr     q17, [x7, #48]

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v4.4s, v5.4s

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v10.4s, v11.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v4.4s, v2.4s, v3.4s
    sha256su1 v10.4s, v8.4s, v9.4s

    /* ---- Pass 2: Rounds 12-15 ---- */
    ldr     q16, [x7, #64]

    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v5.4s, v2.4s

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v11.4s, v8.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v5.4s, v3.4s, v4.4s
    sha256su1 v11.4s, v9.4s, v10.4s

    /* ---- Pass 2: Rounds 16-19 ---- */
    ldr     q17, [x7, #80]

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v2.4s, v3.4s

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v8.4s, v9.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v2.4s, v4.4s, v5.4s
    sha256su1 v8.4s, v10.4s, v11.4s

    /* ---- Pass 2: Rounds 20-23 ---- */
    ldr     q16, [x7, #96]

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v3.4s, v4.4s

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v9.4s, v10.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v3.4s, v5.4s, v2.4s
    sha256su1 v9.4s, v11.4s, v8.4s

    /* ---- Pass 2: Rounds 24-27 ---- */
    ldr     q17, [x7, #112]

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v4.4s, v5.4s

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v10.4s, v11.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v4.4s, v2.4s, v3.4s
    sha256su1 v10.4s, v8.4s, v9.4s

    /* ---- Pass 2: Rounds 28-31 ---- */
    ldr     q16, [x7, #128]

    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v5.4s, v2.4s

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v11.4s, v8.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v5.4s, v3.4s, v4.4s
    sha256su1 v11.4s, v9.4s, v10.4s

    /* ---- Pass 2: Rounds 32-35 ---- */
    ldr     q17, [x7, #144]

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v2.4s, v3.4s

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v8.4s, v9.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v2.4s, v4.4s, v5.4s
    sha256su1 v8.4s, v10.4s, v11.4s

    /* ---- Pass 2: Rounds 36-39 ---- */
    ldr     q16, [x7, #160]

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v3.4s, v4.4s

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v9.4s, v10.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v3.4s, v5.4s, v2.4s
    sha256su1 v9.4s, v11.4s, v8.4s

    /* ---- Pass 2: Rounds 40-43 ---- */
    ldr     q17, [x7, #176]

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b
    sha256su0 v4.4s, v5.4s

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b
    sha256su0 v10.4s, v11.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v4.4s, v2.4s, v3.4s
    sha256su1 v10.4s, v8.4s, v9.4s

    /* ---- Pass 2: Rounds 44-47 ---- */
    ldr     q16, [x7, #192]

    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b
    sha256su0 v5.4s, v2.4s

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b
    sha256su0 v11.4s, v8.4s

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    sha256su1 v5.4s, v3.4s, v4.4s
    sha256su1 v11.4s, v9.4s, v10.4s

    /* ---- Pass 2: Rounds 48-51 ---- */
    ldr     q17, [x7, #208]

    add     v12.4s, v2.4s, v16.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v8.4s, v16.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* ---- Pass 2: Rounds 52-55 ---- */
    ldr     q16, [x7, #224]

    add     v12.4s, v3.4s, v17.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v9.4s, v17.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* ---- Pass 2: Rounds 56-59 ---- */
    ldr     q17, [x7, #240]

    add     v12.4s, v4.4s, v16.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v10.4s, v16.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* ---- Pass 2: Rounds 60-63 ---- */
    add     v12.4s, v5.4s, v17.4s
    mov     v13.16b, v0.16b

    add     v14.4s, v11.4s, v17.4s
    mov     v15.16b, v6.16b

    sha256h   q0, q1, v12.4s
    sha256h2  q1, q13, v12.4s

    sha256h   q6, q7, v14.4s
    sha256h2  q7, q15, v14.4s

    /* Pass 2 finalize: state += H256_INIT */
    add     v0.4s, v0.4s, v26.4s
    add     v1.4s, v1.4s, v27.4s
    add     v6.4s, v6.4s, v26.4s
    add     v7.4s, v7.4s, v27.4s

    /* Store results */
    st1     {v0.4s, v1.4s}, [x9]           /* stateA_out */
    st1     {v6.4s, v7.4s}, [x10]          /* stateB_out */

    /* Restore callee-saved regs */
    ldp     q14, q15, [sp, #96]
    ldp     q12, q13, [sp, #64]
    ldp     q10, q11, [sp, #32]
    ldp     q8, q9, [sp], #128

    ret

    .size sha256d_dual_asm, . - sha256d_dual_asm


/*
 * Data tables
 */
    .section .rodata
    .balign 64

    .global K256_asm
    .type K256_asm, %object
K256_asm:
    .word 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5  /* rounds 0-3   */
    .word 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5  /* rounds 4-7   */
    .word 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3  /* rounds 8-11  */
    .word 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174  /* rounds 12-15 */
    .word 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc  /* rounds 16-19 */
    .word 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da  /* rounds 20-23 */
    .word 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7  /* rounds 24-27 */
    .word 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967  /* rounds 28-31 */
    .word 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13  /* rounds 32-35 */
    .word 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85  /* rounds 36-39 */
    .word 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3  /* rounds 40-43 */
    .word 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070  /* rounds 44-47 */
    .word 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5  /* rounds 48-51 */
    .word 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3  /* rounds 52-55 */
    .word 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208  /* rounds 56-59 */
    .word 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2  /* rounds 60-63 */
    .size K256_asm, . - K256_asm

    .global H256_INIT_asm
    .type H256_INIT_asm, %object
H256_INIT_asm:
    .word 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
    .word 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    .size H256_INIT_asm, . - H256_INIT_asm

    /* GNU stack note: no executable stack needed */
    .section .note.GNU-stack,"",@progbits
