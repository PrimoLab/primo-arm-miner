/*
 * Haraka v2 — ARM AES implementation interface. The permutation core is a
 * translation of the Haraka v2 reference implementation, Copyright (c)
 * 2016 kste (MIT); keyed variants follow the VerusHash construction,
 * Copyright (c) 2018 The Verus Developers (MIT). Full notice in
 * src/algorithm/haraka_native.c.
 */

#ifndef HARAKA_NATIVE_H_
#define HARAKA_NATIVE_H_

#ifdef __aarch64__
#include <arm_neon.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Native ARMv8 implementations - exact same signatures as portable versions
void load_constants_native(void);

void haraka256_native(unsigned char *out, const unsigned char *in);

// Haraka512 variants
void haraka512_native(unsigned char *out, const unsigned char *in);
void haraka512_keyed_native(unsigned char *out, const unsigned char *in, const uint8x16_t *rc);

#ifdef __cplusplus
}
#endif

#ifdef __aarch64__

// AES round function using ARMv8 crypto extensions
// PERFORMANCE: Force inline to eliminate function call overhead
static inline uint8x16_t aes_encrypt_round_native(uint8x16_t state, uint8x16_t round_key) __attribute__((always_inline));
static inline uint8x16_t aes_encrypt_round_native(uint8x16_t state, uint8x16_t round_key) {
    // ARMv8 AES: SubBytes + ShiftRows + MixColumns + AddRoundKey
    return vaesmcq_u8(vaeseq_u8(state, (uint8x16_t){})) ^ round_key;
}

#endif // __aarch64__

#endif // HARAKA_NATIVE_H_
