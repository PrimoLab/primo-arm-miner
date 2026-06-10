/*
 * Endian encode/decode helpers shared by the algorithm and stratum layers.
 * Header-only static inlines (file-local in each TU); previously duplicated
 * in sha256_neon.c, scrypt_neon.c, and stratum_standard.cpp.
 */

#ifndef PRIMO_BYTEORDER_H
#define PRIMO_BYTEORDER_H

#include <stdint.h>

static inline uint32_t be32dec(const void *pp) {
    const uint8_t *p = (const uint8_t *)pp;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void be32enc(void *pp, uint32_t x) {
    uint8_t *p = (uint8_t *)pp;
    p[0] = (x >> 24) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[3] = x & 0xff;
}

static inline uint32_t le32dec(const void *pp) {
    const uint8_t *p = (const uint8_t *)pp;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void le32enc(void *pp, uint32_t x) {
    uint8_t *p = (uint8_t *)pp;
    p[0] = x & 0xff;
    p[1] = (x >> 8) & 0xff;
    p[2] = (x >> 16) & 0xff;
    p[3] = (x >> 24) & 0xff;
}

static inline uint16_t le16dec(const void *pp) {
    const uint8_t *p = (const uint8_t *)pp;
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

#endif /* PRIMO_BYTEORDER_H */
