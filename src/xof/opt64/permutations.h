#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#include <stdint.h>

#define EXT_BYTE64(x, n) ((uint8_t)((uint64_t)(x) >> (8 * (7 - (n)))))
#define INS_BYTE64(x, n) ((uint64_t)(x) << (8 * (7 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define ROUND(C)                    \
  do {                              \
    ascon_xof_ctx_t t;              \
    ctx->x2 ^= C;                      \
    ctx->x0 ^= ctx->x4;                   \
    ctx->x4 ^= ctx->x3;                   \
    ctx->x2 ^= ctx->x1;                   \
    t.x0 = ctx->x0;                    \
    t.x4 = ctx->x4;                    \
    t.x3 = ctx->x3;                    \
    t.x1 = ctx->x1;                    \
    t.x2 = ctx->x2;                    \
    ctx->x0 = t.x0 ^ ((~t.x1) & t.x2); \
    ctx->x2 = t.x2 ^ ((~t.x3) & t.x4); \
    ctx->x4 = t.x4 ^ ((~t.x0) & t.x1); \
    ctx->x1 = t.x1 ^ ((~t.x2) & t.x3); \
    ctx->x3 = t.x3 ^ ((~t.x4) & t.x0); \
    ctx->x1 ^= ctx->x0;                   \
    t.x1 = ctx->x1;                    \
    ctx->x1 = ROTR64(ctx->x1, 39);        \
    ctx->x3 ^= ctx->x2;                   \
    t.x2 = ctx->x2;                    \
    ctx->x2 = ROTR64(ctx->x2, 1);         \
    t.x4 = ctx->x4;                    \
    t.x2 ^= ctx->x2;                   \
    ctx->x2 = ROTR64(ctx->x2, 6 - 1);     \
    t.x3 = ctx->x3;                    \
    t.x1 ^= ctx->x1;                   \
    ctx->x3 = ROTR64(ctx->x3, 10);        \
    ctx->x0 ^= ctx->x4;                   \
    ctx->x4 = ROTR64(ctx->x4, 7);         \
    t.x3 ^= ctx->x3;                   \
    ctx->x2 ^= t.x2;                   \
    ctx->x1 = ROTR64(ctx->x1, 61 - 39);   \
    t.x0 = ctx->x0;                    \
    ctx->x2 = ~ctx->x2;                   \
    ctx->x3 = ROTR64(ctx->x3, 17 - 10);   \
    t.x4 ^= ctx->x4;                   \
    ctx->x4 = ROTR64(ctx->x4, 41 - 7);    \
    ctx->x3 ^= t.x3;                   \
    ctx->x1 ^= t.x1;                   \
    ctx->x0 = ROTR64(ctx->x0, 19);        \
    ctx->x4 ^= t.x4;                   \
    t.x0 ^= ctx->x0;                   \
    ctx->x0 = ROTR64(ctx->x0, 28 - 19);   \
    ctx->x0 ^= t.x0;                   \
  } while (0)

#define P12()    \
  do {           \
    ROUND(0xf0); \
    ROUND(0xe1); \
    ROUND(0xd2); \
    ROUND(0xc3); \
    ROUND(0xb4); \
    ROUND(0xa5); \
    ROUND(0x96); \
    ROUND(0x87); \
    ROUND(0x78); \
    ROUND(0x69); \
    ROUND(0x5a); \
    ROUND(0x4b); \
  } while (0)

#define P8()     \
  do {           \
    ROUND(0xb4); \
    ROUND(0xa5); \
    ROUND(0x96); \
    ROUND(0x87); \
    ROUND(0x78); \
    ROUND(0x69); \
    ROUND(0x5a); \
    ROUND(0x4b); \
  } while (0)

#define P6()     \
  do {           \
    ROUND(0x96); \
    ROUND(0x87); \
    ROUND(0x78); \
    ROUND(0x69); \
    ROUND(0x5a); \
    ROUND(0x4b); \
  } while (0)

#endif  // PERMUTATIONS_H_

