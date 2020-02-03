#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdint.h>
#include "ascon.h"

#define AEAD128_IV ( \
     ((uint64_t)(8 * (ASCON_AEAD_KEY_SIZE)) << 56U) \
     | ((uint64_t)(8 * (ASCON_RATE)) << 48U) \
     | ((uint64_t)(PA_ROUNDS) << 40U) \
     | ((uint64_t)(PB_ROUNDS) << 32U) \
     )
#define XOF_IV ( \
    ((uint64_t)(8 * (ASCON_RATE)) << 48U) \
    | ((uint64_t)(PA_ROUNDS) << 40U) \
    )
#define HASH_IV (XOF_IV | (uint64_t)(8 * ASCON_HASH_DIGEST_SIZE))
#define PADDING(bytes) (0x80ULL << (56 - 8 * ((size_t) bytes)))

#define PA_ROUNDS 12
#define PB_ROUNDS 6

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

static inline void printstate(const char* text, const ascon_state_t* ctx) {
#ifdef DEBUG_PERMUTATIONS
  printf("%s\n", text);
  printf("  x0=%016llx\n", ctx->x0);
  printf("  x1=%016llx\n", ctx->x1);
  printf("  x2=%016llx\n", ctx->x2);
  printf("  x3=%016llx\n", ctx->x3);
  printf("  x4=%016llx\n", ctx->x4);
#else
  // disable warning about unused parameters
  (void)text;
  (void)ctx;
#endif
}

static inline uint64_t BYTES_TO_U64(const uint8_t* bytes, int n) {
  int i;
  uint64_t x = 0;
  for (i = 0; i < n; i++) x |= ((uint64_t)bytes[i]) << (56 - 8 * i);
  return x;
}

static inline void U64_TO_BYTES(uint8_t* bytes, const uint64_t x, int n) {
  int i;
  for (i = 0; i < n; i++) bytes[i] = (uint8_t)(x >> (56 - 8 * i));
}

static inline uint64_t BYTE_MASK(int n) {
  int i;
  uint64_t x = 0;
  for (i = 0; i < n; i++) x |= 0xffull << (56 - 8 * i);
  return x;
}

static inline uint64_t ROTR64(uint64_t x, int n) { return (x << (64 - n)) | (x >> n); }

static inline void ROUND(uint8_t C, ascon_state_t* p) {
  // TODO this function leaves state traces on the stack in s and t structs
  ascon_state_t s = *p;
  ascon_state_t t;
  // addition of round constant
  s.x2 ^= C;
  printstate(" addition of round constant:", &s);
  // substitution layer
  s.x0 ^= s.x4;
  s.x4 ^= s.x3;
  s.x2 ^= s.x1;
  // start of keccak s-box
  t.x0 = ~s.x0;
  t.x1 = ~s.x1;
  t.x2 = ~s.x2;
  t.x3 = ~s.x3;
  t.x4 = ~s.x4;
  t.x0 &= s.x1;
  t.x1 &= s.x2;
  t.x2 &= s.x3;
  t.x3 &= s.x4;
  t.x4 &= s.x0;
  s.x0 ^= t.x1;
  s.x1 ^= t.x2;
  s.x2 ^= t.x3;
  s.x3 ^= t.x4;
  s.x4 ^= t.x0;
  // end of keccak s-box
  s.x1 ^= s.x0;
  s.x0 ^= s.x4;
  s.x3 ^= s.x2;
  s.x2 = ~s.x2;
  printstate(" substitution layer:", &s);
  // linear diffusion layer
  s.x0 ^= ROTR64(s.x0, 19) ^ ROTR64(s.x0, 28);
  s.x1 ^= ROTR64(s.x1, 61) ^ ROTR64(s.x1, 39);
  s.x2 ^= ROTR64(s.x2, 1) ^ ROTR64(s.x2, 6);
  s.x3 ^= ROTR64(s.x3, 10) ^ ROTR64(s.x3, 17);
  s.x4 ^= ROTR64(s.x4, 7) ^ ROTR64(s.x4, 41);
  printstate(" linear diffusion layer:", &s);
  *p = s;
    // TODO erase s and t
}

static inline void P12(ascon_state_t* s) {
  printstate(" permutation input:", s);
  ROUND(0xf0, s);
  ROUND(0xe1, s);
  ROUND(0xd2, s);
  ROUND(0xc3, s);
  ROUND(0xb4, s);
  ROUND(0xa5, s);
  ROUND(0x96, s);
  ROUND(0x87, s);
  ROUND(0x78, s);
  ROUND(0x69, s);
  ROUND(0x5a, s);
  ROUND(0x4b, s);
}

static inline void P8(ascon_state_t* s) {
  printstate(" permutation input:", s);
  ROUND(0xb4, s);
  ROUND(0xa5, s);
  ROUND(0x96, s);
  ROUND(0x87, s);
  ROUND(0x78, s);
  ROUND(0x69, s);
  ROUND(0x5a, s);
  ROUND(0x4b, s);
}

static inline void P6(ascon_state_t* s) {
  printstate(" permutation input:", s);
  ROUND(0x96, s);
  ROUND(0x87, s);
  ROUND(0x78, s);
  ROUND(0x69, s);
  ROUND(0x5a, s);
  ROUND(0x4b, s);
}

#endif  // PERMUTATIONS_H_

