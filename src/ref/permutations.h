#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#include <stddef.h>
#include <stdint.h>
#include "ascon.h"

#define AEAD128_IV ( \
     ((uint64_t)(8 * (ASCON_AEAD_KEY_LEN)) << 56U) \
     | ((uint64_t)(8 * (ASCON_RATE)) << 48U) \
     | ((uint64_t)(PA_ROUNDS) << 40U) \
     | ((uint64_t)(PB_ROUNDS) << 32U) \
     )
#define XOF_IV ( \
    ((uint64_t)(8 * (ASCON_RATE)) << 48U) \
    | ((uint64_t)(PA_ROUNDS) << 40U) \
    )
#define HASH_IV (XOF_IV | (uint64_t)(8 * ASCON_HASH_DIGEST_LEN))
#define PADDING(bytes) (0x80ULL << (56 - 8 * ((size_t) bytes)))

#define PA_ROUNDS 12
#define PB_ROUNDS 6

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

void inline printstate(const char* text, const ascon_state_t* state);
uint64_t bytes_to_u64(const uint8_t* bytes, uint_fast8_t n);
void u64_to_bytes(uint8_t* bytes, uint64_t x, uint_fast8_t n);
uint64_t byte_mask(uint_fast8_t n);
void ascon_permutation_a12(ascon_state_t* state);
void ascon_permutation_8(ascon_state_t* state);
void ascon_permutation_b6(ascon_state_t* state);


#endif  // PERMUTATIONS_H_

