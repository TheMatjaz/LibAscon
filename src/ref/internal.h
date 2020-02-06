/**
 * @file
 * LibAscon internal header file.
 *
 * Common code (mostly the code state permutations) applied during
 * encryption, decryption and hashing.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#ifndef ASCON_INTERNAL_H
#define ASCON_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>
#include "ascon.h"

#define PERMUTATION_A_ROUNDS 12
#define PERMUTATION_B_ROUNDS 6
#define XOF_IV ( \
    ((uint64_t)(8 * (ASCON_RATE)) << 48U) \
    | ((uint64_t)(PERMUTATION_A_ROUNDS) << 40U) \
    )
#define AEAD128_IV ( \
     ((uint64_t)(8 * (ASCON_AEAD_KEY_LEN)) << 56U) \
     | XOF_IV \
     | ((uint64_t)(PERMUTATION_B_ROUNDS) << 32U) \
     )
#define HASH_IV (XOF_IV | (uint64_t)(8 * ASCON_HASH_DIGEST_LEN))
#define PADDING(bytes) (0x80ULL << (56 - 8 * ((size_t) bytes)))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

void printstate(const char* text, const ascon_sponge_t* sponge);

uint64_t bytes_to_u64(const uint8_t* bytes, uint_fast8_t n);

void u64_to_bytes(uint8_t* bytes, uint64_t x, uint_fast8_t n);

void smallcpy(uint8_t* dst, const uint8_t* src, uint8_t amount);

uint64_t byte_mask(uint_fast8_t n);

void ascon_permutation_a12(ascon_sponge_t* sponge);

void ascon_permutation_8(ascon_sponge_t* sponge);

void ascon_permutation_b6(ascon_sponge_t* sponge);

typedef void (* absorb_fptr)(ascon_sponge_t* sponge,
                             uint8_t* data_out,
                             const uint8_t* data);

size_t buffered_accumulation(ascon_bufstate_t* ctx,
                             uint8_t* data_out,
                             const uint8_t* data_in,
                             absorb_fptr absorb,
                             size_t data_in_len);

#ifdef __cplusplus
}
#endif

#endif  /* ASCON_INTERNAL_H */
