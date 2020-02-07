/**
 * @file
 * LibAscon internal header file.
 *
 * Common code (mostly the sponge state permutations and conversion utilities)
 * applied during encryption, decryption and hashing.
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

/* Definitions of the initialisation vectors used to initalise the sponge
 * state for AEAD and the two types of hashing functions. */
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

/**
 * @internal
 * Applies 0b1000...000 right-side padding to a uint8_t[8] array of
 * `bytes` filled elements..
 */
#define PADDING(bytes) (0x80ULL << (56 - 8 * ((unsigned int) (bytes))))

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

/**
 * @internal
 * Prints the sponge state to stdout for debugging purposes.
 *
 * Does nothing unless the macro DEBUG_PERMUTATIONS is defined.
 *
 * @param text string to print before the state, used to indicate when the
 *        printing is performed
 * @param sponge the state to print
 */
void log_sponge(const char* text, const ascon_sponge_t* sponge);

/**
 * @internal
 * Converts an array of 8 bytes, out of which the first n are used, to a
 * uint64_t value.
 *
 * Big endian encoding.
 */
uint64_t bytes_to_u64(const uint8_t* bytes, uint_fast8_t n);

/**
 * Converts a uint64_t value to an array of n bytes, truncating the result
 * if n < 8.
 *
 * Big endian encoding.
 */
void u64_to_bytes(uint8_t* bytes, uint64_t x, uint_fast8_t n);

/**
 * @internal
 * Creates a mask to extract the n most significant bytes of a uint64_t.
 */
uint64_t byte_mask(uint_fast8_t n);

/**
 * @internal
 * Ascon sponge permutation with 12 rounds, known as permutation-a.
 */
void ascon_permutation_a12(ascon_sponge_t* sponge);

/**
 * @internal
 * Ascon sponge permutation with 8 rounds.
 */
void ascon_permutation_8(ascon_sponge_t* sponge);

/**
 * @internal
 * Ascon sponge permutation with 6 rounds, known as permutation-b.
 */
void ascon_permutation_b6(ascon_sponge_t* sponge);

/**
 * @internal
 * Function pointer representing the operation run by the
 * buffered_accumulation() when ASCON_RATE bytes ara available in the buffer to
 * be absorbed.
 *
 * @param sponge the sponge state to absorb data into.
 * @param data_out optional outgoing data from the sponge, which happends during
 *        encryption or decryption, but not during hashing.
 * @param data_in the input data to be absorbed by the sponge.
 */
typedef void (* absorb_fptr)(ascon_sponge_t* sponge,
                             uint8_t* data_out,
                             const uint8_t* data_in);

/**
 * @internal
 * Buffers any input data into the bufstate and on accumulation of ASCON_RATE
 * bytes, runs the absorb function to process them.
 *
 * This function is used by the AEAD and hash implementations to enable
 * the Init-Udpate-Final paradigm. The update functions pass the absorb_fptr
 * function specific to them, while this function is the framework handling the
 * accumulation of data until the proper amount is reached.
 *
 * It is not used during the Final step, as that requires paddings and special
 * additional operations such as tag/digest generation.
 *
 * @param ctx the sponge and the buffer to accumulate data in
 * @param data_out optional output data squeezed from the sponge
 * @param data_in input data to be absorbed by the sponge
 * @param absorb function that handles the absorption and optional squeezing
 *        of the sponge
 * @param data_in_len length of the \p data_in in bytes
 * @return number of bytes written into \p data_out
 */
size_t buffered_accumulation(ascon_bufstate_t* ctx,
                             uint8_t* data_out,
                             const uint8_t* data_in,
                             absorb_fptr absorb,
                             size_t data_in_len);

#ifdef __cplusplus
}
#endif

#endif  /* ASCON_INTERNAL_H */
