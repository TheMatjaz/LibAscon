/**
 * @file
 * LibAscon header file.
 *
 * Interface to the Ascon library providing:
 * - the Ascon AEAD cipher
 * - the Ascon fixed-size output hash
 * - the Ascon variable-size output hash (xof)
 *
 * All functionalities are available in:
 * - online form (init-update-final): the data is processed one chunk at the
 *   time
 * - offline form: the data is available as a whole in memory and processed
 *   in one go
 *
 * Library dependencies:
 * - only the C99 or C11 standard libary, as seen in the `#include` statements
 *   below
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#ifndef ASCON_H
#define ASCON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h> /* For uint8_t, uint64_t */
#include <stddef.h> /* For size_t, NULL */
#include <string.h> /* For memcpy() */

/**
 * Length in bytes of the secret symmetric key used for authenticated
 * encryption and decryption.
 */
#define ASCON_AEAD_KEY_LEN 16U

/**
 * Length in bytes of the public nonce used for authenticated
 * encryption and decryption.
 */
#define ASCON_AEAD_NONCE_LEN 16U

/**
 * Length in bytes of the authentication tag generated by the authenticated
 * encryption and validated by the decryption.
 */
#define ASCON_AEAD_TAG_LEN 16U

/**
 * Length in bytes of the digest generated by the fixed-size (non-xof) hash
 * function.
 */
#define ASCON_HASH_DIGEST_LEN 32U

/**
 * Rate in bytes at which the input data is processed by the cipher.
 *
 * The cipher can absorb this many bytes simultaneously except for the last
 * few bytes that are padded.
 */
#define ASCON_RATE 8U

/**
 * Possible outputs of the final step of the decryption that also validates
 * the tag.
 */
typedef enum e_ascon_tag_validity
{
    ASCON_TAG_OK = 0, /** The tag is valid thus the decryption too. */
    ASCON_TAG_INVALID = 1, /** The tag is invalid thus the decrypted data
                             * should be ignored. */
} ascon_tag_validity_t;

// TODO activate all compiler checks

/**
 * Internal cipher sponge state (320 bits).
 */
struct s_ascon_state
{
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
};
typedef struct s_ascon_state ascon_state_t;

// TODO check that all structs are aligned and compressed
// TODO add explicit struct paddings, where required.
/**
 * Cipher context for authenticated encryption and validated decryption.
 */
struct s_ascon_aead_ctx
{
    /** Cipher sponge state. */
    ascon_state_t state;

    /** Copy of the key, to be used in the final step, part 1. */
    uint64_t k0;

    /** Copy of the key, to be used in the final step, part 2. */
    uint64_t k1;

    /** Counter of all encrypted/decrypted bytes, excluding associated data. */
    uint64_t total_output_len;

    /** Buffer caching the less-than-rate long input between update calls. */
    uint8_t buffer[ASCON_RATE];

    /** Currently used bytes of the buffer. */
    uint8_t buffer_len;

    uint8_t assoc_data_state;
};
typedef struct s_ascon_aead_ctx ascon_aead_ctx_t;

/**
 * Cipher context for hashing.
 */
struct s_ascon_hash_ctx
{
    /** Cipher sponge state. */
    ascon_state_t state;

    /** Buffer caching the less-than-rate long input between update calls. */
    uint8_t buffer[ASCON_RATE];

    /** Currently used bytes of the buffer. */
    uint8_t buffer_len;
};
typedef struct s_ascon_hash_ctx ascon_hash_ctx_t;

// Tag must support ASCON_AEAD_TAG_LEN bytes
// Ciphertext must support plaintext_len bytes.
void ascon128_encrypt(uint8_t* ciphertext,
                      uint8_t* tag,
                      const uint8_t* key,
                      const uint8_t* nonce,
                      const uint8_t* assoc_data,
                      const uint8_t* plaintext,
                      size_t assoc_data_len,
                      size_t plaintext_len);

void ascon128_init(ascon_aead_ctx_t* ctx,
                   const uint8_t* key,
                   const uint8_t* nonce);

void ascon128_assoc_data_update(ascon_aead_ctx_t* ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len);

// Generates [0, plaintext_len] ciphertext bytes
// Returns # of ciphertext bytes generated
size_t ascon128_encrypt_update(ascon_aead_ctx_t* ctx,
                               uint8_t* ciphertext,
                               const uint8_t* plaintext,
                               size_t plaintext_len);

// Generates [0, ASCON_RATE - 1] ciphertext bytes
// Returns # of ciphertext bytes generated
size_t ascon128_encrypt_final(ascon_aead_ctx_t* ctx,
                              uint8_t* ciphertext,
                              uint64_t* total_ciphertext_len, // Could be NULL
                              uint8_t* tag);

// Tag must support ASCON_AEAD_TAG_LEN bytes
// Plaintext must support ciphertext_len bytes
// This function fails if the tag is invalid
ascon_tag_validity_t ascon128_decrypt(uint8_t* plaintext,
                                      const uint8_t* key,
                                      const uint8_t* nonce,
                                      const uint8_t* ciphertext,
                                      const uint8_t* assoc_data,
                                      const uint8_t* tag,
                                      size_t assoc_data_len,
                                      size_t ciphertext_len);

// Generates [0, ciphertext_len] plaintext bytes
// Returns # of plaintext bytes generated
size_t ascon128_decrypt_update(ascon_aead_ctx_t* ctx,
                               uint8_t* plaintext,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len);

// Generates [0, ASCON_RATE - 1] plaintext bytes
// Returns # of plaintext bytes generated
size_t ascon128_decrypt_final(ascon_aead_ctx_t* ctx,
                              uint8_t* plaintext,
                              uint64_t* total_plaintext_len, // Could be NULL
                              ascon_tag_validity_t* tag_validity,
                              const uint8_t* tag);

void ascon_hash(uint8_t* digest, const uint8_t* data, size_t data_len);

void ascon_hash_init(ascon_hash_ctx_t* ctx);

void
ascon_hash_update(ascon_hash_ctx_t* ctx, const uint8_t* data, size_t data_len);

void ascon_hash_final(ascon_hash_ctx_t* ctx, uint8_t* digest);

void ascon_hash_xof(uint8_t* digest,
                    const uint8_t* data,
                    size_t digest_len,
                    size_t data_len);

void ascon_hash_init_xof(ascon_hash_ctx_t* ctx);

void ascon_hash_final_xof(ascon_hash_ctx_t* ctx,
                          uint8_t* digest,
                          size_t digest_len);

#ifdef __cplusplus
}
#endif

#endif  /* ASCON_H */
