/**
 * @file
 * Ascon cipher - Lightweight Authenticated Encryption & Hashing
 *
 * Ascon is a family of authenticated encryption and hashing algorithms
 * designed to be lightweight and easy to implement, even with added
 * countermeasures against side-channel attacks.
 *
 * For more information on the Ascon cipher itself, visit
 * https://ascon.iaik.tugraz.at/
 *
 * This file is the interface to the Ascon library providing:
 * - the Ascon symmetric AEAD cipher
 * - the Ascon fixed-size output hash
 * - the Ascon variable-size output hash (xof)
 *
 * All functionalities are available in:
 * - online form (init-update-final paradigm): the data is processed one
 *   chunk at the time; useful if is still being received or does not
 *   fit into memory
 * - offline form: the data is available as a whole in memory and processed
 *   in one go
 *
 * Library dependencies:
 * - only the C99 or C11 standard library, as seen in the `#include` statements
 *   below
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors See AUTHORS.md file
 */

// TODO test all branches in the algorithm
// TODO test all NULLable parameters
// TODO static analyser
// TODO valgrind
// TODO fuzzer
// TODO tests with updates of different length (contd.)
// 1B, 2B, ... 16B
// Same but with initial offset
// Same with pseudorandom sequences like 3, 17, 9, 1, 0, 22

#ifndef ASCON_H
#define ASCON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h> /* For uint8_t, uint64_t */
#include <stddef.h> /* For size_t, NULL */
#include <string.h> /* For memset() */

#define ASCON_API_VERSION_MAJOR 0
#define ASCON_API_VERSION_MINOR 1
#define ASCON_API_VERSION_BUGFIX 0
// Double level of indirection to allow precompiler to evaluate the
// integer macros as strings properly and thus concatenate them in the
// version string.
#define _ascon_str2(x) #x
#define _ascon_str(x) _ascon_str2(x)
#define ASCON_API_VERSION ( \
    _ascon_str(ASCON_API_VERSION_MAJOR) \
    "." \
    _ascon_str(ASCON_API_VERSION_MINOR) \
    "." \
    _ascon_str(ASCON_API_VERSION_BUGFIX) \
    )

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
 * The cipher can absorb only chunks of this many bytes. Any trailing bytes
 * of the processed data are padded.
 */
#define ASCON_RATE 8U

/**
 * Possible outputs of the final step of the decryption that also validates
 * the tag.
 */
typedef enum
{
    /** The tag is valid thus the decryption too. */
            ASCON_TAG_OK = 0,
    /** The tag is invalid thus the decrypted data should be ignored. */
            ASCON_TAG_INVALID = 1,
} ascon_tag_validity_t;

/**
 * Internal cipher sponge state (320 bits).
 */
typedef struct
{
    /** Sponge's first field */
    uint64_t x0;
    /** Sponge's second field */
    uint64_t x1;
    /** Sponge's third field */
    uint64_t x2;
    /** Sponge's fourth field */
    uint64_t x3;
    /** Sponge's fifth field */
    uint64_t x4;
} ascon_sponge_t;

/**
 * Internal cipher sponge state associated with a buffer holding for
 * less-than-rate updates. Used for the Init-Update-Final implementation.
 */
typedef struct
{
    /** Cipher sponge state. */
    ascon_sponge_t sponge;

    /** Counter of all encrypted/decrypted bytes, excluding associated data. */
    uint64_t total_output_len;

    /** Buffer caching the less-than-rate long input between update calls. */
    uint8_t buffer[ASCON_RATE];

    /** Currently used bytes of the buffer. */
    uint8_t buffer_len;

    /**
     * State of the processing of the associated data.
     *
     * Note: this variable is not semantically relevant in THIS struct,
     * as it should belong in the struct ascon_aead_ctx_t, but by having it
     * here we spare bytes of padding (7 on 64-bit systems, 3 on 32-bit)
     * at the end of the struct ascon_aead_ctx_t, by using the padding space
     * this struct anyway has.
     *
     * This struct has anyway some padding at the end.
     */
    uint8_t assoc_data_state;

    /** Unused padding to the next uint64_t (sponge.x0). */
    uint8_t pad[6];
} ascon_bufstate_t;

/**
 * Cipher context for authenticated encryption and validated decryption.
 *
 * Half of this context's size is the cipher's sponge state, the remaining
 * part is holding the key and the buffering of online data (and some padding).
 */
typedef struct
{
    /** Cipher buffered sponge state. */
    ascon_bufstate_t bufstate;

    /** Copy of the secret key, to be used in the final step, first half. */
    uint64_t k0;

    /** Copy of the secret key, to be used in the final step, second half. */
    uint64_t k1;
} ascon_aead_ctx_t;

/** Cipher context for hashing. */
typedef ascon_bufstate_t ascon_hash_ctx_t;

// TODO difference between AEAD(key, nonce, ad, NO_PT) and HASH
//  (key||nonce||msg)?
/**
 * Offline symmetric encryption using Ascon128.
 *
 * Encrypts the data which is already available as a whole in a contiguous
 * buffer, authenticating any optional associated data in the process.
 * Provides the ciphertext and the authentication tag as output.
 *
 * In case of no associated data at all to be authenticated, set
 * \p assoc_data_len to 0. Iff that is the case, \p assoc_data can
 * be set to NULL.
 *
 * In case of no plaintext at all to be encrypted, set
 * \p plaintext_len to 0. Iff that is the case, \p plaintext can
 * be set to NULL (see warning).
 *
 * @warning
 * Using the AEAD encryption to just authenticate any associated data with no
 * plaintext to be encrypted is not recommended for security reasons.
 * Instead use the Ascon hashing or xof functions in the form
 * `Hash(key || nonce || msg)`.
 *
 * @image html encrypt.png
 *
 * @param[out] ciphertext encrypted data with the same length as the
 *       plaintext, thus \p plaintext_len will be written in this buffer.
 *       This pointer may also point to the same location as \p plaintext
 *       to encrypt the plaintext in-place, sparing on memory instead
 *       of writing into a separate output buffer. Not NULL.
 * @param[out] tag Message Authentication Code (MAC, a.k.a. cryptographic tag,
 *       fingerprint), used to validate the integrity and authenticity of the
 *       associated data and ciphertext. Has ASCON_AEAD_TAG_LEN bytes. Not NULL.
 * @param[in] key secret key of ASCON_AEAD_KEY_LEN bytes.
 * @param[in] nonce public unique nonce of ASCON_AEAD_NONCE_LEN bytes.
 * @param[in] assoc_data data to be authenticated with the same tag
 *        but not encrypted. Can be NULL iff \p assoc_data_len is 0.
 * @param[in] plaintext data to be encrypted into \p ciphertext.
 * @param[in] assoc_data_len length of the data pointed by \p assoc_data in
 *        bytes. Can be 0.
 * @param[in] plaintext_len length of the data pointed by \p plaintext in
 *        bytes. Can be 0 (not recommended, see warning).
 */
void ascon_aead128_encrypt(uint8_t* ciphertext,
                           uint8_t tag[ASCON_AEAD_TAG_LEN],
                           const uint8_t key[ASCON_AEAD_KEY_LEN],
                           const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                           const uint8_t* assoc_data,
                           const uint8_t* plaintext,
                           size_t assoc_data_len,
                           size_t plaintext_len);

/**
 * Online symmetric encryption/decryption using Ascon128, initialisation.
 *
 * Prepares to start a new encryption or decryption session for plaintext or
 * ciphertext and associated data being provided one chunk at the time.
 *
 * The key and nonce are copied/absorbed into the internal state, so they can
 * be deleted from their original location after this function returns.
 *
 * The calling order for encryption/decryption is:
 * 1. ascon_aead128_init() - once only
 * 2. ascon_aead128_assoc_data_update() - 0 or more times
 * 3. ascon_aead128_encrypt_update()/ascon_aead128_decrypt_update() - 0 or
 *    more times, see warning
 * 4. ascon_aead128_encrypt_final()/ascon_aead128_encrypt_final() - once only
 *
 * @warning
 * Using the AEAD encryption to just authenticate any associated data with no
 * plaintext at all to be encrypted is not recommended for security reasons.
 * Instead use the Ascon hashing or xof functions in the form
 * `Hash(key || nonce || msg)`.
 *
 * @warning
 * A copy of the secret key is kept in the \p ctx struct and securely erased
 * during the ascon_aead128_encrypt_final() call. In case the encryption
 * or decryption session is interrupted and never finalised, clear the context
 * with `memset(&ctx, 0, sizeof(ascon_aead_ctx_t));` to erase the key copy.
 *
 * @image html encrypt.png
 * @image html decrypt.png
 *
 * @param[in, out] ctx the encryption/decryption context, handling the cipher
 *       state and buffering of incoming data to be processed. Not NULL.
 * @param[in] key secret key of ASCON_AEAD_KEY_LEN bytes. Not NULL.
 * @param[in] nonce public unique nonce of ASCON_AEAD_NONCE_LEN bytes. Not NULL.
 */
void ascon_aead128_init(ascon_aead_ctx_t* ctx,
                        const uint8_t key[ASCON_AEAD_KEY_LEN],
                        const uint8_t nonce[ASCON_AEAD_NONCE_LEN]);

/**
 * Online symmetric encryption/decryption using Ascon128, feeding associated
 * data.
 *
 * Feeds a chunk of associated data to the already initialised encryption
 * or decryption session. The data will be authenticated by the tag provided by
 * the final function, but not encrypted or decrypted.
 *
 * In case of no associated data at all to be authenticated/validated, this
 * function can either be either skipped completely or called (also many times)
 * with \p assoc_data_len set to 0. Iff that is the case, \p assoc_data can
 * be set to NULL.
 *
 * After calling ascon_aead128_encrypt_update() or
 * ascon_aead128_decrypt_update(), this function must not be used anymore
 * on the same context.
 *
 * The calling order for encryption/decryption is:
 * 1. ascon_aead128_init() - once only
 * 2. ascon_aead128_assoc_data_update() - 0 or more times
 * 3. ascon_aead128_encrypt_update()/ascon_aead128_decrypt_update() - 0 or
 *    more times, see warning
 * 4. ascon_aead128_encrypt_final()/ascon_aead128_encrypt_final() - once only
 *
 * @warning
 * Using the AEAD encryption to just authenticate any associated data with no
 * plaintext at all to be encrypted is not recommended for security reasons.
 * Instead use the Ascon hashing or xof functions in the form
 * `Hash(key || nonce || msg)`.
 *
 * @param[in, out] ctx the encryption/decryption context, handling the cipher
 *       state and buffering of incoming data to be processed. Not NULL.
 * @param[in] assoc_data data to be authenticated/validated with the same tag
 *        but not encrypted/decrypted. May be NULL iff \p assoc_data_len is 0.
 * @param[in] assoc_data_len length of the data pointed by \p assoc_data in
 *        bytes. May be 0.
 */
void ascon_aead128_assoc_data_update(ascon_aead_ctx_t* ctx,
                                     const uint8_t* assoc_data,
                                     size_t assoc_data_len);

/**
 * Online symmetric encryption using Ascon128, feeding plaintext and getting
 * ciphertext.
 *
 * Feeds a chunk of plaintext data to the encryption session after any
 * optional associated data has been processed. The plaintext will be encrypted
 * and provided back in buffered chunks of #ASCON_RATE bytes.
 *
 * It will automatically finalise the absorption of any associated data,
 * so no new associated data could be processed after this function is called.
 *
 * The calling order for encryption is:
 * 1. ascon_aead128_init() - once only
 * 2. ascon_aead128_assoc_data_update() - 0 or more times
 * 3. ascon_aead128_encrypt_update() - 0 or more times, see warning
 * 4. ascon_aead128_encrypt_final() - once only
 *
 * @warning
 * Using the AEAD encryption to just authenticate any associated data with no
 * plaintext at all to be encrypted is not recommended for security reasons.
 * Instead use the Ascon hashing or xof functions in the form
 * `Hash(key || nonce || msg)`.
 *
 * @param[in, out] ctx the encryption context, handling the cipher
 *       state and buffering of incoming data to be processed. Not NULL.
 * @param[out] ciphertext encrypted data, buffered into chunks.
 *       This function will write a multiple of #ASCON_RATE bytes in the
 *       interval [0, \p plaintext_len + #ASCON_RATE[ into \p ciphertext.
 *       The exact number of written bytes is indicated by the return value.
 *       This pointer may also point to the same location as \p plaintext
 *       to encrypt the plaintext in-place, sparing on memory instead
 *       of writing into a separate output buffer. Not NULL.
 * @param[in] plaintext data to be encrypted into \p ciphertext. All of the
 *       plaintext will be processed, even if the function provides less than
 *       \p plaintext_len output bytes. They are just buffered. Not NULL.
 * @param[in] plaintext_len length of the data pointed by \p plaintext in
 *        bytes. May be 0.
 * @returns number of bytes written into \p ciphertext. The value is a multiple
 *        of #ASCON_RATE in [0, \p plaintext_len + #ASCON_RATE[.
 */
size_t ascon_aead128_encrypt_update(ascon_aead_ctx_t* ctx,
                                    uint8_t* ciphertext,
                                    const uint8_t* plaintext,
                                    size_t plaintext_len);

/**
 * Online symmetric encryption using Ascon128, finalisation and tag generation.
 *
 * Finalises the authenticated encryption by returning any remaining buffered
 * ciphertext and the authentication tag.
 *
 * Optionally it can also provide the total ciphertext bytes generated during
 * this session. This is equal to the total plaintext bytes, but for streaming
 * data with unknown length in advance, the encryption session keeps track of
 * the total encrypted bytes.
 *
 * It will securely erase the content of the \p ctx struct before returning.
 *
 * The calling order for encryption is:
 * 1. ascon_aead128_init() - once only
 * 2. ascon_aead128_assoc_data_update() - 0 or more times
 * 3. ascon_aead128_encrypt_update() - 0 or more times, see warning
 * 4. ascon_aead128_encrypt_final() - once only
 *
 * @warning
 * Using the AEAD encryption to just authenticate any associated data with no
 * plaintext at all to be encrypted is not recommended for security reasons.
 * Instead use the Ascon hashing or xof functions in the form
 * `Hash(key || nonce || msg)`.
 *
 * @warning
 * A copy of the secret key is kept in the \p ctx struct and securely erased
 * during the ascon_aead128_encrypt_final() call. In case the
 * encryption session is interrupted and never finalised, clear the context
 * with `memset(&ctx, 0, sizeof(ascon_aead_ctx_t));` to erase the key copy.
 *
 * @param[in, out] ctx the encryption context, handling the cipher
 *       state and buffering of incoming data to be processed. It will be erased
 *       securely before this function returns. Not NULL.
 * @param[out] ciphertext trailing encrypted data still available in the
 *       buffer of the buffered updating. This function will write
 *       [0, #ASCON_RATE[ bytes into \p ciphertext.
 *       The exact number of written bytes is indicated by the return value.
 *       Not NULL.
 * @param[out] total_ecnrypted_bytes sum of all ciphertext bytes generated by
 *       all update calls and this final call of this encryption session.
 *       It's the same as the sum of all plaintext bytes. May be NULL,
 *       if the sum is not of interest.
 * @param[out] tag Message Authentication Code (MAC, a.k.a. cryptographic tag,
 *       fingerprint), used to validate the integrity and authenticity of the
 *       associated data and ciphertext. Has ASCON_AEAD_TAG_LEN bytes. Not NULL.
 * @returns number of bytes written into \p ciphertext. The value is in the
 *        interval [0, #ASCON_RATE[, i.e. whatever remained in the buffer
 *        after the last update call.
 */
size_t ascon_aead128_encrypt_final(ascon_aead_ctx_t* ctx,
                                   uint8_t* ciphertext,
                                   uint64_t* total_ecnrypted_bytes,
                                   uint8_t tag[ASCON_AEAD_TAG_LEN]);

/**
 * Offline symmetric decryption using Ascon128.
 *
 * Decrypts the data which is already available as a whole in a contiguous
 * buffer, validating any optional associated data in the process.
 * Provides the plaintext and the validity of the authentication tag as output.
 *
 * In case of no associated data at all to be authenticated, set
 * \p assoc_data_len to 0. Iff that is the case, \p assoc_data can
 * be set to NULL.
 *
 * In case of no plaintext at all to be encrypted, set
 * \p plaintext_len to 0. Iff that is the case, \p plaintext can
 * be set to NULL (see warning of ascon_aead128_encrypt()).
 *
 * @image html decrypt.png
 *
 * @param[out] plaintext decrypted data with the same length as the
 *       ciphertext, thus \p ciphertext_len will be written in this buffer.
 *       This pointer may also point to the same location as \p ciphertext
 *       to decrypt the ciphertext in-place, sparing on memory instead
 *       of writing into a separate output buffer. Not NULL.
 * @param[in] key secret key of ASCON_AEAD_KEY_LEN bytes.
 * @param[in] nonce public unique nonce of ASCON_AEAD_NONCE_LEN bytes.
 * @param[in] assoc_data data to be validated with the same tag
 *        but not decrypted. Can be NULL iff \p assoc_data_len is 0.
 * @param[in] ciphertext data to be decrypted into \p plaintext.
 * @param[in] tag Message Authentication Code (MAC, a.k.a. cryptographic tag,
 *       fingerprint), used to validate the integrity and authenticity of the
 *       associated data and ciphertext. Has ASCON_AEAD_TAG_LEN bytes. Not NULL.
 * @param[in] assoc_data_len length of the data pointed by \p assoc_data in
 *        bytes. Can be 0.
 * @param[in] ciphertext_len length of the data pointed by \p ciphertext in
 *        bytes. Can be 0 (not recommended, see warning of
 *        ascon_aead128_encrypt()).
 * @returns #ASCON_TAG_OK if the validation of the tag is correct, thus the
 *        associated data and ciphertext are intact and authentic.
 *        #ASCON_TAG_INVALID otherwise.
 */
ascon_tag_validity_t
ascon_aead128_decrypt(uint8_t* plaintext,
                      const uint8_t key[ASCON_AEAD_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data,
                      const uint8_t* ciphertext,
                      const uint8_t tag[ASCON_AEAD_TAG_LEN],
                      size_t assoc_data_len,
                      size_t ciphertext_len);

/**
 * Online symmetric decryption using Ascon128, feeding ciphertext and getting
 * plaintext.
 *
 * Feeds a chunk of ciphertext data to the decryption session after any
 * optional associated data has been processed. The ciphertext will be decrypted
 * and provided back in buffered chunks of #ASCON_RATE bytes.
 *
 * It will automatically finalise the absorption of any associated data,
 * so no new associated data could be processed after this function is called.
 *
 * The calling order is:
 * 1. ascon_aead128_init() - once only
 * 2. ascon_aead128_assoc_data_update() - 0 or more times
 * 3. ascon_aead128_decrypt_update() - 0 or more times, see warning
 * 4. ascon_aead128_decrypt_final() - once only
 *
 * @param[in, out] ctx the decryption context, handling the cipher state
 *       and buffering of incoming data to be processed. Not NULL.
 * @param[out] plaintext decrypted data, buffered into chunks.
 *       This function will write a multiple of #ASCON_RATE bytes in the
 *       interval [0, \p ciphertext_len + #ASCON_RATE[ into \p plaintext.
 *       The exact number of written bytes is indicated by the return value.
 *       This pointer may also point to the same location as \p ciphertext
 *       to decrypt the ciphertext in-place, sparing on memory instead
 *       of writing into a separate output buffer. Not NULL.
 * @param[in] ciphertext data to be decrypted into \p plaintext. All of the
 *       ciphertext will be processed, even if the function provides less than
 *       \p ciphertext_len output bytes. They are just buffered. Not NULL.
 * @param[in] ciphertext_len length of the data pointed by \p ciphertext in
 *        bytes. May be 0.
 * @returns number of bytes written into \p plaintext. The value is a multiple
 *        of #ASCON_RATE in [0, \p ciphertext_len + #ASCON_RATE[.
 */
size_t ascon_aead128_decrypt_update(ascon_aead_ctx_t* ctx,
                                    uint8_t* plaintext,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_len);

/**
 * Online symmetric decryption using Ascon128, finalisation and tag validation.
 *
 * Finalises the authenticated decryption by returning any remaining buffered
 * plaintext and the validity of the authentication tag.
 *
 * Optionally it can also provide the total plaintext bytes generated during
 * this session. This is equal to the total ciphertext bytes, but for streaming
 * data with unknown length in advance, the decryption session keeps track of
 * the total decrypted bytes.
 *
 * It will securely erase the content of the \p ctx struct before returning.
 *
 * The calling order for encryption is:
 * 1. ascon_aead128_init() - once only
 * 2. ascon_aead128_assoc_data_update() - 0 or more times
 * 3. ascon_aead128_decrypt_update() - 0 or more times, see warning
 * 4. ascon_aead128_decrypt_final() - once only
 *
 * @warning
 * A copy of the secret key is kept in the \p ctx struct and securely erased
 * during the ascon_aead128_decrypt_final() call. In case the
 * decryption session is interrupted and never finalised, clear the context
 * with `memset(&ctx, 0, sizeof(ascon_aead_ctx_t));` to erase the key copy.
 *
 * @param[in, out] ctx the decryption context, handling the cipher
 *       state and buffering of incoming data to be processed. It will be erased
 *       securely before this function returns. Not NULL.
 * @param[out] plaintext trailing decrypted data still available in the
 *       buffer of the buffered updating. This function will write
 *       [0, #ASCON_RATE[ bytes into \p plaintext.
 *       The exact number of written bytes is indicated by the return value.
 *       Not NULL.
 * @param[out] total_decrypted_len sum of all plaintext bytes generated by
 *       all update calls and this final call of this decryption session.
 *       It's the same as the sum of all ciphertext bytes fed into the
 *       update calls. May be NULL, if the sum is not of interest.
 * @param[out] tag_validity #ASCON_TAG_OK if the validation of the tag is
 *       correct, thus the associated data and ciphertext are intact and
 *       authentic. #ASCON_TAG_INVALID otherwise.
 * @param[in] tag Message Authentication Code (MAC, a.k.a. cryptographic tag,
 *       fingerprint), used to validate the integrity and authenticity of the
 *       associated data and ciphertext. Has ASCON_AEAD_TAG_LEN bytes. Not NULL.
 * @returns number of bytes written into \p plaintext. The value is in the
 *        interval [0, #ASCON_RATE[, i.e. whatever remained in the buffer
 *        after the last update call.
 */
size_t ascon_aead128_decrypt_final(ascon_aead_ctx_t* ctx,
                                   uint8_t* plaintext,
                                   uint64_t* total_decrypted_len,
                                   ascon_tag_validity_t* tag_validity,
                                   const uint8_t* tag);

/**
 * Offline Ascon Hash with fixed digest length.
 *
 * Hashes the data, which is already available as a whole in a contiguous
 * buffer, and provides the digest for it.
 *
 * @remark
 * This function can be used for keyed hashing to generate a MAC by simply
 * prepending a secret key to the message, like `Hash(key || msg)` or
 * `Hash(key || nonce || msg)` in case also a nonce is used. There
 * is no need to build an HMAC construct around it, as it does not suffer from
 * length-extension vulnerabilities.
 *
 * @warning
 * For security reasons, a digest length of at least 128 bits (16 bytes) is
 * recommended. Against birthday attacks (collisions), 256 bits (32 bytes)
 * are recommended. Against quantum computers, the hash size should be double
 * the amount of wanted security bits. For longer digest sizes, use the xof-hash
 * functions (ascon_hash_xof() or ascon_hash_xof_init()).
 *
 * @param[out] digest fingerprint of the message, output of the hash function,
 *       of #ASCON_HASH_DIGEST_LEN bytes.
 * @param[in] data message fed into the hash function.
 * @param[in] data_len length of \p data in bytes.
 */
void ascon_hash(uint8_t digest[ASCON_HASH_DIGEST_LEN],
                const uint8_t* data,
                size_t data_len);

/**
 * Offline Ascon Hash with fixed digest length, initialisation.
 *
 * Prepares to start a new hashing session to get a digest of
 * #ASCON_HASH_DIGEST_LEN bytes.
 *
 * @remark
 * Ascon Hash can be used for keyed hashing to generate a MAC by simply
 * prepending a secret key to the message, like `Hash(key || msg)` or
 * `Hash(key || nonce || msg)` in case also a nonce is used. There
 * is no need to build an HMAC construct around it, as it does not suffer from
 * length-extension vulnerabilities.
 *
 * @warning
 * For security reasons, a digest length of at least 128 bits (16 bytes) is
 * recommended. Against birthday attacks (collisions), 256 bits (32 bytes)
 * are recommended. Against quantum computers, the hash size should be double
 * the amount of wanted security bits. For longer digest sizes, use the xof-hash
 * functions (ascon_hash_xof() or ascon_hash_xof_init()).
 *
 * @param[in, out] ctx the hashing context, handling the hash function state
 *       and buffering of incoming data to be processed. Not NULL.
 */
void ascon_hash_init(ascon_hash_ctx_t* ctx);

/**
 * Offline Ascon Hash with fixed digest length, feeding data to hash.
 *
 * Feeds a chunk of data to the already initialised hashing session.
 *
 * In case of no data at all to be hashed, this function can be called (also
 * many times) with \p data_len set to 0.* Iff that is the case, \p data can be
 * set to NULL.
 *
 * @param[in, out] ctx the hashing context, handling the hash function state
 *       and buffering of incoming data to be processed. Not NULL.
 * @param[in] data bytes to be hashes. May be NULL iff \p data_len is 0.
 * @param[in] data_len length of the \p data pointed by in bytes. May be 0.
 */
void ascon_hash_update(ascon_hash_ctx_t* ctx,
                       const uint8_t* data,
                       size_t data_len);

/**
 * Offline Ascon Hash with fixed digest length, finalisation and digest
 * generation.
 *
 * Finalises the hashing by returning the digest of the message.
 *
 * @param[in, out] ctx the hashing context, handling the hash function state
 *       and buffering of incoming data to be processed. It will be erased
 *       securely before this function returns. Not NULL.
 * @param[out] digest fingerprint of the message, output of the hash function,
 *       of #ASCON_HASH_DIGEST_LEN bytes.
 */
void ascon_hash_final(ascon_hash_ctx_t* ctx,
                      uint8_t digest[ASCON_HASH_DIGEST_LEN]);

/**
 * Offline Ascon Hash with custom digest length (eXtendable Output Function,
 * XOF).
 *
 * Hashes the data, which is already available as a whole in a contiguous
 * buffer, and provides the digest for it of the desired length.
 *
 * This function can be used for keyed hashing to generate a MAC by simply
 * prepending a secret key to the message, like `Hash(key || msg)` or
 * `Hash(key || nonce || msg)` in case also a nonce is used. There
 * is no need to build an HMAC construct around it, as it does not suffer from
 * length-extension vulnerabilities.
 *
 * @warning
 * For security reasons, a digest length of at least 128 bits (16 bytes) is
 * recommended. Against birthday attacks (collisions), 256 bits (32 bytes)
 * are recommended. Against quantum computers, the hash size should be double
 * the amount of wanted security bits.
 *
 * @param[out] digest fingerprint of the message, output of the hash function,
 *       of \p digest_len bytes.
 * @param[in] data message fed into the hash function.
 * @param[in] digest_len desired length of the \p digest in bytes.
 * @param[in] data_len length of \p data in bytes.
 */
void ascon_hash_xof(uint8_t* digest,
                    const uint8_t* data,
                    size_t digest_len,
                    size_t data_len);

/**
 * Offline Ascon Hash with custom digest length (eXtendable Output Function,
 * XOF), initialisation.
 *
 * Prepares to start a new hashing session to get a digest of custom length.
 *
 * @remark
 * Ascon Hash-Xof can be used for keyed hashing to generate a MAC by simply
 * prepending a secret key to the message, like `Hash(key || msg)` or
 * `Hash(key || nonce || msg)` in case also a nonce is used. There
 * is no need to build an HMAC construct around it, as it does not suffer from
 * length-extension vulnerabilities.
 *
 * @warning
 * For security reasons, a digest length of at least 128 bits (16 bytes) is
 * recommended. Against birthday attacks (collisions), 256 bits (32 bytes)
 * are recommended. Against quantum computers, the hash size should be double
 * the amount of wanted security bits.
 *
 * @param[in, out] ctx the hashing context, handling the hash function state
 *       and buffering of incoming data to be processed. Not NULL.
 */
void ascon_hash_xof_init(ascon_hash_ctx_t* ctx);

/**
 * Offline Ascon Hash with custom digest length (eXtendable Output Function,
 * XOF), feeding data to hash.
 *
 * Feeds a chunk of data to the already initialised hashing session.
 *
 * In case of no data at all to be hashed, this function can be called (also
 * many times) with \p data_len set to 0.* Iff that is the case, \p data can be
 * set to NULL.
 *
 * @param[in, out] ctx the hashing context, handling the hash function state
 *       and buffering of incoming data to be processed. Not NULL.
 * @param[in] data bytes to be hashes. May be NULL iff \p data_len is 0.
 * @param[in] data_len length of the \p data pointed by in bytes. May be 0.
 */
void ascon_hash_xof_update(ascon_hash_ctx_t* ctx,
                           const uint8_t* data,
                           size_t data_len);

/**
 * Offline Ascon Hash with custom digest length (eXtendable Output Function,
 * XOF), finalisation and digest generation.
 *
 * Finalises the hashing by returning the digest of the message.
 *
 * @param[in, out] ctx the hashing context, handling the hash function state
 *       and buffering of incoming data to be processed. It will be erased
 *       securely before this function returns. Not NULL.
 * @param[out] digest fingerprint of the message, output of the hash function,
 *       of \p digest_size bytes.
 * @param[in] digest_len desired length of the \p digest in bytes.
 */
void ascon_hash_xof_final(ascon_hash_ctx_t* ctx,
                          uint8_t* digest,
                          size_t digest_len);

#ifdef __cplusplus
}
#endif

#endif  /* ASCON_H */
