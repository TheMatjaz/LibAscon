/**
 * @file
 * Iterative parser of testcases specified in the test vectors files.
 *
 * The functions open the file and provide one testcase at the time
 * through the iterator pattern, closing the file on EOF or any errors.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#ifndef VECTORS_H
#define VECTORS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascon.h"

// The awk commands retrieve the longest line of a given type in the file.
// Of that line, one has to count the hexstring length and divide by 2.

// awk '{print length, $0}' hash.txt |grep 'Msg ='|sort -nr|head -1
#define VECS_MAX_HASH_MESSAGE_LEN 1024
// awk '{print length, $0}' aead128.txt |grep 'PT ='|sort -nr|head -1
#define VECS_MAX_AEAD_PLAINTEXT_LEN 32
// awk '{print length, $0}' aead128.txt |grep 'AD ='|sort -nr|head -1
#define VECS_MAX_AEAD_ASSOC_DATA_LEN 32
// awk '{print length, $0}' aead128.txt |grep 'CT ='|sort -nr|head -1
#define VECS_MAX_AEAD_CIPHERTEXT_LEN 48

#define VECS_MAX_HEXBYTES_LEN 1024

typedef enum
{
    VECS_OK = 0,
    VECS_EOF = -1,
    VECS_IO_CANNOT_OPEN_FILE = 1,
    VECS_FORMAT_INCORRECT_COUNT_HDR = 2,
    VECS_FORMAT_INCORRECT_MESSAGE_HDR = 3,
    VECS_FORMAT_INCORRECT_DIGEST_HDR = 4,
    VECS_FORMAT_INCORRECT_KEY_HDR = 5,
    VECS_FORMAT_INCORRECT_NONCE_HDR = 6,
    VECS_FORMAT_INCORRECT_PLAINTEXT_HDR = 7,
    VECS_FORMAT_INCORRECT_ASSOC_DATA_HDR = 8,
    VECS_FORMAT_INCORRECT_CIPHERTEXT_HDR = 9,
    VECS_FORMAT_TOO_SHORT_HEXBYTES = 10,
    VECS_FORMAT_TOO_LARGE_HEXBYTES = 11,
    VECS_FORMAT_TOO_SHORT_PLAINTEXT = 12,
    VECS_FORMAT_TOO_LARGE_PLAINTEXT = 13,
    VECS_FORMAT_TOO_SHORT_DIGEST = 14,
    VECS_FORMAT_TOO_SHORT_KEY = 15,
    VECS_FORMAT_TOO_SHORT_NONCE = 16,
    VECS_FORMAT_TOO_SHORT_CIPHERTEXT = 17,
} vecs_err_t;

typedef struct
{
    size_t message_len;
    size_t count;
    uint8_t message[VECS_MAX_HASH_MESSAGE_LEN];
    uint8_t expected_digest[ASCON_HASH_DIGEST_LEN];
} vecs_hash_t;

typedef struct
{
    size_t plaintext_len;
    size_t assoc_data_len;
    size_t ciphertext_len;
    size_t count;
    size_t key_len;
    uint8_t plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    uint8_t assoc_data[VECS_MAX_AEAD_ASSOC_DATA_LEN];
    uint8_t ciphertext[VECS_MAX_AEAD_CIPHERTEXT_LEN];
    uint8_t key[ASCON_AEAD80pq_KEY_LEN]; // Max key len
    uint8_t nonce[ASCON_AEAD_NONCE_LEN];
    uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    uint8_t pad[4];  // if sizeof(size_t)==8, fills the trailing padding. Otherwise just adds 4 B.
} vecs_aead_t;

typedef struct
{
    FILE* handle;
    size_t key_len;
} vecs_ctx_t;

/**
 * @internal
 * Creates the iterator of test vectors, opening the test file.
 *
 * @param[in, out] ctx iterator state
 * @param[in] file_name file where to read the test vectors from
 * @return any error during file opening
 */
vecs_err_t vecs_init(vecs_ctx_t* ctx, const char* file_name, size_t key_len);

/**
 * @internal
 * Parses and provides one testcase from the test vectors file used to
 * test the hashing functions.
 *
 * Closes the file automatically on EOF or parsing error.
 *
 * @param[in, out] ctx iterator state
 * @param[out] testcase parsed test vectors
 * @return any error during file parsing or EOF indication
 */
vecs_err_t vecs_hash_next(vecs_ctx_t* ctx, vecs_hash_t* testcase);

/**
 * @internal
 * Parses and provides one testcase from the test vectors file used to
 * test the AEAD functions.
 *
 * Closes the file automatically on EOF or parsing error.
 *
 * @param[in, out] ctx iterator state
 * @param[out] testcase parsed test vectors
 * @return any error during file parsing or EOF indication
 */
vecs_err_t vecs_aead_next(vecs_ctx_t* ctx, vecs_aead_t* testcase);

/**
 * @internal
 * Logs the hashing testcase to stdout if DEBUG is defined.
 *
 * @param[in] testcase the test vector to log
 * @param[in] obtained_digest optional digest obtained from the
 *        hashing function. Prints it only if not NULL.
 */
void vecs_hash_log(const vecs_hash_t* testcase,
                   const uint8_t* obtained_digest);

/**
 * @internal
 * Logs the AEAD encryption testcase to stdout if DEBUG is defined.
 *
 * @param[in] testcase the test vector to log
 * @param[in] obtained_ciphertext optional ciphertext obtained from the
 *        AEAD encryption function. Prints it only if not NULL.
 * @param[in] obtained_tag optional tag obtained from the
 *        AEAD encryption function. Prints it only if not NULL.
 * @param[in] obtained_ciphertext_len length in bytes of \p obtained_ciphertext.
 *        Ignored if \p obtained_ciphertext is NULL.
 */
void vecs_aead_enc_log(const vecs_aead_t* testcase,
                       const uint8_t* obtained_ciphertext,
                       const uint8_t* obtained_tag,
                       uint64_t obtained_ciphertext_len);

/**
 * @internal
 * Logs the AEAD decryption testcase to stdout if DEBUG is defined.
 *
 * @param[in] testcase the test vector to log
 * @param[in] obtained_plaintext optional plaintext obtained from the
 *        AEAD decryption function. Prints it only if not NULL.
 * @param[in] obtained_plaintext_len length in bytes of \p obtained_plaintext.
 *        Ignored if \p obtained_plaintext is NULL.
 */
void vecs_aead_dec_log(const vecs_aead_t* testcase,
                       const uint8_t* obtained_plaintext,
                       uint64_t obtained_plaintext_len);

/**
 * @internal
 * Log any generic array of bytes in hex format.
 *
 * @param name name of the array (e.g. "key", "plaintext", "tag")
 * @param array the data to log
 * @param amount number of bytes in the array
 */
void vecs_log_hexbytes(const char* name,
                       const uint8_t* array,
                       size_t amount);

#ifdef __cplusplus
}
#endif

#endif  /* VECTORS_H */
