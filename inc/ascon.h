/**
 * @file
 */

#ifndef ASCON_H
#define ASCON_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stddef.h>

// Defines for block size, tag size, hash-digest size, xof-digest size
#define ASCON_AEAD_KEY_SIZE 16
#define ASCON_AEAD_BLOCK_SIZE 16
#define ASCON_AEAD_NONCE_SIZE 16
#define ASCON_HASH_DIGEST_SIZE 32
#define ASCON_XOF_DIGEST_SIZE 32
#define ASCON_XOF_RATE (64 / 8)

// TODO decide between size and len in names
// TODO activate all compiler checks

typedef struct {} ascon_aead_ctx_t;
typedef struct {} ascon_hash_ctx_t;
typedef struct
{
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
} ascon_xof_ctx_t;

typedef enum
{
    ASCON_OK = 0,
    ASCON_TOO_SHORT_CIPHERTEXT = 1,
    ASCON_INVALID_TAG = 2,
} ascon_err_t;

void ascon128_encrypt(uint8_t* ciphertext,
                      size_t* ciphertext_len,
                      const uint8_t* plaintext,
                      const uint8_t* assoc_data,
                      const uint8_t* nonce,
                      const uint8_t* key,
                      size_t plaintext_len,
                      size_t assoc_data_len);

void ascon128_encrypt_init(ascon_aead_ctx_t* ctx,
                           const uint8_t* nonce,
                           const uint8_t* key);

void ascon128_encrypt_update_ad(ascon_aead_ctx_t* ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len);

void ascon128_encrypt_update_pt(ascon_aead_ctx_t* ctx,
                                uint8_t* ciphertext,
                                size_t* ciphertext_len,
                                const uint8_t* plaintext,
                                size_t plaintext_len);

void ascon128_encrypt_final(ascon_aead_ctx_t* ctx,
                            uint8_t* ciphertext,
                            size_t* ciphertext_len);

ascon_err_t ascon128_decrypt(uint8_t* plaintext,
                             const uint8_t* assoc_data,
                             const uint8_t* ciphertext,
                             const uint8_t* nonce,
                             const uint8_t* key,
                             size_t assoc_data_len,
                             size_t ciphertext_len);

void ascon128_decrypt_init(ascon_aead_ctx_t* ctx,
                           const uint8_t* nonce,
                           const uint8_t* key);

void ascon128_decrypt_update_ad(ascon_aead_ctx_t* ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len);

ascon_err_t ascon128_decrypt_update_ct(ascon_aead_ctx_t* ctx,
                                       uint8_t* plaintext,
                                       const uint8_t* ciphertext,
                                       size_t ciphertext_len);

ascon_err_t ascon128_decrypt_final(ascon_aead_ctx_t* ctx,
                                   uint8_t* plaintext);

void ascon_hash(uint8_t* digest, const uint8_t* data, size_t data_len);

void ascon_hash_init(ascon_hash_ctx_t* ctx);

void
ascon_hash_update(ascon_hash_ctx_t* ctx, const uint8_t* data, size_t data_len);

void ascon_hash_final(ascon_hash_ctx_t* ctx, uint8_t* digest);

void ascon_xof(uint8_t* digest, const uint8_t* data, size_t data_len);

void ascon_xof_init(ascon_xof_ctx_t* ctx);

void
ascon_xof_update(ascon_xof_ctx_t* ctx, const uint8_t* data, size_t data_len);

void ascon_xof_final(ascon_xof_ctx_t* ctx, uint8_t* digest);

#ifdef __cplusplus
}
#endif

#endif  /* ASCON_H */
