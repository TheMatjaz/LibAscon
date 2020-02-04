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
#include <string.h>

// Defines for block size, tag size, hash-digest size, xof-digest size
#define ASCON_AEAD_KEY_SIZE 16U
#define ASCON_AEAD_NONCE_SIZE 16U
#define ASCON_AEAD_TAG_SIZE 16U
#define ASCON_RATE 8U
#define ASCON_HASH_DIGEST_SIZE 32U

// TODO decide between size and len in names
// TODO activate all compiler checks

struct s_ascon_state
{
    uint64_t x0;
    uint64_t x1;
    uint64_t x2;
    uint64_t x3;
    uint64_t x4;
};
typedef struct s_ascon_state ascon_state_t;

struct s_ascon_aead_ctx
{
    ascon_state_t state;
    uint64_t k0;
    uint64_t k1;
    uint64_t total_ciphertext_len; // Not size_t as the CT may be larger than
    // memory
    uint8_t buffer[ASCON_RATE];
    uint8_t buffer_len;
};
typedef struct s_ascon_aead_ctx ascon_aead_ctx_t;

struct s_ascon_hash_ctx
{
    ascon_state_t state;
    uint8_t buffer[ASCON_RATE];
    uint8_t buffer_len;
};
typedef struct s_ascon_hash_ctx ascon_hash_ctx_t;

typedef enum e_ascon_err
{
    ASCON_OK = 0,
    ASCON_TOO_SHORT_CIPHERTEXT = 1,
    ASCON_INVALID_TAG = 2,
} ascon_err_t;

void ascon128_encrypt(uint8_t* ciphertext,
                      uint64_t* ciphertext_len,
                      uint8_t* tag,
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

void ascon128_encrypt_final_ad(ascon_aead_ctx_t* ctx);

// Generates [0, plaintext_len] ciphertext bytes
size_t ascon128_encrypt_update_pt(ascon_aead_ctx_t* ctx,
                                  uint8_t* ciphertext,
                                  const uint8_t* plaintext,
                                  size_t plaintext_len);

// Generates [0, ASCON_RATE - 1] ciphertext bytes
size_t ascon128_encrypt_final(ascon_aead_ctx_t* ctx,
                              uint8_t* ciphertext,
                              uint64_t* total_ciphertext_len,
                              uint8_t* tag);
// TODO consider separate uint8_t* tag where the tag is written
//  If NULL, append tag at end of ciphertext

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

// Add some output of plaintext length, as it may be less due to buffering
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
