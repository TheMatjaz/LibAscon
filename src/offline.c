/**
 * @file
 * Implementations of offline AEAD and hashing functions, that is functions
 * that operate on the unfragmented data, feeding it into the state in one go.
 *
 * They are implemented as a simple wrapper around the Init-Update-Final API.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"

#if ASCON_COMPILE_AEAD128

void ascon_aead128_encrypt(uint8_t* ciphertext,
                           uint8_t* tag,
                           const uint8_t* key,
                           const uint8_t* nonce,
                           const uint8_t* assoc_data,
                           const uint8_t* plaintext,
                           size_t assoc_data_len,
                           size_t plaintext_len,
                           uint8_t tag_len)
{
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128_encrypt_update(&ctx, ciphertext,
                                                             plaintext,
                                                             plaintext_len);
    ascon_aead128_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                NULL, tag, tag_len);
}

bool ascon_aead128_decrypt(uint8_t* plaintext,
                           const uint8_t* key,
                           const uint8_t* nonce,
                           const uint8_t* assoc_data,
                           const uint8_t* ciphertext,
                           const uint8_t* tag,
                           size_t assoc_data_len,
                           size_t ciphertext_len,
                           uint8_t tag_len)
{
    ascon_aead_ctx_t ctx;
    bool is_tag_valid;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128_decrypt_update(&ctx,
                                                             plaintext,
                                                             ciphertext,
                                                             ciphertext_len);
    ascon_aead128_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                NULL, &is_tag_valid, tag, tag_len);
    return is_tag_valid;
}

inline void ascon_aead128_cleanup(ascon_aead_ctx_t* const ctx)
{
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
}

#endif /* ASCON_COMPILE_AEAD128 */
#if ASCON_COMPILE_AEAD128a

bool ascon_aead128a_decrypt(uint8_t* plaintext,
                            const uint8_t* key,
                            const uint8_t* nonce,
                            const uint8_t* assoc_data,
                            const uint8_t* ciphertext,
                            const uint8_t* tag,
                            size_t assoc_data_len,
                            size_t ciphertext_len,
                            uint8_t tag_len)
{
    ascon_aead_ctx_t ctx;
    bool is_tag_valid;
    ascon_aead128a_init(&ctx, key, nonce);
    ascon_aead128a_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128a_decrypt_update(&ctx,
                                                              plaintext,
                                                              ciphertext,
                                                              ciphertext_len);
    ascon_aead128a_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                 NULL, &is_tag_valid, tag, tag_len);
    return is_tag_valid;
}

void ascon_aead128a_encrypt(uint8_t* ciphertext,
                            uint8_t* tag,
                            const uint8_t* key,
                            const uint8_t* nonce,
                            const uint8_t* assoc_data,
                            const uint8_t* plaintext,
                            size_t assoc_data_len,
                            size_t plaintext_len,
                            uint8_t tag_len)
{
    ascon_aead_ctx_t ctx;
    ascon_aead128a_init(&ctx, key, nonce);
    ascon_aead128a_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128a_encrypt_update(&ctx, ciphertext,
                                                              plaintext,
                                                              plaintext_len);
    ascon_aead128a_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                 NULL, tag, tag_len);
}

inline void ascon_aead128a_cleanup(ascon_aead_ctx_t* const ctx)
{
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
}

#endif /* ASCON_COMPILE_AEAD128a */
#if ASCON_COMPILE_HASH

void ascon_hash(uint8_t digest[ASCON_HASH_DIGEST_LEN],
                const uint8_t* const data,
                const size_t data_len)
{
    ascon_hash_ctx_t ctx;
    ascon_hash_init(&ctx);
    ascon_hash_update(&ctx, data, data_len);
    ascon_hash_final(&ctx, digest);
}

void ascon_hash_xof(uint8_t* const digest,
                    const uint8_t* const data,
                    const size_t digest_len,
                    const size_t data_len)
{
    ascon_hash_ctx_t ctx;
    ascon_hash_xof_init(&ctx);
    ascon_hash_update(&ctx, data, data_len);
    ascon_hash_xof_final(&ctx, digest, digest_len);
}

void inline ascon_hash_cleanup(ascon_hash_ctx_t* const ctx)
{
    memset(ctx, 0, sizeof(ascon_hash_ctx_t));
}

#endif /* ASCON_COMPILE_HASH */
