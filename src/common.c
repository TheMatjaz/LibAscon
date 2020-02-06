/**
 * @file
 */

#include "ascon.h"

void ascon_aead128_encrypt(uint8_t* ciphertext,
                           uint8_t* tag,
                           const uint8_t* key,
                           const uint8_t* nonce,
                           const uint8_t* assoc_data,
                           const uint8_t* plaintext,
                           size_t assoc_data_len,
                           size_t plaintext_len)
{
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128_encrypt_update(&ctx, ciphertext,
                                                             plaintext,
                                                             plaintext_len);
    ascon_aead128_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                NULL, tag);
}

ascon_tag_validity_t ascon_aead128_decrypt(uint8_t* plaintext,
                                           const uint8_t* key,
                                           const uint8_t* nonce,
                                           const uint8_t* assoc_data,
                                           const uint8_t* ciphertext,
                                           const uint8_t* tag,
                                           size_t assoc_data_len,
                                           size_t ciphertext_len)
{
    ascon_aead_ctx_t ctx;
    ascon_tag_validity_t validity;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128_decrypt_update(&ctx,
                                                             plaintext,
                                                             ciphertext,
                                                             ciphertext_len);
    ascon_aead128_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                NULL, &validity, tag);
    return validity;
}

void ascon_hash(uint8_t* const digest,
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
    ascon_hash_init_xof(&ctx);
    ascon_hash_update(&ctx, data, data_len);
    ascon_hash_final_xof(&ctx, digest, digest_len);
}
