/**
 * @file
 */

#include "ascon.h"

void ascon128_encrypt(uint8_t* ciphertext,
                      uint8_t* tag,
                      const uint8_t* plaintext,
                      const uint8_t* assoc_data,
                      const uint8_t* nonce,
                      const uint8_t* key,
                      size_t plaintext_len,
                      size_t assoc_data_len)
{
    ascon_aead_ctx_t ctx;
    ascon128_init(&ctx, nonce, key);
    ascon128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    ascon128_assoc_data_final(&ctx);
    const size_t new_ct_bytes = ascon128_encrypt_update(&ctx, ciphertext,
                                                        plaintext,
                                                        plaintext_len);
    ascon128_encrypt_final(&ctx, ciphertext + new_ct_bytes, NULL,
                           tag);
}

// TODO consider sorting pointers in alphabetic order or something to make it
// less probable to make a mistake by swapping 2 pointers
ascon_err_t ascon128_decrypt(uint8_t* plaintext,
                             const uint8_t* assoc_data,
                             const uint8_t* ciphertext,
                             const uint8_t* tag,
                             const uint8_t* nonce,
                             const uint8_t* key,
                             size_t assoc_data_len,
                             size_t ciphertext_len)
{
    ascon_aead_ctx_t ctx;
    ascon128_init(&ctx, nonce, key);
    ascon128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    ascon128_assoc_data_final(&ctx);
    const size_t new_pt_bytes = ascon128_decrypt_update(&ctx, plaintext,
                                                        ciphertext,
                                                        ciphertext_len);
    return ascon128_decrypt_final(&ctx, plaintext + new_pt_bytes, NULL, tag);
}

void ascon_hash(uint8_t* digest, const uint8_t* data, size_t data_len)
{
    ascon_hash_ctx_t ctx;
    ascon_hash_init(&ctx);
    ascon_hash_update(&ctx, data, data_len);
    ascon_hash_final(&ctx, digest);
}

void ascon_hash_xof(uint8_t* digest, const uint8_t* data,
                    size_t digest_len, size_t data_len)
{
    ascon_hash_ctx_t ctx;
    ascon_hash_init_xof(&ctx);
    ascon_hash_update(&ctx, data, data_len);
    ascon_hash_final_xof(&ctx, digest, digest_len);
}
