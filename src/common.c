/**
 * @file
 */

#include "ascon.h"

void ascon128_encrypt(uint8_t* ciphertext,
                      uint64_t* ciphertext_len,
                      uint8_t* tag,
                      const uint8_t* plaintext,
                      const uint8_t* assoc_data,
                      const uint8_t* nonce,
                      const uint8_t* key,
                      size_t plaintext_len,
                      size_t assoc_data_len)
{
    ascon_aead_ctx_t ctx;
    ascon128_encrypt_init(&ctx, nonce, key);
    ascon128_encrypt_update_ad(&ctx, assoc_data, assoc_data_len);
    ascon128_encrypt_final_ad(&ctx);
    ascon128_encrypt_update_pt(&ctx, ciphertext, plaintext, plaintext_len);
    ascon128_encrypt_final(&ctx, ciphertext, ciphertext_len, tag);
}

/*
ascon_err_t ascon128_decrypt(uint8_t* plaintext,
                             const uint8_t* assoc_data,
                             const uint8_t* ciphertext,
                             const uint8_t* nonce,
                             const uint8_t* key,
                             size_t assoc_data_len,
                             size_t ciphertext_len)
{
    ascon_aead_ctx_t ctx;
    ascon_err_t errcode;
    ascon128_decrypt_init(&ctx, nonce, key);
    ascon128_decrypt_update_ad(&ctx, assoc_data, assoc_data_len);
    errcode = ascon128_decrypt_update_ct(&ctx, plaintext,
                                         ciphertext, ciphertext_len);
    if (errcode != ASCON_OK)
    {
        // TODO zero-out context
    }
    else
    {
        errcode = ascon128_decrypt_final(&ctx, plaintext);
    }
    return errcode;
}
*/

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
