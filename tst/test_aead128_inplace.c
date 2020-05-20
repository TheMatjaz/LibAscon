/**
 * @file
 * Tests of the AEAD128 encryption and decryption in-place, that is
 * writing the output data into the input buffer itself.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define AEAD_VECTORS_FILE "vectors/aead128.txt"
#define KEY_LEN ASCON_AEAD128_KEY_LEN

static void test_inplace_offline(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t transformed[VECS_MAX_AEAD_PLAINTEXT_LEN];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_aead_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_ctr(testcase.count);
        atto_eq(errcode, VECS_OK);
        atto_eq(testcase.plaintext_len, testcase.ciphertext_len);

        // Encrypt
        memcpy(transformed, testcase.plaintext, testcase.plaintext_len);
        ascon_aead128_encrypt(transformed,
                              obtained_tag,
                              testcase.key,
                              testcase.nonce,
                              testcase.assoc_data,
                              transformed,
                              testcase.assoc_data_len,
                              testcase.plaintext_len,
                              sizeof(testcase.tag));
        vecs_aead_enc_log(&testcase, transformed, obtained_tag,
                          testcase.ciphertext_len);
        atto_memeq(transformed,
                   testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

        // Decrypt
        const bool is_valid = ascon_aead128_decrypt(
                transformed,
                testcase.key,
                testcase.nonce,
                testcase.assoc_data,
                transformed,
                obtained_tag,
                testcase.assoc_data_len,
                testcase.ciphertext_len,
                sizeof(testcase.tag));
        vecs_aead_dec_log(&testcase, transformed,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(transformed,
                   testcase.plaintext,
                   testcase.plaintext_len);
    }
}

static void test_inplace_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t transformed[VECS_MAX_AEAD_PLAINTEXT_LEN];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_bytes = 0;
    bool is_valid;

    while (1)
    {
        errcode = vecs_aead_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_ctr(testcase.count);
        atto_eq(errcode, VECS_OK);
        atto_eq(testcase.plaintext_len, testcase.ciphertext_len);

        // Encrypt
        memcpy(transformed, testcase.plaintext, testcase.plaintext_len);
        ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
        for (size_t i = 0; i < testcase.assoc_data_len; i++)
        {
            ascon_aead128_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                            1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
        }
        for (size_t i = 0; i < testcase.plaintext_len; i++)
        {
            new_bytes = ascon_aead128_encrypt_update(
                    &aead_ctx,
                    transformed +
                    aead_ctx.bufstate.total_output_len,
                    &transformed[i],
                    1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
            if (aead_ctx.bufstate.buffer_len == 0)
            {
                atto_eq(new_bytes, ASCON_RATE);
            }
            else
            {
                atto_eq(new_bytes, 0);
            }
        }
        uint64_t total_ct_len = 0;
        new_bytes = ascon_aead128_encrypt_final(&aead_ctx,
                                                transformed
                                                +
                                                aead_ctx.bufstate.total_output_len,
                                                &total_ct_len, obtained_tag,
                                                sizeof(testcase.tag));
        atto_lt(new_bytes, ASCON_RATE);
        atto_eq(new_bytes, testcase.ciphertext_len % ASCON_RATE);
        atto_eq(total_ct_len, testcase.ciphertext_len);
        vecs_aead_enc_log(&testcase, transformed, obtained_tag,
                          testcase.ciphertext_len);
        atto_memeq(transformed,
                   testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

        // Decrypt
        ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
        for (size_t i = 0; i < testcase.assoc_data_len; i++)
        {
            ascon_aead128_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                            1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
        }
        for (size_t i = 0; i < testcase.ciphertext_len; i++)
        {
            new_bytes = ascon_aead128_decrypt_update(&aead_ctx,
                                                     transformed +
                                                     aead_ctx.bufstate.total_output_len,
                                                     &transformed[i],
                                                     1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
            if (aead_ctx.bufstate.buffer_len == 0)
            {
                atto_eq(new_bytes, ASCON_RATE);
            }
            else
            {
                atto_eq(new_bytes, 0);
            }
        }
        uint64_t total_pt_len = 0;
        new_bytes = ascon_aead128_decrypt_final(&aead_ctx,
                                                transformed +
                                                aead_ctx.bufstate.total_output_len,
                                                &total_pt_len,
                                                &is_valid, testcase.tag,
                                                sizeof(testcase.tag));
        atto_lt(new_bytes, ASCON_RATE);
        atto_eq(new_bytes, testcase.plaintext_len % ASCON_RATE);
        atto_eq(total_pt_len, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, transformed, testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(transformed,
                   testcase.plaintext,
                   testcase.plaintext_len);
    }
}

void test_aead128_inplace(void)
{
    test_inplace_offline();
    test_inplace_update_single_byte();
}
