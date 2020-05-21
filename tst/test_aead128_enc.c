/**
 * @file
 * Tests of the AEAD128 encryption.
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

static void test_aead_cleanup(void)
{
    ascon_aead_ctx_t ctx = {.k0 = 42};
    ascon_aead128_cleanup(&ctx);
    atto_zeros(&ctx, sizeof(ascon_aead_ctx_t));
}

static void test_encrypt_empty(void)
{
    vecs_aead_t testcase =
            {
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .nonce = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .plaintext_len = 0,
                    .assoc_data_len = 0,
                    .tag = {
                            0xE3, 0x55, 0x15, 0x9F, 0x29, 0x29, 0x11, 0xF7,
                            0x94, 0xCB, 0x14, 0x32, 0xA0, 0x10, 0x3A, 0x8A
                    },
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_ciphertext[1];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN] = {0};
    ascon_aead_ctx_t aead_ctx;

    // Offline
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_encrypt(obtained_ciphertext,
                          obtained_tag,
                          testcase.key,
                          testcase.nonce,
                          testcase.assoc_data,
                          testcase.plaintext,
                          testcase.assoc_data_len,
                          testcase.plaintext_len,
                          sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_memeq(obtained_ciphertext, testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, &testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    // Without any update call at all
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    atto_eq(aead_ctx.bufstate.buffer_len, 0);
    size_t new_ct_len = ascon_aead128_encrypt_final(&aead_ctx,
                                                    obtained_ciphertext,
                                                    obtained_tag,
                                                    sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_memeq(obtained_ciphertext,
               testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, &testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    // With AD update calls of zero length
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, obtained_ciphertext, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_memeq(obtained_ciphertext,
               testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    // With PT update calls of zero length
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, NULL,
                                              obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, NULL,
                                              obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                              obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_memeq(obtained_ciphertext, testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    // With AD and PT update calls of zero length
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, obtained_ciphertext, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, NULL,
                                              obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, NULL,
                                              obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                              obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_memeq(obtained_ciphertext, testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
}


static void test_encrypt_1_byte_ad_empty_pt(void)
{
    vecs_aead_t testcase =
            {
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .nonce = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .plaintext_len = 0,
                    .assoc_data = {0x00},
                    .assoc_data_len = 1,
                    .tag = {
                            0x94, 0x4D, 0xF8, 0x87, 0xCD, 0x49, 0x01, 0x61,
                            0x4C, 0x5D, 0xED, 0xBC, 0x42, 0xFC, 0x0D, 0xA0
                    },
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_ciphertext[1];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_len;

    // Without PT call
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_memeq(obtained_ciphertext, testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    // With PT call
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                              testcase.plaintext,
                                              testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(testcase.tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_memeq(obtained_ciphertext,
               testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
}

static void test_encrypt_1_byte_pt_empty_ad(void)
{
    vecs_aead_t testcase =
            {
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .nonce = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .plaintext = {0x00},
                    .plaintext_len = 1,
                    .assoc_data_len = 0,
                    .ciphertext = {0xBC},
                    .tag = {
                            0x18, 0xC3, 0xF4, 0xE3, 0x9E, 0xCA, 0x72, 0x22,
                            0x49, 0x0D, 0x96, 0x7C, 0x79, 0xBF, 0xFC, 0x92
                    },
                    .ciphertext_len = 1,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_ciphertext[testcase.ciphertext_len * 2];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_len;

    // Without AD update call
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                              testcase.plaintext,
                                              testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 1);
    atto_memeq(obtained_ciphertext,
               testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);

    // With AD call
    testcase.ciphertext_len = 0;
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                              testcase.plaintext,
                                              testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 1);
    atto_memeq(obtained_ciphertext,
               testcase.ciphertext,
               testcase.ciphertext_len);
    atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
}

static void test_encrypt_1_byte_pt_1_byte_ad(void)
{
    vecs_aead_t testcase =
            {
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .nonce = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .plaintext = {0x00},
                    .plaintext_len = 1,
                    .assoc_data = {0x00},
                    .assoc_data_len = 1,
                    .ciphertext = {0xBD},
                    .ciphertext_len = 1,
                    .tag = {
                            0x41, 0x02, 0xB7, 0x07, 0x77, 0x5C, 0x3C, 0x15,
                            0x5A, 0xE4, 0x97, 0xB4, 0x3B, 0xF8, 0x34, 0xE5
                    },
            };
    atto_eq(testcase.plaintext_len, testcase.ciphertext_len);
    uint8_t obtained_ciphertext[testcase.ciphertext_len * 2];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_len;

    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    memset(obtained_tag, 0, sizeof(obtained_tag));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_ct_len = ascon_aead128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                              testcase.plaintext,
                                              testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon_aead128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                             obtained_tag,
                                             sizeof(obtained_tag));
    vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                      testcase.ciphertext_len);
    atto_eq(new_ct_len, 1);
    atto_memeq(obtained_ciphertext,
               testcase.ciphertext,
               testcase.ciphertext_len);
}

static void test_encrypt_offline(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[VECS_MAX_AEAD_CIPHERTEXT_LEN];
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
        memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
        memset(obtained_tag, 0, sizeof(obtained_tag));
        ascon_aead128_encrypt(obtained_ciphertext,
                              obtained_tag,
                              testcase.key,
                              testcase.nonce,
                              testcase.assoc_data,
                              testcase.plaintext,
                              testcase.assoc_data_len,
                              testcase.plaintext_len,
                              sizeof(testcase.tag));
        vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                          testcase.ciphertext_len);
        atto_memeq(obtained_ciphertext,
                   testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    }
}

static void test_encrypt_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[VECS_MAX_AEAD_CIPHERTEXT_LEN];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_bytes = 0;
    size_t total_ct_bytes = 0;

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
        memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
        memset(obtained_tag, 0, sizeof(obtained_tag));
        total_ct_bytes = 0;
        // Many 1-byte update calls
        ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
        for (size_t i = 0; i < testcase.assoc_data_len; i++)
        {
            ascon_aead128_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                            1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
        }
        for (size_t i = 0; i < testcase.plaintext_len; i++)
        {
            new_ct_bytes = ascon_aead128_encrypt_update(
                    &aead_ctx,
                    obtained_ciphertext + total_ct_bytes,
                    &testcase.plaintext[i],
                    1);
            total_ct_bytes += new_ct_bytes;
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
            if (aead_ctx.bufstate.buffer_len == 0)
            {
                atto_eq(new_ct_bytes, ASCON_RATE);
            }
            else
            {
                atto_eq(new_ct_bytes, 0);
            }
        }
        new_ct_bytes = ascon_aead128_encrypt_final(
                &aead_ctx,
                obtained_ciphertext + total_ct_bytes,
                obtained_tag, sizeof(obtained_tag));
        total_ct_bytes += new_ct_bytes;
        atto_lt(new_ct_bytes, ASCON_RATE);
        atto_eq(new_ct_bytes, testcase.ciphertext_len % ASCON_RATE);
        atto_eq(total_ct_bytes, testcase.ciphertext_len);
        vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                          testcase.ciphertext_len);
        atto_memeq(obtained_ciphertext,
                   testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    }
}

static void test_encrypt_update_three_bytes(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[VECS_MAX_AEAD_CIPHERTEXT_LEN];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_bytes = 0;
    size_t total_ct_bytes = 0;

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
        memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
        memset(obtained_tag, 0, sizeof(obtained_tag));
        total_ct_bytes = 0;
        // Many 3-byte update calls
        ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
        size_t remaining;
        size_t step;
        size_t i = 0;
        remaining = testcase.assoc_data_len;
        while (remaining)
        {
            step = MIN(remaining, 3);
            ascon_aead128_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                            step);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            remaining -= step;
            i += step;
        }
        i = 0;
        size_t previous_buffer_len = 0;
        remaining = testcase.plaintext_len;
        while (remaining)
        {
            step = MIN(remaining, 3);
            new_ct_bytes = ascon_aead128_encrypt_update(
                    &aead_ctx,
                    obtained_ciphertext + total_ct_bytes,
                    &testcase.plaintext[i],
                    step);
            total_ct_bytes += new_ct_bytes;
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            if (aead_ctx.bufstate.buffer_len < previous_buffer_len)
            {
                atto_eq(new_ct_bytes, ASCON_RATE);
            }
            else
            {
                atto_eq(new_ct_bytes, 0);
            }
            previous_buffer_len = aead_ctx.bufstate.buffer_len;
            remaining -= step;
            i += step;
        }
        new_ct_bytes = ascon_aead128_encrypt_final(
                &aead_ctx,
                obtained_ciphertext + total_ct_bytes,
                obtained_tag, sizeof(obtained_tag));
        total_ct_bytes += new_ct_bytes;
        atto_lt(new_ct_bytes, ASCON_RATE);
        atto_eq(new_ct_bytes, testcase.ciphertext_len % ASCON_RATE);
        atto_eq(total_ct_bytes, testcase.ciphertext_len);
        vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                          testcase.ciphertext_len);
        atto_memeq(obtained_ciphertext,
                   testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    }
}

static void test_encrypt_update_var_bytes(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[VECS_MAX_AEAD_CIPHERTEXT_LEN];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_bytes = 0;
    uint64_t total_ct_len = 0;

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
        memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
        memset(obtained_tag, 0, sizeof(obtained_tag));
        total_ct_len = 0;
        // Many increasingly-larger update calls
        ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
        size_t remaining;
        size_t step = 1;
        size_t i = 0;
        remaining = testcase.assoc_data_len;
        while (remaining)
        {
            step = MIN(remaining, step + 1);
            ascon_aead128_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                            step);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            remaining -= step;
            i += step;
        }
        i = 0;
        total_ct_len = 0;
        remaining = testcase.plaintext_len;
        while (remaining)
        {
            step = MIN(remaining, step + 1);
            new_ct_bytes = ascon_aead128_encrypt_update(
                    &aead_ctx,
                    obtained_ciphertext + total_ct_len,
                    &testcase.plaintext[i],
                    step);
            total_ct_len += new_ct_bytes;
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            if (step > ASCON_RATE)
            {
                atto_ge(new_ct_bytes, ASCON_RATE);
            }
            remaining -= step;
            i += step;
        }
        new_ct_bytes = ascon_aead128_encrypt_final(
                &aead_ctx,
                obtained_ciphertext + total_ct_len,
                obtained_tag, sizeof(obtained_tag));
        total_ct_len += new_ct_bytes;
        atto_lt(new_ct_bytes, ASCON_RATE);
        atto_eq(new_ct_bytes, testcase.ciphertext_len % ASCON_RATE);
        atto_eq(total_ct_len, testcase.ciphertext_len);
        vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                          testcase.ciphertext_len);
        atto_memeq(obtained_ciphertext,
                   testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, testcase.tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    }
}

void test_aead128_encryption(void)
{
    test_aead_cleanup();
    test_encrypt_empty();
    test_encrypt_1_byte_ad_empty_pt();
    test_encrypt_1_byte_pt_empty_ad();
    test_encrypt_1_byte_pt_1_byte_ad();
    test_encrypt_offline();
    test_encrypt_update_single_byte();
    test_encrypt_update_three_bytes();
    test_encrypt_update_var_bytes();
}
