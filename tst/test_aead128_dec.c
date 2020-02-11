/**
 * @file
 * Tests of the AEAD128 decryption.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define AEAD_VECTORS_FILE "vectors/aead128.txt"

static void test_decrypt_empty(void)
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
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    ascon_tag_validity_t validity;

    // Offline
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    validity = ascon_aead128_decrypt(
            obtained_plaintext,
            testcase.key,
            testcase.nonce,
            testcase.assoc_data,
            testcase.ciphertext,
            testcase.tag,
            testcase.assoc_data_len,
            testcase.ciphertext_len);
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(validity, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);

    // Without any update call at all
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    atto_eq(aead_ctx.bufstate.buffer_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx,
                                             obtained_plaintext,
                                             &plaintext_len,
                                             &validity,
                                             testcase.tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With AD update calls of zero length
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, obtained_plaintext, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With PT update calls of zero length
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, NULL,
                                              obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, NULL,
                                              obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, obtained_plaintext,
                                              obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With AD and PT update calls of zero length
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, obtained_plaintext, 0);
    ascon_aead128_assoc_data_update(&aead_ctx, NULL, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, NULL,
                                              obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, NULL,
                                              obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, obtained_plaintext,
                                              obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}


static void test_decrypt_1_byte_ad_empty_pt(void)
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
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    ascon_tag_validity_t validity;

    // Without PT call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With PT call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, obtained_plaintext,
                                              testcase.ciphertext,
                                              testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}

static void test_decrypt_1_byte_pt_empty_ad(void)
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
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    ascon_tag_validity_t validity;

    // Without AD update call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, obtained_plaintext,
                                              testcase.ciphertext,
                                              testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity,
                                             testcase.tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With AD call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, obtained_plaintext,
                                              testcase.ciphertext,
                                              testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}

static void test_decrypt_1_byte_pt_1_byte_ad(void)
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
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    ascon_tag_validity_t validity;

    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                    testcase.assoc_data_len);
    new_pt_len = ascon_aead128_decrypt_update(&aead_ctx, obtained_plaintext,
                                              testcase.ciphertext,
                                              testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128_decrypt_final(&aead_ctx, obtained_plaintext,
                                             &plaintext_len, &validity, testcase
                                                     .tag);
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(validity, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}

static void test_decrypt_offline(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE);
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
        memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
        const ascon_tag_validity_t validity = ascon_aead128_decrypt(
                obtained_plaintext,
                testcase.key,
                testcase.nonce,
                testcase.assoc_data,
                testcase.ciphertext,
                testcase.tag,
                testcase.assoc_data_len,
                testcase.ciphertext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(validity, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
    }
}

static void test_decrypt_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_bytes = 0;
    ascon_tag_validity_t validity;

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
        memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
        // Many 1-byte update calls
        ascon_aead128_init(&aead_ctx, testcase.key, testcase.nonce);
        for (size_t i = 0; i < testcase.assoc_data_len; i++)
        {
            ascon_aead128_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                            1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
        }
        for (size_t i = 0; i < testcase.ciphertext_len; i++)
        {
            new_pt_bytes = ascon_aead128_decrypt_update(
                    &aead_ctx,
                    obtained_plaintext +
                    aead_ctx.bufstate.total_output_len,
                    &testcase.ciphertext[i],
                    1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
            if (aead_ctx.bufstate.buffer_len == 0)
            {
                atto_eq(new_pt_bytes, ASCON_RATE);
            }
            else
            {
                atto_eq(new_pt_bytes, 0);
            }
        }
        uint64_t total_pt_len = 0;
        new_pt_bytes = ascon_aead128_decrypt_final(&aead_ctx,
                                                   obtained_plaintext +
                                                   aead_ctx.bufstate.total_output_len,
                                                   &total_pt_len,
                                                   &validity, testcase.tag);
        atto_lt(new_pt_bytes, ASCON_RATE);
        atto_eq(new_pt_bytes, testcase.plaintext_len % ASCON_RATE);
        atto_eq(total_pt_len, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(validity, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
    }
}


static void test_decrypt_offline_with_corrupted_data(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE);
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
        memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
        if (testcase.assoc_data_len == 0
            && testcase.ciphertext_len == 0)
        {
            // Skip test where there is nothing to corrupt.
            continue;
        }
        if (testcase.assoc_data_len > 0)
        {
            // Corrupt associated data
            testcase.assoc_data[0]++;
        }
        if (testcase.ciphertext_len > 0)
        {
            // Corrupt ciphertext
            testcase.ciphertext[0]++;
        }
        const ascon_tag_validity_t validity = ascon_aead128_decrypt(
                obtained_plaintext,
                testcase.key,
                testcase.nonce,
                testcase.assoc_data,
                testcase.ciphertext,
                testcase.tag,
                testcase.assoc_data_len,
                testcase.ciphertext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_neq(validity, ASCON_TAG_OK);
        if (testcase.plaintext_len > 0)
        {
            atto_memneq(obtained_plaintext,
                        testcase.plaintext,
                        testcase.plaintext_len);
        }
    }
}

void test_aead128_decryption(void)
{
    test_decrypt_empty();
    test_decrypt_1_byte_ad_empty_pt();
    test_decrypt_1_byte_pt_empty_ad();
    test_decrypt_1_byte_pt_1_byte_ad();
    test_decrypt_offline();
    test_decrypt_update_single_byte();
    test_decrypt_offline_with_corrupted_data();
}
