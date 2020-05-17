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

#define TAG_MAX_LEN 64U

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
                    .tag = {0}, // Not used in this test
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_ciphertext[testcase.ciphertext_len * 2];
    const uint8_t expected_tag[TAG_MAX_LEN] = {
            0xE3, 0x55, 0x15, 0x9F, 0x29, 0x29, 0x11, 0xF7,
            0x94, 0xCB, 0x14, 0x32, 0xA0, 0x10, 0x3A, 0x8A,
            0x65, 0xCF, 0x99, 0x43, 0x70, 0xC2, 0xE3, 0xB8,
            0x98, 0xD8, 0x04, 0xD6, 0x3C, 0x22, 0xD3, 0xB4,
            0x8D, 0xF7, 0x82, 0xC0, 0x74, 0xC5, 0xD8, 0x0D,
            0xF8, 0x9F, 0x64, 0xAA, 0xBD, 0xE5, 0x29, 0x51,
            0x50, 0x61, 0x01, 0x99, 0x63, 0xCC, 0x71, 0x59,
            0xE9, 0x35, 0x6F, 0x7D, 0x44, 0x12, 0x65, 0xD9
    };
    uint8_t obtained_tag[TAG_MAX_LEN] = {0};

    // Offline
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    for (size_t tag_len = 0; tag_len <= TAG_MAX_LEN; tag_len++)
    {
        memset(obtained_tag, 0, sizeof(obtained_tag));
        ascon_aead128_encrypt(obtained_ciphertext,
                              obtained_tag,
                              testcase.key,
                              testcase.nonce,
                              testcase.assoc_data,
                              testcase.plaintext,
                              testcase.assoc_data_len,
                              testcase.plaintext_len,
                              tag_len);
        vecs_log_hexbytes("Tag", obtained_tag, tag_len);
        atto_memeq(obtained_ciphertext, testcase.ciphertext,
                   testcase.ciphertext_len);
        atto_memeq(obtained_tag, expected_tag, tag_len);
    }
}

static void test_encrypt_offline(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[VECS_MAX_AEAD_CIPHERTEXT_LEN];
    uint8_t obtained_tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
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
        for (size_t tag_len = 0; tag_len < sizeof(testcase.tag); tag_len++)
        {
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
                                  tag_len);
            vecs_aead_enc_log(&testcase, obtained_ciphertext, obtained_tag,
                              testcase.ciphertext_len);
            atto_memeq(obtained_ciphertext,
                       testcase.ciphertext,
                       testcase.ciphertext_len);
            atto_memeq(obtained_tag, testcase.tag, tag_len);
        }
    }
}

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
                    .tag = {0}, // Not used in this test
                    .ciphertext_len = 0,
            };
    const uint8_t correct_tag[TAG_MAX_LEN] = {
            0xE3, 0x55, 0x15, 0x9F, 0x29, 0x29, 0x11, 0xF7,
            0x94, 0xCB, 0x14, 0x32, 0xA0, 0x10, 0x3A, 0x8A,
            0x65, 0xCF, 0x99, 0x43, 0x70, 0xC2, 0xE3, 0xB8,
            0x98, 0xD8, 0x04, 0xD6, 0x3C, 0x22, 0xD3, 0xB4,
            0x8D, 0xF7, 0x82, 0xC0, 0x74, 0xC5, 0xD8, 0x0D,
            0xF8, 0x9F, 0x64, 0xAA, 0xBD, 0xE5, 0x29, 0x51,
            0x50, 0x61, 0x01, 0x99, 0x63, 0xCC, 0x71, 0x59,
            0xE9, 0x35, 0x6F, 0x7D, 0x44, 0x12, 0x65, 0xD9
    };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    bool is_valid;

    // Offline
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    for (size_t tag_len = 0; tag_len <= TAG_MAX_LEN; tag_len++)
    {
        is_valid = ascon_aead128_decrypt(
                obtained_plaintext,
                testcase.key,
                testcase.nonce,
                testcase.assoc_data,
                testcase.ciphertext,
                correct_tag,
                testcase.assoc_data_len,
                testcase.ciphertext_len,
                tag_len);
        vecs_log_hexbytes("Tag", correct_tag, tag_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext, testcase.plaintext,
                   testcase.plaintext_len);
    }
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
        for (size_t tag_len = 0; tag_len < sizeof(testcase.tag); tag_len++)
        {
            memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
            const bool is_valid = ascon_aead128_decrypt(
                    obtained_plaintext,
                    testcase.key,
                    testcase.nonce,
                    testcase.assoc_data,
                    testcase.ciphertext,
                    testcase.tag,
                    testcase.assoc_data_len,
                    testcase.ciphertext_len,
                    tag_len);
            vecs_aead_dec_log(&testcase, obtained_plaintext,
                              testcase.plaintext_len);
            atto_eq(is_valid, ASCON_TAG_OK);
            atto_memeq(obtained_plaintext,
                       testcase.plaintext,
                       testcase.plaintext_len);
        }
    }
}

void test_aead128_vartaglen(void)
{
    test_encrypt_empty();
    test_encrypt_offline();
    test_decrypt_empty();
    test_decrypt_offline();
}
