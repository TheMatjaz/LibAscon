/**
 * @file
 * Tests of the AEAD80pq encryption/decryption with variable tag length.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define AEAD_VECTORS_FILE "vectors/aead80pq.txt"
#define KEY_LEN ASCON_AEAD80pq_KEY_LEN

#define TAG_MAX_LEN 64U

static void test_encrypt_empty(void)
{
    vecs_aead_t testcase =
            {
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x10, 0x11, 0x12, 0x13
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
    uint8_t obtained_ciphertext[1];
    const uint8_t expected_tag[TAG_MAX_LEN] = {
            0xAB, 0xB6, 0x88, 0xEF, 0xA0, 0xB9, 0xD5, 0x6B,
            0x33, 0x27, 0x7A, 0x2C, 0x97, 0xD2, 0x14, 0x6B,
            0x35, 0x02, 0xA1, 0x5F, 0xD3, 0x7F, 0x18, 0xE1,
            0xE0, 0x12, 0x9C, 0xD0, 0x81, 0x62, 0x33, 0xE7,
            0x57, 0x5B, 0x9D, 0xB9, 0x4D, 0xD1, 0xE9, 0x19,
            0xA6, 0x5E, 0xE0, 0x2B, 0xF3, 0x45, 0x6E, 0xBA,
            0x21, 0x34, 0x3E, 0x5F, 0xF4, 0x4B, 0x58, 0x50,
            0x9D, 0x09, 0xA7, 0xB2, 0xCA, 0xB0, 0xC5, 0xCB
    };
    uint8_t obtained_tag[TAG_MAX_LEN] = {0};
    // Offline
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    for (size_t tag_len = TAG_MAX_LEN; tag_len <= TAG_MAX_LEN; tag_len++)
    {
        memset(obtained_tag, 0, sizeof(obtained_tag));
        ascon_aead80pq_encrypt(obtained_ciphertext,
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
        for (size_t tag_len = 0; tag_len < sizeof(testcase.tag); tag_len++)
        {
            memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
            memset(obtained_tag, 0, sizeof(obtained_tag));
            ascon_aead80pq_encrypt(obtained_ciphertext,
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
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x10, 0x11, 0x12, 0x13
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
            0xAB, 0xB6, 0x88, 0xEF, 0xA0, 0xB9, 0xD5, 0x6B,
            0x33, 0x27, 0x7A, 0x2C, 0x97, 0xD2, 0x14, 0x6B,
            0x35, 0x02, 0xA1, 0x5F, 0xD3, 0x7F, 0x18, 0xE1,
            0xE0, 0x12, 0x9C, 0xD0, 0x81, 0x62, 0x33, 0xE7,
            0x57, 0x5B, 0x9D, 0xB9, 0x4D, 0xD1, 0xE9, 0x19,
            0xA6, 0x5E, 0xE0, 0x2B, 0xF3, 0x45, 0x6E, 0xBA,
            0x21, 0x34, 0x3E, 0x5F, 0xF4, 0x4B, 0x58, 0x50,
            0x9D, 0x09, 0xA7, 0xB2, 0xCA, 0xB0, 0xC5, 0xCB
    };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[1];
    bool is_valid;

    // Offline
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    for (size_t tag_len = 0; tag_len <= TAG_MAX_LEN; tag_len++)
    {
        is_valid = ascon_aead80pq_decrypt(
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
        for (size_t tag_len = 0; tag_len < sizeof(testcase.tag); tag_len++)
        {
            memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
            const bool is_valid = ascon_aead80pq_decrypt(
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

void test_aead80pq_vartaglen(void)
{
    test_encrypt_empty();
    test_encrypt_offline();
    test_decrypt_empty();
    test_decrypt_offline();
}
