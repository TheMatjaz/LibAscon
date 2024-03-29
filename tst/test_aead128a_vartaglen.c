/**
 * @file
 * Tests of the AEAD128a encryption/decryption with variable tag length.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define AEAD_VECTORS_FILE "vectors/aead128a.txt"
#define KEY_LEN ASCON_AEAD128a_KEY_LEN

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
    uint8_t obtained_ciphertext[1];
    const uint8_t expected_tag[TAG_MAX_LEN] = {
            0x7A, 0x83, 0x4E, 0x6F, 0x09, 0x21, 0x09, 0x57,
            0x06, 0x7B, 0x10, 0xFD, 0x83, 0x1F, 0x00, 0x78,
            0x22, 0x0B, 0xEF, 0x41, 0x11, 0xA3, 0x25, 0xC7,
            0xCA, 0xE8, 0x35, 0xA3, 0x02, 0xA6, 0x66, 0x0E,
            0xC7, 0x54, 0x77, 0x00, 0xDD, 0x74, 0x9C, 0xA7,
            0x76, 0x47, 0xF6, 0x8C, 0x53, 0x05, 0xA9, 0x25,
            0x03, 0x69, 0x30, 0xB7, 0x7E, 0x35, 0x87, 0x9F,
            0xED, 0x94, 0x11, 0x35, 0x80, 0x01, 0xE8, 0x74
    };
    uint8_t obtained_tag[TAG_MAX_LEN] = {0};

    // Offline
    memset(obtained_ciphertext, 0, sizeof(obtained_ciphertext));
    for (size_t tag_len = 0; tag_len <= TAG_MAX_LEN; tag_len++)
    {
        memset(obtained_tag, 0, sizeof(obtained_tag));
        ascon_aead128a_encrypt(obtained_ciphertext,
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
            ascon_aead128a_encrypt(obtained_ciphertext,
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
            0x7A, 0x83, 0x4E, 0x6F, 0x09, 0x21, 0x09, 0x57,
            0x06, 0x7B, 0x10, 0xFD, 0x83, 0x1F, 0x00, 0x78,
            0x22, 0x0B, 0xEF, 0x41, 0x11, 0xA3, 0x25, 0xC7,
            0xCA, 0xE8, 0x35, 0xA3, 0x02, 0xA6, 0x66, 0x0E,
            0xC7, 0x54, 0x77, 0x00, 0xDD, 0x74, 0x9C, 0xA7,
            0x76, 0x47, 0xF6, 0x8C, 0x53, 0x05, 0xA9, 0x25,
            0x03, 0x69, 0x30, 0xB7, 0x7E, 0x35, 0x87, 0x9F,
            0xED, 0x94, 0x11, 0x35, 0x80, 0x01, 0xE8, 0x74
    };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[1];
    bool is_valid;

    // Offline
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    for (size_t tag_len = 0; tag_len <= TAG_MAX_LEN; tag_len++)
    {
        is_valid = ascon_aead128a_decrypt(
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
            const bool is_valid = ascon_aead128a_decrypt(
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

void test_aead128a_vartaglen(void)
{
    puts("Testing Ascon-128a en/decryption with variable tag length...");
    test_encrypt_empty();
    test_encrypt_offline();
    test_decrypt_empty();
    test_decrypt_offline();
}
