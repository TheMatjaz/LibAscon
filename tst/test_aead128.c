/**
 * @file
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define AEAD_VECTORS_FILE "vectors/aead128.txt"

// TODO add all tests, with/out AD, with/out PL, encryption and decryption

static void test_aead_empty(void)
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
                    .expected_tag = {
                            0xE3, 0x55, 0x15, 0x9F, 0x29, 0x29, 0x11, 0xF7,
                            0x94, 0xCB, 0x14, 0x32, 0xA0, 0x10, 0x3A, 0x8A
                    },
                    .expected_ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.expected_ciphertext_len);
    uint8_t obtained_ciphertext[testcase.expected_ciphertext_len * 2];
    uint8_t obtained_tag[ASCON_AEAD_TAG_SIZE];
    uint64_t ciphertext_len = 0;
    ascon_aead_ctx_t aead_ctx;

    // Batched
    ascon128_encrypt(obtained_ciphertext,
                     obtained_tag,
                     testcase.plaintext, testcase.assoc_data,
                     testcase.nonce, testcase.key,
                     testcase.plaintext_len, testcase.assoc_data_len);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_memeq(obtained_ciphertext, testcase.expected_ciphertext,
               testcase.expected_ciphertext_len);
    atto_memeq(obtained_tag, &testcase.expected_tag, ASCON_AEAD_TAG_SIZE);
    ciphertext_len = 0;

    // Without any update call at all
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    atto_eq(aead_ctx.buffer_len, 0);
    ascon128_assoc_data_final(&aead_ctx);
    size_t new_ct_len = ascon128_encrypt_final(&aead_ctx,
                                               obtained_ciphertext,
                                               &ciphertext_len,
                                               obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, &testcase.expected_tag, ASCON_AEAD_TAG_SIZE);


    // With AD update calls of zero length
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon128_assoc_data_update(&aead_ctx, obtained_ciphertext, 0);
    ascon128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);

    // With PT update calls of zero length
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, NULL,
                                         obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, NULL,
                                         obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                         obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext, testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);

    // With AD and PT update calls of zero length
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon128_assoc_data_update(&aead_ctx, obtained_ciphertext, 0);
    ascon128_assoc_data_update(&aead_ctx, NULL, 0);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, NULL,
                                         obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, NULL,
                                         obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                         obtained_ciphertext, 0);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext, testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);
}


static void test_aead_1_byte_ad_empty_pt(void)
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
                    .expected_tag = {
                            0x94, 0x4D, 0xF8, 0x87, 0xCD, 0x49, 0x01, 0x61,
                            0x4C, 0x5D, 0xED, 0xBC, 0x42, 0xFC, 0x0D, 0xA0
                    },
                    .expected_ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.expected_ciphertext_len);
    uint8_t obtained_ciphertext[testcase.expected_ciphertext_len * 2];
    uint8_t obtained_tag[ASCON_AEAD_TAG_SIZE];
    uint64_t ciphertext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_len;

    // Without PT call
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                               testcase.assoc_data_len);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext, testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);

    // With PT call
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                               testcase.assoc_data_len);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                         testcase.plaintext,
                                         testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);
}


static void test_aead_1_byte_pt_empty_ad(void)
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
                    .expected_ciphertext = {0xBC},
                    .expected_tag = {
                            0x18, 0xC3, 0xF4, 0xE3, 0x9E, 0xCA, 0x72, 0x22,
                            0x49, 0x0D, 0x96, 0x7C, 0x79, 0xBF, 0xFC, 0x92
                    },
                    .expected_ciphertext_len = 1,
            };
    atto_eq(testcase.plaintext_len,
            testcase.expected_ciphertext_len);
    uint8_t obtained_ciphertext[testcase.expected_ciphertext_len * 2];
    uint8_t obtained_tag[ASCON_AEAD_TAG_SIZE];
    uint64_t ciphertext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_len;

    // Without AD update call
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                         testcase.plaintext,
                                         testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);

    // With AD call
    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                               testcase.assoc_data_len);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                         testcase.plaintext,
                                         testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
    atto_memeq(obtained_tag, testcase.expected_tag, ASCON_AEAD_TAG_SIZE);
}


static void test_aead_1_byte_pt_1_byte_ad(void)
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
                    .expected_ciphertext = {0xBD},
                    .expected_ciphertext_len = 1,
                    .expected_tag = {
                            0x41, 0x02, 0xB7, 0x07, 0x77, 0x5C, 0x3C, 0x15,
                            0x5A, 0xE4, 0x97, 0xB4, 0x3B, 0xF8, 0x34, 0xE5
                    },
            };
    atto_eq(testcase.plaintext_len, testcase.expected_ciphertext_len);
    uint8_t obtained_ciphertext[testcase.expected_ciphertext_len * 2];
    uint8_t obtained_tag[ASCON_AEAD_TAG_SIZE];
    uint64_t ciphertext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_ct_len;

    ascon128_init(&aead_ctx, testcase.nonce, testcase.key);
    ascon128_assoc_data_update(&aead_ctx, testcase.assoc_data,
                               testcase.assoc_data_len);
    ascon128_assoc_data_final(&aead_ctx);
    new_ct_len = ascon128_encrypt_update(&aead_ctx, obtained_ciphertext,
                                         testcase.plaintext,
                                         testcase.plaintext_len);
    atto_eq(new_ct_len, 0);
    new_ct_len = ascon128_encrypt_final(&aead_ctx, obtained_ciphertext,
                                        &ciphertext_len, obtained_tag);
    vecs_aead_log(&testcase, obtained_ciphertext, ciphertext_len);
    atto_eq(new_ct_len, 0);
    atto_eq(ciphertext_len, testcase.expected_ciphertext_len);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}

/*

static void test_aead_1_byte(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 1,
                    .plaintext = {0},
                    .expected_ciphertext = {
                            0x8D, 0xD4, 0x46, 0xAD, 0xA5, 0x8A, 0x77, 0x40,
                            0xEC, 0xF5, 0x6E, 0xB6, 0x38, 0xEF, 0x77, 0x5F,
                            0x7D, 0x5C, 0x0F, 0xD5, 0xF0, 0xC2, 0xBB, 0xBD,
                            0xFD, 0xEC, 0x29, 0x60, 0x9D, 0x3C, 0x43, 0xA2
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, 1);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}


static void test_aead_2_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 2,
                    .plaintext = {0x00, 0x01},
                    .expected_ciphertext = {
                            0xF7, 0x7C, 0xA1, 0x3B, 0xF8, 0x91, 0x46, 0xD3,
                            0x25, 0x4F, 0x1C, 0xFB, 0x7E, 0xDD, 0xBA, 0x8F,
                            0xA1, 0xBF, 0x16, 0x22, 0x84, 0xBB, 0x29, 0xE7,
                            0xF6, 0x45, 0x54, 0x5C, 0xF9, 0xE0, 0x84, 0x24
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[0], 1);
    atto_eq(aead_ctx.buffer_len, 1);
    ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[1], 1);
    atto_eq(aead_ctx.buffer_len, 2);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}

static void test_aead_7_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 7,
                    .plaintext = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
                    .expected_ciphertext = {
                            0xDD, 0x40, 0x9C, 0xCC, 0x0C, 0x60, 0xCD, 0x7F,
                            0x47, 0x4C, 0x0B, 0xEE, 0xD1, 0xE1, 0xCD, 0x48,
                            0x14, 0x0A, 0xD4, 0x5D, 0x51, 0x36, 0xDC, 0x5F,
                            0xDA, 0x5E, 0xBE, 0x28, 0x3D, 0xF8, 0xD3, 0xF6
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    for (size_t i = 0; i < testcase.plaintext_len; i++)
    {
        ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
        atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}


static void test_aead_8_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 8,
                    .plaintext = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                    },
                    .expected_ciphertext = {
                            0xF4, 0xC6, 0xA4, 0x4B, 0x29, 0x91, 0x5D, 0x3D,
                            0x57, 0xCF, 0x92, 0x8A, 0x18, 0xEC, 0x62, 0x26,
                            0xBB, 0x8D, 0xD6, 0xC1, 0x13, 0x6A, 0xCD, 0x24,
                            0x96, 0x5F, 0x7E, 0x77, 0x80, 0xCD, 0x69, 0xCF
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, 0);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    for (size_t i = 0; i < testcase.plaintext_len; i++)
    {
        ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
        atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}

static void test_aead_9_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 9,
                    .plaintext = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08
                    },
                    .expected_ciphertext = {
                            0x1E, 0x1E, 0x71, 0x0D, 0x08, 0xA7, 0x82, 0x63,
                            0x77, 0x33, 0x31, 0x78, 0x26, 0x21, 0x08, 0x8C,
                            0xA9, 0xFE, 0x2E, 0xE4, 0xF5, 0x96, 0xF0, 0x6C,
                            0x8F, 0x78, 0x84, 0xCA, 0x56, 0x4A, 0xCE, 0xC1
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    for (size_t i = 0; i < testcase.plaintext_len; i++)
    {
        ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
        atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}

static void test_aead_15_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 15,
                    .plaintext = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
                    },
                    .expected_ciphertext = {
                            0x9E, 0x48, 0xE0, 0x3E, 0x8A, 0xAE, 0x0B, 0x99,
                            0x30, 0xDF, 0xF1, 0xE8, 0x01, 0x00, 0x7B, 0xC7,
                            0x10, 0x5D, 0x6B, 0xD6, 0xCA, 0xAF, 0x16, 0xE3,
                            0xC3, 0x15, 0x69, 0xD8, 0x94, 0x2F, 0xC4, 0x23
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    for (size_t i = 0; i < testcase.plaintext_len; i++)
    {
        ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
        atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}

static void test_aead_16_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 16,
                    .plaintext = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_ciphertext = {
                            0xD4, 0xE5, 0x6C, 0x48, 0x41, 0xE2, 0xA0, 0x06,
                            0x9D, 0x4F, 0x07, 0xE6, 0x1B, 0x2D, 0xCA, 0x94,
                            0xFD, 0x6D, 0x3F, 0x9C, 0x0D, 0xF7, 0x83, 0x93,
                            0xE6, 0xE8, 0x29, 0x29, 0x21, 0xBC, 0x84, 0x1D
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    for (size_t i = 0; i < testcase.plaintext_len; i++)
    {
        ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
        atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}


static void test_aead_33_bytes(void)
{
    vecs_aead_t testcase =
            {
                    .plaintext_len = 33,
                    .plaintext = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                            0x20
                    },
                    .expected_ciphertext = {
                            0xA6, 0xDF, 0x18, 0x44, 0x41, 0x2B, 0xAD, 0x53,
                            0x6A, 0x98, 0xDB, 0x01, 0x02, 0x4C, 0x73, 0xA8,
                            0x78, 0x0B, 0xE1, 0xA7, 0x09, 0x93, 0x75, 0x69,
                            0x6D, 0x37, 0x43, 0x05, 0x86, 0xBA, 0x93, 0x81
                    }
            };
    uint8_t obtained_ciphertext[ciphertext_len] = {42};
    ascon_aead_ctx_t aead_ctx;

    // Single update call
    ascon128_encrypt_init(&aead_ctx);
    ascon128_encrypt_update(&aead_ctx, testcase.plaintext,
                            testcase.plaintext_len);
    atto_eq(aead_ctx.buffer_len, testcase.plaintext_len % ASCON_RATE);
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);

    // Many 1-byte update calls
    ascon128_encrypt_init(&aead_ctx);
    for (size_t i = 0; i < testcase.plaintext_len; i++)
    {
        ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
        atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);

    vecs_aead_log(&testcase, obtained_ciphertext);
    atto_memeq(obtained_ciphertext,
               testcase.expected_ciphertext,
               ciphertext_len);
}

static void test_aead_batch(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[ciphertext_len];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_aead_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        ascon_aead128(obtained_ciphertext, testcase.plaintext,
                      testcase.plaintext_len);
        vecs_aead_log(&testcase, obtained_ciphertext);
        atto_memeq(obtained_ciphertext,
                   testcase.expected_ciphertext,
                   ciphertext_len);
    }
}

static void test_aead_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_ciphertext[ciphertext_len];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;

    while (1)
    {
        errcode = vecs_aead_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        // Many 1-byte update calls
        ascon128_encrypt_init(&aead_ctx);
        for (size_t i = 0; i < testcase.plaintext_len; i++)
        {
            ascon128_encrypt_update(&aead_ctx, &testcase.plaintext[i], 1);
            atto_eq(aead_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        ascon128_encrypt_final(&aead_ctx, obtained_ciphertext);
        vecs_aead_log(&testcase, obtained_ciphertext);
        atto_memeq(obtained_ciphertext,
                   testcase.expected_ciphertext,
                   ciphertext_len);
    }
}

*/

void test_aead128(void)
{
    test_aead_empty();
    /*test_aead_1_byte_ad_empty_pt();
    test_aead_1_byte_pt_empty_ad();
    test_aead_1_byte_pt_1_byte_ad();
    test_aead_1_byte();
    test_aead_2_bytes();
    test_aead_7_bytes();
    test_aead_8_bytes();
    test_aead_9_bytes();
    test_aead_15_bytes();
    test_aead_16_bytes();
    test_aead_33_bytes();
    test_aead_batch();
    test_aead_update_single_byte();*/
}
