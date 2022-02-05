/**
 * @file
 * Tests of the Ascon-Hasha.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define HASHA_VECTORS_FILE "vectors/hasha.txt"
#define KEY_LEN 0 /* Key not used in this file. */

static void test_hash_empty(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 0,
                    .message = {0},
                    .expected_digest = {
                            0xAE, 0xCD, 0x02, 0x70, 0x26, 0xD0, 0x67, 0x5F,
                            0x9D, 0xE7, 0xA8, 0xAD, 0x8C, 0xCF, 0x51, 0x2D,
                            0xB6, 0x4B, 0x1E, 0xDC, 0xF0, 0xB2, 0x0C, 0x38,
                            0x8A, 0x0C, 0x7C, 0xC6, 0x17, 0xAA, 0xA2, 0xC4
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Without update call
    ascon_hasha_init(&hash_ctx);
    atto_eq(hash_ctx.buffer_len, 0);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);

    // With update calls of zero length
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, NULL, 0);
    ascon_hasha_update(&hash_ctx, obtained_digest, 0);
    ascon_hasha_update(&hash_ctx, NULL, 0);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_1_byte(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 1,
                    .message = {0},
                    .expected_digest = {
                            0x5A, 0x55, 0xF0, 0x36, 0x77, 0x63, 0xD3, 0x34,
                            0xA3, 0x17, 0x4F, 0x9C, 0x17, 0xFA, 0x47, 0x6E,
                            0xB9, 0x19, 0x6A, 0x22, 0xF1, 0x0D, 0xAF, 0x29,
                            0x50, 0x56, 0x33, 0x57, 0x2E, 0x77, 0x56, 0xE4
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, 1);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_hash_2_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 2,
                    .message = {0x00, 0x01},
                    .expected_digest = {
                            0x42, 0x43, 0xFD, 0x3B, 0x87, 0x2E, 0x1E, 0xD4,
                            0x01, 0x37, 0x11, 0x38, 0x2C, 0xBA, 0x03, 0x2F,
                            0xEC, 0xB4, 0x14, 0x7D, 0x84, 0x0D, 0xDF, 0x84,
                            0x36, 0x17, 0x2A, 0xC6, 0x2D, 0x12, 0x9B, 0xC4
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, &testcase.message[0], 1);
    atto_eq(hash_ctx.buffer_len, 1);
    ascon_hasha_update(&hash_ctx, &testcase.message[1], 1);
    atto_eq(hash_ctx.buffer_len, 2);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_7_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 7,
                    .message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
                    .expected_digest = {
                            0x6B, 0x6A, 0xD8, 0xA9, 0x0E, 0xAB, 0x00, 0xDC,
                            0xCC, 0x18, 0x2D, 0xF1, 0xCE, 0xC7, 0x64, 0xE7,
                            0x06, 0x46, 0x1E, 0x76, 0xD3, 0x03, 0x86, 0x37,
                            0x28, 0xB8, 0x59, 0x0B, 0x77, 0x2E, 0x90, 0x82
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_hash_8_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 8,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                    },
                    .expected_digest = {
                            0xBE, 0x93, 0x32, 0xE1, 0x0A, 0xD1, 0x61, 0x37,
                            0x32, 0x29, 0x68, 0xBB, 0xEC, 0x17, 0x76, 0xBA,
                            0x3F, 0x4E, 0xCD, 0xC1, 0x18, 0x3D, 0xB7, 0xDB,
                            0xE1, 0xAC, 0x98, 0xBD, 0x66, 0xFC, 0xE7, 0xB6
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, 0);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_9_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 9,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08
                    },
                    .expected_digest = {
                            0x7D, 0x3E, 0x9E, 0x36, 0xB5, 0x86, 0x5A, 0x87,
                            0x4D, 0xBC, 0x7F, 0x93, 0x73, 0xFB, 0x18, 0x4F,
                            0xA7, 0x22, 0xA9, 0x4D, 0xD3, 0xEE, 0x04, 0x61,
                            0x2B, 0x53, 0x63, 0xC9, 0x49, 0xB5, 0x08, 0x9B
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_15_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 15,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
                    },
                    .expected_digest = {
                            0x2C, 0xAB, 0xC9, 0xFB, 0x4D, 0xF0, 0xC8, 0xEB,
                            0x2E, 0xD7, 0x89, 0xEB, 0x28, 0xAC, 0x5D, 0x46,
                            0x47, 0x62, 0xB1, 0xF9, 0x8C, 0x17, 0x6C, 0x37,
                            0x05, 0x48, 0x49, 0x6C, 0xA9, 0x22, 0x9B, 0xAC
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_16_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 16,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_digest = {
                            0xEA, 0x1C, 0xB7, 0x36, 0x39, 0xBF, 0xA0, 0xC6,
                            0xDE, 0x4E, 0x60, 0x96, 0x0F, 0x4F, 0x73, 0x51,
                            0x0F, 0xE4, 0x48, 0x13, 0x40, 0xF1, 0xD9, 0x56,
                            0xA5, 0x9E, 0x9D, 0xD2, 0x16, 0x6F, 0x9A, 0x99
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_hash_33_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 33,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                            0x20
                    },
                    .expected_digest = {
                            0xB2, 0xE4, 0xEE, 0x02, 0x1A, 0x20, 0xB3, 0x0A,
                            0x84, 0xE1, 0x40, 0x60, 0xA8, 0x94, 0x60, 0x2F,
                            0x3F, 0x53, 0x94, 0x2E, 0xDC, 0x19, 0x26, 0x6B,
                            0xE6, 0xDF, 0xDC, 0x90, 0xED, 0xE5, 0x18, 0xB2
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hasha_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_batch(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, HASHA_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        atto_ctr(testcase.count);
        ascon_hasha(obtained_digest, testcase.message, testcase.message_len);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASHA_DIGEST_LEN);

        // With the final_matches validation
        bool is_tag_valid = ascon_hasha_matches(testcase.expected_digest,
                                                testcase.message,
                                                testcase.message_len);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
    }
}

static void test_hash_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, HASHA_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_hash_ctx_t hash_ctx;

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        atto_ctr(testcase.count);
        // Many 1-byte update calls
        ascon_hasha_init(&hash_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
            atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        ascon_hasha_final(&hash_ctx, obtained_digest);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASHA_DIGEST_LEN);

        // Many 1-byte update calls with digest matching check
        ascon_hasha_init(&hash_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hasha_update(&hash_ctx, &testcase.message[i], 1);
            atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, testcase.expected_digest);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
        vecs_hash_log(&testcase, obtained_digest);
        atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
    }
}

static void test_hash_matches_failing_on_wrong_input(void)
{
    ascon_hash_ctx_t hash_ctx;
    uint8_t dummy_data[] = "abcde";
    uint8_t expected_digest[ASCON_HASHA_DIGEST_LEN];

    // Generate the digest
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    ascon_hasha_final(&hash_ctx, expected_digest);

    // Digest matches when done the same way
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    bool is_tag_valid = ascon_hasha_final_matches(&hash_ctx, expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));

    // Digest does NOT match when data is altered
    dummy_data[1] = 'X';
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hasha_final_matches(&hash_ctx, expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));

    // Enforcing branch when digest differs in last block
    atto_neq(expected_digest[31], 0xFF);
    expected_digest[31] = 0xFF;
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hasha_final_matches(&hash_ctx, expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));

    // Enforcing branch when digest differs in first block
    atto_neq(expected_digest[0], 0xFF);
    expected_digest[0] = 0xFF;
    ascon_hasha_init(&hash_ctx);
    ascon_hasha_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hasha_final_matches(&hash_ctx, expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

void test_hasha(void)
{
    puts("Testing Ascon-Hasha...");
    test_hash_empty();
    test_hash_1_byte();
    test_hash_2_bytes();
    test_hash_7_bytes();
    test_hash_8_bytes();
    test_hash_9_bytes();
    test_hash_15_bytes();
    test_hash_16_bytes();
    test_hash_33_bytes();
    test_hash_batch();
    test_hash_update_single_byte();
    test_hash_matches_failing_on_wrong_input();
}
