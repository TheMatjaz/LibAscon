/**
 * @file
 * Tests of the Ascon-Hash.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define HASH_VECTORS_FILE "vectors/hash.txt"
#define KEY_LEN 0 /* Key not used in this file. */

static void test_hash_cleanup(void)
{
    ascon_hash_ctx_t ctx;
    memset(&ctx, 0xFF, sizeof(ascon_hash_ctx_t));
    ascon_hash_cleanup(&ctx);
    atto_zeros(&ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_empty(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 0,
                    .message = {0},
                    .expected_digest = {
                            0x73, 0x46, 0xBC, 0x14, 0xF0, 0x36, 0xE8, 0x7A,
                            0xE0, 0x3D, 0x09, 0x97, 0x91, 0x30, 0x88, 0xF5,
                            0xF6, 0x84, 0x11, 0x43, 0x4B, 0x3C, 0xF8, 0xB5,
                            0x4F, 0xA7, 0x96, 0xA8, 0x0D, 0x25, 0x1F, 0x91
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Without update call
    ascon_hash_init(&hash_ctx);
    atto_eq(hash_ctx.buffer_len, 0);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // With update calls of zero length
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, NULL, 0);
    ascon_hash_update(&hash_ctx, obtained_digest, 0);
    ascon_hash_update(&hash_ctx, NULL, 0);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0x8D, 0xD4, 0x46, 0xAD, 0xA5, 0x8A, 0x77, 0x40,
                            0xEC, 0xF5, 0x6E, 0xB6, 0x38, 0xEF, 0x77, 0x5F,
                            0x7D, 0x5C, 0x0F, 0xD5, 0xF0, 0xC2, 0xBB, 0xBD,
                            0xFD, 0xEC, 0x29, 0x60, 0x9D, 0x3C, 0x43, 0xA2
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, 1);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0xF7, 0x7C, 0xA1, 0x3B, 0xF8, 0x91, 0x46, 0xD3,
                            0x25, 0x4F, 0x1C, 0xFB, 0x7E, 0xDD, 0xBA, 0x8F,
                            0xA1, 0xBF, 0x16, 0x22, 0x84, 0xBB, 0x29, 0xE7,
                            0xF6, 0x45, 0x54, 0x5C, 0xF9, 0xE0, 0x84, 0x24
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, &testcase.message[0], 1);
    atto_eq(hash_ctx.buffer_len, 1);
    ascon_hash_update(&hash_ctx, &testcase.message[1], 1);
    atto_eq(hash_ctx.buffer_len, 2);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0xDD, 0x40, 0x9C, 0xCC, 0x0C, 0x60, 0xCD, 0x7F,
                            0x47, 0x4C, 0x0B, 0xEE, 0xD1, 0xE1, 0xCD, 0x48,
                            0x14, 0x0A, 0xD4, 0x5D, 0x51, 0x36, 0xDC, 0x5F,
                            0xDA, 0x5E, 0xBE, 0x28, 0x3D, 0xF8, 0xD3, 0xF6
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0xF4, 0xC6, 0xA4, 0x4B, 0x29, 0x91, 0x5D, 0x3D,
                            0x57, 0xCF, 0x92, 0x8A, 0x18, 0xEC, 0x62, 0x26,
                            0xBB, 0x8D, 0xD6, 0xC1, 0x13, 0x6A, 0xCD, 0x24,
                            0x96, 0x5F, 0x7E, 0x77, 0x80, 0xCD, 0x69, 0xCF
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, 0);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0x1E, 0x1E, 0x71, 0x0D, 0x08, 0xA7, 0x82, 0x63,
                            0x77, 0x33, 0x31, 0x78, 0x26, 0x21, 0x08, 0x8C,
                            0xA9, 0xFE, 0x2E, 0xE4, 0xF5, 0x96, 0xF0, 0x6C,
                            0x8F, 0x78, 0x84, 0xCA, 0x56, 0x4A, 0xCE, 0xC1
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0x9E, 0x48, 0xE0, 0x3E, 0x8A, 0xAE, 0x0B, 0x99,
                            0x30, 0xDF, 0xF1, 0xE8, 0x01, 0x00, 0x7B, 0xC7,
                            0x10, 0x5D, 0x6B, 0xD6, 0xCA, 0xAF, 0x16, 0xE3,
                            0xC3, 0x15, 0x69, 0xD8, 0x94, 0x2F, 0xC4, 0x23
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0xD4, 0xE5, 0x6C, 0x48, 0x41, 0xE2, 0xA0, 0x06,
                            0x9D, 0x4F, 0x07, 0xE6, 0x1B, 0x2D, 0xCA, 0x94,
                            0xFD, 0x6D, 0x3F, 0x9C, 0x0D, 0xF7, 0x83, 0x93,
                            0xE6, 0xE8, 0x29, 0x29, 0x21, 0xBC, 0x84, 0x1D
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
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
                            0xA6, 0xDF, 0x18, 0x44, 0x41, 0x2B, 0xAD, 0x53,
                            0x6A, 0x98, 0xDB, 0x01, 0x02, 0x4C, 0x73, 0xA8,
                            0x78, 0x0B, 0xE1, 0xA7, 0x09, 0x93, 0x75, 0x69,
                            0x6D, 0x37, 0x43, 0x05, 0x86, 0xBA, 0x93, 0x81
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t hash_ctx;

    // Single update call
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    atto_eq(hash_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // Many 1-byte update calls
    ascon_hash_init(&hash_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
        atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&hash_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
    atto_zeros(&hash_ctx, sizeof(hash_ctx));

    // With the final_matches validation
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_hash_batch(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, HASH_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        ascon_hash(obtained_digest, testcase.message, testcase.message_len);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASH_DIGEST_LEN);

        // With the final_matches validation
        bool is_tag_valid = ascon_hash_matches(testcase.expected_digest,
                                               testcase.message,
                                               testcase.message_len);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
    }
}

static void test_hash_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, HASH_VECTORS_FILE, KEY_LEN);
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
        // Many 1-byte update calls
        ascon_hash_init(&hash_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
            atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        ascon_hash_final(&hash_ctx, obtained_digest);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASH_DIGEST_LEN);

        // Many 1-byte update calls with digest matching check
        ascon_hash_init(&hash_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hash_update(&hash_ctx, &testcase.message[i], 1);
            atto_eq(hash_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, testcase.expected_digest);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
        vecs_hash_log(&testcase, obtained_digest);
        atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
    }
}

static void test_hash_matches_failing_on_wrong_input(void)
{
    ascon_hash_ctx_t hash_ctx;
    uint8_t dummy_data[] = "abcde";
    uint8_t expected_digest[ASCON_HASH_DIGEST_LEN];

    // Generate the digest
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    ascon_hash_final(&hash_ctx, expected_digest);

    // Digest matches when done the same way
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    bool is_tag_valid = ascon_hash_final_matches(&hash_ctx, expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));

    // Digest does NOT match when data is altered
    dummy_data[1] = 'X';
    ascon_hash_init(&hash_ctx);
    ascon_hash_update(&hash_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hash_final_matches(&hash_ctx, expected_digest);
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&hash_ctx, sizeof(ascon_hash_ctx_t));
}

void test_hash(void)
{
    test_hash_cleanup();
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
