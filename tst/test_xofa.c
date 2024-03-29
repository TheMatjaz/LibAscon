/**
 * @file
 * Tests of the Ascon-Xof.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define XOFA_VECTORS_FILE "vectors/xofa.txt"
#define KEY_LEN 0 /* Key not used in this file. */

static void test_xof_empty(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 0,
                    .message = {0},
                    .expected_digest = {
                            0x7C, 0x10, 0xDF, 0xFD, 0x6B, 0xB0, 0x3B, 0xE2,
                            0x62, 0xD7, 0x2F, 0xBE, 0x1B, 0x0F, 0x53, 0x00,
                            0x13, 0xC6, 0xC4, 0xEA, 0xDA, 0xAB, 0xDE, 0x27,
                            0x8D, 0x6F, 0x29, 0xD5, 0x79, 0xE3, 0x90, 0x8D
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Without update call
    ascon_hasha_xof_init(&xof_ctx);
    atto_eq(xof_ctx.buffer_len, 0);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With update calls of zero length
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, NULL, 0);
    ascon_hasha_xof_update(&xof_ctx, obtained_digest, 0);
    ascon_hasha_xof_update(&xof_ctx, NULL, 0);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_1_byte(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 1,
                    .message = {0},
                    .expected_digest = {
                            0x96, 0x54, 0x45, 0xC4, 0x6C, 0x8E, 0x9B, 0x94,
                            0x8E, 0xDF, 0xEF, 0x7B, 0x58, 0x79, 0xE0, 0x6A,
                            0xB5, 0xF0, 0x23, 0x77, 0x0E, 0xA8, 0x92, 0xFA,
                            0x4B, 0x54, 0x52, 0x50, 0x08, 0x46, 0x7E, 0xA3
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, 1);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_2_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 2,
                    .message = {0x00, 0x01},
                    .expected_digest = {
                            0x48, 0xEB, 0x41, 0xB7, 0xA4, 0x35, 0x2A, 0xFB,
                            0x89, 0x43, 0xB7, 0x65, 0x65, 0x48, 0x55, 0xB1,
                            0xD7, 0x10, 0x4B, 0x22, 0xE9, 0x81, 0xE5, 0x12,
                            0x0D, 0xA9, 0x96, 0x25, 0x79, 0xA7, 0xBA, 0xE6
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, &testcase.message[0], 1);
    atto_eq(xof_ctx.buffer_len, 1);
    ascon_hasha_xof_update(&xof_ctx, &testcase.message[1], 1);
    atto_eq(xof_ctx.buffer_len, 2);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_7_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 7,
                    .message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
                    .expected_digest = {
                            0x00, 0x75, 0x5B, 0x9D, 0x72, 0xB2, 0x63, 0x2D,
                            0x88, 0xCB, 0x69, 0x45, 0xD5, 0x36, 0x38, 0x2C,
                            0x1E, 0x0B, 0x49, 0x57, 0xB4, 0xA4, 0x4B, 0xB5,
                            0x1C, 0x14, 0x88, 0x6A, 0x6F, 0xB3, 0x1A, 0x45
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_xof_8_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 8,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                    },
                    .expected_digest = {
                            0x91, 0xC7, 0x2F, 0x62, 0x73, 0xB6, 0xED, 0x44,
                            0x4B, 0xF5, 0x60, 0xF2, 0xFA, 0xC9, 0x9E, 0x8F,
                            0xED, 0xDD, 0xF3, 0x01, 0x62, 0x68, 0x8B, 0x86,
                            0x55, 0x3E, 0xB5, 0x7F, 0x1C, 0x98, 0xC2, 0x0E
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, 0);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_9_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 9,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08
                    },
                    .expected_digest = {
                            0x7E, 0x79, 0x76, 0x8F, 0x37, 0xD2, 0x13, 0xB1,
                            0x1B, 0x41, 0x93, 0xE1, 0xD6, 0x2D, 0x33, 0x99,
                            0x54, 0xA3, 0xB9, 0xE1, 0x6C, 0xCE, 0xF0, 0x5F,
                            0xD5, 0x74, 0xE1, 0x33, 0x06, 0x68, 0xB6, 0x28
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_15_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 15,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
                    },
                    .expected_digest = {
                            0x75, 0xF6, 0x13, 0x59, 0xF0, 0x4C, 0x77, 0xFF,
                            0x4D, 0xE5, 0x8A, 0x10, 0xF9, 0xF8, 0x7B, 0x31,
                            0xB5, 0xB8, 0xDA, 0x33, 0x73, 0xF6, 0x23, 0x0F,
                            0xE1, 0x73, 0x50, 0x33, 0x44, 0x6B, 0x99, 0x48
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_16_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 16,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_digest = {
                            0x94, 0x24, 0xB7, 0xAE, 0x5F, 0xA7, 0x2D, 0x3E,
                            0xE4, 0xA2, 0x66, 0x11, 0x2E, 0x7A, 0xBC, 0x40,
                            0x92, 0xE8, 0x15, 0xAE, 0x29, 0xFA, 0xB2, 0x6D,
                            0xA6, 0x66, 0xC1, 0x48, 0x5B, 0xA9, 0x2B, 0xDC
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_xof_33_bytes(void)
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
                            0x87, 0xB9, 0x82, 0xC6, 0xA6, 0xBA, 0x14, 0x0A,
                            0xAB, 0x0A, 0x1A, 0x34, 0xFA, 0x24, 0xCB, 0x97,
                            0xDC, 0x87, 0xFC, 0x6B, 0x28, 0xB2, 0x48, 0x6D,
                            0x76, 0xCE, 0xE4, 0xA4, 0x6C, 0xCD, 0x8A, 0xD5
                    }
            };
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_hasha_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASHA_DIGEST_LEN);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                      ASCON_HASHA_DIGEST_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_xof_batch(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, XOFA_VECTORS_FILE, KEY_LEN);
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
        ascon_hasha_xof(obtained_digest, testcase.message,
                        ASCON_HASHA_DIGEST_LEN, testcase.message_len);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASHA_DIGEST_LEN);

        // With the final_matches validation
        bool is_tag_valid = ascon_hasha_xof_matches(testcase.expected_digest, testcase.message,
                                                    ASCON_HASHA_DIGEST_LEN, testcase.message_len);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
    }
}

static void test_xof_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASHA_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, XOFA_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_hash_ctx_t xof_ctx;

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
        ascon_hasha_xof_init(&xof_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
            atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        ascon_hasha_xof_final(&xof_ctx, obtained_digest, ASCON_HASHA_DIGEST_LEN);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASHA_DIGEST_LEN);
        atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

        // Many 1-byte update calls with digest matching check
        ascon_hasha_xof_init(&xof_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hasha_xof_update(&xof_ctx, &testcase.message[i], 1);
            atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, testcase.expected_digest,
                                                          ASCON_HASHA_DIGEST_LEN);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
        vecs_hash_log(&testcase, obtained_digest);
        atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
    }
}

static void test_xof_batch_custom_digest_len(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    const size_t digest_len = 30;
    uint8_t obtained_digest[32] = {0};
    vecs_err_t errcode = vecs_init(&ctx, XOFA_VECTORS_FILE, KEY_LEN);
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
        ascon_hasha_xof(obtained_digest, testcase.message,
                        digest_len, testcase.message_len);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   digest_len);
        atto_eq(obtained_digest[30], 0);
        atto_eq(obtained_digest[31], 0);

        // With a single-call validation
        bool is_tag_valid = ascon_hasha_xof_matches(testcase.expected_digest,
                                                    testcase.message,
                                                    digest_len,
                                                    testcase.message_len);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
    }
}

static void test_xof_matches_failing_on_wrong_input(void)
{
    ascon_hash_ctx_t xof_ctx;
    uint8_t dummy_data[] = "abcde";
    uint8_t expected_digest[13];

    // Generate the digest
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, dummy_data, sizeof(dummy_data));
    ascon_hasha_xof_final(&xof_ctx, expected_digest, sizeof(expected_digest));

    // Digest matches when done the same way
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, dummy_data, sizeof(dummy_data));
    bool is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, expected_digest,
                                                      sizeof(expected_digest));
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Digest does NOT match when data is altered
    dummy_data[1] = 'X';
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, expected_digest,
                                                 sizeof(expected_digest));
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Enforcing branch when digest differs in last block
    atto_neq(expected_digest[12], 0xFF);
    expected_digest[12] = 0xFF;
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, expected_digest,
                                                sizeof(expected_digest));
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));

    // Enforcing branch when digest differs in first block
    atto_neq(expected_digest[0], 0xFF);
    expected_digest[0] = 0xFF;
    ascon_hasha_xof_init(&xof_ctx);
    ascon_hasha_xof_update(&xof_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_hasha_xof_final_matches(&xof_ctx, expected_digest,
                                                sizeof(expected_digest));
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&xof_ctx, sizeof(ascon_hash_ctx_t));
}

void test_xofa(void)
{
    puts("Testing Ascon-XOFa...");
    test_xof_empty();
    test_xof_1_byte();
    test_xof_2_bytes();
    test_xof_7_bytes();
    test_xof_8_bytes();
    test_xof_9_bytes();
    test_xof_15_bytes();
    test_xof_16_bytes();
    test_xof_33_bytes();
    test_xof_batch();
    test_xof_update_single_byte();
    test_xof_batch_custom_digest_len();
    test_xof_matches_failing_on_wrong_input();
}
