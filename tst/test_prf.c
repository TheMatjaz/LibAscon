/**
 * @file
 * Tests of the Ascon-PRF.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define PRF_VECTORS_FILE "vectors/prf.txt"
#define KEY_LEN 16U

static void test_prf_empty(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 0,
                    .message = {0},
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0x2A, 0x76, 0x6F, 0xE9, 0xA4, 0x89, 0x40, 0x73,
                            0xBC, 0x81, 0x1B, 0x19, 0xD5, 0x4A, 0xC3, 0x3D
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Without update call
    ascon_prf_init(&prf_ctx, testcase.key);
    atto_eq(prf_ctx.buffer_len, 0);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With update calls of zero length
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, NULL, 0);
    ascon_prf_update(&prf_ctx, obtained_tag, 0);
    ascon_prf_update(&prf_ctx, NULL, 0);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_1_byte(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 1,
                    .message = {0},
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0xB2, 0xED, 0xBB, 0x27, 0xAC, 0x83, 0x97, 0xA5,
                            0x5B, 0xC8, 0x3D, 0x13, 0x7C, 0x15, 0x1D, 0xE9,
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, 1);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_2_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 2,
                    .message = {0x00, 0x01},
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0xD1, 0x96, 0x46, 0x1C, 0x29, 0x9D, 0xB7, 0x14,
                            0xD7, 0x8C, 0x26, 0x79, 0x24, 0xB5, 0x78, 0x6E,
                            0xE2, 0x6F, 0xC4, 0x3B, 0x3E, 0x64, 0x0D, 0xAA,
                            0x53, 0x97, 0xE3, 0x8E, 0x39, 0xD3, 0x9D, 0xC6
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, &testcase.message[0], 1);
    atto_eq(prf_ctx.buffer_len, 1);
    ascon_prf_update(&prf_ctx, &testcase.message[1], 1);
    atto_eq(prf_ctx.buffer_len, 2);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_7_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 7,
                    .message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0x1D, 0xB7, 0x47, 0x6C, 0xD7, 0x20, 0x64, 0xC6,
                            0x8E, 0x73, 0x6D, 0x82, 0x1E, 0xA6, 0xF0, 0xC9,
                            0x36, 0x10, 0xFE, 0x22, 0x32, 0x67, 0x54, 0xF5,
                            0x36, 0x68, 0x36, 0x87, 0x1A, 0x6F, 0x5A, 0x10
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
        atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_prf_8_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 8,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                    },
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0x18, 0x42, 0x7D, 0x2D, 0x29, 0xDF, 0x1E, 0x02,
                            0x02, 0x64, 0x9F, 0x03, 0x2F, 0x20, 0x80, 0x36,
                            0x3F, 0xEC, 0x5D, 0xE7, 0x2E, 0xCA, 0xE1, 0x1B,
                            0x4F, 0x98, 0xCC, 0xC7, 0x58, 0x43, 0xE7, 0xCC
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, 0);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
        atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_9_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 9,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                            0x07, 0x08
                    },
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0xCE, 0x60, 0x6E, 0x3F, 0xFC, 0xEE, 0x53, 0xB1,
                            0x13, 0xAA, 0x5A, 0x5C, 0xA3, 0xA1, 0x63, 0x76,
                            0xA3, 0xDE, 0x36, 0x43, 0x52, 0x87, 0x5D, 0x33,
                            0x60, 0xE1, 0x31, 0x66, 0x6A, 0x56, 0x72, 0x48
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
        atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_15_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 15,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E
                    },
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0x39, 0x9E, 0x6B, 0xE5, 0x84, 0xDE, 0x50, 0x91,
                            0xF4, 0x97, 0x11, 0xED, 0x6C, 0x19, 0x5F, 0x0D,
                            0xE0, 0xEE, 0x81, 0x11, 0x13, 0xC6, 0x8B, 0x37,
                            0x23, 0x99, 0xDB, 0xBF, 0xF2, 0x8F, 0x11, 0x73
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
        atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_16_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 16,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0xC8, 0x61, 0xA8, 0x9C, 0xFB, 0x13, 0x35, 0xF2,
                            0x78, 0xC9, 0x6C, 0xF7, 0xFF, 0xC9, 0x75, 0x3C,
                            0x29, 0x0C, 0xBE, 0x1A, 0x4E, 0x18, 0x6D, 0x29,
                            0x23, 0xB4, 0x96, 0xBB, 0x4E, 0xA5, 0xE5, 0x19
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
        atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}


static void test_prf_33_bytes(void)
{
    vecs_prf_t testcase =
            {
                    .message_len = 33,
                    .message = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
                            0x20
                    },
                    .count = 0,
                    .key = {
                            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
                    },
                    .expected_tag = {
                            0x12, 0xE2, 0x59, 0x3F, 0xBB, 0x8A, 0x73, 0x3B,
                            0x79, 0xB7, 0xA5, 0x4C, 0x2D, 0x99, 0xC9, 0x52,
                            0x3A, 0x12, 0x6F, 0x32, 0xA1, 0xD1, 0x98, 0xDD,
                            0xC5, 0xDB, 0x3F, 0x8D, 0x98, 0x67, 0x3F, 0xD9
                    }
            };
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN] = {42};
    ascon_hash_ctx_t prf_ctx;

    // Single update call
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    atto_eq(prf_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Many 1-byte update calls
    ascon_prf_init(&prf_ctx, testcase.key);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
        atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);

    vecs_prf_log(&testcase, obtained_tag);
    atto_memeq(obtained_tag,
               testcase.expected_tag,
               VECS_MAX_PRF_TAG_LEN);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // With the final_matches validation
    ascon_prf_init(&prf_ctx, testcase.key);
    ascon_prf_update(&prf_ctx, testcase.message, testcase.message_len);
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                VECS_MAX_PRF_TAG_LEN);
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

static void test_prf_batch(void)
{
    vecs_ctx_t ctx;
    vecs_prf_t testcase;
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN];
    vecs_err_t errcode = vecs_init(&ctx, PRF_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_prf_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        atto_ctr(testcase.count);
        ascon_prf(obtained_tag, testcase.key, testcase.message,
                  VECS_MAX_PRF_TAG_LEN, testcase.message_len);
        vecs_prf_log(&testcase, obtained_tag);
        atto_memeq(obtained_tag,
                   testcase.expected_tag,
                   VECS_MAX_PRF_TAG_LEN);

        // With the final_matches validation
        bool is_tag_valid = ascon_prf_matches(testcase.expected_tag, testcase.key, testcase.message,
                                              VECS_MAX_PRF_TAG_LEN, testcase.message_len);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
    }
}

static void test_prf_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_prf_t testcase;
    uint8_t obtained_tag[VECS_MAX_PRF_TAG_LEN];
    vecs_err_t errcode = vecs_init(&ctx, PRF_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_hash_ctx_t prf_ctx;

    while (1)
    {
        errcode = vecs_prf_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        atto_ctr(testcase.count);
        // Many 1-byte update calls
        ascon_prf_init(&prf_ctx, testcase.key);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
            atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        ascon_prf_final(&prf_ctx, obtained_tag, VECS_MAX_PRF_TAG_LEN);
        vecs_prf_log(&testcase, obtained_tag);
        atto_memeq(obtained_tag,
                   testcase.expected_tag,
                   VECS_MAX_PRF_TAG_LEN);
        atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

        // Many 1-byte update calls with tag matching check
        ascon_prf_init(&prf_ctx, testcase.key);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_prf_update(&prf_ctx, &testcase.message[i], 1);
            atto_eq(prf_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, testcase.expected_tag,
                                                    VECS_MAX_PRF_TAG_LEN);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
        vecs_prf_log(&testcase, obtained_tag);
        atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
    }
}

static void test_prf_batch_custom_tag_len(void)
{
    vecs_ctx_t ctx;
    vecs_prf_t testcase;
    const size_t tag_len = 30;
    uint8_t obtained_tag[32] = {0};
    vecs_err_t errcode = vecs_init(&ctx, PRF_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_prf_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        atto_ctr(testcase.count);
        ascon_prf(obtained_tag, testcase.key, testcase.message,
                  tag_len, testcase.message_len);
        vecs_prf_log(&testcase, obtained_tag);
        atto_memeq(obtained_tag,
                   testcase.expected_tag,
                   tag_len);
        atto_eq(obtained_tag[30], 0);
        atto_eq(obtained_tag[31], 0);

        // With a single-call validation
        bool is_tag_valid = ascon_prf_matches(testcase.expected_tag,
                                              testcase.key,
                                              testcase.message,
                                              tag_len,
                                              testcase.message_len);
        atto_eq(is_tag_valid, ASCON_TAG_OK);
    }
}

static void test_prf_matches_failing_on_wrong_input(void)
{
    ascon_hash_ctx_t prf_ctx;
    uint8_t dummy_data[] = "abcde";
    uint8_t expected_tag[13];
    const uint8_t key[KEY_LEN] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    // Generate the tag
    ascon_prf_init(&prf_ctx, key);
    ascon_prf_update(&prf_ctx, dummy_data, sizeof(dummy_data));
    ascon_prf_final(&prf_ctx, expected_tag, sizeof(expected_tag));

    // Tag matches when done the same way
    ascon_prf_init(&prf_ctx, key);
    ascon_prf_update(&prf_ctx, dummy_data, sizeof(dummy_data));
    bool is_tag_valid = ascon_prf_final_matches(&prf_ctx, expected_tag,
                                                sizeof(expected_tag));
    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Tag does NOT match when data is altered
    dummy_data[1] = 'X';
    ascon_prf_init(&prf_ctx, key);
    ascon_prf_update(&prf_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_prf_final_matches(&prf_ctx, expected_tag,
                                           sizeof(expected_tag));
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Enforcing branch when tag differs in last block
    atto_neq(expected_tag[12], 0xFF);
    expected_tag[12] = 0xFF;
    ascon_prf_init(&prf_ctx, key);
    ascon_prf_update(&prf_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_prf_final_matches(&prf_ctx, expected_tag,
                                           sizeof(expected_tag));
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));

    // Enforcing branch when tag differs in first block
    atto_neq(expected_tag[0], 0xFF);
    expected_tag[0] = 0xFF;
    ascon_prf_init(&prf_ctx, key);
    ascon_prf_update(&prf_ctx, dummy_data, sizeof(dummy_data));
    is_tag_valid = ascon_prf_final_matches(&prf_ctx, expected_tag,
                                           sizeof(expected_tag));
    atto_eq(is_tag_valid, ASCON_TAG_INVALID);
    atto_zeros(&prf_ctx, sizeof(ascon_hash_ctx_t));
}

void test_prf(void)
{
    puts("Testing Ascon-PRF...");
    test_prf_empty();
    test_prf_1_byte();
    test_prf_2_bytes();
    test_prf_7_bytes();
    test_prf_8_bytes();
    test_prf_9_bytes();
    test_prf_15_bytes();
    test_prf_16_bytes();
    test_prf_33_bytes();
    test_prf_batch();
    test_prf_update_single_byte();
    test_prf_batch_custom_tag_len();
    test_prf_matches_failing_on_wrong_input();
}
