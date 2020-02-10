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

#define XOF_VECTORS_FILE "vectors/xof.txt"

static void test_xof_empty(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 0,
                    .message = {0},
                    .expected_digest = {
                            0x5D, 0x4C, 0xBD, 0xE6, 0x35, 0x0E, 0xA4, 0xC1,
                            0x74, 0xBD, 0x65, 0xB5, 0xB3, 0x32, 0xF8, 0x40,
                            0x8F, 0x99, 0x74, 0x0B, 0x81, 0xAA, 0x02, 0x73,
                            0x5E, 0xAE, 0xFB, 0xCF, 0x0B, 0xA0, 0x33, 0x9E
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Without update call
    ascon_hash_xof_init(&xof_ctx);
    atto_eq(xof_ctx.buffer_len, 0);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // With update calls of zero length
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, NULL, 0);
    ascon_hash_xof_update(&xof_ctx, obtained_digest, 0);
    ascon_hash_xof_update(&xof_ctx, NULL, 0);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
}

static void test_xof_1_byte(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 1,
                    .message = {0},
                    .expected_digest = {
                            0xB2, 0xED, 0xBB, 0x27, 0xAC, 0x83, 0x97, 0xA5,
                            0x5B, 0xC8, 0x3D, 0x13, 0x7C, 0x15, 0x1D, 0xE9,
                            0xED, 0xE0, 0x48, 0x33, 0x8F, 0xE9, 0x07, 0xF0,
                            0xD3, 0x62, 0x9E, 0x71, 0x78, 0x46, 0xFE, 0xDC
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, 1);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
}


static void test_xof_2_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 2,
                    .message = {0x00, 0x01},
                    .expected_digest = {
                            0xD1, 0x96, 0x46, 0x1C, 0x29, 0x9D, 0xB7, 0x14,
                            0xD7, 0x8C, 0x26, 0x79, 0x24, 0xB5, 0x78, 0x6E,
                            0xE2, 0x6F, 0xC4, 0x3B, 0x3E, 0x64, 0x0D, 0xAA,
                            0x53, 0x97, 0xE3, 0x8E, 0x39, 0xD3, 0x9D, 0xC6
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, &testcase.message[0], 1);
    atto_eq(xof_ctx.buffer_len, 1);
    ascon_hash_xof_update(&xof_ctx, &testcase.message[1], 1);
    atto_eq(xof_ctx.buffer_len, 2);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
}

static void test_xof_7_bytes(void)
{
    vecs_hash_t testcase =
            {
                    .message_len = 7,
                    .message = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
                    .expected_digest = {
                            0x1D, 0xB7, 0x47, 0x6C, 0xD7, 0x20, 0x64, 0xC6,
                            0x8E, 0x73, 0x6D, 0x82, 0x1E, 0xA6, 0xF0, 0xC9,
                            0x36, 0x10, 0xFE, 0x22, 0x32, 0x67, 0x54, 0xF5,
                            0x36, 0x68, 0x36, 0x87, 0x1A, 0x6F, 0x5A, 0x10
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
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
                            0x18, 0x42, 0x7D, 0x2D, 0x29, 0xDF, 0x1E, 0x02,
                            0x02, 0x64, 0x9F, 0x03, 0x2F, 0x20, 0x80, 0x36,
                            0x3F, 0xEC, 0x5D, 0xE7, 0x2E, 0xCA, 0xE1, 0x1B,
                            0x4F, 0x98, 0xCC, 0xC7, 0x58, 0x43, 0xE7, 0xCC
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, 0);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
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
                            0xCE, 0x60, 0x6E, 0x3F, 0xFC, 0xEE, 0x53, 0xB1,
                            0x13, 0xAA, 0x5A, 0x5C, 0xA3, 0xA1, 0x63, 0x76,
                            0xA3, 0xDE, 0x36, 0x43, 0x52, 0x87, 0x5D, 0x33,
                            0x60, 0xE1, 0x31, 0x66, 0x6A, 0x56, 0x72, 0x48
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
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
                            0x39, 0x9E, 0x6B, 0xE5, 0x84, 0xDE, 0x50, 0x91,
                            0xF4, 0x97, 0x11, 0xED, 0x6C, 0x19, 0x5F, 0x0D,
                            0xE0, 0xEE, 0x81, 0x11, 0x13, 0xC6, 0x8B, 0x37,
                            0x23, 0x99, 0xDB, 0xBF, 0xF2, 0x8F, 0x11, 0x73
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
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
                            0xC8, 0x61, 0xA8, 0x9C, 0xFB, 0x13, 0x35, 0xF2,
                            0x78, 0xC9, 0x6C, 0xF7, 0xFF, 0xC9, 0x75, 0x3C,
                            0x29, 0x0C, 0xBE, 0x1A, 0x4E, 0x18, 0x6D, 0x29,
                            0x23, 0xB4, 0x96, 0xBB, 0x4E, 0xA5, 0xE5, 0x19
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
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
                            0x12, 0xE2, 0x59, 0x3F, 0xBB, 0x8A, 0x73, 0x3B,
                            0x79, 0xB7, 0xA5, 0x4C, 0x2D, 0x99, 0xC9, 0x52,
                            0x3A, 0x12, 0x6F, 0x32, 0xA1, 0xD1, 0x98, 0xDD,
                            0xC5, 0xDB, 0x3F, 0x8D, 0x98, 0x67, 0x3F, 0xD9
                    }
            };
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN] = {42};
    ascon_hash_ctx_t xof_ctx;

    // Single update call
    ascon_hash_xof_init(&xof_ctx);
    ascon_hash_xof_update(&xof_ctx, testcase.message, testcase.message_len);
    atto_eq(xof_ctx.buffer_len, testcase.message_len % ASCON_RATE);
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);

    // Many 1-byte update calls
    ascon_hash_xof_init(&xof_ctx);
    for (size_t i = 0; i < testcase.message_len; i++)
    {
        ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
        atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
    }
    ascon_hash_final(&xof_ctx, obtained_digest);

    vecs_hash_log(&testcase, obtained_digest);
    atto_memeq(obtained_digest,
               testcase.expected_digest,
               ASCON_HASH_DIGEST_LEN);
}

static void test_xof_batch(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, XOF_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        ascon_hash_xof(obtained_digest, testcase.message,
                       ASCON_HASH_DIGEST_LEN, testcase.message_len);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASH_DIGEST_LEN);
    }
}

static void test_xof_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_HASH_DIGEST_LEN];
    vecs_err_t errcode = vecs_init(&ctx, XOF_VECTORS_FILE);
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
        // Many 1-byte update calls
        ascon_hash_xof_init(&xof_ctx);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_hash_xof_update(&xof_ctx, &testcase.message[i], 1);
            atto_eq(xof_ctx.buffer_len, (i + 1) % ASCON_RATE);
        }
        ascon_hash_final(&xof_ctx, obtained_digest);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_HASH_DIGEST_LEN);
    }
}

static void test_xof_batch_custom_digest_len(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    const size_t digest_len = 30;
    uint8_t obtained_digest[32] = {0};
    vecs_err_t errcode = vecs_init(&ctx, XOF_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        ascon_hash_xof(obtained_digest, testcase.message,
                       digest_len, testcase.message_len);
        vecs_hash_log(&testcase, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   digest_len);
        atto_eq(obtained_digest[30], 0);
        atto_eq(obtained_digest[31], 0);
    }
}

void test_xof(void)
{
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
}
