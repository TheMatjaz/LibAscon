/**
 * @file
 * Tests of the AEAD80pq decryption.
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
                    .tag = {
                            0xAB, 0xB6, 0x88, 0xEF, 0xA0, 0xB9, 0xD5, 0x6B,
                            0x33, 0x27, 0x7A, 0x2C, 0x97, 0xD2, 0x14, 0x6B
                    },
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[1];
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    // Offline
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    is_valid = ascon_aead80pq_decrypt(
            obtained_plaintext,
            testcase.key,
            testcase.nonce,
            testcase.assoc_data,
            testcase.ciphertext,
            testcase.tag,
            testcase.assoc_data_len,
            testcase.ciphertext_len,
            sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);

    // Without any update call at all
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    atto_eq(aead_ctx.bufstate.buffer_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx,
                                              obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));

    // With AD update calls of zero length
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead80pq_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead80pq_assoc_data_update(&aead_ctx, obtained_plaintext, 0);
    ascon_aead80pq_assoc_data_update(&aead_ctx, NULL, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));

    // With PT update calls of zero length
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, obtained_plaintext,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));

    // With AD and PT update calls of zero length
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead80pq_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead80pq_assoc_data_update(&aead_ctx, obtained_plaintext, 0);
    ascon_aead80pq_assoc_data_update(&aead_ctx, NULL, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, obtained_plaintext,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));
}


static void test_decrypt_1_byte_ad_empty_pt(void)
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
                    .assoc_data = {0x00},
                    .assoc_data_len = 1,
                    .tag = {
                            0xA2, 0x59, 0xD7, 0x60, 0xE8, 0x7B, 0x0C, 0xA7,
                            0x30, 0x02, 0xC3, 0xA0, 0x1E, 0x69, 0xB5, 0x67
                    },
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[1];
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    // Without PT call
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead80pq_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));

    // With PT call
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead80pq_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));
}

static void test_decrypt_1_byte_pt_empty_ad(void)
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
                    .plaintext = {0x00},
                    .plaintext_len = 1,
                    .assoc_data_len = 0,
                    .ciphertext = {0x28},
                    .tag = {
                            0xAA, 0x80, 0xFF, 0xF4, 0xCA, 0x3A, 0xF3, 0x2F,
                            0x60, 0xEB, 0xCA, 0xF6, 0x3A, 0x4C, 0xCA, 0xB7
                    },
                    .ciphertext_len = 1,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    // Without AD update call
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));

    // With AD call
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead80pq_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));
}

static void test_decrypt_1_byte_pt_1_byte_ad(void)
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
                    .plaintext = {0x00},
                    .plaintext_len = 1,
                    .assoc_data = {0x00},
                    .assoc_data_len = 1,
                    .ciphertext = {0xA9},
                    .ciphertext_len = 1,
                    .tag = {
                            0x23, 0x55, 0x34, 0x74, 0xFF, 0x99, 0x58, 0x42,
                            0xEC, 0xCD, 0xC6, 0x6E, 0x0B, 0xCA, 0x3D, 0x45
                    },
            };
    atto_eq(testcase.plaintext_len, testcase.ciphertext_len);
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead80pq_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead80pq_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead80pq_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, testcase.plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_memeq(obtained_plaintext, testcase.plaintext, testcase.plaintext_len);
    atto_zeros(&aead_ctx, sizeof(aead_ctx));
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
                sizeof(testcase.tag));
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
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
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_bytes = 0;
    size_t total_pt_bytes = 0;
    bool is_valid;

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
        total_pt_bytes = 0;
        // Many 1-byte update calls
        ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
        for (size_t i = 0; i < testcase.assoc_data_len; i++)
        {
            ascon_aead80pq_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                             1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_RATE);
        }
        for (size_t i = 0; i < testcase.ciphertext_len; i++)
        {
            new_pt_bytes = ascon_aead80pq_decrypt_update(
                    &aead_ctx,
                    obtained_plaintext + total_pt_bytes,
                    &testcase.ciphertext[i],
                    1);
            total_pt_bytes += new_pt_bytes;
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
        new_pt_bytes = ascon_aead80pq_decrypt_final(&aead_ctx,
                                                    obtained_plaintext +
                                                    total_pt_bytes,
                                                    &is_valid, testcase.tag,
                                                    sizeof(testcase.tag));
        total_pt_bytes += new_pt_bytes;
        atto_lt(new_pt_bytes, ASCON_RATE);
        atto_eq(new_pt_bytes, testcase.plaintext_len % ASCON_RATE);
        atto_eq(total_pt_bytes, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
        atto_zeros(&aead_ctx, sizeof(aead_ctx));
    }
}


static void test_decrypt_offline_with_corrupted_data(void)
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
        const bool is_valid = ascon_aead80pq_decrypt(
                obtained_plaintext,
                testcase.key,
                testcase.nonce,
                testcase.assoc_data,
                testcase.ciphertext,
                testcase.tag,
                testcase.assoc_data_len,
                testcase.ciphertext_len,
                sizeof(testcase.tag));
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_neq(is_valid, ASCON_TAG_OK);
        if (testcase.plaintext_len > 0)
        {
            atto_memneq(obtained_plaintext,
                        testcase.plaintext,
                        testcase.plaintext_len);
        }
    }
}

static void test_decrypt_update_three_bytes(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_bytes = 0;
    size_t total_pt_bytes = 0;
    bool is_valid;

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
        total_pt_bytes = 0;
        // Many 3-byte update calls
        ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
        size_t remaining;
        size_t step;
        size_t i = 0;
        remaining = testcase.assoc_data_len;
        while (remaining)
        {
            step = MIN(remaining, 3);
            ascon_aead80pq_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                             step);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            remaining -= step;
            i += step;
        }
        i = 0;
        size_t previous_buffer_len = 0;
        remaining = testcase.plaintext_len;
        while (remaining)
        {
            step = MIN(remaining, 3);
            new_pt_bytes = ascon_aead80pq_decrypt_update(
                    &aead_ctx,
                    obtained_plaintext + total_pt_bytes,
                    &testcase.ciphertext[i],
                    step);
            total_pt_bytes += new_pt_bytes;
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            if (aead_ctx.bufstate.buffer_len < previous_buffer_len)
            {
                atto_eq(new_pt_bytes, ASCON_RATE);
            }
            else
            {
                atto_eq(new_pt_bytes, 0);
            }
            previous_buffer_len = aead_ctx.bufstate.buffer_len;
            remaining -= step;
            i += step;
        }
        new_pt_bytes = ascon_aead80pq_decrypt_final(&aead_ctx,
                                                    obtained_plaintext +
                                                    total_pt_bytes,
                                                    &is_valid, testcase.tag,
                                                    sizeof(testcase.tag));
        total_pt_bytes += new_pt_bytes;
        atto_lt(new_pt_bytes, ASCON_RATE);
        atto_eq(new_pt_bytes, testcase.plaintext_len % ASCON_RATE);
        atto_eq(total_pt_bytes, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
        atto_zeros(&aead_ctx, sizeof(aead_ctx));
    }
}

static void test_decrypt_update_var_bytes(void)
{
    vecs_ctx_t ctx;
    vecs_aead_t testcase;
    uint8_t obtained_plaintext[VECS_MAX_AEAD_PLAINTEXT_LEN];
    vecs_err_t errcode = vecs_init(&ctx, AEAD_VECTORS_FILE, KEY_LEN);
    atto_eq(errcode, VECS_OK);
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_bytes = 0;
    uint64_t total_pt_len = 0;
    bool is_valid;

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
        // Many 3-byte update calls
        ascon_aead80pq_init(&aead_ctx, testcase.key, testcase.nonce);
        size_t remaining;
        size_t step = 1;
        size_t i = 0;
        remaining = testcase.assoc_data_len;
        while (remaining)
        {
            step = MIN(remaining, step + 1);
            ascon_aead80pq_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                             step);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            remaining -= step;
            i += step;
        }
        i = 0;
        total_pt_len = 0;
        remaining = testcase.ciphertext_len;
        while (remaining)
        {
            step = MIN(remaining, step + 1);
            new_pt_bytes = ascon_aead80pq_decrypt_update(
                    &aead_ctx,
                    obtained_plaintext + total_pt_len,
                    &testcase.ciphertext[i],
                    step);
            total_pt_len += new_pt_bytes;
            atto_eq(aead_ctx.bufstate.buffer_len, (i + step) % ASCON_RATE);
            if (step > ASCON_RATE)
            {
                atto_ge(new_pt_bytes, ASCON_RATE);
            }
            remaining -= step;
            i += step;
        }
        new_pt_bytes = ascon_aead80pq_decrypt_final(&aead_ctx,
                                                    obtained_plaintext +
                                                    total_pt_len,
                                                    &is_valid, testcase.tag,
                                                    sizeof(testcase.tag));
        total_pt_len += new_pt_bytes;
        atto_lt(new_pt_bytes, ASCON_RATE);
        atto_eq(new_pt_bytes, testcase.plaintext_len % ASCON_RATE);
        atto_eq(total_pt_len, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
        atto_zeros(&aead_ctx, sizeof(aead_ctx));
    }
}

void test_aead80pq_decryption(void)
{
    test_decrypt_empty();
    test_decrypt_1_byte_ad_empty_pt();
    test_decrypt_1_byte_pt_empty_ad();
    test_decrypt_1_byte_pt_1_byte_ad();
    test_decrypt_offline();
    test_decrypt_update_single_byte();
    test_decrypt_offline_with_corrupted_data();
    test_decrypt_update_three_bytes();
    test_decrypt_update_var_bytes();
}
