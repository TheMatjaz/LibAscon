/**
 * @file
 * Tests of the AEAD128a decryption.
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
                    .tag = {
                            0x7A, 0x83, 0x4E, 0x6F, 0x09, 0x21, 0x09, 0x57,
                            0x06, 0x7B, 0x10, 0xFD, 0x83, 0x1F, 0x00, 0x78
                    },
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[1];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    // Offline
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    is_valid = ascon_aead128a_decrypt(
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
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    atto_eq(aead_ctx.bufstate.buffer_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx,
                                              obtained_plaintext,
                                              &plaintext_len,
                                              &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With AD update calls of zero length
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128a_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead128a_assoc_data_update(&aead_ctx, obtained_plaintext, 0);
    ascon_aead128a_assoc_data_update(&aead_ctx, NULL, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With PT update calls of zero length
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, obtained_plaintext,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With AD and PT update calls of zero length
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128a_assoc_data_update(&aead_ctx, NULL, 0);
    ascon_aead128a_assoc_data_update(&aead_ctx, obtained_plaintext, 0);
    ascon_aead128a_assoc_data_update(&aead_ctx, NULL, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, NULL, NULL, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, NULL,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, obtained_plaintext,
                                               obtained_plaintext, 0);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}


static void test_decrypt_1_byte_ad_empty_pt(void)
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
                    .tag = {
                            0xAF, 0x30, 0x31, 0xB0, 0x7B, 0x12, 0x9E, 0xC8,
                            0x41, 0x53, 0x37, 0x3D, 0xDC, 0xAB, 0xA5, 0x28
                    },
                    .ciphertext_len = 0,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[1];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    // Without PT call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128a_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With PT call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128a_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 0);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}

static void test_decrypt_1_byte_pt_empty_ad(void)
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
                    .ciphertext = {0x6E},
                    .tag = {
                            0x65, 0x2B, 0x55, 0xBF, 0xDC, 0x8C, 0xAD, 0x2E,
                            0xC4, 0x38, 0x15, 0xB1, 0x66, 0x6B, 0x1A, 0x3A
                    },
                    .ciphertext_len = 1,
            };
    atto_eq(testcase.plaintext_len,
            testcase.ciphertext_len);
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    // Without AD update call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);

    // With AD call
    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128a_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
}

static void test_decrypt_1_byte_pt_1_byte_ad(void)
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
                    .ciphertext = {0xE9},
                    .ciphertext_len = 1,
                    .tag = {
                            0xC2, 0x81, 0x3C, 0xC8, 0xC6, 0xDD, 0x2F, 0x24,
                            0x5F, 0x3B, 0xB9, 0x76, 0xDA, 0x56, 0x6E, 0x9D
                    },
            };
    atto_eq(testcase.plaintext_len, testcase.ciphertext_len);
    uint8_t obtained_plaintext[testcase.plaintext_len * 2];
    uint64_t plaintext_len = 0;
    ascon_aead_ctx_t aead_ctx;
    size_t new_pt_len = 0;
    bool is_valid;

    plaintext_len = 0;
    memset(obtained_plaintext, 0, sizeof(obtained_plaintext));
    ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
    ascon_aead128a_assoc_data_update(&aead_ctx, testcase.assoc_data,
                                     testcase.assoc_data_len);
    new_pt_len = ascon_aead128a_decrypt_update(&aead_ctx, obtained_plaintext,
                                               testcase.ciphertext,
                                               testcase.ciphertext_len);
    atto_eq(new_pt_len, 0);
    new_pt_len = ascon_aead128a_decrypt_final(&aead_ctx, obtained_plaintext,
                                              &plaintext_len, &is_valid,
                                              testcase.tag,
                                              sizeof(testcase.tag));
    vecs_aead_dec_log(&testcase, obtained_plaintext, plaintext_len);
    atto_eq(new_pt_len, 1);
    atto_eq(is_valid, ASCON_TAG_OK);
    atto_eq(plaintext_len, testcase.plaintext_len);
    atto_memeq(obtained_plaintext, testcase.plaintext, plaintext_len);
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
        const bool is_valid = ascon_aead128a_decrypt(
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
        // Many 1-byte update calls
        ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
        for (size_t i = 0; i < testcase.assoc_data_len; i++)
        {
            ascon_aead128a_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                             1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_DOUBLE_RATE);
        }
        for (size_t i = 0; i < testcase.ciphertext_len; i++)
        {
            new_pt_bytes = ascon_aead128a_decrypt_update(
                    &aead_ctx,
                    obtained_plaintext +
                    aead_ctx.bufstate.total_output_len,
                    &testcase.ciphertext[i],
                    1);
            atto_eq(aead_ctx.bufstate.buffer_len, (i + 1) % ASCON_DOUBLE_RATE);
            if (aead_ctx.bufstate.buffer_len == 0)
            {
                atto_eq(new_pt_bytes, ASCON_DOUBLE_RATE);
            }
            else
            {
                atto_eq(new_pt_bytes, 0);
            }
        }
        uint64_t total_pt_len = 0;
        new_pt_bytes = ascon_aead128a_decrypt_final(&aead_ctx,
                                                    obtained_plaintext +
                                                    aead_ctx.bufstate.total_output_len,
                                                    &total_pt_len,
                                                    &is_valid, testcase.tag,
                                                    sizeof(testcase.tag));
        atto_lt(new_pt_bytes, ASCON_DOUBLE_RATE);
        atto_eq(new_pt_bytes, testcase.plaintext_len % ASCON_DOUBLE_RATE);
        atto_eq(total_pt_len, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
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
        const bool is_valid = ascon_aead128a_decrypt(
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
        ascon_aead128a_init(&aead_ctx, testcase.key, testcase.nonce);
        size_t remaining;
        size_t step;
        size_t i = 0;
        remaining = testcase.assoc_data_len;
        while (remaining)
        {
            step = MIN(remaining, 3);
            ascon_aead128a_assoc_data_update(&aead_ctx, &testcase.assoc_data[i],
                                             step);
            atto_eq(aead_ctx.bufstate.buffer_len,
                    (i + step) % ASCON_DOUBLE_RATE);
            remaining -= step;
            i += step;
        }
        i = 0;
        size_t previous_buffer_len = 0;
        remaining = testcase.plaintext_len;
        while (remaining)
        {
            step = MIN(remaining, 3);
            new_pt_bytes = ascon_aead128a_decrypt_update(
                    &aead_ctx,
                    obtained_plaintext +
                    aead_ctx.bufstate.total_output_len,
                    &testcase.ciphertext[i],
                    step);
            atto_eq(aead_ctx.bufstate.buffer_len,
                    (i + step) % ASCON_DOUBLE_RATE);
            if (aead_ctx.bufstate.buffer_len < previous_buffer_len)
            {
                atto_eq(new_pt_bytes, ASCON_DOUBLE_RATE);
            }
            else
            {
                atto_eq(new_pt_bytes, 0);
            }
            previous_buffer_len = aead_ctx.bufstate.buffer_len;
            remaining -= step;
            i += step;
        }
        uint64_t total_pt_len = 0;
        new_pt_bytes = ascon_aead128a_decrypt_final(&aead_ctx,
                                                    obtained_plaintext +
                                                    aead_ctx.bufstate.total_output_len,
                                                    &total_pt_len,
                                                    &is_valid, testcase.tag,
                                                    sizeof(testcase.tag));
        atto_lt(new_pt_bytes, ASCON_DOUBLE_RATE);
        atto_eq(new_pt_bytes, testcase.plaintext_len % ASCON_DOUBLE_RATE);
        atto_eq(total_pt_len, testcase.plaintext_len);
        vecs_aead_dec_log(&testcase, obtained_plaintext,
                          testcase.plaintext_len);
        atto_eq(is_valid, ASCON_TAG_OK);
        atto_memeq(obtained_plaintext,
                   testcase.plaintext,
                   testcase.plaintext_len);
    }
}

void test_aead128a_decryption(void)
{
    test_decrypt_empty();
    test_decrypt_1_byte_ad_empty_pt();
    test_decrypt_1_byte_pt_empty_ad();
    test_decrypt_1_byte_pt_1_byte_ad();
    test_decrypt_offline();
    test_decrypt_update_single_byte();
    test_decrypt_offline_with_corrupted_data();
    test_decrypt_update_three_bytes();
}
