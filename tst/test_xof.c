/**
 * @file
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"
#include "vectors.h"

#define XOF_VECTORS_FILE "vectors/xof.txt"


static void test_xof_batch(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_XOF_DIGEST_SIZE];
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
        ascon_xof(obtained_digest, testcase.message, testcase.message_len);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_XOF_DIGEST_SIZE);
    }
}

static void test_xof_update_single_byte(void)
{
    vecs_ctx_t ctx;
    vecs_hash_t testcase;
    uint8_t obtained_digest[ASCON_XOF_DIGEST_SIZE];
    vecs_err_t errcode = vecs_init(&ctx, XOF_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);
    ascon_xof_ctx_t xof_ctx;
    ascon_xof_init(&xof_ctx);

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        for (size_t i = 0; i < testcase.message_len; i++)
        {
            ascon_xof_update(&xof_ctx, &testcase.message[i], 1);
        }
        ascon_xof_final(&xof_ctx, obtained_digest);
        atto_memeq(obtained_digest,
                   testcase.expected_digest,
                   ASCON_XOF_DIGEST_SIZE);
    }
}

void test_xof(void)
{
    test_xof_batch();
    test_xof_update_single_byte();
}
