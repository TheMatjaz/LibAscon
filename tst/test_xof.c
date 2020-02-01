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
    vecs_err_t errcode = vecs_hash_init(&ctx, XOF_VECTORS_FILE);
    atto_eq(errcode, VECS_OK);

    while (1)
    {
        errcode = vecs_hash_next(&ctx, &testcase);
        if (errcode == VECS_EOF)
        {
            break;
        }
        atto_eq(errcode, VECS_OK);
        ascon_xof(obtained_digest, testcase.plaintext, testcase.plaintext_len);
        atto_memeq(obtained_digest, testcase.expected_digest,
                   ASCON_XOF_DIGEST_SIZE);
    }
}

void test_xof(void)
{
    test_xof_batch();
}
