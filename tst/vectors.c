/**
 * @file
 */

#include "vectors.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#define DIGEST_HEX_CHAR_LEN 64

vecs_err_t vecs_hash_init(vecs_ctx_t* ctx, const char* file_name)
{
    ctx->handle = fopen(file_name, "r");
    if (ctx->handle == NULL)
    {
        return VECS_IO_CANNOT_OPEN_FILE;
    }
    return VECS_OK;
}

static vecs_err_t fscan_hexbytes(FILE* handle, uint8_t bytes[], size_t amount)
{
    for (size_t i = 0; i < amount; i++)
    {
        uint8_t a_byte;
        const int bytes_read = fscanf(handle, " %2hhx ", &a_byte);
        if (bytes_read != 1)
        {
            return VECS_FORMAT_TOO_SHORT_HEXBYTES;
        }
        else
        {
            bytes[i] = a_byte;
        }
    }
    return VECS_OK;
}

vecs_err_t vecs_hash_next(vecs_ctx_t* ctx, vecs_hash_t* testcase)
{
    vecs_err_t errcode = VECS_OK;
    unsigned int count = 1;
    size_t obtained_len;
    if (feof(ctx->handle))
    {
        errcode = VECS_EOF;
        goto termination;
    }
    obtained_len = fscanf(ctx->handle, " Count = %u ", &count);
    if (obtained_len != 1)
    {
        errcode = VECS_FORMAT_INCORRECT_COUNT_HDR;
        goto termination;
    }
    testcase->plaintext_len = count - 1;
    if (testcase->plaintext_len > VECS_MAX_PLAINTEXT_SIZE)
    {
        errcode = VECS_FORMAT_TOO_LARGE_PLAINTEXT;
        goto termination;
    }
    obtained_len = fscanf(ctx->handle, " Msg = ");
    if (obtained_len != 0)
    {
        errcode = VECS_FORMAT_INCORRECT_MSG_HDR;
        goto termination;
    }
    errcode = fscan_hexbytes(ctx->handle, testcase->plaintext,
                             testcase->plaintext_len);
    if (errcode != VECS_OK)
    {
        errcode = VECS_FORMAT_TOO_SHORT_PLAINTEXT;
        goto termination;
    }
    obtained_len = fscanf(ctx->handle, " MD = ");
    if (obtained_len != 0)
    {
        errcode = VECS_FORMAT_INCORRECT_DIGEST_HDR;
        goto termination;
    }
    errcode = fscan_hexbytes(ctx->handle, testcase->expected_digest,
                             ASCON_XOF_DIGEST_SIZE);
    if (errcode != VECS_OK)
    {
        errcode = VECS_FORMAT_TOO_SHORT_DIGEST;
        goto termination;
    }
    fscanf(ctx->handle, " ");  // Discard any trailing whitespace
    termination:
    {
        if (errcode != VECS_OK)
        {
            fclose(ctx->handle);
        }
        return errcode;
    }
}
