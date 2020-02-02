/**
 * @file
 */

#include "vectors.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "ascon.h"

vecs_err_t vecs_init(vecs_ctx_t* const ctx, const char* const file_name)
{
    ctx->handle = fopen(file_name, "r");
    if (ctx->handle == NULL)
    {
        return VECS_IO_CANNOT_OPEN_FILE;
    }
    return VECS_OK;
}

static vecs_err_t fscan_exact_hexbytes(FILE* const handle,
                                       uint8_t* bytes,
                                       const size_t amount)
{
    for (size_t i = 0; i < amount; i++)
    {
        const int bytes_read = fscanf(handle, " %2hhx ", bytes++);
        if (bytes_read != 1)
        {
            return VECS_FORMAT_TOO_SHORT_HEXBYTES;
        }
    }
    return VECS_OK;
}

static vecs_err_t fscan_variable_hexbytes(FILE* const handle,
                                          uint8_t* bytes,
                                          size_t* amount)
{
    size_t i = 0;
    while (1)
    {
        if (i >= VECS_MAX_HEXBYTES)
        {
            return VECS_FORMAT_TOO_LARGE_HEXBYTES;
        }
        const int bytes_read = fscanf(handle, " %2hhx", bytes++);
        if (bytes_read != 1)
        {
            break;
        }
        i++;
    }
    *amount = i;
    return VECS_OK;
}

static vecs_err_t fscan_count_hash(vecs_ctx_t* const ctx,
                                   vecs_hash_t* const testcase)
{
    unsigned int count = 1;
    size_t obtained_len = fscanf(ctx->handle, " Count = %u ", &count);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_COUNT_HDR;
    }
    testcase->message_len = count - 1;
    if (testcase->message_len > VECS_MAX_HASH_MESSAGE_SIZE)
    {
        return VECS_FORMAT_TOO_LARGE_PLAINTEXT;
    }
    return VECS_OK;
}

static vecs_err_t fscan_msg(vecs_ctx_t* const ctx,
                            vecs_hash_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " Msg = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_MESSAGE_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->message,
                                                    testcase->message_len);
    if (errcode != VECS_OK)
    {
        return VECS_FORMAT_TOO_SHORT_PLAINTEXT;
    }
    return VECS_OK;
}

static vecs_err_t fscan_digest(vecs_ctx_t* const ctx,
                               vecs_hash_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " MD = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_DIGEST_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->expected_digest,
                                                    ASCON_XOF_DIGEST_SIZE);
    if (errcode != VECS_OK)
    {
        return VECS_FORMAT_TOO_SHORT_DIGEST;
    }
    return VECS_OK;
}

vecs_err_t vecs_hash_next(vecs_ctx_t* const ctx, vecs_hash_t* const testcase)
{
    vecs_err_t errcode;
    if (feof(ctx->handle))
    {
        errcode = VECS_EOF;
        goto termination;
    }
    errcode = fscan_count_hash(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_msg(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_digest(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
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

static vecs_err_t fscan_count_aead(vecs_ctx_t* const ctx,
                                   vecs_aead_t* const testcase)
{
    unsigned int count = 1;
    size_t obtained_len = fscanf(ctx->handle, " Count = %u ", &count);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_COUNT_HDR;
    }
    return VECS_OK;
}

static vecs_err_t fscan_key(vecs_ctx_t* const ctx,
                            vecs_aead_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " Key = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_KEY_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->key,
                                                    ASCON_AEAD_KEY_SIZE);
    if (errcode != VECS_OK)
    {
        return VECS_FORMAT_TOO_SHORT_KEY;
    }
    return VECS_OK;
}

static vecs_err_t fscan_nonce(vecs_ctx_t* const ctx,
                              vecs_aead_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " Nonce = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_NONCE_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->nonce,
                                                    ASCON_AEAD_NONCE_SIZE);
    if (errcode != VECS_OK)
    {
        return VECS_FORMAT_TOO_SHORT_NONCE;
    }
    return VECS_OK;
}

static vecs_err_t fscan_plaintext(vecs_ctx_t* const ctx,
                                  vecs_aead_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " PT = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_PLAINTEXT_HDR;
    }
    return fscan_variable_hexbytes(ctx->handle, testcase->plaintext,
                                   &testcase->plaintext_len);
}

static vecs_err_t fscan_assoc_data(vecs_ctx_t* const ctx,
                                   vecs_aead_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " AD = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_ASSOC_DATA_HDR;
    }
    return fscan_variable_hexbytes(ctx->handle, testcase->assoc_data,
                                   &testcase->assoc_data_len);
}

static vecs_err_t fscan_ciphertext(vecs_ctx_t* const ctx,
                                   vecs_aead_t* const testcase)
{
    const size_t obtained_len = fscanf(ctx->handle, " CT = ");
    if (obtained_len != 0)
    {
        return VECS_FORMAT_INCORRECT_CIPHERTEXT_HDR;
    }
    return fscan_variable_hexbytes(ctx->handle, testcase->expected_ciphertext,
                                   &testcase->ciphertext_len);
}

vecs_err_t vecs_aead_next(vecs_ctx_t* const ctx, vecs_aead_t* const testcase)
{
    vecs_err_t errcode;
    if (feof(ctx->handle))
    {
        errcode = VECS_EOF;
        goto termination;
    }
    errcode = fscan_count_aead(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_key(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_nonce(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_plaintext(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_assoc_data(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
    errcode = fscan_ciphertext(ctx, testcase);
    if (errcode != VECS_OK) { goto termination; }
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

static void log_hexbytes(const char* const name,
                       const uint8_t* const array,
                       const size_t amount)
{
    printf("%s (%zu B): ", name, amount);
    for (size_t i = 0; i < amount; i++)
    {
        printf("%02X", array[i]);
    }
    puts("");
}

void vecs_hash_log(const vecs_hash_t* const testcase,
                   const uint8_t* const obtained_digest)
{
#ifdef DEBUG
    log_hexbytes("Msg", testcase->message, testcase->message_len);
    log_hexbytes("Expected digest", testcase->expected_digest,
                      ASCON_HASH_DIGEST_SIZE);
    if (obtained_digest != NULL)
    {
        log_hexbytes("Obtained digest", obtained_digest,
                          ASCON_HASH_DIGEST_SIZE);
    }
    fflush(stdout);
#else
    (void) testcase;
    (void) obtained_digest;
#endif
}
