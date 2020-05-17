/**
 * @file
 * Implementation of the test vectors file iterator.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
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
        if (i >= VECS_MAX_HEXBYTES_LEN)
        {
            return VECS_FORMAT_TOO_LARGE_HEXBYTES;
        }
        const int bytes_read = fscanf(handle, " %2hhx ", bytes++);
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
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " %s = %u ", string, &count);
    if (obtained_len != 2)
    {
        return VECS_FORMAT_INCORRECT_COUNT_HDR;
    }
    if (memcmp(string, "Count", 5) != 0)
    {
        return VECS_FORMAT_INCORRECT_COUNT_HDR;
    }
    testcase->message_len = count - 1;
    if (testcase->message_len > VECS_MAX_HASH_MESSAGE_LEN)
    {
        return VECS_FORMAT_TOO_LARGE_PLAINTEXT;
    }
    testcase->count = count;
    return VECS_OK;
}

static vecs_err_t fscan_msg(vecs_ctx_t* const ctx,
                            vecs_hash_t* const testcase)
{
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " %s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_MESSAGE_HDR;
    }
    if (memcmp(string, "Msg", 3) != 0)
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
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " %s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_DIGEST_HDR;
    }
    if (memcmp(string, "MD", 2) != 0)
    {
        return VECS_FORMAT_INCORRECT_DIGEST_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->expected_digest,
                                                    ASCON_HASH_DIGEST_LEN);
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
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " _%s = %u ", string, &count);
    if (obtained_len != 2)
    {
        return VECS_FORMAT_INCORRECT_COUNT_HDR;
    }
    if (memcmp(string, "Count", 5) != 0)
    {
        return VECS_FORMAT_INCORRECT_COUNT_HDR;
    }
    testcase->count = count;
    return VECS_OK;
}

static vecs_err_t fscan_key(vecs_ctx_t* const ctx,
                            vecs_aead_t* const testcase)
{
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " _%s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_KEY_HDR;
    }
    if (memcmp(string, "Key", 3) != 0)
    {
        return VECS_FORMAT_INCORRECT_KEY_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->key,
                                                    ASCON_AEAD_KEY_LEN);
    if (errcode != VECS_OK)
    {
        return VECS_FORMAT_TOO_SHORT_KEY;
    }
    return VECS_OK;
}

static vecs_err_t fscan_nonce(vecs_ctx_t* const ctx,
                              vecs_aead_t* const testcase)
{
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " _%s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_NONCE_HDR;
    }
    if (memcmp(string, "Nonce", 5) != 0)
    {
        return VECS_FORMAT_INCORRECT_NONCE_HDR;
    }
    const vecs_err_t errcode = fscan_exact_hexbytes(ctx->handle,
                                                    testcase->nonce,
                                                    ASCON_AEAD_NONCE_LEN);
    if (errcode != VECS_OK)
    {
        return VECS_FORMAT_TOO_SHORT_NONCE;
    }
    return VECS_OK;
}

static vecs_err_t fscan_plaintext(vecs_ctx_t* const ctx,
                                  vecs_aead_t* const testcase)
{
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " _%s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_PLAINTEXT_HDR;
    }
    if (memcmp(string, "PT", 2) != 0)
    {
        return VECS_FORMAT_INCORRECT_PLAINTEXT_HDR;
    }
    return fscan_variable_hexbytes(ctx->handle, testcase->plaintext,
                                   &testcase->plaintext_len);
}

static vecs_err_t fscan_assoc_data(vecs_ctx_t* const ctx,
                                   vecs_aead_t* const testcase)
{
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " _%s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_ASSOC_DATA_HDR;
    }
    if (memcmp(string, "AD", 2) != 0)
    {
        return VECS_FORMAT_INCORRECT_ASSOC_DATA_HDR;
    }
    return fscan_variable_hexbytes(ctx->handle, testcase->assoc_data,
                                   &testcase->assoc_data_len);
}

static vecs_err_t fscan_ciphertext(vecs_ctx_t* const ctx,
                                   vecs_aead_t* const testcase)
{
    char string[10];
    const int obtained_len = fscanf(ctx->handle, " _%s = ", string);
    if (obtained_len != 1)
    {
        return VECS_FORMAT_INCORRECT_CIPHERTEXT_HDR;
    }
    if (memcmp(string, "CT", 2) != 0)
    {
        return VECS_FORMAT_INCORRECT_CIPHERTEXT_HDR;
    }
    vecs_err_t errcode = fscan_variable_hexbytes(
            ctx->handle,
            testcase->ciphertext,
            &testcase->ciphertext_len);
    if (errcode != VECS_OK)
    {
        return errcode;
    }
    if (testcase->ciphertext_len < ASCON_AEAD_TAG_MIN_SECURE_LEN)
    {
        return VECS_FORMAT_TOO_SHORT_CIPHERTEXT;
    }
    testcase->ciphertext_len -= ASCON_AEAD_TAG_MIN_SECURE_LEN;
    memcpy(testcase->tag,
           &testcase->ciphertext[testcase->ciphertext_len],
           ASCON_AEAD_TAG_MIN_SECURE_LEN);
    return VECS_OK;
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

#ifdef DEBUG
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
#endif

void vecs_hash_log(const vecs_hash_t* const testcase,
                   const uint8_t* const obtained_digest)
{
#ifdef DEBUG
    log_hexbytes("Msg", testcase->message, testcase->message_len);
    log_hexbytes("Expected digest", testcase->expected_digest,
                 ASCON_HASH_DIGEST_LEN);
    if (obtained_digest != NULL)
    {
        log_hexbytes("Obtained digest", obtained_digest,
                     ASCON_HASH_DIGEST_LEN);
    }
    fflush(stdout);
#else
    (void) testcase;
    (void) obtained_digest;
#endif
}

void vecs_aead_enc_log(const vecs_aead_t* const testcase,
                       const uint8_t* const obtained_ciphertext,
                       const uint8_t* const obtained_tag,
                       const uint64_t obtained_ciphertext_len)
{
#ifdef DEBUG
    printf("---\nCount: %zu\n", testcase->count);
    log_hexbytes("Key", testcase->key, ASCON_AEAD_KEY_LEN);
    log_hexbytes("Nonce", testcase->nonce, ASCON_AEAD_NONCE_LEN);
    log_hexbytes("AD", testcase->assoc_data, testcase->assoc_data_len);
    log_hexbytes("PT", testcase->plaintext, testcase->plaintext_len);
    log_hexbytes("Expected CT", testcase->ciphertext,
                 testcase->ciphertext_len);
    if (obtained_ciphertext != NULL)
    {
        log_hexbytes("Obtained CT", obtained_ciphertext,
                     obtained_ciphertext_len);
    }
    log_hexbytes("Expected tag", testcase->tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    if (obtained_tag != NULL)
    {
        log_hexbytes("Obtained tag", obtained_tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    }
    fflush(stdout);
#else
    (void) testcase;
    (void) obtained_ciphertext;
    (void) obtained_tag;
    (void) obtained_ciphertext_len;
#endif
}

void vecs_aead_dec_log(const vecs_aead_t* const testcase,
                       const uint8_t* const obtained_plaintext,
                       const uint64_t obtained_plaintext_len)
{
#ifdef DEBUG
    printf("---\nCount: %zu\n", testcase->count);
    log_hexbytes("Key", testcase->key, ASCON_AEAD_KEY_LEN);
    log_hexbytes("Nonce", testcase->nonce, ASCON_AEAD_NONCE_LEN);
    log_hexbytes("AD", testcase->assoc_data, testcase->assoc_data_len);
    log_hexbytes("CT", testcase->ciphertext, testcase->ciphertext_len);
    log_hexbytes("Expected PT", testcase->plaintext, testcase->plaintext_len);
    if (obtained_plaintext != NULL)
    {
        log_hexbytes("Obtained CT", obtained_plaintext,
                     obtained_plaintext_len);
    }
    log_hexbytes("Expected tag", testcase->tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    fflush(stdout);
#else
    (void) testcase;
    (void) obtained_plaintext;
    (void) obtained_plaintext_len;
#endif
}
