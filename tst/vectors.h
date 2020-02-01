/**
 * @file
 */

#ifndef VECTORS_H
#define VECTORS_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "ascon.h"

#define VECS_MAX_PLAINTEXT_SIZE 1024

typedef enum
{
    VECS_OK = 0,
    VECS_EOF = -1,
    VECS_IO_CANNOT_OPEN_FILE = 1,
    VECS_FORMAT_INCORRECT_COUNT_HDR = 2,
    VECS_FORMAT_TOO_LARGE_PLAINTEXT = 3,
    VECS_FORMAT_TOO_SHORT_HEXBYTES = 4,
    VECS_FORMAT_INCORRECT_MSG_HDR = 5,
    VECS_FORMAT_INCORRECT_DIGEST_HDR = 6,
    VECS_FORMAT_TOO_SHORT_PLAINTEXT = 7,
    VECS_FORMAT_TOO_SHORT_DIGEST = 8,
} vecs_err_t;

typedef struct
{
    uint8_t plaintext[VECS_MAX_PLAINTEXT_SIZE];
    uint8_t expected_digest[ASCON_XOF_DIGEST_SIZE];
    size_t plaintext_len;
} vecs_hash_t;

typedef struct
{
    FILE* handle;
} vecs_ctx_t;

vecs_err_t vecs_hash_init(vecs_ctx_t* ctx, const char* file_name);
vecs_err_t vecs_hash_next(vecs_ctx_t* ctx, vecs_hash_t* testcase);

#ifdef __cplusplus
}
#endif

#endif  /* VECTORS_H */
