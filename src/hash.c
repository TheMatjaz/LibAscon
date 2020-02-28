/**
 * @file
 * Implementation of Ascon-Hash and Ascon-Xof.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "internal.h"

void init(ascon_hash_ctx_t* const ctx, const uint64_t iv)
{
    ctx->sponge.x0 = iv;
    ctx->sponge.x1 = 0;
    ctx->sponge.x2 = 0;
    ctx->sponge.x3 = 0;
    ctx->sponge.x4 = 0;
    ctx->buffer_len = 0;
    log_sponge("initial value:", &ctx->sponge);
    ascon_permutation_a12(&ctx->sponge);
    log_sponge("initialization:", &ctx->sponge);
}

void inline ascon_hash_init(ascon_hash_ctx_t* const ctx)
{
    init(ctx, HASH_IV);
}

void inline ascon_hash_xof_init(ascon_hash_ctx_t* const ctx)
{
    init(ctx, XOF_IV);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb data to be hashed.
 */
void absorb_hash_data(ascon_sponge_t* const sponge,
                      uint8_t* const data_out,
                      const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bytes_to_u64(data, ASCON_RATE);
    ascon_permutation_a12(sponge);
}

void inline ascon_hash_update(ascon_hash_ctx_t* const ctx,
                              const uint8_t* data,
                              size_t data_len)
{
    buffered_accumulation(ctx, NULL, data, absorb_hash_data, data_len);
}


void inline ascon_hash_xof_update(ascon_hash_ctx_t* const ctx,
                                  const uint8_t* data,
                                  size_t data_len)
{
    buffered_accumulation(ctx, NULL, data, absorb_hash_data, data_len);
}

void ascon_hash_xof_final(ascon_hash_ctx_t* const ctx,
                          uint8_t* digest,
                          size_t digest_len)
{
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->sponge.x0 ^= bytes_to_u64(ctx->buffer, ctx->buffer_len);
    ctx->sponge.x0 ^= PADDING(ctx->buffer_len);
    // Squeeze the digest from the inner state.
    while (digest_len > ASCON_RATE)
    {
        ascon_permutation_a12(&ctx->sponge);
        u64_to_bytes(digest, ctx->sponge.x0, ASCON_RATE);
        digest_len -= ASCON_RATE;
        digest += ASCON_RATE;
    }
    ascon_permutation_a12(&ctx->sponge);
    u64_to_bytes(digest, ctx->sponge.x0, (uint_fast8_t) digest_len);
    // Final security cleanup of the internal state and buffer.
    ascon_hash_cleanup(ctx);
}

void inline ascon_hash_final(ascon_hash_ctx_t* const ctx,
                             uint8_t digest[ASCON_HASH_DIGEST_LEN])
{
    ascon_hash_xof_final(ctx, digest, ASCON_HASH_DIGEST_LEN);
}
