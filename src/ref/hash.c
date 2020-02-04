#include "ascon.h"
#include "permutations.h"

_Static_assert(ASCON_RATE <= 255,
               "Hash rate does not fit in a uint8_t. "
               "Please increase the s_ascon_hash_&ctx->state.buffer_len type.");

static void init(ascon_hash_ctx_t* const ctx, const uint64_t iv)
{
    ctx->state.x0 = iv;
    ctx->state.x1 = 0;
    ctx->state.x2 = 0;
    ctx->state.x3 = 0;
    ctx->state.x4 = 0;
    ctx->buffer_len = 0;
    printstate("initial value:", &ctx->state);
    ascon_permutation_a12(&ctx->state);
    printstate("initialization:", &ctx->state);
}

void inline ascon_hash_init(ascon_hash_ctx_t* const ctx)
{
    init(ctx, HASH_IV);
}

void inline ascon_hash_init_xof(ascon_hash_ctx_t* const ctx)
{
    init(ctx, XOF_IV);
}

void buffered_process(ascon_hash_ctx_t* const ctx,
                      const uint8_t* data,
                      size_t data_len)
{
    if (ctx->buffer_len > 0)
    {
        // There is data in the buffer already.
        // Place as much as possible of the new data into the buffer.
        const size_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const size_t into_buffer = MIN(space_in_buffer, data_len);
        memcpy(&ctx->buffer[ctx->buffer_len], data, into_buffer);
        ctx->buffer_len += into_buffer;
        data += into_buffer;
        data_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ASCON_RATE);
            ascon_permutation_a12(&ctx->state);
            ctx->buffer_len = 0;
        }
        else
        {
            // Do nothing.
            // The buffer contains some data, but it's not full yet
            // and there is no more data in this update call.
            // Keep it cached for the next update call or the digest call.
        }
    }
    else
    {
        // Do nothing.
        // The buffer contains no data, because this is the first update call
        // or because the last update had no less-than-a-block trailing data.
    }
    // Absorb remaining data (if any) one block at the time.
    while (data_len >= ASCON_RATE)
    {
        ctx->state.x0 ^= BYTES_TO_U64(data, ASCON_RATE);
        ascon_permutation_a12(&ctx->state);
        data_len -= ASCON_RATE;
        data += ASCON_RATE;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (data_len > 0)
    {
        memcpy(&ctx->buffer, data, data_len);
        ctx->buffer_len = data_len;
    }
}

void ascon_hash_update(ascon_hash_ctx_t* const ctx,
                       const uint8_t* data,
                       size_t data_len)
{
    if (ctx->buffer_len > 0)
    {
        // There is data in the buffer already.
        // Place as much as possible of the new data into the buffer.
        const size_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const size_t into_buffer = MIN(space_in_buffer, data_len);
        memcpy(&ctx->buffer[ctx->buffer_len], data, into_buffer);
        ctx->buffer_len += into_buffer;
        data += into_buffer;
        data_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ASCON_RATE);
            ascon_permutation_a12(&ctx->state);
            ctx->buffer_len = 0;
        }
        else
        {
            // Do nothing.
            // The buffer contains some data, but it's not full yet
            // and there is no more data in this update call.
            // Keep it cached for the next update call or the digest call.
        }
    }
    else
    {
        // Do nothing.
        // The buffer contains no data, because this is the first update call
        // or because the last update had no less-than-a-block trailing data.
    }
    // Absorb remaining data (if any) one block at the time.
    while (data_len >= ASCON_RATE)
    {
        ctx->state.x0 ^= BYTES_TO_U64(data, ASCON_RATE);
        ascon_permutation_a12(&ctx->state);
        data_len -= ASCON_RATE;
        data += ASCON_RATE;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (data_len > 0)
    {
        memcpy(&ctx->buffer, data, data_len);
        ctx->buffer_len = data_len;
    }
}

void ascon_hash_final_xof(ascon_hash_ctx_t* const ctx,
                          uint8_t* digest,
                          size_t digest_size)
{
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
    ctx->state.x0 ^= PADDING(ctx->buffer_len);
    // Squeeze the digest from the inner state.
    while (digest_size > ASCON_RATE)
    {
        ascon_permutation_a12(&ctx->state);
        U64_TO_BYTES(digest, ctx->state.x0, ASCON_RATE);
        digest_size -= ASCON_RATE;
        digest += ASCON_RATE;
    }
    ascon_permutation_a12(&ctx->state);
    U64_TO_BYTES(digest, ctx->state.x0, digest_size);
    // Final security cleanup of the internal state and buffer.
    memset(ctx, 0, sizeof(ascon_hash_ctx_t));
}


void inline ascon_hash_final(ascon_hash_ctx_t* const ctx, uint8_t* digest)
{
    ascon_hash_final_xof(ctx, digest, ASCON_HASH_DIGEST_SIZE);
}
