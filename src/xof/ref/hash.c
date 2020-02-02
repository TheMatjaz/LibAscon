#include "ascon.h"
#include "permutations.h"
#include <string.h>

#define PA_ROUNDS 12
#define IV ((uint64_t)(8 * (ASCON_XOF_RATE)) << 48 | (uint64_t)(PA_ROUNDS) << 40)
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

void ascon_xof_init(ascon_xof_ctx_t* const ctx)
{
    ctx->x0 = IV;
    ctx->x1 = 0;
    ctx->x2 = 0;
    ctx->x3 = 0;
    ctx->x4 = 0;
    ctx->buffer_len = 0;
    printstate("initial value:", ctx);
    P12(ctx);
    printstate("initialization:", ctx);
}

void ascon_xof_update(ascon_xof_ctx_t* const ctx,
                      const uint8_t* data,
                      size_t data_len)
{
    if (ctx->buffer_len > 0)
    {
        // There is data in the buffer already.
        // Place as much as possible of the new data into the buffer.
        const size_t space_in_buffer = ASCON_XOF_RATE - ctx->buffer_len;
        const size_t into_buffer = MIN(space_in_buffer, data_len);
        memcpy(&ctx->buffer[ctx->buffer_len], data, into_buffer);
        ctx->buffer_len += into_buffer;
        data += into_buffer;
        data_len -= into_buffer;
        if (ctx->buffer_len == ASCON_XOF_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->x0 ^= BYTES_TO_U64(ctx->buffer, ASCON_XOF_RATE);
            P12(ctx);
            ctx->buffer_len = 0;
        }
        else
        {
            // TODO assert(ctx->buffer_len < ASCON_XOF_RATE);
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
    while (data_len >= ASCON_XOF_RATE)
    {
        ctx->x0 ^= BYTES_TO_U64(data, ASCON_XOF_RATE);
        P12(ctx);
        data_len -= ASCON_XOF_RATE;
        data += ASCON_XOF_RATE;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (data_len > 0)
    {
        memcpy(&ctx->buffer, data, data_len);
        ctx->buffer_len = data_len;
    }
}

void ascon_xof_final(ascon_xof_ctx_t* const ctx, uint8_t* digest)
{
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->x0 ^= BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
    ctx->x0 ^= 0x80ULL << (56 - 8 * (size_t) ctx->buffer_len);
    // Squeeze the digest from the inner state.
    // TODO What about custom tag length passed by user?
    size_t outlen = ASCON_XOF_DIGEST_SIZE;
    while (outlen > ASCON_XOF_RATE)
    {
        P12(ctx);
        U64_TO_BYTES(digest, ctx->x0, ASCON_XOF_RATE);
        outlen -= ASCON_XOF_RATE;
        digest += ASCON_XOF_RATE;
    }
    P12(ctx);
    U64_TO_BYTES(digest, ctx->x0, ASCON_XOF_RATE);
    // Final security cleanup of the internal state and buffer.
    memset(ctx, 0, sizeof(ascon_xof_ctx_t));
}
