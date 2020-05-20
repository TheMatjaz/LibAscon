/**
 * @file
 * Implementation of buffering used for the Init-Update-Final paradigm
 * of both the AEAD ciphers and hashing.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include <stdint.h>
#include <stddef.h>
#include "ascon.h"
#include "ascon_internal.h"

/**
 * @internal
 * Simplistic clone of memcpy for small arrays.
 *
 * It should work faster than memcpy for very small amounts of bytes given
 * the reduced overhead.
 */
inline static void smallcpy(uint8_t* dst, const uint8_t* src, uint8_t amount)
{
    while (amount--)
    {
        *(dst++) = *(src++);
    }
}

uint64_t bytes_to_u64(const uint8_t* const bytes, const uint_fast8_t n)
{
    uint64_t x = 0;
    for (uint_fast8_t i = 0; i < n; i++)
    {
        // Cast to unsigned int to remove warning about <<-operator with signed
        // value. uint_fast8_t does not work, so unsigned int should be the
        // fastest unsigned type on a machine.
        x |= ((uint64_t) bytes[i]) << (56 - 8 * (unsigned int) i);
    }
    return x;
}

void u64_to_bytes(uint8_t* const bytes, const uint64_t x, const uint_fast8_t n)
{
    for (uint_fast8_t i = 0; i < n; i++)
    {
        // Cast to unsigned int to remove warning about <<-operator with signed
        // value. uint_fast8_t does not work, so unsigned int should be the
        // fastest unsigned type on a machine.
        bytes[i] = (uint8_t) (x >> (56 - 8 * (unsigned int) i));
    }
}

uint64_t byte_mask(const uint_fast8_t n)
{
    uint64_t x = 0;
    for (uint_fast8_t i = 0; i < n; i++)
    {
        // Cast to unsigned int to remove warning about <<-operator with signed
        // value. uint_fast8_t does not work, so unsigned int should be the
        // fastest unsigned type on a machine.
        x |= 0xFFULL << (56 - 8 * (unsigned int) i);
    }
    return x;
}

size_t buffered_accumulation(ascon_bufstate_t* const ctx,
                             uint8_t* data_out,
                             const uint8_t* data_in,
                             absorb_fptr absorb,
                             size_t data_in_len,
                             const uint8_t rate)
{
    size_t fresh_out_bytes = 0;
    if (ctx->buffer_len > 0)
    {
        // There is associated data in the buffer already.
        // Place as much as possible of the new associated data into the buffer.
        const uint8_t space_in_buf = (uint8_t) (rate - ctx->buffer_len);
        const uint8_t into_buffer = (uint8_t) MIN(space_in_buf, data_in_len);
        smallcpy(&ctx->buffer[ctx->buffer_len], data_in, into_buffer);
        ctx->buffer_len = (uint8_t) (ctx->buffer_len + into_buffer);
        data_in += into_buffer;
        data_in_len -= into_buffer;
        if (ctx->buffer_len == rate)
        {
            // The buffer was filled completely, thus absorb it.
            absorb(&ctx->sponge, data_out, ctx->buffer);
            ctx->buffer_len = 0;
            data_out += rate;
            fresh_out_bytes += rate;
        }
        else
        {
            // Do nothing.
            // The buffer contains some associated data, but it's not full yet
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
    while (data_in_len >= rate)
    {
        absorb(&ctx->sponge, data_out, data_in);
        data_out += rate;
        data_in += rate;
        data_in_len -= rate;
        fresh_out_bytes += rate;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (data_in_len > 0)
    {
        smallcpy(ctx->buffer, data_in, (uint8_t) data_in_len);
        ctx->buffer_len = (uint8_t) data_in_len;
    }
    ctx->total_output_len += fresh_out_bytes;
    return fresh_out_bytes;
}
