/**
 * @file
 */

#include <stdint.h>
#include <stddef.h>
#include "ascon.h"
#include "internal.h"

#ifdef DEBUG_PERMUTATIONS
#include <stdio.h>
#endif

static const uint8_t ROUND_CONSTANTS[] = {
        // 12-round starts here, index 0
        0xf0, 0xe1, 0xd2, 0xc3,
        // 8-round starts here, index 4
        0xb4, 0xa5,
        // 6-round starts here, index 6
        0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};
#define ROUND_CONSTANTS_AMOUNT 12
#define PERMUTATION_12_START 0
#define PERMUTATION_8_START 4
#define PERMUTATION_6_START 6

void inline printstate(const char* text, const ascon_sponge_t* sponge)
{
#ifdef DEBUG_PERMUTATIONS
    printf("%s sponge\n", text);
    printf("  x0=%016llx\n", sponge->x0);
    printf("  x1=%016llx\n", sponge->x1);
    printf("  x2=%016llx\n", sponge->x2);
    printf("  x3=%016llx\n", sponge->x3);
    printf("  x4=%016llx\n", sponge->x4);
#else
    // disable warning about unused parameters
    (void) text;
    (void) sponge;
#endif
}

static inline uint64_t rotr64(const uint64_t x, const uint_fast8_t n)
{
    // Cast to uint8_t to remove warning about <<-operator with signed value
    return (x << (uint8_t) (64 - n)) | (x >> n);
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

void inline smallcpy(uint8_t* dst, const uint8_t* src, uint8_t amount)
{
    while (amount--)
    {
        *(dst++) = *(src++);
    }
}

static void ascon_round(ascon_sponge_t* const p, const uint_fast8_t round_const)
{
    // TODO this function leaves sponge traces on the stack in sponge and t structs
    ascon_sponge_t sponge = *p;
    ascon_sponge_t t;
    // addition of round constant
    sponge.x2 ^= round_const;
    printstate(" addition of round constant:", &sponge);
    // substitution layer
    sponge.x0 ^= sponge.x4;
    sponge.x4 ^= sponge.x3;
    sponge.x2 ^= sponge.x1;
    // start of keccak s-box
    t.x0 = ~sponge.x0;
    t.x1 = ~sponge.x1;
    t.x2 = ~sponge.x2;
    t.x3 = ~sponge.x3;
    t.x4 = ~sponge.x4;
    t.x0 &= sponge.x1;
    t.x1 &= sponge.x2;
    t.x2 &= sponge.x3;
    t.x3 &= sponge.x4;
    t.x4 &= sponge.x0;
    sponge.x0 ^= t.x1;
    sponge.x1 ^= t.x2;
    sponge.x2 ^= t.x3;
    sponge.x3 ^= t.x4;
    sponge.x4 ^= t.x0;
    // end of keccak s-box
    sponge.x1 ^= sponge.x0;
    sponge.x0 ^= sponge.x4;
    sponge.x3 ^= sponge.x2;
    sponge.x2 = ~sponge.x2;
    printstate(" substitution layer:", &sponge);
    // linear diffusion layer
    sponge.x0 ^= rotr64(sponge.x0, 19) ^ rotr64(sponge.x0, 28);
    sponge.x1 ^= rotr64(sponge.x1, 61) ^ rotr64(sponge.x1, 39);
    sponge.x2 ^= rotr64(sponge.x2, 1) ^ rotr64(sponge.x2, 6);
    sponge.x3 ^= rotr64(sponge.x3, 10) ^ rotr64(sponge.x3, 17);
    sponge.x4 ^= rotr64(sponge.x4, 7) ^ rotr64(sponge.x4, 41);
    printstate(" linear diffusion layer:", &sponge);
    *p = sponge;
    // TODO erase sponge and t
}

void inline ascon_permutation_a12(ascon_sponge_t* const sponge)
{
    printstate(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_12_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

void inline ascon_permutation_8(ascon_sponge_t* const sponge)
{
    printstate(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_8_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

void inline ascon_permutation_b6(ascon_sponge_t* const sponge)
{
    printstate(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_6_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

size_t buffered_accumulation(ascon_bufstate_t* const ctx,
                             uint8_t* data_out,
                             const uint8_t* data_in,
                             absorb_fptr absorb,
                             size_t data_in_len)
{
    size_t fresh_out_bytes = 0;
    if (ctx->buffer_len > 0)
    {
        // There is associated data in the buffer already.
        // Place as much as possible of the new associated data into the buffer.
        const uint_fast8_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const uint_fast8_t into_buffer = MIN(space_in_buffer, data_in_len);
        smallcpy(&ctx->buffer[ctx->buffer_len], data_in, into_buffer);
        ctx->buffer_len += into_buffer;
        data_in += into_buffer;
        data_in_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            absorb(&ctx->sponge, data_out, ctx->buffer);
            ctx->buffer_len = 0;
            data_out += ASCON_RATE;
            fresh_out_bytes += ASCON_RATE;
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
    while (data_in_len >= ASCON_RATE)
    {
        absorb(&ctx->sponge, data_out, data_in);
        data_out += ASCON_RATE;
        data_in += ASCON_RATE;
        data_in_len -= ASCON_RATE;
        fresh_out_bytes += ASCON_RATE;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (data_in_len > 0)
    {
        smallcpy(ctx->buffer, data_in, data_in_len);
        ctx->buffer_len = data_in_len;
    }
    ctx->total_output_len += fresh_out_bytes;
    return fresh_out_bytes;
}
