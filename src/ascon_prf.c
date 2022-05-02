/**
 * @file
 * Implementation of Ascon-MAC.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "ascon_internal.h"

ASCON_API void
ascon_prf_init(ascon_hash_ctx_t* const ctx,
               const uint8_t key[ASCON_PRF_KEY_LEN])
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(key != NULL);
    ctx->sponge.x0 = ASCON_IV_PRF;
    ctx->sponge.x1 = bigendian_decode_u64(key);
    ctx->sponge.x2 = bigendian_decode_u64(key + sizeof(uint64_t));
    ctx->sponge.x3 = 0;
    ctx->sponge.x4 = 0;
    ascon_permutation_12(&ctx->sponge);
    ctx->buffer_len = 0;
    ctx->flow_state = ASCON_FLOW_PRF_INITIALISED;
    ctx->sponge_index = 0;
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb data to be hashed
 * when using Ascon-PRF.
 */
static void
absorb_prf_data(ascon_sponge_t* const sponge,
                uint8_t* const sponge_index,
                const uint8_t* const data)
{
    ASCON_ASSERT(0); // see comment below
    // FIXME abusing the sponge_index pointer here will not work,
    // because the buffering function increments it to progress over
    // the output buffer. The information on where to write the input
    // data should come from elsewhere.
    // IDEA: let the buffering function pass the sponge_index to EVERY
    // absorb() as a NEW parameter. Existing absorbing functions need to be altered.
    // IDEA2: pass the ctx, not only the sponge to the absorb() function, so it can tweak
    // the sponge index. Existing absorbing functions need to be altered.
    (&sponge->x0)[(*sponge_index)++] ^= bigendian_decode_u64(data);
    if (*sponge_index >= 4)
    {
        ascon_permutation_12(sponge);
        *sponge_index = 0;
    }
}

ASCON_API void
ascon_prf_update(ascon_hash_ctx_t* const ctx,
                 const uint8_t* data,
                 size_t data_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_PRF_INITIALISED ||
                 ctx->flow_state == ASCON_FLOW_PRF_UPDATED);
    buffered_accumulation(ctx, &ctx->sponge_index, data, absorb_prf_data, data_len, ASCON_RATE);
    ctx->flow_state = ASCON_FLOW_PRF_UPDATED;
}

ASCON_API void
ascon_prf_final(ascon_hash_ctx_t* const ctx,
                uint8_t* output,
                size_t output_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(output_len == 0 || output != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_PRF_INITIALISED
                 || ctx->flow_state == ASCON_FLOW_PRF_UPDATED);
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    uint64_t* sponge_part = &ctx->sponge.x0;
    uint64_t block = bigendian_decode_varlen(ctx->buffer, ctx->buffer_len);
    block ^= PADDING(ctx->buffer_len);
    sponge_part[ctx->sponge_index] ^= block;
    // Application of a constant at end of absorption for domain separation.
    ctx->sponge.x4 ^= 1U;
    ascon_permutation_12(&ctx->sponge);
    // Squeeze the random data from the inner state.
    sponge_part = &ctx->sponge.x0;
    while (output_len > ASCON_RATE)
    {
        bigendian_encode_u64(output, *sponge_part++);
        if (sponge_part > &ctx->sponge.x2)
        {
            // Wrote x0 and x1: squeeze and go back to sponge start
            sponge_part = &ctx->sponge.x0;
            ascon_permutation_12(&ctx->sponge);
        }
        output += ASCON_RATE;
        output_len -= ASCON_RATE;
    }
    // Squeeze final block of random data, potentially shorter
    bigendian_encode_varlen(output, *sponge_part, (uint_fast8_t) output_len);
    // Final security cleanup of the internal state and buffer.
    ascon_hash_cleanup(ctx);
}

/**
 * @internal
 * Final step of the PRF flow with random-output equality checks.
 */
static bool
prf_final_matches(ascon_hash_ctx_t* const ctx,
                  const uint8_t* expected_output,
                  size_t expected_output_len)
{
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    uint64_t* sponge_part = &ctx->sponge.x0;
    uint64_t block = bigendian_decode_varlen(ctx->buffer, ctx->buffer_len);
    block ^= PADDING(ctx->buffer_len);
    sponge_part[ctx->sponge_index] ^= block;
    // Application of a constant at end of absorption for domain separation.
    ctx->sponge.x4 ^= 1U;
    ascon_permutation_12(&ctx->sponge);
    // Squeeze the digest from the inner state 8 bytes at the time to compare
    // it chunk by chunk with the expected digest
    sponge_part = &ctx->sponge.x0;
    uint64_t expected_output_block;
    bool outputs_differ = false;
    while (expected_output_len > ASCON_RATE)
    {
        expected_output_block = bigendian_decode_u64(expected_output);
        outputs_differ |= (*sponge_part++) ^ expected_output_block;
        expected_output += sizeof(expected_output_block);
        expected_output_len -= sizeof(expected_output_block);
        if (sponge_part > &ctx->sponge.x2)
        {
            // Wrote x0 and x1: squeeze and go back to sponge start
            sponge_part = &ctx->sponge.x0;
            ascon_permutation_12(&ctx->sponge);
        }
    }
    // Extract the remaining n most significant bytes of expected/computed outputs
    const uint64_t ms_mask = mask_most_signif_bytes((uint_fast8_t) expected_output_len);
    expected_output_block = bigendian_decode_varlen(
            expected_output, (uint_fast8_t) expected_output_len);
    // Constant time comparison expected vs computed chunk
    outputs_differ |= (expected_output_block ^ (*sponge_part & ms_mask));
    // Final security cleanup of the internal state and buffer.
    ascon_hash_cleanup(ctx);
    return !outputs_differ; // True if they are equal
}

ASCON_API bool
ascon_prf_final_matches(ascon_hash_ctx_t* const ctx,
                        const uint8_t* expected_output,
                        size_t expected_output_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(expected_output_len == 0 || expected_output != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_PRF_INITIALISED
                 || ctx->flow_state == ASCON_FLOW_PRF_UPDATED);
    return prf_final_matches(ctx, expected_output, expected_output_len);
}


ASCON_API void
ascon_prf(uint8_t* output,
          const uint8_t key[ASCON_PRF_KEY_LEN],
          const uint8_t* const seed,
          const size_t seed_len,
          const size_t output_len)
{
    ascon_hash_ctx_t ctx;
    ascon_prf_init(&ctx, key);
    ascon_prf_update(&ctx, seed, seed_len);
    ascon_prf_final(&ctx, output, output_len);
}

ASCON_API bool
ascon_prf_matches(
        const uint8_t* const expected_output,
        const uint8_t key[ASCON_PRF_KEY_LEN],
        const uint8_t* const seed,
        const size_t expected_output_len,
        const size_t seed_len)
{
    ascon_hash_ctx_t ctx;
    ascon_prf_init(&ctx, key);
    ascon_prf_update(&ctx, seed, seed_len);
    return ascon_prf_final_matches(&ctx, expected_output, expected_output_len);
}
