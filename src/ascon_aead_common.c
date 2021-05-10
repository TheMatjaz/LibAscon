/**
 * @file
 *
 * @copyright Copyright © 2020, Matjaž Guštin <dev@matjaz.it>
 * <https://matjaz.it>. All rights reserved.
 * @license BSD 3-clause license.
 */

#include "ascon.h"
#include "ascon_internal.h"

void
ascon_aead_init(ascon_aead_ctx_t* const ctx,
                const uint8_t* const key,
                const uint8_t* const nonce,
                const uint64_t iv)
{
    // Store the key in the context as it's required in the final step.
    ctx->k0 = bigendian_decode_u64(key);
    ctx->k1 = bigendian_decode_u64(key + sizeof(uint64_t));
    ctx->bufstate.sponge.x0 = iv;
    ctx->bufstate.sponge.x1 = ctx->k0;
    ctx->bufstate.sponge.x2 = ctx->k1;
    ctx->bufstate.sponge.x3 = bigendian_decode_u64(nonce);
    ctx->bufstate.sponge.x4 = bigendian_decode_u64(nonce + sizeof(uint64_t));
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.assoc_data_state = ASCON_FLOW_NO_ASSOC_DATA;
}

void
ascon_aead128_80pq_finalise_assoc_data(ascon_aead_ctx_t* const ctx)
{
    // If there was at least some associated data obtained so far,
    // pad it and absorb any content of the buffer.
    // Note: this step is performed even if the buffer is now empty because
    // a state permutation is required if there was at least some associated
    // data absorbed beforehand.
    if (ctx->bufstate.assoc_data_state == ASCON_FLOW_SOME_ASSOC_DATA)
    {
        ctx->bufstate.sponge.x0 ^= bigendian_decode_varlen(ctx->bufstate.buffer,
                                                           ctx->bufstate.buffer_len);
        ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
        ascon_permutation_b6(&ctx->bufstate.sponge);
    }
    // Application of a constant at end of associated data for domain
    // separation. Done always, regardless if there was some associated
    // data or not.
    ctx->bufstate.sponge.x4 ^= 1U;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.assoc_data_state = ASCON_FLOW_ASSOC_DATA_FINALISED;
}

void
ascon_aead_generate_tag(ascon_aead_ctx_t* const ctx,
                        uint8_t* tag,
                        size_t tag_len)
{
    while (tag_len > ASCON_AEAD_TAG_MIN_SECURE_LEN)
    {
        // All bytes before the last 16
        // Note: converting the sponge uint64_t to bytes to then check them as
        // uint64_t is required, as the conversion to bytes ensures the
        // proper byte order regardless of the platform native endianness.
        bigendian_encode_u64(tag, ctx->bufstate.sponge.x3);
        bigendian_encode_u64(tag + sizeof(uint64_t), ctx->bufstate.sponge.x4);
        ascon_permutation_a12(&ctx->bufstate.sponge);
        tag_len -= ASCON_AEAD_TAG_MIN_SECURE_LEN;
        tag += ASCON_AEAD_TAG_MIN_SECURE_LEN;
    }
    // The last 16 or less bytes (also 0)
    uint_fast8_t remaining = (uint_fast8_t) MIN(sizeof(uint64_t), tag_len);
    bigendian_encode_varlen(tag, ctx->bufstate.sponge.x3, remaining);
    tag += remaining;
    // The last 8 or less bytes (also 0)
    tag_len -= remaining;
    remaining = (uint_fast8_t) MIN(sizeof(uint64_t), tag_len);
    bigendian_encode_varlen(tag, ctx->bufstate.sponge.x4, remaining);
}

inline static bool
small_neq(const uint8_t* a, const uint8_t* b, uint_fast8_t amount)
{
    while (amount--)
    {
        if (*(a++) != *(b++)) { return true; }
    }
    return false;
}

bool
ascon_aead_is_tag_valid(ascon_aead_ctx_t* ctx,
                        const uint8_t* obtained_tag,
                        size_t tag_len)
{
    uint8_t expected_tag_chunk[sizeof(uint64_t)];
    while (tag_len > ASCON_AEAD_TAG_MIN_SECURE_LEN)
    {
        // All bytes before the last 16
        // Note: converting the sponge uint64_t to bytes to then check them as
        // uint64_t is required, as the conversion to bytes ensures the
        // proper tag's byte order regardless of the platform's endianness.
        bigendian_encode_u64(expected_tag_chunk, ctx->bufstate.sponge.x3);
        if (NOT_EQUAL_U64(expected_tag_chunk, obtained_tag)) { return ASCON_TAG_INVALID; }
        obtained_tag += sizeof(uint64_t);
        tag_len -= sizeof(uint64_t);
        bigendian_encode_u64(expected_tag_chunk, ctx->bufstate.sponge.x4);
        if (NOT_EQUAL_U64(expected_tag_chunk, obtained_tag)) { return ASCON_TAG_INVALID; }
        obtained_tag += sizeof(uint64_t);
        tag_len -= sizeof(uint64_t);
        ascon_permutation_a12(&ctx->bufstate.sponge);
    }
    // The last 16 or less bytes (also 0)
    uint_fast8_t remaining = (uint_fast8_t) MIN(sizeof(uint64_t), tag_len);
    bigendian_encode_varlen(expected_tag_chunk, ctx->bufstate.sponge.x3, remaining);
    if (small_neq(expected_tag_chunk, obtained_tag, remaining)) { return ASCON_TAG_INVALID; }
    obtained_tag += remaining;
    // The last 8 or less bytes (also 0)
    tag_len -= remaining;
    remaining = (uint_fast8_t) MIN(sizeof(uint64_t), tag_len);
    bigendian_encode_varlen(expected_tag_chunk, ctx->bufstate.sponge.x4, remaining);
    if (small_neq(expected_tag_chunk, obtained_tag, remaining)) { return ASCON_TAG_INVALID; }
    return ASCON_TAG_OK;
}

ASCON_API inline void
ascon_aead_cleanup(ascon_aead_ctx_t* const ctx)
{
#ifdef DEBUG
    assert(ctx != NULL);
#endif
    // Manual cleanup using volatile pointers to have more assurance the
    // cleanup will not be removed by the optimiser.
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x0 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x1 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x2 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x3 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.sponge.x4 = 0U;
    *(volatile uint64_t*) &ctx->bufstate.buffer[0] = 0U;
    *(volatile uint64_t*) &ctx->bufstate.buffer[ASCON_RATE] = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.buffer_len = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->bufstate.assoc_data_state = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->k0 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->k1 = 0U;
    ((volatile ascon_aead_ctx_t*) ctx)->k2 = 0U;
}
