/**
 * @file
 * Implementation of Ascon-Hash and Ascon-Xof.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "ascon_internal.h"

/**
 * @internal
 * Precomputed initialised sponge state of the Ascon-Hash function.
 *
 * Spares the computation cost of a 12-round permutation.
 *
 * This is equivalent to the sponge obtained by initialising it with the IV
 * and permuting it for the first time before absorbing any input:
 *
 *      ascon_sponge_t sponge = {
 *          .x0 = 0x00400c0000000100ULL, // Init. vector of Ascon-Hash
 *          .x1 = 0, .x2 = 0, .x3 = 0, .x4 = 0,
 *      };
 *      ascon_permutation_12(&sponge);
 */
static const ascon_sponge_t INITIALISED_SPONGE_HASH = {
        .x0=0xee9398aadb67f03dULL,
        .x1=0x8bb21831c60f1002ULL,
        .x2=0xb48a92db98d5da62ULL,
        .x3=0x43189921b8f8e3e8ULL,
        .x4=0x348fa5c9d525e140ULL,
};

/**
 * @internal
 * Precomputed initialised sponge state of the Ascon-Hasha function.
 *
 * Spares the computation cost of a 12-round permutation.
 *
 * This is equivalent to the sponge obtained by initialising it with the IV
 * and permuting it for the first time before absorbing any input:
 *
 *      ascon_sponge_t sponge = {
 *          .x0 = 0x00400c0400000100ULL, // Init. vector of Ascon-Hasha
 *          .x1 = 0, .x2 = 0, .x3 = 0, .x4 = 0,
 *      };
 *      ascon_permutation_12(&sponge);
 */
static const ascon_sponge_t INITIALISED_SPONGE_HASHA = {
        .x0=0x01470194fc6528a6ULL,
        .x1=0x738ec38ac0adffa7ULL,
        .x2=0x2ec8e3296c76384cULL,
        .x3=0xd6f6a54d7f52377dULL,
        .x4=0xa13c42a223be8d87ULL,
};

/**
 * @internal
 * Precomputed initialised sponge state of the Ascon-XOF function.
 *
 * Spares the computation cost of a 12-round permutation.
 *
 * This is equivalent to the sponge obtained by initialising it with the IV
 * and permuting it for the first time before absorbing any input:
 *
 *      ascon_sponge_t sponge = {
 *          .x0 = 0x00400c0000000000ULL, // Init. vector of Ascon-XOF
 *          .x1 = 0, .x2 = 0, .x3 = 0, .x4 = 0,
 *      };
 *      ascon_permutation_12(&sponge);
 */
static const ascon_sponge_t INITIALISED_SPONGE_XOF = {
        .x0=0xb57e273b814cd416ULL,
        .x1=0x2b51042562ae2420ULL,
        .x2=0x66a3a7768ddf2218ULL,
        .x3=0x5aad0a7a8153650cULL,
        .x4=0x4f3e0e32539493b6ULL,
};

/**
 * @internal
 * Precomputed initialised sponge state of the Ascon-XOFa function.
 *
 * Spares the computation cost of a 12-round permutation.
 *
 * This is equivalent to the sponge obtained by initialising it with the IV
 * and permuting it for the first time before absorbing any input:
 *
 *      ascon_sponge_t sponge = {
 *          .x0 = 0x00400c0400000000ULL, // Init. vector of Ascon-XOFa
 *          .x1 = 0, .x2 = 0, .x3 = 0, .x4 = 0,
 *      };
 *      ascon_permutation_12(&sponge);
 */
static const ascon_sponge_t INITIALISED_SPONGE_XOFA = {
        .x0=0x44906568b77b9832ULL,
        .x1=0xcd8d6cae53455532ULL,
        .x2=0xf7b5212756422129ULL,
        .x3=0x246885e1de0d225bULL,
        .x4=0xa8cb5ce33449973fULL,
};

/* Initialisation functions. */
ASCON_API void
ascon_hash_init(ascon_hash_ctx_t* const ctx)
{
    ASCON_ASSERT(ctx != NULL);
    ctx->sponge = INITIALISED_SPONGE_HASH;
    ctx->buffer_len = 0;
    ctx->flow_state = ASCON_FLOW_HASH_INITIALISED;
}

ASCON_API void
ascon_hasha_init(ascon_hash_ctx_t* const ctx)
{
    ASCON_ASSERT(ctx != NULL);
    ctx->sponge = INITIALISED_SPONGE_HASHA;
    ctx->buffer_len = 0;
    ctx->flow_state = ASCON_FLOW_HASHA_INITIALISED;
}

ASCON_API void
ascon_hash_xof_init(ascon_hash_ctx_t* const ctx)
{
    ASCON_ASSERT(ctx != NULL);
    ctx->sponge = INITIALISED_SPONGE_XOF;
    ctx->buffer_len = 0;
    ctx->flow_state = ASCON_FLOW_HASH_INITIALISED;
}

ASCON_API void
ascon_hasha_xof_init(ascon_hash_ctx_t* const ctx)
{
    ASCON_ASSERT(ctx != NULL);
    ctx->sponge = INITIALISED_SPONGE_XOFA;
    ctx->buffer_len = 0;
    ctx->flow_state = ASCON_FLOW_HASHA_INITIALISED;
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb data to be hashed
 * when using Ascon-Hash or Ascon-XOF.
 */
static void
absorb_hash_data(ascon_sponge_t* const sponge,
                 uint8_t* const data_out,
                 const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bigendian_decode_u64(data);
    ascon_permutation_12(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb data to be hashed
 * when using Ascon-Hasha or Ascon-XOFa.
 */
static void
absorb_hasha_data(ascon_sponge_t* const sponge,
                  uint8_t* const data_out,
                  const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bigendian_decode_u64(data);
    ascon_permutation_8(sponge);
}

ASCON_API void
ascon_hash_xof_update(ascon_hash_ctx_t* const ctx,
                      const uint8_t* data,
                      size_t data_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_HASH_INITIALISED ||
                 ctx->flow_state == ASCON_FLOW_HASH_UPDATED);
    buffered_accumulation(ctx, NULL, data, absorb_hash_data, data_len, ASCON_RATE);
    ctx->flow_state = ASCON_FLOW_HASH_UPDATED;
}

ASCON_API void
ascon_hasha_xof_update(ascon_hash_ctx_t* const ctx,
                       const uint8_t* data,
                       size_t data_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_HASHA_INITIALISED ||
                 ctx->flow_state == ASCON_FLOW_HASHA_UPDATED);
    buffered_accumulation(ctx, NULL, data, absorb_hasha_data, data_len, ASCON_RATE);
    ctx->flow_state = ASCON_FLOW_HASHA_UPDATED;
}

ASCON_API void
ascon_hash_update(ascon_hash_ctx_t* const ctx,
                  const uint8_t* data,
                  size_t data_len)
{
    ascon_hash_xof_update(ctx, data, data_len);
}

ASCON_API void
ascon_hasha_update(ascon_hash_ctx_t* const ctx,
                   const uint8_t* data,
                   size_t data_len)
{
    ascon_hasha_xof_update(ctx, data, data_len);
}

/**
 * @internal
 * Final step of the hashing flow, same for Hash, XOF, Hasha and XOFa, except
 * for the amount of rounds in the squeezing permutation.
 */
static void
hash_final(permutation_fptr permutation,
           ascon_hash_ctx_t* const ctx,
           uint8_t* digest,
           size_t digest_len)
{
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->sponge.x0 ^= bigendian_decode_varlen(ctx->buffer, ctx->buffer_len);
    ctx->sponge.x0 ^= PADDING(ctx->buffer_len);
    ascon_permutation_12(&ctx->sponge);
    // Squeeze the digest from the inner state.
    while (digest_len > ASCON_RATE)
    {
        bigendian_encode_u64(digest, ctx->sponge.x0);
        permutation(&ctx->sponge);
        digest_len -= ASCON_RATE;
        digest += ASCON_RATE;
    }
    bigendian_encode_varlen(digest, ctx->sponge.x0, (uint_fast8_t) digest_len);
    // Final security cleanup of the internal state and buffer.
    ascon_hash_cleanup(ctx);
}

ASCON_API void
ascon_hash_xof_final(ascon_hash_ctx_t* const ctx,
                     uint8_t* digest,
                     size_t digest_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(digest_len == 0 || digest != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_HASH_INITIALISED
                 || ctx->flow_state == ASCON_FLOW_HASH_UPDATED);
    hash_final(ascon_permutation_12, ctx, digest, digest_len);
}


ASCON_API void
ascon_hasha_xof_final(ascon_hash_ctx_t* const ctx,
                      uint8_t* digest,
                      size_t digest_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(digest_len == 0 || digest != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_HASHA_INITIALISED
                 || ctx->flow_state == ASCON_FLOW_HASHA_UPDATED);
    hash_final(ascon_permutation_8, ctx, digest, digest_len);
}

ASCON_API void
ascon_hash_final(ascon_hash_ctx_t* const ctx,
                 uint8_t digest[ASCON_HASH_DIGEST_LEN])
{
    ascon_hash_xof_final(ctx, digest, ASCON_HASH_DIGEST_LEN);
}

ASCON_API void
ascon_hasha_final(ascon_hash_ctx_t* const ctx,
                  uint8_t digest[ASCON_HASHA_DIGEST_LEN])
{
    ascon_hasha_xof_final(ctx, digest, ASCON_HASHA_DIGEST_LEN);
}

ASCON_API void
ascon_hash_cleanup(ascon_hash_ctx_t* const ctx)
{
    ASCON_ASSERT(ctx != NULL);
    // Manual cleanup using volatile pointers to have more assurance the
    // cleanup will not be removed by the optimiser.
    ((volatile ascon_hash_ctx_t*) ctx)->sponge.x0 = 0U;
    ((volatile ascon_hash_ctx_t*) ctx)->sponge.x1 = 0U;
    ((volatile ascon_hash_ctx_t*) ctx)->sponge.x2 = 0U;
    ((volatile ascon_hash_ctx_t*) ctx)->sponge.x3 = 0U;
    ((volatile ascon_hash_ctx_t*) ctx)->sponge.x4 = 0U;
    for (uint_fast8_t i = 0; i < ASCON_DOUBLE_RATE; i++)
    {
        ((volatile ascon_aead_ctx_t*) ctx)->bufstate.buffer[i] = 0U;
    }
    ((volatile ascon_hash_ctx_t*) ctx)->buffer_len = 0U;
    ((volatile ascon_hash_ctx_t*) ctx)->flow_state = ASCON_FLOW_CLEANED;
    // Clearing also the padding to set the whole context to be all-zeros.
    // Makes it easier to check for initialisation and provides a known
    // state after cleanup, initialising all memory.
    for (uint_fast8_t i = 0U; i < 6U; i++)
    {
        ((volatile ascon_aead_ctx_t*) ctx)->bufstate.pad[i] = 0U;
    }
}

/** @internal Simplistic clone of `memcmp() != 0`, true when NOT equal. */
inline static bool
small_neq(const uint8_t* restrict a, const uint8_t* restrict b, size_t amount)
{
    while (amount--)
    {
        if (*(a++) != *(b++)) { return true; }
    }
    return false;
}

/**
 * @internal
 * Final step of the hashing flow with tag equality checks, same for Hash, XOF,
 * Hasha and XOFa, except for the amount of rounds in the squeezing
 * permutation.
 */
static bool
hash_final_matches(permutation_fptr permutation,
                   ascon_hash_ctx_t* const ctx,
                   const uint8_t* expected_digest,
                   size_t expected_digest_len)
{
    // If there is any remaining less-than-a-block data to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->sponge.x0 ^= bigendian_decode_varlen(ctx->buffer, ctx->buffer_len);
    ctx->sponge.x0 ^= PADDING(ctx->buffer_len);
    ascon_permutation_12(&ctx->sponge);
    // Squeeze the digest from the inner state 8 bytes at the time to compare
    // it chunk by chunk with the expected digest
    uint8_t computed_digest_chunk[ASCON_RATE];
    while (expected_digest_len > ASCON_RATE)
    {
        // Note: converting the sponge uint64_t to bytes to then check them as
        // is required, as the conversion to bytes ensures the
        // proper tag's byte order regardless of the platform's endianness.
        bigendian_encode_u64(computed_digest_chunk, ctx->sponge.x0);
        permutation(&ctx->sponge);
        if (small_neq(computed_digest_chunk, expected_digest, sizeof(computed_digest_chunk)))
        {
            ascon_hash_cleanup(ctx);
            return ASCON_TAG_INVALID;
        }
        expected_digest_len -= sizeof(computed_digest_chunk);
        expected_digest += sizeof(computed_digest_chunk);
    }
    bigendian_encode_varlen(computed_digest_chunk, ctx->sponge.x0,
                            (uint_fast8_t) expected_digest_len);
    // Check the remaining bytes in the chunk, potentially less than ASCON_RATE
    if (small_neq(computed_digest_chunk, expected_digest, expected_digest_len))
    {
        ascon_hash_cleanup(ctx);
        return ASCON_TAG_INVALID;
    }
    // Final security cleanup of the internal state and buffer.
    ascon_hash_cleanup(ctx);
    return ASCON_TAG_OK;
}

ASCON_API bool
ascon_hash_xof_final_matches(ascon_hash_ctx_t* const ctx,
                             const uint8_t* expected_digest,
                             size_t expected_digest_len)
{
    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(expected_digest_len == 0 || expected_digest != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_HASH_INITIALISED
                 || ctx->flow_state == ASCON_FLOW_HASH_UPDATED);
    return hash_final_matches(ascon_permutation_12, ctx, expected_digest, expected_digest_len);
}

ASCON_API bool
ascon_hasha_xof_final_matches(ascon_hash_ctx_t* const ctx,
                              const uint8_t* expected_digest,
                              size_t expected_digest_len)
{

    ASCON_ASSERT(ctx != NULL);
    ASCON_ASSERT(expected_digest_len == 0 || expected_digest != NULL);
    ASCON_ASSERT(ctx->flow_state == ASCON_FLOW_HASHA_INITIALISED
                 || ctx->flow_state == ASCON_FLOW_HASHA_UPDATED);
    return hash_final_matches(ascon_permutation_8, ctx, expected_digest, expected_digest_len);
}

ASCON_API bool
ascon_hash_final_matches(ascon_hash_ctx_t* const ctx,
                         const uint8_t expected_digest[ASCON_HASH_DIGEST_LEN])
{
    return ascon_hash_xof_final_matches(ctx, expected_digest, ASCON_HASH_DIGEST_LEN);
}

ASCON_API bool
ascon_hasha_final_matches(ascon_hash_ctx_t* const ctx,
                          const uint8_t expected_digest[ASCON_HASHA_DIGEST_LEN])
{
    return ascon_hasha_xof_final_matches(ctx, expected_digest, ASCON_HASHA_DIGEST_LEN);
}

ASCON_API void
ascon_hash(uint8_t digest[ASCON_HASH_DIGEST_LEN],
           const uint8_t* const data,
           const size_t data_len)
{
    ASCON_ASSERT(digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hash_init(&ctx);
    ascon_hash_xof_update(&ctx, data, data_len);
    ascon_hash_xof_final(&ctx, digest, ASCON_HASH_DIGEST_LEN);
}

ASCON_API void
ascon_hasha(uint8_t digest[ASCON_HASHA_DIGEST_LEN],
            const uint8_t* const data,
            const size_t data_len)
{
    ASCON_ASSERT(digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hasha_init(&ctx);
    ascon_hasha_xof_update(&ctx, data, data_len);
    ascon_hasha_xof_final(&ctx, digest, ASCON_HASHA_DIGEST_LEN);
}

ASCON_API bool
ascon_hash_matches(const uint8_t expected_digest[ASCON_HASH_DIGEST_LEN],
                   const uint8_t* const data,
                   const size_t data_len)
{
    ASCON_ASSERT(expected_digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hash_init(&ctx);
    ascon_hash_xof_update(&ctx, data, data_len);
    return ascon_hash_xof_final_matches(&ctx, expected_digest, ASCON_HASH_DIGEST_LEN);
}

ASCON_API bool
ascon_hasha_matches(const uint8_t expected_digest[ASCON_HASHA_DIGEST_LEN],
                    const uint8_t* const data,
                    const size_t data_len)
{
    ASCON_ASSERT(expected_digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hasha_init(&ctx);
    ascon_hasha_xof_update(&ctx, data, data_len);
    return ascon_hasha_xof_final_matches(&ctx, expected_digest, ASCON_HASHA_DIGEST_LEN);
}

ASCON_API void
ascon_hash_xof(uint8_t* const digest,
               const uint8_t* const data,
               const size_t digest_len,
               const size_t data_len)
{
    ASCON_ASSERT(digest_len == 0 || digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hash_xof_init(&ctx);
    ascon_hash_xof_update(&ctx, data, data_len);
    ascon_hash_xof_final(&ctx, digest, digest_len);
}

ASCON_API void
ascon_hasha_xof(uint8_t* const digest,
                const uint8_t* const data,
                const size_t digest_len,
                const size_t data_len)
{
    ASCON_ASSERT(digest_len == 0 || digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hasha_xof_init(&ctx);
    ascon_hasha_xof_update(&ctx, data, data_len);
    ascon_hasha_xof_final(&ctx, digest, digest_len);
}

ASCON_API bool
ascon_hash_xof_matches(const uint8_t* const expected_digest,
                       const uint8_t* const data,
                       const size_t expected_digest_len,
                       const size_t data_len)
{
    ASCON_ASSERT(expected_digest_len == 0 || expected_digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hash_xof_init(&ctx);
    ascon_hash_xof_update(&ctx, data, data_len);
    return ascon_hash_xof_final_matches(&ctx, expected_digest, expected_digest_len);
}

ASCON_API bool
ascon_hasha_xof_matches(const uint8_t* const expected_digest,
                        const uint8_t* const data,
                        const size_t expected_digest_len,
                        const size_t data_len)
{
    ASCON_ASSERT(expected_digest_len == 0 || expected_digest != NULL);
    ASCON_ASSERT(data_len == 0 || data != NULL);
    ascon_hash_ctx_t ctx;
    ascon_hasha_xof_init(&ctx);
    ascon_hasha_xof_update(&ctx, data, data_len);
    return ascon_hasha_xof_final_matches(&ctx, expected_digest, expected_digest_len);
}
