/**
 * @file
 * 64-bit optimised implementation of Ascon128 AEAD cipher.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "internal.h"

/* States used to understand when to finalise the associated data. */
#define FLOW_NO_ASSOC_DATA 0
#define FLOW_SOME_ASSOC_DATA 1
#define FLOW_ASSOC_DATA_FINALISED 2

void ascon_aead128_init(ascon_aead_ctx_t* const ctx,
                        const uint8_t* const key,
                        const uint8_t* const nonce)
{
    // Store the key in the context as it's required in the final step.
    ctx->k0 = bytes_to_u64(key, sizeof(uint64_t));
    ctx->k1 = bytes_to_u64(key + sizeof(uint64_t), sizeof(uint64_t));
    ctx->bufstate.sponge.x0 = AEAD128_IV;
    ctx->bufstate.sponge.x1 = ctx->k0;
    ctx->bufstate.sponge.x2 = ctx->k1;
    ctx->bufstate.sponge.x3 = bytes_to_u64(nonce, sizeof(uint64_t));
    ctx->bufstate.sponge.x4 = bytes_to_u64(nonce + sizeof(uint64_t),
                                           sizeof(uint64_t));
    log_sponge("initial value:", &ctx->bufstate.sponge);
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.total_output_len = 0;
    ctx->bufstate.assoc_data_state = FLOW_NO_ASSOC_DATA;
    log_sponge("initialization:", &ctx->bufstate.sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the associated data to
 * be authenticated, both during encryption and decryption.
 */
static void absorb_assoc_data(ascon_sponge_t* sponge,
                              uint8_t* const data_out,
                              const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bytes_to_u64(data, ASCON_RATE);
    ascon_permutation_b6(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the plaintext
 * and squeeze out ciphertext during encryption.
 */
static void absorb_plaintext(ascon_sponge_t* const sponge,
                             uint8_t* const plaintext,
                             const uint8_t* const ciphertext)
{
    // Absorb the ciphertext.
    const uint64_t c_0 = bytes_to_u64(ciphertext, ASCON_RATE);
    // Squeeze out some plaintext
    u64_to_bytes(plaintext, sponge->x0 ^ c_0, ASCON_RATE);
    sponge->x0 = c_0;
    // Permute the state
    ascon_permutation_b6(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the ciphertext
 * and squeeze out plaintext during decryption.
 */
static void absorb_ciphertext(ascon_sponge_t* const sponge,
                              uint8_t* const ciphertext,
                              const uint8_t* const plaintext)
{
    // Absorb the plaintext.
    sponge->x0 ^= bytes_to_u64(plaintext, ASCON_RATE);
    // Squeeze out some ciphertext
    u64_to_bytes(ciphertext, sponge->x0, ASCON_RATE);
    // Permute the state
    ascon_permutation_b6(sponge);
}


void ascon_aead128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                     const uint8_t* assoc_data,
                                     size_t assoc_data_len)
{
    if (assoc_data_len > 0)
    {
        ctx->bufstate.assoc_data_state = FLOW_SOME_ASSOC_DATA;
        buffered_accumulation(&ctx->bufstate, NULL, assoc_data,
                              absorb_assoc_data, assoc_data_len);
    }
}

/**
 * @internals
 * Handles the finalisation of the associated data before any plaintext or
 * ciphertext is being processed.
 *
 * MUST be called ONLY once! In other words, when
 * ctx->bufstate.assoc_data_state == FLOW_ASSOC_DATA_FINALISED
 * then it MUST NOT be called anymore.
 *
 * It handles both the case when some or none associated data was given.
 */
static void finalise_assoc_data(ascon_aead_ctx_t* const ctx)
{
    // If there was at least some associated data obtained so far,
    // pad it and absorb any content of the buffer.
    // Note: this step is performed even if the buffer is now empty because
    // a state permutation is required if there was at least some associated
    // data absorbed beforehand.
    if (ctx->bufstate.assoc_data_state == FLOW_SOME_ASSOC_DATA)
    {
        ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                                ctx->bufstate.buffer_len);
        ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
        ascon_permutation_b6(&ctx->bufstate.sponge);
        ctx->bufstate.buffer_len = 0;
    }
    // Application of a constant at end of associated data for domain
    // separation. Done always, regardless if there was some associated
    // data or not.
    ctx->bufstate.sponge.x4 ^= 1U;
    ctx->bufstate.total_output_len = 0;
    ctx->bufstate.assoc_data_state = FLOW_ASSOC_DATA_FINALISED;
    log_sponge("process associated data:", &ctx->bufstate.sponge);
}

size_t ascon_aead128_encrypt_update(ascon_aead_ctx_t* const ctx,
                                    uint8_t* ciphertext,
                                    const uint8_t* plaintext,
                                    size_t plaintext_len)
{
    if (ctx->bufstate.assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    // Start absorbing plaintext and simultaneously squeezing out ciphertext
    return buffered_accumulation(&ctx->bufstate, ciphertext, plaintext,
                                 absorb_ciphertext, plaintext_len);
}

static void generate_tag(ascon_aead_ctx_t* const ctx,
                         uint8_t* tag,
                         uint8_t tag_len)
{
    while (tag_len > ASCON_AEAD_TAG_MIN_SECURE_LEN)
    {
        u64_to_bytes(tag, ctx->bufstate.sponge.x3, sizeof(uint64_t));
        u64_to_bytes(tag + sizeof(uint64_t), ctx->bufstate.sponge.x4,
                     sizeof(uint64_t));
        ascon_permutation_a12(&ctx->bufstate.sponge);
        tag_len -= ASCON_AEAD_TAG_MIN_SECURE_LEN;
        tag += ASCON_AEAD_TAG_MIN_SECURE_LEN;
    }
    uint8_t remaining = (uint8_t) MIN(sizeof(uint64_t), tag_len);
    u64_to_bytes(tag, ctx->bufstate.sponge.x3, remaining);
    tag += sizeof(uint64_t);
    tag_len -= remaining;
    remaining = (uint8_t) MIN(sizeof(uint64_t), tag_len);
    u64_to_bytes(tag, ctx->bufstate.sponge.x4, remaining);
}

size_t ascon_aead128_encrypt_final(ascon_aead_ctx_t* const ctx,
                                   uint8_t* const ciphertext,
                                   uint64_t* const total_encrypted_bytes,
                                   uint8_t* tag,
                                   uint8_t tag_len)
{
    if (ctx->bufstate.assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    size_t freshly_generated_ciphertext_len = 0;
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                            ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    // Squeeze out last ciphertext bytes, if any.
    u64_to_bytes(ciphertext, ctx->bufstate.sponge.x0, ctx->bufstate.buffer_len);
    freshly_generated_ciphertext_len += ctx->bufstate.buffer_len;
    log_sponge("process plaintext:", &ctx->bufstate.sponge);
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    log_sponge("finalization:", &ctx->bufstate.sponge);
    // Squeeze out tag into its buffer.
    generate_tag(ctx, tag, tag_len);
    if (total_encrypted_bytes != NULL)
    {
        *total_encrypted_bytes =
                ctx->bufstate.total_output_len +
                freshly_generated_ciphertext_len;
    }
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead128_cleanup(ctx);
    return freshly_generated_ciphertext_len;
}

size_t ascon_aead128_decrypt_update(ascon_aead_ctx_t* const ctx,
                                    uint8_t* plaintext,
                                    const uint8_t* ciphertext,
                                    size_t ciphertext_len)
{
    if (ctx->bufstate.assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    // Start absorbing ciphertext and simultaneously squeezing out plaintext
    return buffered_accumulation(&ctx->bufstate, plaintext, ciphertext,
                                 absorb_plaintext, ciphertext_len);
}

size_t ascon_aead128_decrypt_final(ascon_aead_ctx_t* const ctx,
                                   uint8_t* plaintext,
                                   uint64_t* const total_decrypted_len,
                                   bool* const is_tag_valid,
                                   const uint8_t* const tag,
                                   const uint8_t tag_len)
{
    if (ctx->bufstate.assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    const uint64_t c_0 = bytes_to_u64(ctx->bufstate.buffer,
                                      ctx->bufstate.buffer_len);
    // Squeeze out last plaintext bytes, if any.
    u64_to_bytes(plaintext, ctx->bufstate.sponge.x0 ^ c_0,
                 ctx->bufstate.buffer_len);
    freshly_generated_plaintext_len += ctx->bufstate.buffer_len;
    // Final state changes at decryption's end
    ctx->bufstate.sponge.x0 &= ~byte_mask(ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 |= c_0;
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    log_sponge("process ciphertext:", &ctx->bufstate.sponge);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    log_sponge("finalization:", &ctx->bufstate.sponge);
    if (total_decrypted_len != NULL)
    {
        *total_decrypted_len = ctx->bufstate.total_output_len +
                               freshly_generated_plaintext_len;
    }
    // Validate tag with variable len
    uint8_t expected_tag[tag_len];
    generate_tag(ctx, expected_tag, tag_len);
    const int tags_differ = memcmp(tag, expected_tag, tag_len);
    memset(expected_tag, 0, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    if (tags_differ)
    {
        *is_tag_valid = ASCON_TAG_INVALID;
    }
    else
    {
        *is_tag_valid = ASCON_TAG_OK;
    }
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead128_cleanup(ctx);
    return freshly_generated_plaintext_len;
}