/**
 * @file
 * 64-bit optimised implementation of Ascon128a AEAD cipher.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "ascon_internal.h"

void ascon_aead128a_encrypt(uint8_t* ciphertext,
                            uint8_t* tag,
                            const uint8_t* key,
                            const uint8_t* nonce,
                            const uint8_t* assoc_data,
                            const uint8_t* plaintext,
                            size_t assoc_data_len,
                            size_t plaintext_len,
                            uint8_t tag_len)
{
    ascon_aead_ctx_t ctx;
    ascon_aead128a_init(&ctx, key, nonce);
    ascon_aead128a_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128a_encrypt_update(&ctx, ciphertext,
                                                              plaintext,
                                                              plaintext_len);
    ascon_aead128a_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                 tag, tag_len);
}

bool ascon_aead128a_decrypt(uint8_t* plaintext,
                            const uint8_t* key,
                            const uint8_t* nonce,
                            const uint8_t* assoc_data,
                            const uint8_t* ciphertext,
                            const uint8_t* tag,
                            size_t assoc_data_len,
                            size_t ciphertext_len,
                            uint8_t tag_len)
{
    ascon_aead_ctx_t ctx;
    bool is_tag_valid;
    ascon_aead128a_init(&ctx, key, nonce);
    ascon_aead128a_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128a_decrypt_update(&ctx,
                                                              plaintext,
                                                              ciphertext,
                                                              ciphertext_len);
    ascon_aead128a_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                 &is_tag_valid, tag, tag_len);
    return is_tag_valid;
}

inline void ascon_aead128a_cleanup(ascon_aead_ctx_t* const ctx)
{
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
}

inline void ascon_aead128a_init(ascon_aead_ctx_t* const ctx,
                                const uint8_t* const key,
                                const uint8_t* const nonce)
{
    ascon_aead_init(ctx, key, nonce, AEAD128a_IV);
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
    sponge->x1 ^= bytes_to_u64(data + ASCON_RATE, ASCON_RATE);
    ascon_permutation_b8(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the ciphertext
 * and squeeze out plaintext during decryption.
 */
static void absorb_ciphertext(ascon_sponge_t* const sponge,
                              uint8_t* const plaintext,
                              const uint8_t* const ciphertext)
{
    // Absorb the ciphertext.
    const uint64_t c_0 = bytes_to_u64(ciphertext, ASCON_RATE);
    const uint64_t c_1 = bytes_to_u64(ciphertext + ASCON_RATE, ASCON_RATE);
    // Squeeze out some plaintext
    u64_to_bytes(plaintext, sponge->x0 ^ c_0, ASCON_RATE);
    u64_to_bytes(plaintext + ASCON_RATE, sponge->x1 ^ c_1, ASCON_RATE);
    sponge->x0 = c_0;
    sponge->x1 = c_1;
    // Permute the state
    ascon_permutation_b8(sponge);
}

/**
 * @internal
 * Function passed to buffered_accumulation() to absorb the plaintext
 * and squeeze out ciphertext during encryption.
 */
static void absorb_plaintext(ascon_sponge_t* const sponge,
                             uint8_t* const ciphertext,
                             const uint8_t* const plaintext)
{
    // Absorb the plaintext.
    sponge->x0 ^= bytes_to_u64(plaintext, ASCON_RATE);
    sponge->x1 ^= bytes_to_u64(plaintext + ASCON_RATE, ASCON_RATE);
    // Squeeze out some ciphertext
    u64_to_bytes(ciphertext, sponge->x0, ASCON_RATE);
    u64_to_bytes(ciphertext + ASCON_RATE, sponge->x1, ASCON_RATE);
    // Permute the state
    ascon_permutation_b8(sponge);
}


void ascon_aead128a_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                      const uint8_t* assoc_data,
                                      size_t assoc_data_len)
{
    if (assoc_data_len > 0)
    {
        ctx->bufstate.assoc_data_state = ASCON_FLOW_SOME_ASSOC_DATA;
        buffered_accumulation(&ctx->bufstate, NULL, assoc_data,
                              absorb_assoc_data, assoc_data_len,
                              ASCON_DOUBLE_RATE);
    }
}

/**
 * @internals
 * Handles the finalisation of the associated data before any plaintext or
 * ciphertext is being processed.
 *
 * MUST be called ONLY once! In other words, when
 * ctx->bufstate.assoc_data_state == ASCON_FLOW_ASSOC_DATA_FINALISED
 * then it MUST NOT be called anymore.
 *
 * It handles both the case when some or none associated data was given.
 */
static void ascon_128a_finalise_assoc_data(ascon_aead_ctx_t* const ctx)
{
    // If there was at least some associated data obtained so far,
    // pad it and absorb any content of the buffer.
    // Note: this step is performed even if the buffer is now empty because
    // a state permutation is required if there was at least some associated
    // data absorbed beforehand.
    if (ctx->bufstate.assoc_data_state == ASCON_FLOW_SOME_ASSOC_DATA)
    {
        if (ctx->bufstate.buffer_len >= ASCON_RATE)
        {
            ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                                    ASCON_RATE);
            ctx->bufstate.sponge.x1 ^= bytes_to_u64(
                    ctx->bufstate.buffer + ASCON_RATE,
                    ctx->bufstate.buffer_len - ASCON_RATE);
            ctx->bufstate.sponge.x1 ^= PADDING(
                    ctx->bufstate.buffer_len - ASCON_RATE);
        }
        else
        {
            ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                                    ctx->bufstate.buffer_len);
            ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
        }
        ascon_permutation_b8(&ctx->bufstate.sponge);
    }
    // Application of a constant at end of associated data for domain
    // separation. Done always, regardless if there was some associated
    // data or not.
    ctx->bufstate.sponge.x4 ^= 1U;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.assoc_data_state = ASCON_FLOW_ASSOC_DATA_FINALISED;
    log_sponge("process associated data:", &ctx->bufstate.sponge);
}

size_t ascon_aead128a_encrypt_update(ascon_aead_ctx_t* const ctx,
                                     uint8_t* ciphertext,
                                     const uint8_t* plaintext,
                                     size_t plaintext_len)
{
    if (ctx->bufstate.assoc_data_state != ASCON_FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        ascon_128a_finalise_assoc_data(ctx);
    }
    // Start absorbing plaintext and simultaneously squeezing out ciphertext
    return buffered_accumulation(&ctx->bufstate, ciphertext, plaintext,
                                 absorb_plaintext, plaintext_len,
                                 ASCON_DOUBLE_RATE);
}

size_t ascon_aead128a_encrypt_final(ascon_aead_ctx_t* const ctx,
                                    uint8_t* const ciphertext,
                                    uint8_t* tag,
                                    uint8_t tag_len)
{
    if (ctx->bufstate.assoc_data_state != ASCON_FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        ascon_128a_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_ciphertext_len = 0;
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    if (ctx->bufstate.buffer_len >= ASCON_RATE)
    {
        // Absorb plaintext in buffer
        ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                                ASCON_RATE);
        const uint8_t second_half =
                (uint8_t) (ctx->bufstate.buffer_len - ASCON_RATE);
        ctx->bufstate.sponge.x1 ^= bytes_to_u64(
                ctx->bufstate.buffer + ASCON_RATE, second_half);
        ctx->bufstate.sponge.x1 ^= PADDING(second_half);
        // Squeeze out the ciphertext
        u64_to_bytes(ciphertext, ctx->bufstate.sponge.x0, ASCON_RATE);
        u64_to_bytes(ciphertext + ASCON_RATE, ctx->bufstate.sponge.x1,
                     second_half);
    }
    else
    {
        // Absorb plaintext in buffer
        ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                                ctx->bufstate.buffer_len);
        ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
        // Squeeze out the last ciphertext bytes, if any
        u64_to_bytes(ciphertext, ctx->bufstate.sponge.x0,
                     ctx->bufstate.buffer_len);
    }
    freshly_generated_ciphertext_len += ctx->bufstate.buffer_len;
    log_sponge("process plaintext:", &ctx->bufstate.sponge);
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x2 ^= ctx->k0;
    ctx->bufstate.sponge.x3 ^= ctx->k1;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    log_sponge("finalization:", &ctx->bufstate.sponge);
    // Squeeze out tag into its buffer.
    ascon_aead_generate_tag(ctx, tag, tag_len);
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead128a_cleanup(ctx);
    return freshly_generated_ciphertext_len;
}

size_t ascon_aead128a_decrypt_update(ascon_aead_ctx_t* const ctx,
                                     uint8_t* plaintext,
                                     const uint8_t* ciphertext,
                                     size_t ciphertext_len)
{
    if (ctx->bufstate.assoc_data_state != ASCON_FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        ascon_128a_finalise_assoc_data(ctx);
    }
    // Start absorbing ciphertext and simultaneously squeezing out plaintext
    return buffered_accumulation(&ctx->bufstate, plaintext, ciphertext,
                                 absorb_ciphertext, ciphertext_len,
                                 ASCON_DOUBLE_RATE);
}

size_t ascon_aead128a_decrypt_final(ascon_aead_ctx_t* const ctx,
                                    uint8_t* plaintext,
                                    bool* const is_tag_valid,
                                    const uint8_t* const tag,
                                    const uint8_t tag_len)
{
    if (ctx->bufstate.assoc_data_state != ASCON_FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        ascon_128a_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    if (ctx->bufstate.buffer_len >= ASCON_RATE)
    {
        // Absorb ciphertext in buffer
        const uint64_t c_0 = bytes_to_u64(ctx->bufstate.buffer, ASCON_RATE);
        const uint8_t second_half =
                (uint8_t) (ctx->bufstate.buffer_len - ASCON_RATE);
        const uint64_t c_1 = bytes_to_u64(
                ctx->bufstate.buffer + ASCON_RATE, second_half);
        // Squeeze out last plaintext bytes
        u64_to_bytes(plaintext, ctx->bufstate.sponge.x0 ^ c_0, ASCON_RATE);
        u64_to_bytes(plaintext + ASCON_RATE,
                     ctx->bufstate.sponge.x1 ^ c_1,
                     second_half);
        // Final state changes at decryption's end
        ctx->bufstate.sponge.x0 = c_0;
        ctx->bufstate.sponge.x1 &= ~byte_mask(second_half);
        ctx->bufstate.sponge.x1 |= c_1;
        ctx->bufstate.sponge.x1 ^= PADDING(second_half);
    }
    else
    {
        // Absorb ciphertext in buffer
        const uint64_t c_0 = bytes_to_u64(ctx->bufstate.buffer,
                                          ctx->bufstate.buffer_len);
        // Squeeze out last plaintext bytes
        u64_to_bytes(plaintext, ctx->bufstate.sponge.x0 ^ c_0,
                     ctx->bufstate.buffer_len);
        // Final state changes at decryption's end
        ctx->bufstate.sponge.x0 &= ~byte_mask(ctx->bufstate.buffer_len);
        ctx->bufstate.sponge.x0 |= c_0;
        ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    }
    freshly_generated_plaintext_len += ctx->bufstate.buffer_len;
    log_sponge("process ciphertext:", &ctx->bufstate.sponge);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x2 ^= ctx->k0;
    ctx->bufstate.sponge.x3 ^= ctx->k1;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    log_sponge("finalization:", &ctx->bufstate.sponge);
    // Validate tag with variable len
    uint8_t expected_tag[tag_len];
    ascon_aead_generate_tag(ctx, expected_tag, tag_len);
    const int tags_differ = memcmp(tag, expected_tag, tag_len);
    if (tags_differ)
    {
        *is_tag_valid = ASCON_TAG_INVALID;
    }
    else
    {
        *is_tag_valid = ASCON_TAG_OK;
    }
    // Final security cleanup of the internal state, key and buffer.
    memset(expected_tag, 0, tag_len);
    ascon_aead128a_cleanup(ctx);
    return freshly_generated_plaintext_len;
}
