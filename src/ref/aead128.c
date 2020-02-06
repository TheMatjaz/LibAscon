/**
 * @file
 * Implementation of Ascon128 AEAD cipher.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "internal.h"

#define FLOW_NO_ASSOC_DATA 0
#define FLOW_SOME_ASSOC_DATA 1
#define FLOW_ASSOC_DATA_FINALISED 2

void ascon128_init(ascon_aead_ctx_t* const ctx,
                   const uint8_t* const key,
                   const uint8_t* const nonce)
{
    // Store the key in the context as it's required in the final step.
    ctx->k0 = bytes_to_u64(key, sizeof(uint64_t));
    ctx->k1 = bytes_to_u64(key + sizeof(uint64_t), sizeof(uint64_t));
    ctx->bufstate.sponge.x0 = AEAD128_IV;
    ctx->bufstate.sponge.x1 = ctx->k0;
    ctx->bufstate.sponge.x2 = ctx->k1;
    ctx->bufstate.sponge.x3 = bytes_to_u64(nonce, sizeof(uint64_t));;
    ctx->bufstate.sponge.x4 = bytes_to_u64(nonce + sizeof(uint64_t),
                                           sizeof(uint64_t));;
    printstate("initial value:", &ctx->bufstate.sponge);
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.total_output_len = 0;
    ctx->assoc_data_state = FLOW_NO_ASSOC_DATA;
    printstate("initialization:", &ctx->bufstate.sponge);
}

static void absorb_assoc_data(ascon_sponge_t* const sponge,
                              uint8_t* const data_out,
                              const uint8_t* const data)
{
    (void) data_out;
    sponge->x0 ^= bytes_to_u64(data, ASCON_RATE);
    ascon_permutation_b6(sponge);
}

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

static void absorb_plaintext(ascon_sponge_t* const sponge,
                             uint8_t* const plaintext,
                             const uint8_t* const ciphertext)
{
    // Absorb the ciphertext.
    const uint64_t c0 = bytes_to_u64(ciphertext, ASCON_RATE);
    // Squeeze out some plaintext
    u64_to_bytes(plaintext, sponge->x0 ^ c0, ASCON_RATE);
    sponge->x0 = c0;
    // Permute the state
    ascon_permutation_b6(sponge);
}

void ascon128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len)
{
    if (assoc_data_len > 0)
    {
        ctx->assoc_data_state = FLOW_SOME_ASSOC_DATA;
        buffered_accumulation(&ctx->bufstate, NULL, assoc_data,
                              absorb_assoc_data, assoc_data_len);
    }
}

static void finalise_assoc_data(ascon_aead_ctx_t* const ctx)
{
    // If there was at least some associated data obtained so far,
    // pad it and absorb any content of the buffer.
    // Note: this step is performed even if the buffer is now empty because
    // a state permutation is required if there was at least some associated
    // data absorbed beforehand.
    if (ctx->assoc_data_state == FLOW_SOME_ASSOC_DATA)
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
    ctx->bufstate.sponge.x4 ^= 1;
    ctx->assoc_data_state = FLOW_ASSOC_DATA_FINALISED;
    printstate("process associated data:", &ctx->bufstate.sponge);
}

size_t ascon128_encrypt_update(ascon_aead_ctx_t* const ctx,
                               uint8_t* ciphertext,
                               const uint8_t* plaintext,
                               size_t plaintext_len)
{
    if (ctx->assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    // Start absorbing plaintext and simultaneously squeezing out ciphertext
    return buffered_accumulation(&ctx->bufstate, ciphertext, plaintext,
                                 absorb_ciphertext, plaintext_len);
}

size_t ascon128_encrypt_final(ascon_aead_ctx_t* const ctx,
                              uint8_t* const ciphertext,
                              uint64_t* const total_ciphertext_len,
                              uint8_t* const tag)
{
    if (ctx->assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
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
    printstate("process plaintext:", &ctx->bufstate.sponge);
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->bufstate.sponge);
    // Squeeze out tag into is buffer.
    u64_to_bytes(tag, ctx->bufstate.sponge.x3, sizeof(uint64_t));
    u64_to_bytes(tag + sizeof(uint64_t), ctx->bufstate.sponge.x4,
                 sizeof(uint64_t));
    if (total_ciphertext_len != NULL)
    {
        *total_ciphertext_len =
                ctx->bufstate.total_output_len +
                freshly_generated_ciphertext_len;
    }
    // Final security cleanup of the internal state, key and buffer.
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
    return freshly_generated_ciphertext_len;
}

size_t ascon128_decrypt_update(ascon_aead_ctx_t* const ctx,
                               uint8_t* plaintext,
                               const uint8_t* ciphertext,
                               size_t ciphertext_len)
{
    if (ctx->assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    // Start absorbing ciphertext and simultaneously squeezing out plaintext
    return buffered_accumulation(&ctx->bufstate, plaintext, ciphertext,
                                 absorb_plaintext, ciphertext_len);
}

size_t ascon128_decrypt_final(ascon_aead_ctx_t* const ctx,
                              uint8_t* plaintext,
                              uint64_t* const total_plaintext_len,
                              ascon_tag_validity_t* const tag_validity,
                              const uint8_t* const tag)
{
    if (ctx->assoc_data_state != FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    const uint64_t c0 = bytes_to_u64(ctx->bufstate.buffer,
                                     ctx->bufstate.buffer_len);
    // Squeeze out last plaintext bytes, if any.
    u64_to_bytes(plaintext, ctx->bufstate.sponge.x0 ^ c0,
                 ctx->bufstate.buffer_len);
    freshly_generated_plaintext_len += ctx->bufstate.buffer_len;
    // Final state changes at decryption's end
    ctx->bufstate.sponge.x0 &= ~byte_mask(ctx->bufstate.buffer_len);
    ctx->bufstate.sponge.x0 |= c0;
    ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
    printstate("process ciphertext:", &ctx->bufstate.sponge);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0;
    ctx->bufstate.sponge.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k0;
    ctx->bufstate.sponge.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->bufstate.sponge);
    // Validate tag
    if (((ctx->bufstate.sponge.x3 ^ bytes_to_u64(tag, sizeof(uint64_t)))
         | (ctx->bufstate.sponge.x4 ^ bytes_to_u64(tag + sizeof(uint64_t),
                                                   sizeof(uint64_t)))) != 0)
    {
        *tag_validity = ASCON_TAG_INVALID;
    }
    else
    {
        *tag_validity = ASCON_TAG_OK;
    }
    if (total_plaintext_len != NULL)
    {
        *total_plaintext_len = ctx->bufstate.total_output_len +
                               freshly_generated_plaintext_len;
    }
    // Final security cleanup of the internal state, key and buffer.
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
    return freshly_generated_plaintext_len;
}
