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
    ctx->state.x0 = AEAD128_IV;
    ctx->state.x1 = ctx->k0;
    ctx->state.x2 = ctx->k1;
    ctx->state.x3 = bytes_to_u64(nonce, sizeof(uint64_t));;
    ctx->state.x4 = bytes_to_u64(nonce + sizeof(uint64_t), sizeof(uint64_t));;
    printstate("initial value:", &ctx->state);
    ascon_permutation_a12(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    ctx->buffer_len = 0;
    ctx->total_output_len = 0;
    ctx->assoc_data_state = FLOW_NO_ASSOC_DATA;
    printstate("initialization:", &ctx->state);
}

void ascon128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                const uint8_t* assoc_data,
                                size_t assoc_data_len)
{
    if (ctx->buffer_len > 0)
    {
        // There is associated data in the buffer already.
        // Place as much as possible of the new associated data into the buffer.
        const uint_fast8_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const uint_fast8_t into_buffer = MIN(space_in_buffer, assoc_data_len);
        memcpy(&ctx->buffer[ctx->buffer_len], assoc_data, into_buffer);
        ctx->buffer_len += into_buffer;
        assoc_data += into_buffer;
        assoc_data_len -= into_buffer;
        ctx->assoc_data_state = FLOW_SOME_ASSOC_DATA;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->state.x0 ^= bytes_to_u64(ctx->buffer, ASCON_RATE);
            ascon_permutation_b6(&ctx->state);
            ctx->buffer_len = 0;
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
    while (assoc_data_len >= ASCON_RATE)
    {
        ctx->state.x0 ^= bytes_to_u64(assoc_data, ASCON_RATE);
        ascon_permutation_b6(&ctx->state);
        assoc_data_len -= ASCON_RATE;
        assoc_data += ASCON_RATE;
        ctx->assoc_data_state = FLOW_SOME_ASSOC_DATA;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (assoc_data_len > 0)
    {
        memcpy(&ctx->buffer, assoc_data, assoc_data_len);
        ctx->buffer_len = assoc_data_len;
        ctx->assoc_data_state = FLOW_SOME_ASSOC_DATA;
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
        ctx->state.x0 ^= bytes_to_u64(ctx->buffer, ctx->buffer_len);
        ctx->state.x0 ^= PADDING(ctx->buffer_len);
        ascon_permutation_b6(&ctx->state);
        ctx->buffer_len = 0;
    }
    // Application of a constant at end of associated data for domain
    // separation. Done always, regardless if there was some associated
    // data or not.
    ctx->state.x4 ^= 1;
    ctx->assoc_data_state = FLOW_ASSOC_DATA_FINALISED;
    printstate("process associated data:", &ctx->state);
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
    size_t freshly_generated_ciphertext_len = 0;
    if (ctx->buffer_len > 0)
    {
        // There is plaintext in the buffer already.
        // Place as much as possible of the new plaintext into the buffer.
        const uint_fast8_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const uint_fast8_t into_buffer = MIN(space_in_buffer, plaintext_len);
        memcpy(&ctx->buffer[ctx->buffer_len], plaintext, into_buffer);
        ctx->buffer_len += into_buffer;
        plaintext += into_buffer;
        plaintext_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->state.x0 ^= bytes_to_u64(ctx->buffer, ASCON_RATE);
            ctx->buffer_len = 0;
            // Squeeze out some ciphertext
            u64_to_bytes(ciphertext, ctx->state.x0, ASCON_RATE);
            ciphertext += ASCON_RATE;
            freshly_generated_ciphertext_len += ASCON_RATE;
            // Permute the state
            ascon_permutation_b6(&ctx->state);
        }
        else
        {
            // Do nothing.
            // The buffer contains some data, but it's not full yet
            // and there is no more data in this update call.
            // Keep it cached for the next update call or the final call.
        }
    }
    else
    {
        // Do nothing.
        // The buffer contains no data, because this is the first update call
        // or because the last update had no less-than-a-block trailing data.
    }
    // Absorb remaining plaintext (if any) one block at the time
    // while squeezing out ciphertext.
    while (plaintext_len >= ASCON_RATE)
    {
        // Absorb plaintext
        ctx->state.x0 ^= bytes_to_u64(plaintext, ASCON_RATE);
        plaintext += ASCON_RATE;
        plaintext_len -= ASCON_RATE;
        // Squeeze out ciphertext
        u64_to_bytes(ciphertext, ctx->state.x0, ASCON_RATE);
        ciphertext += ASCON_RATE;
        freshly_generated_ciphertext_len += ASCON_RATE;
        // Permute the state
        ascon_permutation_b6(&ctx->state);
    }
    // If there is any remaining less-than-a-block plaintext to be absorbed,
    // cache it into the buffer for the next update call or final call.
    if (plaintext_len > 0)
    {
        memcpy(&ctx->buffer, plaintext, plaintext_len);
        ctx->buffer_len = plaintext_len;
    }
    ctx->total_output_len += freshly_generated_ciphertext_len;
    return freshly_generated_ciphertext_len;
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
    ctx->state.x0 ^= bytes_to_u64(ctx->buffer, ctx->buffer_len);
    ctx->state.x0 ^= PADDING(ctx->buffer_len);
    // Squeeze out last ciphertext bytes, if any.
    u64_to_bytes(ciphertext, ctx->state.x0, ctx->buffer_len);
    freshly_generated_ciphertext_len += ctx->buffer_len;
    printstate("process plaintext:", &ctx->state);
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->state.x1 ^= ctx->k0;
    ctx->state.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->state);
    // Squeeze out tag into is buffer.
    u64_to_bytes(tag, ctx->state.x3, sizeof(uint64_t));
    u64_to_bytes(tag + sizeof(uint64_t), ctx->state.x4, sizeof(uint64_t));
    if (total_ciphertext_len != NULL)
    {
        *total_ciphertext_len =
                ctx->total_output_len + freshly_generated_ciphertext_len;
    }
    // Final security cleanup of the internal state, key and buffer.
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
    return freshly_generated_ciphertext_len;
}

// TODO use the encrypt as model for the inline comments for the
//  hash functions
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
    size_t freshly_generated_plaintext_len = 0;
    uint64_t c0;
    if (ctx->buffer_len > 0)
    {
        // There is ciphertext in the buffer already.
        // Place as much as possible of the new ciphertext into the buffer.
        const uint_fast8_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const uint_fast8_t into_buffer = MIN(space_in_buffer, ciphertext_len);
        memcpy(&ctx->buffer[ctx->buffer_len], ciphertext, into_buffer);
        ctx->buffer_len += into_buffer;
        ciphertext += into_buffer;
        ciphertext_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            c0 = bytes_to_u64(ctx->buffer, ASCON_RATE);
            ctx->buffer_len = 0;
            // Squeeze out some plaintext
            u64_to_bytes(plaintext, ctx->state.x0 ^ c0, ASCON_RATE);
            ctx->state.x0 = c0;
            plaintext += ASCON_RATE;
            freshly_generated_plaintext_len += ASCON_RATE;
            // Permute the state
            ascon_permutation_b6(&ctx->state);
        }
        else
        {
            // Do nothing.
            // The buffer contains some data, but it's not full yet
            // and there is no more data in this update call.
            // Keep it cached for the next update call or the final call.
        }
    }
    else
    {
        // Do nothing.
        // The buffer contains no data, because this is the first update call
        // or because the last update had no less-than-a-block trailing data.
    }
    // Absorb remaining ciphertext (if any) one block at the time
    // while squeezing out plaintext.
    while (ciphertext_len >= ASCON_RATE)
    {
        // Absorb ciphertext
        c0 = bytes_to_u64(ciphertext, ASCON_RATE);
        ciphertext += ASCON_RATE;
        ciphertext_len -= ASCON_RATE;
        // Squeeze out plaintext
        u64_to_bytes(plaintext, ctx->state.x0 ^ c0, ASCON_RATE);
        ctx->state.x0 = c0;
        plaintext += ASCON_RATE;
        freshly_generated_plaintext_len += ASCON_RATE;
        // Permute the state
        ascon_permutation_b6(&ctx->state);
    }
    // If there is any remaining less-than-a-block ciphertext to be absorbed,
    // cache it into the buffer for the next update call or final call.
    if (ciphertext_len > 0)
    {
        memcpy(&ctx->buffer, ciphertext, ciphertext_len);
        ctx->buffer_len = ciphertext_len;
    }
    ctx->total_output_len += freshly_generated_plaintext_len;
    return freshly_generated_plaintext_len;
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
    const uint64_t c0 = bytes_to_u64(ctx->buffer, ctx->buffer_len);
    // Squeeze out last plaintext bytes, if any.
    u64_to_bytes(plaintext, ctx->state.x0 ^ c0, ctx->buffer_len);
    freshly_generated_plaintext_len += ctx->buffer_len;
    // Final state changes at decryption's end
    ctx->state.x0 &= ~byte_mask(ctx->buffer_len);
    ctx->state.x0 |= c0;
    ctx->state.x0 ^= PADDING(ctx->buffer_len);
    printstate("process ciphertext:", &ctx->state);
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->state.x1 ^= ctx->k0;
    ctx->state.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->state);
    // Validate tag
    if (((ctx->state.x3 ^ bytes_to_u64(tag, sizeof(uint64_t)))
         | (ctx->state.x4 ^ bytes_to_u64(tag + sizeof(uint64_t),
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
        *total_plaintext_len =
                ctx->total_output_len + freshly_generated_plaintext_len;
    }
    // Final security cleanup of the internal state, key and buffer.
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
    return freshly_generated_plaintext_len;
}
