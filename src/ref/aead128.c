#include "ascon.h"
#include "permutations.h"

void ascon128_init(ascon_aead_ctx_t* const ctx,
                   const uint8_t* const key,
                   const uint8_t* const nonce)
{
    // Store the key in the context as it's required in the final step.
    ctx->k0 = BYTES_TO_U64(key, sizeof(uint64_t));
    ctx->k1 = BYTES_TO_U64(key + sizeof(uint64_t), sizeof(uint64_t));
    ctx->state.x0 = AEAD128_IV;
    ctx->state.x1 = ctx->k0;
    ctx->state.x2 = ctx->k1;
    ctx->state.x3 = BYTES_TO_U64(nonce, sizeof(uint64_t));;
    ctx->state.x4 = BYTES_TO_U64(nonce + sizeof(uint64_t), sizeof(uint64_t));;
    printstate("initial value:", &ctx->state);
    ascon_permutation_a12(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    ctx->buffer_len = 0;
    ctx->total_output_len = 0;
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
        const size_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const size_t into_buffer = MIN(space_in_buffer, assoc_data_len);
        memcpy(&ctx->buffer[ctx->buffer_len], assoc_data, into_buffer);
        ctx->buffer_len += into_buffer;
        assoc_data += into_buffer;
        assoc_data_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ASCON_RATE);
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
        ctx->state.x0 ^= BYTES_TO_U64(assoc_data, ASCON_RATE);
        ascon_permutation_b6(&ctx->state);
        assoc_data_len -= ASCON_RATE;
        assoc_data += ASCON_RATE;
    }
    // If there is any remaining less-than-a-block data to be absorbed,
    // cache it into the buffer for the next update call or digest call.
    if (assoc_data_len > 0)
    {
        memcpy(&ctx->buffer, assoc_data, assoc_data_len);
        ctx->buffer_len = assoc_data_len;
    }
}

void ascon128_assoc_data_final(ascon_aead_ctx_t* const ctx)
{
    // Finalise absorption of associated data left in the buffer, if any
    if (ctx->buffer_len > 0)
    {
        ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
        ctx->state.x0 ^= PADDING(ctx->buffer_len);
        ascon_permutation_b6(&ctx->state);
        ctx->buffer_len = 0;
    }
    ctx->state.x4 ^= 1;  // Application of a constant at end of associated data
    printstate("process associated data:", &ctx->state);
}

size_t ascon128_encrypt_update(ascon_aead_ctx_t* const ctx,
                               uint8_t* ciphertext,
                               const uint8_t* plaintext,
                               size_t plaintext_len)
{
    // Start absorbing plaintext and simultaneously squeezing out ciphertext
    size_t freshly_generated_ciphertext_len = 0;
    if (ctx->buffer_len > 0)
    {
        // There is plaintext in the buffer already.
        // Place as much as possible of the new plaintext into the buffer.
        const size_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const size_t into_buffer = MIN(space_in_buffer, plaintext_len);
        memcpy(&ctx->buffer[ctx->buffer_len], plaintext, into_buffer);
        ctx->buffer_len += into_buffer;
        plaintext += into_buffer;
        plaintext_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ASCON_RATE);
            ctx->buffer_len = 0;
            // Squeeze out some ciphertext
            U64_TO_BYTES(ciphertext, ctx->state.x0, ASCON_RATE);
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
        ctx->state.x0 ^= BYTES_TO_U64(plaintext, ASCON_RATE);
        plaintext_len -= ASCON_RATE;
        // Squeeze out ciphertext
        U64_TO_BYTES(ciphertext, ctx->state.x0, ASCON_RATE);
        plaintext += ASCON_RATE;
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
                              uint8_t* ciphertext,
                              uint64_t* const total_ciphertext_len,
                              uint8_t* const tag)
{
    size_t freshly_generated_ciphertext_len = 0;
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
    ctx->state.x0 ^= PADDING(ctx->buffer_len);
    // Squeeze out last ciphertext bytes, if any.
    U64_TO_BYTES(ciphertext, ctx->state.x0, ctx->buffer_len);
    ciphertext += ctx->buffer_len;
    freshly_generated_ciphertext_len += ctx->buffer_len;
    printstate("process plaintext:", &ctx->state);
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag
    ctx->state.x1 ^= ctx->k0;
    ctx->state.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->state);
    // Squeeze out tag into is buffer.
    U64_TO_BYTES(tag, ctx->state.x3, sizeof(uint64_t));
    U64_TO_BYTES(tag + sizeof(uint64_t), ctx->state.x4, sizeof(uint64_t));
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
// decrypt and hash functions
size_t ascon128_decrypt_update(ascon_aead_ctx_t* const ctx,
                               uint8_t* plaintext,
                               const uint8_t* ciphertext,
                               size_t plaintext_len)
{
    // Start absorbing ciphertext and simultaneously squeezing out plaintext
    size_t freshly_generated_plaintext_len = 0;
    uint64_t c0;
    if (ctx->buffer_len > 0)
    {
        // There is ciphertext in the buffer already.
        // Place as much as possible of the new ciphertext into the buffer.
        const size_t space_in_buffer = ASCON_RATE - ctx->buffer_len;
        const size_t into_buffer = MIN(space_in_buffer, plaintext_len);
        memcpy(&ctx->buffer[ctx->buffer_len], plaintext, into_buffer);
        ctx->buffer_len += into_buffer;
        plaintext += into_buffer;
        plaintext_len -= into_buffer;
        if (ctx->buffer_len == ASCON_RATE)
        {
            // The buffer was filled completely, thus absorb it.
            c0 = BYTES_TO_U64(ctx->buffer, ASCON_RATE);
            U64_TO_BYTES(plaintext, ctx->state.x0 ^ c0, ASCON_RATE);
            ctx->state.x0 = c0;
            ascon_permutation_b6(&ctx->state);
            ciphertext += ASCON_RATE;
            freshly_generated_plaintext_len += ASCON_RATE;
            ctx->buffer_len = 0;
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
    while (plaintext_len >= ASCON_RATE)
    {
        c0 = BYTES_TO_U64(ciphertext, ASCON_RATE);
        U64_TO_BYTES(plaintext, ctx->state.x0 ^ c0, ASCON_RATE);
        ctx->state.x0 = c0;
        ascon_permutation_b6(&ctx->state);
        plaintext_len -= ASCON_RATE;
        plaintext += ASCON_RATE;
        ciphertext += ASCON_RATE;
        freshly_generated_plaintext_len += ASCON_RATE;
    }
    // If there is any remaining less-than-a-block ciphertext to be absorbed,
    // cache it into the buffer for the next update call or final call.
    if (plaintext_len > 0)
    {
        memcpy(&ctx->buffer, plaintext, plaintext_len);
        ctx->buffer_len = plaintext_len;
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
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
    size_t freshly_generated_plaintext_len = 0;
    const uint64_t c0 = BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
    U64_TO_BYTES(plaintext, ctx->state.x0 ^ c0, ctx->buffer_len);
    ctx->state.x0 &= ~BYTE_MASK(ctx->buffer_len);
    ctx->state.x0 |= c0;
    ctx->state.x0 ^= PADDING(ctx->buffer_len);
    freshly_generated_plaintext_len += ctx->buffer_len;
    printstate("process ciphertext:", &ctx->state);
    // End of decryption, start of tag validation.
    // Apply key twice more.
    ctx->state.x1 ^= ctx->k0;
    ctx->state.x2 ^= ctx->k1;
    ascon_permutation_a12(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->state);
    // Validate tag
    if (((ctx->state.x3 ^ BYTES_TO_U64(tag, sizeof(uint64_t)))
         | (ctx->state.x4 ^ BYTES_TO_U64(tag + sizeof(uint64_t),
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
