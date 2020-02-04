#include "ascon.h"
#include "permutations.h"

void ascon128_encrypt_init(ascon_aead_ctx_t* const ctx,
                           const uint8_t* const nonce,
                           const uint8_t* const key)
{
    ctx->k0 = BYTES_TO_U64(key, sizeof(uint64_t));
    ctx->k1 = BYTES_TO_U64(key + sizeof(uint64_t), sizeof(uint64_t));
    ctx->state.x0 = AEAD128_IV;
    ctx->state.x1 = ctx->k0;
    ctx->state.x2 = ctx->k1;
    ctx->state.x3 = BYTES_TO_U64(nonce, sizeof(uint64_t));;
    ctx->state.x4 = BYTES_TO_U64(nonce + sizeof(uint64_t), sizeof(uint64_t));;
    printstate("initial value:", &ctx->state);
    ascon_permutation_a(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    ctx->buffer_len = 0;
    ctx->total_ciphertext_len = 0;
    printstate("initialization:", &ctx->state);
}

void ascon128_encrypt_update_ad(ascon_aead_ctx_t* const ctx,
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
            ascon_permutation_b(&ctx->state);
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
        ascon_permutation_b(&ctx->state);
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

void ascon128_encrypt_final_ad(ascon_aead_ctx_t* const ctx)
{
    // Finalise absorption of associated data left in the buffer
    if (ctx->buffer_len > 0)
    {
        ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
        ctx->state.x0 ^= PADDING(ctx->buffer_len);
        ascon_permutation_b(&ctx->state);
        ctx->buffer_len = 0;
    }
    ctx->state.x4 ^= 1U;
    printstate("process associated data:", &ctx->state);
}

size_t ascon128_encrypt_update_pt(ascon_aead_ctx_t* const ctx,
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
            // Squeeze out some ciphertext
            U64_TO_BYTES(ciphertext, ctx->state.x0, ASCON_RATE);
            ascon_permutation_b(&ctx->state);
            ciphertext += ASCON_RATE;
            freshly_generated_ciphertext_len += ASCON_RATE;
            ctx->buffer_len = 0;
        }
        else
        {
            // Do nothing.
            // The buffer contains some data, but it's not full yet
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
    // Absorb remaining plaintext (if any) one block at the time
    // while squeezing out ciphertext.
    while (plaintext_len >= ASCON_RATE)
    {
        ctx->state.x0 ^= BYTES_TO_U64(plaintext, ASCON_RATE);
        U64_TO_BYTES(ciphertext, ctx->state.x0, ASCON_RATE);
        ascon_permutation_b(&ctx->state);
        plaintext_len -= ASCON_RATE;
        plaintext += ASCON_RATE;
        ciphertext += ASCON_RATE;
        freshly_generated_ciphertext_len += ASCON_RATE;
    }
    // If there is any remaining less-than-a-block plaintext to be absorbed,
    // cache it into the buffer for the next update call or final call.
    if (plaintext_len > 0)
    {
        memcpy(&ctx->buffer, plaintext, plaintext_len);
        ctx->buffer_len = plaintext_len;
    }
    printstate("process plaintext:", &ctx->state);
    ctx->total_ciphertext_len += freshly_generated_ciphertext_len;
    return freshly_generated_ciphertext_len;
}

// TODO consider placing tag in separate pointer?
size_t ascon128_encrypt_final(ascon_aead_ctx_t* const ctx,
                              uint8_t* ciphertext,
                              uint64_t* const total_ciphertext_len)
{
    // If there is any remaining less-than-a-block plaintext to be absorbed
    // cached in the buffer, pad it and absorb it.
    size_t freshly_generated_ciphertext_len = 0;
    if (ctx->buffer_len > 0)
    {
        ctx->state.x0 ^= BYTES_TO_U64(ctx->buffer, ctx->buffer_len);
        ctx->state.x0 ^= PADDING(ctx->buffer_len);
        U64_TO_BYTES(ciphertext, ctx->state.x0, ctx->buffer_len);
        ciphertext += ctx->buffer_len;
        freshly_generated_ciphertext_len += ctx->buffer_len;
    }
    // End of encryption, start of tag generation.
    // Apply key twice more.
    ctx->state.x1 ^= ctx->k0;
    ctx->state.x2 ^= ctx->k1;
    ascon_permutation_a(&ctx->state);
    ctx->state.x3 ^= ctx->k0;
    ctx->state.x4 ^= ctx->k1;
    printstate("finalization:", &ctx->state);
    // Set tag as the last part of the ciphertext.
    U64_TO_BYTES(ciphertext, ctx->state.x3, sizeof(uint64_t));
    ciphertext += sizeof(uint64_t);
    U64_TO_BYTES(ciphertext, ctx->state.x4, sizeof(uint64_t));
    freshly_generated_ciphertext_len += ASCON_AEAD_TAG_SIZE;
    // Final security cleanup of the internal state, key and buffer.
    *total_ciphertext_len = ctx->total_ciphertext_len + freshly_generated_ciphertext_len;
    memset(ctx, 0, sizeof(ascon_aead_ctx_t));
    return freshly_generated_ciphertext_len;
}

