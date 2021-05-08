/**
 * @file
 * 64-bit optimised implementation of Ascon80pq AEAD cipher.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include "ascon.h"
#include "ascon_internal.h"

ASCON_API void
ascon_aead80pq_encrypt(uint8_t* ciphertext,
                       uint8_t* tag,
                       const uint8_t* key,
                       const uint8_t* nonce,
                       const uint8_t* assoc_data,
                       const uint8_t* plaintext,
                       size_t assoc_data_len,
                       size_t plaintext_len,
                       size_t tag_len)
{
    ascon_aead_ctx_t ctx;
    ascon_aead80pq_init(&ctx, key, nonce);
    ascon_aead80pq_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead80pq_encrypt_update(&ctx, ciphertext,
                                                              plaintext,
                                                              plaintext_len);
    ascon_aead80pq_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                 tag, tag_len);
}

ASCON_API bool
ascon_aead80pq_decrypt(uint8_t* plaintext,
                       const uint8_t* key,
                       const uint8_t* nonce,
                       const uint8_t* assoc_data,
                       const uint8_t* ciphertext,
                       const uint8_t* tag,
                       size_t assoc_data_len,
                       size_t ciphertext_len,
                       size_t tag_len)
{
    ascon_aead_ctx_t ctx;
    bool is_tag_valid;
    ascon_aead80pq_init(&ctx, key, nonce);
    ascon_aead80pq_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead80pq_decrypt_update(&ctx,
                                                              plaintext,
                                                              ciphertext,
                                                              ciphertext_len);
    ascon_aead80pq_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                 &is_tag_valid, tag, tag_len);
    return is_tag_valid;
}

ASCON_API void
ascon_aead80pq_init(ascon_aead_ctx_t* const ctx,
                    const uint8_t* const key,
                    const uint8_t* const nonce)
{
    // Store the key in the context as it's required in the final step.
    ctx->k0 = bytes_to_u64(key, sizeof(uint64_t)) >> 32U;
    ctx->k1 = bytes_to_u64(key + 4, sizeof(uint64_t));
    ctx->k2 = bytes_to_u64(key + 4 + sizeof(uint64_t), sizeof(uint64_t));
    ctx->bufstate.sponge.x0 = AEAD80pq_IV | ctx->k0;
    ctx->bufstate.sponge.x1 = ctx->k1;
    ctx->bufstate.sponge.x2 = ctx->k2;
    ctx->bufstate.sponge.x3 = bytes_to_u64(nonce, sizeof(uint64_t));
    ctx->bufstate.sponge.x4 = bytes_to_u64(nonce + sizeof(uint64_t),
                                           sizeof(uint64_t));
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x2 ^= ctx->k0;
    ctx->bufstate.sponge.x3 ^= ctx->k1;
    ctx->bufstate.sponge.x4 ^= ctx->k2;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.assoc_data_state = ASCON_FLOW_NO_ASSOC_DATA;
}

ASCON_API void
ascon_aead80pq_assoc_data_update(ascon_aead_ctx_t* ctx,
                                 const uint8_t* assoc_data,
                                 size_t assoc_data_len)
{
    ascon_aead128_assoc_data_update(ctx, assoc_data, assoc_data_len);
}

ASCON_API size_t
ascon_aead80pq_encrypt_update(ascon_aead_ctx_t* ctx,
                              uint8_t* ciphertext,
                              const uint8_t* plaintext,
                              size_t plaintext_len)
{
    return ascon_aead128_encrypt_update(ctx, ciphertext, plaintext,
                                        plaintext_len);
}

ASCON_API size_t
ascon_aead80pq_encrypt_final(ascon_aead_ctx_t* const ctx,
                             uint8_t* const ciphertext,
                             uint8_t* tag,
                             size_t tag_len)
{
    if (ctx->bufstate.assoc_data_state != ASCON_FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
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
    // End of encryption, start of tag generation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0 << 32U | ctx->k1 >> 32U;
    ctx->bufstate.sponge.x2 ^= ctx->k1 << 32U | ctx->k2 >> 32U;
    ctx->bufstate.sponge.x3 ^= ctx->k2 << 32U;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k1;
    ctx->bufstate.sponge.x4 ^= ctx->k2;
    // Squeeze out tag into its buffer.
    ascon_aead_generate_tag(ctx, tag, tag_len);
    // Final security cleanup of the internal state, key and buffer.
    ascon_aead_cleanup(ctx);
    return freshly_generated_ciphertext_len;
}

ASCON_API size_t
ascon_aead80pq_decrypt_update(ascon_aead_ctx_t* ctx,
                              uint8_t* plaintext,
                              const uint8_t* ciphertext,
                              size_t ciphertext_len)
{
    return ascon_aead128_decrypt_update(ctx, plaintext, ciphertext,
                                        ciphertext_len);
}

ASCON_API size_t
ascon_aead80pq_decrypt_final(ascon_aead_ctx_t* const ctx,
                             uint8_t* plaintext,
                             bool* const is_tag_valid,
                             const uint8_t* const tag,
                             const size_t tag_len)
{
    if (ctx->bufstate.assoc_data_state != ASCON_FLOW_ASSOC_DATA_FINALISED)
    {
        // Finalise the associated data if not already done sos.
        ascon_aead128_80pq_finalise_assoc_data(ctx);
    }
    size_t freshly_generated_plaintext_len = 0;
    // If there is any remaining less-than-a-block ciphertext to be absorbed
    // cached in the buffer, pad it and absorb it.
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
    freshly_generated_plaintext_len += ctx->bufstate.buffer_len;
    // End of decryption, start of tag validation.
    // Apply key twice more with a permutation to set the state for the tag.
    ctx->bufstate.sponge.x1 ^= ctx->k0 << 32U | ctx->k1 >> 32U;
    ctx->bufstate.sponge.x2 ^= ctx->k1 << 32U | ctx->k2 >> 32U;
    ctx->bufstate.sponge.x3 ^= ctx->k2 << 32U;
    ascon_permutation_a12(&ctx->bufstate.sponge);
    ctx->bufstate.sponge.x3 ^= ctx->k1;
    ctx->bufstate.sponge.x4 ^= ctx->k2;
    // Validate tag with variable len
    // If the user requests tag_len==0, than expected_tag[0] is problematic
    // for some compilers. Thus we replace it with a 1 just in this case
    const uint8_t local_len = tag_len > 0 ? tag_len : 1;
    uint8_t expected_tag[local_len];
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
    ascon_aead_cleanup(ctx);
    return freshly_generated_plaintext_len;
}
