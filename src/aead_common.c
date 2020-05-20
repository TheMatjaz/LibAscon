/**
 * @file
 *
 * @copyright Copyright © 2020, Matjaž Guštin <dev@matjaz.it>
 * <https://matjaz.it>. All rights reserved.
 * @license BSD 3-clause license.
 */

#include "ascon.h"
#include "internal.h"

void ascon_aead128_80pq_finalise_assoc_data(ascon_aead_ctx_t* const ctx)
{
    // If there was at least some associated data obtained so far,
    // pad it and absorb any content of the buffer.
    // Note: this step is performed even if the buffer is now empty because
    // a state permutation is required if there was at least some associated
    // data absorbed beforehand.
    if (ctx->bufstate.assoc_data_state == ASCON_FLOW_SOME_ASSOC_DATA)
    {
        ctx->bufstate.sponge.x0 ^= bytes_to_u64(ctx->bufstate.buffer,
                                                ctx->bufstate.buffer_len);
        ctx->bufstate.sponge.x0 ^= PADDING(ctx->bufstate.buffer_len);
        ascon_permutation_b6(&ctx->bufstate.sponge);
    }
    // Application of a constant at end of associated data for domain
    // separation. Done always, regardless if there was some associated
    // data or not.
    ctx->bufstate.sponge.x4 ^= 1U;
    ctx->bufstate.buffer_len = 0;
    ctx->bufstate.total_output_len = 0;
    ctx->bufstate.assoc_data_state = ASCON_FLOW_ASSOC_DATA_FINALISED;
    log_sponge("process associated data:", &ctx->bufstate.sponge);
}

void ascon_aead_generate_tag(ascon_aead_ctx_t* const ctx,
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
