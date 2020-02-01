#include "ascon.h"
#include "permutations.h"

#define PA_ROUNDS 12
#define IV ((uint64_t)(8 * (ASCON_XOF_RATE)) << 48 | (uint64_t)(PA_ROUNDS) << 40)

void ascon_xof_init(ascon_xof_ctx_t* const ctx)
{
    ctx->x0 = IV;
    ctx->x1 = 0;
    ctx->x2 = 0;
    ctx->x3 = 0;
    ctx->x4 = 0;
    printstate("initial value:", ctx);
    P12(ctx);
    printstate("initialization:", ctx);
}

void ascon_xof_update(ascon_xof_ctx_t* ctx,
                       const uint8_t* data,
                       size_t data_len)
{
    while (data_len >= ASCON_XOF_RATE)
    {
        ctx->x0 ^= BYTES_TO_U64(data, 8);
        P12(ctx);
        data_len -= ASCON_XOF_RATE;
        data += ASCON_XOF_RATE;
    }
    ctx->x0 ^= BYTES_TO_U64(data, data_len);
    ctx->x0 ^= 0x80ULL << (56 - 8 * data_len);
    printstate("absorb plaintext:", ctx);
    P12(ctx);
    printstate("finalization:", ctx);
}

static void inline xof_zero_out(ascon_xof_ctx_t* const ctx)
{
    ctx->x0 = 0;
    ctx->x1 = 0;
    ctx->x2 = 0;
    ctx->x3 = 0;
    ctx->x4 = 0;
}

void ascon_xof_final(ascon_xof_ctx_t* ctx, uint8_t* digest)
{
    // TODO What about custom tag length passed by user?
    size_t outlen = ASCON_XOF_DIGEST_SIZE;
    while (outlen > ASCON_XOF_RATE)
    {
        U64_TO_BYTES(digest, ctx->x0, 8);
        P12(ctx);
        outlen -= ASCON_XOF_RATE;
        digest += ASCON_XOF_RATE;
    }
    U64_TO_BYTES(digest, ctx->x0, 8);
    xof_zero_out(ctx);
}
