#include "endian.h"
#include "ascon.h"
#include "permutations.h"

#define PA_ROUNDS 12

void ascon_xof_init(ascon_xof_ctx_t* const ctx)
{
    ctx->x0 = 0xb57e273b814cd416ull;
    ctx->x1 = 0x2b51042562ae2420ull;
    ctx->x2 = 0x66a3a7768ddf2218ull;
    ctx->x3 = 0x5aad0a7a8153650cull;
    ctx->x4 = 0x4f3e0e32539493b6ull;
}

void ascon_xof_update(ascon_xof_ctx_t* ctx,
                      const uint8_t* data,
                      size_t data_len)
{
    while (data_len >= ASCON_XOF_RATE)
    {
        ctx->x0 ^= U64BIG(*(uint64_t*) data);
        P12();
        data_len -= ASCON_XOF_RATE;
        data += ASCON_XOF_RATE;
    }
    for (size_t i = 0; i < data_len; ++i, ++data)
    {
        ctx->x0 ^= INS_BYTE64(*data, i);
    }
    ctx->x0 ^= INS_BYTE64(0x80, data_len);
    P12();
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
    size_t outlen = ASCON_XOF_DIGEST_SIZE;
    while (outlen > ASCON_XOF_RATE)
    {
        *(uint64_t*) digest = U64BIG(ctx->x0);
        P12();
        outlen -= ASCON_XOF_RATE;
        digest += ASCON_XOF_RATE;
    }
    *(uint64_t*) digest = U64BIG(ctx->x0);
    xof_zero_out(ctx);
}

