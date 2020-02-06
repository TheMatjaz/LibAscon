/**
 * @file
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"

void test_structs(void)
{
    printf("Sizeof sponge: %lu\n", sizeof(ascon_sponge_t));
    atto_eq(sizeof(ascon_sponge_t), 5 * 8);
    printf("Sizeof bufstate: %lu\n", sizeof(ascon_bufstate_t));
    atto_eq(sizeof(ascon_bufstate_t), sizeof(ascon_sponge_t)
                                      + 8 + ASCON_RATE + 8);
    printf("Sizeof aead ctx: %lu\n", sizeof(ascon_aead_ctx_t));
    atto_eq(sizeof(ascon_aead_ctx_t), sizeof(ascon_bufstate_t)
                                      + 8 + 8);
}
