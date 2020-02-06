/**
 * @file
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"

void test_structs(void)
{
    atto_eq(sizeof(ascon_sponge_t), 5 * 8);
    atto_eq(sizeof(ascon_bufstate_t), sizeof(ascon_sponge_t)
                                      + ASCON_RATE + 1);
    atto_eq(sizeof(ascon_aead_ctx_t), sizeof(ascon_bufstate_t)
                                      + 8 + 8 + 1);
}
