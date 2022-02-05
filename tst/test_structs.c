/**
 * @file
 * Tests of the padding of the structures used as context for AEAD and hashing.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"

void test_structs(void)
{
    puts("Testing structs...");
    atto_eq(sizeof(ascon_sponge_t), 5 * 8);
    atto_eq(sizeof(ascon_bufstate_t), sizeof(ascon_sponge_t)
                                      + ASCON_DOUBLE_RATE + 8);
    atto_eq(sizeof(ascon_aead_ctx_t), sizeof(ascon_bufstate_t)
                                      + 8 + 8 + 8);
}
