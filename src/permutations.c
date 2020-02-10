/**
 * @file
 * Core cryptographic operations, i.e. permutations of the sponge state.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include <stdint.h>
#include "ascon.h"
/* Linter warnings about #include "internal.h" being unused are WRONG.
 * If you do not include the header, the linker cannot find the references. */
#include "internal.h"

#ifdef DEBUG_PERMUTATIONS
#include <stdio.h>
#endif

const uint8_t ROUND_CONSTANTS[] = {
        // 12-round starts here, index 0
        0xf0, 0xe1, 0xd2, 0xc3,
        // 8-round starts here, index 4
        0xb4, 0xa5,
        // 6-round starts here, index 6
        0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};
#define ROUND_CONSTANTS_AMOUNT 12
#define PERMUTATION_12_START 0
#define PERMUTATION_8_START 4
#define PERMUTATION_6_START 6

void inline log_sponge(const char* const text,
                       const ascon_sponge_t* const sponge)
{
#ifdef DEBUG_PERMUTATIONS
    printf("%s sponge\n", text);
    printf("  x0=%016llx\n", sponge->x0);
    printf("  x1=%016llx\n", sponge->x1);
    printf("  x2=%016llx\n", sponge->x2);
    printf("  x3=%016llx\n", sponge->x3);
    printf("  x4=%016llx\n", sponge->x4);
#else
    // disable warning about unused parameters
    (void) text;
    (void) sponge;
#endif
}

static inline uint64_t rotr64(const uint64_t x, const uint_fast8_t n)
{
    // Cast to uint8_t to remove warning about <<-operator with signed value
    return (x << (uint8_t) (64 - n)) | (x >> n);
}

void ascon_round(ascon_sponge_t* sponge, const uint_fast8_t round_const)
{
    ascon_sponge_t temp;
    // addition of round constant
    sponge->x2 ^= round_const;
    log_sponge(" addition of round constant:", sponge);
    // substitution layer
    sponge->x0 ^= sponge->x4;
    sponge->x4 ^= sponge->x3;
    sponge->x2 ^= sponge->x1;
    // start of keccak s-box
    temp.x0 = ~sponge->x0;
    temp.x1 = ~sponge->x1;
    temp.x2 = ~sponge->x2;
    temp.x3 = ~sponge->x3;
    temp.x4 = ~sponge->x4;
    temp.x0 &= sponge->x1;
    temp.x1 &= sponge->x2;
    temp.x2 &= sponge->x3;
    temp.x3 &= sponge->x4;
    temp.x4 &= sponge->x0;
    sponge->x0 ^= temp.x1;
    sponge->x1 ^= temp.x2;
    sponge->x2 ^= temp.x3;
    sponge->x3 ^= temp.x4;
    sponge->x4 ^= temp.x0;
    // TODO erase temp to avoid leaving traces?
    // end of keccak s-box
    sponge->x1 ^= sponge->x0;
    sponge->x0 ^= sponge->x4;
    sponge->x3 ^= sponge->x2;
    sponge->x2 = ~sponge->x2;
    log_sponge(" substitution layer:", sponge);
    // linear diffusion layer
    sponge->x0 ^= rotr64(sponge->x0, 19) ^ rotr64(sponge->x0, 28);
    sponge->x1 ^= rotr64(sponge->x1, 61) ^ rotr64(sponge->x1, 39);
    sponge->x2 ^= rotr64(sponge->x2, 1) ^ rotr64(sponge->x2, 6);
    sponge->x3 ^= rotr64(sponge->x3, 10) ^ rotr64(sponge->x3, 17);
    sponge->x4 ^= rotr64(sponge->x4, 7) ^ rotr64(sponge->x4, 41);
    log_sponge(" linear diffusion layer:", sponge);
}

void inline ascon_permutation_a12(ascon_sponge_t* const sponge)
{
    log_sponge(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_12_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

void inline ascon_permutation_8(ascon_sponge_t* const sponge)
{
    log_sponge(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_8_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

void inline ascon_permutation_b6(ascon_sponge_t* const sponge)
{
    log_sponge(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_6_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}
