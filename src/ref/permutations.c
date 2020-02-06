/**
 * @file
 */

#include <stdint.h>
#include <stddef.h>
#include "ascon.h"
#include "internal.h"

#ifdef DEBUG_PERMUTATIONS
#include <stdio.h>
#endif

static const uint8_t ROUND_CONSTANTS[] = {
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

void inline printstate(const char* text, const ascon_sponge_t* sponge)
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

static void ascon_round(ascon_sponge_t* const p, const uint_fast8_t round_const)
{
    // TODO this function leaves sponge traces on the stack in sponge and t structs
    ascon_sponge_t sponge = *p;
    ascon_sponge_t t;
    // addition of round constant
    sponge.x2 ^= round_const;
    printstate(" addition of round constant:", &sponge);
    // substitution layer
    sponge.x0 ^= sponge.x4;
    sponge.x4 ^= sponge.x3;
    sponge.x2 ^= sponge.x1;
    // start of keccak s-box
    t.x0 = ~sponge.x0;
    t.x1 = ~sponge.x1;
    t.x2 = ~sponge.x2;
    t.x3 = ~sponge.x3;
    t.x4 = ~sponge.x4;
    t.x0 &= sponge.x1;
    t.x1 &= sponge.x2;
    t.x2 &= sponge.x3;
    t.x3 &= sponge.x4;
    t.x4 &= sponge.x0;
    sponge.x0 ^= t.x1;
    sponge.x1 ^= t.x2;
    sponge.x2 ^= t.x3;
    sponge.x3 ^= t.x4;
    sponge.x4 ^= t.x0;
    // end of keccak s-box
    sponge.x1 ^= sponge.x0;
    sponge.x0 ^= sponge.x4;
    sponge.x3 ^= sponge.x2;
    sponge.x2 = ~sponge.x2;
    printstate(" substitution layer:", &sponge);
    // linear diffusion layer
    sponge.x0 ^= rotr64(sponge.x0, 19) ^ rotr64(sponge.x0, 28);
    sponge.x1 ^= rotr64(sponge.x1, 61) ^ rotr64(sponge.x1, 39);
    sponge.x2 ^= rotr64(sponge.x2, 1) ^ rotr64(sponge.x2, 6);
    sponge.x3 ^= rotr64(sponge.x3, 10) ^ rotr64(sponge.x3, 17);
    sponge.x4 ^= rotr64(sponge.x4, 7) ^ rotr64(sponge.x4, 41);
    printstate(" linear diffusion layer:", &sponge);
    *p = sponge;
    // TODO erase sponge and t
}

void inline ascon_permutation_a12(ascon_sponge_t* const sponge)
{
    printstate(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_12_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

void inline ascon_permutation_8(ascon_sponge_t* const sponge)
{
    printstate(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_8_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}

void inline ascon_permutation_b6(ascon_sponge_t* const sponge)
{
    printstate(" permutation input:", sponge);
    for (uint_fast8_t i = PERMUTATION_6_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(sponge, ROUND_CONSTANTS[i]);
    }
}
