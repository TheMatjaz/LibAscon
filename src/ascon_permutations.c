/**
 * @file
 * Core cryptographic operations, i.e. permutations of the sponge state.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include <stdint.h>
#include "ascon.h"
/* Linter warnings about #include "ascon_internal.h" being unused are WRONG.
 * If you do not include the header, the linker cannot find the references. */
#include "ascon_internal.h"

#ifdef DEBUG_PERMUTATIONS
#include <stdio.h>
#endif

// 12-round permutation starts here
#define ROUND_CONSTANT_01 0xF0
#define ROUND_CONSTANT_02 0xE1
#define ROUND_CONSTANT_03 0xD2
#define ROUND_CONSTANT_04 0xC3

// 8-round permutation starts here
#define ROUND_CONSTANT_05 0xB4
#define ROUND_CONSTANT_06 0xA5

// 6-round permutation starts here
#define ROUND_CONSTANT_07 0x96
#define ROUND_CONSTANT_08 0x87
#define ROUND_CONSTANT_09 0x78
#define ROUND_CONSTANT_10 0x69
#define ROUND_CONSTANT_11 0x5A
#define ROUND_CONSTANT_12 0x4B

#ifdef DEBUG_PERMUTATIONS
inline void log_sponge(const char* const text,
                       const ascon_sponge_t* const sponge)
{
    printf("%s sponge\n", text);
    printf("  x0=%016llx\n", sponge->x0);
    printf("  x1=%016llx\n", sponge->x1);
    printf("  x2=%016llx\n", sponge->x2);
    printf("  x3=%016llx\n", sponge->x3);
    printf("  x4=%016llx\n", sponge->x4);
#endif

inline static uint64_t rotr64(const uint64_t x, const uint_fast8_t n)
{
    return (x << (64U - n)) | (x >> n);
}

ASCON_INLINE static void ascon_round(ascon_sponge_t* sponge,
                                     const uint_fast8_t round_const)
{
    ascon_sponge_t temp;
    // addition of round constant
    sponge->x2 ^= round_const;
#ifdef DEBUG_PERMUTATIONS
    log_sponge(" addition of round constant:", sponge);
#endif
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
    // end of keccak s-box
    sponge->x1 ^= sponge->x0;
    sponge->x0 ^= sponge->x4;
    sponge->x3 ^= sponge->x2;
    sponge->x2 = ~sponge->x2;
#ifdef DEBUG_PERMUTATIONS
    log_sponge(" substitution layer:", sponge);
#endif
    // linear diffusion layer
    sponge->x0 ^= rotr64(sponge->x0, 19) ^ rotr64(sponge->x0, 28);
    sponge->x1 ^= rotr64(sponge->x1, 61) ^ rotr64(sponge->x1, 39);
    sponge->x2 ^= rotr64(sponge->x2, 1) ^ rotr64(sponge->x2, 6);
    sponge->x3 ^= rotr64(sponge->x3, 10) ^ rotr64(sponge->x3, 17);
    sponge->x4 ^= rotr64(sponge->x4, 7) ^ rotr64(sponge->x4, 41);
#ifdef DEBUG_PERMUTATIONS
    log_sponge(" linear diffusion layer:", sponge);
#endif
}

ASCON_INLINE void ascon_permutation_a12(ascon_sponge_t* const sponge)
{
#ifdef DEBUG_PERMUTATIONS
    log_sponge(" permutation12 input:", sponge);
#endif
    ascon_round(sponge, ROUND_CONSTANT_01);
    ascon_round(sponge, ROUND_CONSTANT_02);
    ascon_round(sponge, ROUND_CONSTANT_03);
    ascon_round(sponge, ROUND_CONSTANT_04);
    ascon_round(sponge, ROUND_CONSTANT_05);
    ascon_round(sponge, ROUND_CONSTANT_06);
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_INLINE void ascon_permutation_b8(ascon_sponge_t* const sponge)
{
#ifdef DEBUG_PERMUTATIONS
    log_sponge(" permutation8 input:", sponge);
#endif
    ascon_round(sponge, ROUND_CONSTANT_05);
    ascon_round(sponge, ROUND_CONSTANT_06);
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}

ASCON_INLINE void ascon_permutation_b6(ascon_sponge_t* const sponge)
{
#ifdef DEBUG_PERMUTATIONS
    log_sponge(" permutation6 input:", sponge);
#endif
    ascon_round(sponge, ROUND_CONSTANT_07);
    ascon_round(sponge, ROUND_CONSTANT_08);
    ascon_round(sponge, ROUND_CONSTANT_09);
    ascon_round(sponge, ROUND_CONSTANT_10);
    ascon_round(sponge, ROUND_CONSTANT_11);
    ascon_round(sponge, ROUND_CONSTANT_12);
}
