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

void inline printstate(const char* text, const ascon_state_t* state)
{
#ifdef DEBUG_PERMUTATIONS
    printf("%state\n", text);
    printf("  x0=%016llx\n", state->x0);
    printf("  x1=%016llx\n", state->x1);
    printf("  x2=%016llx\n", state->x2);
    printf("  x3=%016llx\n", state->x3);
    printf("  x4=%016llx\n", state->x4);
#else
    // disable warning about unused parameters
    (void) text;
    (void) state;
#endif
}

static inline uint64_t rotr64(const uint64_t x, const uint_fast8_t n)
{
    // Cast to uint8_t to remove warning about <<-operator with signed value
    return (x << (uint8_t) (64 - n)) | (x >> n);
}

uint64_t bytes_to_u64(const uint8_t* const bytes, const uint_fast8_t n)
{
    uint64_t x = 0;
    for (uint_fast8_t i = 0; i < n; i++)
    {
        // Cast to unsigned int to remove warning about <<-operator with signed
        // value. uint_fast8_t does not work, so unsigned int should be the
        // fastest unsigned type on a machine.
        x |= ((uint64_t) bytes[i]) << (56 - 8 * (unsigned int) i);
    }
    return x;
}

void u64_to_bytes(uint8_t* const bytes, const uint64_t x, const uint_fast8_t n)
{
    for (uint_fast8_t i = 0; i < n; i++)
    {
        // Cast to unsigned int to remove warning about <<-operator with signed
        // value. uint_fast8_t does not work, so unsigned int should be the
        // fastest unsigned type on a machine.
        bytes[i] = (uint8_t) (x >> (56 - 8 * (unsigned int) i));
    }
}

uint64_t byte_mask(const uint_fast8_t n)
{
    uint64_t x = 0;
    for (uint_fast8_t i = 0; i < n; i++)
    {
        // Cast to unsigned int to remove warning about <<-operator with signed
        // value. uint_fast8_t does not work, so unsigned int should be the
        // fastest unsigned type on a machine.
        x |= 0xFFULL << (56 - 8 * (unsigned int) i);
    }
    return x;
}

static void ascon_round(ascon_state_t* const p, const uint_fast8_t round_const)
{
    // TODO this function leaves state traces on the stack in state and t structs
    ascon_state_t state = *p;
    ascon_state_t t;
    // addition of round constant
    state.x2 ^= round_const;
    printstate(" addition of round constant:", &state);
    // substitution layer
    state.x0 ^= state.x4;
    state.x4 ^= state.x3;
    state.x2 ^= state.x1;
    // start of keccak state-box
    t.x0 = ~state.x0;
    t.x1 = ~state.x1;
    t.x2 = ~state.x2;
    t.x3 = ~state.x3;
    t.x4 = ~state.x4;
    t.x0 &= state.x1;
    t.x1 &= state.x2;
    t.x2 &= state.x3;
    t.x3 &= state.x4;
    t.x4 &= state.x0;
    state.x0 ^= t.x1;
    state.x1 ^= t.x2;
    state.x2 ^= t.x3;
    state.x3 ^= t.x4;
    state.x4 ^= t.x0;
    // end of keccak state-box
    state.x1 ^= state.x0;
    state.x0 ^= state.x4;
    state.x3 ^= state.x2;
    state.x2 = ~state.x2;
    printstate(" substitution layer:", &state);
    // linear diffusion layer
    state.x0 ^= rotr64(state.x0, 19) ^ rotr64(state.x0, 28);
    state.x1 ^= rotr64(state.x1, 61) ^ rotr64(state.x1, 39);
    state.x2 ^= rotr64(state.x2, 1) ^ rotr64(state.x2, 6);
    state.x3 ^= rotr64(state.x3, 10) ^ rotr64(state.x3, 17);
    state.x4 ^= rotr64(state.x4, 7) ^ rotr64(state.x4, 41);
    printstate(" linear diffusion layer:", &state);
    *p = state;
    // TODO erase state and t
}

void ascon_permutation_a12(ascon_state_t* const state)
{
    printstate(" permutation input:", state);
    for (uint_fast8_t i = PERMUTATION_12_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(state, ROUND_CONSTANTS[i]);
    }
}

void ascon_permutation_8(ascon_state_t* const state)
{
    printstate(" permutation input:", state);
    for (uint_fast8_t i = PERMUTATION_8_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(state, ROUND_CONSTANTS[i]);
    }
}

void ascon_permutation_b6(ascon_state_t* const state)
{
    printstate(" permutation input:", state);
    for (uint_fast8_t i = PERMUTATION_6_START; i < ROUND_CONSTANTS_AMOUNT; i++)
    {
        ascon_round(state, ROUND_CONSTANTS[i]);
    }
}
