#include <stdint.h>

/**
 * @file
 */

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "ascon.h"

#define ITERATIONS 200000U
//0.000084
int main(void)
{
    uint8_t transformed[1024];
    uint8_t obtained_tag[ASCON_AEAD_TAG_LEN];
    const uint8_t key[ASCON_AEAD_KEY_LEN] = {
            255, 45, 2, 9,
            9, 9, 2, 1,
            12, 12, 1, 2,
            1, 12, 12, 1
    };
    const uint8_t nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 1, 2,
            1, 2, 1, 12,
            12, 1, 2, 3,
            45, 77, 77, 77
    };
    printf("Benchmarking: %u iterations\n", ITERATIONS);
    printf("On a 64-bit Intel i5 this should last about %u seconds.\n",
           (unsigned) (0.000090f * ITERATIONS));
    fflush(stdout);
    const clock_t start = clock();
    for (uint_fast32_t i = 0; i < ITERATIONS; i++)
    {
        ascon_aead128_encrypt(transformed,
                              obtained_tag,
                              key,
                              nonce,
                              transformed,
                              transformed,
                              256,
                              1024);
    }
    const clock_t end = clock();
    const clock_t delta = end - start;
    const double delta_per_iteration = ((double) delta) / ITERATIONS;
    const double seconds = ((double) delta) / CLOCKS_PER_SEC;
    const double seconds_per_iteration = seconds / ITERATIONS;
    printf("~%lu cycles, ~%f cycles/iteration\n"
           "~%f seconds, ~%f seconds/iteration\n",
           delta, delta_per_iteration, seconds, seconds_per_iteration);
    return 0;
}
