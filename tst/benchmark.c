#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include "ascon.h"

#if !defined(__arm__) && !defined(_M_ARM)
    #pragma message("Using RDTSC to count cycles")
    #ifdef _MSC_VER
        #include <intrin.h>
        #define ALIGN(x)
    #else
        #include <x86intrin.h>
        #define ALIGN(x) __attribute__((aligned(x)))
    #endif
    #define init_cpucycles()
    #define cpucycles(cycles) cycles = __rdtsc()
#endif


#if defined(__ARM_ARCH_6__) || __ARM_ARCH == 6 || _M_ARM == 6
    #define ALIGN(x) __attribute__((aligned(x)))
    #pragma message("Using ARMv6 PMU to count cycles")
    #define init_cpucycles() \
      __asm__ __volatile__("mcr p15, 0, %0, c15, c12, 0" ::"r"(1))
    #define cpucycles(cycles) \
      __asm__ __volatile__("mrc p15, 0, %0, c15, c12, 1" : "=r"(cycles))
#elif defined(__arm__) || defined(_M_ARM)
    #define ALIGN(x) __attribute__((aligned(x)))
    #pragma message("Using ARMv7 PMU to count cycles")
    #define init_cpucycles()                                                \
      __asm__ __volatile__("mcr p15, 0, %0, c9, c12, 0" ::"r"(17));         \
      __asm__ __volatile__("mcr p15, 0, %0, c9, c12, 1" ::"r"(0x8000000f)); \
      __asm__ __volatile__("mcr p15, 0, %0, c9, c12, 3" ::"r"(0x8000000f))
    #define cpucycles(cycles) \
      __asm__ __volatile__("mrc p15, 0, %0, c9, c13, 0" : "=r"(cycles))
#endif

#if defined(__arm__) || defined(_M_ARM)
typedef unsigned int cycles_t;
#else
typedef uint64_t cycles_t;
#endif

#define AMOUNT_OF_RUNS 16U
#define MAX_TEXT_LEN 32768U
#define AMOUNT_OF_TEXT_LENGTHS 7U

const uint16_t TEXT_LENGTHS[] = {1, 8, 16, 32, 64, 1536, MAX_TEXT_LEN};

typedef struct
{
    uint8_t ALIGN(16) text[MAX_TEXT_LEN];
    uint8_t ALIGN(16) key[ASCON_AEAD_KEY_LEN];
    uint8_t ALIGN(16) nonce[ASCON_AEAD_NONCE_LEN];
    uint8_t ALIGN(16) assoc_data[MAX_TEXT_LEN];
    uint8_t ALIGN(16) obtained_tag[ASCON_AEAD_TAG_LEN];
    uint8_t ALIGN(16) obtained_digest[ASCON_HASH_DIGEST_LEN];
    size_t text_len;
} benchmark_data_t;

static void init_random_array(uint8_t* array, size_t amount)
{
    while (amount--)
    {
        *(array++) = (uint8_t) rand();
    }
}

static void init_benchmark_data(benchmark_data_t* const data,
                                const size_t text_len)
{
    init_random_array(data->text, text_len);
    init_random_array(data->key, ASCON_AEAD_KEY_LEN);
    init_random_array(data->nonce, ASCON_AEAD_NONCE_LEN);
    init_random_array(data->assoc_data, text_len);
    data->text_len = text_len;
}

static void benchmark_cycles(
        uint64_t elapsed_cycles[AMOUNT_OF_TEXT_LENGTHS][AMOUNT_OF_RUNS * 2])
{
    benchmark_data_t data;
    cycles_t start;
    cycles_t end;
    init_cpucycles();
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; len++)
    {
        printf("\nBenchmarking text len %5u B:", TEXT_LENGTHS[len]);
        const uint64_t repetitions = MAX_TEXT_LEN / TEXT_LENGTHS[len];
        for (size_t run = 0; run < AMOUNT_OF_RUNS; run++)
        {
            printf(" %zu", run);
            fflush(stdout);
            init_benchmark_data(&data, TEXT_LENGTHS[len]);
            cpucycles(start);
            for (size_t rep = 0; rep < repetitions; rep++)
            {
                ascon_aead128_encrypt(
                        data.text,
                        data.obtained_tag,
                        data.key,
                        data.nonce,
                        data.assoc_data,
                        data.text,
                        data.text_len,
                        data.text_len);
            }
            cpucycles(end);
            elapsed_cycles[len][run] = end - start;
        }
    }
    puts("");
}

int compare_uint64(const void* const first, const void* const second)
{
    const uint64_t* const a = (uint64_t*) first;
    const uint64_t* const b = (uint64_t*) second;
    if (*a > *b) { return 1; }
    if (*a < *b) { return -1; }
    return 0;
}

static void sort_cycles(
        uint64_t elapsed_cycles[AMOUNT_OF_TEXT_LENGTHS][AMOUNT_OF_RUNS * 2])
{
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; ++len)
    {
        qsort(elapsed_cycles[len], AMOUNT_OF_RUNS, sizeof(uint64_t),
              &compare_uint64);
    }
}

static void print_cycles(
        const uint64_t elapsed_cycles
        [AMOUNT_OF_TEXT_LENGTHS][AMOUNT_OF_RUNS * 2])
{
    printf("\nSorted cycles:\n");
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; len++)
    {
        const uint64_t repetitions = MAX_TEXT_LEN / TEXT_LENGTHS[len];
        printf("%5u: ", TEXT_LENGTHS[len]);
        for (size_t run = 0; run < AMOUNT_OF_RUNS; run++)
        {
            printf("%8"PRIu64" ", (elapsed_cycles[len][run] / repetitions));
        }
        printf("\n");
    }
}

static void print_stats(
        const uint64_t elapsed_cycles
        [AMOUNT_OF_TEXT_LENGTHS][AMOUNT_OF_RUNS * 2],
        const double factor)
{
    printf("\nCycles per byte (min, median):\n");
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; ++len)
    {
        uint64_t repetitions = MAX_TEXT_LEN / TEXT_LENGTHS[len];
        uint64_t bytes = TEXT_LENGTHS[len] * repetitions;
        printf("%5u: %7.1f %7.1f\n", TEXT_LENGTHS[len],
               factor * elapsed_cycles[len][0] / bytes + 0.05,
               factor * elapsed_cycles[len][AMOUNT_OF_RUNS / 2] / bytes + 0.05);
    }
    puts("");
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; len++)
    {
        printf("| %6u ", TEXT_LENGTHS[len]);
    }
    printf("|\n");
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; len++)
    {
        printf("|-------:");
    }
    printf("|\n");
    for (size_t len = 0; len < AMOUNT_OF_TEXT_LENGTHS; len++)
    {
        const uint64_t repetitions = MAX_TEXT_LEN / TEXT_LENGTHS[len];
        const uint64_t bytes = TEXT_LENGTHS[len] * repetitions;
        if (TEXT_LENGTHS[len] <= 32)
        {
            printf("| %6.0f ", factor * elapsed_cycles[len][0] / bytes + 0.5);
        }
        else
        {
            printf("| %6.1f ", factor * elapsed_cycles[len][0] / bytes + 0.05);
        }
    }
    printf("|\n");
}

int main(int argc, char* argv[])
{
    double factor = 1.0;
    if (argc == 2)
    {
        factor = atof(argv[1]);
    }
    uint64_t elapsed_cycles[AMOUNT_OF_TEXT_LENGTHS][AMOUNT_OF_RUNS * 2];
    benchmark_cycles(elapsed_cycles);
    sort_cycles(elapsed_cycles);
    print_cycles(elapsed_cycles);
    print_stats(elapsed_cycles, factor);
    return 0;
}

