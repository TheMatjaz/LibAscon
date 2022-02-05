/**
 * @file
 * Benchmarking tool measuring the average CPU cycles per byte processed.
 *
 * Adapted from the reference implementation, heavily simplified.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors see AUTHORS.md file
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "ascon.h"

#if !defined(__arm__) && !defined(_M_ARM)
#pragma message("Using RDTSC to count cycles")
#ifdef _MSC_VER
#include <intrin.digest>
#define ALIGN(x)
#else
#include <x86intrin.h>
#define ALIGN(x) __attribute__((aligned(x)))
#endif
#define init_cpucycles()
#define cpucycles(cycles) __rdtsc()
#endif

#if defined(__ARM_ARCH_6__) \
 || (defined(__ARM_ARCH_6__) && __ARM_ARCH == 6) \
 || (defined(_M_ARM) && _M_ARM == 6)
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

#define AMOUNT_OF_RUNS 100U
#define MAX_PLAINTEXT_LENGTH 32768U
#define AMOUNT_OF_LENGTHS 7U

static const size_t plaintext_lengths[] = {1, 8, 16, 32, 64, 1536, 32768};
static uint8_t ALIGN(16) plaintext[MAX_PLAINTEXT_LENGTH];
static uint8_t ALIGN(16) assoc_data[MAX_PLAINTEXT_LENGTH];
static uint8_t ALIGN(16) ciphertext[MAX_PLAINTEXT_LENGTH];
static uint8_t ALIGN(16) tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
static uint8_t ALIGN(16) nonce[ASCON_AEAD_NONCE_LEN];
static uint8_t ALIGN(16) key[ASCON_AEAD128_KEY_LEN];
static uint8_t ALIGN(16) digest[ASCON_HASH_DIGEST_LEN];
static uint64_t cycles[AMOUNT_OF_LENGTHS][AMOUNT_OF_RUNS * 2];

static void randomise_input(void)
{
    unsigned int i;
    srand(123456);
    for (i = 0; i < MAX_PLAINTEXT_LENGTH; i++) { plaintext[i] = (uint8_t) rand(); }
    for (i = 0; i < MAX_PLAINTEXT_LENGTH; i++) { assoc_data[i] = (uint8_t) rand(); }
    for (i = 0; i < ASCON_AEAD128_KEY_LEN; i++) { key[i] = (uint8_t) rand(); }
    for (i = 0; i < ASCON_AEAD_NONCE_LEN; i++) { nonce[i] = (uint8_t) rand(); }
}

static uint64_t
measure_aead(const size_t plaintext_len)
{
    init_cpucycles();
    size_t repetitions = MAX_PLAINTEXT_LENGTH / plaintext_len;
    randomise_input();
    const uint64_t start = cpucycles(before);
    for (size_t i = 0; i < repetitions; i++)
    {
        ascon_aead128_encrypt(ciphertext, tag, key, nonce,
                              NULL, plaintext,
                              0, plaintext_len, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    }
    const uint64_t end = cpucycles(after);
    return end - start;
}

static uint64_t
measure_hash(const size_t plaintext_len)
{
    init_cpucycles();
    size_t repetitions = MAX_PLAINTEXT_LENGTH / plaintext_len;
    randomise_input();
    const uint64_t start = cpucycles(before);
    for (size_t i = 0; i < repetitions; i++)
    {
        ascon_hash(digest, plaintext, plaintext_len);
    }
    const uint64_t end = cpucycles(after);
    return end - start;
}

static int
compare_uint64(const void* first, const void* second)
{
    const uint64_t* ia = (const uint64_t*) first;
    const uint64_t* ib = (const uint64_t*) second;
    if (*ia > *ib) { return 1; }
    if (*ia < *ib) { return -1; }
    return 0;
}

static void
report(const char* title)
{
    const double factor = 1.0;
    size_t i;
    printf("%s\nCycles per byte (min, median):\n", title);
    for (i = 0; i < AMOUNT_OF_LENGTHS; i++)
    {
        const size_t repetitions = MAX_PLAINTEXT_LENGTH / plaintext_lengths[i];
        const size_t bytes = plaintext_lengths[i] * repetitions;
        printf("%5zu: %6.1f %6.1f\n", plaintext_lengths[i],
               factor * (double) cycles[i][0] / (double) bytes + 0.05,
               factor * (double) cycles[i][AMOUNT_OF_RUNS / 2U] / (double) bytes + 0.05);
    }
    printf("\n");
}

int
main(void)
{
    size_t i;
    size_t j;
    for (i = 0; i < AMOUNT_OF_LENGTHS; i++)
    {
        for (j = 0; j < AMOUNT_OF_RUNS; j++) { cycles[i][j] = measure_aead(plaintext_lengths[i]); }
        qsort(cycles[i], AMOUNT_OF_RUNS, sizeof(uint64_t), &compare_uint64);
    }
    report("Ascon128");
    for (i = 0; i < AMOUNT_OF_LENGTHS; i++)
    {
        for (j = 0; j < AMOUNT_OF_RUNS; j++) { cycles[i][j] = measure_hash(plaintext_lengths[i]); }
        qsort(cycles[i], AMOUNT_OF_RUNS, sizeof(uint64_t), &compare_uint64);
    }
    report("Ascon-Hash");

    return 0;
}
