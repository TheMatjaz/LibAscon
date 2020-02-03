/**
 * @file
 */

#include "test.h"
#include "atto.h"
#include "ascon.h"

static void test_ciphertext_len(void)
{
    atto_eq(ASCON_AEAD_BLOCK_SIZE, 16);
    atto_eq(ascon_ciphertext_len(0), 0);
    atto_eq(ascon_ciphertext_len(1), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(2), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(7), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(8), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(9), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(15), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(16), ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(17), 2 * ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(18), 2 * ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(31), 2 * ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(32), 2 * ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(33), 3 * ASCON_AEAD_BLOCK_SIZE);;
    atto_eq(ascon_ciphertext_len(47), 3 * ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(48), 3 * ASCON_AEAD_BLOCK_SIZE);
    atto_eq(ascon_ciphertext_len(49), 4 * ASCON_AEAD_BLOCK_SIZE);
}

void test_utils(void)
{
    test_ciphertext_len();
}
