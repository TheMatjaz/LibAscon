/**
 * @file
 * Main file of the test suite, running it.
 *
 * Returns non-zero in case at least 1 testcase failed.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"

int main(void)
{
    printf("Testing LibAscon M:%d m:%d bf:%d = v%s\n",
           ASCON_API_VERSION_MAJOR,
           ASCON_API_VERSION_MINOR,
           ASCON_API_VERSION_BUGFIX,
           ASCON_API_VERSION);
    test_structs();
    test_xof();
    test_hash();
    test_aead128_encryption();
    test_aead128_decryption();
    test_aead128_inplace();
    test_aead128_vartaglen();
    test_aead128a_encryption();
    test_aead128a_decryption();
    test_aead128a_inplace();
    test_aead128a_vartaglen();
    test_aead80pq_encryption();
    test_aead80pq_decryption();
    test_aead80pq_inplace();
    test_aead80pq_vartaglen();
    test_readme_example();
    return atto_at_least_one_fail;
}
