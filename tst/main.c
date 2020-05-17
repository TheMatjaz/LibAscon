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
    printf("Testing Ascon M:%d m:%d bf:%d = v%s\n",
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
    return atto_at_least_one_fail;
}
