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
    printf("Testing Ascon v%d.%d.%d\n", ASCON_API_VERSION_MAJOR,
            ASCON_API_VERSION_MINOR, ASCON_API_VERSION_BUGFIX);
    test_structs();
    test_xof();
    test_hash();
    test_aead128_encryption();
    test_aead128_decryption();
    test_aead128_inplace();
    return atto_at_least_one_fail;
}
