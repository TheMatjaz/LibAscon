/**
 * @file
 */

#include "atto.h"
#include "test.h"

int main(void)
{
    // TODO test for ALL pointers being also NULL and not crashing
    test_utils();
    test_xof();
    test_hash();
    return atto_at_least_one_fail;
}
