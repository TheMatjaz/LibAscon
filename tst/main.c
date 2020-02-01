/**
 * @file
 */

#include "atto.h"
#include "test.h"

int main(void)
{
    test_xof();
    return atto_at_least_one_fail;
}
