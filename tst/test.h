/**
 * @file
 *
 * @copyright Copyright © 2020, Matjaž Guštin <dev@matjaz.it>
 * <https://matjaz.it>. All rights reserved.
 * @license BSD 3-clause license.
 */

#ifndef TEST_H
#define TEST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>

void test_log(const char* string);

void test_log_hexbytes(const char* name,
                       const uint8_t* array,
                       size_t amount);

void test_xof(void);

#ifdef __cplusplus
}
#endif

#endif  /* TEST_H */
