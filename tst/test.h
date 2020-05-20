/**
 * @file
 * Tests run by the main().
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#ifndef TEST_H
#define TEST_H

#ifdef __cplusplus
extern "C"
{
#endif

void test_structs(void);

void test_xof(void);

void test_hash(void);

void test_aead128_encryption(void);

void test_aead128_decryption(void);

void test_aead128_inplace(void);

void test_aead128_vartaglen(void);

void test_aead128a_encryption(void);

void test_aead128a_decryption(void);

void test_aead128a_inplace(void);

void test_aead128a_vartaglen(void);

#ifdef __cplusplus
}
#endif

#endif  /* TEST_H */
