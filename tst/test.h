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

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

void test_structs(void);

void test_xof(void);

void test_hash(void);

void test_xofa(void);

void test_hasha(void);

void test_prf(void);

void test_aead128_encryption(void);

void test_aead128_decryption(void);

void test_aead128_inplace(void);

void test_aead128_vartaglen(void);

void test_aead128a_encryption(void);

void test_aead128a_decryption(void);

void test_aead128a_inplace(void);

void test_aead128a_vartaglen(void);

void test_aead80pq_encryption(void);

void test_aead80pq_decryption(void);

void test_aead80pq_inplace(void);

void test_aead80pq_vartaglen(void);

void test_readme_example(void);

#ifdef __cplusplus
}
#endif

#endif  /* TEST_H */
