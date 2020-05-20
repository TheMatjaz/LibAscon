/**
 * @file
 * Tests of the AEAD128 encryption.
 *
 * @license Creative Commons Zero (CC0) 1.0
 * @authors Matjaž Guštin <dev@matjaz.it>
 */

#include "atto.h"
#include "test.h"
#include "ascon.h"

void test_readme_example(void)
{
    // Initialisation
    // We need the key and the nonce, both 128 bits.
    // Note: Ascon80pq uses longer keys
    const uint8_t secret_key[ASCON_AEAD128_KEY_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    const uint8_t unique_nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, secret_key, unique_nonce);

    // Now we feed any associated data into the cipher first
    // Our data is fragmented into 2 parts, so we feed one at the time.
    const char associated_data_pt1[] = "2 messages will foll";
    const char associated_data_pt2[] = "ow, but they are both secret.";
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt1, strlen
            (associated_data_pt1));
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt2, strlen
            (associated_data_pt2));

    // Next, we feed the plaintext, which is also fragmented in 2 parts.
    const char plaintext_pt1[] = "Hello, I'm a secret mes";
    const char plaintext_pt2[] = "sage and I should be encrypted!";
    uint8_t buffer[100];
    // The ciphertext is generated block-wise, so we need the return value
    // to know how to offset the pointer to where the next ciphertext
    // part should be written.
    size_t ciphertext_len = 0;
    ciphertext_len += ascon_aead128_encrypt_update(
            &ctx, buffer + ciphertext_len,
            (uint8_t*) plaintext_pt1, strlen(plaintext_pt1));
    ciphertext_len += ascon_aead128_encrypt_update(
            &ctx, buffer + ciphertext_len,
            (uint8_t*) plaintext_pt2, strlen(plaintext_pt2));

    // Finally, we wrap up the encryption and generate the tag.
    // There may still be some trailing ciphertext to be produced.
    // The tag length can be specified. ASCON_AEAD_TAG_MIN_SECURE_LEN is
    // the minimum recommended (128 b)
    uint8_t tag[ASCON_AEAD_TAG_MIN_SECURE_LEN];
    ciphertext_len += ascon_aead128_encrypt_final(
            &ctx, buffer + ciphertext_len,
            NULL, tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
    // Now the buffer contains our ciphertext, long ciphertext_len

    // Now we can decrypt
    ascon_aead128_init(&ctx, secret_key, unique_nonce);
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt1,
                                    strlen(associated_data_pt1));
    ascon_aead128_assoc_data_update(&ctx, (uint8_t*) associated_data_pt2,
                                    strlen(associated_data_pt2));
    // We perform the decryption in-place, in the same buffer where the
    // ciphertext it: to do so, we pass the same pointer for plaintext
    // and ciphertext
    size_t plaintext_len = 0;
    plaintext_len += ascon_aead128_decrypt_update(
            &ctx, buffer,
            buffer, ciphertext_len);
    // The final decryption step automatically checks the tag
    bool is_tag_valid = false;
    plaintext_len += ascon_aead128_decrypt_final(
            &ctx, buffer + plaintext_len,
            NULL,
            &is_tag_valid, tag,
            ASCON_AEAD_TAG_MIN_SECURE_LEN);
    printf("Tag is valid: %d\n", is_tag_valid);  // Yes, it's valid :)
    // The macros ASCON_TAG_OK=true and ASCON_TAG_INVALID=false are also
    // available if you prefer them over booleans for is_tag_valid.

    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_memeq(buffer, plaintext_pt1, strlen(plaintext_pt1));
    atto_memeq(buffer + strlen(plaintext_pt1), plaintext_pt2, strlen
            (plaintext_pt2));
}
