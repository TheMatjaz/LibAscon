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

static void test_readme_example_encrypting_iuf(void)
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
            tag, sizeof(tag));
    // The final function zeroes out the context automatically.
    // Now the buffer contains our ciphertext, long ciphertext_len bytes.

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
            &is_tag_valid, tag, sizeof(tag));
    buffer[plaintext_len] = '\0'; // Null terminated, because it's text
    printf("Decrypted msg: %s, tag is valid: %d\n", buffer, is_tag_valid);
    // The macros ASCON_TAG_OK=true and ASCON_TAG_INVALID=false are also
    // available if you prefer them over booleans for is_tag_valid.
    // The final function zeroes out the context automatically.

    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_memeq(buffer, plaintext_pt1, strlen(plaintext_pt1));
    atto_memeq(buffer + strlen(plaintext_pt1), plaintext_pt2, strlen
            (plaintext_pt2));
}

static void test_readme_example_encrypting_offline(void)
{
    // We need the key and the nonce, both 128 bits.
    // Note: Ascon80pq uses longer keys
    const uint8_t secret_key[ASCON_AEAD128_KEY_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    const uint8_t unique_nonce[ASCON_AEAD_NONCE_LEN] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };

    // For the "offline" operation, we need all data to be already contiguous
    // in memory. The operation is just one Ascon function call for the user.
    const char associated_data[] = "1 contiguous message will follow.";
    const char plaintext[] = "Hello, I'm a secret message and I should be encrypted!";

    uint8_t buffer[100];
    uint8_t tag[42];
    // To showcase the LibAscon extensions, we will generate an arbitrary-length
    // tag. Here is 42 bytes, but shorter-than-default (16) tags are also
    // possible e.g. 12 bytes for systems with heavy limitations.
    ascon_aead128_encrypt(buffer,
                          tag,
                          secret_key,
                          unique_nonce,
                          (uint8_t*) associated_data,
                          (uint8_t*) plaintext,
                          strlen(associated_data),
                          strlen(plaintext),
                          sizeof(tag));
    // The function zeroes out the context automatically.

    // The decryption looks almost the same. Just for fun, we will again
    // reuse the same buffer where the ciphertext is to write the plaintext into.
    bool is_tag_valid = ascon_aead128_decrypt(buffer, // Output plaintext
                                              secret_key,
                                              unique_nonce,
                                              (uint8_t*) associated_data,
                                              (uint8_t*) buffer, // Input ciphertext,
                                              tag, // Expected tag the ciphertext comes with
                                              strlen(associated_data),
                                              strlen(plaintext),
                                              sizeof(tag));
    // This time we get a boolean as a return value, which is true when
    // the tag is OK. To avoid confusion, it can also be compared to
    // two handy macros
    if (is_tag_valid == ASCON_TAG_OK)
    {
        puts("Correct decryption!");
    }
    else
    { // ASCON_TAG_INVALID
        puts("Something went wrong!");
    }
    // The function zeroes out the context automatically.

    atto_eq(is_tag_valid, ASCON_TAG_OK);
    atto_memeq(buffer, plaintext, strlen(plaintext));
}

static void test_readme_example_hashing_iuf(void)
{
    const uint8_t secret_key[] = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6
    };
    const char message_pt1[] = "Hello, I'm some data we need the digest of";
    const char message_pt2[] = " but I'm very long and I was not transmit";
    const char message_pt3[] = "ted in one contiguous block.";

    // Preparing the Ascon-XOF function. The XOF allows arbitrary digest size,
    // while Ascon-Hash (ascon_hash_init) has a fixed digest length.
    // NOTE: Ascon-Hash and Ascon-XOF produce different outputs!
    ascon_hash_ctx_t ctx;
    ascon_hash_xof_init(&ctx);

    // If we want a Message Authentication Code that also proves authenticity,
    // not only integrity of the message, we can simply prepend the key to the
    // message to hash, just like we would for SHA-3. Length extension attacks
    // are not a problem for Ascon-Hash/XOF, so the HMAC scheme is not needed.
    ascon_hash_xof_update(&ctx, (uint8_t*) secret_key, sizeof(secret_key));

    // Feeding chunk by chunk
    ascon_hash_xof_update(&ctx, (uint8_t*) message_pt1, strlen(message_pt1));
    ascon_hash_xof_update(&ctx, (uint8_t*) message_pt2, strlen(message_pt2));
    ascon_hash_xof_update(&ctx, (uint8_t*) message_pt3, strlen(message_pt3));

    // Finally, we get a digest of arbitrary length
    uint8_t digest[21];  // Choose any length from 0 to SIZE_MAX
    ascon_hash_xof_final(&ctx, digest, sizeof(digest));
    // The final function zeroes out the context automatically.

    // Now let's imagine we transmit the message alongside with the digest.
    // The receiver also has the secret key and can easily verify the keyed hash.
    ascon_hash_xof_init(&ctx);
    ascon_hash_xof_update(&ctx, (uint8_t*) secret_key, sizeof(secret_key));
    ascon_hash_xof_update(&ctx, (uint8_t*) message_pt1, strlen(message_pt1));
    ascon_hash_xof_update(&ctx, (uint8_t*) message_pt2, strlen(message_pt2));
    ascon_hash_xof_update(&ctx, (uint8_t*) message_pt3, strlen(message_pt3));
    // A handy function computing the obtained digest and validating it
    // against the obtained.
    bool is_tag_valid = ascon_hash_xof_final_matches(&ctx, digest, sizeof(digest));
    if (is_tag_valid == ASCON_TAG_OK)
    {
        puts("Correct decryption!");
    }
    else
    { // ASCON_TAG_INVALID
        puts("Something went wrong!");
    }

    atto_eq(is_tag_valid, ASCON_TAG_OK);
}

void test_readme_example(void)
{
    test_readme_example_encrypting_iuf();
    test_readme_example_encrypting_offline();
    test_readme_example_hashing_iuf();
}
