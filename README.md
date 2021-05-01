LibAscon - Lightweight Authenticated Encryption & Hashing
================================================================================

![Travis build status master](https://travis-ci.com/TheMatjaz/LibAscon.svg?branch=master)
![Travis build status develop](https://travis-ci.com/TheMatjaz/LibAscon.svg?branch=develop)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/TheMatjaz/LibAscon)
![GitHub](https://img.shields.io/github/license/TheMatjaz/LibAscon)

LibAscon is an ISO C11 cryptographic library wrapping the
[reference C implementation](https://github.com/ascon/ascon-c)
of the Ascon family of lightweight authenticated encryption schemes with
associated data (AEAD) and hashing functions, but it also includes
Init-Update-Final processing and variable tag length.


Features
----------------------------------------

LibAscon provides:

- 3 AEAD ciphers:
  - Ascon128 v1.2 (128 b key, 64 b rate)
  - Ascon128a v1.2 (128 b key, 128 b rate)
  - Ascon80pq v1.2 (160 b key, 64 b rate)

- 2 hashing functions
  - Ascon-Hash v1.2 (fixed-length output)
  - Ascon-XOF v1.2 (variable-length output)

- **Online processing** (**Init-Update-Final** paradigm) for hashing and
  encryption/decryption. This means that the data can be processed one
  chunk at the time. Useful when operating on large amounts of data that are
  not available contiguously in memory, e.g. a too-large file or data in
  transmission.

- Naturally offline processing (whole data contiguous in memory) is also
  available with a simple wrapper.

- **Variable tag length** for authenticated encryption: can generate any tag
  length **from 0 to 255 bytes**. Of course at least 16 bytes (128 bits) is
  recommended.
  
  Note: the tag bytes above 16 bytes are an extension of the original Ascon 
  algorithm using the same sponge squeezing technique as for the XOF;

- Encryption/decryption can be performed in-place, without the need of a
  second output buffer.

- Same performance as the original implementation in _Release_ mode,
  about 2x slower in _MinSizeRel_ mode.

- A **[heavily documented](https://thematjaz.github.io/LibAscon/)
  developer-friendly API**, making it easier to compile and add to your project,
  both through static and dynamic inclusion.

- Tested with **100% code coverage**!



FAQ
----------------------------------------

- **Q**: May I use this library for-
 
  **A**: YES! :D The library (and also the Ascon reference implementation)
  is released under the Creative Commons Zero (CC0) license which basically(*)
  means you can do whatever you want with it. Commercial purposes, personal
  projects, modifications of it, anything goes.
  
  (*) for the legally-binding text check the [license file](LICENSE.md).

- **Q**: Where is the documentation?

  **A**: The [library header file `inc/ascon.h`](inc/ascon.h) is documented with
  Doxygen and you can find it
  [compiled here](https://thematjaz.github.io/LibAscon/).

- **Q**: Why should I use Ascon-AEAD instead of, say, AES?
  
  **A**: Ascon is designed to be lightweight (great for embedded systems) and
  natively supports authenticated encryption of data of any length, while
  AES must be wrapped in an AEAD mode such as AES-GCM, which is well-proven
  but heavier.

- **Q**: Why should I use Ascon-Hash instead of, say, SHA-256?

  **A**: Ascon is designed to be lightweight (great for embedded systems)
  and does not suffer from length-extension attacks as SHA-256, given its
  sponge construction (similarly to what SHA-3 does). Additionally Ascon
  offers also the XOF hashing producing digests of variable length.

- **Q**: Who designed Ascon? Who wrote this library?

  **A**: Check the [Authors file](AUTHORS.md) for details.

- **Q**: I don't trust Ascon.

  **A**: Good. You should not keep your guard up for everything, but Ascon
  has been selected as the primary choice for lightweight authenticated 
  encryption in the final portfolio of the
  [CAESAR competition (2014–2019)](https://competitions.cr.yp.to/caesar-submissions.html)
  and is currently competing in the
  [NIST Lightweight Cryptography competition (2019–)](https://csrc.nist.gov/projects/lightweight-cryptography).
  Cryptographers like it and that's a good sign, right?

- **Q**: I don't trust this implementation.

  **A**: Good, again. You can read the source code to see what it
  does to be sure ;) If you find any bugs or possible improvements,
  open a pull request or an issue. I would like to make as clear and as good
  as possible.


Usage example
----------------------------------------

```c
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
        tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
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
        &is_tag_valid, tag, ASCON_AEAD_TAG_MIN_SECURE_LEN);
buffer[plaintext_len] = '\0'; // Null terminated, because it's text
printf("Decrypted msg: %s, tag is valid: %d\n", buffer, is_tag_valid);
// The macros ASCON_TAG_OK=true and ASCON_TAG_INVALID=false are also
// available if you prefer them over booleans for is_tag_valid.
```

For more examples, check the test suite.



Known limitations
----------------------------------------

- There is no architecture-specific optimisation, only a generic portable
  implementation using mostly `uint64_t` data types.



Compiling
----------------------------------------

### Static source inclusion

If you just want to compile manually from sources in your existing project:

- Copy the `inc` and `src` folders (or their content) into your existing
  C project.
- Add both to the include folders list.
- Add `src` to the sources folders list.
- Compile.


### Compiling Ascon into all possible targets with CMake

```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel 8
```

This will build all targets:

- `ascon`: a shared library (`.dll` or `.dylib`)
- static libraries:
  - `asconfull` with full feature set
  - `ascon128` with only Ascon128
  - `ascon128a` with only Ascon128a
  - `ascon80pq` with only Ascon80pq
  - `asconhash` with only Ascon-hash and Ascon-XOF
  - `ascon128hash` with only Ascon128, Ascon-hash and Ascon-XOF
  - `ascon128ahash` with only Ascon128a, Ascon-hash and Ascon-XOF
  - `ascon80pqhash` with only Ascon80pq, Ascon-hash and Ascon-XOF
  for a smaller build result when not all features are needed
- shared libraries:
  - `ascon` with full feature set (like `asconfull`, but shared)
- `testascon`: a test runner executable , which test all features
- `benchmark`: a simple benchmarking tool to get the number of CPU cycles per
  processed byte for offline-Ascon128 only. This is copied from the original
  reference implementation and used to compare the performance
  
Doxygen (if installed) is built separately to avoid recompiling it for any
library change:
```
cmake --build . --target doxygen
```

To compile only a single target, for example `ascon80pq`, run
```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --target ascon80pq
```

To compile with the optimisation for size, use the
`-DCMAKE_BUILD_TYPE=MinSizeRel` flag instead.
