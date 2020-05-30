Changelog
===============================================================================

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

*******************************************************************************

[1.0.1] - 2020-05-30
----------------------------------------

Fixed slowdowns - now as fast as reference implementation, 100% test coverage.


### Fixed

- Fixed 2x slowdown compared to original reference implementation by
  unrolling loops in `ascon_permutation_[a12|b8|b6]`. Apparently the
  compiler does not do that automatically, even when requested with
  `-funroll-loops`.
  This brings LibAscon to the same performance as the reference implementation,
  when compiled in _Release_ mode.

- When building in _MinSizeRel_ mode (`-DCMAKE_BUILD_TYPE=MinSizeRel`), the core
  round and permutation functions are not hinted to be inlined by the compiled,
  thus the library takes slightly less space.

- Replaced rewritten benchmark runner with original one (copy-pasted and
  slightly changed). Apparently the rewritten benchmark was about 2x slower.
  Now the benchmark results are comparable between original implementation
  and LibAscon.

- Test coverage reached 100%: removed a dead branch in
  `ascon_aead80pq_decrypt_final()`, which was a copy-paste error.

- Fix a `int` to `uint8` type conversion warning.

- Removed unused internal `log_sponge()` function, making the library slightly
  smaller.



[1.0.0] - 2020-05-21
----------------------------------------

First stable version with all ciphers.


### Modified

- **Breaking** change from previous versions: removed `total_output_len`
  parameters from the functions
  - `ascon_aead*_encrypt()`
  - `ascon_aead*_decrypt()`
  - `ascon_aead*_encrypt_final()`
  - `ascon_aead*_decrypt_final()`
  and from the `ascon_bufstate_t` struct, making it 8 B smaller.
  Why? TL;DR it's redundant.
  
  The reasoning is that the user of the first two (offline processing)
  already knows the length of the plaintext/ciphertext; the user of the second
  two obtains the length of the processed chunks as return values so they
  can simply sum the up - and anyhow the user known the length of all the
  chunks provided to the cipher; those could be summed up to. In most of the
  cases the argument was `NULL` in the function usage. For details on how to
  obtain the total length, the example in the Readme should suffice.
- Renamed all files in `src` so they start with `ascon_`.


### Fixed

- Added more tests to cover more branching cases of the online-buffering
  algorithm.
- Removal of some minor warnings after inspection with static analyser
  (`scan-build`) and CLion code inspection tool.
- Typos
- Added missing _Known limitations_ paragraphs to the previous releases
  in this Changelog.


### Known limitations

- Because LibAscon is implemented with reuse of existing functions in mind,
  in order to spare on code size and with the Init-Update-Digest paradigm,
  which has some internal buffering, the cipher is about **4x slower** than the
  [reference implementation (`ref`)](https://github.com/ascon/ascon-c).
- There is no architecture-specific optimisation, only a generic portable
  implementation using mostly `uint64_t` data types.



[0.4.0] - 2020-05-20
----------------------------------------

Added Ascon80pq cipher, example in Readme.


### Added

- `ascon_aead128a_*` functions, working exactly as the `aead128` versions.
  Internally they absorb the data with a double rate.
- Example encryption and decrpytion code into Readme.


### Removed

- Macros to exclude some parts of the library from the previous version,
  as they only complicate the building process. It's easier to exclude some
  source files from the build, now that they are better organised.
  - `ASCON_COMPILE_AEAD128`
  - `ASCON_COMPILE_AEAD128a`
  - `ASCON_COMPILE_AEAD80pq`
  -` ASCON_COMPILE_HASH`


### Known limitations

- Because LibAscon is implemented with reuse of existing functions in mind,
  in order to spare on code size and with the Init-Update-Digest paradigm,
  which has some internal buffering, the cipher is about **4x slower** than the
  [reference implementation (`ref`)](https://github.com/ascon/ascon-c).
- There is no architecture-specific optimisation, only a generic portable
  implementation using mostly `uint64_t` data types.



[0.3.0] - 2020-05-20
----------------------------------------

Added Ascon128a cipher and macros to exclude some parts of the library.


### Added

- `ascon_aead128a_*` functions, working exactly as the `aead128` versions.
  Internally they absorb the data with a double rate.
- Added macros to exclude some parts of the library if they are not needed
  for a smaller build
  - `ASCON_COMPILE_AEAD128`
  - `ASCON_COMPILE_AEAD128a`
  - `ASCON_COMPILE_AEAD80pq` (which is not included in the lib yet) 
  -` ASCON_COMPILE_HASH`


### Known limitations

- Because LibAscon is implemented with reuse of existing functions in mind,
  in order to spare on code size and with the Init-Update-Digest paradigm,
  which has some internal buffering, the cipher is about **4x slower** than the
  [reference implementation (`ref`)](https://github.com/ascon/ascon-c).
- There is no architecture-specific optimisation, only a generic portable
  implementation using mostly `uint64_t` data types.
- The only AEAD algorithms implemented are Ascon128 and Ascon128a. Ascon80pq is
  still to be done.



[0.2.0] - 2020-05-17
----------------------------------------

Variable tags length, secure context cleanup, minor QOL improvements.


### Added

- `ascon_aead128_cleanup()` and `ascon_hash_cleanup()` to securely cleanup
  the context in case the online processing is not terminated with the
  final function.


### Changed

- `ascon_aead128_encrypt()`, `ascon_aead128_encrypt_final()`,
  `ascon_aead128_decrypt()`, `ascon_aead128_decrypt_final()`
  have a **new parameter**: `tag_len`. The user can specify the length of the
  tag to generate and verify respectively. The value can be any value in
  [0, 255] bytes. At least 16 is of course recommended.
  
  Note: the tag bytes above 16 B are an extension of the original Ascon 
  algorithm using the same sponge squeezing technique as for the XOF.

- Replace `ascon_tag_validity_t` enum with simpler `bool` from `stdbool.h`
  indicating "is tag valid?": `true` for valid, `false` otherwise. It's one
  less datatype to handle. Macros `ASCON_TAG_OK` and `ASCON_TAG_INVALID`
  are still available.

- Because of the previous point: `srtbool.h` as now a dependency.

- Changed ISO C standard for compilation from C99 to C11, as there are
  no noticeable differences for this codebase.


### Fixed

- Improvements in the Doxygen documentation, especially the security warnings.
- Some warnings about type casting when compiling on GCC for Windows or
  ARM microcontrollers with strict warning settings (`-Wall`, `-Wextra` etc.).
- Variety of typos and linter warnings.
- Minor readme improvements.


### Known limitations

- Same as in v0.1.0



[0.1.0] - 2020-02-11
----------------------------------------

Initial version.


### Added

- AEAD encryption and decryption with Ascon128, both offline and online
- Hashing with Ascon-Hash and Ascon-XOF, both offline and online
- Test suite checking against test vectors
- Wrapping everything with single extensively documented header file


### Known limitations

- At the moment the library is **optimised for size**, making the cipher
  about 4x slower than the
  [reference implementation](https://github.com/ascon/ascon-c).
  On the other hand the size of the whole library is about 2x smaller than the
  AEAD-Ascon128 implementation alone, while the library includes online
  processing, Ascon-Hash and Ascon-XOF.
- There is no architecture-specific optimisation yet, only a generic portable
  C implementation using mostly `uint64_t` data types.
- The only AEAD algorithm implemented is the Ascon128 AEAD. The Ascon128a and 
  Ascon80pq are still to be done.

