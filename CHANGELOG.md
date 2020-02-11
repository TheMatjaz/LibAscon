Changelog
===============================================================================

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

*******************************************************************************

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
- There is no NULL pointer check for the mandatory function parameters, thus
  it will crash on improper usage.

