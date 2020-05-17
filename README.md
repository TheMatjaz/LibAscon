LibAscon - Lightweight Authenticated Encryption & Hashing
================================================================================

LibAscon is a ISO C11 library wrapping the
[reference C implementation](https://github.com/ascon/ascon-c)
of the Ascon family of lightweight authenticated encryption schemes with
associated data (AEAD) and hashing functions, including an extendible output
function (XOF).


Features
----------------------------------------

LibAscon provides:

- **online processing** (**Init-Update-Final** paradigm) for hasing and
  encryption/decryption. This means that the data can be processed one
  chunk at the time. Useful when operating on large amounts of data that are
  not available contiguously in memory, e.g. a too-large file or data in
  transmission;

- naturally offline processing (whole data contiguous in memory) is also
  available;

- variable tag length for authenticated encryption: can generate any tag length
  from 0 to 255 bytes. Of course at least 16 bytes (128 bits) is recommended.
  
  Note: the tag bytes above 16 B are an extension of the original Ascon 
  algorithm using the same sponge squeezing technique as for the XOF;

- encryption/decryption can be performed in-place, without the need of a
  second output buffer; 

- a **[documented](https://thematjaz.github.io/LibAscon/)
  developer-friendly API**, making it easier to compile and add to your project,
  both through static and dynamic inclusion



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

  **A**: Good, again. First of all you can read the source code to see what it
  does to be sure ;) If you find any bugs or possible improvements,
  open a pull request or an issue. I would like to make as clear and as good
  as possible.



Known limitations
----------------------------------------

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



Getting started
----------------------------------------

### Static source inclusion

Copy the `inc` and `src` folders (or their content) into your existing
C project, add them to the source folders and compile. Done.


### Compiling Ascon into all possible targets

```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

This will build all targets:

- a `libascon.dylib`/`libascon.dll` shared library
- a `libstaticascon.a` static library
- a test runner executable `testascon`
- the Doxygen documentation (if Doxygen is installed)
- a benchmarking tool `benchmark` to get the number of CPU cycles per
  processed byte

To compile with the optimisation for size, use the
`-DCMAKE_BUILD_TYPE=MinSizeRel` flag instead.

To compile only a single target, for example Doxygen, run
```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --target doxygen
```
