cmake_minimum_required(VERSION 3.6)
project(LibAscon
        VERSION 0.1.0
        LANGUAGES C
        DESCRIPTION "Lightweight Authenticated Encryption & Hashing")

# Unless specified, by default create Release builds
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)



# -----------------------------------------------------------------------------
# Compiler flags
# -----------------------------------------------------------------------------
set(CMAKE_C_STANDARD 99)
# Activate a million warnings to have the cleanest possible code
set(FLAGS_WARNINGS -Wall -Wextra -pedantic -Wconversion -Wdouble-promotion
        -Wswitch-default -Wswitch-enum -Wuninitialized -Wno-unused-variable
        -Wpacked -Wpadded -Wshadow -Wformat-security -Wlogical-not-parentheses
        -Waggregate-return -Wmissing-declarations -Wmissing-declarations)
# Debug build: compile with no optimisation, debug info and printing
set(CMAKE_C_FLAGS_DEBUG "${WARNING_FLAGS} -g -O0 -DDEBUG")
# Append sanitiser flags on non-Windows systems
if (NOT WIN32 AND NOT CYGWIN AND NOT MSYS)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} \
            -fsanitize=address,undefined -static-libsan")
endif ()

# Mini-sized release build: compile with optimisation for size
# convert warnings into errors, have position independent code
# and some other optimisations
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} \
        ${WARNING_FLAGS} \
        -Os -Werror -fPIC -fomit-frame-pointer -march=native -mtune=native")

# Performance-oriented release build: compile with optimisation for speed
# convert warnings into errors, have position independent code
# and some other optimisations
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} \
        ${WARNING_FLAGS} \
        -O3 -Werror -fPIC -fomit-frame-pointer -march=native -mtune=native \
        -funroll-loops")



# -----------------------------------------------------------------------------
# Source files
# -----------------------------------------------------------------------------
set(LIB_SRC_FILES
        src/internal.h
        src/offline.c
        src/hash.c
        src/aead128.c
        src/permutations.c
        src/buffering.c)
set(TEST_FRAMEWORK
        tst/atto/atto.c
        tst/main.c
        tst/vectors.c)
set(TEST_SRC_FILES
        tst/test_xof.c
        tst/test_hash.c
        tst/test_aead128_enc.c
        tst/test_aead128_dec.c
        tst/test_aead128_inplace.c
        tst/test_structs.c)
set(BENCHMARK_SRC_FILES
        tst/benchmark.c)
include_directories(AFTER SYSTEM inc/ tst/atto/)



# -----------------------------------------------------------------------------
# Build targets
# ----------------------------------------------------------------------------
# Build the library first into an object, but keep `objlibascon` as
# a reference to it, so there is no need to recompile it when building
# a different target, that uses the same source files.
add_library(objlibascon OBJECT ${LIB_SRC_FILES})

# Shared library (dylib / dll)
add_library(ascon SHARED $<TARGET_OBJECTS:objlibascon>)

# Test runner executable
add_executable(testascon
        $<TARGET_OBJECTS:objlibascon>
        ${TEST_FRAMEWORK}
        ${TEST_SRC_FILES})
# Copy test vectors files to build directory after the make-build.
# They are used by the test runner
add_custom_command(
        TARGET testascon POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/tst/vectors
        ${CMAKE_BINARY_DIR}/vectors)
# Delete the test vectors file on make-clean
set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
        "${CMAKE_BINARY_DIR}/vectors")

# Benchmark runner executable
add_executable(benchmark
        $<TARGET_OBJECTS:objlibascon>
        ${BENCHMARK_SRC_FILES})

# Doxygen documentation builder
find_package(Doxygen)
if (DOXYGEN_FOUND)
    # Cmake's wrapper of Doxygen, constructing a doxyfile from the
    # DOXYGEN_* variables, which are mapped to the Doxygen variables.
    set(DOXYGEN_GENERATE_HTML YES)
    set(DOXYGEN_GENERATE_MAN YES)
    set(DOXYGEN_JAVADOC_AUTOBRIEF YES)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
    set(DOXYGEN_ALIASES license="**License:**")
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE README.md)
    doxygen_add_docs(doxygen
            # List of input files for Doxygen
            ${PROJECT_SOURCE_DIR}/inc/ascon.h
            ${PROJECT_SOURCE_DIR}/LICENSE
            ${PROJECT_SOURCE_DIR}/AUTHORS.md
            ${PROJECT_SOURCE_DIR}/README.md
            ${PROJECT_SOURCE_DIR}/CHANGELOG.md)
else (DOXYGEN_FOUND)
    message(WARNING "Doxygen not found. Cannot generate documentation.")
endif (DOXYGEN_FOUND)

# TODO https://stackoverflow.com/questions/10487256/cmake-how-to-properly-copy-static-librarys-header-file-into-usr-include
# TODO https://stackoverflow.com/questions/12899582/cmake-how-can-i-build-a-shared-and-a-static-library-without-recompiling-the-sou
# TODO https://stackoverflow.com/questions/17511496/how-to-create-a-shared-library-with-cmake
