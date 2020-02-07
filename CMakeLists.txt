cmake_minimum_required(VERSION 3.6)
project(ascon C)

# Unless specified, by default create Release builds
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif ()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG_PERMUTATIONS")

### Compiler flags
set(CMAKE_C_STANDARD 99)
set(FLAGS_WARNINGS -Wall -Wextra -pedantic -Wconversion -Wdouble-promotion
        -Wswitch-default -Wswitch-enum -Wuninitialized -Wno-unused-variable
        -Wpacked -Wpadded -Wshadow -Wformat-security -Wlogical-not-parentheses
        -Waggregate-return -Wmissing-declarations -Wmissing-declarations)
set(CMAKE_C_FLAGS_DEBUG "${WARNING_FLAGS} -g -O0")
# Append sanitiser flags on non-Windows systems
if (NOT WIN32 AND NOT CYGWIN AND NOT MSYS)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} \
            -fsanitize=address,undefined -static-libsan")
endif ()
set(CMAKE_C_FLAGS_MINSIZEREL "${CMAKE_C_FLAGS_MINSIZEREL} \
        ${WARNING_FLAGS} \
        -Os -Werror -fPIC -fomit-frame-pointer -march=native -mtune=native")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} \
        ${WARNING_FLAGS} \
        -O3 -Werror -fPIC -fomit-frame-pointer -march=native -mtune=native \
        -funroll-loops")


### Source files
set(LIB_SRC_FILES
        src/internal.h
        src/offline.c
        src/hash.c
        src/aead128.c
        src/permutations.c src/buffering.c)
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

### Targets
# Build the library itself into object code, but keep `objlibascon` as
# a reference to it, so there is no need to recompile it when building
# a different target.
add_library(objlibascon OBJECT ${LIB_SRC_FILES})
add_library(ascon SHARED $<TARGET_OBJECTS:objlibascon>)
add_executable(testascon
        $<TARGET_OBJECTS:objlibascon>
        ${TEST_FRAMEWORK}
        ${TEST_SRC_FILES})
# Copy test vectors files to build directory after the make-build
add_custom_command(
        TARGET testascon POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/tst/vectors
        ${CMAKE_BINARY_DIR}/vectors)
add_executable(benchmark
        $<TARGET_OBJECTS:objlibascon>
        ${BENCHMARK_SRC_FILES})

# TODO https://stackoverflow.com/questions/10487256/cmake-how-to-properly-copy-static-librarys-header-file-into-usr-include
# TODO https://stackoverflow.com/questions/12899582/cmake-how-can-i-build-a-shared-and-a-static-library-without-recompiling-the-sou
# TODO https://stackoverflow.com/questions/17511496/how-to-create-a-shared-library-with-cmake
