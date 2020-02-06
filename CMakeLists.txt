cmake_minimum_required(VERSION 3.6)
project(ascon C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")
#set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG_PERMUTATIONS")

set(LIB_SRC_FILES
        src/ref/internal.h
        src/common.c
        src/ref/hash.c
        src/ref/aead128.c
        src/ref/permutations.c src/ref/buffering.c)
set(TEST_FRAMEWORK
        tst/atto/atto.c
        tst/main.c
        tst/vectors.c)
set(TEST_SRC_FILES
        tst/test_xof.c
        tst/test_hash.c
        tst/test_aead128_enc.c
        tst/test_aead128_dec.c
        tst/test_aead128_inplace.c)
include_directories(AFTER SYSTEM inc/ tst/atto/)
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

# TODO add release builds
# TODO https://stackoverflow.com/questions/10487256/cmake-how-to-properly-copy-static-librarys-header-file-into-usr-include
# TODO https://stackoverflow.com/questions/12899582/cmake-how-can-i-build-a-shared-and-a-static-library-without-recompiling-the-sou
# TODO https://stackoverflow.com/questions/17511496/how-to-create-a-shared-library-with-cmake
