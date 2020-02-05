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
        src/ref/permutations.c)
set(TEST_FRAMEWORK
        tst/atto/atto.c
        tst/main.c
        tst/vectors.c)
set(TEST_SRC_FILES
        tst/test_xof.c
        tst/test_hash.c
        tst/test_aead128_enc.c
        tst/test_aead128_dec.c)
include_directories(AFTER SYSTEM inc/ tst/atto/)
add_library(staticascon OBJECT ${LIB_SRC_FILES})
add_library(ascon SHARED $<TARGET_OBJECTS:staticascon>)
add_executable(testascon
        $<TARGET_OBJECTS:staticascon>
        ${TEST_FRAMEWORK}
        ${TEST_SRC_FILES})
file(COPY tst/vectors DESTINATION ${CMAKE_BINARY_DIR})


# TODO https://stackoverflow.com/questions/10487256/cmake-how-to-properly-copy-static-librarys-header-file-into-usr-include
