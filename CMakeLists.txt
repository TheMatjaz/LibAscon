cmake_minimum_required(VERSION 3.6)
project(ascon C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(LIB_SRC_FILES src/batch.c src/xof/ref/hash.c)
#set(TEST_INC_FILES tst/vectors/vectors.h)
set(TEST_SRC_FILES tst/main.c tst/test_xof.c tst/vectors.c)
include_directories(AFTER SYSTEM inc/)
add_library(libascon STATIC ${LIB_SRC_FILES})
add_executable(testascon ${LIB_SRC_FILES} ${TEST_SRC_FILES})
file(COPY tst/vectors DESTINATION ${CMAKE_BINARY_DIR})


# TODO https://stackoverflow.com/questions/10487256/cmake-how-to-properly-copy-static-librarys-header-file-into-usr-include
