# CMake compiler flags as used by LibAscon
# License: Creative Commons Zero (CC0) 1.0

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
message(STATUS "C compiler ID: ${CMAKE_C_COMPILER_ID}")

# https://cmake.org/cmake/help/latest/module/CheckCCompilerFlag.html
include(CheckCCompilerFlag)

# Check if a compiler supports a flag, appending it to the proper flags
# variable. Cache the result so it's faster on the next config.
# Ispired by https://gist.github.com/jibsen/74c64ac50d7a37a3f5f329ccfc749970
function(compflag COMPILER_FLAGS)
    foreach(FLAG ${ARGN})
        # Create a string representing the compiler flag with only alphanumeric
        # characters, so it's easy to cache
        string(REGEX REPLACE "[^0-9A-Za-z]+" "_"
                ACCEPTED "COMPILER_FLAG_ACCEPTED_${FLAG}")
        # Verify whether the FLAG is accepted by the compiler. The result is
        # cached into the ACCEPTED variable so the next configuration is fast.
        check_c_compiler_flag("${FLAG}" ${ACCEPTED})
        if(${ACCEPTED})
            set(${COMPILER_FLAGS} "${${COMPILER_FLAGS}} ${FLAG}")
        else()
            set(COMPILER_FLAGS_REJECTED "${COMPILER_FLAGS_REJECTED} ${FLAG}")
        endif()
    endforeach()
    # Copy local variables to outer scope
    set(${COMPILER_FLAGS} "${${COMPILER_FLAGS}}" PARENT_SCOPE)
    set(COMPILER_FLAGS_REJECTED "${COMPILER_FLAGS_REJECTED}" PARENT_SCOPE)
endfunction()


if (MSVC)
    message(STATUS "Using compiler flags for Microsoft Visual C++ compiler CL (MSVC)")

    # Activate a million warnings to have the cleanest possible code
    compflag(CMAKE_C_FLAGS "-Wall")  # Activate all warnings
    # (compared to GCC, this actually turns on ALL of the warnings, not just most)
    compflag(CMAKE_C_FLAGS "-Qspectre")  # Let the compiler inject Spectre mitigation code

    # Suppress the warning about Spectre mitigation.
    # The problem is that even when the Spectre mitigation flag is enabled, the warning about
    # the mitigation being required still appears, so we have to forcibly disable it.
    compflag(CMAKE_C_FLAGS "-wd5045")

    # Suppress warning about deprecated stdio functions.
    # The warning notifies that the functions should be replaced with the safer C11 alternatives
    # fopen -> fopen_s, fscanf -> fscanf_s etc. Here they are only used in the test framework,
    # not in the Ascon implementation, so they are not critical. They are also used in a safe
    # manner to start with, given that the parsed data is fixed (the test vectors).
    # Finally, not every clib implements them, so we cannot assume the compilation succeeds
    # if we use them. Thus, better deactivated.
    compflag(CMAKE_C_FLAGS "-wd4996")

    # Suppress warning about constant conditional expr.
    # This warning only pops up in the test suite's checks of the Ascon context and state struct
    # sizes, which ARE constant. The tests are there just as a double-check, an assertion,
    # and must stay, so the warning is disabled.
    compflag(CMAKE_C_FLAGS "-wd4127")

    # Suppress informational warning about inlining.
    # MSVC notifies with a warning when the optimised inlines/does not inline a function that
    # is not/is marked for inlining. The warning is informational, thus disabled.
    compflag(CMAKE_C_FLAGS "-wd4710 -wd4711")

    # Debug mode
    compflag(CMAKE_C_FLAGS_DEBUG "-Od")  # Do not optimise

    # Release mode optimised for speed
    compflag(CMAKE_C_FLAGS_RELEASE "-O2")  # Optimise for speed
    compflag(CMAKE_C_FLAGS_RELEASE "-WX")  # Warnings as errors

    # Release mode optimised for size
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-O1")  # Optimise for size
    compflag(CMAKE_C_FLAGS_RELEASE "-WX")  # Warnings as errors
else ()
    message(STATUS "Using compiler flags for GCC and Clang")

    # Activate a million warnings to have the cleanest possible code
    compflag(CMAKE_C_FLAGS "-Wall -Wextra -pedantic") # Activate most warnings
    compflag(CMAKE_C_FLAGS "-Wconversion")  # Values are implicitly converted
    compflag(CMAKE_C_FLAGS "-Wsign-conversion")  # Signed to/from unsigned implicit conversion
    compflag(CMAKE_C_FLAGS "-Wdouble-promotion")  # Floats implicitly promoted to doubles
    compflag(CMAKE_C_FLAGS "-Wfloat-equal")  # Floats compared exactly instead of approx.
    compflag(CMAKE_C_FLAGS "-Wswitch-default")  # Switch-case missing default
    compflag(CMAKE_C_FLAGS "-Wswitch-enum")  # Switch-case of an enum not covering all values
    compflag(CMAKE_C_FLAGS "-Wuninitialized")  # Usage of uninitialised variable
    compflag(CMAKE_C_FLAGS "-Wno-unused-variable")  # Variable never used
    compflag(CMAKE_C_FLAGS "-Wpacked")  # Packing of struct not needed

    # NOTE: deactivating padded struct warning: all structs in LibAscon have been inspected and
    # optimised. Some will still inevitably have trailing padding (to reach the aligned address
    # where the next struct in an array of structs would start) and this padding varies on each
    # platform. There is not much to be done anymore.
    #compflag(CMAKE_C_FLAGS "-Wpadded")  # Struct contains paddings

    compflag(CMAKE_C_FLAGS "-Wshadow")  # Shadowing variable name
    compflag(CMAKE_C_FLAGS "-Waggregate-return")  # Returning a struct from a function
    compflag(CMAKE_C_FLAGS "-Wformat-security")  # (s/f)printf format string vulnerability
    compflag(CMAKE_C_FLAGS "-Wlogical-not-parentheses")  # Unclear boolean expression
    compflag(CMAKE_C_FLAGS "-Wmissing-declarations")  #
    compflag(CMAKE_C_FLAGS "-Wnull-dereference")  # Potential NULL pointer dereference
    compflag(CMAKE_C_FLAGS "-Wduplicate-cond")  # Checking same thing twice

    # NOTE: deactivating goto warnings: they are used only within the test suite, not the library
    #compflag(CMAKE_C_FLAGS "-Wjump-misses-init")  # Switch/goto jump skips variable init

    # Debug mode
    compflag(CMAKE_C_FLAGS_DEBUG "-g3")  # Max debug info
    compflag(CMAKE_C_FLAGS_DEBUG "-O0")  # Do not optimise
    compflag(CMAKE_C_FLAGS_DEBUG "-coverage")  # Gather code coverage info

    # Release mode optimised for speed
    compflag(CMAKE_C_FLAGS_RELEASE "-O3")  # Max optimisation for speed
    compflag(CMAKE_C_FLAGS_RELEASE "-s")  # Strip binary
    compflag(CMAKE_C_FLAGS_RELEASE "-Werror")  # Warnings as errors
    compflag(CMAKE_C_FLAGS_RELEASE "-fomit-frame-pointer")
    compflag(CMAKE_C_FLAGS_RELEASE "-march=native")
    compflag(CMAKE_C_FLAGS_RELEASE "-mtune=native")

    # Release mode optimised for size
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-Os")  # Optimise for size
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-s")  # Strip binary
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-fomit-frame-pointer")
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-march=native")
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-mtune=native")
    compflag(CMAKE_C_FLAGS_MINSIZEREL "-funroll-loops")
endif ()
# Options for all compilers
compflag(CMAKE_C_FLAGS "")
compflag(CMAKE_C_FLAGS_DEBUG "-DDEBUG")
compflag(CMAKE_C_FLAGS_RELEASE "-DRELEASE")
compflag(CMAKE_C_FLAGS_MINSIZEREL "-DMINSIZEREL")
# Sanitiser flags
compflag(CMAKE_C_FLAGS_DEBUG "-static-libsan")   # Note: san, not Asan, for GCC
compflag(CMAKE_C_FLAGS_DEBUG "-static-libasan")  # Note: Asan, not san, for Clang
compflag(CMAKE_C_FLAGS_DEBUG "-fsanitize=address,undefined")
compflag(CMAKE_C_FLAGS_DEBUG "-fno-omit-frame-pointer")
compflag(CMAKE_C_FLAGS_DEBUG "-mno-omit-leaf-frame-pointer")

# Some information for the user
message(STATUS "Accepted compiler flags: CMAKE_C_FLAGS = ${CMAKE_C_FLAGS}")
message(STATUS "Accepted compiler flags: CMAKE_C_FLAGS_DEBUG = ${CMAKE_C_FLAGS_DEBUG}")
message(STATUS "Accepted compiler flags: CMAKE_C_FLAGS_RELEASE = ${CMAKE_C_FLAGS_RELEASE}")
message(STATUS "Accepted compiler flags: CMAKE_C_FLAGS_MINSIZEREL = ${CMAKE_C_FLAGS_MINSIZEREL}")
if (COMPILER_FLAGS_REJECTED)
    message(STATUS "Rejected compiler flags: COMPILER_FLAGS_REJECTED = ${COMPILER_FLAGS_REJECTED}")
endif()
