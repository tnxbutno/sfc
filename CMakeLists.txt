cmake_minimum_required(VERSION 3.25)
project(sfc VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # required by clang-tidy and IWYU

# ---------------------------------------------------------------------------
# Build options
# ---------------------------------------------------------------------------

option(SFC_ASAN   "Enable AddressSanitizer + UndefinedBehaviourSanitizer" OFF)
option(SFC_TSAN   "Enable ThreadSanitizer (mutually exclusive with SFC_ASAN)"  OFF)
option(SFC_FUZZ   "Build libFuzzer fuzz targets (requires Clang with libFuzzer)" OFF)
option(SFC_STATIC "Link third-party deps (zstd/brotli/lz4) statically into sfc CLI" OFF)

# On MSVC with static linking, all targets (including FetchContent deps) must
# use the same CRT. Set this before any FetchContent_MakeAvailable calls.
if(MSVC AND SFC_STATIC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(SFC_ASAN AND SFC_TSAN)
    message(FATAL_ERROR "SFC_ASAN and SFC_TSAN are mutually exclusive")
endif()

# ---------------------------------------------------------------------------
# Compiler warning flags
# ---------------------------------------------------------------------------
# Applied to sfc_lib (strict) and sfc_tests (slightly relaxed — avoids pedantic
# issues inside GTest macro expansions).

if(MSVC)
    set(SFC_WARN_LIB   /W4 /WX /permissive-)
    set(SFC_WARN_TESTS /W4 /WX /permissive-)
else()
    # Library: full strictness including conversion and sign warnings.
    set(SFC_WARN_LIB
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wdouble-promotion
        -Wformat=2
        -Wnull-dereference
        -Wimplicit-fallthrough
        -Werror
    )
    # Tests: same but skip -Wpedantic and conversion warnings — GTest macros
    # are not written to our stricter standard.
    # -Wno-missing-field-initializers: GCC fires on partial designated init
    # even though C++ zero-initializes omitted fields; suppress for tests.
    set(SFC_WARN_TESTS
        -Wall
        -Wextra
        -Wshadow
        -Wimplicit-fallthrough
        -Wno-missing-field-initializers
        -Werror
    )
endif()

# ---------------------------------------------------------------------------
# Sanitizer compile+link flags
# ---------------------------------------------------------------------------

set(SFC_SAN_FLAGS "")
if(SFC_ASAN)
    list(APPEND SFC_SAN_FLAGS
        -fsanitize=address,undefined  # ASan + UBSan together
        -fno-omit-frame-pointer       # readable stack traces
        -fno-sanitize-recover=all     # abort on first violation
        -g                            # debug symbols for reports
    )
elseif(SFC_TSAN)
    list(APPEND SFC_SAN_FLAGS
        -fsanitize=thread             # TSan (cannot combine with ASan)
        -fno-omit-frame-pointer
        -g
    )
endif()

# ---------------------------------------------------------------------------
# External dependencies
# ---------------------------------------------------------------------------

include(FetchContent)

# BLAKE3 — vendored via FetchContent (not in Homebrew)
FetchContent_Declare(
    blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG        1.8.2
    SOURCE_SUBDIR  c
)
FetchContent_MakeAvailable(blake3)

# CLI11 — header-only argument parsing for the sfc CLI
FetchContent_Declare(
    CLI11
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG        v2.4.2
)
FetchContent_MakeAvailable(CLI11)

# zstd, brotli, lz4 — Windows uses find_package (vcpkg), Unix uses pkg-config.
if(WIN32)
    find_package(zstd CONFIG REQUIRED)
    find_package(unofficial-brotli CONFIG REQUIRED)
    find_package(lz4 CONFIG REQUIRED)
    set(SFC_COMP_LIBS
        zstd::libzstd_static
        unofficial::brotli::brotlienc
        unofficial::brotli::brotlidec
        LZ4::lz4_static
    )
    set(SFC_COMP_INCLUDE_DIRS "")
    set(SFC_COMP_LIBRARY_DIRS "")
    set(SFC_COMP_CFLAGS       "")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(ZSTD   REQUIRED libzstd)
    pkg_check_modules(BROTLI REQUIRED libbrotlienc libbrotlidec)
    pkg_check_modules(LZ4    REQUIRED liblz4)

    if(SFC_STATIC AND NOT APPLE)
        # Use static libraries populated by pkg-config from Libs.private entries.
        set(SFC_COMP_LIBS ${ZSTD_STATIC_LIBRARIES} ${BROTLI_STATIC_LIBRARIES} ${LZ4_STATIC_LIBRARIES})
    else()
        set(SFC_COMP_LIBS ${ZSTD_LIBRARIES} ${BROTLI_LIBRARIES} ${LZ4_LIBRARIES})
    endif()
    set(SFC_COMP_INCLUDE_DIRS ${ZSTD_INCLUDE_DIRS} ${BROTLI_INCLUDE_DIRS} ${LZ4_INCLUDE_DIRS})
    set(SFC_COMP_LIBRARY_DIRS ${ZSTD_LIBRARY_DIRS} ${BROTLI_LIBRARY_DIRS} ${LZ4_LIBRARY_DIRS})
    set(SFC_COMP_CFLAGS       ${ZSTD_CFLAGS_OTHER} ${BROTLI_CFLAGS_OTHER} ${LZ4_CFLAGS_OTHER})
endif()

# ---------------------------------------------------------------------------
# Library: sfc_lib
# ---------------------------------------------------------------------------

add_library(sfc_lib
    src/byte_utils.cpp
    src/gf_arithmetic.cpp
    src/gf_matrix.cpp
    src/reed_solomon.cpp
    src/blake3_hash.cpp
    src/compression.cpp
    src/filename_sanitize.cpp
    src/tlv.cpp
    src/global_header.cpp
    src/chunk.cpp
    src/trailer.cpp
    src/segment_header.cpp
    src/manifest.cpp
    src/validation.cpp
    src/reassembly.cpp
    src/encoder.cpp
    src/decoder.cpp
    src/split_encoder.cpp
    src/split_decoder.cpp
    src/directory.cpp
)

target_include_directories(sfc_lib PUBLIC include)

target_link_libraries(sfc_lib PUBLIC blake3)

target_include_directories(sfc_lib SYSTEM PRIVATE ${SFC_COMP_INCLUDE_DIRS})
target_link_directories(sfc_lib PUBLIC ${SFC_COMP_LIBRARY_DIRS})
target_link_libraries(sfc_lib PUBLIC ${SFC_COMP_LIBS})
target_compile_options(sfc_lib PRIVATE ${SFC_WARN_LIB} ${SFC_COMP_CFLAGS})

# Sanitizer flags: compile the library objects with instrumentation.
if(SFC_SAN_FLAGS)
    target_compile_options(sfc_lib PRIVATE ${SFC_SAN_FLAGS})
    # Static library link flags propagate to consuming executables via PUBLIC.
    target_link_options(sfc_lib PUBLIC ${SFC_SAN_FLAGS})
endif()

# ---------------------------------------------------------------------------
# Tests: sfc_tests
# ---------------------------------------------------------------------------

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.15.2
)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(sfc_tests
    tests/test_byte_utils.cpp
    tests/test_gf_phase2.cpp
    tests/test_phase3.cpp
    tests/test_phase4.cpp
    tests/test_phase5.cpp
    tests/test_phase6.cpp
    tests/test_phase7.cpp
    tests/test_phase8_9.cpp
    tests/test_p2.cpp
    tests/test_p5.cpp
    tests/test_metadata.cpp
)

target_link_libraries(sfc_tests PRIVATE sfc_lib GTest::gtest_main)

# Mark GTest include dirs as SYSTEM to suppress warnings from GTest headers.
get_target_property(_gtest_incs GTest::gtest INTERFACE_INCLUDE_DIRECTORIES)
if(_gtest_incs)
    target_include_directories(sfc_tests SYSTEM PRIVATE ${_gtest_incs})
endif()

target_compile_options(sfc_tests PRIVATE ${SFC_WARN_TESTS})

# Sanitizer link flags for the test binary (the binary carries the runtime).
if(SFC_SAN_FLAGS)
    target_compile_options(sfc_tests PRIVATE ${SFC_SAN_FLAGS})
    target_link_options(sfc_tests PRIVATE ${SFC_SAN_FLAGS})
endif()

include(GoogleTest)
gtest_discover_tests(sfc_tests)

# ---------------------------------------------------------------------------
# CLI integration tests: sfc_cli_tests
# ---------------------------------------------------------------------------
# These tests invoke the compiled sfc binary and exercise all commands
# end-to-end against real files on disk.  SFC_BINARY_PATH is injected at
# compile time so the tests know the exact binary location regardless of
# the working directory when ctest is run.

add_executable(sfc_cli_tests tests/test_cli.cpp)

target_link_libraries(sfc_cli_tests PRIVATE GTest::gtest_main)

get_target_property(_gtest_incs GTest::gtest INTERFACE_INCLUDE_DIRECTORIES)
if(_gtest_incs)
    target_include_directories(sfc_cli_tests SYSTEM PRIVATE ${_gtest_incs})
endif()

target_compile_options(sfc_cli_tests PRIVATE ${SFC_WARN_TESTS})

# Pass the binary path as a compile-time string literal.
target_compile_definitions(sfc_cli_tests PRIVATE
    SFC_BINARY_PATH="$<TARGET_FILE:sfc_cli>")

# CLI tests must run after the sfc binary is built.
add_dependencies(sfc_cli_tests sfc_cli)

if(SFC_SAN_FLAGS)
    target_compile_options(sfc_cli_tests PRIVATE ${SFC_SAN_FLAGS})
    target_link_options(sfc_cli_tests PRIVATE ${SFC_SAN_FLAGS})
endif()

gtest_discover_tests(sfc_cli_tests)

# ---------------------------------------------------------------------------
# Collect all C++ sources for formatting and static analysis
# ---------------------------------------------------------------------------

file(GLOB_RECURSE SFC_ALL_SOURCES
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/include/sfc/*.h"
    "${CMAKE_SOURCE_DIR}/tests/*.cpp"
    "${CMAKE_SOURCE_DIR}/fuzz/*.cpp"
)

# Library sources only (clang-tidy + cppcheck skip test/fuzz files).
file(GLOB_RECURSE SFC_LIB_SOURCES
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/include/sfc/*.h"
)

# ---------------------------------------------------------------------------
# clang-format targets
# ---------------------------------------------------------------------------

find_program(CLANG_FORMAT_EXE
    NAMES clang-format
    PATHS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
)

if(CLANG_FORMAT_EXE)
    # format: apply formatting in-place to all C++ files.
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXE} -i ${SFC_ALL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "clang-format: formatting all sources in-place"
        VERBATIM
    )

    # format-check: fail if any file differs from the canonical format.
    add_custom_target(format-check
        COMMAND ${CLANG_FORMAT_EXE} --dry-run --Werror ${SFC_ALL_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "clang-format: checking format (fails on diff)"
        VERBATIM
    )
else()
    message(STATUS "clang-format not found — format/format-check targets unavailable")
endif()

# ---------------------------------------------------------------------------
# clang-tidy target (library sources only)
# ---------------------------------------------------------------------------

find_program(CLANG_TIDY_EXE
    NAMES clang-tidy
    PATHS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin
)

if(CLANG_TIDY_EXE)
    # Run clang-tidy on every library .cpp file using compile_commands.json.
    # --warnings-as-errors='*' means any finding is a hard failure.
    add_custom_target(lint-clang-tidy
        COMMAND ${CLANG_TIDY_EXE}
            -p "${CMAKE_BINARY_DIR}"
            --warnings-as-errors=*
            ${SFC_LIB_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "clang-tidy: static analysis (fails on any finding)"
        VERBATIM
    )
else()
    message(STATUS "clang-tidy not found — lint-clang-tidy target unavailable")
endif()

# ---------------------------------------------------------------------------
# cppcheck target
# ---------------------------------------------------------------------------

find_program(CPPCHECK_EXE cppcheck)

if(CPPCHECK_EXE)
    add_custom_target(lint-cppcheck
        COMMAND ${CPPCHECK_EXE}
            --enable=all
            --inconclusive
            --error-exitcode=1        # non-zero exit → CMake treats as failure
            --std=c++23
            --language=c++
            --suppress=missingIncludeSystem   # system headers not on search path
            --suppress=unusedFunction         # public API called only from tests
            --suppress=unmatchedSuppression   # keep config clean
            -I "${CMAKE_SOURCE_DIR}/include"
            "${CMAKE_SOURCE_DIR}/src"
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "cppcheck: deep static analysis (fails on any finding)"
        VERBATIM
    )
else()
    message(STATUS "cppcheck not found — lint-cppcheck target unavailable")
endif()

# ---------------------------------------------------------------------------
# include-what-you-use target
# ---------------------------------------------------------------------------

find_program(IWYU_EXE include-what-you-use
    PATHS /opt/homebrew/opt/include-what-you-use/bin
          /usr/local/bin
)
find_program(IWYU_TOOL_EXE iwyu_tool.py
    PATHS /opt/homebrew/opt/include-what-you-use/bin
          /usr/local/bin
)

if(IWYU_EXE AND IWYU_TOOL_EXE)
    # iwyu_tool.py drives IWYU using compile_commands.json.
    add_custom_target(iwyu
        COMMAND ${IWYU_TOOL_EXE}
            -p "${CMAKE_BINARY_DIR}"
            -- --no_fwd_decls
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "include-what-you-use: checking #include coverage"
        VERBATIM
    )
elseif(IWYU_EXE)
    # Fallback: run IWYU directly on each source file.
    add_custom_target(iwyu
        COMMAND ${IWYU_EXE}
            -p "${CMAKE_BINARY_DIR}"
            ${SFC_LIB_SOURCES}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        COMMENT "include-what-you-use: checking #include coverage (direct mode)"
        VERBATIM
    )
else()
    message(STATUS "include-what-you-use not found — iwyu target unavailable")
endif()

# ---------------------------------------------------------------------------
# Combined lint target
# ---------------------------------------------------------------------------

add_custom_target(lint COMMENT "Running all linters")

if(TARGET lint-clang-tidy)
    add_dependencies(lint lint-clang-tidy)
endif()
if(TARGET lint-cppcheck)
    add_dependencies(lint lint-cppcheck)
endif()

# ---------------------------------------------------------------------------
# CLI: sfc executable
# ---------------------------------------------------------------------------

add_executable(sfc_cli
    cli/main.cpp
    cli/cmd_pack.cpp
    cli/cmd_unpack.cpp
    cli/cmd_info.cpp
    cli/cmd_verify.cpp
    cli/cmd_repair.cpp
)

set_target_properties(sfc_cli PROPERTIES OUTPUT_NAME sfc)

target_include_directories(sfc_cli PRIVATE cli)
target_link_libraries(sfc_cli PRIVATE sfc_lib CLI11::CLI11)

# Use relaxed warnings (same as tests) — CLI11 macros not written to lib standard.
target_compile_options(sfc_cli PRIVATE ${SFC_WARN_TESTS})

# Propagate sanitizer flags when building in ASan/TSan mode.
if(SFC_SAN_FLAGS)
    target_compile_options(sfc_cli PRIVATE ${SFC_SAN_FLAGS})
    target_link_options(sfc_cli PRIVATE ${SFC_SAN_FLAGS})
endif()

# Static linking: embed third-party deps into the sfc binary.
if(SFC_STATIC)
    if(APPLE)
        # macOS: fully static binaries are not supported (no static libSystem).
        # Link C++ stdlib statically; result depends only on macOS system libs.
        target_link_options(sfc_cli PRIVATE -static-libstdc++)
    elseif(UNIX)
        # Linux: link C++ and GCC runtime statically. Third-party .a files are
        # already pulled in via pkg_check_modules STATIC above.
        # For a fully static binary (no glibc dep) use musl libc (see README).
        target_link_options(sfc_cli PRIVATE -static-libstdc++ -static-libgcc)
    endif()
endif()

# ---------------------------------------------------------------------------
# Fuzz targets  (cmake -DSFC_FUZZ=ON)
# ---------------------------------------------------------------------------

if(SFC_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR
            "SFC_FUZZ requires Clang (AppleClang or LLVM Clang). "
            "Set CC=clang CXX=clang++ before configuring.")
    endif()

    # libFuzzer instrumentation: -fsanitize=fuzzer also implies ASan.
    set(SFC_FUZZ_FLAGS -fsanitize=fuzzer,address -g -O1 -fno-omit-frame-pointer)

    # Build a sanitizer-instrumented copy of the library for the fuzz targets.
    add_library(sfc_lib_fuzz OBJECT ${CMAKE_CURRENT_SOURCE_DIR}/src/byte_utils.cpp
        src/gf_arithmetic.cpp src/gf_matrix.cpp src/reed_solomon.cpp
        src/blake3_hash.cpp src/compression.cpp src/filename_sanitize.cpp
        src/tlv.cpp src/global_header.cpp src/chunk.cpp src/trailer.cpp
        src/segment_header.cpp src/manifest.cpp src/validation.cpp
        src/reassembly.cpp src/encoder.cpp src/decoder.cpp
        src/split_encoder.cpp src/split_decoder.cpp src/directory.cpp
    )
    target_include_directories(sfc_lib_fuzz PUBLIC include)
    target_link_libraries(sfc_lib_fuzz PUBLIC blake3 ${SFC_COMP_LIBS})
    target_include_directories(sfc_lib_fuzz SYSTEM PRIVATE ${SFC_COMP_INCLUDE_DIRS})
    target_compile_options(sfc_lib_fuzz PRIVATE ${SFC_FUZZ_FLAGS})

    # fuzz_decode: exercises decode() with arbitrary bytes.
    add_executable(fuzz_decode fuzz/fuzz_decode.cpp)
    target_link_libraries(fuzz_decode PRIVATE sfc_lib_fuzz)
    target_compile_options(fuzz_decode PRIVATE ${SFC_FUZZ_FLAGS})
    target_link_options(fuzz_decode PRIVATE ${SFC_FUZZ_FLAGS})

    # fuzz_global_header: exercises parse_global_header() alone.
    add_executable(fuzz_global_header fuzz/fuzz_global_header.cpp)
    target_link_libraries(fuzz_global_header PRIVATE sfc_lib_fuzz)
    target_compile_options(fuzz_global_header PRIVATE ${SFC_FUZZ_FLAGS})
    target_link_options(fuzz_global_header PRIVATE ${SFC_FUZZ_FLAGS})

    # fuzz target: run both fuzzers for a bounded number of iterations.
    add_custom_target(fuzz
        COMMAND "${CMAKE_BINARY_DIR}/fuzz_decode"
                -max_len=131072 -runs=50000
        COMMAND "${CMAKE_BINARY_DIR}/fuzz_global_header"
                -max_len=65536  -runs=50000
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running fuzz targets (50k iterations each)"
        VERBATIM
    )
endif()
