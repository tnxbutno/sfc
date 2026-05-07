cmake_minimum_required(VERSION 3.25)
project(sfc_wasm CXX C)

if(NOT EMSCRIPTEN)
    message(FATAL_ERROR
        "This build must use the Emscripten toolchain:\n"
        "  emcmake cmake -S wasm -B wasm/build -DCMAKE_BUILD_TYPE=Release\n"
        "  cmake --build wasm/build")
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Some vendored CMake projects still declare cmake_minimum_required() below
# 3.5. CMake 4 rejects that unless the embedding project sets a floor.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)

include(FetchContent)

# BLAKE3

FetchContent_Declare(blake3
    GIT_REPOSITORY https://github.com/BLAKE3-team/BLAKE3.git
    GIT_TAG        1.8.2
    SOURCE_SUBDIR  c
)
set(BLAKE3_SIMD_TYPE none CACHE STRING "" FORCE)
FetchContent_MakeAvailable(blake3)

# zstd

FetchContent_Declare(zstd
    GIT_REPOSITORY https://github.com/facebook/zstd.git
    GIT_TAG        v1.5.6
    SOURCE_SUBDIR  build/cmake
)
set(ZSTD_BUILD_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_CONTRIB  OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(ZSTD_BUILD_SHARED   OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(zstd)

# brotli

FetchContent_Declare(brotli
    GIT_REPOSITORY https://github.com/google/brotli.git
    GIT_TAG        v1.1.0
)
set(BROTLI_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(brotli)
if(TARGET brotli)
    set_target_properties(brotli PROPERTIES EXCLUDE_FROM_ALL TRUE)
endif()

# lz4

FetchContent_Declare(lz4
    GIT_REPOSITORY https://github.com/lz4/lz4.git
    GIT_TAG        v1.9.4
    SOURCE_SUBDIR  build/cmake
)
set(LZ4_BUILD_CLI         OFF CACHE BOOL "" FORCE)
set(LZ4_BUILD_LEGACY_LZ4C OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(lz4)

# sfc library compiled for WASM

add_library(sfc_lib_wasm STATIC
    ../src/byte_utils.cpp
    ../src/gf_arithmetic.cpp
    ../src/gf_matrix.cpp
    ../src/reed_solomon.cpp
    ../src/blake3_hash.cpp
    ../src/compression.cpp
    ../src/filename_sanitize.cpp
    ../src/tlv.cpp
    ../src/global_header.cpp
    ../src/chunk.cpp
    ../src/trailer.cpp
    ../src/segment_header.cpp
    ../src/manifest.cpp
    ../src/validation.cpp
    ../src/reassembly.cpp
    ../src/encoder.cpp
    ../src/decoder.cpp
    ../src/split_encoder.cpp
    ../src/split_decoder.cpp
    ../src/directory.cpp
)

target_include_directories(sfc_lib_wasm PUBLIC
    ../include
    ${brotli_SOURCE_DIR}/c/include
)

target_link_libraries(sfc_lib_wasm PUBLIC
    blake3
    libzstd_static
    brotlienc
    brotlidec
    brotlicommon
    lz4_static
)

target_compile_options(sfc_lib_wasm PRIVATE -fwasm-exceptions)

# WASM binding

add_executable(sfc_wasm sfc_wasm.cpp)
set_target_properties(sfc_wasm PROPERTIES
    SUFFIX ".js"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../web
)

target_link_libraries(sfc_wasm PRIVATE sfc_lib_wasm)
target_compile_options(sfc_wasm PRIVATE -fwasm-exceptions)

target_link_options(sfc_wasm PRIVATE
    -fwasm-exceptions
    -lembind
    "SHELL:-sMODULARIZE=1"
    "SHELL:-sEXPORT_NAME=SfcModule"
    "SHELL:-sALLOW_MEMORY_GROWTH=1"
    "SHELL:-sINITIAL_MEMORY=33554432"
    -sSINGLE_FILE=1
    --no-entry
)
