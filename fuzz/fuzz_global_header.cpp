/// @file fuzz_global_header.cpp
/// @brief libFuzzer entry point for the binary-structure parsers.
///
/// Fuzzes three parsers independently per input using byte-range splitting:
///   - parse_global_header  (bytes [0 .. size/3))
///   - parse_chunk          (bytes [size/3 .. 2*size/3))
///   - parse_manifest       (bytes [2*size/3 .. size))
///
/// This lets a single corpus entry exercise three different attack surfaces.

#include "sfc/chunk.h"
#include "sfc/global_header.h"
#include "sfc/manifest.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    // Divide input into three non-overlapping regions.
    const size_t third  = size / 3;
    const size_t third2 = 2 * third;

    // --- parse_global_header ---
    // Accepts a span of arbitrary length; returns an error for anything invalid.
    {
        auto result = sfc::parse_global_header(
            std::span<const uint8_t>{data, third});
        (void)result;
    }

    // --- parse_chunk ---
    // Reads 48-byte header + payload + 36-byte trailer; safe with any input.
    {
        auto result = sfc::parse_chunk(
            std::span<const uint8_t>{data + third, third2 - third});
        (void)result;
    }

    // --- parse_manifest ---
    // Reads MFST header + body + BLAKE3; verifies checksum.
    {
        auto result = sfc::parse_manifest(
            std::span<const uint8_t>{data + third2, size - third2});
        (void)result;
    }

    return 0;
}
