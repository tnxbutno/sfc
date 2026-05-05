#include "sfc/byte_utils.h"

#include <algorithm>  // std::all_of, std::copy, std::equal, std::min, std::max
#include <bit>        // std::endian, std::byteswap
#include <cstring>    // std::memcpy

namespace sfc {

// ---------------------------------------------------------------------------
// Reading little-endian integers from raw bytes
// ---------------------------------------------------------------------------
// SFC is a little-endian format (least significant byte first). For example,
// the number 0x0801 is stored on disk as two bytes: [0x01, 0x08].
//
// How it works:
// 1. memcpy copies raw bytes into a uint16/32/64 variable.
//    Why memcpy instead of *(uint16_t*)ptr? Because direct pointer casting
//    is undefined behavior in C++ (strict aliasing violation).
//    memcpy is the only correct way to reinterpret bytes as integers.
// 2. "if constexpr" is a compile-time check (not a runtime branch!).
//    On our Mac (ARM64, little-endian) this branch is completely eliminated
//    by the compiler — byteswap is never called. The code exists only for
//    portability to big-endian platforms.
// ---------------------------------------------------------------------------

uint16_t read_u16_le(std::span<const uint8_t, 2> data) {
    // span<const uint8_t, 2> is a "pointer" to exactly 2 bytes.
    // The size is checked at compile time, not at runtime.
    uint16_t value;
    std::memcpy(&value, data.data(), 2);
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);  // reverses byte order
    }
    return value;
}

uint32_t read_u32_le(std::span<const uint8_t, 4> data) {
    uint32_t value;
    std::memcpy(&value, data.data(), 4);
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    return value;
}

uint64_t read_u64_le(std::span<const uint8_t, 8> data) {
    uint64_t value;
    std::memcpy(&value, data.data(), 8);
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    return value;
}

// ---------------------------------------------------------------------------
// Writing integers to little-endian bytes
// ---------------------------------------------------------------------------
// Reverse operation: integer -> byte array.
// Returns std::array of fixed size (stack-allocated, no heap allocation).
// ---------------------------------------------------------------------------

std::array<uint8_t, 2> write_u16_le(uint16_t value) {
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    std::array<uint8_t, 2> result;
    std::memcpy(result.data(), &value, 2);
    return result;
}

std::array<uint8_t, 4> write_u32_le(uint32_t value) {
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    std::array<uint8_t, 4> result;
    std::memcpy(result.data(), &value, 4);
    return result;
}

std::array<uint8_t, 8> write_u64_le(uint64_t value) {
    if constexpr (std::endian::native == std::endian::big) {
        value = std::byteswap(value);
    }
    std::array<uint8_t, 8> result;
    std::memcpy(result.data(), &value, 8);
    return result;
}

// ---------------------------------------------------------------------------
// Byte checks and manipulation
// ---------------------------------------------------------------------------

// Checks that every byte in the span is zero.
// Used for validating reserved fields per spec Section 5.5:
// "Decoders MUST treat non-zero reserved bytes as a hard format error"
bool is_all_zeros(std::span<const uint8_t> data) {
    // std::all_of returns true if the lambda returns true for EVERY element.
    // For an empty span it returns true (no elements = all conditions met).
    return std::all_of(data.begin(), data.end(),
                       [](uint8_t b) { return b == 0; });
}

// Zero-pads data to target_size bytes.
// Used for padding the last data chunk to S bytes before RS encoding (Section 5.2):
// "The last data chunk MUST be zero-padded to exactly S bytes"
std::vector<uint8_t> zero_pad(std::span<const uint8_t> input,
                               size_t target_size) {
    // Create a zero-filled vector of the required size, then copy input
    // into the beginning.
    std::vector<uint8_t> result(std::max(input.size(), target_size), 0);
    std::copy(input.begin(), input.end(), result.begin());
    return result;
}

// Truncates data to target_size bytes.
// Used for trimming to Inner File Size after reassembly (Section 9.1 step 3):
// "Trim output to Inner File Size"
std::vector<uint8_t> trim(std::span<const uint8_t> input,
                           size_t target_size) {
    const size_t actual = std::min(input.size(), target_size);
    // Vector constructor from two iterators — copies the range [begin, begin+actual).
    return {input.begin(), input.begin() + static_cast<std::ptrdiff_t>(actual)};
}

// Compares two byte spans for equality.
// Used for checking magic bytes, UUID comparisons, etc.
bool bytes_equal(std::span<const uint8_t> a,
                  std::span<const uint8_t> b) {
    if (a.size() != b.size()) return false;
    return std::equal(a.begin(), a.end(), b.begin());
}

}  // namespace sfc
