#pragma once

/// @file byte_utils.h
/// @brief Pure functions for little-endian encoding/decoding and byte operations.
///
/// All functions are pure (no side effects) and operate on spans or values.
/// These are the lowest-level utilities used by all SFC parsers/serializers.

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// @brief Read a uint16 from 2 bytes in little-endian order.
/// @param data Exactly 2 bytes to interpret.
/// @return The decoded uint16 value.
[[nodiscard]] uint16_t read_u16_le(std::span<const uint8_t, 2> data);

/// @brief Read a uint32 from 4 bytes in little-endian order.
/// @param data Exactly 4 bytes to interpret.
/// @return The decoded uint32 value.
[[nodiscard]] uint32_t read_u32_le(std::span<const uint8_t, 4> data);

/// @brief Read a uint64 from 8 bytes in little-endian order.
/// @param data Exactly 8 bytes to interpret.
/// @return The decoded uint64 value.
[[nodiscard]] uint64_t read_u64_le(std::span<const uint8_t, 8> data);

/// @brief Serialize a uint16 to 2 bytes in little-endian order.
/// @param value The value to serialize.
/// @return 2-byte array in LE order.
[[nodiscard]] std::array<uint8_t, 2> write_u16_le(uint16_t value);

/// @brief Serialize a uint32 to 4 bytes in little-endian order.
/// @param value The value to serialize.
/// @return 4-byte array in LE order.
[[nodiscard]] std::array<uint8_t, 4> write_u32_le(uint32_t value);

/// @brief Serialize a uint64 to 8 bytes in little-endian order.
/// @param value The value to serialize.
/// @return 8-byte array in LE order.
[[nodiscard]] std::array<uint8_t, 8> write_u64_le(uint64_t value);

/// @brief Check if all bytes in a span are zero.
/// @param data The byte span to check.
/// @return true if every byte is 0x00, or if span is empty.
[[nodiscard]] bool is_all_zeros(std::span<const uint8_t> data);

/// @brief Zero-pad data to target_size bytes.
/// @param input Source bytes.
/// @param target_size Desired output size. Must be >= input.size().
/// @return A vector of exactly target_size bytes: input followed by zeros.
///         If input.size() >= target_size, returns a copy of input (no truncation).
[[nodiscard]] std::vector<uint8_t> zero_pad(std::span<const uint8_t> input,
                                            size_t target_size);

/// @brief Trim data to target_size bytes (truncate).
/// @param input Source bytes.
/// @param target_size Desired output size. Must be <= input.size().
/// @return A vector of exactly target_size bytes from the start of input.
///         If input.size() <= target_size, returns a copy of input (no padding).
[[nodiscard]] std::vector<uint8_t> trim(std::span<const uint8_t> input,
                                        size_t target_size);

/// @brief Check if two byte spans have identical content.
/// @param a First span.
/// @param b Second span.
/// @return true if both spans have equal length and identical bytes.
[[nodiscard]] bool bytes_equal(std::span<const uint8_t> a,
                               std::span<const uint8_t> b);

}  // namespace sfc