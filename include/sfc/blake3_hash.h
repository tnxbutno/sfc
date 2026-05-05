#pragma once

/// @file blake3_hash.h
/// @brief Pure BLAKE3 hashing wrappers for SFC integrity verification.
///
/// SFC uses BLAKE3 as the sole hash algorithm (Section 8).
/// All functions are pure (no side effects).
///
/// Usage:
///   - blake3()        — hash a single byte span
///   - blake3_concat() — hash two spans as if they were concatenated
///                       (used for per-chunk integrity: header || payload)
///   - blake3_verify() — constant-time comparison against an expected hash

#include "sfc/error.h"

#include <array>
#include <cstdint>
#include <span>

namespace sfc {

/// BLAKE3 digest size in bytes (fixed at 32 for all SFC uses).
inline constexpr size_t kBlake3DigestSize = 32;

/// A 32-byte BLAKE3 digest.
using Blake3Digest = std::array<uint8_t, kBlake3DigestSize>;

/// @brief Compute the BLAKE3 hash of a byte span.
/// @param data Input bytes (may be empty).
/// @return 32-byte digest.
[[nodiscard]] Blake3Digest blake3(std::span<const uint8_t> data) noexcept;

/// @brief Compute the BLAKE3 hash of two byte spans concatenated.
///
/// Equivalent to blake3(concat(a, b)) but avoids a heap allocation.
/// Used for per-chunk integrity (Section 8.1): hash(header_bytes || payload_bytes).
///
/// @param a First byte span.
/// @param b Second byte span.
/// @return 32-byte digest of a||b.
[[nodiscard]] Blake3Digest blake3_concat(std::span<const uint8_t> a,
                                         std::span<const uint8_t> b) noexcept;

/// @brief Verify a byte span against an expected BLAKE3 digest.
///
/// Uses a constant-time comparison to prevent timing side-channels.
///
/// @param data     Input bytes to hash.
/// @param expected Expected 32-byte digest.
/// @return VoidResult: success if digests match, ErrorCode::ChunkBlake3Failure otherwise.
[[nodiscard]] VoidResult blake3_verify(std::span<const uint8_t> data,
                                       const Blake3Digest& expected) noexcept;

/// @brief Verify two spans (concatenated) against an expected BLAKE3 digest.
///
/// Equivalent to blake3_verify(concat(a,b), expected) without heap allocation.
/// Used for D3d per-chunk validation: verify(header||payload, stored_hash).
///
/// @param a        First span (e.g. chunk header bytes).
/// @param b        Second span (e.g. chunk payload bytes).
/// @param expected Expected 32-byte digest.
/// @return VoidResult: success if digests match, ErrorCode::ChunkBlake3Failure otherwise.
[[nodiscard]] VoidResult blake3_verify_concat(std::span<const uint8_t> a,
                                              std::span<const uint8_t> b,
                                              const Blake3Digest& expected) noexcept;

}  // namespace sfc
