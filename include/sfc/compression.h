#pragma once

/// @file compression.h
/// @brief Pure compression/decompression dispatch for SFC algorithm IDs (Section 7).
///
/// Supports:
///   0x00 — identity (no-op)
///   0x01 — zstd (MUST)
///   0x02 — deprecated synonym for 0x01 (MUST decode as zstd)
///   0x03 — brotli (SHOULD)
///   0x04 — lz4 frame format (SHOULD)
///
/// All functions are pure (no side effects).

#include "sfc/error.h"
#include "sfc/types.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// Normalization
// ---------------------------------------------------------------------------

/// @brief Normalize a compression algorithm ID per Section 7.1.
///
/// Algorithm 0x02 (deprecated "zstd level 19") MUST be treated identically
/// to 0x01 (zstd).  All other IDs are returned unchanged.
///
/// @param id Raw algorithm byte from the wire.
/// @return Normalized CompressionAlgo value.
[[nodiscard]] constexpr CompressionAlgo normalize_compression_id(uint8_t id) noexcept {
    // 0x02 is a deprecated synonym; normalise to 0x01 before any comparison.
    if (id == 0x02) return CompressionAlgo::Zstd;
    return static_cast<CompressionAlgo>(id);
}

// ---------------------------------------------------------------------------
// Compression
// ---------------------------------------------------------------------------

/// @brief Compress data using the given algorithm.
///
/// Each call compresses independently (per-chunk independence, Section 7.3).
/// Algorithm 0x00 returns a copy of the input unchanged.
///
/// @param data  Input bytes to compress.
/// @param algo  Compression algorithm ID (will be normalised internally).
/// @return Compressed bytes on success, or SfcError on failure.
[[nodiscard]] Result<std::vector<uint8_t>> compress(std::span<const uint8_t> data,
                                                     CompressionAlgo algo);

// ---------------------------------------------------------------------------
// Decompression
// ---------------------------------------------------------------------------

/// @brief Decompress a chunk payload.
///
/// For algorithm 0x00 (identity): returns a copy of the input.
/// For other algorithms: decompresses and verifies the output size matches
/// expected_size (per spec §6.4: decompressed size MUST equal S).
///
/// @param data          Compressed bytes (chunk payload).
/// @param algo          Compression algorithm ID (normalised internally).
/// @param expected_size Expected decompressed size in bytes (= S for data/recovery chunks).
///                      Pass 0 to skip the size check.
/// @return Decompressed bytes on success, or SfcError on failure.
[[nodiscard]] Result<std::vector<uint8_t>> decompress(std::span<const uint8_t> data,
                                                       CompressionAlgo algo,
                                                       size_t expected_size);

}  // namespace sfc
