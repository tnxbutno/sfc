#pragma once

/// @file compression.h
/// @brief Pure compression/decompression dispatch for SFC algorithm IDs (Section 7).
///
/// Supports:
///   0x00 — identity (no-op)
///   0x01 — zstd (MUST)
///   0x02 — brotli (SHOULD)
///   0x03 — lz4 frame format (SHOULD)
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

/// @brief Parse a raw compression algorithm byte from the wire.
///
/// @param id Raw algorithm byte from the wire.
/// @return Corresponding CompressionAlgo value.
[[nodiscard]] constexpr CompressionAlgo normalize_compression_id(uint8_t id) noexcept {
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
