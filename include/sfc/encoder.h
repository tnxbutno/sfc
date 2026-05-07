#pragma once

/// @file encoder.h
/// @brief Pure SFC encoder — builds a complete .sfc file in memory (§10).
///
/// All functions are pure (no I/O).

#include "sfc/error.h"
#include "sfc/types.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// Encoder parameters
// ---------------------------------------------------------------------------

/// Parameters controlling how an SFC file is encoded.
struct EncodeParams {
    uint32_t        m;           ///< Number of recovery chunks (0 = no erasure coding).
    uint32_t        s;           ///< Nominal chunk size in bytes (must be even, > 0).
    CompressionAlgo algo;        ///< Compression algorithm for all chunks.
    FileUuid        uuid;        ///< File UUID (caller must supply a random UUID).
    uint64_t        timestamp;   ///< Encoder timestamp (Unix epoch seconds; 0 = unset).
    uint16_t        format_id;   ///< Inner Format ID.
    std::string     filename;    ///< Inner filename (plain name, no path separator).
    uint16_t        flags = 0;   ///< Extra flags for the GlobalHeader (profile bits, etc.).
    FileMetadata    metadata;    ///< Optional user metadata stored in TLV fields.
    std::vector<uint32_t> priority_list; ///< Priority chunk indices for image profile (P1) Class P formats (§12.4).
                                         ///< For Class S (JPEG Baseline), auto-computed if empty.
};

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/// @brief Compute N = ceil(inner_file_size / s).
///
/// Exception per §10.1: if inner_file_size == 0, returns 1.
///
/// @param inner_file_size Total inner content byte count.
/// @param s               Nominal chunk size (must be > 0).
/// @return N, the number of data chunks required.
[[nodiscard]] constexpr uint32_t compute_n(uint64_t inner_file_size,
                                            uint32_t s) noexcept {
    if (inner_file_size == 0 || s == 0) return 1;
    return static_cast<uint32_t>((inner_file_size + s - 1) / s);
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// @brief Encode inner content into a complete SFC file (in memory).
///
/// Produces the full wire-format byte sequence:
///   8-byte preamble
///   Global Header Region (H+4 bytes)
///   N data chunks
///   M recovery chunks
///   64-byte Trailer
///
/// @param content  Inner content bytes.
/// @param params   Encoding parameters.
/// @return Complete SFC file bytes, or error.
[[nodiscard]] Result<std::vector<uint8_t>>
encode(std::span<const uint8_t> content, const EncodeParams& params);

}  // namespace sfc
