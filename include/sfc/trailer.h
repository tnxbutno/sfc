#pragma once

/// @file trailer.h
/// @brief Pure parse/serialize for the SFC File Trailer (§3.4, 64 bytes).
///
/// Layout:
///   [0]  4   "TRLR" magic (0x54 0x52 0x4C 0x52)
///   [4]  4   Reserved (must be zero)
///   [8]  32  BLAKE3 hash of the Global Header Region
///   [40] 8   Encoder timestamp (unix seconds, LE uint64)
///   [48] 16  Reserved (must be zero)

#include "sfc/blake3_hash.h"
#include "sfc/error.h"

#include <array>
#include <cstdint>
#include <span>

namespace sfc {

/// Parsed File Trailer.
struct Trailer {
    Blake3Digest header_hash;  ///< BLAKE3 hash of the Global Header Region.
    uint64_t     timestamp;    ///< Unix epoch seconds (encoder-set; advisory).
};

/// @brief Parse a 64-byte File Trailer.
///
/// Verifies "TRLR" magic and both reserved regions are zero.
///
/// @param data Exactly 64 bytes.
/// @return Parsed Trailer, or error.
[[nodiscard]] Result<Trailer>
parse_trailer(std::span<const uint8_t, 64> data);

/// @brief Serialize a Trailer to 64 bytes (reserved bytes zeroed).
/// @param t Trailer to serialize.
/// @return 64-byte array.
[[nodiscard]] std::array<uint8_t, 64>
serialize_trailer(const Trailer& t);

}  // namespace sfc
