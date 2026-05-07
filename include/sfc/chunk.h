#pragma once

/// @file chunk.h
/// @brief Pure parse/serialize for SFC chunk structures (Section 5).
///
/// Physical layout of one chunk:
///   48 bytes  ChunkHeader
///   P  bytes  Payload (compressed; P = compressed_payload_length)
///   36 bytes  ChunkTrailer (32-byte BLAKE3 + 4-byte "/CHK" marker)

#include "sfc/blake3_hash.h"
#include "sfc/error.h"
#include "sfc/types.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// ChunkHeader - 48 bytes fixed
// ---------------------------------------------------------------------------

/// Parsed chunk header (48 bytes, Section 5.1).
struct ChunkHeader {
    FileUuid uuid;                  ///< 16-byte File UUID.
    uint32_t chunk_index;           ///< Position index (0-based).
    ChunkType chunk_type;           ///< Data (1) or Recovery (2).
    uint32_t compressed_payload_len;///< Compressed payload byte count.
    uint8_t  compression_algo;     ///< Compression algorithm ID.
    uint8_t  erasure_algo;         ///< Erasure coding algorithm ID.
    // Bytes 34-47 are reserved and must be zero.
};

/// @brief Parse a 48-byte chunk header.
/// @param data Exactly 48 bytes.
/// @return Parsed ChunkHeader, or error for unknown chunk type.
[[nodiscard]] Result<ChunkHeader>
parse_chunk_header(std::span<const uint8_t, 48> data);

/// @brief Serialize a ChunkHeader to 48 bytes (reserved bytes zeroed).
/// @param hdr Header to serialize.
/// @return 48-byte array.
[[nodiscard]] std::array<uint8_t, 48>
serialize_chunk_header(const ChunkHeader& hdr);

// ---------------------------------------------------------------------------
// ChunkTrailer - 36 bytes fixed
// ---------------------------------------------------------------------------

/// @brief Parse the 36-byte chunk trailer.
///
/// Verifies the "/CHK" end marker at bytes 32-35.
///
/// @param data Exactly 36 bytes.
/// @return BLAKE3 digest stored in the trailer, or error if end marker invalid.
[[nodiscard]] Result<Blake3Digest>
parse_chunk_trailer(std::span<const uint8_t, 36> data);

/// @brief Serialize a chunk trailer from its BLAKE3 hash.
/// @param hash 32-byte BLAKE3 digest.
/// @return 36-byte trailer (hash + "/CHK" end marker).
[[nodiscard]] std::array<uint8_t, 36>
serialize_chunk_trailer(const Blake3Digest& hash);

// ---------------------------------------------------------------------------
// ParsedChunk - complete parsed chunk
// ---------------------------------------------------------------------------

/// A fully parsed chunk (header + compressed payload + verified hash).
struct ParsedChunk {
    ChunkHeader          header;   ///< Parsed 48-byte header.
    std::vector<uint8_t> payload;  ///< Compressed payload bytes.
    Blake3Digest         hash;     ///< BLAKE3 hash from the trailer.
};

/// @brief Parse one complete chunk from a byte span.
///
/// Reads header (48), payload (header.compressed_payload_len), trailer (36).
/// Does NOT verify the BLAKE3 hash - caller must call blake3_verify_concat.
///
/// @param data Byte span starting at the first "CHK\0" magic byte.
/// @return {ParsedChunk, bytes_consumed} on success.
[[nodiscard]] Result<std::pair<ParsedChunk, size_t>>
parse_chunk(std::span<const uint8_t> data);

/// @brief Serialize a complete chunk (header + payload + trailer).
///
/// Computes the BLAKE3 hash of (header_bytes || payload) and writes the trailer.
///
/// @param hdr     Chunk header.
/// @param payload Compressed payload bytes.
/// @return Complete chunk bytes (48 + payload.size() + 36).
[[nodiscard]] std::vector<uint8_t>
serialize_chunk(const ChunkHeader& hdr, const std::vector<uint8_t>& payload);

}  // namespace sfc
