#pragma once

/// @file manifest.h
/// @brief Pure parse/serialize for the directory Manifest (P5, §16.2, §16.3).
///
/// Manifest binary layout:
///   [0]     4    "MFST" magic
///   [4]     4    Body length B (LE uint32); B = 4 + sum(entry sizes)
///   [8]     4    File count F (LE uint32)
///   [12]    var  F file entries (§16.3)
///   [8+B]   32   BLAKE3(bytes 0..8+B-1)
///
/// File entry layout (§16.3):
///   [0]   2    Path length L (LE uint16)
///   [2]   L    Relative path (UTF-8)
///   [2+L] 8    Byte offset in inner content (LE uint64)
///   [10+L]8    File size (LE uint64)
///   [18+L]32   Per-file BLAKE3 hash
///   [50+L]2    Inner Format ID (LE uint16)
///   Total: 52 + L bytes per entry.

#include "sfc/blake3_hash.h"
#include "sfc/error.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace sfc {

/// One file entry in the Manifest (§16.3).
struct ManifestFileEntry {
    std::string  path;           ///< Relative path (UTF-8, '/' separated).
    uint64_t     byte_offset;    ///< Byte offset in inner content stream.
    uint64_t     file_size;      ///< File size in bytes.
    Blake3Digest file_hash;      ///< BLAKE3 of this file's content.
    uint16_t     inner_format_id;///< Inner Format ID.
};

/// Parsed Manifest.
struct Manifest {
    std::vector<ManifestFileEntry> entries; ///< F file entries.
    Blake3Digest                   hash;    ///< BLAKE3 of the manifest header+body.
};

/// @brief Parse a Manifest from bytes (complete manifest_size bytes).
///
/// Verifies "MFST" magic, BLAKE3 hash, and entry offsets.
///
/// @param data Complete Manifest bytes (8 + B + 32 = manifest_size).
/// @return Parsed Manifest on success.
[[nodiscard]] Result<Manifest>
parse_manifest(std::span<const uint8_t> data);

/// @brief Serialize a Manifest to bytes.
///
/// Computes B, F, all entry bytes, and the BLAKE3 hash.
///
/// @param entries File entries to include.
/// @return Serialized Manifest bytes (manifest_size = 8+B+32).
[[nodiscard]] std::vector<uint8_t>
serialize_manifest(const std::vector<ManifestFileEntry>& entries);

/// @brief Compute manifest_size from raw manifest bytes (reads only B field).
///
/// Useful for computing K = ceil(manifest_size / S) from partial data.
///
/// @param chunk0_decompressed Decompressed bytes of chunk 0 (at least 8 bytes).
/// @return manifest_size = 8 + B + 32, or error if magic invalid.
[[nodiscard]] Result<uint64_t>
manifest_size_from_chunk0(std::span<const uint8_t> chunk0_decompressed);

}  // namespace sfc
