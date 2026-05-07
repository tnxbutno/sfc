#pragma once

/// @file directory.h
/// @brief Pure directory profile encode and extract (P5, Section 16).
///
/// Inner content layout for a directory file:
///   [0 .. manifest_size-1]  Manifest (MFST header + entries + BLAKE3)
///   [manifest_size ..]      File contents concatenated in manifest order
///
/// The SFC container uses Inner Format ID 0x0050 and has Flag bit 8 (P5Directory) set.

#include "sfc/chunk.h"
#include "sfc/encoder.h"
#include "sfc/error.h"
#include "sfc/global_header.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// One input file when building a directory container.
struct DirectoryInputFile {
    std::string           path;       ///< Relative path (UTF-8, '/' separated).
                                      ///< Must not start with '/', contain '\\',
                                      ///< ".." or "." components, or control chars.
    std::vector<uint8_t>  content;    ///< Raw file bytes.
    uint16_t              format_id;  ///< Inner Format ID for this file.
};

/// One file extracted from a directory container.
struct ExtractedFile {
    std::string           path;       ///< Relative path from the manifest.
    std::vector<uint8_t>  content;    ///< Extracted and verified file bytes.
    uint16_t              format_id;  ///< Inner Format ID from the manifest.
};

/// Result of a full or partial directory extraction.
struct DirectoryExtractResult {
    std::vector<ExtractedFile> files;          ///< Fully extracted & verified files.
    std::vector<std::string>   pending_paths;  ///< Paths present in manifest but
                                               ///< not extractable (missing chunks).
};

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// @brief Encode a set of files as a directory container (P5, Section 16).
///
/// Steps:
///   1. Validate each path (no '..', '.', '\\', leading '/', control chars).
///   2. Detect case collisions via Unicode Simple Case Folding (Section 4.8).
///   3. Sort files by path (lexicographic).
///   4. Compute per-file BLAKE3 hashes.
///   5. Compute manifest_size from path lengths; derive byte_offsets.
///   6. Serialize the Manifest; build inner_content = manifest || files.
///   7. Set params.format_id = 0x0050, params.flags |= P5Directory (bit 8).
///   8. Call encode(inner_content, params).
///
/// @param files   Input files (paths must satisfy Section 16 constraints).
/// @param params  Base encode parameters (uuid, s, m, algo, timestamp).
///                filename and format_id are overridden internally.
/// @return Complete SFC file bytes, or SfcError.
[[nodiscard]] Result<std::vector<uint8_t>>
encode_directory(std::vector<DirectoryInputFile> files, EncodeParams params);

/// @brief Encode a set of files as a directory split across N carrier segments (P5+P2, Section 16).
///
/// Identical to encode_directory but calls encode_split instead of encode,
/// distributing chunks across num_segments output buffers.
///
/// @param files        Input files (same constraints as encode_directory).
/// @param params       Base encode parameters.
/// @param num_segments Number of carrier segments (>= 1, capped at N+M).
/// @return Vector of num_segments byte buffers, or SfcError.
[[nodiscard]] Result<std::vector<std::vector<uint8_t>>>
encode_directory_split(std::vector<DirectoryInputFile> files,
                       EncodeParams params,
                       uint32_t num_segments);

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

/// @brief Full directory extraction from fully-reassembled inner content.
///
/// Parses the Manifest from the first manifest_size bytes, validates
/// byte_offset consistency (Section 16.7), then extracts and BLAKE3-verifies each
/// file from the remaining bytes.
///
/// @param inner_content Trimmed inner content bytes (manifest || files).
/// @return DirectoryExtractResult on success.
[[nodiscard]] Result<DirectoryExtractResult>
extract_directory_full(std::span<const uint8_t> inner_content);

/// @brief Partial directory extraction when fewer than N chunks are available.
///
/// Section 16.8 Case A (V >= N): RS reconstruction -> full_reassembly -> extract_directory_full.
/// Section 16.8 Case B (V < N): Uses whatever chunks are available.
///   - Requires chunk 0 to determine manifest_size and K = ceil(manifest_size/S).
///   - Requires all K manifest chunks to parse the Manifest.
///   - For each file, checks whether all covering chunks are present.
///   - Fully covered files are extracted and BLAKE3-verified.
///   - Partially covered files appear in pending_paths.
///
/// @param working_set  All validated chunks (data + recovery, any order).
/// @param hdr          Parsed Global Header.
/// @return DirectoryExtractResult, or SfcError if chunk 0 / manifest chunks absent.
[[nodiscard]] Result<DirectoryExtractResult>
extract_directory_partial(const std::vector<ParsedChunk>& working_set,
                          const GlobalHeader& hdr);

}  // namespace sfc
