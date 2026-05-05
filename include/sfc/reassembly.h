#pragma once

/// @file reassembly.h
/// @brief Pure reassembly procedures §9.1 (full), §9.2 (unverified), §9.3 (partial).
///
/// All functions are pure (no I/O). They operate on in-memory data.

#include "sfc/chunk.h"
#include "sfc/error.h"
#include "sfc/global_header.h"

#include <cstdint>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// Verification status
// ---------------------------------------------------------------------------

/// Describes the verification status of a reassembly result.
enum class ReassemblyStatus {
    FullyVerified,         ///< All hashes checked (D2c + D5f).
    ContentVerified,       ///< Global file hash verified but Trailer absent.
    Partial,               ///< Incomplete; output is a byte prefix.
};

/// Result of a reassembly operation.
struct ReassemblyResult {
    std::vector<uint8_t>  content;        ///< Reassembled inner content bytes.
    ReassemblyStatus      status;         ///< Verification level.
    std::vector<uint32_t> missing_chunks; ///< Indices absent (for Partial).
    FileMetadata          metadata;       ///< Metadata from TLV fields (may be empty).
};

// ---------------------------------------------------------------------------
// Duplicate handling (§9.5, applied before reassembly)
// ---------------------------------------------------------------------------

/// @brief Handle duplicate chunks per §9.5.
///
/// Benign duplicates (same hash): keeps one copy.
/// Contaminated (same index, different hash):
///   - B1: exactly one passes hash check → keep it.
///   - B2: both pass → hard error (ContaminatedDuplicate).
///   - B3: neither passes → discard both.
///
/// @param chunks Input chunks (may contain duplicates).
/// @return Deduplicated vector, or ContaminatedDuplicate on B2.
[[nodiscard]] Result<std::vector<ParsedChunk>>
handle_duplicates(std::vector<ParsedChunk> chunks);

// ---------------------------------------------------------------------------
// §9.1 Full Reassembly
// ---------------------------------------------------------------------------

/// @brief Full reassembly (§9.1): all N chunks present, Trailer verified.
///
/// Decompresses each data chunk, concatenates blocks, trims to inner_file_size,
/// verifies global hash (D5f).
///
/// @param data_chunks   Exactly N decompressed data blocks in index order.
/// @param hdr           Parsed Global Header.
/// @param trailer_verified True if D2c has been verified (Trailer hash passed).
/// @return ReassemblyResult with FullyVerified or ContentVerified status.
[[nodiscard]] Result<ReassemblyResult>
full_reassembly(const std::vector<std::vector<uint8_t>>& data_blocks,
                const GlobalHeader& hdr,
                bool trailer_verified);

// ---------------------------------------------------------------------------
// §9.3 Partial Reassembly
// ---------------------------------------------------------------------------

/// @brief Partial reassembly (§9.3): fewer than N chunks available.
///
/// Finds the longest contiguous run of data chunks starting from 0.
/// Decompresses and concatenates them. No hash verification possible.
///
/// @param working_set  All verified chunks in the working set.
/// @param hdr          Parsed Global Header.
/// @return ReassemblyResult with Partial status.
[[nodiscard]] Result<ReassemblyResult>
partial_reassembly(const std::vector<ParsedChunk>& working_set,
                   const GlobalHeader& hdr);

}  // namespace sfc
