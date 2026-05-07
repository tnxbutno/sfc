#pragma once

/// @file split_decoder.h
/// @brief Pure split transport decoder (P2, Section 13).
///
/// decode_split merges chunks from multiple carrier segments and runs the
/// standard decode pipeline.  decode_multi auto-groups files by UUID.

#include "sfc/decoder.h"
#include "sfc/error.h"
#include "sfc/reassembly.h"
#include "sfc/types.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// @brief Decode a set of split-transport carrier segments.
///
/// For each segment the function:
///   1. Parses the preamble, Global Header Region, and 16-byte Segment Header.
///   2. Collects chunk bytes (everything between the Segment Header and the
///      optional Trailer of the terminal segment).
///
/// Cross-validation requirements:
///   - All header_regions must be byte-identical.
///   - All Segment Headers must agree on total_count.
///   - No two segments may share the same segment_index.
///   - At most one segment may have the terminal flag set.
///
/// After merging, a virtual file (preamble + header_region + merged_chunks +
/// optional Trailer) is fed to decode() to produce the ReassemblyResult.
///
/// @param segments Raw byte buffers, one per segment (in any order).
/// @return ReassemblyResult on success, or SfcError on fatal failure.
[[nodiscard]] Result<ReassemblyResult>
decode_split(std::span<const std::vector<uint8_t>> segments);

// ---------------------------------------------------------------------------
// Multi-file decode
// ---------------------------------------------------------------------------

/// One entry in the result of decode_multi.
struct MultiDecodeEntry {
    FileUuid         uuid;    ///< UUID of the decoded stream.
    ReassemblyResult result;  ///< Reassembly result for this UUID.
};

/// @brief Decode a heterogeneous collection of SFC files and/or split-transport segments.
///
/// Algorithm:
///   1. Read the UUID (at fixed file offset 12) and the flags field from each file.
///   2. Files without the SPLIT_TRANSPORT flag are decoded individually via decode().
///   3. Files with SPLIT_TRANSPORT set are grouped by UUID and decoded together
///      via decode_split().
///
/// @param files Raw byte buffers, one per SFC file or split-transport segment.
/// @return Vector of per-UUID decode results, or SfcError on first fatal failure.
[[nodiscard]] Result<std::vector<MultiDecodeEntry>>
decode_multi(std::span<const std::vector<uint8_t>> files);

}  // namespace sfc
