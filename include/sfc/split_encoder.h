#pragma once

/// @file split_encoder.h
/// @brief Pure split transport encoder (P2, §13).
///
/// encode_split distributes an SFC file's chunks across multiple carrier segments.
/// Each segment shares the same byte-identical Global Header Region.
/// Only the last (terminal) segment carries the 64-byte Trailer.

#include "sfc/encoder.h"
#include "sfc/error.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// @brief Encode content into a sequence of split-transport carrier segments.
///
/// Performs the full encoding pipeline (compress + RS recovery), then
/// distributes the N+M chunks as evenly as possible across num_segments
/// output segments.  Each segment has the layout:
///   8-byte preamble (identical in every segment)
///   Global Header Region (byte-identical in every segment)
///   16-byte Segment Header ("SEG\0" + index + total_count + terminal_flag)
///   Chunks assigned to this segment
///   64-byte Trailer (only in the last / terminal segment)
///
/// Sets SPLIT_TRANSPORT (bit 0) and the split transport profile flag (P2, bit 5).
/// num_segments is capped internally at N+M so that every segment has ≥1 chunk.
///
/// @param content      Inner content bytes to encode.
/// @param params       Encoding parameters (same fields as encode()).
/// @param num_segments Requested number of output segments (must be ≥ 1).
/// @return Vector of num_segments byte buffers, or SfcError on failure.
[[nodiscard]] Result<std::vector<std::vector<uint8_t>>>
encode_split(std::span<const uint8_t> content,
             const EncodeParams& params,
             uint32_t num_segments);

}  // namespace sfc
