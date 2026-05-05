#pragma once

/// @file split_encoder.h
/// @brief Pure SFC/P2 Split Transport encoder (§13).
///
/// encode_split distributes an SFC file's chunks across multiple P2 segments.
/// Each segment shares the same byte-identical Global Header Region.
/// Only the last (terminal) segment carries the 64-byte Trailer.

#include "sfc/encoder.h"
#include "sfc/error.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// @brief Encode content into a sequence of P2 Split Transport segments.
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
/// The GlobalHeader flags include SPLIT_TRANSPORT (bit 0) and P2Split (bit 5).
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
