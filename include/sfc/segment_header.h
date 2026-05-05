#pragma once

/// @file segment_header.h
/// @brief Pure parse/serialize for the SFC/P2 Segment Header (§13.1, 16 bytes).
///
/// Layout:
///   [0]  4   "SEG\0" magic (0x53 0x45 0x47 0x00)
///   [4]  4   Segment index (LE uint32)
///   [8]  4   Total segment count (LE uint32)
///   [12] 1   Terminal flag (0x00 = non-terminal, 0x01 = terminal)
///   [13] 3   Reserved (must be zero)

#include "sfc/error.h"

#include <array>
#include <cstdint>
#include <span>

namespace sfc {

/// Parsed Segment Header (SFC/P2).
struct SegmentHeader {
    uint32_t segment_index;  ///< 0-based index of this segment.
    uint32_t total_count;    ///< Total number of segments for this UUID.
    bool     is_terminal;    ///< True if this is the Terminal Segment.
};

/// @brief Parse a 16-byte Segment Header.
///
/// Verifies "SEG\0" magic, reserved bytes, and terminal flag value.
///
/// @param data Exactly 16 bytes.
/// @return Parsed SegmentHeader, or error.
[[nodiscard]] Result<SegmentHeader>
parse_segment_header(std::span<const uint8_t, 16> data);

/// @brief Serialize a SegmentHeader to 16 bytes (reserved bytes zeroed).
/// @param sh SegmentHeader to serialize.
/// @return 16-byte array.
[[nodiscard]] std::array<uint8_t, 16>
serialize_segment_header(const SegmentHeader& sh);

}  // namespace sfc
