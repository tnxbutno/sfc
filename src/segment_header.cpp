/// @file segment_header.cpp
/// @brief Segment Header parse/serialize.

#include "sfc/segment_header.h"
#include "sfc/byte_utils.h"

#include <format>

namespace sfc {

Result<SegmentHeader> parse_segment_header(std::span<const uint8_t, 16> data) {
    // "SEG\0" magic at bytes 0-3.
    if (data[0] != 0x53 || data[1] != 0x45 || data[2] != 0x47 || data[3] != 0x00) {
        return std::unexpected(SfcError{
            ErrorCode::MissingOrInvalidSegmentHeader,
            std::format("expected SEG\\0, got {:02X} {:02X} {:02X} {:02X}",
                        data[0], data[1], data[2], data[3])
        });
    }

    SegmentHeader sh{};

    // Segment index [4..7]
    sh.segment_index = read_u32_le(
        std::span<const uint8_t, 4>{data.data() + 4, 4});

    // Total count [8..11]
    sh.total_count = read_u32_le(
        std::span<const uint8_t, 4>{data.data() + 8, 4});

    // Terminal flag [12]
    uint8_t flag = data[12];
    if (flag != 0x00 && flag != 0x01) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidTerminalFlagValue,
            std::format("invalid terminal flag value 0x{:02X}", flag)
        });
    }
    sh.is_terminal = (flag == 0x01);

    // Reserved bytes [13..15] must be zero.
    for (size_t i = 13; i < 16; ++i) {
        if (data[i] != 0x00) {
            return std::unexpected(SfcError{
                ErrorCode::SegmentHeaderReservedNonZero,
                std::format("non-zero segment header reserved byte at offset {}", i)
            });
        }
    }

    // Segment index must be < total count.
    if (sh.total_count == 0 || sh.segment_index >= sh.total_count) {
        return std::unexpected(SfcError{
            ErrorCode::SegmentIndexGteCount,
            std::format("segment_index={} >= total_count={}",
                        sh.segment_index, sh.total_count)
        });
    }

    return sh;
}

std::array<uint8_t, 16> serialize_segment_header(const SegmentHeader& sh) {
    std::array<uint8_t, 16> out{};

    // "SEG\0" magic
    out[0] = 0x53; out[1] = 0x45; out[2] = 0x47; out[3] = 0x00;

    // Segment index
    auto idx = write_u32_le(sh.segment_index);
    std::copy_n(idx.begin(), 4, out.data() + 4);

    // Total count
    auto cnt = write_u32_le(sh.total_count);
    std::copy_n(cnt.begin(), 4, out.data() + 8);

    // Terminal flag
    out[12] = sh.is_terminal ? 0x01 : 0x00;
    // Bytes 13-15: reserved, stay zero.

    return out;
}

}  // namespace sfc
