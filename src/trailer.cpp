/// @file trailer.cpp
/// @brief File Trailer parse/serialize.

#include "sfc/trailer.h"
#include "sfc/byte_utils.h"

#include <algorithm>
#include <format>

namespace sfc {

Result<Trailer> parse_trailer(std::span<const uint8_t, 64> data) {
    // Verify "TRLR" magic at bytes 0-3.
    if (data[0] != 0x54 || data[1] != 0x52 || data[2] != 0x4C || data[3] != 0x52) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            std::format("expected TRLR magic, got {:02X} {:02X} {:02X} {:02X}",
                        data[0], data[1], data[2], data[3])
        });
    }

    // Reserved bytes 4-7 must be zero (Section 3.4 / Section 5.5).
    for (size_t i = 4; i < 8; ++i) {
        if (data[i] != 0x00) {
            return std::unexpected(SfcError{
                ErrorCode::NonZeroTrailerReserved4_7,
                std::format("non-zero trailer reserved byte at offset {}: 0x{:02X}",
                            i, data[i])
            });
        }
    }

    // Reserved bytes 48-63 must be zero.
    for (size_t i = 48; i < 64; ++i) {
        if (data[i] != 0x00) {
            return std::unexpected(SfcError{
                ErrorCode::NonZeroTrailerReserved4_7,
                std::format("non-zero trailer reserved byte at offset {}: 0x{:02X}",
                            i, data[i])
            });
        }
    }

    Trailer t{};

    // BLAKE3 hash at bytes 8-39.
    std::copy_n(data.data() + 8, 32, t.header_hash.begin());

    // Timestamp at bytes 40-47.
    t.timestamp = read_u64_le(
        std::span<const uint8_t, 8>{data.data() + 40, 8});

    return t;
}

std::array<uint8_t, 64> serialize_trailer(const Trailer& t) {
    std::array<uint8_t, 64> out{};

    // Magic "TRLR"
    out[0] = 0x54; out[1] = 0x52; out[2] = 0x4C; out[3] = 0x52;
    // Bytes 4-7: reserved, stay zero.

    // BLAKE3 hash at 8-39.
    std::copy_n(t.header_hash.begin(), 32, out.data() + 8);

    // Timestamp at 40-47.
    auto ts = write_u64_le(t.timestamp);
    std::copy_n(ts.begin(), 8, out.data() + 40);

    // Bytes 48-63: reserved, stay zero.
    return out;
}

}  // namespace sfc
