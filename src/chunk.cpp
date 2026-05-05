/// @file chunk.cpp
/// @brief Chunk parse/serialize implementation.

#include "sfc/chunk.h"
#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"

#include <format>

namespace sfc {

// Offsets within the 48-byte chunk header.
namespace chkoff {
    inline constexpr size_t MAGIC   = 0;  // 4 bytes "CHK\0"
    inline constexpr size_t UUID    = 4;  // 16 bytes
    inline constexpr size_t INDEX   = 20; // 4 bytes
    inline constexpr size_t TYPE    = 24; // 4 bytes
    inline constexpr size_t PAYLOAD_LEN = 28; // 4 bytes
    inline constexpr size_t COMP_ALGO   = 32; // 1 byte
    inline constexpr size_t ERASURE_ALGO= 33; // 1 byte
    inline constexpr size_t RESERVED    = 34; // 14 bytes (must be zero)
}

Result<ChunkHeader> parse_chunk_header(std::span<const uint8_t, 48> data) {
    // Verify "CHK\0" magic.
    if (data[0] != 0x43 || data[1] != 0x48 || data[2] != 0x4B || data[3] != 0x00) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            std::format("expected CHK\\0, got {:02X} {:02X} {:02X} {:02X}",
                        data[0], data[1], data[2], data[3])
        });
    }

    ChunkHeader hdr{};

    // UUID [4..19]
    std::copy_n(data.data() + chkoff::UUID, 16, hdr.uuid.bytes.begin());

    // Chunk index [20..23]
    hdr.chunk_index = read_u32_le(
        std::span<const uint8_t, 4>{data.data() + chkoff::INDEX, 4});

    // Chunk type [24..27]
    uint32_t raw_type = read_u32_le(
        std::span<const uint8_t, 4>{data.data() + chkoff::TYPE, 4});
    if (raw_type != 0x00000001 && raw_type != 0x00000002) {
        return std::unexpected(SfcError{
            ErrorCode::UnknownChunkType,
            std::format("unknown chunk type 0x{:08X} at index {}", raw_type, 0)
        });
    }
    hdr.chunk_type = static_cast<ChunkType>(raw_type);

    // Compressed payload length [28..31]
    hdr.compressed_payload_len = read_u32_le(
        std::span<const uint8_t, 4>{data.data() + chkoff::PAYLOAD_LEN, 4});

    // Algorithm IDs [32, 33]
    hdr.compression_algo = data[chkoff::COMP_ALGO];
    hdr.erasure_algo     = data[chkoff::ERASURE_ALGO];

    // Reserved bytes [34..47] must be zero.
    for (size_t i = chkoff::RESERVED; i < 48; ++i) {
        if (data[i] != 0x00) {
            return std::unexpected(SfcError{
                ErrorCode::NonZeroChunkReservedBytes,
                std::format("non-zero reserved byte at chunk header offset {}", i)
            });
        }
    }

    return hdr;
}

std::array<uint8_t, 48> serialize_chunk_header(const ChunkHeader& hdr) {
    std::array<uint8_t, 48> out{};

    // Magic "CHK\0"
    out[0] = 0x43; out[1] = 0x48; out[2] = 0x4B; out[3] = 0x00;

    // UUID
    std::copy_n(hdr.uuid.bytes.begin(), 16, out.data() + chkoff::UUID);

    // Chunk index
    auto idx = write_u32_le(hdr.chunk_index);
    std::copy_n(idx.begin(), 4, out.data() + chkoff::INDEX);

    // Chunk type
    auto typ = write_u32_le(static_cast<uint32_t>(hdr.chunk_type));
    std::copy_n(typ.begin(), 4, out.data() + chkoff::TYPE);

    // Payload length
    auto plen = write_u32_le(hdr.compressed_payload_len);
    std::copy_n(plen.begin(), 4, out.data() + chkoff::PAYLOAD_LEN);

    // Algo IDs
    out[chkoff::COMP_ALGO]    = hdr.compression_algo;
    out[chkoff::ERASURE_ALGO] = hdr.erasure_algo;
    // Reserved bytes remain zero (default-initialised).

    return out;
}

Result<Blake3Digest> parse_chunk_trailer(std::span<const uint8_t, 36> data) {
    // Bytes 32-35 must be "/CHK" (0x2F 0x43 0x48 0x4B).
    if (data[32] != 0x2F || data[33] != 0x43 || data[34] != 0x48 || data[35] != 0x4B) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkEndMarkerInvalid,
            "chunk end marker '/CHK' not found"
        });
    }

    Blake3Digest hash;
    std::copy_n(data.data(), 32, hash.begin());
    return hash;
}

std::array<uint8_t, 36> serialize_chunk_trailer(const Blake3Digest& hash) {
    std::array<uint8_t, 36> out{};
    std::copy_n(hash.begin(), 32, out.begin());
    // "/CHK" end marker.
    out[32] = 0x2F; out[33] = 0x43; out[34] = 0x48; out[35] = 0x4B;
    return out;
}

Result<std::pair<ParsedChunk, size_t>> parse_chunk(std::span<const uint8_t> data) {
    constexpr size_t kHdrSize        = 48;
    constexpr size_t kChunkTailSize  = 36;  // per-chunk trailer (hash + "/CHK"), §3.3

    if (data.size() < kHdrSize) {
        return std::unexpected(SfcError{
            ErrorCode::TruncatedChunk, "data too small for chunk header"
        });
    }

    // Parse header.
    auto hdr_res = parse_chunk_header(
        std::span<const uint8_t, 48>{data.data(), 48});
    if (!hdr_res) return std::unexpected(hdr_res.error());
    const ChunkHeader& hdr = *hdr_res;

    // Bounds-check payload.
    const size_t payload_len = hdr.compressed_payload_len;
    const size_t total       = kHdrSize + payload_len + kChunkTailSize;
    if (data.size() < total) {
        return std::unexpected(SfcError{
            ErrorCode::TruncatedChunk,
            std::format("chunk too small: need {} bytes, got {}", total, data.size())
        });
    }

    // Extract payload.
    std::vector<uint8_t> payload(
        data.data() + kHdrSize, data.data() + kHdrSize + payload_len);

    // Parse trailer.
    auto trailer_res = parse_chunk_trailer(
        std::span<const uint8_t, 36>{data.data() + kHdrSize + payload_len, 36});
    if (!trailer_res) return std::unexpected(trailer_res.error());

    ParsedChunk chunk{
        .header  = hdr,
        .payload = std::move(payload),
        .hash    = *trailer_res
    };

    return std::make_pair(std::move(chunk), total);
}

std::vector<uint8_t> serialize_chunk(const ChunkHeader& hdr,
                                      const std::vector<uint8_t>& payload) {
    // Build header bytes.
    ChunkHeader mutable_hdr = hdr;
    mutable_hdr.compressed_payload_len = static_cast<uint32_t>(payload.size());
    auto hdr_bytes = serialize_chunk_header(mutable_hdr);

    // Compute BLAKE3 hash of (header || payload).
    Blake3Digest hash = blake3_concat(
        std::span<const uint8_t>(hdr_bytes.data(), hdr_bytes.size()),
        std::span<const uint8_t>(payload.data(), payload.size()));

    // Build trailer.
    auto trailer = serialize_chunk_trailer(hash);

    // Assemble complete chunk.
    std::vector<uint8_t> out;
    out.reserve(48 + payload.size() + 36);
    out.insert(out.end(), hdr_bytes.begin(), hdr_bytes.end());
    out.insert(out.end(), payload.begin(), payload.end());
    out.insert(out.end(), trailer.begin(), trailer.end());
    return out;
}

}  // namespace sfc
