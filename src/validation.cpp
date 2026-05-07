/// @file validation.cpp
/// @brief SFC validation pipeline D1-D5.

#include "sfc/validation.h"
#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"

#include <format>

namespace sfc {

VoidResult validate_preamble(std::span<const uint8_t, 8> preamble) {
    // D1a: verify "SFC\0" magic at bytes 0-3.
    if (preamble[0] != 0x53 || preamble[1] != 0x46 ||
        preamble[2] != 0x43 || preamble[3] != 0x00) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            std::format("expected SFC\\0 magic, got {:02X} {:02X} {:02X} {:02X}",
                        preamble[0], preamble[1], preamble[2], preamble[3])
        });
    }

    // D1b: major version must be 0 (bytes [4..5], LE uint16).
    const uint16_t major = read_u16_le(
        std::span<const uint8_t, 2>{preamble.data() + 4, 2});
    if (major != kMajorVersion) {
        return std::unexpected(SfcError{
            ErrorCode::UnsupportedMajorVersion,
            std::format("unsupported major version {}", major)
        });
    }

    return {};
}

VoidResult validate_trailer_hash(const Trailer& trailer,
                                  std::span<const uint8_t> header_region_bytes) {
    // D2c: BLAKE3(global header region) must match the stored hash in the Trailer.
    auto verify_res = blake3_verify(header_region_bytes, trailer.header_hash);
    if (!verify_res) {
        return std::unexpected(SfcError{
            ErrorCode::TrailerBlake3Mismatch,
            "Trailer BLAKE3 hash does not match Global Header Region"
        });
    }
    return {};
}

VoidResult validate_chunk_hash(const ParsedChunk& chunk) {
    // D3d: BLAKE3(header_bytes || payload) must match the hash in the Chunk Trailer.
    // Re-serialize the header to get the exact 48 bytes used for hashing.
    auto hdr_bytes = serialize_chunk_header(chunk.header);

    auto verify_res = blake3_verify_concat(
        std::span<const uint8_t>(hdr_bytes.data(), hdr_bytes.size()),
        std::span<const uint8_t>(chunk.payload.data(), chunk.payload.size()),
        chunk.hash);

    if (!verify_res) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkBlake3Failure,
            std::format("BLAKE3 hash mismatch for chunk index {}",
                        chunk.header.chunk_index)
        });
    }
    return {};
}

VoidResult validate_chunk_payload_length(const ParsedChunk& chunk, uint32_t s) {
    // D3c: compressed payload length MUST NOT exceed 2*S (Section 17.3).
    const uint64_t max_len = static_cast<uint64_t>(s) * 2;
    if (chunk.header.compressed_payload_len > max_len) {
        return std::unexpected(SfcError{
            ErrorCode::CompressedPayloadExceeds2S,
            std::format("chunk {}: compressed payload {} > 2*S={}",
                        chunk.header.chunk_index,
                        chunk.header.compressed_payload_len,
                        max_len)
        });
    }
    return {};
}

VoidResult validate_chunk_uuid(const ParsedChunk& chunk, const GlobalHeader& hdr) {
    // D4a: chunk File UUID must match the Global Header UUID.
    if (chunk.header.uuid != hdr.uuid) {
        return std::unexpected(SfcError{
            ErrorCode::FileUuidMismatch,
            std::format("chunk {} UUID does not match Global Header",
                        chunk.header.chunk_index)
        });
    }
    return {};
}

VoidResult validate_chunk_index(const ParsedChunk& chunk, const GlobalHeader& hdr) {
    // D4b: chunk index must be in [0, N+M-1].
    const uint32_t max_idx = hdr.n + hdr.m;
    if (chunk.header.chunk_index >= max_idx) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkIndexOutOfRange,
            std::format("chunk index {} >= N+M={}", chunk.header.chunk_index, max_idx)
        });
    }
    return {};
}

VoidResult validate_chunk_algo(const ParsedChunk& chunk, const GlobalHeader& hdr) {
    // D4d: algorithm IDs must match exactly (Section 5.1).
    if (chunk.header.compression_algo != hdr.compression_algo) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkAlgoMismatch,
            std::format("chunk {} compression algo 0x{:02X} != header 0x{:02X}",
                        chunk.header.chunk_index,
                        chunk.header.compression_algo,
                        hdr.compression_algo)
        });
    }

    if (chunk.header.erasure_algo != hdr.erasure_algo) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkAlgoMismatch,
            std::format("chunk {} erasure algo 0x{:02X} != header 0x{:02X}",
                        chunk.header.chunk_index,
                        chunk.header.erasure_algo,
                        hdr.erasure_algo)
        });
    }

    return {};
}

VoidResult validate_global_content_hash(std::span<const uint8_t> content,
                                         const GlobalHeader& hdr) {
    // D5f: BLAKE3 of trimmed inner content must match Global Header's stored hash.
    auto verify_res = blake3_verify(content, hdr.global_hash);
    if (!verify_res) {
        return std::unexpected(SfcError{
            ErrorCode::GlobalFileHashMismatch,
            "global file BLAKE3 hash mismatch after reassembly"
        });
    }
    return {};
}

}  // namespace sfc
