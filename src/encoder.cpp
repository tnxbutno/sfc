/// @file encoder.cpp
/// @brief SFC encoder implementation.
///
/// Encoding pipeline:
///   1. Validate params (S even, filename fits, etc.)
///   2. Split content into N data blocks (last zero-padded to S bytes)
///   3. Compress each block independently (§7.3)
///   4. RS-encode to produce M recovery blocks, then compress each (§6.4)
///   5. Build GlobalHeader + compute Trailer hash
///   6. Assemble preamble + header + chunks + trailer into one buffer

#include "sfc/encoder.h"

#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"
#include "sfc/chunk.h"
#include "sfc/compression.h"
#include "sfc/global_header.h"
#include "sfc/reed_solomon.h"
#include "sfc/trailer.h"
#include "sfc/validation.h"

#include <algorithm>
#include <format>
#include <numeric>

namespace sfc {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the image profile (P1) priority list per §12.4.
/// Returns error for Class P without a caller-supplied list.
/// Returns auto-computed list for Class S (JPEG Baseline).
/// Returns override_list unchanged if non-empty.
/// Returns empty list (P=0) for Class Q/I/N/Unknown.
static Result<std::vector<uint32_t>>
resolve_p1_priority(uint16_t format_id, uint32_t n,
                    const std::vector<uint32_t>& override_list, bool p1_flag) {
    if (!p1_flag) return override_list;  // image profile (P1) not declared — use whatever caller gave (may be empty)

    if (!override_list.empty()) return override_list;  // explicit override wins

    const auto fid = static_cast<InnerFormatId>(format_id);

    if (fid == InnerFormatId::Jpeg2000 || fid == InnerFormatId::JpegXl) {
        // Class P: codestream inspection required; caller MUST supply priority_list.
        return std::unexpected(SfcError{
            ErrorCode::ProfileMustViolation,
            "image profile (P1) Class P format (JPEG 2000/XL): priority_list must be provided (§12.4)"
        });
    }

    if (fid == InnerFormatId::JpegBaseline) {
        // Class S: auto-compute indices 0..ceil(N*0.1)-1.
        const uint32_t count = (n + 9) / 10;  // ceil(N/10)
        std::vector<uint32_t> list(count);
        std::iota(list.begin(), list.end(), 0u);
        return list;
    }

    return std::vector<uint32_t>{};  // Class Q/I/N: no mandatory priority
}

/// Write the 8-byte preamble (magic + version) into out.
static void append_preamble(std::vector<uint8_t>& out) {
    // "SFC\0"
    out.push_back(0x53); out.push_back(0x46);
    out.push_back(0x43); out.push_back(0x00);
    // Major version 0 (LE uint16)
    out.push_back(0x00); out.push_back(0x00);
    // Minor version 1 (LE uint16)
    out.push_back(0x01); out.push_back(0x00);
}

/// Build a ChunkHeader for the given chunk index and type.
static ChunkHeader make_chunk_header(const FileUuid& uuid,
                                     uint32_t idx,
                                     ChunkType type,
                                     uint32_t payload_len,
                                     uint8_t comp_algo,
                                     uint8_t erasure_algo) {
    return ChunkHeader{
        .uuid                   = uuid,
        .chunk_index            = idx,
        .chunk_type             = type,
        .compressed_payload_len = payload_len,
        .compression_algo       = comp_algo,
        .erasure_algo           = erasure_algo,
    };
}

// ---------------------------------------------------------------------------
// Main encode function
// ---------------------------------------------------------------------------

Result<std::vector<uint8_t>> encode(std::span<const uint8_t> content,
                                     const EncodeParams& params) {
    // --- Validate parameters ---
    if (params.s == 0 || params.s % 2 != 0) {
        return std::unexpected(SfcError{
            ErrorCode::OddChunkSizeS,
            std::format("S={} must be positive and even", params.s)
        });
    }
    if (params.filename.size() > 254) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument,
            "filename too long (max 254 bytes)"
        });
    }
    // Filename must not contain forbidden bytes: 0x00-0x1F, '/', '\\' (§4.8).
    for (char c : params.filename) {
        const auto b = static_cast<uint8_t>(c);
        if (b <= 0x1F || b == 0x2F || b == 0x5C) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidArgument,
                std::format("filename contains forbidden byte 0x{:02X}", b)
            });
        }
    }
    // Reserved flag bits 1-3 and 9-15 must be zero (§4.6).
    constexpr uint16_t kReservedFlagMask = 0b1111111000001110u;  // bits 1-3, 9-15
    if (params.flags & kReservedFlagMask) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument,
            std::format("flags 0x{:04X} has reserved bits set (mask 0x{:04X})",
                        params.flags, kReservedFlagMask)
        });
    }
    // Erasure algo: if M==0, use 0x00; if M>0, use 0x01 (RS).
    const uint8_t erasure_algo = (params.m > 0) ? 0x01 : 0x00;
    const uint8_t comp_algo    = static_cast<uint8_t>(params.algo);

    // --- Compute N ---
    const uint64_t inner_size = static_cast<uint64_t>(content.size());
    const uint32_t n          = compute_n(inner_size, params.s);

    if (static_cast<uint64_t>(n) + params.m > limits::kMaxTotalChunkCount) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("N+M={} exceeds 65535", (uint64_t)n + params.m)
        });
    }

    // --- Split content into N data blocks ---
    // Each block is exactly S bytes; last block is zero-padded.
    std::vector<std::vector<uint8_t>> data_blocks(n);
    for (uint32_t i = 0; i < n; ++i) {
        const size_t start = static_cast<size_t>(i) * params.s;
        const size_t end   = std::min(start + params.s,
                                      static_cast<size_t>(content.size()));
        data_blocks[i].assign(content.data() + start, content.data() + end);
        // Zero-pad the last block to exactly S bytes.
        if (data_blocks[i].size() < params.s) {
            data_blocks[i].resize(params.s, 0x00);
        }
    }

    // --- Compress data blocks ---
    std::vector<std::vector<uint8_t>> data_payloads(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto res = compress(data_blocks[i], params.algo);
        if (!res) return std::unexpected(res.error());
        data_payloads[i] = std::move(*res);
    }

    // --- RS-encode to produce M recovery blocks, then compress ---
    std::vector<std::vector<uint8_t>> recovery_payloads;
    if (params.m > 0) {
        // RS encoding operates on uncompressed blocks (§6.4 ordering: RS before compression).
        auto rs_res = rs_encode(data_blocks, params.m);
        if (!rs_res) return std::unexpected(rs_res.error());

        recovery_payloads.resize(params.m);
        for (uint32_t i = 0; i < params.m; ++i) {
            auto res = compress((*rs_res)[i], params.algo);
            if (!res) return std::unexpected(res.error());
            recovery_payloads[i] = std::move(*res);
        }
    }

    // --- Build GlobalHeader ---
    GlobalHeader ghdr{};
    ghdr.uuid            = params.uuid;
    ghdr.inner_file_size = inner_size;
    ghdr.inner_format_id = params.format_id;
    ghdr.n               = n;
    ghdr.m               = params.m;
    ghdr.s               = params.s;
    ghdr.erasure_algo    = erasure_algo;
    ghdr.compression_algo= comp_algo;
    ghdr.flags           = params.flags;  // caller-supplied profile/flag bits

    // Priority list per §12.4.
    const bool p1_flag = (params.flags & (1u << static_cast<uint16_t>(FlagBit::ImageProfile))) != 0;
    auto prio_res = resolve_p1_priority(params.format_id, n, params.priority_list, p1_flag);
    if (!prio_res) return std::unexpected(prio_res.error());
    ghdr.priority_list  = std::move(*prio_res);
    ghdr.priority_count = static_cast<uint16_t>(ghdr.priority_list.size());

    // Fill inner filename field (255 bytes, null-padded).
    ghdr.inner_filename.fill(0);
    const size_t fname_len = std::min(params.filename.size(), size_t(254));
    std::copy_n(params.filename.begin(), fname_len, ghdr.inner_filename.begin());

    // Global file hash: BLAKE3 of the trimmed content (before zero-padding).
    ghdr.global_hash = blake3(content);

    // Validate and append metadata TLV fields in ascending tag order.
    auto add_meta_tlv = [&](uint16_t tag, const std::string& s) -> VoidResult {
        if (s.empty()) return {};
        if (s.size() > limits::kMaxMetadataStringLength) {
            return std::unexpected(SfcError{
                ErrorCode::FieldAboveMaximum,
                std::format("metadata TLV 0x{:04X}: string {} bytes > max {}",
                            tag, s.size(), limits::kMaxMetadataStringLength)
            });
        }
        TlvField f;
        f.tag = tag;
        f.value.assign(s.begin(), s.end());
        ghdr.tlv_fields.push_back(std::move(f));
        return {};
    };
    if (auto r = add_meta_tlv(TlvTag::kAuthor,      params.metadata.author);      !r) return std::unexpected(r.error());
    if (auto r = add_meta_tlv(TlvTag::kDescription, params.metadata.description); !r) return std::unexpected(r.error());
    if (auto r = add_meta_tlv(TlvTag::kLocation,    params.metadata.location);    !r) return std::unexpected(r.error());
    if (auto r = add_meta_tlv(TlvTag::kSoftware,    params.metadata.software);    !r) return std::unexpected(r.error());
    if (auto r = add_meta_tlv(TlvTag::kComment,     params.metadata.comment);     !r) return std::unexpected(r.error());

    // Validate before serializing (catches field constraint violations early).
    if (auto v = validate_global_header(ghdr); !v) return std::unexpected(v.error());

    // Serialize header region (H+4 bytes); fails if priority+TLV causes H > 65,536.
    auto header_region_res = serialize_global_header(ghdr);
    if (!header_region_res) return std::unexpected(header_region_res.error());
    auto& header_region = *header_region_res;

    // --- Assemble file ---
    std::vector<uint8_t> file_bytes;
    file_bytes.reserve(8 + header_region.size() +
                       n * (48 + params.s + 36) +
                       params.m * (48 + params.s + 36) + 64);

    // Preamble (8 bytes).
    append_preamble(file_bytes);

    // Global Header Region.
    file_bytes.insert(file_bytes.end(),
                      header_region.begin(), header_region.end());

    // Data chunks.
    for (uint32_t i = 0; i < n; ++i) {
        auto hdr = make_chunk_header(
            params.uuid, i, ChunkType::Data,
            static_cast<uint32_t>(data_payloads[i].size()),
            comp_algo, erasure_algo);
        auto chunk_bytes = serialize_chunk(hdr, data_payloads[i]);
        file_bytes.insert(file_bytes.end(),
                          chunk_bytes.begin(), chunk_bytes.end());
    }

    // Recovery chunks.
    for (uint32_t i = 0; i < params.m; ++i) {
        auto hdr = make_chunk_header(
            params.uuid, n + i, ChunkType::Recovery,
            static_cast<uint32_t>(recovery_payloads[i].size()),
            comp_algo, erasure_algo);
        auto chunk_bytes = serialize_chunk(hdr, recovery_payloads[i]);
        file_bytes.insert(file_bytes.end(),
                          chunk_bytes.begin(), chunk_bytes.end());
    }

    // Trailer: BLAKE3 of the Global Header Region.
    Trailer trailer{};
    trailer.header_hash = blake3(header_region);
    trailer.timestamp   = params.timestamp;
    auto trailer_bytes  = serialize_trailer(trailer);
    file_bytes.insert(file_bytes.end(),
                      trailer_bytes.begin(), trailer_bytes.end());

    return file_bytes;
}

}  // namespace sfc
