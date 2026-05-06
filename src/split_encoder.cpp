/// @file split_encoder.cpp
/// @brief SFC/P2 Split Transport encoder.
///
/// Pipeline (mirrors encoder.cpp, then distributes instead of monolithic assembly):
///   1. Validate params.
///   2. Split content into N zero-padded data blocks.
///   3. Compress each data block.
///   4. RS-encode to produce M recovery blocks, then compress each.
///   5. Build GlobalHeader with SPLIT_TRANSPORT + P2Split flags.
///   6. Serialize all N+M chunks independently.
///   7. Distribute chunks evenly across num_segments segments.
///   8. Assemble each segment: preamble + header_region + SegmentHeader + chunks + [Trailer].

#include "sfc/split_encoder.h"

#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"
#include "sfc/chunk.h"
#include "sfc/compression.h"
#include "sfc/global_header.h"
#include "sfc/reed_solomon.h"
#include "sfc/segment_header.h"
#include "sfc/tlv.h"
#include "sfc/trailer.h"
#include "sfc/types.h"
#include "sfc/validation.h"

#include <algorithm>
#include <format>
#include <numeric>

namespace sfc {

// ---------------------------------------------------------------------------
// Internal helpers (file-local)
// ---------------------------------------------------------------------------

/// Compute the SFC/P1 priority list per §12.4 (mirrors encoder.cpp).
static Result<std::vector<uint32_t>>
resolve_p1_priority(uint16_t format_id, uint32_t n,
                    const std::vector<uint32_t>& override_list, bool p1_flag) {
    if (!p1_flag) return override_list;
    if (!override_list.empty()) return override_list;

    const auto fid = static_cast<InnerFormatId>(format_id);
    if (fid == InnerFormatId::Jpeg2000 || fid == InnerFormatId::JpegXl) {
        return std::unexpected(SfcError{
            ErrorCode::ProfileMustViolation,
            "SFC/P1 Class P format (JPEG 2000/XL): priority_list must be provided (§12.4)"
        });
    }
    if (fid == InnerFormatId::JpegBaseline) {
        const uint32_t count = (n + 9) / 10;
        std::vector<uint32_t> list(count);
        std::iota(list.begin(), list.end(), 0u);
        return list;
    }
    return std::vector<uint32_t>{};
}

/// Write the 8-byte SFC preamble (magic + major/minor version) into out.
static void append_preamble(std::vector<uint8_t>& out) {
    // "SFC\0"
    out.push_back(0x53); out.push_back(0x46);
    out.push_back(0x43); out.push_back(0x00);
    // major version 0 (LE uint16)
    out.push_back(0x00); out.push_back(0x00);
    // minor version 1 (LE uint16)
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
// encode_split
// ---------------------------------------------------------------------------

Result<std::vector<std::vector<uint8_t>>>
encode_split(std::span<const uint8_t> content,
             const EncodeParams& params,
             uint32_t num_segments) {
    // --- Validate basic parameters ---
    if (num_segments == 0) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument, "num_segments must be ≥ 1"
        });
    }
    if (params.s == 0 || params.s % 2 != 0) {
        return std::unexpected(SfcError{
            ErrorCode::OddChunkSizeS,
            std::format("S={} must be positive and even", params.s)
        });
    }
    if (params.filename.size() > 254) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument, "filename too long (max 254 bytes)"
        });
    }

    const uint8_t erasure_algo = (params.m > 0) ? 0x01 : 0x00;
    const uint8_t comp_algo    = static_cast<uint8_t>(params.algo);
    const uint64_t inner_size  = static_cast<uint64_t>(content.size());
    const uint32_t n           = compute_n(inner_size, params.s);

    if (static_cast<uint64_t>(n) + params.m > limits::kMaxTotalChunkCount) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("N+M={} exceeds 65535", static_cast<uint64_t>(n) + params.m)
        });
    }

    // --- Step 2: split content into N zero-padded data blocks ---
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

    // --- Step 3: compress data blocks ---
    std::vector<std::vector<uint8_t>> data_payloads(n);
    for (uint32_t i = 0; i < n; ++i) {
        auto res = compress(data_blocks[i], params.algo);
        if (!res) return std::unexpected(res.error());
        data_payloads[i] = std::move(*res);
    }

    // --- Step 4: RS-encode recovery blocks, then compress ---
    std::vector<std::vector<uint8_t>> recovery_payloads;
    if (params.m > 0) {
        // RS operates on uncompressed data blocks (§6.4).
        auto rs_res = rs_encode(data_blocks, params.m);
        if (!rs_res) return std::unexpected(rs_res.error());

        recovery_payloads.resize(params.m);
        for (uint32_t i = 0; i < params.m; ++i) {
            auto res = compress((*rs_res)[i], params.algo);
            if (!res) return std::unexpected(res.error());
            recovery_payloads[i] = std::move(*res);
        }
    }

    // --- Step 5: build GlobalHeader with P2 flags ---
    GlobalHeader ghdr{};
    ghdr.uuid             = params.uuid;
    ghdr.inner_file_size  = inner_size;
    ghdr.inner_format_id  = params.format_id;
    ghdr.n                = n;
    ghdr.m                = params.m;
    ghdr.s                = params.s;
    ghdr.erasure_algo     = erasure_algo;
    ghdr.compression_algo = comp_algo;
    // P2 requires SPLIT_TRANSPORT (bit 0) and P2Split (bit 5).
    // Preserve any profile flags already in params (e.g. P5Directory).
    ghdr.flags = params.flags |
                 (1u << static_cast<uint16_t>(FlagBit::SplitTransport)) |
                 (1u << static_cast<uint16_t>(FlagBit::P2Split));

    // Priority list per §12.4.
    const bool p1_flag = (params.flags & (1u << static_cast<uint16_t>(FlagBit::P1Image))) != 0;
    auto prio_res = resolve_p1_priority(params.format_id, n, params.priority_list, p1_flag);
    if (!prio_res) return std::unexpected(prio_res.error());
    ghdr.priority_list  = std::move(*prio_res);
    ghdr.priority_count = static_cast<uint16_t>(ghdr.priority_list.size());
    ghdr.inner_filename.fill(0);
    const size_t fname_len = std::min(params.filename.size(), size_t(254));
    std::copy_n(params.filename.begin(), fname_len, ghdr.inner_filename.begin());
    ghdr.global_hash = blake3(content);  // BLAKE3 of the TRIMMED content

    // Metadata TLV fields — same logic as encoder.cpp.
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

    // Serialize header region (H+4 bytes) — shared across all segments.
    // Fails if priority list + TLV would push H above 65,536 bytes (§4.5 rule g).
    auto header_region_res = serialize_global_header(ghdr);
    if (!header_region_res) return std::unexpected(header_region_res.error());
    auto& header_region = *header_region_res;

    // --- Step 6: serialize all N+M chunks ---
    const uint32_t total_chunks = n + params.m;
    std::vector<std::vector<uint8_t>> all_chunk_bytes(total_chunks);

    for (uint32_t i = 0; i < n; ++i) {
        auto hdr = make_chunk_header(
            params.uuid, i, ChunkType::Data,
            static_cast<uint32_t>(data_payloads[i].size()),
            comp_algo, erasure_algo);
        all_chunk_bytes[i] = serialize_chunk(hdr, data_payloads[i]);
    }
    for (uint32_t i = 0; i < params.m; ++i) {
        auto hdr = make_chunk_header(
            params.uuid, n + i, ChunkType::Recovery,
            static_cast<uint32_t>(recovery_payloads[i].size()),
            comp_algo, erasure_algo);
        all_chunk_bytes[n + i] = serialize_chunk(hdr, recovery_payloads[i]);
    }

    // Cap num_segments at total_chunks so every segment gets ≥ 1 chunk.
    if (num_segments > total_chunks) num_segments = total_chunks;

    // Build the Trailer once — only the terminal segment includes it.
    Trailer trlr{};
    trlr.header_hash = blake3(header_region);  // BLAKE3 of the Global Header Region
    trlr.timestamp   = params.timestamp;
    auto trailer_bytes = serialize_trailer(trlr);

    // --- Step 7: distribute chunks evenly ---
    // Segment seg gets chunks in [lo..lo+count-1].
    // base = total_chunks / num_segments, first `rem` segments get +1.
    const uint32_t base = total_chunks / num_segments;
    const uint32_t rem  = total_chunks % num_segments;

    // --- Step 8: assemble segments ---
    std::vector<std::vector<uint8_t>> segments(num_segments);
    uint32_t chunk_pos = 0;

    for (uint32_t seg = 0; seg < num_segments; ++seg) {
        const uint32_t seg_chunk_count = base + (seg < rem ? 1u : 0u);
        const bool     is_terminal     = (seg == num_segments - 1);

        // Segment Header
        SegmentHeader sh{ seg, num_segments, is_terminal };
        auto sh_bytes = serialize_segment_header(sh);

        auto& out = segments[seg];
        out.reserve(8                       // preamble
                    + header_region.size()  // Global Header Region
                    + 16                    // Segment Header
                    + seg_chunk_count * (48 + params.s + 36)  // rough chunk estimate
                    + (is_terminal ? 64u : 0u));  // Trailer (terminal only)

        // 8-byte preamble (identical across segments).
        append_preamble(out);

        // Global Header Region (byte-identical across segments).
        out.insert(out.end(), header_region.begin(), header_region.end());

        // 16-byte Segment Header.
        out.insert(out.end(), sh_bytes.begin(), sh_bytes.end());

        // Chunks assigned to this segment.
        for (uint32_t k = 0; k < seg_chunk_count; ++k) {
            const auto& cb = all_chunk_bytes[chunk_pos++];
            out.insert(out.end(), cb.begin(), cb.end());
        }

        // 64-byte Trailer: only the terminal segment carries it.
        if (is_terminal) {
            out.insert(out.end(), trailer_bytes.begin(), trailer_bytes.end());
        }
    }

    return segments;
}

}  // namespace sfc
