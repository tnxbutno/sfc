/// @file split_decoder.cpp
/// @brief Split transport decoder (P2, Section 13).
///
/// Strategy for decode_split:
///   1. Parse each segment into its structural components (header_region,
///      SegmentHeader, raw chunk bytes, optional Trailer).
///   2. Cross-validate consistency across segments.
///   3. Sort segments by segment_index and concatenate their chunk bytes.
///   4. Build a "virtual" monolithic SFC file and delegate to decode().
///
/// The virtual file is:
///   preamble (8 B)  +  header_region (H+4 B)  +  merged_chunks  +  [Trailer 64 B]
/// This allows full reuse of the existing D3/D4/D5 pipeline.

#include "sfc/split_decoder.h"

#include "sfc/byte_utils.h"
#include "sfc/decoder.h"
#include "sfc/global_header.h"
#include "sfc/segment_header.h"
#include "sfc/trailer.h"
#include "sfc/validation.h"

#include <algorithm>
#include <format>
#include <numeric>
#include <unordered_map>

namespace sfc {

// ---------------------------------------------------------------------------
// decode_split
// ---------------------------------------------------------------------------

Result<ReassemblyResult>
decode_split(std::span<const std::vector<uint8_t>> segments) {
    if (segments.empty()) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument, "decode_split: no segments provided"
        });
    }

    // ---------------------------------------------------------------------------
    // Per-segment parse result.
    // ---------------------------------------------------------------------------
    struct SegmentData {
        std::vector<uint8_t> header_region;   // H+4 bytes
        SegmentHeader        seg_hdr;          // parsed Segment Header
        std::vector<uint8_t> chunk_bytes;      // raw chunk region
        bool                 has_trailer;      // terminal + valid Trailer found
        std::vector<uint8_t> trailer_bytes;    // 64 bytes (only when has_trailer)
    };

    std::vector<SegmentData> parsed(segments.size());

    // Remember segment-0 version bytes for cross-segment comparison (Section 13.2).
    uint16_t ver_major_0 = 0, ver_minor_0 = 0;

    for (size_t i = 0; i < segments.size(); ++i) {
        const auto& seg = segments[i];
        auto& pd        = parsed[i];

        // D1: preamble
        if (seg.size() < 8) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidMagic,
                std::format("segment {}: too small for preamble", i)
            });
        }
        auto pre_res = validate_preamble(
            std::span<const uint8_t, 8>{seg.data(), 8});
        if (!pre_res) return std::unexpected(pre_res.error());

        // Version bytes [4..7]: major at [4..5], minor at [6..7] (LE uint16).
        const uint16_t ver_major = read_u16_le(
            std::span<const uint8_t, 2>{seg.data() + 4, 2});
        const uint16_t ver_minor = read_u16_le(
            std::span<const uint8_t, 2>{seg.data() + 6, 2});
        if (i == 0) {
            ver_major_0 = ver_major;
            ver_minor_0 = ver_minor;
        } else if (ver_major != ver_major_0 || ver_minor != ver_minor_0) {
            return std::unexpected(SfcError{
                ErrorCode::VersionMismatchAcrossSegments,
                std::format("segment {}: version {}.{} != segment 0 version {}.{}",
                            i, ver_major, ver_minor, ver_major_0, ver_minor_0)
            });
        }

        // D2a: read H field and validate bounds
        if (seg.size() < 12) {
            return std::unexpected(SfcError{
                ErrorCode::HeaderLengthOutOfBounds,
                std::format("segment {}: too small to read H", i)
            });
        }
        uint32_t H = read_u32_le(
            std::span<const uint8_t, 4>{seg.data() + 8, 4});

        if (H < limits::kMinHeaderLength || H > limits::kMaxHeaderLength) {
            return std::unexpected(SfcError{
                ErrorCode::HeaderLengthOutOfBounds,
                std::format("segment {}: H={} out of bounds [{},{}]",
                            i, H, limits::kMinHeaderLength, limits::kMaxHeaderLength)
            });
        }
        const size_t header_region_size = static_cast<size_t>(H) + 4;
        if (seg.size() < 8 + header_region_size) {
            return std::unexpected(SfcError{
                ErrorCode::HeaderLengthOutOfBounds,
                std::format("segment {}: truncated before end of header region", i)
            });
        }

        // Copy header_region bytes for later comparison.
        pd.header_region.assign(seg.begin() + 8,
                                 seg.begin() + 8 + static_cast<std::ptrdiff_t>(header_region_size));

        // SegmentHeader is immediately after the header region.
        const size_t sh_offset = 8 + header_region_size;
        if (seg.size() < sh_offset + 16) {
            return std::unexpected(SfcError{
                ErrorCode::MissingOrInvalidSegmentHeader,
                std::format("segment {}: truncated before Segment Header", i)
            });
        }
        auto sh_res = parse_segment_header(
            std::span<const uint8_t, 16>{seg.data() + sh_offset, 16});
        if (!sh_res) return std::unexpected(sh_res.error());
        pd.seg_hdr = *sh_res;

        // Chunk region starts immediately after the Segment Header.
        const size_t chunk_start = sh_offset + 16;
        size_t       chunk_end   = seg.size();

        // Inspect the last 64 bytes for a Trailer per the terminal conflict table (Section 13.4).
        pd.has_trailer = false;
        if (seg.size() >= chunk_start + 64) {
            auto trailer_span = std::span<const uint8_t, 64>{
                seg.data() + seg.size() - 64, 64};
            auto tr_res = parse_trailer(trailer_span);
            if (tr_res) {
                // TRLR magic present - validate the hash.
                auto th_res = validate_trailer_hash(*tr_res, pd.header_region);
                if (th_res) {
                    if (!pd.seg_hdr.is_terminal) {
                        // Row 4: valid Trailer on a non-terminal segment -> error.
                        return std::unexpected(SfcError{
                            ErrorCode::TerminalByTrailerOnlyNoFlag,
                            std::format("segment {}: valid Trailer on non-terminal segment", i)
                        });
                    }
                    pd.has_trailer = true;
                    pd.trailer_bytes.assign(seg.end() - 64, seg.end());
                    chunk_end = seg.size() - 64;
                } else {
                    if (pd.seg_hdr.is_terminal) {
                        // Row 3: terminal flag set, TRLR magic present, hash wrong -> error.
                        return std::unexpected(SfcError{
                            ErrorCode::TerminalFlagButTrailerInvalid,
                            std::format("segment {}: terminal segment has TRLR magic but invalid hash", i)
                        });
                    }
                    // Non-terminal with TRLR magic + wrong hash: treat last 64 bytes as chunk data.
                }
            }
            // parse_trailer failed (wrong magic): last 64 bytes are chunk data.
        }

        pd.chunk_bytes.assign(seg.begin() + static_cast<std::ptrdiff_t>(chunk_start),
                               seg.begin() + static_cast<std::ptrdiff_t>(chunk_end));
    }

    // ---------------------------------------------------------------------------
    // Cross-segment validation
    // ---------------------------------------------------------------------------

    // All header_regions must be byte-identical.
    for (size_t i = 1; i < parsed.size(); ++i) {
        if (!bytes_equal(parsed[0].header_region, parsed[i].header_region)) {
            return std::unexpected(SfcError{
                ErrorCode::GlobalHeaderConflict,
                std::format("segment {}: header_region differs from segment 0", i)
            });
        }
    }

    // All total_count values must match.
    const uint32_t total_count = parsed[0].seg_hdr.total_count;
    for (size_t i = 1; i < parsed.size(); ++i) {
        if (parsed[i].seg_hdr.total_count != total_count) {
            return std::unexpected(SfcError{
                ErrorCode::InconsistentSegmentCount,
                std::format("segment {}: total_count {} ≠ {}", i,
                            parsed[i].seg_hdr.total_count, total_count)
            });
        }
    }

    // No duplicate segment indices.
    std::vector<bool> seen(total_count, false);
    for (const auto& pd : parsed) {
        const uint32_t idx = pd.seg_hdr.segment_index;
        if (idx >= total_count) {
            return std::unexpected(SfcError{
                ErrorCode::SegmentIndexGteCount,
                std::format("segment_index {} >= total_count {}", idx, total_count)
            });
        }
        if (seen[idx]) {
            return std::unexpected(SfcError{
                ErrorCode::DuplicateSegmentIndex,
                std::format("segment_index {} appears more than once", idx)
            });
        }
        seen[idx] = true;
    }

    // At most one terminal segment.
    int terminal_count = 0;
    bool trailer_verified = false;
    for (const auto& pd : parsed) {
        if (pd.seg_hdr.is_terminal) {
            ++terminal_count;
            if (pd.has_trailer) trailer_verified = true;
        }
    }
    if (terminal_count > 1) {
        return std::unexpected(SfcError{
            ErrorCode::MultipleTerminalFlags,
            "more than one terminal segment found"
        });
    }

    // ---------------------------------------------------------------------------
    // Build a virtual monolithic SFC file and delegate to decode()
    // ---------------------------------------------------------------------------

    // Sort by segment_index so chunks appear in the intended order.
    std::vector<size_t> order(parsed.size());
    std::iota(order.begin(), order.end(), 0);
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return parsed[a].seg_hdr.segment_index < parsed[b].seg_hdr.segment_index;
    });

    // Compute total chunk bytes for pre-allocation.
    size_t total_chunk_bytes = 0;
    for (const auto& pd : parsed) total_chunk_bytes += pd.chunk_bytes.size();

    std::vector<uint8_t> virtual_file;
    virtual_file.reserve(8                            // preamble
                         + parsed[0].header_region.size()  // header region
                         + 16                              // placeholder SegmentHeader
                         + total_chunk_bytes
                         + (trailer_verified ? 64u : 0u));

    // Preamble: write "SFC\0" + version 0.1
    const uint8_t preamble[8] = {0x53,0x46,0x43,0x00, 0x00,0x00, 0x01,0x00};
    virtual_file.insert(virtual_file.end(), preamble, preamble + 8);

    // Header region (shared; use segment 0's copy).
    virtual_file.insert(virtual_file.end(),
                        parsed[0].header_region.begin(),
                        parsed[0].header_region.end());

    // Placeholder Segment Header (16 zero bytes): decode() skips these when
    // the SPLIT_TRANSPORT flag is set, aligning the read cursor with the chunks.
    // The Trailer hash covers only the header region, so this placeholder does
    // not affect hash verification.
    const std::array<uint8_t, 16> seg_placeholder{};
    virtual_file.insert(virtual_file.end(), seg_placeholder.begin(), seg_placeholder.end());

    // Merged chunk bytes in segment_index order.
    for (size_t idx : order) {
        const auto& cb = parsed[idx].chunk_bytes;
        virtual_file.insert(virtual_file.end(), cb.begin(), cb.end());
    }

    // Trailer from terminal segment (if available).
    if (trailer_verified) {
        for (const auto& pd : parsed) {
            if (pd.seg_hdr.is_terminal && pd.has_trailer) {
                virtual_file.insert(virtual_file.end(),
                                    pd.trailer_bytes.begin(),
                                    pd.trailer_bytes.end());
                break;
            }
        }
    }

    return decode(virtual_file);
}

// ---------------------------------------------------------------------------
// decode_multi
// ---------------------------------------------------------------------------

Result<std::vector<MultiDecodeEntry>>
decode_multi(std::span<const std::vector<uint8_t>> files) {
    // ---------------------------------------------------------------------------
    // Step 1: Read UUID (file offset 12, 16 bytes) and flags (offset 339,
    // 2 bytes) from each file.  Both are at fixed positions that do not
    // depend on the H field value for any valid SFC file.
    // ---------------------------------------------------------------------------
    struct FileInfo {
        FileUuid uuid;
        bool     is_p2;   // SPLIT_TRANSPORT flag (bit 0) set
    };

    std::vector<FileInfo> infos;
    infos.reserve(files.size());

    for (size_t i = 0; i < files.size(); ++i) {
        const auto& f = files[i];

        // Need at least 341 bytes to reach the flags field.
        // (preamble 8 + H 4 + fixed-body 329 = 341; flags at [339..340])
        if (f.size() < 341) {
            // Too small to decode; let decode() produce an appropriate error.
            FileUuid uuid{};
            if (f.size() >= 28)  // UUID is at offset 12..27
                std::copy_n(f.data() + 12, 16, uuid.bytes.begin());
            infos.push_back({uuid, false});
            continue;
        }

        FileUuid uuid{};
        std::copy_n(f.data() + 12, 16, uuid.bytes.begin());

        // Flags field is at fixed byte offset 339 in the file (LE uint16).
        const uint16_t flags = read_u16_le(
            std::span<const uint8_t, 2>{f.data() + 339, 2});

        // Bit 0 = SPLIT_TRANSPORT -> this file is a split-transport segment (P2, Section 13).
        const bool is_p2 = (flags & (1u << static_cast<uint16_t>(FlagBit::SplitTransport))) != 0;

        infos.push_back({uuid, is_p2});
    }

    // ---------------------------------------------------------------------------
    // Step 2: Group split-transport files by UUID; decode regular files individually.
    // ---------------------------------------------------------------------------
    std::vector<MultiDecodeEntry> result;
    std::vector<bool> processed(files.size(), false);

    for (size_t i = 0; i < infos.size(); ++i) {
        if (processed[i]) continue;
        processed[i] = true;

        if (!infos[i].is_p2) {
            // Regular SFC file: decode individually.
            auto res = decode(files[i]);
            if (!res) return std::unexpected(res.error());
            result.push_back({infos[i].uuid, std::move(*res)});
        } else {
            // Split-transport segment: collect all segments with the same UUID.
            std::vector<std::vector<uint8_t>> segs;
            segs.push_back(files[i]);

            for (size_t j = i + 1; j < infos.size(); ++j) {
                if (!processed[j] &&
                    infos[j].is_p2 &&
                    infos[j].uuid == infos[i].uuid) {
                    segs.push_back(files[j]);
                    processed[j] = true;
                }
            }

            auto res = decode_split(std::span<const std::vector<uint8_t>>{segs});
            if (!res) return std::unexpected(res.error());
            result.push_back({infos[i].uuid, std::move(*res)});
        }
    }

    return result;
}

}  // namespace sfc
