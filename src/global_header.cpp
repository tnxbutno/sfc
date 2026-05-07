/// @file global_header.cpp
/// @brief Global Header parse/serialize/validate.

#include "sfc/global_header.h"
#include "sfc/byte_utils.h"

#include <format>

namespace sfc {

// Offsets within the Global Header Region (starting at the H field = byte 0).
// The H field itself is at [0..3].  All other offsets are relative to [0].
namespace off {
    inline constexpr size_t H             = 0;   // 4 bytes
    inline constexpr size_t UUID          = 4;   // 16 bytes
    inline constexpr size_t INNER_SIZE    = 20;  // 8 bytes
    inline constexpr size_t FORMAT_ID     = 28;  // 2 bytes
    inline constexpr size_t FILENAME      = 30;  // 255 bytes
    inline constexpr size_t GLOBAL_HASH   = 285; // 32 bytes
    inline constexpr size_t N             = 317; // 4 bytes
    inline constexpr size_t M             = 321; // 4 bytes
    inline constexpr size_t S             = 325; // 4 bytes
    inline constexpr size_t ERASURE_ALGO  = 329; // 1 byte
    inline constexpr size_t COMP_ALGO     = 330; // 1 byte
    inline constexpr size_t FLAGS         = 331; // 2 bytes
    inline constexpr size_t PRIO_COUNT    = 333; // 2 bytes
    inline constexpr size_t PRIO_LIST     = 335; // 4*P bytes
}  // namespace off

Result<GlobalHeader> parse_global_header(std::span<const uint8_t> data) {
    // We need at least 4 bytes to read H.
    if (data.size() < 4) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            "global header region too small to read H field"
        });
    }

    GlobalHeader hdr{};
    hdr.h = read_u32_le(std::span<const uint8_t, 4>{data.data() + off::H, 4});

    // Total region size must be H+4 bytes.
    if (data.size() != static_cast<size_t>(hdr.h) + 4) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            std::format("global header region: H={} but got {} bytes",
                        hdr.h, data.size())
        });
    }

    // Check we have at least the fixed body through priority count field.
    // Fixed body ends at off::PRIO_COUNT + 2 = 335.
    if (data.size() < off::PRIO_LIST) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            "global header too small for fixed fields"
        });
    }

    // UUID [4..19]
    std::copy_n(data.data() + off::UUID, 16, hdr.uuid.bytes.begin());

    // Inner File Size [20..27]
    hdr.inner_file_size = read_u64_le(
        std::span<const uint8_t, 8>{data.data() + off::INNER_SIZE, 8});

    // Inner Format ID [28..29]
    hdr.inner_format_id = read_u16_le(
        std::span<const uint8_t, 2>{data.data() + off::FORMAT_ID, 2});

    // Inner filename [30..284]
    std::copy_n(data.data() + off::FILENAME, 255, hdr.inner_filename.begin());

    // Global hash [285..316]
    std::copy_n(data.data() + off::GLOBAL_HASH, 32, hdr.global_hash.begin());

    // N, M, S
    hdr.n = read_u32_le(std::span<const uint8_t, 4>{data.data() + off::N, 4});
    hdr.m = read_u32_le(std::span<const uint8_t, 4>{data.data() + off::M, 4});
    hdr.s = read_u32_le(std::span<const uint8_t, 4>{data.data() + off::S, 4});

    // Algorithm IDs
    hdr.erasure_algo     = data[off::ERASURE_ALGO];
    hdr.compression_algo = data[off::COMP_ALGO];

    // Flags
    hdr.flags = read_u16_le(
        std::span<const uint8_t, 2>{data.data() + off::FLAGS, 2});

    // Priority count
    hdr.priority_count = read_u16_le(
        std::span<const uint8_t, 2>{data.data() + off::PRIO_COUNT, 2});

    // Priority list: 4 bytes each.
    const size_t prio_bytes = static_cast<size_t>(hdr.priority_count) * 4;
    if (data.size() < off::PRIO_LIST + prio_bytes) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            "priority list extends past header boundary"
        });
    }
    hdr.priority_list.resize(hdr.priority_count);
    for (size_t i = 0; i < hdr.priority_count; ++i) {
        hdr.priority_list[i] = read_u32_le(
            std::span<const uint8_t, 4>{
                data.data() + off::PRIO_LIST + i * 4, 4});
    }

    // TLV fields: remainder of the region.
    const size_t tlv_start = off::PRIO_LIST + prio_bytes;
    auto tlv_res = parse_tlv_fields(data.subspan(tlv_start));
    if (!tlv_res) return std::unexpected(tlv_res.error());
    hdr.tlv_fields = std::move(*tlv_res);

    return hdr;
}

Result<std::vector<uint8_t>> serialize_global_header(const GlobalHeader& hdr) {
    // Build the variable portion first (priority list + TLV) to compute H.
    std::vector<uint8_t> var_part;
    for (uint32_t idx : hdr.priority_list) {
        auto b = write_u32_le(idx);
        var_part.insert(var_part.end(), b.begin(), b.end());
    }
    auto tlv_bytes = serialize_tlv_fields(hdr.tlv_fields);
    var_part.insert(var_part.end(), tlv_bytes.begin(), tlv_bytes.end());

    // H = fixed body (331 bytes from UUID onwards) + var_part.
    // Fixed body (UUID->priority_count) = 335 - 4 = 331 bytes.
    const uint32_t h = static_cast<uint32_t>(kGlobalHeaderFixedBodySize + var_part.size());

    // Section 4.5 rule g: H must not exceed 65,536 bytes.
    if (h > limits::kMaxHeaderLength) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            std::format("computed H={} exceeds maximum {} (priority list + TLV too large)",
                        h, limits::kMaxHeaderLength)
        });
    }

    // Total region = H + 4 bytes.
    std::vector<uint8_t> out;
    out.reserve(h + 4);

    // H field (4 bytes).
    auto h_bytes = write_u32_le(h);
    out.insert(out.end(), h_bytes.begin(), h_bytes.end());

    // UUID (16).
    out.insert(out.end(), hdr.uuid.bytes.begin(), hdr.uuid.bytes.end());

    // Inner File Size (8).
    auto ifs = write_u64_le(hdr.inner_file_size);
    out.insert(out.end(), ifs.begin(), ifs.end());

    // Inner Format ID (2).
    auto fmt = write_u16_le(hdr.inner_format_id);
    out.insert(out.end(), fmt.begin(), fmt.end());

    // Filename (255).
    out.insert(out.end(), hdr.inner_filename.begin(), hdr.inner_filename.end());

    // Global hash (32).
    out.insert(out.end(), hdr.global_hash.begin(), hdr.global_hash.end());

    // N, M, S.
    auto nb = write_u32_le(hdr.n); out.insert(out.end(), nb.begin(), nb.end());
    auto mb = write_u32_le(hdr.m); out.insert(out.end(), mb.begin(), mb.end());
    auto sb = write_u32_le(hdr.s); out.insert(out.end(), sb.begin(), sb.end());

    // Algo IDs.
    out.push_back(hdr.erasure_algo);
    out.push_back(hdr.compression_algo);

    // Flags (2).
    auto fl = write_u16_le(hdr.flags);
    out.insert(out.end(), fl.begin(), fl.end());

    // Priority count (2).
    auto pc = write_u16_le(hdr.priority_count);
    out.insert(out.end(), pc.begin(), pc.end());

    // Variable part.
    out.insert(out.end(), var_part.begin(), var_part.end());

    return out;  // Result<std::vector<uint8_t>>
}

VoidResult validate_global_header(const GlobalHeader& hdr) {
    // Section 4.6: Flags bits 1-3 are permanently reserved; MUST be zero.
    constexpr uint16_t kReservedFlagsMask = 0b0000'0000'0000'1110u;
    if (hdr.flags & kReservedFlagsMask) {
        return std::unexpected(SfcError{
            ErrorCode::ProfileMustViolation,
            std::format("Flags bits 1-3 must be zero; got flags=0x{:04X}", hdr.flags)
        });
    }
    // Inner File Size <= 1 TB (Section 17.3).
    if (hdr.inner_file_size > limits::kMaxInnerFileSize) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("inner_file_size={} > 1 TiB limit", hdr.inner_file_size)
        });
    }
    // S must be even (Section 6.4).
    if (hdr.s % 2 != 0) {
        return std::unexpected(SfcError{
            ErrorCode::OddChunkSizeS,
            std::format("S={} is odd", hdr.s)
        });
    }
    // S minimum (Section 17.3).
    if (hdr.s < limits::kMinChunkSize) {
        return std::unexpected(SfcError{
            ErrorCode::FieldBelowMinimum,
            std::format("S={} < minimum {}", hdr.s, limits::kMinChunkSize)
        });
    }
    // S maximum.
    if (hdr.s > limits::kMaxChunkSize) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("S={} > maximum {}", hdr.s, limits::kMaxChunkSize)
        });
    }
    // N > 0.
    if (hdr.n == 0) {
        return std::unexpected(SfcError{
            ErrorCode::FieldBelowMinimum, "N=0 is not allowed"
        });
    }
    // N <= 65534 and M <= 65534 (individual limits, Section 17.3).
    if (hdr.n > limits::kMaxDataChunkCount) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("N={} > maximum {}", hdr.n, limits::kMaxDataChunkCount)
        });
    }
    if (hdr.m > limits::kMaxRecoveryChunkCount) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("M={} > maximum {}", hdr.m, limits::kMaxRecoveryChunkCount)
        });
    }
    // N+M <= 65535.
    if (static_cast<uint64_t>(hdr.n) + hdr.m > limits::kMaxTotalChunkCount) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("N+M={} exceeds maximum 65535", (uint64_t)hdr.n + hdr.m)
        });
    }
    // Erasure 0x00 with M>0 (Section 6.1).
    if (hdr.erasure_algo == 0x00 && hdr.m > 0) {
        return std::unexpected(SfcError{
            ErrorCode::ErasureNoneWithMGreaterZero,
            "erasure algo 0x00 but M>0"
        });
    }
    // Non-zero erasure algo with M=0 (Section 6.1).
    if (hdr.erasure_algo != 0x00 && hdr.m == 0) {
        return std::unexpected(SfcError{
            ErrorCode::NonZeroErasureAlgoWithMZero,
            std::format("erasure algo 0x{:02X} but M=0", hdr.erasure_algo)
        });
    }
    // inner_file_size == 0 requires N == 1 (Section 17.3).
    if (hdr.inner_file_size == 0 && hdr.n != 1) {
        return std::unexpected(SfcError{
            ErrorCode::InnerFileSizeZeroWithNNot1,
            std::format("inner_file_size=0 but N={}", hdr.n)
        });
    }
    // Priority count <= N (Section 4.5 rule a).
    if (hdr.priority_count > hdr.n) {
        return std::unexpected(SfcError{
            ErrorCode::PriorityCountExceedsN,
            std::format("P={} > N={}", hdr.priority_count, hdr.n)
        });
    }
    // Priority indices in range [0, N-1] and no duplicates (Section 4.5 rules b, c).
    std::vector<bool> seen(hdr.n, false);
    for (uint32_t idx : hdr.priority_list) {
        if (idx >= hdr.n) {
            return std::unexpected(SfcError{
                ErrorCode::PriorityIndexOutOfRange,
                std::format("priority index {} >= N={}", idx, hdr.n)
            });
        }
        if (seen[idx]) {
            return std::unexpected(SfcError{
                ErrorCode::DuplicatePriorityIndex,
                std::format("duplicate priority index {}", idx)
            });
        }
        seen[idx] = true;
    }
    // Profile TLV tags must only appear when the corresponding flag bit is set (Section 3.2).
    for (const auto& tlv : hdr.tlv_fields) {
        if (tlv.tag == TlvTag::kChunkOffsetIndex &&
            !(hdr.flags & (1u << static_cast<uint16_t>(FlagBit::HttpProfile)))) {
            return std::unexpected(SfcError{
                ErrorCode::ProfileTlvWithoutBit,
                "chunk offset index metadata present but HTTP delivery flag not set"
            });
        }
        if (tlv.tag == TlvTag::kOriginalFormatId &&
            !(hdr.flags & (1u << static_cast<uint16_t>(FlagBit::PreprocessProfile)))) {
            return std::unexpected(SfcError{
                ErrorCode::ProfileTlvWithoutBit,
                "original format metadata present but preprocessing flag not set"
            });
        }
    }
    return {};
}

}  // namespace sfc
