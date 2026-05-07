#pragma once

/// @file tlv.h
/// @brief Pure TLV (Type-Length-Value) parsing and serialization per SFC §3.2.
///
/// Each TLV field: 2-byte tag (LE) + 4-byte length L (LE) + L bytes value.
/// Rules: known tags appear at most once; unknown tags may be repeated and
/// must be skipped; tags must appear in ascending order (encoder requirement).

#include "sfc/error.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// One TLV extension field.
struct TlvField {
    uint16_t             tag;   ///< 2-byte type tag (LE).
    std::vector<uint8_t> value; ///< Up to kMaxTlvValueLength bytes.
};

/// @brief Parse all TLV fields from a byte span.
///
/// @param data Byte span covering the TLV region (after the priority list).
/// @return Vector of TlvField on success. Returns error if:
///         - a known tag appears more than once (DuplicateKnownTlvTag)
///         - a TLV value extends past the end of data (TlvValueOverrunsHeader)
[[nodiscard]] Result<std::vector<TlvField>>
parse_tlv_fields(std::span<const uint8_t> data);

/// @brief Serialize TLV fields into bytes.
///
/// Fields are serialized in the order given. Callers are responsible
/// for ascending-tag ordering (per §3.2 rule d).
///
/// @param fields TLV fields to serialize.
/// @return Serialized bytes.
[[nodiscard]] std::vector<uint8_t>
serialize_tlv_fields(const std::vector<TlvField>& fields);

/// @brief Known TLV tag values.
namespace TlvTag {
    inline constexpr uint16_t kChunkOffsetIndex = 0x0020; ///< HTTP delivery profile (P3, §14): chunk byte offsets (uint64[])
    inline constexpr uint16_t kOriginalFormatId = 0x0030; ///< preprocessing profile (P4, §15): original format ID (uint16 LE)

    // Metadata tags (§3.2): UTF-8 strings, max 4096 bytes each.
    inline constexpr uint16_t kAuthor      = 0x0100; ///< Author name
    inline constexpr uint16_t kDescription = 0x0101; ///< Description
    inline constexpr uint16_t kLocation    = 0x0102; ///< Location (place name or geo string)
    inline constexpr uint16_t kSoftware    = 0x0103; ///< Creating software
    inline constexpr uint16_t kComment     = 0x0104; ///< Free-form comment
}

/// @brief Returns true if tag is a known spec-defined tag.
[[nodiscard]] constexpr bool is_known_tag(uint16_t tag) noexcept {
    return tag == TlvTag::kChunkOffsetIndex ||
           tag == TlvTag::kOriginalFormatId ||
           tag == TlvTag::kAuthor           ||
           tag == TlvTag::kDescription      ||
           tag == TlvTag::kLocation         ||
           tag == TlvTag::kSoftware         ||
           tag == TlvTag::kComment;
}

}  // namespace sfc
