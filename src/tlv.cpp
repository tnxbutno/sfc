/// @file tlv.cpp
/// @brief TLV parsing and serialization.

#include "sfc/tlv.h"
#include "sfc/byte_utils.h"
#include "sfc/types.h"

#include <format>
#include <unordered_set>

namespace sfc {

Result<std::vector<TlvField>> parse_tlv_fields(std::span<const uint8_t> data) {
    std::vector<TlvField> fields;
    std::unordered_set<uint16_t> seen_known_tags;

    size_t pos = 0;
    while (pos < data.size()) {
        // Need at least 6 bytes for tag(2) + length(4).
        if (data.size() - pos < 6) {
            return std::unexpected(SfcError{
                ErrorCode::TlvValueOverrunsHeader,
                std::format("truncated TLV header at offset {}", pos)
            });
        }

        uint16_t tag = read_u16_le(
            std::span<const uint8_t, 2>{data.data() + pos, 2});
        uint32_t len = read_u32_le(
            std::span<const uint8_t, 4>{data.data() + pos + 2, 4});
        pos += 6;

        // TLV value length ≤ 16,384 (§3.2 rule e).
        if (len > limits::kMaxTlvValueLength) {
            return std::unexpected(SfcError{
                ErrorCode::FieldAboveMaximum,
                std::format("TLV tag 0x{:04X}: value length {} > max {}",
                            tag, len, limits::kMaxTlvValueLength)
            });
        }

        // Verify the value region fits within data.
        if (static_cast<size_t>(len) > data.size() - pos) {
            return std::unexpected(SfcError{
                ErrorCode::TlvValueOverrunsHeader,
                std::format("TLV tag 0x{:04X}: value length {} overruns boundary", tag, len)
            });
        }

        // Known tag checks.
        if (is_known_tag(tag)) {
            // Duplicate check.
            if (!seen_known_tags.insert(tag).second) {
                return std::unexpected(SfcError{
                    ErrorCode::DuplicateKnownTlvTag,
                    std::format("duplicate known TLV tag 0x{:04X}", tag)
                });
            }
            // Expected length validation.
            if (tag == TlvTag::kOriginalFormatId && len != 2) {
                return std::unexpected(SfcError{
                    ErrorCode::KnownTlvUnexpectedLength,
                    std::format("kOriginalFormatId: expected 2 bytes, got {}", len)
                });
            }
            if (tag == TlvTag::kChunkOffsetIndex && len % 8 != 0) {
                return std::unexpected(SfcError{
                    ErrorCode::KnownTlvUnexpectedLength,
                    std::format("kChunkOffsetIndex: length {} is not a multiple of 8", len)
                });
            }
            // Metadata string tags: L=0 and L>4096 are both format errors (§3.2).
            const bool is_metadata_tag =
                tag == TlvTag::kAuthor      || tag == TlvTag::kDescription ||
                tag == TlvTag::kLocation    || tag == TlvTag::kSoftware    ||
                tag == TlvTag::kComment;
            if (is_metadata_tag && len == 0) {
                return std::unexpected(SfcError{
                    ErrorCode::KnownTlvUnexpectedLength,
                    std::format("metadata TLV tag 0x{:04X}: L=0 is not permitted", tag)
                });
            }
            if (is_metadata_tag && len > limits::kMaxMetadataStringLength) {
                return std::unexpected(SfcError{
                    ErrorCode::FieldAboveMaximum,
                    std::format("metadata TLV tag 0x{:04X}: length {} > max {}",
                                tag, len, limits::kMaxMetadataStringLength)
                });
            }
        }

        // Copy value bytes.
        TlvField field;
        field.tag = tag;
        field.value.assign(data.data() + pos, data.data() + pos + len);
        fields.push_back(std::move(field));
        pos += len;
    }

    return fields;
}

std::vector<uint8_t> serialize_tlv_fields(const std::vector<TlvField>& fields) {
    std::vector<uint8_t> out;
    for (const auto& f : fields) {
        // Tag (2 bytes LE).
        auto tag_bytes = write_u16_le(f.tag);
        out.insert(out.end(), tag_bytes.begin(), tag_bytes.end());
        // Length (4 bytes LE).
        auto len_bytes = write_u32_le(static_cast<uint32_t>(f.value.size()));
        out.insert(out.end(), len_bytes.begin(), len_bytes.end());
        // Value.
        out.insert(out.end(), f.value.begin(), f.value.end());
    }
    return out;
}

}  // namespace sfc
