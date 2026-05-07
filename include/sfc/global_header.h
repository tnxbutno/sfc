#pragma once

/// @file global_header.h
/// @brief Pure parse/serialize/validate for the SFC Global Header (Section 3.2).
///
/// Layout (immediately after 8-byte preamble):
///   [0]  4    Header length H (LE uint32; H+4 = total global header region)
///   [4]  16   File UUID
///   [20] 8    Inner File Size (LE uint64)
///   [28] 2    Inner Format ID (LE uint16)
///   [30] 255  Inner filename (null-padded UTF-8)
///   [285]32   Global file BLAKE3 hash
///   [317]4    N - data chunk count (LE uint32)
///   [321]4    M - recovery chunk count (LE uint32)
///   [325]4    S - nominal chunk size (LE uint32)
///   [329]1    Erasure algorithm ID
///   [330]1    Compression algorithm ID
///   [331]2    Flags (LE uint16)
///   [333] 2    Priority count P (LE uint16)
///   [335] 4*P Priority chunk index list
///   [335+4P] var TLV extension fields

#include "sfc/blake3_hash.h"
#include "sfc/error.h"
#include "sfc/tlv.h"
#include "sfc/types.h"

#include <array>
#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// Minimum fixed size of the global header body (excluding TLV and priority list).
/// Offset 333 is the start of the priority count field; we count from offset 4
/// (first byte after H field) to offset 335 (after priority count) = 331 bytes.
inline constexpr size_t kGlobalHeaderFixedBodySize = 331; // bytes [4..334]

/// Parsed Global Header.
struct GlobalHeader {
    uint32_t h;                          ///< Header length (value of H field).
    FileUuid uuid;                       ///< 16-byte File UUID.
    uint64_t inner_file_size;            ///< Inner content byte count.
    uint16_t inner_format_id;            ///< Inner Format ID (Section 4.2).
    std::array<uint8_t, 255> inner_filename{}; ///< Raw 255-byte filename field.
    Blake3Digest global_hash;            ///< Global BLAKE3 hash (Section 8.2).
    uint32_t n;                          ///< Data chunk count.
    uint32_t m;                          ///< Recovery chunk count.
    uint32_t s;                          ///< Nominal chunk size in bytes.
    uint8_t  erasure_algo;               ///< Erasure coding algorithm ID.
    uint8_t  compression_algo;           ///< Compression algorithm ID.
    uint16_t flags;                      ///< Profile and flags bitfield.
    uint16_t priority_count;             ///< P - number of priority chunks.
    std::vector<uint32_t> priority_list; ///< Priority chunk indices [0..P-1].
    std::vector<TlvField> tlv_fields;    ///< Extension TLV fields.
};

/// @brief Parse the Global Header from the H+4 byte Global Header Region.
///
/// Input must be the complete Global Header Region (H+4 bytes), starting at
/// the H field (NOT including the 8-byte preamble).
///
/// @param data Byte span of exactly H+4 bytes.
/// @return Parsed GlobalHeader on success.
[[nodiscard]] Result<GlobalHeader>
parse_global_header(std::span<const uint8_t> data);

/// @brief Serialize a GlobalHeader to bytes.
///
/// Returns the Global Header Region (H+4 bytes). Does NOT include the 8-byte preamble.
/// Fails with HeaderLengthOutOfBounds if the computed H exceeds 65,536 bytes (Section 4.5 rule g).
///
/// @param hdr GlobalHeader to serialize.
/// @return Serialized bytes or error.
[[nodiscard]] Result<std::vector<uint8_t>>
serialize_global_header(const GlobalHeader& hdr);

/// @brief Validate a parsed GlobalHeader against protocol limits (Section 18.3).
///
/// Checks: N,M,S within limits; S even; N+M <= 65535; priority list valid;
/// erasure 0x00 with M>0; inner_file_size==0 with N!=1.
///
/// @param hdr Parsed header.
/// @return VoidResult: success or first error found.
[[nodiscard]] VoidResult validate_global_header(const GlobalHeader& hdr);

}  // namespace sfc
