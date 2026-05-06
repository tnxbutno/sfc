#pragma once

/// @file types.h
/// @brief Core types, enums, and protocol constants for SFC format (draft-sfc-container-format-01).
///
/// This header defines all value types, magic bytes, version numbers,
/// and hard protocol limits from the SFC specification. No logic here —
/// only data definitions.

#include <array>
#include <cstdint>
#include <functional>
#include <string>

namespace sfc {

// ---------------------------------------------------------------------------
// Magic bytes
// ---------------------------------------------------------------------------

/// SFC file magic: "SFC\0" (Section 3.1)
inline constexpr std::array<uint8_t, 4> kSfcMagic = {0x53, 0x46, 0x43, 0x00};

/// Chunk header magic: "CHK\0" (Section 5.1)
inline constexpr std::array<uint8_t, 4> kChunkMagic = {0x43, 0x48, 0x4B, 0x00};

/// Chunk end marker: "/CHK" (Section 5.3)
inline constexpr std::array<uint8_t, 4> kChunkEndMarker = {0x2F, 0x43, 0x48, 0x4B};

/// Trailer magic: "TRLR" (Section 3.4)
inline constexpr std::array<uint8_t, 4> kTrailerMagic = {0x54, 0x52, 0x4C, 0x52};

/// Segment Header magic: "SEG\0" (Section 13.1)
inline constexpr std::array<uint8_t, 4> kSegmentMagic = {0x53, 0x45, 0x47, 0x00};

/// Manifest magic: "MFST" (Section 16.2)
inline constexpr std::array<uint8_t, 4> kManifestMagic = {0x4D, 0x46, 0x53, 0x54};

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

inline constexpr uint16_t kMajorVersion = 0;
inline constexpr uint16_t kMinorVersion = 1;

// ---------------------------------------------------------------------------
// Fixed structure sizes
// ---------------------------------------------------------------------------

inline constexpr size_t kPreambleSize = 8;        ///< Magic (4) + Major (2) + Minor (2)
inline constexpr size_t kChunkHeaderSize = 48;     ///< Section 5.1
inline constexpr size_t kChunkTrailerSize = 36;    ///< Section 5.3
inline constexpr size_t kTrailerSize = 64;         ///< Section 3.4
inline constexpr size_t kSegmentHeaderSize = 16;   ///< Section 13.1
inline constexpr size_t kBlake3HashSize = 32;      ///< BLAKE3 output size
inline constexpr size_t kInnerFilenameSize = 255;  ///< Section 4.8
inline constexpr size_t kFileUuidSize = 16;        ///< 128-bit UUID

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Chunk type field values (Section 5.1, offset 24).
enum class ChunkType : uint32_t {
    Data     = 0x00000001,
    Recovery = 0x00000002,
};

/// Compression algorithm IDs (Section 7.1).
enum class CompressionAlgo : uint8_t {
    Identity  = 0x00,  ///< No compression (MUST support)
    Zstd      = 0x01,  ///< zstd RFC 8878 (MUST support)
    Brotli    = 0x02,  ///< brotli RFC 7932 (SHOULD support)
    Lz4Frame  = 0x03,  ///< LZ4 Frame Format (SHOULD support)
};

/// Erasure coding algorithm IDs (Section 6.1).
enum class ErasureAlgo : uint8_t {
    None              = 0x00,  ///< No erasure coding (M MUST be 0)
    ReedSolomonGF2_16 = 0x01,  ///< RS over GF(2^16), Cauchy matrix (MUST support)
};

/// Inner Format IDs (Section 4.2). Non-exhaustive.
enum class InnerFormatId : uint16_t {
    Unknown          = 0x0000,
    ArbitraryBinary  = 0x0001,
    PlainText        = 0x0010,
    LineOriented     = 0x0011,
    JpegBaseline     = 0x0020,
    JpegProgressive  = 0x0021,
    Jpeg2000         = 0x0022,
    JpegXl           = 0x0023,
    PngNonInterlaced = 0x0024,
    PngAdam7         = 0x0025,
    WebP             = 0x0026,
    FragmentedMp4    = 0x0030,
    MatroskaWebm     = 0x0031,
    Zip              = 0x0040,
    Gzip             = 0x0041,
    ZstdData         = 0x0042,
    TarZstd          = 0x0043,
    SfcDirectory     = 0x0050,
    NestedSfc        = 0x00FF,
    Pdf              = 0x0100,
    EPub             = 0x0101,
};

/// Profile flag bit positions within the 2-byte Flags field (Section 4.6).
/// Usage: (flags >> static_cast<uint16_t>(bit)) & 1
enum class FlagBit : uint16_t {
    SplitTransport = 0,   ///< Bit 0: SPLIT_TRANSPORT
    // Bits 1-3: reserved permanently
    P1Image        = 4,   ///< Bit 4: SFC/P1
    P2Split        = 5,   ///< Bit 5: SFC/P2
    P3Http         = 6,   ///< Bit 6: SFC/P3
    P4Preprocess   = 7,   ///< Bit 7: SFC/P4
    P5Directory    = 8,   ///< Bit 8: SFC/P5
    // Bits 9-15: reserved for future profiles
};

// ---------------------------------------------------------------------------
// Protocol hard limits (Section 18.3)
// ---------------------------------------------------------------------------

namespace limits {

inline constexpr uint64_t kMaxInnerFileSize       = 1'099'511'627'776ULL;  ///< 1 TB
inline constexpr uint32_t kMaxDataChunkCount      = 65'534;               ///< N max
inline constexpr uint32_t kMaxRecoveryChunkCount  = 65'534;               ///< M max
inline constexpr uint32_t kMaxTotalChunkCount     = 65'535;               ///< N+M max (GF(2^16))
inline constexpr uint32_t kMinChunkSize           = 2;                    ///< S min (must be even)
inline constexpr uint32_t kMaxChunkSize           = 268'435'456;          ///< S max = 256 MB
inline constexpr uint32_t kMinHeaderLength        = 331;                  ///< H min
inline constexpr uint32_t kMaxHeaderLength        = 65'536;               ///< H max
inline constexpr uint32_t kMaxTlvValueLength      = 16'384;              ///< TLV value max
inline constexpr uint32_t kMinManifestBodyB       = 57;                   ///< B min (1 file, 1-byte path)
inline constexpr uint32_t kMaxManifestBodyB       = 67'108'864;           ///< B max = 64 MB
inline constexpr uint32_t kMaxFileCount           = 1'048'576;            ///< F max (P5)
inline constexpr uint16_t kMinPathLength          = 1;                    ///< L min (P5)
inline constexpr uint16_t kMaxPathLength          = 4'096;                ///< L max (P5)
inline constexpr uint32_t kMaxMetadataStringLength = 4'096;               ///< max UTF-8 bytes per metadata TLV

}  // namespace limits

// ---------------------------------------------------------------------------
// FileMetadata — optional user-supplied metadata stored in TLV fields
// ---------------------------------------------------------------------------

/// User-supplied metadata that travels with every SFC file.
/// Empty strings are not encoded (no TLV emitted for that field).
struct FileMetadata {
    std::string author;       ///< Author name (UTF-8, TLV 0x0100).
    std::string description;  ///< Description (UTF-8, TLV 0x0101).
    std::string location;     ///< Location: place name or geo string (UTF-8, TLV 0x0102).
    std::string software;     ///< Creating software (UTF-8, TLV 0x0103).
    std::string comment;      ///< Free-form comment (UTF-8, TLV 0x0104).
};

// ---------------------------------------------------------------------------
// FileUuid — 128-bit identifier (Section 4.1)
// ---------------------------------------------------------------------------

/// 128-bit File UUID. Value type with equality and hashing.
struct FileUuid {
    std::array<uint8_t, 16> bytes{};

    bool operator==(const FileUuid&) const = default;
    auto operator<=>(const FileUuid&) const = default;
};

}  // namespace sfc

/// std::hash specialization for FileUuid (enables use in unordered containers).
template <>
struct std::hash<sfc::FileUuid> {
    size_t operator()(const sfc::FileUuid& uuid) const noexcept {
        size_t h = 0;
        for (auto b : uuid.bytes) {
            h ^= std::hash<uint8_t>{}(b) + 0x9e3779b9 + (h << 6) + (h >> 2);
        }
        return h;
    }
};