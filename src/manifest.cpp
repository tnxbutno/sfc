/// @file manifest.cpp
/// @brief Directory Manifest parse/serialize (P5, §16).

#include "sfc/manifest.h"
#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"
#include "sfc/types.h"

#include <cstring>  // std::memcpy

#include <format>

namespace sfc {

Result<Manifest> parse_manifest(std::span<const uint8_t> data) {
    // Minimum: 8 (header) + 4 (F field) + 32 (hash) = 44 bytes, with B>=4 → at least 44.
    if (data.size() < 44) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            "manifest too small"
        });
    }

    // Verify "MFST" magic at bytes 0-3.
    if (data[0] != 0x4D || data[1] != 0x46 || data[2] != 0x53 || data[3] != 0x54) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            std::format("expected MFST magic, got {:02X}{:02X}{:02X}{:02X}",
                        data[0], data[1], data[2], data[3])
        });
    }

    // Body length B [4..7].
    uint32_t B = read_u32_le(std::span<const uint8_t, 4>{data.data() + 4, 4});

    // B must be within protocol limits (§16.2).
    if (B < limits::kMinManifestBodyB || B > limits::kMaxManifestBodyB) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("manifest B={} out of bounds [{}, {}]",
                        B, limits::kMinManifestBodyB, limits::kMaxManifestBodyB)
        });
    }

    // manifest_size = 8 + B + 32.
    const size_t manifest_size = 8 + static_cast<size_t>(B) + 32;
    if (data.size() < manifest_size) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            std::format("manifest data {} bytes < expected {} bytes",
                        data.size(), manifest_size)
        });
    }

    // Verify BLAKE3 hash at offset 8+B covering bytes [0..8+B-1].
    Blake3Digest expected_hash;
    std::copy_n(data.data() + 8 + B, 32, expected_hash.begin());

    auto verify_res = blake3_verify(data.subspan(0, 8 + B), expected_hash);
    if (!verify_res) {
        return std::unexpected(SfcError{
            ErrorCode::ManifestBlake3Failure, "manifest BLAKE3 hash mismatch"
        });
    }

    // File count F [8..11].
    if (B < 4) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic, "manifest B < 4 (no F field)"
        });
    }
    uint32_t F = read_u32_le(std::span<const uint8_t, 4>{data.data() + 8, 4});

    // F must be in [1, kMaxFileCount] (§16.2).
    if (F < 1 || F > limits::kMaxFileCount) {
        return std::unexpected(SfcError{
            ErrorCode::FieldAboveMaximum,
            std::format("manifest F={} out of bounds [1, {}]", F, limits::kMaxFileCount)
        });
    }

    // Parse F file entries from bytes [12..8+B-1].
    Manifest mfst;
    mfst.hash = expected_hash;

    size_t pos = 12;  // first entry starts at byte 12
    const size_t entries_end = 8 + B;  // exclusive end of entry region

    for (uint32_t fi = 0; fi < F; ++fi) {
        if (pos + 2 > entries_end) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidMagic,
                std::format("manifest entry {} truncated at path length", fi)
            });
        }

        ManifestFileEntry entry{};

        // Path length L [pos..pos+1].
        uint16_t L = read_u16_le(std::span<const uint8_t, 2>{data.data() + pos, 2});
        pos += 2;

        // L must be in [kMinPathLength, kMaxPathLength] (§16.3).
        if (L < limits::kMinPathLength || L > limits::kMaxPathLength) {
            return std::unexpected(SfcError{
                ErrorCode::FieldAboveMaximum,
                std::format("manifest entry {}: path length L={} out of bounds [{}, {}]",
                            fi, L, limits::kMinPathLength, limits::kMaxPathLength)
            });
        }

        // Path bytes [pos..pos+L-1].
        if (pos + L > entries_end) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidMagic,
                std::format("manifest entry {} path overruns boundary", fi)
            });
        }
        // Copy L bytes of UTF-8 path into the std::string via memcpy.
        // This avoids reinterpret_cast<const char*> while remaining type-safe.
        entry.path.resize(static_cast<size_t>(L));
        std::memcpy(entry.path.data(), data.data() + pos, static_cast<size_t>(L));
        pos += L;

        // Remaining fixed fields: 8+8+32+2 = 50 bytes.
        if (pos + 50 > entries_end) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidMagic,
                std::format("manifest entry {} fixed fields overrun boundary", fi)
            });
        }

        // Byte offset [pos..pos+7].
        entry.byte_offset = read_u64_le(
            std::span<const uint8_t, 8>{data.data() + pos, 8});
        pos += 8;

        // File size [pos..pos+7].
        entry.file_size = read_u64_le(
            std::span<const uint8_t, 8>{data.data() + pos, 8});
        pos += 8;

        // Per-file BLAKE3 hash [pos..pos+31].
        std::copy_n(data.data() + pos, 32, entry.file_hash.begin());
        pos += 32;

        // Inner Format ID [pos..pos+1].
        entry.inner_format_id = read_u16_le(
            std::span<const uint8_t, 2>{data.data() + pos, 2});
        pos += 2;

        mfst.entries.push_back(std::move(entry));
    }

    return mfst;
}

std::vector<uint8_t> serialize_manifest(const std::vector<ManifestFileEntry>& entries) {
    // Build all entry bytes first.
    std::vector<uint8_t> entry_bytes;
    for (const auto& e : entries) {
        uint16_t L = static_cast<uint16_t>(e.path.size());
        auto L_bytes = write_u16_le(L);
        entry_bytes.insert(entry_bytes.end(), L_bytes.begin(), L_bytes.end());
        entry_bytes.insert(entry_bytes.end(), e.path.begin(), e.path.end());
        auto bo = write_u64_le(e.byte_offset);
        entry_bytes.insert(entry_bytes.end(), bo.begin(), bo.end());
        auto fs = write_u64_le(e.file_size);
        entry_bytes.insert(entry_bytes.end(), fs.begin(), fs.end());
        entry_bytes.insert(entry_bytes.end(), e.file_hash.begin(), e.file_hash.end());
        auto fid = write_u16_le(e.inner_format_id);
        entry_bytes.insert(entry_bytes.end(), fid.begin(), fid.end());
    }

    // B = 4 (F field) + total entry bytes.
    uint32_t B = 4 + static_cast<uint32_t>(entry_bytes.size());
    uint32_t F = static_cast<uint32_t>(entries.size());

    // Assemble header + entries (= 8+B bytes to hash).
    std::vector<uint8_t> to_hash;
    to_hash.reserve(8 + B);
    // Magic "MFST"
    to_hash.push_back(0x4D); to_hash.push_back(0x46);
    to_hash.push_back(0x53); to_hash.push_back(0x54);
    auto B_bytes = write_u32_le(B);
    to_hash.insert(to_hash.end(), B_bytes.begin(), B_bytes.end());
    auto F_bytes = write_u32_le(F);
    to_hash.insert(to_hash.end(), F_bytes.begin(), F_bytes.end());
    to_hash.insert(to_hash.end(), entry_bytes.begin(), entry_bytes.end());

    // Compute BLAKE3 hash of the 8+B byte region.
    Blake3Digest hash = blake3(to_hash);

    // Final output: to_hash + hash (32 bytes).
    std::vector<uint8_t> out(std::move(to_hash));
    out.insert(out.end(), hash.begin(), hash.end());
    return out;
}

Result<uint64_t> manifest_size_from_chunk0(std::span<const uint8_t> data) {
    if (data.size() < 8) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic, "chunk 0 too small to read manifest B"
        });
    }
    // Verify "MFST" magic.
    if (data[0] != 0x4D || data[1] != 0x46 || data[2] != 0x53 || data[3] != 0x54) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic, "chunk 0 does not start with MFST magic"
        });
    }
    uint32_t B = read_u32_le(std::span<const uint8_t, 4>{data.data() + 4, 4});
    return static_cast<uint64_t>(8) + B + 32;
}

}  // namespace sfc
