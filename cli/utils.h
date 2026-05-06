#pragma once

/// @file utils.h
/// @brief Shared CLI helpers: file I/O, UUID generation, display formatting.

#include "sfc/byte_utils.h"
#include "sfc/decoder.h"
#include "sfc/global_header.h"
#include "sfc/segment_header.h"
#include "sfc/types.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <optional>
#include <print>
#include <random>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace cli {

// ---------------------------------------------------------------------------
// File I/O
// ---------------------------------------------------------------------------

/// Read an entire file into a byte vector.  Throws std::runtime_error on failure.
inline std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open for reading: " + path);
    const auto size = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> data(static_cast<size_t>(size));
    in.read(reinterpret_cast<char*>(data.data()), size);
    if (!in) throw std::runtime_error("read error: " + path);
    return data;
}

/// Drain stdin into a byte vector.
inline std::vector<uint8_t> read_stdin() {
    std::vector<uint8_t> data;
    std::array<char, 8192> buf{};
    while (std::cin.read(buf.data(), static_cast<std::streamsize>(buf.size()))) {
        const auto n = static_cast<size_t>(std::cin.gcount());
        data.insert(data.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
    }
    const auto tail = static_cast<size_t>(std::cin.gcount());
    data.insert(data.end(), buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(tail));
    return data;
}

/// Write bytes to a file, creating parent directories as needed.
inline void write_file(const std::string& path, std::span<const uint8_t> data) {
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent);
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("cannot open for writing: " + path);
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    if (!out) throw std::runtime_error("write error: " + path);
}

/// Write bytes to stdout.
inline void write_stdout(std::span<const uint8_t> data) {
    std::cout.write(reinterpret_cast<const char*>(data.data()),
                    static_cast<std::streamsize>(data.size()));
    if (!std::cout) throw std::runtime_error("write error: stdout");
}

// ---------------------------------------------------------------------------
// UUID generation
// ---------------------------------------------------------------------------

/// Generate a random UUID conforming to RFC 9562 version 4.
inline sfc::FileUuid generate_uuid() {
    sfc::FileUuid uuid;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    for (auto& b : uuid.bytes)
        b = static_cast<uint8_t>(dist(gen));
    // Version 4: high nibble of byte 6 = 0100b.
    uuid.bytes[6] = static_cast<uint8_t>((uuid.bytes[6] & 0x0Fu) | 0x40u);
    // Variant 1: two high bits of byte 8 = 10b.
    uuid.bytes[8] = static_cast<uint8_t>((uuid.bytes[8] & 0x3Fu) | 0x80u);
    return uuid;
}

// ---------------------------------------------------------------------------
// Naming helpers
// ---------------------------------------------------------------------------

/// Derive the output .sfc path from the input path:  "input.bin" → "input.sfc".
inline std::string default_output_path(const std::string& input) {
    return std::filesystem::path(input).replace_extension(".sfc").string();
}

/// Build the N-th segment output path.
/// base="archive.sfc", index=0, total=4  →  "archive-01.sfc"
/// base="archive.sfc", index=0, total=100 →  "archive-001.sfc"
inline std::string segment_path(const std::string& base,
                                 uint32_t index, uint32_t total) {
    const std::filesystem::path p(base);
    // Minimum 2 digits so single-digit totals still produce seg-01, seg-02.
    const int width = std::max(2, static_cast<int>(std::to_string(total).size()));
    return (p.parent_path() /
            std::format("{}-{:0{}d}{}",
                        p.stem().string(),
                        index + 1,
                        width,
                        p.extension().string()))
               .string();
}

// ---------------------------------------------------------------------------
// format_id inference from file extension
// ---------------------------------------------------------------------------

inline uint16_t format_id_from_extension(const std::filesystem::path& p) {
    std::string ext = p.extension().string();
    for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (ext == ".txt" || ext == ".md"  || ext == ".log" || ext == ".csv") return 0x0010;
    if (ext == ".jpg" || ext == ".jpeg")                                   return 0x0020;
    if (ext == ".png")                                                     return 0x0024;
    if (ext == ".webp")                                                    return 0x0026;
    if (ext == ".mp4")                                                     return 0x0030;
    if (ext == ".mkv" || ext == ".webm")                                   return 0x0031;
    if (ext == ".pdf")                                                     return 0x0100;
    if (ext == ".epub")                                                    return 0x0101;
    if (ext == ".zip")                                                     return 0x0040;
    if (ext == ".gz")                                                      return 0x0041;
    if (ext == ".zst")                                                     return 0x0042;
    return 0x0001;  // ArbitraryBinary
}

// ---------------------------------------------------------------------------
// algo parsing
// ---------------------------------------------------------------------------

inline sfc::CompressionAlgo parse_algo(const std::string& s) {
    if (s == "zstd")   return sfc::CompressionAlgo::Zstd;
    if (s == "brotli") return sfc::CompressionAlgo::Brotli;
    if (s == "lz4")    return sfc::CompressionAlgo::Lz4Frame;
    if (s == "none")   return sfc::CompressionAlgo::Identity;
    throw std::runtime_error("unknown algo '" + s + "' — use: zstd | brotli | lz4 | none");
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

inline std::string format_uuid(const sfc::FileUuid& uuid) {
    // xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    const auto& b = uuid.bytes;
    return std::format(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}"
        "-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
}

inline std::string format_timestamp(uint64_t ts) {
    if (ts == 0) return "unset";
    const std::time_t t = static_cast<std::time_t>(ts);
    std::array<char, 32> buf{};
    std::tm tm_buf{};
#ifdef _WIN32
    gmtime_s(&tm_buf, &t);
#else
    gmtime_r(&t, &tm_buf);
#endif
    std::strftime(buf.data(), buf.size(), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
    return std::string(buf.data());
}

inline std::string_view format_id_name(uint16_t id) {
    switch (static_cast<sfc::InnerFormatId>(id)) {
        case sfc::InnerFormatId::Unknown:          return "Unknown";
        case sfc::InnerFormatId::ArbitraryBinary:  return "ArbitraryBinary";
        case sfc::InnerFormatId::PlainText:        return "PlainText";
        case sfc::InnerFormatId::LineOriented:     return "LineOriented";
        case sfc::InnerFormatId::JpegBaseline:     return "JpegBaseline";
        case sfc::InnerFormatId::JpegProgressive:  return "JpegProgressive";
        case sfc::InnerFormatId::Jpeg2000:         return "Jpeg2000";
        case sfc::InnerFormatId::JpegXl:           return "JpegXl";
        case sfc::InnerFormatId::PngNonInterlaced: return "PngNonInterlaced";
        case sfc::InnerFormatId::PngAdam7:         return "PngAdam7";
        case sfc::InnerFormatId::WebP:             return "WebP";
        case sfc::InnerFormatId::FragmentedMp4:    return "FragmentedMp4";
        case sfc::InnerFormatId::MatroskaWebm:     return "MatroskaWebm";
        case sfc::InnerFormatId::Zip:              return "Zip";
        case sfc::InnerFormatId::Gzip:             return "Gzip";
        case sfc::InnerFormatId::ZstdData:         return "ZstdData";
        case sfc::InnerFormatId::TarZstd:          return "TarZstd";
        case sfc::InnerFormatId::SfcDirectory:     return "SfcDirectory";
        case sfc::InnerFormatId::NestedSfc:        return "NestedSfc";
        case sfc::InnerFormatId::Pdf:              return "Pdf";
        case sfc::InnerFormatId::EPub:             return "EPub";
        default:                                    return "Unknown";
    }
}

inline std::string_view compression_algo_name(uint8_t algo) {
    switch (static_cast<sfc::CompressionAlgo>(algo)) {
        case sfc::CompressionAlgo::Identity:  return "none";
        case sfc::CompressionAlgo::Zstd:      return "zstd";
        case sfc::CompressionAlgo::Brotli:    return "brotli";
        case sfc::CompressionAlgo::Lz4Frame:  return "lz4";
        default:                                    return "unknown";
    }
}

inline std::string profile_name(uint16_t flags) {
    using F = sfc::FlagBit;
    if (flags & (1u << static_cast<uint16_t>(F::P2Split)))    return "P2/split";
    if (flags & (1u << static_cast<uint16_t>(F::P5Directory))) return "P5/directory";
    if (flags & (1u << static_cast<uint16_t>(F::P1Image)))    return "P1/image";
    if (flags & (1u << static_cast<uint16_t>(F::P3Http)))     return "P3/http";
    if (flags & (1u << static_cast<uint16_t>(F::P4Preprocess))) return "P4/preprocess";
    return "regular";
}

inline std::string inner_filename_str(const std::array<uint8_t, 255>& raw) {
    const auto end = std::find(raw.begin(), raw.end(), static_cast<uint8_t>(0));
    return std::string(raw.begin(), end);
}

// ---------------------------------------------------------------------------
// Header parsing from raw file bytes
// ---------------------------------------------------------------------------

/// Parse the GlobalHeader from a complete SFC file byte buffer.
/// Handles preamble skip; uses the H field at offset 8 to locate the header region.
inline sfc::Result<sfc::GlobalHeader>
parse_header_from_file(std::span<const uint8_t> data) {
    // Need at least preamble (8) + H field (4).
    if (data.size() < 12) {
        return std::unexpected(sfc::SfcError{
            sfc::ErrorCode::BufferTooSmall, "file too small to contain a global header"});
    }
    const uint32_t h = sfc::read_u32_le(std::span<const uint8_t, 4>{data.data() + 8, 4});
    if (data.size() < static_cast<size_t>(8 + h + 4)) {
        return std::unexpected(sfc::SfcError{
            sfc::ErrorCode::BufferTooSmall, "file truncated within global header region"});
    }
    return sfc::parse_global_header(data.subspan(8, static_cast<size_t>(h + 4)));
}

/// Returns true if the file has the SPLIT_TRANSPORT flag set (P2 segment).
inline bool is_p2_segment(std::span<const uint8_t> data) {
    auto hdr = parse_header_from_file(data);
    if (!hdr) return false;
    return (hdr->flags & (1u << static_cast<uint16_t>(sfc::FlagBit::SplitTransport))) != 0;
}

/// Returns true if the file has the P5Directory flag set.
inline bool is_p5_directory(std::span<const uint8_t> data) {
    auto hdr = parse_header_from_file(data);
    if (!hdr) return false;
    return (hdr->flags & (1u << static_cast<uint16_t>(sfc::FlagBit::P5Directory))) != 0;
}

/// Attempt to parse a P2 SegmentHeader from a file (only valid if is_p2_segment).
inline std::optional<sfc::SegmentHeader>
parse_segment_hdr_from_file(std::span<const uint8_t> data) {
    if (data.size() < 12) return std::nullopt;
    const uint32_t h = sfc::read_u32_le(std::span<const uint8_t, 4>{data.data() + 8, 4});
    const size_t seg_offset = 8 + static_cast<size_t>(h) + 4;
    if (data.size() < seg_offset + 16) return std::nullopt;
    auto r = sfc::parse_segment_header(
        std::span<const uint8_t, 16>{data.data() + seg_offset, 16});
    if (!r) return std::nullopt;
    return *r;
}

// ---------------------------------------------------------------------------
// P2 segment auto-discovery
// ---------------------------------------------------------------------------

/// Read exactly N bytes from a file into a fixed-size array.
/// Returns false if the file is shorter than N bytes or cannot be opened.
template <size_t N>
inline bool read_file_head(const std::string& path,
                           std::array<uint8_t, N>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(N));
    return static_cast<size_t>(f.gcount()) == N;
}

/// Extract the UUID from the first 28 bytes of an SFC file
/// (§13.3 Step 2: Preamble 8 + H-field 4 + UUID 16 = 28 bytes).
/// Returns false if the header is too short or magic is wrong.
inline bool uuid_from_head(const std::array<uint8_t, 28>& head,
                            sfc::FileUuid& out) {
    // Verify SFC magic "SFC\0".
    if (head[0] != 0x53 || head[1] != 0x46 ||
        head[2] != 0x43 || head[3] != 0x00) return false;
    std::copy_n(head.data() + 12, 16, out.bytes.begin());
    return true;
}

/// Given the path to a single .sfc file, return the full list of P2 siblings
/// sharing its UUID found in the same directory.  If the file is not a P2
/// segment, or no siblings exist, returns a one-element vector with the
/// original path unchanged.
///
/// Candidate files are identified by reading only the first 28 bytes
/// (§13.3 Step 2 — MUST NOT read full file contents during scan).
inline std::vector<std::string>
discover_p2_siblings(const std::string& path) {
    std::vector<uint8_t> data;
    try { data = read_file(path); } catch (...) { return {path}; }

    if (!is_p2_segment(data)) return {path};

    auto hdr = parse_header_from_file(data);
    if (!hdr) return {path};

    const sfc::FileUuid target = hdr->uuid;

    const std::filesystem::path dir =
        std::filesystem::path(path).parent_path();
    const std::filesystem::path scan =
        dir.empty() ? std::filesystem::path(".") : dir;

    std::vector<std::string> found;
    try {
        for (const auto& e : std::filesystem::directory_iterator(scan)) {
            if (!e.is_regular_file()) continue;
            if (e.path().extension() != ".sfc") continue;
            // §13.3 Step 2: read only the first 28 bytes for UUID comparison.
            std::array<uint8_t, 28> head{};
            if (!read_file_head(e.path().string(), head)) continue;
            sfc::FileUuid candidate_uuid{};
            if (!uuid_from_head(head, candidate_uuid)) continue;
            if (candidate_uuid == target)
                found.push_back(e.path().string());
        }
    } catch (...) { return {path}; }

    if (found.empty()) return {path};

    std::sort(found.begin(), found.end());
    return found;
}

}  // namespace cli
