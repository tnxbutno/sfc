/// @file directory.cpp
/// @brief Directory profile implementation (P5, Section 16).
///
/// Encoding layout (inner_content):
///   [0 .. manifest_size-1]  Manifest  (8+B+32 bytes)
///   [manifest_size ..]      File bytes concatenated in manifest order
///
/// manifest_size  = 8 (MFST header) + B + 32 (BLAKE3)
/// B              = 4 (F field) + sum(52 + path_len)  for all files

#include "sfc/directory.h"

#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"
#include "sfc/compression.h"
#include "sfc/filename_sanitize.h"
#include "sfc/manifest.h"
#include "sfc/reassembly.h"
#include "sfc/reed_solomon.h"
#include "sfc/split_encoder.h"

#include <algorithm>
#include <format>
#include <unordered_map>

namespace sfc {

// ===========================================================================
// Internal helpers
// ===========================================================================

/// @brief Validate a single relative file path per Section 16 rules.
///
/// Returns false if the path is empty, starts with '/', contains '\\',
/// has a ".." or "." component, contains control characters, or has
/// an empty component (double slash).
[[nodiscard]] static bool is_valid_directory_path(const std::string& path) noexcept {
    if (path.empty()) return false;
    if (path.front() == '/') return false;   // no leading slash
    if (path.back()  == '/') return false;   // no trailing slash
    if (path.find('\\') != std::string::npos) return false;  // no backslash

    // No control characters (0x00-0x1F, 0x7F).
    for (char raw : path) {
        auto c = static_cast<unsigned char>(raw);
        if (c < 0x20 || c == 0x7F) return false;
    }

    // Validate every slash-delimited component.
    const std::string_view sv = path;
    size_t start = 0;
    while (start <= sv.size()) {
        size_t slash = sv.find('/', start);
        size_t len   = (slash == std::string_view::npos)
                       ? sv.size() - start
                       : slash - start;
        std::string_view component = sv.substr(start, len);
        if (component.empty()) return false;          // double-slash
        if (component == "." || component == "..") return false;
        start = (slash == std::string_view::npos) ? sv.size() + 1 : slash + 1;
    }
    return true;
}

/// @brief Compute manifest_size from a list of paths without serializing.
///
/// manifest_size = 8 (header) + B + 32 (hash)
/// B             = 4 (F field) + sum(52 + path.size())
[[nodiscard]] static uint64_t compute_manifest_size(
    const std::vector<DirectoryInputFile>& files) noexcept
{
    // 52 bytes per entry (fixed fields) + path length.
    uint64_t entry_bytes = 0;
    for (const auto& f : files)
        entry_bytes += 52 + static_cast<uint64_t>(f.path.size());

    const uint64_t B = 4 + entry_bytes;       // F field + entries
    return 8 + B + 32;                         // header + body + BLAKE3
}

// ===========================================================================
// prepare_directory_inner  (shared by encode_directory and encode_directory_split)
// ===========================================================================

/// @brief Validate, sort, hash, and serialise directory files into inner content.
///
/// Performs steps 1-8 of the directory encoding pipeline (P5, Section 16), producing
/// the raw inner_content bytes (manifest || file data) and the updated EncodeParams
/// with directory profile flags set.
/// Both encode_directory and encode_directory_split delegate here.
[[nodiscard]] static Result<std::pair<std::vector<uint8_t>, EncodeParams>>
prepare_directory_inner(std::vector<DirectoryInputFile> files, EncodeParams params) {
    // Directory profile requires at least one file (F >= 1, Section 16.2).
    if (files.empty()) {
        return std::unexpected(SfcError{
            ErrorCode::FieldBelowMinimum, "directory must contain at least one file (F >= 1)"
        });
    }
    // Directory profile requires S >= 8 so Manifest Magic and B fit in chunk 0 (Section 16.1).
    if (params.s < 8) {
        return std::unexpected(SfcError{
            ErrorCode::FieldBelowMinimum,
            std::format("directory profile requires S >= 8; got S={}", params.s)
        });
    }

    // ---------------------------------------------------------------------------
    // Step 1: Validate all paths.
    // ---------------------------------------------------------------------------
    for (const auto& f : files) {
        if (!is_valid_directory_path(f.path)) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidArgument,
                std::format("invalid path: \"{}\"", f.path)
            });
        }
    }

    // ---------------------------------------------------------------------------
    // Step 2: Detect case collisions (Section 4.8).
    // ---------------------------------------------------------------------------
    std::unordered_map<std::string, std::string> seen_folded;
    for (const auto& f : files) {
        std::string folded = case_fold(f.path);
        auto [it, inserted] = seen_folded.emplace(folded, f.path);
        if (!inserted && it->second != f.path) {
            return std::unexpected(SfcError{
                ErrorCode::CaseCollisionInManifest,
                std::format("case collision: \"{}\" vs \"{}\"", f.path, it->second)
            });
        }
    }

    // ---------------------------------------------------------------------------
    // Step 3: Sort files by path (lexicographic on UTF-8 bytes).
    // ---------------------------------------------------------------------------
    std::sort(files.begin(), files.end(),
              [](const DirectoryInputFile& a, const DirectoryInputFile& b) {
                  return a.path < b.path;
              });

    // ---------------------------------------------------------------------------
    // Step 4: Compute per-file BLAKE3 hashes.
    // ---------------------------------------------------------------------------
    std::vector<Blake3Digest> file_hashes;
    file_hashes.reserve(files.size());
    for (const auto& f : files) {
        file_hashes.push_back(blake3(f.content));
    }

    // ---------------------------------------------------------------------------
    // Step 5: Compute manifest_size, then derive byte_offsets.
    // ---------------------------------------------------------------------------
    const uint64_t manifest_sz = compute_manifest_size(files);

    std::vector<uint64_t> byte_offsets(files.size());
    if (!files.empty()) {
        byte_offsets[0] = manifest_sz;
        for (size_t i = 1; i < files.size(); ++i) {
            byte_offsets[i] = byte_offsets[i - 1]
                              + static_cast<uint64_t>(files[i - 1].content.size());
        }
    }

    // ---------------------------------------------------------------------------
    // Step 6: Build ManifestFileEntry list and serialize manifest.
    // ---------------------------------------------------------------------------
    std::vector<ManifestFileEntry> entries;
    entries.reserve(files.size());
    for (size_t i = 0; i < files.size(); ++i) {
        entries.push_back(ManifestFileEntry{
            .path            = files[i].path,
            .byte_offset     = byte_offsets[i],
            .file_size       = static_cast<uint64_t>(files[i].content.size()),
            .file_hash       = file_hashes[i],
            .inner_format_id = files[i].format_id,
        });
    }

    auto manifest_bytes = serialize_manifest(entries);

    // ---------------------------------------------------------------------------
    // Step 7: Build inner_content = manifest || file contents.
    // ---------------------------------------------------------------------------
    uint64_t total_file_bytes = 0;
    for (const auto& f : files) total_file_bytes += f.content.size();

    std::vector<uint8_t> inner_content;
    inner_content.reserve(manifest_bytes.size() + total_file_bytes);
    inner_content.insert(inner_content.end(),
                         manifest_bytes.begin(), manifest_bytes.end());
    for (const auto& f : files) {
        inner_content.insert(inner_content.end(),
                             f.content.begin(), f.content.end());
    }

    // ---------------------------------------------------------------------------
    // Step 8: Override format_id, set directory profile flag, clear inner filename.
    // ---------------------------------------------------------------------------
    params.format_id  = static_cast<uint16_t>(InnerFormatId::SfcDirectory);
    params.flags     |= static_cast<uint16_t>(1u << static_cast<uint16_t>(FlagBit::DirectoryProfile));
    params.filename   = "";

    return std::make_pair(std::move(inner_content), std::move(params));
}

// ===========================================================================
// encode_directory
// ===========================================================================

Result<std::vector<uint8_t>>
encode_directory(std::vector<DirectoryInputFile> files, EncodeParams params) {
    auto prep = prepare_directory_inner(std::move(files), std::move(params));
    if (!prep) return std::unexpected(prep.error());
    auto [inner, p] = std::move(*prep);
    return encode(inner, p);
}

// ===========================================================================
// encode_directory_split
// ===========================================================================

Result<std::vector<std::vector<uint8_t>>>
encode_directory_split(std::vector<DirectoryInputFile> files,
                       EncodeParams params,
                       uint32_t num_segments) {
    auto prep = prepare_directory_inner(std::move(files), std::move(params));
    if (!prep) return std::unexpected(prep.error());
    auto [inner, p] = std::move(*prep);
    return encode_split(inner, p, num_segments);
}

// ===========================================================================
// extract_directory_full
// ===========================================================================

Result<DirectoryExtractResult>
extract_directory_full(std::span<const uint8_t> inner_content) {
    // ---------------------------------------------------------------------------
    // Read manifest_size from the first 8 bytes (MFST + B).
    // ---------------------------------------------------------------------------
    if (inner_content.size() < 8) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic, "inner_content too small for manifest header"
        });
    }

    // manifest_size_from_chunk0 reads the "MFST" magic + B field.
    auto ms_res = manifest_size_from_chunk0(inner_content);
    if (!ms_res) return std::unexpected(ms_res.error());
    const uint64_t manifest_sz = *ms_res;

    if (inner_content.size() < manifest_sz) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic,
            std::format("inner_content {} bytes < manifest_size {} bytes",
                        inner_content.size(), manifest_sz)
        });
    }

    // ---------------------------------------------------------------------------
    // Parse and hash-verify the Manifest.
    // ---------------------------------------------------------------------------
    auto mfst_res = parse_manifest(inner_content.subspan(0, manifest_sz));
    if (!mfst_res) return std::unexpected(mfst_res.error());
    const Manifest& mfst = *mfst_res;

    // ---------------------------------------------------------------------------
    // Validate byte_offset consistency (Section 16.7).
    // First file must start at manifest_sz; entries must be contiguous.
    // Path length L must be at least 1 (Section 16.7 step 2f, Section 18.3).
    // ---------------------------------------------------------------------------
    for (size_t i = 0; i < mfst.entries.size(); ++i) {
        if (mfst.entries[i].path.empty()) {
            return std::unexpected(SfcError{
                ErrorCode::EmptyInnerFilename,
                std::format("manifest entry {}: path length L=0", i)
            });
        }
    }
    const uint64_t content_size = static_cast<uint64_t>(inner_content.size());
    uint64_t expected_offset = manifest_sz;
    for (size_t i = 0; i < mfst.entries.size(); ++i) {
        const auto& e = mfst.entries[i];
        if (e.byte_offset != expected_offset) {
            return std::unexpected(SfcError{
                ErrorCode::ManifestOffsetSizeInconsistency,
                std::format("entry {}: byte_offset {} != expected {}",
                            i, e.byte_offset, expected_offset)
            });
        }
        if (e.file_size > content_size - expected_offset) {
            return std::unexpected(SfcError{
                ErrorCode::ManifestOffsetSizeInconsistency,
                std::format("entry {}: file_size {} overflows inner content at offset {}",
                            i, e.file_size, expected_offset)
            });
        }
        expected_offset += e.file_size;
    }

    // Total inner_content must be at least manifest_sz + sum(file_sizes).
    if (inner_content.size() < expected_offset) {
        return std::unexpected(SfcError{
            ErrorCode::ManifestOffsetSizeInconsistency,
            std::format("inner_content {} bytes < required {} bytes",
                        inner_content.size(), expected_offset)
        });
    }

    // ---------------------------------------------------------------------------
    // Extract and BLAKE3-verify each file.
    // ---------------------------------------------------------------------------
    DirectoryExtractResult result;
    result.files.reserve(mfst.entries.size());

    for (const auto& e : mfst.entries) {
        auto file_span = inner_content.subspan(
            static_cast<size_t>(e.byte_offset),
            static_cast<size_t>(e.file_size));

        auto hash_res = blake3_verify(file_span, e.file_hash);
        if (!hash_res) {
            return std::unexpected(SfcError{
                ErrorCode::PerFileBlake3Mismatch,
                std::format("per-file BLAKE3 mismatch: \"{}\"", e.path)
            });
        }

        result.files.push_back(ExtractedFile{
            .path      = e.path,
            .content   = std::vector<uint8_t>(file_span.begin(), file_span.end()),
            .format_id = e.inner_format_id,
        });
    }

    return result;
}

// ===========================================================================
// extract_directory_partial
// ===========================================================================

Result<DirectoryExtractResult>
extract_directory_partial(const std::vector<ParsedChunk>& working_set,
                          const GlobalHeader& hdr)
{
    // ---------------------------------------------------------------------------
    // Count distinct data chunks available (V_data).
    // V = working_set.size() counts all chunks including recovery.
    // For RS reconstruction we need at least N total chunks.
    // ---------------------------------------------------------------------------
    const CompressionAlgo algo = normalize_compression_id(hdr.compression_algo);

    // Check if V >= N  (we might be able to do full reconstruction).
    if (working_set.size() >= hdr.n) {
        // Sort working_set by index; try RS reconstruct.
        std::vector<RsChunk> rs_inputs;
        rs_inputs.reserve(hdr.n);

        // Collect up to N decompressible chunks.
        std::vector<const ParsedChunk*> sorted_ws;
        sorted_ws.reserve(working_set.size());
        for (const auto& c : working_set) sorted_ws.push_back(&c);
        std::sort(sorted_ws.begin(), sorted_ws.end(),
                  [](const ParsedChunk* a, const ParsedChunk* b){
                      return a->header.chunk_index < b->header.chunk_index; });

        for (const auto* c : sorted_ws) {
            auto dec = decompress(c->payload, algo, hdr.s);
            if (!dec) continue;
            rs_inputs.push_back(RsChunk{c->header.chunk_index, std::move(*dec)});
            if (rs_inputs.size() == hdr.n) break;
        }

        if (rs_inputs.size() >= hdr.n) {
            // Full reconstruction possible via RS.
            std::vector<std::vector<uint8_t>> data_blocks;
            if (hdr.m == 0) {
                // All data chunks present directly.
                data_blocks.resize(hdr.n);
                for (auto& ri : rs_inputs) {
                    if (ri.index < hdr.n)
                        data_blocks[ri.index] = std::move(ri.data);
                }
            } else {
                auto rs_res = rs_reconstruct(rs_inputs, hdr.n, hdr.m, hdr.s);
                if (!rs_res) return std::unexpected(rs_res.error());
                data_blocks = std::move(*rs_res);
            }

            // Reconstruct inner_content.
            std::vector<uint8_t> inner_content;
            inner_content.reserve(static_cast<size_t>(hdr.n) * hdr.s);
            for (const auto& blk : data_blocks)
                inner_content.insert(inner_content.end(), blk.begin(), blk.end());
            if (inner_content.size() > hdr.inner_file_size)
                inner_content.resize(static_cast<size_t>(hdr.inner_file_size));

            return extract_directory_full(inner_content);
        }
        // Fall through to Case B if RS inputs insufficient.
    }

    // ---------------------------------------------------------------------------
    // Case B: V < N - partial extraction from available data chunks.
    // ---------------------------------------------------------------------------

    // Build a map: data_chunk_index -> decompressed data.
    // Use S=0 for expected_size so decompress skips the size check for
    // partial blocks (the last chunk may not fill S bytes when trimmed).
    std::unordered_map<uint32_t, std::vector<uint8_t>> decompressed;
    for (const auto& c : working_set) {
        if (c.header.chunk_index >= hdr.n) continue;  // skip recovery chunks
        auto dec = decompress(c.payload, algo, 0);
        if (!dec) continue;  // skip undecompressible chunks
        decompressed[c.header.chunk_index] = std::move(*dec);
    }

    // Need chunk 0 to determine manifest_size.
    if (!decompressed.count(0)) {
        return std::unexpected(SfcError{
            ErrorCode::InsufficientChunks,
            "chunk 0 not available; cannot read manifest_size"
        });
    }

    // manifest_size = 8 + B + 32, read from the first 8 bytes of chunk 0.
    auto ms_res = manifest_size_from_chunk0(decompressed.at(0));
    if (!ms_res) return std::unexpected(ms_res.error());
    const uint64_t manifest_sz = *ms_res;

    // K = ceil(manifest_size / S) - number of chunks that hold the manifest.
    const uint64_t K = (manifest_sz + hdr.s - 1) / hdr.s;

    // Ensure all K manifest chunks are available.
    for (uint64_t k = 0; k < K; ++k) {
        if (!decompressed.count(static_cast<uint32_t>(k))) {
            return std::unexpected(SfcError{
                ErrorCode::InsufficientChunks,
                std::format("manifest chunk {} not available (K={})", k, K)
            });
        }
    }

    // Reconstruct manifest bytes from chunks 0..K-1.
    std::vector<uint8_t> manifest_bytes;
    manifest_bytes.reserve(static_cast<size_t>(K) * hdr.s);
    for (uint64_t k = 0; k < K; ++k) {
        const auto& d = decompressed.at(static_cast<uint32_t>(k));
        manifest_bytes.insert(manifest_bytes.end(), d.begin(), d.end());
    }
    manifest_bytes.resize(static_cast<size_t>(manifest_sz));  // trim

    auto mfst_res = parse_manifest(manifest_bytes);
    if (!mfst_res) return std::unexpected(mfst_res.error());
    const Manifest& mfst = *mfst_res;

    // ---------------------------------------------------------------------------
    // Validate byte_offset consistency (Section 16.8 Case B, same as Section 16.7 step 2f).
    // Also validate L >= 1 (Section 16.7 step 2f, Section 18.3).
    // A malicious manifest could use crafted byte_offset values to cause
    // out-of-bounds reads when slicing concatenated chunk data.
    // ---------------------------------------------------------------------------
    for (size_t i = 0; i < mfst.entries.size(); ++i) {
        if (mfst.entries[i].path.empty()) {
            return std::unexpected(SfcError{
                ErrorCode::EmptyInnerFilename,
                std::format("manifest entry {}: path length L=0", i)
            });
        }
    }
    {
        uint64_t expected_offset = manifest_sz;
        for (size_t i = 0; i < mfst.entries.size(); ++i) {
            const auto& e = mfst.entries[i];
            if (e.byte_offset != expected_offset) {
                return std::unexpected(SfcError{
                    ErrorCode::ManifestOffsetSizeInconsistency,
                    std::format("partial entry {}: byte_offset {} != expected {}",
                                i, e.byte_offset, expected_offset)
                });
            }
            if (e.byte_offset + e.file_size > hdr.inner_file_size) {
                return std::unexpected(SfcError{
                    ErrorCode::ManifestOffsetSizeInconsistency,
                    std::format("partial entry {}: byte_offset+file_size {} exceeds Inner File Size {}",
                                i, e.byte_offset + e.file_size, hdr.inner_file_size)
                });
            }
            expected_offset += e.file_size;
        }
    }

    // ---------------------------------------------------------------------------
    // For each file in the manifest: determine covering chunks and extract
    // if all covering chunks are available.
    // ---------------------------------------------------------------------------
    DirectoryExtractResult result;

    for (const auto& entry : mfst.entries) {
        // Empty file: always extractable (no chunk data needed).
        if (entry.file_size == 0) {
            auto hash_res = blake3_verify(
                std::span<const uint8_t>{},
                entry.file_hash);
            if (!hash_res) {
                return std::unexpected(SfcError{
                    ErrorCode::PerFileBlake3Mismatch,
                    std::format("empty file BLAKE3 mismatch: \"{}\"", entry.path)
                });
            }
            result.files.push_back({entry.path, {}, entry.inner_format_id});
            continue;
        }

        // Determine which chunk indices cover this file.
        const uint32_t first_chunk =
            static_cast<uint32_t>(entry.byte_offset / hdr.s);
        const uint32_t last_chunk  =
            static_cast<uint32_t>((entry.byte_offset + entry.file_size - 1) / hdr.s);

        // Guard against out-of-range offsets (should not happen with a valid manifest).
        if (last_chunk >= hdr.n) {
            result.pending_paths.push_back(entry.path);
            continue;
        }

        // Check all covering chunks are available.
        bool all_available = true;
        for (uint32_t ci = first_chunk; ci <= last_chunk; ++ci) {
            if (!decompressed.count(ci)) {
                all_available = false;
                break;
            }
        }

        if (!all_available) {
            result.pending_paths.push_back(entry.path);
            continue;
        }

        // Concatenate decompressed data for chunks [first_chunk..last_chunk].
        std::vector<uint8_t> concat;
        concat.reserve(static_cast<size_t>(last_chunk - first_chunk + 1) * hdr.s);
        for (uint32_t ci = first_chunk; ci <= last_chunk; ++ci) {
            const auto& d = decompressed.at(ci);
            concat.insert(concat.end(), d.begin(), d.end());
        }

        // Slice to the file's byte range within the concatenated data.
        const size_t start_in_concat =
            static_cast<size_t>(entry.byte_offset - static_cast<uint64_t>(first_chunk) * hdr.s);
        const size_t end_in_concat = start_in_concat + static_cast<size_t>(entry.file_size);

        if (end_in_concat > concat.size()) {
            // Decompressed data too short - skip (shouldn't happen).
            result.pending_paths.push_back(entry.path);
            continue;
        }

        std::vector<uint8_t> file_content(
            concat.begin() + static_cast<std::ptrdiff_t>(start_in_concat),
            concat.begin() + static_cast<std::ptrdiff_t>(end_in_concat));

        // Verify per-file BLAKE3.
        auto hash_res = blake3_verify(file_content, entry.file_hash);
        if (!hash_res) {
            return std::unexpected(SfcError{
                ErrorCode::PerFileBlake3Mismatch,
                std::format("per-file BLAKE3 mismatch: \"{}\"", entry.path)
            });
        }

        result.files.push_back({
            entry.path,
            std::move(file_content),
            entry.inner_format_id
        });
    }

    return result;
}

}  // namespace sfc
