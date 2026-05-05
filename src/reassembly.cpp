/// @file reassembly.cpp
/// @brief Reassembly procedures §9.1, §9.3, and duplicate handling §9.5.

#include "sfc/reassembly.h"
#include "sfc/blake3_hash.h"
#include "sfc/compression.h"
#include "sfc/reed_solomon.h"
#include "sfc/validation.h"

#include <algorithm>
#include <format>
#include <unordered_map>

namespace sfc {

// ===========================================================================
// §9.5 Duplicate handling
// ===========================================================================

Result<std::vector<ParsedChunk>> handle_duplicates(std::vector<ParsedChunk> chunks) {
    // Group chunks by index.
    std::unordered_map<uint32_t, std::vector<size_t>> by_index;
    for (size_t i = 0; i < chunks.size(); ++i) {
        by_index[chunks[i].header.chunk_index].push_back(i);
    }

    std::vector<bool> keep(chunks.size(), true);

    for (auto& [idx, positions] : by_index) {
        if (positions.size() == 1) continue;  // no duplicate

        // Check if all are byte-identical (benign duplicate).
        bool all_same = true;
        for (size_t k = 1; k < positions.size(); ++k) {
            if (chunks[positions[k]].hash != chunks[positions[0]].hash) {
                all_same = false; break;
            }
        }
        if (all_same) {
            // Benign: keep only the first, discard the rest.
            for (size_t k = 1; k < positions.size(); ++k) keep[positions[k]] = false;
            continue;
        }

        // Contaminated duplicate: verify each chunk's hash independently.
        std::vector<size_t> passing;
        for (size_t pos : positions) {
            if (validate_chunk_hash(chunks[pos]).has_value()) {
                passing.push_back(pos);
            }
        }

        if (passing.size() == 1) {
            // B1: exactly one passes — keep it, discard others.
            for (size_t pos : positions) {
                if (pos != passing[0]) keep[pos] = false;
            }
        } else if (passing.size() > 1) {
            // B2: multiple copies pass — contaminated duplicate, halt.
            return std::unexpected(SfcError{
                ErrorCode::ContaminatedDuplicate,
                std::format("chunk index {}: contaminated duplicate (B2: {} copies pass hash)",
                            idx, passing.size())
            });
        } else {
            // B3: none pass — discard all.
            for (size_t pos : positions) keep[pos] = false;
        }
    }

    // Build deduplicated result.
    std::vector<ParsedChunk> result;
    result.reserve(chunks.size());
    for (size_t i = 0; i < chunks.size(); ++i) {
        if (keep[i]) result.push_back(std::move(chunks[i]));
    }
    return result;
}

// ===========================================================================
// §9.1 Full Reassembly
// ===========================================================================

Result<ReassemblyResult> full_reassembly(
    const std::vector<std::vector<uint8_t>>& data_blocks,
    const GlobalHeader& hdr,
    bool trailer_verified)
{
    // Validate: must have exactly N blocks.
    if (data_blocks.size() != hdr.n) {
        return std::unexpected(SfcError{
            ErrorCode::InsufficientChunks,
            std::format("full_reassembly: expected {} blocks, got {}",
                        hdr.n, data_blocks.size())
        });
    }

    // Concatenate all N decompressed data blocks.
    std::vector<uint8_t> content;
    content.reserve(static_cast<size_t>(hdr.n) * hdr.s);
    for (const auto& block : data_blocks) {
        content.insert(content.end(), block.begin(), block.end());
    }

    // Trim to Inner File Size (D5e): last chunk was zero-padded.
    if (content.size() > hdr.inner_file_size) {
        content.resize(static_cast<size_t>(hdr.inner_file_size));
    }

    // D5f: verify global file hash.
    auto hash_res = validate_global_content_hash(content, hdr);
    if (!hash_res) return std::unexpected(hash_res.error());

    const ReassemblyStatus status = trailer_verified
        ? ReassemblyStatus::FullyVerified
        : ReassemblyStatus::ContentVerified;

    return ReassemblyResult{
        .content        = std::move(content),
        .status         = status,
        .missing_chunks = {}
    };
}

// ===========================================================================
// §9.3 Partial Reassembly
// ===========================================================================

Result<ReassemblyResult> partial_reassembly(
    const std::vector<ParsedChunk>& working_set,
    const GlobalHeader& hdr)
{
    // Find the longest contiguous run of data chunks starting from index 0.
    // Build a set of present data-chunk indices.
    std::vector<bool> present(hdr.n, false);
    for (const auto& chunk : working_set) {
        if (chunk.header.chunk_index < hdr.n) {
            present[chunk.header.chunk_index] = true;
        }
    }

    uint32_t run_end = 0;  // exclusive; run covers [0, run_end)
    while (run_end < hdr.n && present[run_end]) ++run_end;

    if (run_end == 0) {
        return std::unexpected(SfcError{
            ErrorCode::InsufficientChunks,
            "partial_reassembly: no data chunks starting from index 0"
        });
    }

    // Sort working set by chunk index for ordered access.
    std::vector<const ParsedChunk*> ordered;
    ordered.reserve(working_set.size());
    for (const auto& c : working_set) ordered.push_back(&c);
    std::sort(ordered.begin(), ordered.end(),
              [](const ParsedChunk* a, const ParsedChunk* b){
                  return a->header.chunk_index < b->header.chunk_index; });

    // Decompress and concatenate chunks [0, run_end).
    std::vector<uint8_t> content;
    content.reserve(static_cast<size_t>(run_end) * hdr.s);

    const CompressionAlgo algo =
        normalize_compression_id(hdr.compression_algo);

    for (uint32_t i = 0; i < run_end; ++i) {
        // Find chunk i in ordered list.
        const ParsedChunk* found = nullptr;
        for (const auto* c : ordered) {
            if (c->header.chunk_index == i) { found = c; break; }
        }
        if (!found) break;  // shouldn't happen given present[] check

        // Decompress payload (expected size = S, but skip size check for partial).
        auto dec_res = decompress(found->payload, algo, 0);
        if (!dec_res) return std::unexpected(dec_res.error());
        content.insert(content.end(), dec_res->begin(), dec_res->end());
    }

    // Trim only if the last data chunk (N-1) is in the run.
    if (run_end == hdr.n && content.size() > hdr.inner_file_size) {
        content.resize(static_cast<size_t>(hdr.inner_file_size));
    }

    // Collect missing chunk indices in [0, N-1].
    std::vector<uint32_t> missing;
    for (uint32_t i = 0; i < hdr.n; ++i) {
        if (!present[i]) missing.push_back(i);
    }

    return ReassemblyResult{
        .content        = std::move(content),
        .status         = ReassemblyStatus::Partial,
        .missing_chunks = std::move(missing)
    };
}

}  // namespace sfc
