/// @file decoder.cpp
/// @brief SFC decoder — full validation and reassembly pipeline.

#include "sfc/decoder.h"

#include "sfc/blake3_hash.h"
#include "sfc/byte_utils.h"
#include "sfc/chunk.h"
#include "sfc/compression.h"
#include "sfc/global_header.h"
#include "sfc/reassembly.h"
#include "sfc/reed_solomon.h"
#include "sfc/tlv.h"
#include "sfc/trailer.h"
#include "sfc/validation.h"

#include <algorithm>
#include <format>

namespace sfc {

// Extract FileMetadata from TLV fields of a parsed GlobalHeader.
static FileMetadata extract_metadata(const GlobalHeader& hdr) {
    FileMetadata meta;
    auto get = [&](uint16_t tag) -> std::string {
        for (const auto& f : hdr.tlv_fields) {
            if (f.tag == tag)
                return std::string(f.value.begin(), f.value.end());
        }
        return {};
    };
    meta.author      = get(TlvTag::kAuthor);
    meta.description = get(TlvTag::kDescription);
    meta.location    = get(TlvTag::kLocation);
    meta.software    = get(TlvTag::kSoftware);
    meta.comment     = get(TlvTag::kComment);
    return meta;
}

Result<ReassemblyResult> decode(std::span<const uint8_t> file_bytes) {
    // -----------------------------------------------------------------------
    // D1: Preamble (8 bytes)
    // -----------------------------------------------------------------------
    if (file_bytes.size() < 8) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidMagic, "file too small for preamble"
        });
    }
    {
        auto preamble_res = validate_preamble(
            std::span<const uint8_t, 8>{file_bytes.data(), 8});
        if (!preamble_res) return std::unexpected(preamble_res.error());
    }

    // -----------------------------------------------------------------------
    // D2a: Read H field and parse Global Header Region
    // -----------------------------------------------------------------------
    if (file_bytes.size() < 12) {  // 8 preamble + 4 H field
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds, "file too small to read H"
        });
    }

    uint32_t H = read_u32_le(
        std::span<const uint8_t, 4>{file_bytes.data() + 8, 4});

    // Bounds-check H (§18.3): limits apply to the H field value, not the region size.
    // Total region size = H+4; maximum allocatable buffer = 65,540 bytes.
    if (H < limits::kMinHeaderLength || H > limits::kMaxHeaderLength) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            std::format("H={} out of bounds [{},{}]",
                        H, limits::kMinHeaderLength, limits::kMaxHeaderLength)
        });
    }
    if (file_bytes.size() < 8 + static_cast<size_t>(H) + 4) {
        return std::unexpected(SfcError{
            ErrorCode::HeaderLengthOutOfBounds,
            "file truncated before end of Global Header Region"
        });
    }

    // Parse Global Header Region.
    const size_t header_region_size = static_cast<size_t>(H) + 4;
    auto header_region = file_bytes.subspan(8, header_region_size);

    auto hdr_res = parse_global_header(header_region);
    if (!hdr_res) return std::unexpected(hdr_res.error());
    const GlobalHeader& hdr = *hdr_res;

    // D2b: validate header fields.
    auto val_res = validate_global_header(hdr);
    if (!val_res) return std::unexpected(val_res.error());

    // D2b-extra: P2 and P3 flags are mutually exclusive (§13.6).
    const bool has_p2 = (hdr.flags & (1u << static_cast<uint16_t>(FlagBit::P2Split))) != 0;
    const bool has_p3 = (hdr.flags & (1u << static_cast<uint16_t>(FlagBit::P3Http))) != 0;
    if (has_p2 && has_p3) {
        return std::unexpected(SfcError{
            ErrorCode::P2AndP3BothSet, "P2 (SplitTransport) and P3 (Http) flags both set"
        });
    }
    // D2b-extra: SPLIT_TRANSPORT bit (0) set without P2 Profile bit (5) is a format error (§9.4).
    const bool has_split_transport =
        (hdr.flags & (1u << static_cast<uint16_t>(FlagBit::SplitTransport))) != 0;
    if (has_split_transport && !has_p2) {
        return std::unexpected(SfcError{
            ErrorCode::SplitTransportWithoutP2,
            "SPLIT_TRANSPORT bit (0) set without SFC/P2 Profile bit (5)"
        });
    }

    // D2b-extra: unsupported erasure algorithm.
    if (hdr.erasure_algo != static_cast<uint8_t>(ErasureAlgo::None) &&
        hdr.erasure_algo != static_cast<uint8_t>(ErasureAlgo::ReedSolomonGF2_16)) {
        return std::unexpected(SfcError{
            ErrorCode::UnsupportedErasureAlgo,
            std::format("unsupported erasure algorithm 0x{:02X}", hdr.erasure_algo)
        });
    }

    // -----------------------------------------------------------------------
    // D2c: Check for Trailer and verify its hash
    // -----------------------------------------------------------------------
    // The Trailer (64 bytes) is the last 64 bytes of the file.
    bool trailer_verified = false;
    if (file_bytes.size() >= 64) {
        auto maybe_trailer_span = std::span<const uint8_t, 64>{
            file_bytes.data() + file_bytes.size() - 64, 64};
        auto trailer_res = parse_trailer(maybe_trailer_span);
        if (trailer_res) {
            // Trailer parsed; verify its hash against the Global Header Region.
            auto th_res = validate_trailer_hash(*trailer_res, header_region);
            if (th_res) {
                trailer_verified = true;
            } else {
                // Trailer present but hash failed → hard error.
                return std::unexpected(th_res.error());
            }
        }
        // If trailer_res is an error (magic wrong / reserved bytes non-zero),
        // the last 64 bytes are simply the last chunk's trailer — that is fine
        // for non-terminal P2 segments; for simple files we'll detect at the end.
    }

    // -----------------------------------------------------------------------
    // D3 + D4: Parse and validate each chunk
    // -----------------------------------------------------------------------
    // Chunks begin immediately after the Global Header Region.
    // For P2 segments (SPLIT_TRANSPORT set) a 16-byte Segment Header follows
    // the Global Header Region before the first chunk — skip it.
    size_t pos = 8 + header_region_size;
    const bool split_transport =
        (hdr.flags & (1u << static_cast<uint16_t>(FlagBit::SplitTransport))) != 0;
    if (split_transport) {
        if (file_bytes.size() < pos + kSegmentHeaderSize) {
            return std::unexpected(SfcError{
                ErrorCode::MissingOrInvalidSegmentHeader,
                "file truncated before end of Segment Header"
            });
        }
        pos += kSegmentHeaderSize;
    }

    // The file ends either at the Trailer (if present) or at the file end.
    // For a simple (non-P2) file the Trailer is the last 64 bytes.
    const size_t chunks_end = trailer_verified
        ? file_bytes.size() - 64
        : file_bytes.size();

    std::vector<ParsedChunk> provisional;
    std::vector<ParsedChunk> working_set;

    while (pos < chunks_end) {
        // D3: parse one chunk.
        auto chunk_res = parse_chunk(file_bytes.subspan(pos));
        if (!chunk_res) {
            if (chunk_res.error().code == ErrorCode::UnknownChunkType ||
                chunk_res.error().code == ErrorCode::NonZeroChunkReservedBytes ||
                chunk_res.error().code == ErrorCode::ChunkEndMarkerInvalid) {
                // §9.4: chunk-level errors — discard this chunk and continue.
                // Peek payload_len at fixed offset 28 to find the next chunk
                // boundary (48-byte header + payload + 36-byte trailer).
                constexpr size_t kHdrSize = 48;
                constexpr size_t kTrlSize = 36;
                constexpr size_t kPayLenOff = 28;
                auto remaining = file_bytes.subspan(pos);
                if (remaining.size() >= kHdrSize) {
                    uint32_t plen = read_u32_le(
                        std::span<const uint8_t, 4>{remaining.data() + kPayLenOff, 4});
                    size_t skip = kHdrSize + plen + kTrlSize;
                    if (skip <= remaining.size()) {
                        pos += skip;
                        continue;
                    }
                }
                // Can't determine boundary — treat as truncation and halt.
            }
            return std::unexpected(chunk_res.error());
        }
        auto& [chunk, consumed] = *chunk_res;
        pos += consumed;

        // D3d: verify chunk hash.
        auto hash_res = validate_chunk_hash(chunk);
        if (!hash_res) continue;  // discard chunk, continue

        // D3c: payload length ≤ 2*S.
        auto len_res = validate_chunk_payload_length(chunk, hdr.s);
        if (!len_res) continue;   // discard chunk

        // D4a: UUID match.
        auto uuid_res = validate_chunk_uuid(chunk, hdr);
        if (!uuid_res) continue;

        // D4b: index in range.
        auto idx_res = validate_chunk_index(chunk, hdr);
        if (!idx_res) continue;

        // D4c/D4d: algo match.
        auto algo_res = validate_chunk_algo(chunk, hdr);
        if (!algo_res) continue;

        working_set.push_back(std::move(chunk));
    }

    // D5a: handle duplicates.
    auto dd_res = handle_duplicates(std::move(working_set));
    if (!dd_res) return std::unexpected(dd_res.error());
    working_set = std::move(*dd_res);

    // -----------------------------------------------------------------------
    // D5b/D5c: Decompress + RS reconstruct → obtain N data blocks
    // -----------------------------------------------------------------------
    const CompressionAlgo algo = normalize_compression_id(hdr.compression_algo);

    // V = total working-set size; both data and recovery chunks count (§9).
    const uint32_t v = static_cast<uint32_t>(working_set.size());

    if (v >= hdr.n) {
        // We have enough chunks for full reconstruction.

        // Build the list of available chunks for RS.
        // Sort by index for convenience.
        std::sort(working_set.begin(), working_set.end(),
                  [](const ParsedChunk& a, const ParsedChunk& b){
                      return a.header.chunk_index < b.header.chunk_index; });

        // Check if all N data chunks are directly present.
        std::vector<bool> data_present(hdr.n, false);
        for (const auto& c : working_set) {
            if (c.header.chunk_index < hdr.n) {
                data_present[c.header.chunk_index] = true;
            }
        }
        const bool all_data_present = std::all_of(
            data_present.begin(), data_present.end(), [](bool b){ return b; });

        std::vector<std::vector<uint8_t>> data_blocks(hdr.n);

        if (all_data_present && hdr.m == 0) {
            // No RS needed — just decompress N data chunks.
            for (const auto& c : working_set) {
                if (c.header.chunk_index >= hdr.n) continue;
                auto dec = decompress(c.payload, algo, hdr.s);
                if (!dec) return std::unexpected(dec.error());
                data_blocks[c.header.chunk_index] = std::move(*dec);
            }
        } else {
            // Need RS reconstruction.
            // Decompress all available chunks into a candidate pool so we can
            // retry with a different N-subset if the initial matrix is singular
            // (§6.4: discard one recovery chunk and retry).
            std::vector<RsChunk> candidates;
            candidates.reserve(working_set.size());
            for (const auto& c : working_set) {
                auto dec = decompress(c.payload, algo, hdr.s);
                if (!dec) continue;  // skip malformed chunks
                candidates.push_back(RsChunk{c.header.chunk_index, std::move(*dec)});
            }

            if (candidates.size() < hdr.n) {
                return std::unexpected(SfcError{
                    ErrorCode::InsufficientChunks,
                    "not enough decompressible chunks for RS"
                });
            }

            // Try successive N-subsets until one inverts (singular matrix retry).
            // For conforming encoders this loop executes exactly once.
            Result<std::vector<std::vector<uint8_t>>> rs_res = std::unexpected(SfcError{
                ErrorCode::MatrixSingular, "RS reconstruction failure: no valid chunk subset found"
            });
            std::vector<RsChunk> subset(hdr.n);
            for (size_t start = 0; start + hdr.n <= candidates.size(); ++start) {
                std::copy_n(candidates.begin() + static_cast<std::ptrdiff_t>(start),
                            hdr.n, subset.begin());
                rs_res = rs_reconstruct(subset, hdr.n, hdr.m, hdr.s);
                if (rs_res || rs_res.error().code != ErrorCode::MatrixSingular) break;
            }
            if (!rs_res) return std::unexpected(rs_res.error());
            data_blocks = std::move(*rs_res);
        }

        // D5d/D5e/D5f: concatenate, trim, verify.
        auto res = full_reassembly(data_blocks, hdr, trailer_verified);
        if (res) res->metadata = extract_metadata(hdr);
        return res;

    } else {
        // V < N: partial reassembly.
        auto res = partial_reassembly(working_set, hdr);
        if (res) res->metadata = extract_metadata(hdr);
        return res;
    }
}

}  // namespace sfc
