#pragma once

/// @file validation.h
/// @brief Pure validation pipeline D1–D5 per SFC §9.4 dependency groups.
///
/// All functions are pure (no I/O, no side effects).

#include "sfc/blake3_hash.h"
#include "sfc/chunk.h"
#include "sfc/error.h"
#include "sfc/global_header.h"
#include "sfc/trailer.h"

#include <span>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// D1 — Preamble validation
// ---------------------------------------------------------------------------

/// @brief D1: Verify the 8-byte file preamble (magic + version).
///
/// Checks "SFC\0" magic (D1a) and major version (D1b).
///
/// @param preamble Exactly 8 bytes from the start of the file.
/// @return VoidResult: success, or InvalidMagic / UnsupportedMajorVersion.
[[nodiscard]] VoidResult validate_preamble(std::span<const uint8_t, 8> preamble);

// ---------------------------------------------------------------------------
// D2 — Global Header + Trailer hash
// ---------------------------------------------------------------------------

/// @brief D2c: Verify the Trailer BLAKE3 hash covers the Global Header Region.
///
/// The Trailer's stored hash must equal BLAKE3(global_header_region_bytes).
///
/// @param trailer            Parsed Trailer.
/// @param header_region_bytes Raw bytes of the Global Header Region (H+4 bytes).
/// @return VoidResult: success, or TrailerBlake3Mismatch.
[[nodiscard]] VoidResult validate_trailer_hash(
    const Trailer& trailer,
    std::span<const uint8_t> header_region_bytes);

// ---------------------------------------------------------------------------
// D3 — Per-chunk phase 1: Provisional validation
// ---------------------------------------------------------------------------

/// @brief D3d: Verify the per-chunk BLAKE3 hash (header || payload).
///
/// @param chunk ParsedChunk containing header, payload, and stored hash.
/// @return VoidResult: success, or ChunkBlake3Failure.
[[nodiscard]] VoidResult validate_chunk_hash(const ParsedChunk& chunk);

/// @brief D3c: Verify compressed payload length ≤ 2*S (§17.3).
///
/// @param chunk  ParsedChunk.
/// @param s      Nominal chunk size from Global Header.
/// @return VoidResult: success, or CompressedPayloadExceeds2S.
[[nodiscard]] VoidResult validate_chunk_payload_length(const ParsedChunk& chunk,
                                                        uint32_t s);

// ---------------------------------------------------------------------------
// D4 — Per-chunk phase 2: Working set promotion
// ---------------------------------------------------------------------------

/// @brief D4a: Verify chunk File UUID matches the Global Header UUID.
///
/// @param chunk ParsedChunk.
/// @param hdr   Parsed Global Header.
/// @return VoidResult: success, or FileUuidMismatch.
[[nodiscard]] VoidResult validate_chunk_uuid(const ParsedChunk& chunk,
                                              const GlobalHeader& hdr);

/// @brief D4b: Verify chunk index is within [0, N+M-1].
///
/// @param chunk ParsedChunk.
/// @param hdr   Parsed Global Header.
/// @return VoidResult: success, or ChunkIndexOutOfRange.
[[nodiscard]] VoidResult validate_chunk_index(const ParsedChunk& chunk,
                                               const GlobalHeader& hdr);

/// @brief D4d: Verify chunk algorithm IDs match the Global Header after normalisation.
///
/// Per §5.1: compression 0x02 normalises to 0x01 for this comparison.
///
/// @param chunk ParsedChunk.
/// @param hdr   Parsed Global Header.
/// @return VoidResult: success, or ChunkAlgoMismatch.
[[nodiscard]] VoidResult validate_chunk_algo(const ParsedChunk& chunk,
                                              const GlobalHeader& hdr);

// ---------------------------------------------------------------------------
// D5 — Reconstruction validation
// ---------------------------------------------------------------------------

/// @brief D5f: Verify the reconstructed inner content against the global hash.
///
/// @param content Reassembled and trimmed inner content bytes.
/// @param hdr     Parsed Global Header containing the expected hash.
/// @return VoidResult: success, or GlobalFileHashMismatch.
[[nodiscard]] VoidResult validate_global_content_hash(
    std::span<const uint8_t> content,
    const GlobalHeader& hdr);

}  // namespace sfc
