#pragma once

/// @file reed_solomon.h
/// @brief Pure Reed-Solomon erasure coding over GF(2^16) per SFC Section 6.4.
///
/// Implements the systematic Cauchy-matrix Reed-Solomon scheme:
///   - Encoding: given N data blocks of S bytes, produce M recovery blocks.
///   - Reconstruction: given any N of the N+M blocks, recover the missing data.
///
/// All functions are pure (no side effects, no I/O).
/// Block size S MUST be even (each 2-byte pair is one GF(2^16) word).

#include "sfc/error.h"
#include "sfc/gf_matrix.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// Utility: block ↔ word conversion
// ---------------------------------------------------------------------------

/// @brief Convert an S-byte block to S/2 GF(2^16) words (uint16 LE pairs).
/// @param block Byte span of length S (must be even).
/// @return Vector of S/2 words, each read as little-endian uint16.
[[nodiscard]] std::vector<uint16_t> block_to_words(std::span<const uint8_t> block);

/// @brief Convert S/2 GF(2^16) words back to S bytes (uint16 LE pairs).
/// @param words Word vector of length S/2.
/// @return Vector of S bytes.
[[nodiscard]] std::vector<uint8_t> words_to_block(std::span<const uint16_t> words);

// ---------------------------------------------------------------------------
// Cauchy matrix
// ---------------------------------------------------------------------------

/// @brief Build the Cauchy generator matrix C (M×N) over GF(2^16).
///
/// C[i][j] = gf_inv(i XOR (M + j))  for i in [0,M), j in [0,N).
/// This is the ONLY conforming construction per SFC spec §6.4.
///
/// @param n Number of data chunks (columns).
/// @param m Number of recovery chunks (rows).
/// @return M×N Cauchy matrix.
[[nodiscard]] gf::GfMatrix build_cauchy_matrix(uint32_t n, uint32_t m);

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// @brief Encode N data blocks into M recovery blocks using Reed-Solomon.
///
/// Each block must be exactly S bytes (even). The last data block must already
/// be zero-padded to S bytes by the caller (per spec §5.2).
///
/// @param data_blocks Vector of N blocks, each exactly S bytes.
/// @param m           Number of recovery blocks to produce.
/// @return Result holding a vector of M recovery blocks (each S bytes),
///         or an error if arguments are invalid.
[[nodiscard]] Result<std::vector<std::vector<uint8_t>>>
rs_encode(const std::vector<std::vector<uint8_t>>& data_blocks, uint32_t m);

// ---------------------------------------------------------------------------
// Reconstruction
// ---------------------------------------------------------------------------

/// @brief Descriptor of one available chunk for Reed-Solomon reconstruction.
struct RsChunk {
    uint32_t              index; ///< Original chunk index: [0,N) for data, [N,N+M) for recovery.
    std::vector<uint8_t>  data;  ///< Exactly S decompressed bytes.
};

/// @brief Reconstruct all N data blocks from any N available chunks.
///
/// Implements the Gauss-Jordan reconstruction procedure from spec §6.4.
/// Caller must provide exactly N chunks (any mix of data and recovery).
/// Missing data chunk indices are inferred from which [0,N) indices are absent.
///
/// @param available N available chunks (each S bytes, indices in [0, N+M)).
/// @param n         Total number of data chunks.
/// @param m         Total number of recovery chunks.
/// @param s         Nominal chunk size in bytes (must be even).
/// @return Result holding vector of N data blocks (each S bytes),
///         or an error if reconstruction is impossible.
[[nodiscard]] Result<std::vector<std::vector<uint8_t>>>
rs_reconstruct(const std::vector<RsChunk>& available, uint32_t n, uint32_t m, uint32_t s);

}  // namespace sfc
