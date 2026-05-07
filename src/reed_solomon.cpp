/// @file reed_solomon.cpp
/// @brief Reed-Solomon erasure coding over GF(2^16) - implementation.
///
/// Follows SFC spec Section 6.4 exactly:
///   Generator: Cauchy matrix C[i][j] = gf_inv(i XOR (M+j))
///   Encoding:  R[i][w] = XOR_j ( gf_mul(C[i][j], W[j][w]) )
///   Reconstruction: build system matrix A from available chunks,
///                   invert over GF(2^16), multiply by available word vectors.

#include "sfc/reed_solomon.h"
#include "sfc/byte_utils.h"
#include "sfc/gf_arithmetic.h"

#include <algorithm>
#include <format>
#include <ranges>

namespace sfc {

// ---------------------------------------------------------------------------
// block_to_words / words_to_block
// ---------------------------------------------------------------------------

std::vector<uint16_t> block_to_words(std::span<const uint8_t> block) {
    // Each pair of bytes forms one GF(2^16) word (little-endian).
    const size_t word_count = block.size() / 2;
    std::vector<uint16_t> words(word_count);

    for (size_t w = 0; w < word_count; ++w) {
        // Little-endian: low byte first.
        words[w] = static_cast<uint16_t>(
            static_cast<uint16_t>(block[2 * w]) |
            static_cast<uint16_t>(static_cast<uint16_t>(block[2 * w + 1]) << 8));
    }
    return words;
}

std::vector<uint8_t> words_to_block(std::span<const uint16_t> words) {
    // Each word serialises to two bytes, little-endian.
    std::vector<uint8_t> block(words.size() * 2);

    for (size_t w = 0; w < words.size(); ++w) {
        block[2 * w]     = static_cast<uint8_t>(words[w] & 0xFF);        // low byte
        block[2 * w + 1] = static_cast<uint8_t>((words[w] >> 8) & 0xFF); // high byte
    }
    return block;
}

// ---------------------------------------------------------------------------
// Cauchy matrix
// ---------------------------------------------------------------------------

gf::GfMatrix build_cauchy_matrix(uint32_t n, uint32_t m) {
    // Allocate MxN matrix.
    gf::GfMatrix c = gf::make_zero_matrix(m, n);

    for (uint32_t i = 0; i < m; ++i) {
        for (uint32_t j = 0; j < n; ++j) {
            // Spec Section 6.4: C[i][j] = gf_inv(i XOR (M + j)).
            // Since i < M and (M+j) >= M, the XOR is always non-zero,
            // so gf_inv is always well-defined here.
            uint16_t denom = static_cast<uint16_t>(i ^ (m + j));
            c.data[i * n + j] = gf::gf_inv(denom);
        }
    }
    return c;
}

// ---------------------------------------------------------------------------
// rs_encode
// ---------------------------------------------------------------------------

Result<std::vector<std::vector<uint8_t>>>
rs_encode(const std::vector<std::vector<uint8_t>>& data_blocks, uint32_t m) {
    const uint32_t n = static_cast<uint32_t>(data_blocks.size());

    // Validate: must have at least one data block and at least one recovery block.
    if (n == 0) {
        return std::unexpected(SfcError{ErrorCode::InvalidArgument, "rs_encode: N=0"});
    }
    if (m == 0) {
        // Nothing to encode - return empty vector.
        return std::vector<std::vector<uint8_t>>{};
    }

    // All blocks must be the same even size S.
    const size_t s = data_blocks[0].size();
    if (s == 0 || s % 2 != 0) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument,
            std::format("rs_encode: block size {} is 0 or odd", s)
        });
    }
    for (const auto& blk : data_blocks) {
        if (blk.size() != s) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidArgument,
                "rs_encode: inconsistent block sizes"
            });
        }
    }

    const size_t word_count = s / 2;  // number of GF words per block

    // Convert all N data blocks to word vectors.
    std::vector<std::vector<uint16_t>> data_words(n);
    for (uint32_t j = 0; j < n; ++j) {
        data_words[j] = block_to_words(data_blocks[j]);
    }

    // Build Cauchy matrix C (MxN).
    gf::GfMatrix C = build_cauchy_matrix(n, m);

    // Compute M recovery blocks.
    // R[i][w] = XOR over j: gf_mul(C[i][j], W[j][w])
    std::vector<std::vector<uint8_t>> recovery(m);

    for (uint32_t i = 0; i < m; ++i) {
        std::vector<uint16_t> r_words(word_count, 0);

        for (uint32_t j = 0; j < n; ++j) {
            uint16_t coeff = gf::mat_get(C, i, j);  // C[i][j]

            for (size_t w = 0; w < word_count; ++w) {
                // Accumulate: r_words[w] ^= coeff * W[j][w]
                r_words[w] = gf::gf_add(r_words[w],
                                        gf::gf_mul(coeff, data_words[j][w]));
            }
        }

        // Serialise recovery words back to bytes.
        recovery[i] = words_to_block(r_words);
    }

    return recovery;
}

// ---------------------------------------------------------------------------
// rs_reconstruct
// ---------------------------------------------------------------------------

Result<std::vector<std::vector<uint8_t>>>
rs_reconstruct(const std::vector<RsChunk>& available, uint32_t n, uint32_t m, uint32_t s) {
    // Must have exactly N chunks available.
    if (available.size() != n) {
        return std::unexpected(SfcError{
            ErrorCode::InsufficientChunks,
            std::format("rs_reconstruct: need {} chunks, got {}", n, available.size())
        });
    }
    if (s == 0 || s % 2 != 0) {
        return std::unexpected(SfcError{
            ErrorCode::InvalidArgument,
            std::format("rs_reconstruct: block size {} is 0 or odd", s)
        });
    }

    const size_t word_count = s / 2;

    // Identify which data chunk indices [0,N) are missing.
    // A chunk with index in [0,N) is a data chunk; [N, N+M) is a recovery chunk.
    std::vector<bool> data_present(n, false);
    for (const auto& chunk : available) {
        if (chunk.index < n) {
            data_present[chunk.index] = true;
        }
    }

    // Build the NxN system matrix A per spec Section 6.4:
    //   - For each available position i, if chunk.index = idx:
    //       idx < N  -> identity row (row[j] = 1 if j==idx else 0)
    //       idx >= N -> Cauchy row [gf_inv(k ^ (M+j)) for j in 0..N], k = idx - N
    gf::GfMatrix A = gf::make_zero_matrix(n, n);
    gf::GfMatrix C = build_cauchy_matrix(n, m);  // full Cauchy for recovery rows

    for (uint32_t i = 0; i < n; ++i) {
        const uint32_t idx = available[i].index;

        if (idx < n) {
            // Data chunk: identity row for column idx.
            A.data[i * n + idx] = 1;
        } else {
            // Recovery chunk k = idx - N.
            uint32_t k = idx - n;
            // Copy Cauchy row k into row i of A.
            for (uint32_t j = 0; j < n; ++j) {
                A.data[i * n + j] = gf::mat_get(C, k, j);
            }
        }
    }

    // Invert A over GF(2^16).
    auto inv_result = gf::mat_inv(A);
    if (!inv_result) {
        return std::unexpected(inv_result.error());
    }
    const gf::GfMatrix& A_inv = *inv_result;

    // Convert available blocks to word vectors (rows of the "known" matrix).
    std::vector<std::vector<uint16_t>> avail_words(n);
    for (uint32_t i = 0; i < n; ++i) {
        if (available[i].data.size() != s) {
            return std::unexpected(SfcError{
                ErrorCode::InvalidArgument,
                std::format("rs_reconstruct: chunk {} has size {}, expected {}",
                            available[i].index, available[i].data.size(), s)
            });
        }
        avail_words[i] = block_to_words(available[i].data);
    }

    // Recover all N data blocks.
    // recovered[p][w] = XOR over i: gf_mul(A_inv[p][i], avail_words[i][w])
    std::vector<std::vector<uint8_t>> result(n, std::vector<uint8_t>(s));

    for (uint32_t p = 0; p < n; ++p) {
        std::vector<uint16_t> rec_words(word_count, 0);

        for (uint32_t i = 0; i < n; ++i) {
            uint16_t coeff = gf::mat_get(A_inv, p, i);
            if (coeff == 0) continue;  // skip zero multipliers

            for (size_t w = 0; w < word_count; ++w) {
                rec_words[w] = gf::gf_add(rec_words[w],
                                          gf::gf_mul(coeff, avail_words[i][w]));
            }
        }

        result[p] = words_to_block(rec_words);
    }

    return result;
}

}  // namespace sfc
