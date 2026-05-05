/// @file test_gf_phase2.cpp
/// @brief Unit tests for Phase 2: GF(2^16) arithmetic, matrix ops, Reed-Solomon.
///
/// Conformance vectors from SFC spec §6.4:
///   gf_inv(2) = 0x8016
///   gf_inv(3) = 0xFFE4
///   Worked example: N=2, M=1, S=4

#include "sfc/gf_arithmetic.h"
#include "sfc/gf_matrix.h"
#include "sfc/reed_solomon.h"

#include <gtest/gtest.h>

using namespace sfc;
using namespace sfc::gf;

// ===========================================================================
// GF(2^16) arithmetic — gf_add
// ===========================================================================

TEST(GfArithmetic, Add_IsXor) {
    // Addition in GF(2^k) is XOR.
    EXPECT_EQ(gf_add(0x0003, 0x0005), 0x0006);
}

TEST(GfArithmetic, Add_Self_IsZero) {
    // x XOR x = 0 for all x.
    EXPECT_EQ(gf_add(0xABCD, 0xABCD), 0);
}

TEST(GfArithmetic, Add_WithZero_IsIdentity) {
    // x XOR 0 = x.
    EXPECT_EQ(gf_add(0x1234, 0), 0x1234);
}

// ===========================================================================
// GF(2^16) arithmetic — gf_mul
// ===========================================================================

TEST(GfArithmetic, Mul_ByZero_IsZero) {
    EXPECT_EQ(gf_mul(0xFFFF, 0), 0);
    EXPECT_EQ(gf_mul(0, 0xFFFF), 0);
}

TEST(GfArithmetic, Mul_ByOne_IsIdentity) {
    // Multiplying by 1 returns the same element.
    EXPECT_EQ(gf_mul(0x1234, 1), 0x1234);
    EXPECT_EQ(gf_mul(1, 0xABCD), 0xABCD);
}

TEST(GfArithmetic, Mul_Commutativity) {
    // GF multiplication is commutative.
    EXPECT_EQ(gf_mul(0x0002, 0x0003), gf_mul(0x0003, 0x0002));
    EXPECT_EQ(gf_mul(0x8016, 0x0042), gf_mul(0x0042, 0x8016));
}

TEST(GfArithmetic, Mul_Associativity) {
    // (a*b)*c == a*(b*c)
    uint16_t a = 0x0007, b = 0x0013, c = 0x00FF;
    EXPECT_EQ(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)));
}

// ===========================================================================
// GF(2^16) arithmetic — gf_inv (spec conformance vectors)
// ===========================================================================

TEST(GfArithmetic, Inv_SpecVector_2) {
    // Spec §6.4: gf_inv(2) MUST equal 0x8016.
    EXPECT_EQ(gf_inv(2), 0x8016);
}

TEST(GfArithmetic, Inv_SpecVector_3) {
    // Spec §6.4: gf_inv(3) MUST equal 0xFFE4.
    EXPECT_EQ(gf_inv(3), 0xFFE4);
}

TEST(GfArithmetic, Inv_RoundTrip) {
    // gf_mul(x, gf_inv(x)) == 1 for all non-zero x.
    for (uint16_t x = 1; x <= 255; ++x) {
        EXPECT_EQ(gf_mul(x, gf_inv(x)), 1u) << "failed for x=" << x;
    }
}

TEST(GfArithmetic, Inv_OfOne_IsOne) {
    EXPECT_EQ(gf_inv(1), 1);
}

TEST(GfArithmetic, Inv_Zero_IsZero) {
    // Undefined mathematically; implementation returns 0 as sentinel.
    EXPECT_EQ(gf_inv(0), 0);
}

// Verify the intermediate values from the spec worked example §6.4:
//   gf_mul(0x8016, 0x0002) = 0x0001  (since gf_inv(2)=0x8016)
TEST(GfArithmetic, Mul_SpecExample_8016x2) {
    EXPECT_EQ(gf_mul(0x8016, 0x0002), 0x0001);
}

// ===========================================================================
// GF(2^16) matrix — construction
// ===========================================================================

TEST(GfMatrix, ZeroMatrix) {
    auto m = make_zero_matrix(3, 4);
    EXPECT_EQ(m.rows, 3u);
    EXPECT_EQ(m.cols, 4u);
    for (auto v : m.data) EXPECT_EQ(v, 0);
}

TEST(GfMatrix, IdentityMatrix) {
    auto I = make_identity(4);
    for (uint32_t r = 0; r < 4; ++r) {
        for (uint32_t c = 0; c < 4; ++c) {
            EXPECT_EQ(mat_get(I, r, c), (r == c) ? 1 : 0);
        }
    }
}

TEST(GfMatrix, MatGet_MatSet_RoundTrip) {
    auto m = make_zero_matrix(2, 2);
    m = mat_set(m, 0, 1, 0x1234);
    EXPECT_EQ(mat_get(m, 0, 1), 0x1234);
    EXPECT_EQ(mat_get(m, 0, 0), 0);   // other elements unchanged
}

// ===========================================================================
// GF(2^16) matrix — multiplication
// ===========================================================================

TEST(GfMatrix, Mul_ByIdentity_IsOriginal) {
    // A * I = A for square matrix A.
    gf::GfMatrix A = make_zero_matrix(3, 3);
    // Fill with some values.
    for (uint32_t r = 0; r < 3; ++r) {
        for (uint32_t c = 0; c < 3; ++c) {
            A = mat_set(A, r, c, static_cast<uint16_t>(r * 3 + c + 1));
        }
    }
    auto I = make_identity(3);
    auto R = mat_mul(A, I);
    for (uint32_t r = 0; r < 3; ++r) {
        for (uint32_t c = 0; c < 3; ++c) {
            EXPECT_EQ(mat_get(R, r, c), mat_get(A, r, c));
        }
    }
}

// ===========================================================================
// GF(2^16) matrix — inversion
// ===========================================================================

TEST(GfMatrix, Inv_ThenMul_IsIdentity) {
    // A * A^-1 should be identity for an invertible matrix.
    // Use the 2×2 matrix from the spec worked example:
    //   A = [[1, 0], [1, 0x8016]]
    gf::GfMatrix A = make_zero_matrix(2, 2);
    A = mat_set(A, 0, 0, 1);
    A = mat_set(A, 0, 1, 0);
    A = mat_set(A, 1, 0, 1);
    A = mat_set(A, 1, 1, 0x8016);

    auto inv_res = mat_inv(A);
    ASSERT_TRUE(inv_res.has_value()) << "matrix should be invertible";

    auto product = mat_mul(A, *inv_res);
    auto I = make_identity(2);
    for (uint32_t r = 0; r < 2; ++r) {
        for (uint32_t c = 0; c < 2; ++c) {
            EXPECT_EQ(mat_get(product, r, c), mat_get(I, r, c))
                << "A * A_inv != I at (" << r << "," << c << ")";
        }
    }
}

TEST(GfMatrix, Inv_SpecExample_Matrix) {
    // Spec §6.4 worked example:
    // A_inv[1] = [2, 2]  (row 1 of the inverted matrix)
    gf::GfMatrix A = make_zero_matrix(2, 2);
    A = mat_set(A, 0, 0, 1);
    A = mat_set(A, 0, 1, 0);
    A = mat_set(A, 1, 0, 1);
    A = mat_set(A, 1, 1, 0x8016);

    auto inv_res = mat_inv(A);
    ASSERT_TRUE(inv_res.has_value());

    // Row 1 of A_inv should be [2, 2] per spec.
    EXPECT_EQ(mat_get(*inv_res, 1, 0), 2);
    EXPECT_EQ(mat_get(*inv_res, 1, 1), 2);
}

TEST(GfMatrix, Inv_SingularMatrix_ReturnsError) {
    // A matrix with two identical rows is singular.
    gf::GfMatrix A = make_zero_matrix(2, 2);
    A = mat_set(A, 0, 0, 1);
    A = mat_set(A, 0, 1, 2);
    A = mat_set(A, 1, 0, 1);  // same as row 0
    A = mat_set(A, 1, 1, 2);

    auto inv_res = mat_inv(A);
    EXPECT_FALSE(inv_res.has_value());
    EXPECT_EQ(inv_res.error().code, ErrorCode::MatrixSingular);
}

// ===========================================================================
// Reed-Solomon — block/word conversion
// ===========================================================================

TEST(ReedSolomon, BlockToWords_LittleEndian) {
    // [0x01, 0x00, 0x02, 0x00] → [0x0001, 0x0002]
    std::vector<uint8_t> block = {0x01, 0x00, 0x02, 0x00};
    auto words = block_to_words(block);
    ASSERT_EQ(words.size(), 2u);
    EXPECT_EQ(words[0], 0x0001u);
    EXPECT_EQ(words[1], 0x0002u);
}

TEST(ReedSolomon, WordsToBlock_LittleEndian) {
    // [0x0001, 0x0002] → [0x01, 0x00, 0x02, 0x00]
    std::vector<uint16_t> words = {0x0001, 0x0002};
    auto block = words_to_block(words);
    ASSERT_EQ(block.size(), 4u);
    EXPECT_EQ(block[0], 0x01);
    EXPECT_EQ(block[1], 0x00);
    EXPECT_EQ(block[2], 0x02);
    EXPECT_EQ(block[3], 0x00);
}

TEST(ReedSolomon, BlockWords_RoundTrip) {
    std::vector<uint8_t> orig = {0x16, 0x80, 0x00, 0x00};
    auto words = block_to_words(orig);
    auto recovered = words_to_block(words);
    EXPECT_EQ(recovered, orig);
}

// ===========================================================================
// Reed-Solomon — Cauchy matrix conformance
// ===========================================================================

TEST(ReedSolomon, CauchyMatrix_SpecExample_N2M1) {
    // Spec §6.4: N=2, M=1
    // C[0][0] = gf_inv(0 XOR (1+0)) = gf_inv(1) = 1
    // C[0][1] = gf_inv(0 XOR (1+1)) = gf_inv(2) = 0x8016
    auto C = build_cauchy_matrix(2, 1);
    EXPECT_EQ(mat_get(C, 0, 0), 1u);
    EXPECT_EQ(mat_get(C, 0, 1), 0x8016u);
}

// ===========================================================================
// Reed-Solomon — encoding (spec §6.4 worked example)
// ===========================================================================

TEST(ReedSolomon, Encode_SpecWorkedExample) {
    // N=2, M=1, S=4
    // B[0] = [0x01,0x00,0x02,0x00], B[1] = [0x03,0x00,0x04,0x00]
    // Expected R[0] bytes: [0x16, 0x80, 0x00, 0x00]
    std::vector<std::vector<uint8_t>> data = {
        {0x01, 0x00, 0x02, 0x00},
        {0x03, 0x00, 0x04, 0x00},
    };

    auto res = rs_encode(data, 1);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->size(), 1u);

    std::vector<uint8_t> expected_r0 = {0x16, 0x80, 0x00, 0x00};
    EXPECT_EQ((*res)[0], expected_r0);
}

// ===========================================================================
// Reed-Solomon — reconstruction (spec §6.4 worked example)
// ===========================================================================

TEST(ReedSolomon, Reconstruct_SpecWorkedExample_LoseChunk1) {
    // Available: chunk 0 (data B[0]) and chunk 2 (recovery R[0]).
    // Missing: data chunk 1 (B[1]).
    // Expected recovery: W[1] = [0x0003, 0x0004]
    // i.e. B[1] = [0x03, 0x00, 0x04, 0x00]
    std::vector<RsChunk> available = {
        RsChunk{0, {0x01, 0x00, 0x02, 0x00}},  // data chunk 0
        RsChunk{2, {0x16, 0x80, 0x00, 0x00}},  // recovery chunk 0 (index N+0=2)
    };

    auto res = rs_reconstruct(available, /*n=*/2, /*m=*/1, /*s=*/4);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->size(), 2u);

    // Data block 0 (was present directly)
    EXPECT_EQ((*res)[0], (std::vector<uint8_t>{0x01, 0x00, 0x02, 0x00}));
    // Data block 1 (reconstructed)
    EXPECT_EQ((*res)[1], (std::vector<uint8_t>{0x03, 0x00, 0x04, 0x00}));
}

// ===========================================================================
// Reed-Solomon — round-trip: encode then lose up to M chunks, reconstruct
// ===========================================================================

TEST(ReedSolomon, RoundTrip_N3M2_LoseAnyTwo) {
    // N=3 data blocks, M=2 recovery blocks, S=8 bytes.
    const uint32_t N = 3, M = 2, S = 8;

    std::vector<std::vector<uint8_t>> data = {
        {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
        {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
        {0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
    };

    auto enc_res = rs_encode(data, M);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;
    auto& recovery = *enc_res;

    // Test losing every possible pair of 2 chunks out of 5 total (N+M=5).
    // For each pair of lost indices, assemble the remaining N=3 chunks
    // and reconstruct.
    for (uint32_t lost_a = 0; lost_a < N + M; ++lost_a) {
        for (uint32_t lost_b = lost_a + 1; lost_b < N + M; ++lost_b) {
            std::vector<RsChunk> available;
            for (uint32_t idx = 0; idx < N + M; ++idx) {
                if (idx == lost_a || idx == lost_b) continue;
                std::vector<uint8_t> chunk_data =
                    (idx < N) ? data[idx] : recovery[idx - N];
                available.push_back(RsChunk{idx, chunk_data});
            }

            auto rec_res = rs_reconstruct(available, N, M, S);
            ASSERT_TRUE(rec_res.has_value())
                << "failed losing chunks " << lost_a << " and " << lost_b
                << ": " << rec_res.error().detail;

            // All N data blocks must match the originals.
            for (uint32_t p = 0; p < N; ++p) {
                EXPECT_EQ((*rec_res)[p], data[p])
                    << "block " << p << " mismatch when losing "
                    << lost_a << "," << lost_b;
            }
        }
    }
}

TEST(ReedSolomon, Encode_M0_ReturnsEmpty) {
    std::vector<std::vector<uint8_t>> data = {{0x01, 0x02}};
    auto res = rs_encode(data, 0);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res->empty());
}

TEST(ReedSolomon, Reconstruct_AllDataPresent_NoRecoveryNeeded) {
    // When all N data chunks are present, reconstruction is a pass-through.
    const uint32_t N = 2, M = 1, S = 4;
    std::vector<RsChunk> available = {
        RsChunk{0, {0x01, 0x00, 0x02, 0x00}},
        RsChunk{1, {0x03, 0x00, 0x04, 0x00}},
    };
    auto res = rs_reconstruct(available, N, M, S);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ((*res)[0], (std::vector<uint8_t>{0x01, 0x00, 0x02, 0x00}));
    EXPECT_EQ((*res)[1], (std::vector<uint8_t>{0x03, 0x00, 0x04, 0x00}));
}

TEST(ReedSolomon, Reconstruct_InsufficientChunks_ReturnsError) {
    // Providing fewer than N chunks should fail.
    std::vector<RsChunk> available = {
        RsChunk{0, {0x01, 0x00, 0x02, 0x00}},
    };
    // N=2 but only 1 chunk provided.
    auto res = rs_reconstruct(available, 2, 1, 4);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InsufficientChunks);
}
