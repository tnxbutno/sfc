#pragma once

/// @file gf_matrix.h
/// @brief Pure GF(2^16) matrix operations for Reed-Solomon erasure coding.
///
/// GfMatrix is a dense matrix over GF(2^16) stored in row-major order.
/// All operations are pure (return new matrices, no mutation of inputs).
/// Used by Reed-Solomon to build and invert the recovery system matrix.

#include "sfc/error.h"
#include "sfc/gf_arithmetic.h"

#include <cstdint>
#include <vector>

namespace sfc::gf {

// ---------------------------------------------------------------------------
// GfMatrix - dense matrix over GF(2^16)
// ---------------------------------------------------------------------------

/// Dense matrix of GF(2^16) elements stored in row-major order.
/// Element at row r, column c is data[r * cols + c].
struct GfMatrix {
    uint32_t             rows;  ///< Number of rows.
    uint32_t             cols;  ///< Number of columns.
    std::vector<uint16_t> data; ///< Row-major element storage (rows * cols entries).
};

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

/// @brief Create a matrix filled with zeros.
/// @param rows Number of rows.
/// @param cols Number of columns.
/// @return Zero matrix of the given dimensions.
[[nodiscard]] GfMatrix make_zero_matrix(uint32_t rows, uint32_t cols);

/// @brief Create an nxn identity matrix over GF(2^16).
/// @param n Dimension.
/// @return Identity matrix where diag = 1, off-diag = 0.
[[nodiscard]] GfMatrix make_identity(uint32_t n);

// ---------------------------------------------------------------------------
// Element access helpers (pure, no mutation)
// ---------------------------------------------------------------------------

/// @brief Read a single element from a matrix.
/// @param m The matrix.
/// @param r Row index (0-based).
/// @param c Column index (0-based).
/// @return The GF element at (r, c).
[[nodiscard]] uint16_t mat_get(const GfMatrix& m, uint32_t r, uint32_t c) noexcept;

/// @brief Write a single element; returns a new matrix with that element changed.
/// @param m    Source matrix.
/// @param r    Row index.
/// @param c    Column index.
/// @param val  New GF element value.
/// @return Copy of m with m[r][c] = val.
[[nodiscard]] GfMatrix mat_set(GfMatrix m, uint32_t r, uint32_t c, uint16_t val);

// ---------------------------------------------------------------------------
// Algebraic operations
// ---------------------------------------------------------------------------

/// @brief Multiply two matrices over GF(2^16).
/// @param a Left matrix  (a.rows x a.cols).
/// @param b Right matrix (b.rows x b.cols). a.cols must equal b.rows.
/// @return Product matrix (a.rows x b.cols).
[[nodiscard]] GfMatrix mat_mul(const GfMatrix& a, const GfMatrix& b);

/// @brief Invert a square matrix over GF(2^16) using Gauss-Jordan elimination.
/// @param m Square matrix to invert.
/// @return Result<GfMatrix>: the inverse on success,
///         or ErrorCode::MatrixSingular if the matrix is not invertible.
[[nodiscard]] Result<GfMatrix> mat_inv(const GfMatrix& m);

}  // namespace sfc::gf
