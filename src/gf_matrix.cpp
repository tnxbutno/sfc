/// @file gf_matrix.cpp
/// @brief GF(2^16) matrix operations: construction, multiplication, inversion.

#include "sfc/gf_matrix.h"

#include <cassert>
#include <format>
#include <stdexcept>

namespace sfc::gf {

// ---------------------------------------------------------------------------
// Internal helpers (not in the header - implementation-private)
// ---------------------------------------------------------------------------

/// Return a reference to element (r,c) in m (mutable helper for inversion).
static uint16_t& elem(GfMatrix& m, uint32_t r, uint32_t c) noexcept {
    return m.data[r * m.cols + c];
}

// ---------------------------------------------------------------------------
// Factory functions
// ---------------------------------------------------------------------------

GfMatrix make_zero_matrix(uint32_t rows, uint32_t cols) {
    // Allocate a vector of rows*cols zero-initialised elements.
    return GfMatrix{rows, cols, std::vector<uint16_t>(rows * cols, 0)};
}

GfMatrix make_identity(uint32_t n) {
    // Start from an all-zero matrix, then set diagonal to 1.
    GfMatrix m = make_zero_matrix(n, n);
    for (uint32_t i = 0; i < n; ++i) {
        m.data[i * n + i] = 1;  // diagonal element = multiplicative identity
    }
    return m;
}

// ---------------------------------------------------------------------------
// Element access
// ---------------------------------------------------------------------------

uint16_t mat_get(const GfMatrix& m, uint32_t r, uint32_t c) noexcept {
    return m.data[r * m.cols + c];
}

GfMatrix mat_set(GfMatrix m, uint32_t r, uint32_t c, uint16_t val) {
    // Accepts the matrix by value (already a copy at the call site).
    m.data[r * m.cols + c] = val;
    return m;
}

// ---------------------------------------------------------------------------
// Matrix multiplication
// ---------------------------------------------------------------------------

GfMatrix mat_mul(const GfMatrix& a, const GfMatrix& b) {
    assert(a.cols == b.rows && "mat_mul: inner dimensions must match");

    // Result is (a.rows x b.cols), initialised to zero.
    GfMatrix result = make_zero_matrix(a.rows, b.cols);

    for (uint32_t r = 0; r < a.rows; ++r) {
        for (uint32_t c = 0; c < b.cols; ++c) {
            // Compute dot product of row r of A with column c of B over GF(2^16).
            uint16_t acc = 0;
            for (uint32_t k = 0; k < a.cols; ++k) {
                // gf_add = XOR, gf_mul uses log/exp tables.
                acc = gf_add(acc, gf_mul(mat_get(a, r, k), mat_get(b, k, c)));
            }
            result.data[r * result.cols + c] = acc;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Matrix inversion - Gauss-Jordan elimination over GF(2^16)
// ---------------------------------------------------------------------------

Result<GfMatrix> mat_inv(const GfMatrix& m) {
    // Only square matrices are invertible.
    if (m.rows != m.cols) {
        return std::unexpected(SfcError{
            ErrorCode::MatrixSingular,
            std::format("mat_inv: non-square matrix {}x{}", m.rows, m.cols)
        });
    }

    const uint32_t n = m.rows;

    // Build augmented matrix [m | I] of size n x 2n.
    // We will transform it to [I | m^-1] via row operations.
    GfMatrix aug = make_zero_matrix(n, 2 * n);

    // Copy m into the left half of aug.
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            elem(aug, r, c) = mat_get(m, r, c);
        }
    }

    // Copy identity into the right half of aug.
    for (uint32_t r = 0; r < n; ++r) {
        elem(aug, r, n + r) = 1;
    }

    // Forward elimination: for each pivot column, find a non-zero row and
    // reduce all other rows to zero in that column.
    for (uint32_t col = 0; col < n; ++col) {
        // --- Find pivot row: first row >= col with a non-zero element in this column ---
        uint32_t pivot_row = n;  // sentinel: "not found"
        for (uint32_t r = col; r < n; ++r) {
            if (elem(aug, r, col) != 0) {
                pivot_row = r;
                break;
            }
        }

        if (pivot_row == n) {
            // No non-zero pivot -> matrix is singular.
            return std::unexpected(SfcError{
                ErrorCode::MatrixSingular,
                std::format("mat_inv: singular matrix, zero pivot at col {}", col)
            });
        }

        // --- Swap pivot row into position ---
        if (pivot_row != col) {
            for (uint32_t c = 0; c < 2 * n; ++c) {
                std::swap(elem(aug, col, c), elem(aug, pivot_row, c));
            }
        }

        // --- Scale pivot row so that the diagonal element becomes 1 ---
        uint16_t pivot_val = elem(aug, col, col);
        uint16_t inv_pivot = gf_inv(pivot_val);  // multiply row by 1/pivot_val

        for (uint32_t c = 0; c < 2 * n; ++c) {
            elem(aug, col, c) = gf_mul(elem(aug, col, c), inv_pivot);
        }

        // --- Eliminate column `col` in all other rows ---
        for (uint32_t r = 0; r < n; ++r) {
            if (r == col) continue;        // skip the pivot row itself
            uint16_t factor = elem(aug, r, col);
            if (factor == 0) continue;     // already zero, nothing to do

            // Row r = Row r - factor * pivot_row  (GF subtract = XOR)
            for (uint32_t c = 0; c < 2 * n; ++c) {
                elem(aug, r, c) = gf_add(elem(aug, r, c),
                                         gf_mul(factor, elem(aug, col, c)));
            }
        }
    }

    // Extract the right half of the augmented matrix: that is m^-1.
    GfMatrix inv = make_zero_matrix(n, n);
    for (uint32_t r = 0; r < n; ++r) {
        for (uint32_t c = 0; c < n; ++c) {
            elem(inv, r, c) = elem(aug, r, n + c);
        }
    }

    return inv;
}

}  // namespace sfc::gf
