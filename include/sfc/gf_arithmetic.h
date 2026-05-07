#pragma once

/// @file gf_arithmetic.h
/// @brief Pure GF(2^16) arithmetic over field polynomial 0x1002D.
///
/// Implements the Galois Field GF(2^16) as required by SFC Section 6.4.
/// Field polynomial: x^16 + x^5 + x^3 + x^2 + 1  (0x1002D).
/// All functions are pure (no side effects) and operate on uint16_t elements.
///
/// Reference values (spec Section 6.4):
///   gf_inv(2) == 0x8016
///   gf_inv(3) == 0xFFE4

#include <array>
#include <cstdint>

namespace sfc::gf {

// ---------------------------------------------------------------------------
// Field constant
// ---------------------------------------------------------------------------

/// Primitive polynomial for GF(2^16): x^16 + x^5 + x^3 + x^2 + 1.
/// Low 16 bits encode non-leading terms: bit5|bit3|bit2|bit0 = 0x002D.
inline constexpr uint32_t kPoly = 0x1002D;

/// Field order: 2^16 = 65536, so there are 65535 non-zero elements.
inline constexpr uint32_t kFieldSize = 65536;

/// Number of non-zero elements (= order of the multiplicative group).
inline constexpr uint32_t kGroupOrder = 65535;

// ---------------------------------------------------------------------------
// Table types
// ---------------------------------------------------------------------------

/// exp_table[i] = g^i in GF(2^16), generator g=2.
/// Size 2*65535 so log/exp arithmetic never needs a modulo branch.
using ExpTable = std::array<uint16_t, 2 * kGroupOrder>;

/// log_table[x] = discrete log base g of x (log_table[0] unused).
using LogTable = std::array<uint16_t, kFieldSize>;

// ---------------------------------------------------------------------------
// Externally defined precomputed tables (initialised in gf_arithmetic.cpp)
// ---------------------------------------------------------------------------

extern const ExpTable kExpTable;
extern const LogTable kLogTable;

// ---------------------------------------------------------------------------
// Pure field operations
// ---------------------------------------------------------------------------

/// @brief GF(2^16) addition (XOR, since characteristic 2).
/// @param a First field element.
/// @param b Second field element.
/// @return a XOR b.
[[nodiscard]] constexpr uint16_t gf_add(uint16_t a, uint16_t b) noexcept {
    // In GF(2^k) addition equals bitwise XOR - no carry propagates.
    return static_cast<uint16_t>(a ^ b);
}

/// @brief GF(2^16) multiplication via precomputed log/exp tables.
/// @param a First field element.
/// @param b Second field element.
/// @return a * b in GF(2^16). Returns 0 if either operand is 0.
[[nodiscard]] uint16_t gf_mul(uint16_t a, uint16_t b) noexcept;

/// @brief GF(2^16) multiplicative inverse.
/// @param a Non-zero field element.
/// @return a^-1 such that gf_mul(a, gf_inv(a)) == 1.
///         Returns 0 for input 0 (undefined - caller must ensure a != 0).
[[nodiscard]] uint16_t gf_inv(uint16_t a) noexcept;

// ---------------------------------------------------------------------------
// Table builders (used once at startup to initialise kExpTable / kLogTable)
// ---------------------------------------------------------------------------

/// @brief Build exp table: exp_table[i] = 2^i mod kPoly.
/// @return 131070-entry table, doubled to avoid modulo in hot paths.
[[nodiscard]] ExpTable build_exp_table() noexcept;

/// @brief Build log table as the inverse of exp table.
/// @param exp Fully populated exp table.
/// @return 65536-entry table where log_table[exp_table[i]] = i % kGroupOrder.
[[nodiscard]] LogTable build_log_table(const ExpTable& exp) noexcept;

}  // namespace sfc::gf
