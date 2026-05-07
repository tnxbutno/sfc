/// @file gf_arithmetic.cpp
/// @brief GF(2^16) arithmetic implementation over polynomial 0x1002D.
///
/// All tables are computed once at program startup and stored as const globals.
/// Hot-path functions (gf_mul, gf_inv) do a single table lookup each - O(1).

#include "sfc/gf_arithmetic.h"

#include <cstdint>
#include <cstdlib>

namespace sfc::gf {

// ---------------------------------------------------------------------------
// Table construction
// ---------------------------------------------------------------------------

ExpTable build_exp_table() noexcept {
    ExpTable tbl{};

    // Start with generator element g = 1 (i.e. g^0 = 1).
    uint32_t x = 1;
    for (uint32_t i = 0; i < kGroupOrder; ++i) {
        tbl[i] = static_cast<uint16_t>(x);

        // Multiply x by g=2 in GF(2^16):
        // left-shift by 1 (multiply by 2), then reduce mod kPoly if the
        // degree-16 bit is set.
        x <<= 1;
        if (x & kFieldSize) {          // bit 16 set -> degree exceeds 15
            x ^= kPoly;               // reduce: subtract (XOR) the polynomial
        }
    }

    // Double the table (indices 65535..131069) to allow modular arithmetic
    // like tbl[i + j] without an explicit modulo operation in the hot path.
    for (uint32_t i = 0; i < kGroupOrder; ++i) {
        tbl[i + kGroupOrder] = tbl[i];
    }

    return tbl;
}

LogTable build_log_table(const ExpTable& exp) noexcept {
    LogTable tbl{};

    // log_table[0] is undefined (log of zero has no meaning in a field).
    // Leave tbl[0] = 0; callers must never query it.
    for (uint32_t i = 0; i < kGroupOrder; ++i) {
        // exp[i] = g^i, so log(g^i) = i.
        tbl[exp[i]] = static_cast<uint16_t>(i);
    }

    return tbl;
}

// ---------------------------------------------------------------------------
// Precomputed tables - initialised once before main() via static initialisation.
// ---------------------------------------------------------------------------

const ExpTable kExpTable = build_exp_table();
const LogTable kLogTable = build_log_table(kExpTable);

// Self-test: the spec mandates gf_inv(2) == 0x8016 as a reference value (Section 6.2).
// Computed once at startup; a mismatch means the polynomial or generator is wrong.
namespace {
[[maybe_unused]] const bool kGfTableCheck = [] {
    const uint32_t log_inv = kGroupOrder - static_cast<uint32_t>(kLogTable[2]);
    const uint16_t inv2    = kExpTable[log_inv];
    if (inv2 != 0x8016) {
        // Abort rather than silently produce wrong RS codes.
        std::abort();
    }
    return true;
}();
}  // namespace

// ---------------------------------------------------------------------------
// Field operations
// ---------------------------------------------------------------------------

uint16_t gf_mul(uint16_t a, uint16_t b) noexcept {
    // Multiplying by zero always yields zero.
    if (a == 0 || b == 0) return 0;

    // Use log/exp tables: a*b = g^(log(a) + log(b)).
    // The doubled exp table avoids a modulo: kLogTable values are in [0,65534],
    // so their sum is in [0,131068], safely within kExpTable's bounds.
    uint32_t log_sum = static_cast<uint32_t>(kLogTable[a]) +
                       static_cast<uint32_t>(kLogTable[b]);
    return kExpTable[log_sum];   // equivalent to g^(log_sum mod 65535)
}

uint16_t gf_inv(uint16_t a) noexcept {
    // Inverse of 0 is undefined; return 0 as a sentinel.
    if (a == 0) return 0;

    // a^-1 = g^(kGroupOrder - log(a)), because g^kGroupOrder = 1 in GF(2^16).
    // kGroupOrder - log(a) is always in [1, 65535], so lookup is in-bounds.
    uint32_t log_inv = kGroupOrder - static_cast<uint32_t>(kLogTable[a]);
    return kExpTable[log_inv];
}

}  // namespace sfc::gf
