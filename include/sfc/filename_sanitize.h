#pragma once

/// @file filename_sanitize.h
/// @brief Pure filename sanitization per SFC Section 4.8.
///
/// All functions are pure (no side effects, no I/O).
///
/// Mandatory two-pass sanitization (Section 4.8):
///   Pass 1: replace each maximal run of forbidden bytes with '_'
///           Forbidden: 0x00-0x1F (control), 0x2F ('/'), 0x5C ('\')
///   Pass 2: replace each maximal invalid-UTF-8 subsequence with '_'
///           (W3C "replacement of maximal subparts" algorithm)

#include "sfc/error.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace sfc {

// ---------------------------------------------------------------------------
// Individual sanitization passes (exposed for testability)
// ---------------------------------------------------------------------------

/// @brief Pass 1: replace forbidden bytes (Section 4.8 byte-level sanitization).
///
/// Each maximal contiguous run of forbidden bytes (0x00-0x1F, '/', '\')
/// is replaced by a single '_' (0x5F).
///
/// @param input Raw bytes of the filename field.
/// @return Bytes with forbidden sequences collapsed to '_'.
[[nodiscard]] std::vector<uint8_t>
replace_forbidden_bytes(std::span<const uint8_t> input) noexcept;

/// @brief Pass 2: replace invalid UTF-8 subsequences with '_'.
///
/// Uses the W3C Encoding Standard "replacement of maximal subparts"
/// algorithm.  Each maximal invalid-UTF-8 byte subsequence is replaced
/// by exactly one '_' (0x5F), NOT by U+FFFD.
///
/// @param input Bytes that have already passed forbidden-byte replacement.
/// @return Valid UTF-8 bytes with invalid subsequences collapsed to '_'.
[[nodiscard]] std::vector<uint8_t>
replace_invalid_utf8(std::span<const uint8_t> input) noexcept;

// ---------------------------------------------------------------------------
// Full sanitization entry-point
// ---------------------------------------------------------------------------

/// @brief Apply full Section 4.8 sanitization to an inner filename field.
///
/// Steps:
///   1. Read bytes up to the first null (0x00).
///   2. Verify all bytes after the null are zero; error if not (Section 4.8 rule).
///   3. Apply replace_forbidden_bytes (Pass 1).
///   4. Apply replace_invalid_utf8 (Pass 2).
///   5. Reject if result is empty (Section 4.8 rule b: "empty inner filename").
///   6. Reject if result equals "." or ".." (Section 4.8 encoder MUST NOT rules).
///
/// @param raw_field 255-byte filename field from the Global Header.
/// @return Result<string>: sanitized filename on success, SfcError on failure.
[[nodiscard]] Result<std::string>
sanitize_filename(std::span<const uint8_t, 255> raw_field);

// ---------------------------------------------------------------------------
// Unicode Simple Case Folding (for path collision detection)
// ---------------------------------------------------------------------------

/// @brief Apply Unicode 15.1.0 Simple Case Folding ("C"+"S" mappings) to a
///        UTF-8 string.
///
/// Used to detect case collisions in Manifest paths (Section 16.3).
/// Implementation covers the full BMP via hardcoded folding table entries,
/// with ASCII optimised as a fast path.
///
/// @param utf8 A valid UTF-8 string.
/// @return Case-folded UTF-8 string.
[[nodiscard]] std::string case_fold(const std::string& utf8) noexcept;

// ---------------------------------------------------------------------------
// Collision detection
// ---------------------------------------------------------------------------

/// @brief Test whether two UTF-8 paths collide under Unicode Simple Case Folding.
///
/// Two paths collide if case_fold(a) == case_fold(b).
///
/// @param a First path (UTF-8).
/// @param b Second path (UTF-8).
/// @return true if the paths are case-fold-identical.
[[nodiscard]] bool paths_collide(const std::string& a,
                                 const std::string& b) noexcept;

}  // namespace sfc
