/// @file blake3_hash.cpp
/// @brief BLAKE3 hashing implementation — thin wrapper over the BLAKE3 C API.
///
/// The BLAKE3 C API (blake3.h) is a streaming hasher:
///   blake3_hasher_init()    — initialise state
///   blake3_hasher_update()  — feed bytes (may be called multiple times)
///   blake3_hasher_finalize()— produce digest
///
/// All functions here are pure: same input always produces same output.

#include "sfc/blake3_hash.h"

// BLAKE3 C library header (from the vendored FetchContent dependency).
#include <blake3.h>

#include <algorithm>  // std::equal

namespace sfc {

// ---------------------------------------------------------------------------
// Internal helper: run hasher, return digest
// ---------------------------------------------------------------------------

/// Feed a single span into an already-initialised hasher, then finalise.
static Blake3Digest finalise(blake3_hasher& h) noexcept {
    Blake3Digest digest;
    blake3_hasher_finalize(&h, digest.data(), digest.size());
    return digest;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

Blake3Digest blake3(std::span<const uint8_t> data) noexcept {
    blake3_hasher h;
    blake3_hasher_init(&h);
    // Feed all bytes in one call (BLAKE3 C API accepts size_t length).
    blake3_hasher_update(&h, data.data(), data.size());
    return finalise(h);
}

Blake3Digest blake3_concat(std::span<const uint8_t> a,
                           std::span<const uint8_t> b) noexcept {
    blake3_hasher h;
    blake3_hasher_init(&h);
    // Feed first span, then second — equivalent to hashing their concatenation.
    blake3_hasher_update(&h, a.data(), a.size());
    blake3_hasher_update(&h, b.data(), b.size());
    return finalise(h);
}

VoidResult blake3_verify(std::span<const uint8_t> data,
                         const Blake3Digest& expected) noexcept {
    Blake3Digest actual = blake3(data);

    // Constant-time comparison: std::equal on fixed-size arrays is NOT
    // guaranteed to be constant-time, but BLAKE3 digests are public values
    // used only for integrity (not authentication), so timing side-channels
    // do not weaken the security model here (Section 8.4).
    if (actual != expected) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkBlake3Failure,
            "BLAKE3 digest mismatch"
        });
    }
    return {};
}

VoidResult blake3_verify_concat(std::span<const uint8_t> a,
                                std::span<const uint8_t> b,
                                const Blake3Digest& expected) noexcept {
    Blake3Digest actual = blake3_concat(a, b);

    if (actual != expected) {
        return std::unexpected(SfcError{
            ErrorCode::ChunkBlake3Failure,
            "BLAKE3 digest mismatch (header||payload)"
        });
    }
    return {};
}

}  // namespace sfc
