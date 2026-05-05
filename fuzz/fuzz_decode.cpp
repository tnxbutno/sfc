/// @file fuzz_decode.cpp
/// @brief libFuzzer entry point for sfc::decode().
///
/// The fuzzer feeds arbitrary bytes to decode() and verifies that:
///   - The function never crashes or triggers undefined behaviour.
///   - Every error path is reachable (coverage-guided exploration).
///
/// Build: cmake -DSFC_FUZZ=ON -B build-fuzz && cmake --build build-fuzz
/// Run:   ./build-fuzz/fuzz_decode -max_len=131072 corpus/

#include "sfc/decoder.h"

#include <cstddef>
#include <cstdint>
#include <span>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Feed arbitrary bytes to the full decode pipeline.
    // Any return value is acceptable — we only care that the function
    // does not crash, assert-abort, or trigger a sanitizer violation.
    auto result = sfc::decode(std::span<const uint8_t>{data, size});

    // Suppress unused-variable warning; the result is intentionally discarded.
    (void)result;

    // Return 0 to tell libFuzzer the input was processed (non-crash).
    return 0;
}
