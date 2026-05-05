#pragma once

/// @file decoder.h
/// @brief Pure SFC decoder — parses a .sfc file and reassembles the content (§9).
///
/// All functions are pure (no I/O).

#include "sfc/error.h"
#include "sfc/reassembly.h"

#include <cstdint>
#include <span>
#include <vector>

namespace sfc {

/// @brief Decode a single SFC file from bytes.
///
/// Performs the full validation and reassembly pipeline:
///   D1: preamble validation
///   D2: global header + trailer hash
///   D3: per-chunk provisional validation (hash, payload length)
///   D4: per-chunk working set promotion (UUID, index, algo)
///   D5: decompression + RS reconstruction + global hash
///
/// Applies duplicate handling (§9.5) before reconstruction.
/// If V >= N and Trailer is verified → full reassembly (§9.1).
/// If V >= N and Trailer absent     → unverified reconstruction (§9.2).
/// If V < N                         → partial reassembly (§9.3).
///
/// @param file_bytes Complete bytes of a .sfc file.
/// @return ReassemblyResult on success, or SfcError on fatal error.
[[nodiscard]] Result<ReassemblyResult>
decode(std::span<const uint8_t> file_bytes);

}  // namespace sfc
