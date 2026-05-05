#pragma once

/// @file error.h
/// @brief Error codes, error type, and Result<T> alias for SFC operations.
///
/// Every fallible pure function returns Result<T> = std::expected<T, SfcError>.
/// Error codes cover all conditions from Section 9.4 of the SFC spec.

#include <cstdint>
#include <expected>
#include <string>

namespace sfc {

/// All distinct error conditions from Section 9.4, plus internal errors.
/// Each code MUST be distinguishable in diagnostic output per spec requirement.
enum class ErrorCode : uint32_t {
    // --- File-level errors (decoder MUST halt) ---
    InvalidMagic                    = 1001,
    UnsupportedMajorVersion         = 1002,
    HeaderLengthOutOfBounds         = 1003,
    DuplicateKnownTlvTag            = 1004,
    TlvValueOverrunsHeader          = 1005,
    KnownTlvUnexpectedLength        = 1006,
    ProfileTlvWithoutBit            = 1007,
    NonZeroTrailerReserved4_7       = 1008,
    TrailerBlake3Mismatch           = 1009,
    GlobalHeaderConflict            = 1010,
    UnsupportedCompressionAlgo      = 1011,
    UnsupportedErasureAlgo          = 1012,
    ErasureNoneWithMGreaterZero     = 1013,
    OddChunkSizeS                   = 1014,
    InnerFileSizeZeroWithNNot1      = 1015,
    VersionMismatchAcrossSegments   = 1016,
    MissingOrInvalidSegmentHeader   = 1017,
    SegmentHeaderReservedNonZero    = 1018,
    SegmentIndexGteCount            = 1019,
    DuplicateSegmentIndex           = 1020,
    InconsistentSegmentCount        = 1021,
    InvalidTerminalFlagValue        = 1022,
    ManifestBlake3Failure           = 1023,
    ManifestOffsetSizeInconsistency = 1024,
    MultipleTerminalFlags           = 1025,
    TerminalFlagButTrailerInvalid   = 1026,
    TerminalByTrailerOnlyNoFlag     = 1027,
    MissingGlobalHeader             = 1028,
    FieldBelowMinimum               = 1029,
    FieldAboveMaximum               = 1030,

    // --- Chunk-level errors (decoder SHOULD discard chunk, continue) ---
    ChunkBlake3Failure              = 2001,
    ChunkIndexOutOfRange            = 2002,
    UnknownChunkType                = 2003,
    ChunkAlgoMismatch               = 2004,
    NonZeroChunkReservedBytes       = 2005,
    TruncatedChunk                  = 2006,
    ChunkEndMarkerInvalid           = 2007,
    DecompressedSizeMismatch        = 2008,
    CompressedPayloadExceeds2S      = 2009,
    InsufficientChunks              = 2010,

    // --- Content-level errors ---
    GlobalFileHashMismatch          = 3001,
    FileUuidMismatch                = 3002,
    ContaminatedDuplicate           = 3003,
    EmptyInnerFilename              = 3004,
    NonZeroAfterFilenameNull        = 3005,
    ProfileMustViolation            = 3006,
    P2AndP3BothSet                  = 3007,
    CaseCollisionInManifest         = 3008,
    PerFileBlake3Mismatch           = 3009,
    PriorityCountExceedsN           = 3010,
    DuplicatePriorityIndex          = 3011,
    PriorityIndexOutOfRange         = 3012,

    // --- Warnings (non-fatal) ---
    TerminalSegmentNotFound         = 4001,

    // --- Internal / generic ---
    DecompressionFailed             = 9001,
    CompressionFailed               = 9002,
    MatrixSingular                  = 9003,
    InvalidArgument                 = 9004,
    BufferTooSmall                  = 9005,
};

/// Severity classification per Section 9.4.
enum class ErrorSeverity {
    ChunkLevel,  ///< Discard affected chunk, continue processing.
    FileLevel,   ///< Halt processing.
    Warning,     ///< Non-fatal informational.
};

/// Returns the severity classification for a given error code.
constexpr ErrorSeverity error_severity(ErrorCode code) {
    auto v = static_cast<uint32_t>(code);
    if (v >= 4000 && v < 5000) return ErrorSeverity::Warning;
    if (v >= 2000 && v < 3000) return ErrorSeverity::ChunkLevel;
    return ErrorSeverity::FileLevel;
}

/// Error type carrying a code and a human-readable detail string.
struct SfcError {
    ErrorCode code;
    std::string detail;
};

/// Result type for all fallible SFC operations.
/// On success holds T, on failure holds SfcError.
template <typename T>
using Result = std::expected<T, SfcError>;

/// Convenience alias for operations that return nothing on success.
using VoidResult = Result<void>;

}  // namespace sfc