/// @file compression.cpp
/// @brief Compression/decompression dispatch for SFC algorithm IDs.
///
/// Each algorithm is handled by its own small function.
/// All are stateless: no streaming state is reused between calls
/// (per Section 7.3: per-chunk independence requirement).

#include "sfc/compression.h"

// zstd — MUST support (0x01 / 0x02)
#include <zstd.h>

// brotli — SHOULD support (0x03)
#include <brotli/decode.h>
#include <brotli/encode.h>

// lz4 — SHOULD support (0x04, LZ4 Frame format)
#include <lz4frame.h>

#include <format>
#include <vector>

namespace sfc {

// ===========================================================================
// Internal per-algorithm helpers
// ===========================================================================

// ---------------------------------------------------------------------------
// Identity (0x00)
// ---------------------------------------------------------------------------

/// Copy bytes unchanged — no compression.
static Result<std::vector<uint8_t>> identity_compress(std::span<const uint8_t> data) {
    return std::vector<uint8_t>(data.begin(), data.end());
}

static Result<std::vector<uint8_t>> identity_decompress(std::span<const uint8_t> data,
                                                         size_t expected_size) {
    // Size check: if caller specifies expected_size, verify the identity payload matches.
    if (expected_size != 0 && data.size() != expected_size) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressedSizeMismatch,
            std::format("identity decompress: got {} bytes, expected {}", data.size(), expected_size)
        });
    }
    return std::vector<uint8_t>(data.begin(), data.end());
}

// ---------------------------------------------------------------------------
// zstd (0x01 / 0x02)
// ---------------------------------------------------------------------------

static Result<std::vector<uint8_t>> zstd_compress(std::span<const uint8_t> data) {
    // Allocate output buffer sized to the maximum zstd compressed size.
    const size_t bound = ZSTD_compressBound(data.size());
    std::vector<uint8_t> out(bound);

    // Compress at default level (3). Encoder is free to choose any level; the
    // decompressor is agnostic to level (all levels produce the same frame format).
    const size_t written = ZSTD_compress(
        out.data(), out.size(),
        data.data(), data.size(),
        ZSTD_defaultCLevel()
    );

    if (ZSTD_isError(written)) {
        return std::unexpected(SfcError{
            ErrorCode::CompressionFailed,
            std::format("zstd compress: {}", ZSTD_getErrorName(written))
        });
    }

    out.resize(written);  // trim to actual compressed size
    return out;
}

static Result<std::vector<uint8_t>> zstd_decompress(std::span<const uint8_t> data,
                                                      size_t expected_size) {
    // Query the decompressed size embedded in the zstd frame.
    const unsigned long long frame_size =
        ZSTD_getFrameContentSize(data.data(), data.size());

    if (frame_size == ZSTD_CONTENTSIZE_ERROR) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressionFailed,
            "zstd: invalid frame or size not stored"
        });
    }

    // Allocate output; if expected_size is set, verify the frame header matches.
    size_t alloc_size = (frame_size == ZSTD_CONTENTSIZE_UNKNOWN)
                        ? (expected_size != 0 ? expected_size : data.size() * 4)
                        : static_cast<size_t>(frame_size);

    if (expected_size != 0 && frame_size != ZSTD_CONTENTSIZE_UNKNOWN &&
        static_cast<size_t>(frame_size) != expected_size) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressedSizeMismatch,
            std::format("zstd: frame declares {} bytes, expected {}",
                        frame_size, expected_size)
        });
    }

    std::vector<uint8_t> out(alloc_size);
    const size_t written = ZSTD_decompress(
        out.data(), out.size(),
        data.data(), data.size()
    );

    if (ZSTD_isError(written)) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressionFailed,
            std::format("zstd decompress: {}", ZSTD_getErrorName(written))
        });
    }

    out.resize(written);

    // Final size validation against the caller's expected_size.
    if (expected_size != 0 && written != expected_size) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressedSizeMismatch,
            std::format("zstd decompress: produced {} bytes, expected {}",
                        written, expected_size)
        });
    }

    return out;
}

// ---------------------------------------------------------------------------
// Brotli (0x03)
// ---------------------------------------------------------------------------

static Result<std::vector<uint8_t>> brotli_compress_impl(std::span<const uint8_t> data) {
    // Brotli's BrotliEncoderMaxCompressedSize gives the worst-case output size.
    const size_t bound = BrotliEncoderMaxCompressedSize(data.size());
    std::vector<uint8_t> out(bound);
    size_t out_size = bound;

    const BROTLI_BOOL ok = BrotliEncoderCompress(
        BROTLI_DEFAULT_QUALITY,
        BROTLI_DEFAULT_WINDOW,
        BROTLI_DEFAULT_MODE,
        data.size(), data.data(),
        &out_size, out.data()
    );

    if (ok != BROTLI_TRUE) {
        return std::unexpected(SfcError{
            ErrorCode::CompressionFailed,
            "brotli compress failed"
        });
    }

    out.resize(out_size);
    return out;
}

static Result<std::vector<uint8_t>> brotli_decompress(std::span<const uint8_t> data,
                                                        size_t expected_size) {
    // Allocate output; brotli does not store decompressed size in the stream,
    // so we start with expected_size (or 4× input as fallback).
    size_t alloc = (expected_size != 0) ? expected_size : data.size() * 4;
    std::vector<uint8_t> out(alloc);
    size_t out_size = alloc;

    const BrotliDecoderResult res = BrotliDecoderDecompress(
        data.size(), data.data(),
        &out_size, out.data()
    );

    if (res != BROTLI_DECODER_RESULT_SUCCESS) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressionFailed,
            "brotli decompress failed"
        });
    }

    out.resize(out_size);

    if (expected_size != 0 && out_size != expected_size) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressedSizeMismatch,
            std::format("brotli decompress: produced {} bytes, expected {}",
                        out_size, expected_size)
        });
    }

    return out;
}

// ---------------------------------------------------------------------------
// LZ4 Frame (0x04)
// ---------------------------------------------------------------------------

static Result<std::vector<uint8_t>> lz4_compress_impl(std::span<const uint8_t> data) {
    // LZ4 Frame: use LZ4F_compressFrame for a self-contained, independently
    // decompressable frame (meets per-chunk independence requirement §7.3).
    const size_t bound = LZ4F_compressFrameBound(data.size(), nullptr);
    std::vector<uint8_t> out(bound);

    const size_t written = LZ4F_compressFrame(
        out.data(), out.size(),
        data.data(), data.size(),
        nullptr   // default preferences
    );

    if (LZ4F_isError(written)) {
        return std::unexpected(SfcError{
            ErrorCode::CompressionFailed,
            std::format("lz4 compress: {}", LZ4F_getErrorName(written))
        });
    }

    out.resize(written);
    return out;
}

static Result<std::vector<uint8_t>> lz4_decompress(std::span<const uint8_t> data,
                                                     size_t expected_size) {
    // Create a decompression context.
    LZ4F_dctx* dctx = nullptr;
    LZ4F_errorCode_t err = LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);
    if (LZ4F_isError(err)) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressionFailed,
            "lz4: failed to create decompression context"
        });
    }

    // Allocate output buffer.
    size_t alloc = (expected_size != 0) ? expected_size : data.size() * 4;
    std::vector<uint8_t> out(alloc);

    size_t dst_size = alloc;
    size_t src_size = data.size();

    const size_t written = LZ4F_decompress(
        dctx,
        out.data(), &dst_size,
        data.data(), &src_size,
        nullptr   // default options
    );

    LZ4F_freeDecompressionContext(dctx);

    if (LZ4F_isError(written)) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressionFailed,
            std::format("lz4 decompress: {}", LZ4F_getErrorName(written))
        });
    }

    out.resize(dst_size);

    if (expected_size != 0 && dst_size != expected_size) {
        return std::unexpected(SfcError{
            ErrorCode::DecompressedSizeMismatch,
            std::format("lz4 decompress: produced {} bytes, expected {}",
                        dst_size, expected_size)
        });
    }

    return out;
}

// ===========================================================================
// Public API
// ===========================================================================

Result<std::vector<uint8_t>> compress(std::span<const uint8_t> data,
                                       CompressionAlgo algo) {
    // Normalise 0x02 → 0x01 before dispatch.
    const CompressionAlgo normalised =
        normalize_compression_id(static_cast<uint8_t>(algo));

    switch (normalised) {
        case CompressionAlgo::Identity:
            return identity_compress(data);

        case CompressionAlgo::Zstd:
        case CompressionAlgo::ZstdDeprecated:  // after normalise, this is Zstd
            return zstd_compress(data);

        case CompressionAlgo::Brotli:
            return brotli_compress_impl(data);

        case CompressionAlgo::Lz4Frame:
            return lz4_compress_impl(data);

        default:
            return std::unexpected(SfcError{
                ErrorCode::UnsupportedCompressionAlgo,
                std::format("compress: unsupported algorithm 0x{:02X}",
                            static_cast<uint8_t>(algo))
            });
    }
}

Result<std::vector<uint8_t>> decompress(std::span<const uint8_t> data,
                                         CompressionAlgo algo,
                                         size_t expected_size) {
    // Normalise 0x02 → 0x01 before dispatch (spec §7.1).
    const CompressionAlgo normalised =
        normalize_compression_id(static_cast<uint8_t>(algo));

    switch (normalised) {
        case CompressionAlgo::Identity:
            return identity_decompress(data, expected_size);

        case CompressionAlgo::Zstd:
        case CompressionAlgo::ZstdDeprecated:  // after normalise, this is Zstd
            return zstd_decompress(data, expected_size);

        case CompressionAlgo::Brotli:
            return brotli_decompress(data, expected_size);

        case CompressionAlgo::Lz4Frame:
            return lz4_decompress(data, expected_size);

        default:
            return std::unexpected(SfcError{
                ErrorCode::UnsupportedCompressionAlgo,
                std::format("decompress: unsupported algorithm 0x{:02X}",
                            static_cast<uint8_t>(algo))
            });
    }
}

}  // namespace sfc
