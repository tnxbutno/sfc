/// @file test_phase8_9.cpp
/// @brief Integration tests for Phase 8 (encoder) and Phase 9 (decoder).
///
/// These tests exercise the full encode → decode round-trip and verify that:
///   - Content is reassembled exactly.
///   - ReassemblyStatus reflects the correct verification level.
///   - Various content sizes and compression algorithms work correctly.
///   - RS recovery (M > 0) reconstructs content when chunks are absent.

#include "sfc/decoder.h"
#include "sfc/encoder.h"
#include "sfc/types.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <numeric>
#include <vector>

using namespace sfc;

// ===========================================================================
// Helpers
// ===========================================================================

/// Generate a deterministic FileUuid from a single seed byte.
static FileUuid make_uuid(uint8_t seed) {
    FileUuid u{};
    for (size_t i = 0; i < 16; ++i) u.bytes[i] = static_cast<uint8_t>(seed + i);
    return u;
}

/// Build default EncodeParams for a simple (no RS) encode.
static EncodeParams make_params(CompressionAlgo algo = CompressionAlgo::Identity,
                                 uint32_t s = 64,
                                 uint32_t m = 0) {
    return EncodeParams{
        .m         = m,
        .s         = s,
        .algo      = algo,
        .uuid      = make_uuid(0x42),
        .timestamp = 0,
        .format_id = 0x0001,
        .filename  = "test.bin",
    };
}

// ===========================================================================
// Phase 8: encode — basic parameter validation
// ===========================================================================

TEST(Encode, OddS_Error) {
    EncodeParams p = make_params();
    p.s = 63;  // not even
    std::vector<uint8_t> content = {0x01};
    auto res = encode(content, p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OddChunkSizeS);
}

TEST(Encode, ZeroS_Error) {
    EncodeParams p = make_params();
    p.s = 0;
    std::vector<uint8_t> content = {0x01};
    auto res = encode(content, p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OddChunkSizeS);
}

TEST(Encode, FilenameTooLong_Error) {
    EncodeParams p = make_params();
    p.filename = std::string(255, 'x');  // 255 bytes > 254 limit
    std::vector<uint8_t> content = {0x01};
    auto res = encode(content, p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(Encode, ProducesNonEmptyBytes) {
    auto p = make_params();
    std::vector<uint8_t> content = {0x01, 0x02};
    auto res = encode(content, p);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    // Minimum: 8 (preamble) + header_region + 1 chunk + 64 (trailer)
    EXPECT_GT(res->size(), 64u);
}

// ===========================================================================
// Phase 8+9: round-trip — identity compression
// ===========================================================================

TEST(EncodeDecode, RoundTrip_Identity_SmallContent) {
    auto p = make_params(CompressionAlgo::Identity, 64);
    std::vector<uint8_t> content = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;

    EXPECT_EQ(dec_res->content, content);
    EXPECT_EQ(dec_res->status, ReassemblyStatus::FullyVerified);
    EXPECT_TRUE(dec_res->missing_chunks.empty());
}

TEST(EncodeDecode, RoundTrip_Identity_EmptyContent) {
    // Empty inner content: N=1 by spec exception (§10.1).
    auto p = make_params(CompressionAlgo::Identity, 64);
    std::vector<uint8_t> content;

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;

    EXPECT_EQ(dec_res->content, content);
    EXPECT_EQ(dec_res->status, ReassemblyStatus::FullyVerified);
}

TEST(EncodeDecode, RoundTrip_Identity_ExactlyS) {
    // Content size == S → one full block, no zero-padding needed.
    const uint32_t s = 64;
    auto p           = make_params(CompressionAlgo::Identity, s);
    std::vector<uint8_t> content(s);
    std::iota(content.begin(), content.end(), 0x00);

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
}

TEST(EncodeDecode, RoundTrip_Identity_MultiChunk) {
    // 150 bytes with S=64 → N=3 chunks (64+64+22 padded to 64).
    const uint32_t s = 64;
    auto p           = make_params(CompressionAlgo::Identity, s);
    std::vector<uint8_t> content(150);
    std::iota(content.begin(), content.end(), 0x00);

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
    EXPECT_EQ(dec_res->status, ReassemblyStatus::FullyVerified);
}

TEST(EncodeDecode, RoundTrip_Identity_SingleByte) {
    auto p = make_params(CompressionAlgo::Identity, 2);  // S=2 (minimum even)
    std::vector<uint8_t> content = {0xFF};

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
}

// ===========================================================================
// Phase 8+9: round-trip — zstd compression
// ===========================================================================

TEST(EncodeDecode, RoundTrip_Zstd_SmallContent) {
    auto p = make_params(CompressionAlgo::Zstd, 64);
    std::vector<uint8_t> content(64, 0xAB);  // highly compressible

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
    EXPECT_EQ(dec_res->status, ReassemblyStatus::FullyVerified);
}

TEST(EncodeDecode, RoundTrip_Zstd_RandomishContent) {
    auto p = make_params(CompressionAlgo::Zstd, 128);
    // Pseudo-random bytes (incompressible, but zstd should handle gracefully).
    std::vector<uint8_t> content(256);
    for (size_t i = 0; i < content.size(); ++i)
        content[i] = static_cast<uint8_t>((i * 17 + 11) & 0xFF);

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
}

// ===========================================================================
// Phase 8+9: round-trip — RS recovery (M > 0)
// ===========================================================================

/// Remove chunks at given 0-based byte-level positions from a raw SFC file.
///
/// The function locates each "CHK\0" magic occurrence starting after the header
/// region and drops the chunk whose parsed index matches the given set.
/// Returns the modified byte vector.
static std::vector<uint8_t> drop_chunks(const std::vector<uint8_t>& sfc_bytes,
                                         const std::vector<uint32_t>& drop_indices) {
    // Parse H field (at offset 8) to find header_region_end.
    if (sfc_bytes.size() < 12) return sfc_bytes;
    uint32_t H = static_cast<uint32_t>(sfc_bytes[8])
               | (static_cast<uint32_t>(sfc_bytes[9]) << 8)
               | (static_cast<uint32_t>(sfc_bytes[10]) << 16)
               | (static_cast<uint32_t>(sfc_bytes[11]) << 24);
    const size_t chunk_start = 8 + static_cast<size_t>(H) + 4;

    // Walk chunks in the chunk region (stop 64 bytes before end = Trailer).
    const size_t chunk_end = sfc_bytes.size() >= 64
                             ? sfc_bytes.size() - 64
                             : sfc_bytes.size();

    std::vector<uint8_t> out;
    out.insert(out.end(), sfc_bytes.begin(), sfc_bytes.begin() + chunk_start);

    size_t pos = chunk_start;
    while (pos + 84 <= chunk_end) {  // 48 hdr + ≥0 payload + 36 trailer = min 84
        // Check magic "CHK\0".
        if (sfc_bytes[pos] != 0x43 || sfc_bytes[pos+1] != 0x48 ||
            sfc_bytes[pos+2] != 0x4B || sfc_bytes[pos+3] != 0x00) break;

        // Read chunk index from bytes [pos+20..pos+23].
        uint32_t idx = static_cast<uint32_t>(sfc_bytes[pos+20])
                     | (static_cast<uint32_t>(sfc_bytes[pos+21]) << 8)
                     | (static_cast<uint32_t>(sfc_bytes[pos+22]) << 16)
                     | (static_cast<uint32_t>(sfc_bytes[pos+23]) << 24);

        // Read compressed payload length from bytes [pos+28..pos+31].
        uint32_t payload_len = static_cast<uint32_t>(sfc_bytes[pos+28])
                             | (static_cast<uint32_t>(sfc_bytes[pos+29]) << 8)
                             | (static_cast<uint32_t>(sfc_bytes[pos+30]) << 16)
                             | (static_cast<uint32_t>(sfc_bytes[pos+31]) << 24);

        const size_t chunk_size = 48 + payload_len + 36;
        if (pos + chunk_size > chunk_end) break;

        // Include or skip the chunk.
        bool drop = std::find(drop_indices.begin(), drop_indices.end(), idx)
                    != drop_indices.end();
        if (!drop) {
            out.insert(out.end(),
                       sfc_bytes.begin() + pos,
                       sfc_bytes.begin() + pos + chunk_size);
        }
        pos += chunk_size;
    }

    // Append the Trailer (last 64 bytes).
    out.insert(out.end(), sfc_bytes.end() - 64, sfc_bytes.end());
    return out;
}

TEST(EncodeDecode, RoundTrip_RS_DropOneDataChunk) {
    // N=2 data chunks, M=1 recovery → can tolerate loss of 1 chunk.
    const uint32_t s = 64;
    EncodeParams p   = make_params(CompressionAlgo::Identity, s, /*m=*/1);
    p.uuid           = make_uuid(0x10);

    std::vector<uint8_t> content(100);
    std::iota(content.begin(), content.end(), 0x00);

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    // Drop data chunk 0 — RS should reconstruct it.
    auto modified = drop_chunks(*enc_res, {0});

    auto dec_res = decode(modified);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
}

TEST(EncodeDecode, RoundTrip_RS_DropRecoveryChunk) {
    // N=2, M=1. Drop the recovery chunk — all data is present so no RS needed.
    const uint32_t s = 64;
    EncodeParams p   = make_params(CompressionAlgo::Identity, s, /*m=*/1);
    p.uuid           = make_uuid(0x20);

    std::vector<uint8_t> content(100);
    std::iota(content.begin(), content.end(), 0x10);

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    // The recovery chunk has index N = 2 (0-based, after data chunks 0 and 1).
    auto modified = drop_chunks(*enc_res, {2});

    auto dec_res = decode(modified);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
}

// ===========================================================================
// Phase 9: decode — error cases
// ===========================================================================

TEST(Decode, TooSmall_Error) {
    std::vector<uint8_t> tiny = {0x01, 0x02, 0x03};
    auto res = decode(tiny);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(Decode, BadMagic_Error) {
    std::vector<uint8_t> bad(64, 0x00);  // 64 zero bytes — wrong magic
    auto res = decode(bad);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(Decode, TruncatedAfterPreamble_Error) {
    // Valid preamble but nothing after it.
    std::vector<uint8_t> buf = {0x53, 0x46, 0x43, 0x00, 0x01, 0x00, 0x08, 0x00};
    auto res = decode(buf);
    ASSERT_FALSE(res.has_value());
    // Too small to read H → HeaderLengthOutOfBounds.
    EXPECT_EQ(res.error().code, ErrorCode::HeaderLengthOutOfBounds);
}

TEST(Decode, AllChunksPresent_ZstdAlgo) {
    // Encode with zstd, then decode — verifies the full zstd path.
    auto p = make_params(CompressionAlgo::Zstd, 64);
    p.uuid = make_uuid(0x30);
    std::vector<uint8_t> content(128, 0xCC);

    auto enc_res = encode(content, p);
    ASSERT_TRUE(enc_res.has_value()) << enc_res.error().detail;

    auto dec_res = decode(*enc_res);
    ASSERT_TRUE(dec_res.has_value()) << dec_res.error().detail;
    EXPECT_EQ(dec_res->content, content);
    EXPECT_EQ(dec_res->status, ReassemblyStatus::FullyVerified);
}

TEST(Decode, compute_n_Basic) {
    // encode/decode implicitly tests compute_n; verify it directly here too.
    EXPECT_EQ(compute_n(0,   64),  1u);   // empty content → 1 chunk
    EXPECT_EQ(compute_n(64,  64),  1u);   // exactly S → 1 chunk
    EXPECT_EQ(compute_n(65,  64),  2u);   // one byte over → 2 chunks
    EXPECT_EQ(compute_n(128, 64),  2u);
    EXPECT_EQ(compute_n(129, 64),  3u);
    EXPECT_EQ(compute_n(1,   2),   1u);
}
