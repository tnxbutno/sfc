/// @file test_phase3.cpp
/// @brief Unit tests for Phase 3: BLAKE3 hashing and compression.
///
/// BLAKE3 tests use a known vector from the BLAKE3 reference implementation.
/// Compression tests verify: identity round-trip, zstd round-trip,
/// 0x02 normalisation, size-mismatch error, unsupported-algo error.

#include "sfc/blake3_hash.h"
#include "sfc/compression.h"

#include <gtest/gtest.h>

#include <numeric>  // std::iota

using namespace sfc;

// ===========================================================================
// BLAKE3 - basic hashing
// ===========================================================================

TEST(Blake3, EmptyInput) {
    // BLAKE3 of empty input is a deterministic, known value.
    // Reference: https://github.com/BLAKE3-team/BLAKE3#the-blake3-hash-of-the-empty-string
    // Expected (first 4 bytes): af 13 49 b9
    auto digest = blake3(std::span<const uint8_t>{});
    EXPECT_EQ(digest[0], 0xAF);
    EXPECT_EQ(digest[1], 0x13);
    EXPECT_EQ(digest[2], 0x49);
    EXPECT_EQ(digest[3], 0xB9);
}

TEST(Blake3, SingleByte) {
    // BLAKE3 of a single 0x00 byte - must produce a 32-byte result.
    std::array<uint8_t, 1> data = {0x00};
    auto digest = blake3(data);
    EXPECT_EQ(digest.size(), 32u);
    // The result must not be all-zero (extremely unlikely).
    bool all_zero = true;
    for (auto b : digest) if (b) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}

TEST(Blake3, Deterministic) {
    // Same input always produces the same digest.
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0xFF};
    auto d1 = blake3(data);
    auto d2 = blake3(data);
    EXPECT_EQ(d1, d2);
}

TEST(Blake3, DifferentInputsDifferentDigests) {
    std::vector<uint8_t> a = {0x00};
    std::vector<uint8_t> b = {0x01};
    EXPECT_NE(blake3(a), blake3(b));
}

// ===========================================================================
// BLAKE3 - concat
// ===========================================================================

TEST(Blake3Concat, EquivalentToJoinedHash) {
    // blake3_concat(a, b) must equal blake3(a||b).
    std::vector<uint8_t> a = {0x01, 0x02, 0x03};
    std::vector<uint8_t> b = {0x04, 0x05, 0x06};

    // Compute reference by concatenating manually.
    std::vector<uint8_t> ab;
    ab.insert(ab.end(), a.begin(), a.end());
    ab.insert(ab.end(), b.begin(), b.end());

    EXPECT_EQ(blake3_concat(a, b), blake3(ab));
}

TEST(Blake3Concat, EmptyFirst) {
    std::vector<uint8_t> b = {0x42, 0x43};
    auto ref = blake3(b);
    auto got = blake3_concat(std::span<const uint8_t>{}, b);
    EXPECT_EQ(got, ref);
}

TEST(Blake3Concat, EmptySecond) {
    std::vector<uint8_t> a = {0x42, 0x43};
    auto ref = blake3(a);
    auto got = blake3_concat(a, std::span<const uint8_t>{});
    EXPECT_EQ(got, ref);
}

// ===========================================================================
// BLAKE3 - verify
// ===========================================================================

TEST(Blake3Verify, CorrectHash_ReturnsSuccess) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    Blake3Digest expected = blake3(data);
    auto res = blake3_verify(data, expected);
    EXPECT_TRUE(res.has_value());
}

TEST(Blake3Verify, WrongHash_ReturnsError) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    Blake3Digest wrong{};   // all-zero - extremely unlikely to match
    auto res = blake3_verify(data, wrong);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkBlake3Failure);
}

TEST(Blake3Verify, Concat_CorrectHash) {
    std::vector<uint8_t> hdr = {0xAA, 0xBB};
    std::vector<uint8_t> payload = {0x11, 0x22, 0x33};
    Blake3Digest expected = blake3_concat(hdr, payload);
    auto res = blake3_verify_concat(hdr, payload, expected);
    EXPECT_TRUE(res.has_value());
}

TEST(Blake3Verify, Concat_WrongHash) {
    std::vector<uint8_t> hdr = {0xAA, 0xBB};
    std::vector<uint8_t> payload = {0x11, 0x22, 0x33};
    Blake3Digest wrong{};
    auto res = blake3_verify_concat(hdr, payload, wrong);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkBlake3Failure);
}

// ===========================================================================
// Compression - normalize_compression_id
// ===========================================================================

TEST(Compression, Normalize_0x00_IsIdentity) {
    EXPECT_EQ(normalize_compression_id(0x00), CompressionAlgo::Identity);
}

TEST(Compression, Normalize_0x01_IsZstd) {
    EXPECT_EQ(normalize_compression_id(0x01), CompressionAlgo::Zstd);
}

TEST(Compression, Normalize_0x02_IsBrotli) {
    EXPECT_EQ(normalize_compression_id(0x02), CompressionAlgo::Brotli);
}

TEST(Compression, Normalize_0x03_IsLz4) {
    EXPECT_EQ(normalize_compression_id(0x03), CompressionAlgo::Lz4Frame);
}

// ===========================================================================
// Compression - identity (0x00) round-trip
// ===========================================================================

TEST(Compression, Identity_Compress_IsNoop) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    auto res = compress(data, CompressionAlgo::Identity);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, data);   // identity: output == input
}

TEST(Compression, Identity_Decompress_IsNoop) {
    std::vector<uint8_t> data = {0xAA, 0xBB, 0xCC};
    auto res = decompress(data, CompressionAlgo::Identity, 3);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, data);
}

TEST(Compression, Identity_Decompress_SizeMismatch_ReturnsError) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    // Claim expected_size=4 but data is only 3 bytes.
    auto res = decompress(data, CompressionAlgo::Identity, 4);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::DecompressedSizeMismatch);
}

// ===========================================================================
// Compression - zstd (0x01) round-trip
// ===========================================================================

TEST(Compression, Zstd_RoundTrip_SmallData) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    auto compressed = compress(data, CompressionAlgo::Zstd);
    ASSERT_TRUE(compressed.has_value()) << compressed.error().detail;

    auto decompressed = decompress(*compressed, CompressionAlgo::Zstd, data.size());
    ASSERT_TRUE(decompressed.has_value()) << decompressed.error().detail;
    EXPECT_EQ(*decompressed, data);
}

TEST(Compression, Zstd_RoundTrip_LargeRepetitive) {
    // Repetitive data compresses well with zstd.
    std::vector<uint8_t> data(4096, 0xAB);
    auto compressed = compress(data, CompressionAlgo::Zstd);
    ASSERT_TRUE(compressed.has_value());
    // Compressed should be significantly smaller.
    EXPECT_LT(compressed->size(), data.size() / 2);

    auto decompressed = decompress(*compressed, CompressionAlgo::Zstd, data.size());
    ASSERT_TRUE(decompressed.has_value()) << decompressed.error().detail;
    EXPECT_EQ(*decompressed, data);
}

TEST(Compression, Zstd_SizeMismatch_ReturnsError) {
    std::vector<uint8_t> data = {0x01, 0x02};
    auto compressed = compress(data, CompressionAlgo::Zstd);
    ASSERT_TRUE(compressed.has_value());

    // Claim wrong expected_size (data.size() + 1).
    auto res = decompress(*compressed, CompressionAlgo::Zstd, data.size() + 1);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::DecompressedSizeMismatch);
}

// ===========================================================================
// Compression - brotli (0x02) round-trip
// ===========================================================================

TEST(Compression, Brotli_RoundTrip) {
    std::vector<uint8_t> data(1024);
    std::iota(data.begin(), data.end(), 0);   // 0,1,2,...,255,0,1,... (4 cycles)

    auto compressed = compress(data, CompressionAlgo::Brotli);
    ASSERT_TRUE(compressed.has_value()) << compressed.error().detail;

    auto decompressed = decompress(*compressed, CompressionAlgo::Brotli, data.size());
    ASSERT_TRUE(decompressed.has_value()) << decompressed.error().detail;
    EXPECT_EQ(*decompressed, data);
}

// ===========================================================================
// Compression - lz4 frame (0x03) round-trip
// ===========================================================================

TEST(Compression, Lz4_RoundTrip) {
    std::vector<uint8_t> data(512, 0x55);   // repetitive data

    auto compressed = compress(data, CompressionAlgo::Lz4Frame);
    ASSERT_TRUE(compressed.has_value()) << compressed.error().detail;

    auto decompressed = decompress(*compressed, CompressionAlgo::Lz4Frame, data.size());
    ASSERT_TRUE(decompressed.has_value()) << decompressed.error().detail;
    EXPECT_EQ(*decompressed, data);
}

// ===========================================================================
// Compression - unsupported algorithm
// ===========================================================================

TEST(Compression, Unsupported_Compress_ReturnsError) {
    std::vector<uint8_t> data = {0x01};
    // 0x80 is vendor-specific and not supported.
    auto res = compress(data, static_cast<CompressionAlgo>(0x80));
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedCompressionAlgo);
}

TEST(Compression, Unsupported_Decompress_ReturnsError) {
    std::vector<uint8_t> data = {0x01};
    auto res = decompress(data, static_cast<CompressionAlgo>(0x80), 0);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedCompressionAlgo);
}

// ===========================================================================
// Integration: compress then verify hash
// ===========================================================================

TEST(Phase3_Integration, CompressAndHash) {
    // Compress data, then verify BLAKE3 of the compressed payload matches.
    std::vector<uint8_t> data(256, 0x42);
    auto compressed = compress(data, CompressionAlgo::Zstd);
    ASSERT_TRUE(compressed.has_value());

    // Hash the compressed payload (simulate what the encoder would store).
    Blake3Digest stored_hash = blake3(*compressed);

    // Later, the decoder verifies the received compressed bytes against the hash.
    auto verify_res = blake3_verify(*compressed, stored_hash);
    EXPECT_TRUE(verify_res.has_value());

    // Tamper with one byte - verify must fail.
    (*compressed)[0] ^= 0xFF;
    auto tamper_res = blake3_verify(*compressed, stored_hash);
    EXPECT_FALSE(tamper_res.has_value());
    EXPECT_EQ(tamper_res.error().code, ErrorCode::ChunkBlake3Failure);
}
