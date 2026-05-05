/// @file test_phase6.cpp
/// @brief Unit tests for Phase 6: Validation pipeline D1-D5.

#include "sfc/validation.h"
#include "sfc/blake3_hash.h"
#include "sfc/chunk.h"
#include "sfc/global_header.h"
#include "sfc/trailer.h"

#include <gtest/gtest.h>
#include <array>

using namespace sfc;

// ===========================================================================
// Helpers
// ===========================================================================

/// Serialize + parse a chunk so we get a fully valid ParsedChunk with the
/// correct BLAKE3 hash stored in the trailer.
static ParsedChunk make_valid_parsed_chunk(uint32_t index,
                                            const FileUuid& uuid,
                                            const std::vector<uint8_t>& payload) {
    ChunkHeader hdr{};
    hdr.uuid              = uuid;
    hdr.chunk_index       = index;
    hdr.chunk_type        = ChunkType::Data;
    hdr.compression_algo  = 0x00;
    hdr.erasure_algo      = 0x00;

    auto chunk_bytes = serialize_chunk(hdr, payload);
    auto res         = parse_chunk(chunk_bytes);
    return res->first;
}

/// Build a minimal GlobalHeader (N=1, M=0, S=64, identity algo).
static GlobalHeader make_test_global_header(const FileUuid& uuid = {}) {
    GlobalHeader hdr{};
    hdr.uuid             = uuid;
    hdr.n                = 1;
    hdr.m                = 0;
    hdr.s                = 64;
    hdr.inner_file_size  = 1;
    hdr.erasure_algo     = 0x00;
    hdr.compression_algo = 0x00;
    hdr.flags            = 0;
    hdr.priority_count   = 0;
    return hdr;
}

// ===========================================================================
// D1: validate_preamble
// ===========================================================================

TEST(ValidatePreamble, Valid_SFCv1) {
    // "SFC\0" + major=1 (LE u16) + minor=8 (LE u16).
    std::array<uint8_t, 8> p = {0x53, 0x46, 0x43, 0x00, 0x01, 0x00, 0x08, 0x00};
    auto res = validate_preamble(p);
    EXPECT_TRUE(res.has_value()) << (res.has_value() ? "" : res.error().detail);
}

TEST(ValidatePreamble, BadMagic_Error) {
    // First byte corrupted.
    std::array<uint8_t, 8> p = {0xFF, 0x46, 0x43, 0x00, 0x01, 0x00, 0x08, 0x00};
    auto res = validate_preamble(p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(ValidatePreamble, MajorVersion2_Error) {
    // Major version 2 is not supported.
    std::array<uint8_t, 8> p = {0x53, 0x46, 0x43, 0x00, 0x02, 0x00, 0x00, 0x00};
    auto res = validate_preamble(p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedMajorVersion);
}

TEST(ValidatePreamble, MajorVersion0_Error) {
    // Version 0 is also invalid.
    std::array<uint8_t, 8> p = {0x53, 0x46, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto res = validate_preamble(p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::UnsupportedMajorVersion);
}

// ===========================================================================
// D2c: validate_trailer_hash
// ===========================================================================

TEST(ValidateTrailerHash, CorrectHash_OK) {
    // Compute the expected hash and put it in the Trailer.
    std::vector<uint8_t> header_region = {0x01, 0x02, 0x03, 0xAA, 0xBB};
    Trailer t{};
    t.header_hash = blake3(header_region);

    auto res = validate_trailer_hash(t, header_region);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateTrailerHash, WrongHash_Error) {
    std::vector<uint8_t> header_region = {0x01, 0x02};
    Trailer t{};
    t.header_hash.fill(0x00);  // all-zero hash never equals a real BLAKE3 output

    auto res = validate_trailer_hash(t, header_region);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::TrailerBlake3Mismatch);
}

TEST(ValidateTrailerHash, EmptyRegion_WrongHash_Error) {
    // BLAKE3("") is a known non-zero value; zero hash must fail.
    std::vector<uint8_t> header_region;
    Trailer t{};
    t.header_hash.fill(0xFF);  // wrong

    auto res = validate_trailer_hash(t, header_region);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::TrailerBlake3Mismatch);
}

// ===========================================================================
// D3d: validate_chunk_hash
// ===========================================================================

TEST(ValidateChunkHash, ValidChunk_OK) {
    FileUuid uuid{};
    uuid.bytes[0] = 0x10;
    auto chunk    = make_valid_parsed_chunk(0, uuid, {0xDE, 0xAD, 0xBE, 0xEF});
    auto res      = validate_chunk_hash(chunk);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateChunkHash, TamperedPayload_Error) {
    FileUuid uuid{};
    auto chunk = make_valid_parsed_chunk(0, uuid, {0x01, 0x02, 0x03});
    // Flip one byte — the hash no longer matches.
    chunk.payload[0] ^= 0xFF;

    auto res = validate_chunk_hash(chunk);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkBlake3Failure);
}

TEST(ValidateChunkHash, TamperedHash_Error) {
    FileUuid uuid{};
    auto chunk = make_valid_parsed_chunk(0, uuid, {0xAA});
    // Corrupt the stored hash.
    chunk.hash[0] ^= 0xFF;

    auto res = validate_chunk_hash(chunk);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkBlake3Failure);
}

// ===========================================================================
// D3c: validate_chunk_payload_length
// ===========================================================================

TEST(ValidateChunkPayloadLength, ExactlyDouble_OK) {
    // compressed_payload_len == 2*S is the upper limit (inclusive).
    FileUuid uuid{};
    auto chunk = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compressed_payload_len = 16;  // == 2*8

    auto res = validate_chunk_payload_length(chunk, 8);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateChunkPayloadLength, Exceeds2S_Error) {
    FileUuid uuid{};
    auto chunk = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compressed_payload_len = 17;  // 17 > 2*8

    auto res = validate_chunk_payload_length(chunk, 8);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::CompressedPayloadExceeds2S);
}

TEST(ValidateChunkPayloadLength, Zero_SmallS_OK) {
    // Empty payload is allowed (0 <= 2*S always).
    FileUuid uuid{};
    auto chunk = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compressed_payload_len = 0;

    auto res = validate_chunk_payload_length(chunk, 2);
    EXPECT_TRUE(res.has_value());
}

// ===========================================================================
// D4a: validate_chunk_uuid
// ===========================================================================

TEST(ValidateChunkUuid, MatchingUuid_OK) {
    FileUuid uuid{};
    uuid.bytes[3] = 0x77;
    auto hdr      = make_test_global_header(uuid);
    auto chunk    = make_valid_parsed_chunk(0, uuid, {0x01});

    auto res = validate_chunk_uuid(chunk, hdr);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateChunkUuid, MismatchedUuid_Error) {
    FileUuid uuid_hdr{};
    uuid_hdr.bytes[0] = 0xAA;
    FileUuid uuid_chunk{};
    uuid_chunk.bytes[0] = 0xBB;  // different

    auto hdr   = make_test_global_header(uuid_hdr);
    auto chunk = make_valid_parsed_chunk(0, uuid_chunk, {0x01});

    auto res = validate_chunk_uuid(chunk, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::FileUuidMismatch);
}

// ===========================================================================
// D4b: validate_chunk_index
// ===========================================================================

TEST(ValidateChunkIndex, LastDataIndex_OK) {
    FileUuid uuid{};
    auto hdr = make_test_global_header(uuid);
    hdr.n = 3; hdr.m = 1;  // valid range: [0, 3]

    auto chunk = make_valid_parsed_chunk(3, uuid, {});  // index 3 = N+M-1
    auto res   = validate_chunk_index(chunk, hdr);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateChunkIndex, EqualToNplusM_Error) {
    FileUuid uuid{};
    auto hdr = make_test_global_header(uuid);
    hdr.n = 2; hdr.m = 1;  // valid range: [0, 2]

    auto chunk = make_valid_parsed_chunk(3, uuid, {});  // index 3 >= N+M=3
    auto res   = validate_chunk_index(chunk, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkIndexOutOfRange);
}

TEST(ValidateChunkIndex, VeryLargeIndex_Error) {
    FileUuid uuid{};
    auto hdr = make_test_global_header(uuid);
    hdr.n = 1; hdr.m = 0;

    auto chunk = make_valid_parsed_chunk(999, uuid, {});
    auto res   = validate_chunk_index(chunk, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkIndexOutOfRange);
}

// ===========================================================================
// D4d: validate_chunk_algo
// ===========================================================================

TEST(ValidateChunkAlgo, IdentityMatch_OK) {
    FileUuid uuid{};
    auto hdr             = make_test_global_header(uuid);
    hdr.compression_algo = 0x00;
    hdr.erasure_algo     = 0x00;

    auto chunk                      = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compression_algo   = 0x00;
    chunk.header.erasure_algo       = 0x00;

    auto res = validate_chunk_algo(chunk, hdr);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateChunkAlgo, DeprecatedZstd_NormalisedToZstd_OK) {
    // Header says 0x01 (zstd); chunk says 0x02 (deprecated zstd).
    // After normalisation both are 0x01 → no mismatch.
    FileUuid uuid{};
    auto hdr             = make_test_global_header(uuid);
    hdr.compression_algo = 0x01;
    hdr.erasure_algo     = 0x00;

    auto chunk                      = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compression_algo   = 0x02;  // deprecated → normalised to 0x01
    chunk.header.erasure_algo       = 0x00;

    auto res = validate_chunk_algo(chunk, hdr);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateChunkAlgo, CompressMismatch_Error) {
    FileUuid uuid{};
    auto hdr             = make_test_global_header(uuid);
    hdr.compression_algo = 0x00;  // identity
    hdr.erasure_algo     = 0x00;

    auto chunk                      = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compression_algo   = 0x03;  // brotli ≠ identity

    auto res = validate_chunk_algo(chunk, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkAlgoMismatch);
}

TEST(ValidateChunkAlgo, ErasureMismatch_Error) {
    FileUuid uuid{};
    auto hdr             = make_test_global_header(uuid);
    hdr.compression_algo = 0x00;
    hdr.erasure_algo     = 0x01;  // RS

    auto chunk                      = make_valid_parsed_chunk(0, uuid, {});
    chunk.header.compression_algo   = 0x00;
    chunk.header.erasure_algo       = 0x00;  // none ≠ RS

    auto res = validate_chunk_algo(chunk, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkAlgoMismatch);
}

// ===========================================================================
// D5f: validate_global_content_hash
// ===========================================================================

TEST(ValidateGlobalContentHash, CorrectHash_OK) {
    std::vector<uint8_t> content = {0x01, 0x02, 0x03, 0x04};
    GlobalHeader hdr{};
    hdr.global_hash = blake3(content);  // correct expected hash

    auto res = validate_global_content_hash(content, hdr);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateGlobalContentHash, EmptyContent_CorrectHash_OK) {
    std::vector<uint8_t> content;  // empty
    GlobalHeader hdr{};
    hdr.global_hash = blake3(content);

    auto res = validate_global_content_hash(content, hdr);
    EXPECT_TRUE(res.has_value());
}

TEST(ValidateGlobalContentHash, WrongHash_Error) {
    std::vector<uint8_t> content = {0xDE, 0xAD};
    GlobalHeader hdr{};
    hdr.global_hash.fill(0x00);  // wrong hash

    auto res = validate_global_content_hash(content, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::GlobalFileHashMismatch);
}
