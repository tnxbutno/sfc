/// @file test_phase7.cpp
/// @brief Unit tests for Phase 7: Reassembly and duplicate handling.

#include "sfc/reassembly.h"
#include "sfc/blake3_hash.h"
#include "sfc/chunk.h"
#include "sfc/global_header.h"

#include <gtest/gtest.h>
#include <numeric>

using namespace sfc;

// ===========================================================================
// Helpers
// ===========================================================================

/// Build a valid ParsedChunk (identity compression) for a given index/payload.
/// Uses serialize_chunk so the BLAKE3 hash in the trailer is correct.
static ParsedChunk make_chunk(uint32_t index,
                               const std::vector<uint8_t>& payload,
                               const FileUuid& uuid = {}) {
    ChunkHeader hdr{};
    hdr.uuid             = uuid;
    hdr.chunk_index      = index;
    hdr.chunk_type       = ChunkType::Data;
    hdr.compression_algo = 0x00;  // identity
    hdr.erasure_algo     = 0x00;

    auto bytes = serialize_chunk(hdr, payload);
    return parse_chunk(bytes)->first;
}

/// Build a GlobalHeader with N data chunks, chunk size S, identity compression.
static GlobalHeader make_header(uint32_t n, uint32_t s,
                                 const FileUuid& uuid = {}) {
    GlobalHeader hdr{};
    hdr.uuid             = uuid;
    hdr.n                = n;
    hdr.m                = 0;
    hdr.s                = s;
    hdr.inner_file_size  = static_cast<uint64_t>(n) * s;  // padded size by default
    hdr.erasure_algo     = 0x00;
    hdr.compression_algo = 0x00;
    hdr.flags            = 0;
    hdr.priority_count   = 0;
    return hdr;
}

// ===========================================================================
// handle_duplicates - Section 9.5
// ===========================================================================

TEST(HandleDuplicates, NoDuplicates_AllRetained) {
    auto c0 = make_chunk(0, {0x01});
    auto c1 = make_chunk(1, {0x02});

    auto result = handle_duplicates({c0, c1});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2u);
}

TEST(HandleDuplicates, BenignDuplicate_KeepsOne) {
    // Two byte-identical copies of the same chunk (same hash) -> benign -> one kept.
    auto c0a = make_chunk(0, {0xAA, 0xBB});
    auto c0b = c0a;  // exact copy

    auto result = handle_duplicates({c0a, c0b});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1u);
    EXPECT_EQ((*result)[0].header.chunk_index, 0u);
}

TEST(HandleDuplicates, BenignDuplicate_ThreeCopies_KeepsOne) {
    auto c = make_chunk(0, {0x55});
    auto result = handle_duplicates({c, c, c});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1u);
}

TEST(HandleDuplicates, ContaminatedB2_BothValidHash_Error) {
    // Two chunks share the same index but have different payloads.
    // Both have valid hashes -> B2 -> ContaminatedDuplicate error (Section 9.5).
    auto c0a = make_chunk(0, {0x01});
    auto c0b = make_chunk(0, {0x02});  // different payload, different hash

    auto result = handle_duplicates({c0a, c0b});
    ASSERT_FALSE(result.has_value()) << "B2: both pass hash check -> ContaminatedDuplicate";
    EXPECT_EQ(result.error().code, ErrorCode::ContaminatedDuplicate);
}

TEST(HandleDuplicates, ContaminatedB1_OneCorrupted_KeepsGood) {
    // One chunk has a valid hash; its twin has a tampered hash -> B1 -> keep valid.
    auto c_good = make_chunk(0, {0xCC});
    auto c_bad  = c_good;
    c_bad.hash[0] ^= 0xFF;  // corrupt stored hash (validate_chunk_hash will fail)

    auto result = handle_duplicates({c_good, c_bad});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 1u);
    EXPECT_EQ((*result)[0].hash, c_good.hash);
}

TEST(HandleDuplicates, MultipleIndices_PartialDuplicate) {
    // index 0: benign dup (2 copies); index 1: unique. Expected: {0, 1}.
    auto c0a = make_chunk(0, {0xAA});
    auto c0b = c0a;
    auto c1  = make_chunk(1, {0xBB});

    auto result = handle_duplicates({c0a, c0b, c1});
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2u);
}

// ===========================================================================
// full_reassembly - Section 9.1
// ===========================================================================

TEST(FullReassembly, SingleChunk_FullyVerified) {
    // content = {1,2,3,4}, S=8 -> one block zero-padded to 8 bytes.
    std::vector<uint8_t> content = {0x01, 0x02, 0x03, 0x04};
    const uint32_t s = 8;

    // Build the decompressed block (zero-padded to S).
    std::vector<uint8_t> block(s, 0x00);
    std::copy(content.begin(), content.end(), block.begin());

    GlobalHeader hdr = make_header(1, s);
    hdr.inner_file_size = content.size();   // actual size, not padded
    hdr.global_hash     = blake3(content);   // hash of trimmed bytes

    auto res = full_reassembly({block}, hdr, /*trailer_verified=*/true);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->status,  ReassemblyStatus::FullyVerified);
    EXPECT_EQ(res->content, content);
    EXPECT_TRUE(res->missing_chunks.empty());
}

TEST(FullReassembly, SingleChunk_ContentVerified_NoTrailer) {
    // Without a verified Trailer the status is ContentVerified, not FullyVerified.
    std::vector<uint8_t> content = {0xAA};
    const uint32_t s = 2;
    std::vector<uint8_t> block(s, 0x00);
    block[0] = 0xAA;

    GlobalHeader hdr = make_header(1, s);
    hdr.inner_file_size = 1;
    hdr.global_hash     = blake3(content);

    auto res = full_reassembly({block}, hdr, /*trailer_verified=*/false);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->status, ReassemblyStatus::ContentVerified);
    EXPECT_EQ(res->content, content);
}

TEST(FullReassembly, TwoChunks_Concatenated_FullyVerified) {
    // content = 12 bytes spread across 2 chunks of S=8.
    // Block 0: first 8 bytes; Block 1: bytes 8-11 zero-padded to 8.
    std::vector<uint8_t> content(12);
    std::iota(content.begin(), content.end(), 0x00);

    const uint32_t s = 8;
    std::vector<uint8_t> block0(s), block1(s, 0x00);
    std::copy_n(content.begin(),     8, block0.begin());
    std::copy_n(content.begin() + 8, 4, block1.begin());

    GlobalHeader hdr = make_header(2, s);
    hdr.inner_file_size = content.size();
    hdr.global_hash     = blake3(content);

    auto res = full_reassembly({block0, block1}, hdr, true);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->status,  ReassemblyStatus::FullyVerified);
    EXPECT_EQ(res->content, content);
}

TEST(FullReassembly, WrongGlobalHash_Error) {
    std::vector<uint8_t> content = {0x01};
    const uint32_t s = 2;
    std::vector<uint8_t> block(s, 0x00);
    block[0] = 0x01;

    GlobalHeader hdr = make_header(1, s);
    hdr.inner_file_size = 1;
    hdr.global_hash.fill(0xFF);  // wrong hash

    auto res = full_reassembly({block}, hdr, true);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::GlobalFileHashMismatch);
}

TEST(FullReassembly, WrongBlockCount_Error) {
    // N=2 but only one block provided -> error.
    std::vector<uint8_t> block(8, 0x00);
    GlobalHeader hdr = make_header(2, 8);
    hdr.global_hash.fill(0x00);

    auto res = full_reassembly({block}, hdr, true);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InsufficientChunks);
}

// ===========================================================================
// partial_reassembly - Section 9.3
// ===========================================================================

TEST(PartialReassembly, OnlyChunk0_ReturnsPrefix) {
    // N=3, S=4. Only chunk 0 is present.
    // Partial reassembly should return 4 bytes and report indices 1,2 missing.
    const uint32_t n = 3, s = 4;
    FileUuid uuid{}; uuid.bytes[0] = 0x11;

    GlobalHeader hdr = make_header(n, s, uuid);
    hdr.inner_file_size = static_cast<uint64_t>(n) * s;

    // Block for chunk 0 (identity-compressed -> payload == block).
    std::vector<uint8_t> block0(s, 0x01);
    auto c0 = make_chunk(0, block0, uuid);

    auto res = partial_reassembly({c0}, hdr);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->status, ReassemblyStatus::Partial);

    // Content is the decompressed block0 (4 bytes, all 0x01).
    ASSERT_EQ(res->content.size(), s);
    EXPECT_EQ(res->content, block0);

    // Missing chunks are 1 and 2.
    ASSERT_EQ(res->missing_chunks.size(), 2u);
    EXPECT_EQ(res->missing_chunks[0], 1u);
    EXPECT_EQ(res->missing_chunks[1], 2u);
}

TEST(PartialReassembly, Chunks0And1_Missing2) {
    const uint32_t n = 3, s = 4;
    FileUuid uuid{}; uuid.bytes[0] = 0x22;
    GlobalHeader hdr = make_header(n, s, uuid);
    hdr.inner_file_size = static_cast<uint64_t>(n) * s;

    std::vector<uint8_t> block0(s, 0xAA);
    std::vector<uint8_t> block1(s, 0xBB);
    auto c0 = make_chunk(0, block0, uuid);
    auto c1 = make_chunk(1, block1, uuid);

    auto res = partial_reassembly({c0, c1}, hdr);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->status, ReassemblyStatus::Partial);

    // Content = block0 || block1 = 8 bytes.
    ASSERT_EQ(res->content.size(), 2u * s);
    std::vector<uint8_t> expected_content(block0);
    expected_content.insert(expected_content.end(), block1.begin(), block1.end());
    EXPECT_EQ(res->content, expected_content);

    ASSERT_EQ(res->missing_chunks.size(), 1u);
    EXPECT_EQ(res->missing_chunks[0], 2u);
}

TEST(PartialReassembly, NoChunk0_Error) {
    // The spec requires the longest run starting from 0.
    // If chunk 0 is absent, reassembly fails with InsufficientChunks.
    const uint32_t n = 2, s = 4;
    FileUuid uuid{};
    GlobalHeader hdr = make_header(n, s, uuid);

    std::vector<uint8_t> block1(s, 0x01);
    auto c1 = make_chunk(1, block1, uuid);

    auto res = partial_reassembly({c1}, hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InsufficientChunks);
}
