/// @file test_split.cpp
/// @brief Tests for split transport (P2, §13): encode_split, decode_split, decode_multi.

#include "sfc/split_decoder.h"
#include "sfc/split_encoder.h"
#include "sfc/types.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <numeric>
#include <vector>

using namespace sfc;

// ===========================================================================
// Helpers
// ===========================================================================

static FileUuid make_uuid(uint8_t seed) {
    FileUuid u{};
    for (size_t i = 0; i < 16; ++i) u.bytes[i] = static_cast<uint8_t>(seed + i);
    return u;
}

static EncodeParams make_params(CompressionAlgo algo = CompressionAlgo::Identity,
                                 uint32_t s = 64, uint32_t m = 0,
                                 uint8_t uuid_seed = 0x01) {
    return EncodeParams{
        .m         = m,
        .s         = s,
        .algo      = algo,
        .uuid      = make_uuid(uuid_seed),
        .timestamp = 0,
        .format_id = 0x0001,
        .filename  = "split_test.bin",
        .metadata  = {},
    };
}

/// Generate a content vector of the given size with an iota pattern.
static std::vector<uint8_t> make_content(size_t size, uint8_t start = 0x00) {
    std::vector<uint8_t> v(size);
    for (size_t i = 0; i < size; ++i)
        v[i] = static_cast<uint8_t>((start + i) & 0xFF);
    return v;
}

// ===========================================================================
// encode_split — parameter validation
// ===========================================================================

TEST(EncodeSplit, ZeroSegments_Error) {
    auto p = make_params();
    auto res = encode_split(make_content(10), p, 0);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeSplit, OddS_Error) {
    auto p = make_params();
    p.s = 63;
    auto res = encode_split(make_content(10), p, 2);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OddChunkSizeS);
}

TEST(EncodeSplit, ProducesCorrectSegmentCount) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x02);
    auto res = encode_split(make_content(200), p, 3);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->size(), 3u);
}

TEST(EncodeSplit, SegmentCountCappedAtTotalChunks) {
    // 1 data chunk, 0 recovery → total_chunks = 1; cap at 1 even if 5 requested.
    auto p = make_params(CompressionAlgo::Identity, 256, 0, 0x03);
    auto res = encode_split(make_content(10), p, 5);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->size(), 1u);  // capped at 1
}

TEST(EncodeSplit, EachSegmentStartsWithSFCMagic) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x04);
    auto res = encode_split(make_content(300), p, 4);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    for (const auto& seg : *res) {
        ASSERT_GE(seg.size(), 8u);
        EXPECT_EQ(seg[0], 0x53u); EXPECT_EQ(seg[1], 0x46u);
        EXPECT_EQ(seg[2], 0x43u); EXPECT_EQ(seg[3], 0x00u);
    }
}

TEST(EncodeSplit, TerminalSegmentIsLast) {
    // The last segment must have is_terminal = true in its SegmentHeader.
    // SegmentHeader is at offset 8 + H + 4 bytes.
    // The terminal flag is SegmentHeader byte 12 (offset 12 into the 16-byte header).
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x05);
    auto res = encode_split(make_content(200), p, 3);
    ASSERT_TRUE(res.has_value()) << res.error().detail;

    // Check terminal flag in the last segment's SegmentHeader.
    // Header region: starts at byte 8, H is stored at bytes [8..11] (LE uint32).
    const auto& last_seg = res->back();
    ASSERT_GE(last_seg.size(), 12u);
    uint32_t H = static_cast<uint32_t>(last_seg[8])
               | (static_cast<uint32_t>(last_seg[9]) << 8)
               | (static_cast<uint32_t>(last_seg[10]) << 16)
               | (static_cast<uint32_t>(last_seg[11]) << 24);
    // SegmentHeader starts at 8 + H + 4 bytes from the file start.
    const size_t sh_offset = 8 + H + 4;
    ASSERT_GE(last_seg.size(), sh_offset + 16u);
    EXPECT_EQ(last_seg[sh_offset + 12], 0x01u);  // terminal flag

    // Non-terminal segments must have terminal flag = 0.
    for (size_t i = 0; i + 1 < res->size(); ++i) {
        const auto& seg = (*res)[i];
        ASSERT_GE(seg.size(), sh_offset + 16u);
        EXPECT_EQ(seg[sh_offset + 12], 0x00u);
    }
}

// ===========================================================================
// encode_split + decode_split — round-trips
// ===========================================================================

TEST(P2RoundTrip, OneSegment_Identity) {
    auto p     = make_params(CompressionAlgo::Identity, 64, 0, 0x10);
    auto content = make_content(100);

    auto enc = encode_split(content, p, 1);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode_split(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
    EXPECT_EQ(dec->status, ReassemblyStatus::FullyVerified);
}

TEST(P2RoundTrip, TwoSegments_Identity) {
    auto p       = make_params(CompressionAlgo::Identity, 64, 0, 0x11);
    auto content = make_content(200);

    auto enc = encode_split(content, p, 2);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;
    EXPECT_EQ(enc->size(), 2u);

    auto dec = decode_split(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
    EXPECT_EQ(dec->status, ReassemblyStatus::FullyVerified);
}

TEST(P2RoundTrip, FourSegments_Identity) {
    auto p       = make_params(CompressionAlgo::Identity, 32, 0, 0x12);
    auto content = make_content(400);

    auto enc = encode_split(content, p, 4);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode_split(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
}

TEST(P2RoundTrip, TwoSegments_Zstd) {
    auto p       = make_params(CompressionAlgo::Zstd, 64, 0, 0x13);
    auto content = make_content(256, 0xAB);

    auto enc = encode_split(content, p, 2);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode_split(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
    EXPECT_EQ(dec->status, ReassemblyStatus::FullyVerified);
}

TEST(P2RoundTrip, EmptyContent) {
    auto p       = make_params(CompressionAlgo::Identity, 64, 0, 0x14);
    std::vector<uint8_t> content;

    auto enc = encode_split(content, p, 1);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode_split(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
}

TEST(P2RoundTrip, SegmentsInReversedOrder) {
    // decode_split must handle segments in any order.
    auto p       = make_params(CompressionAlgo::Identity, 64, 0, 0x15);
    auto content = make_content(200);

    auto enc = encode_split(content, p, 3);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    // Reverse the order.
    std::vector<std::vector<uint8_t>> reversed(enc->rbegin(), enc->rend());
    auto dec = decode_split(reversed);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
}

TEST(P2RoundTrip, WithRS_DropOneSegment) {
    // N=2 data + M=1 recovery → can lose any 1 chunk.
    // Spread across 3 segments (1 chunk each); drop the middle segment.
    auto p   = make_params(CompressionAlgo::Identity, 64, /*m=*/1, 0x16);
    auto content = make_content(100);

    auto enc = encode_split(content, p, 3);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;
    ASSERT_EQ(enc->size(), 3u);

    // Drop segment 1 (middle).
    std::vector<std::vector<uint8_t>> two_segs = {(*enc)[0], (*enc)[2]};
    auto dec = decode_split(two_segs);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->content, content);
}

// ===========================================================================
// decode_split — error cases
// ===========================================================================

TEST(DecodeSplit, NoSegments_Error) {
    std::vector<std::vector<uint8_t>> empty;
    auto res = decode_split(empty);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(DecodeSplit, BadMagic_Error) {
    std::vector<uint8_t> bad(100, 0x00);
    std::vector<std::vector<uint8_t>> segs = {bad};
    auto res = decode_split(segs);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(DecodeSplit, DuplicateSegmentIndex_Error) {
    auto p       = make_params(CompressionAlgo::Identity, 64, 0, 0x20);
    auto content = make_content(100);

    auto enc = encode_split(content, p, 2);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;
    ASSERT_EQ(enc->size(), 2u);

    // Pass segment 0 twice — same segment_index → error.
    std::vector<std::vector<uint8_t>> segs = {(*enc)[0], (*enc)[0]};
    auto res = decode_split(segs);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::DuplicateSegmentIndex);
}

TEST(DecodeSplit, InconsistentHeaders_Error) {
    // Produce two separate 1-segment split-transport files with different content.
    auto p1 = make_params(CompressionAlgo::Identity, 64, 0, 0x21);
    auto p2 = make_params(CompressionAlgo::Identity, 64, 0, 0x22);
    auto c1  = make_content(64);
    auto c2  = make_content(64, 0x80);

    auto enc1 = encode_split(c1, p1, 1);
    auto enc2 = encode_split(c2, p2, 1);
    ASSERT_TRUE(enc1.has_value()); ASSERT_TRUE(enc2.has_value());

    // Mixing segments from different files → header mismatch (different UUID,
    // different content, etc.).  The error might manifest as GlobalHeaderConflict
    // or as an inner decode error; either way it must fail.
    std::vector<std::vector<uint8_t>> segs = {(*enc1)[0], (*enc2)[0]};
    auto res = decode_split(segs);
    ASSERT_FALSE(res.has_value());
    // Accept any file-level error — the exact code depends on which check fires first.
}

// ===========================================================================
// decode_multi
// ===========================================================================

TEST(DecodeMulti, SingleRegularFile) {
    // A regular SFC file (no split-transport flags) should be decoded individually.
    EncodeParams p{};
    p.m = 0; p.s = 64; p.algo = CompressionAlgo::Identity;
    p.uuid = make_uuid(0x30);
    p.timestamp = 0; p.format_id = 0x0001; p.filename = "single.bin";

    auto content = make_content(50);

    // Use encode() to build a regular (non-split) file.
    auto enc = encode(content, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    std::vector<std::vector<uint8_t>> files = {*enc};
    auto res = decode_multi(files);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->size(), 1u);
    EXPECT_EQ((*res)[0].uuid, p.uuid);
    EXPECT_EQ((*res)[0].result.content, content);
}

TEST(DecodeMulti, TwoRegularFiles_DifferentUUIDs) {
    EncodeParams p1{};
    p1.m = 0; p1.s = 64; p1.algo = CompressionAlgo::Identity;
    p1.uuid = make_uuid(0x31); p1.timestamp = 0;
    p1.format_id = 0x0001; p1.filename = "a.bin";

    EncodeParams p2 = p1;
    p2.uuid = make_uuid(0x40);
    p2.filename = "b.bin";

    auto c1 = make_content(50);
    auto c2 = make_content(80, 0x55);

    auto enc1 = encode(c1, p1);
    auto enc2 = encode(c2, p2);
    ASSERT_TRUE(enc1.has_value()); ASSERT_TRUE(enc2.has_value());

    std::vector<std::vector<uint8_t>> files = {*enc1, *enc2};
    auto res = decode_multi(files);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->size(), 2u);

    // Both UUIDs should appear.
    bool found1 = false, found2 = false;
    for (const auto& e : *res) {
        if (e.uuid == p1.uuid) { EXPECT_EQ(e.result.content, c1); found1 = true; }
        if (e.uuid == p2.uuid) { EXPECT_EQ(e.result.content, c2); found2 = true; }
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);
}

TEST(DecodeMulti, SplitSegments_GroupedByUUID) {
    auto p       = make_params(CompressionAlgo::Identity, 64, 0, 0x50);
    auto content = make_content(200);

    auto enc = encode_split(content, p, 3);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    // Pass all 3 segments to decode_multi in shuffled order.
    std::vector<std::vector<uint8_t>> files = {(*enc)[2], (*enc)[0], (*enc)[1]};
    auto res = decode_multi(files);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->size(), 1u);
    EXPECT_EQ((*res)[0].uuid, p.uuid);
    EXPECT_EQ((*res)[0].result.content, content);
}

TEST(DecodeMulti, MixedRegularAndSplit) {
    // One regular file + one split-transport group (2 segments).
    EncodeParams preg{};
    preg.m = 0; preg.s = 64; preg.algo = CompressionAlgo::Identity;
    preg.uuid = make_uuid(0x60); preg.timestamp = 0;
    preg.format_id = 0x0001; preg.filename = "regular.bin";

    auto creg   = make_content(60);
    auto enc_reg = encode(creg, preg);
    ASSERT_TRUE(enc_reg.has_value());

    auto p2 = make_params(CompressionAlgo::Identity, 64, 0, 0x70);
    auto c2  = make_content(150);
    auto enc_p2 = encode_split(c2, p2, 2);
    ASSERT_TRUE(enc_p2.has_value());

    // Mix all files together.
    std::vector<std::vector<uint8_t>> files = {
        (*enc_p2)[1], *enc_reg, (*enc_p2)[0]
    };

    auto res = decode_multi(files);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->size(), 2u);

    bool found_reg = false, found_p2 = false;
    for (const auto& e : *res) {
        if (e.uuid == preg.uuid) { EXPECT_EQ(e.result.content, creg); found_reg = true; }
        if (e.uuid == p2.uuid)   { EXPECT_EQ(e.result.content, c2);   found_p2  = true; }
    }
    EXPECT_TRUE(found_reg);
    EXPECT_TRUE(found_p2);
}

TEST(DecodeMulti, Empty_ReturnsEmpty) {
    std::vector<std::vector<uint8_t>> files;
    auto res = decode_multi(files);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res->empty());
}
