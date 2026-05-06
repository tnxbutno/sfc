/// @file test_phase5.cpp
/// @brief Unit tests for Phase 5: TLV, GlobalHeader, Chunk, Trailer, SegmentHeader, Manifest.

#include "sfc/chunk.h"
#include "sfc/global_header.h"
#include "sfc/manifest.h"
#include "sfc/segment_header.h"
#include "sfc/tlv.h"
#include "sfc/trailer.h"
#include "sfc/blake3_hash.h"
#include "sfc/types.h"

#include <gtest/gtest.h>
#include <array>

using namespace sfc;

// ===========================================================================
// TLV
// ===========================================================================

TEST(Tlv, EmptySpan_ReturnsEmpty) {
    // Parsing an empty span produces an empty TLV list.
    auto res = parse_tlv_fields(std::span<const uint8_t>{});
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(res->empty());
}

TEST(Tlv, RoundTrip_SingleUnknownField) {
    // Unknown tag 0x0001, value {0xAB, 0xCD}:
    // wire = tag(2) + length(4) + value(2) = 8 bytes.
    TlvField f;
    f.tag   = 0x0001;
    f.value = {0xAB, 0xCD};

    auto bytes = serialize_tlv_fields({f});
    ASSERT_EQ(bytes.size(), 8u);

    auto res = parse_tlv_fields(bytes);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(res->size(), 1u);
    EXPECT_EQ((*res)[0].tag,   0x0001u);
    EXPECT_EQ((*res)[0].value, f.value);
}

TEST(Tlv, RoundTrip_TwoUnknownFields) {
    // Two distinct unknown tags; both must appear in the parsed result.
    TlvField f1, f2;
    f1.tag = 0x0010; f1.value = {0x11};
    f2.tag = 0x0011; f2.value = {0x22, 0x33};

    auto bytes = serialize_tlv_fields({f1, f2});
    auto res   = parse_tlv_fields(bytes);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(res->size(), 2u);
    EXPECT_EQ((*res)[0].tag, 0x0010u);
    EXPECT_EQ((*res)[1].tag, 0x0011u);
}

TEST(Tlv, DuplicateKnownTag_Error) {
    // kChunkOffsetIndex (0x0020) may appear at most once.
    TlvField f1, f2;
    f1.tag   = TlvTag::kChunkOffsetIndex;
    f1.value = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    f2       = f1;  // identical tag

    auto bytes = serialize_tlv_fields({f1, f2});
    auto res   = parse_tlv_fields(bytes);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::DuplicateKnownTlvTag);
}

TEST(Tlv, ValueOverrun_Error) {
    // Manually craft a TLV whose declared length exceeds the buffer.
    // tag=0x0002(2B) | length=100(4B) | only 1 byte of value present → overrun.
    std::vector<uint8_t> bytes = {
        0x02, 0x00,              // tag = 0x0002
        0x64, 0x00, 0x00, 0x00, // length = 100
        0xFF                     // only 1 byte available
    };
    auto res = parse_tlv_fields(bytes);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::TlvValueOverrunsHeader);
}

// ===========================================================================
// GlobalHeader
// ===========================================================================

/// Construct a minimal valid GlobalHeader (N=1, M=0, S=64, identity algo).
static GlobalHeader make_min_global_header() {
    GlobalHeader hdr{};
    hdr.uuid.bytes[0] = 0x01;
    hdr.inner_file_size  = 100;
    hdr.inner_format_id  = 0x0001;
    hdr.inner_filename.fill(0);
    hdr.inner_filename[0] = 'f';
    hdr.global_hash.fill(0xAA);
    hdr.n               = 1;
    hdr.m               = 0;
    hdr.s               = 64;  // must be even
    hdr.erasure_algo    = 0x00;
    hdr.compression_algo= 0x00;
    hdr.flags           = 0;
    hdr.priority_count  = 0;
    return hdr;
}

TEST(GlobalHeader, RoundTrip_Minimal) {
    auto hdr   = make_min_global_header();
    auto bytes = *serialize_global_header(hdr);

    auto res = parse_global_header(bytes);
    ASSERT_TRUE(res.has_value()) << res.error().detail;

    EXPECT_EQ(res->n,                hdr.n);
    EXPECT_EQ(res->m,                hdr.m);
    EXPECT_EQ(res->s,                hdr.s);
    EXPECT_EQ(res->inner_file_size,  hdr.inner_file_size);
    EXPECT_EQ(res->uuid,             hdr.uuid);
    EXPECT_EQ(res->global_hash,      hdr.global_hash);
    EXPECT_EQ(res->erasure_algo,     hdr.erasure_algo);
    EXPECT_EQ(res->compression_algo, hdr.compression_algo);
    EXPECT_EQ(res->flags,            hdr.flags);
    EXPECT_TRUE(res->priority_list.empty());
}

TEST(GlobalHeader, RoundTrip_WithPriorityList) {
    auto hdr = make_min_global_header();
    hdr.n              = 3;
    hdr.priority_count = 2;
    hdr.priority_list  = {2, 0};

    auto bytes = *serialize_global_header(hdr);
    auto res   = parse_global_header(bytes);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->priority_count, 2u);
    ASSERT_EQ(res->priority_list.size(), 2u);
    EXPECT_EQ(res->priority_list[0], 2u);
    EXPECT_EQ(res->priority_list[1], 0u);
}

TEST(GlobalHeader, RoundTrip_WithTlvField) {
    auto hdr = make_min_global_header();
    TlvField f;
    f.tag   = 0x0003;  // unknown tag
    f.value = {0xDE, 0xAD};
    hdr.tlv_fields = {f};

    auto bytes = *serialize_global_header(hdr);
    auto res   = parse_global_header(bytes);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->tlv_fields.size(), 1u);
    EXPECT_EQ(res->tlv_fields[0].tag, 0x0003u);
}

TEST(GlobalHeader, Validate_OddS_Error) {
    auto hdr = make_min_global_header();
    hdr.s    = 63;  // not even
    auto res = validate_global_header(hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::OddChunkSizeS);
}

TEST(GlobalHeader, Validate_InnerFileSizeZero_NNot1_Error) {
    auto hdr = make_min_global_header();
    hdr.inner_file_size = 0;
    hdr.n               = 2;
    auto res = validate_global_header(hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InnerFileSizeZeroWithNNot1);
}

TEST(GlobalHeader, Validate_ErasureNone_MNonZero_Error) {
    auto hdr = make_min_global_header();
    hdr.m            = 2;
    hdr.erasure_algo = 0x00;  // "none" but M > 0 → invalid
    auto res = validate_global_header(hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ErasureNoneWithMGreaterZero);
}

TEST(GlobalHeader, Validate_PriorityExceedsN_Error) {
    auto hdr = make_min_global_header();
    hdr.n              = 2;
    hdr.priority_count = 3;  // P > N
    hdr.priority_list  = {0, 1, 2};
    auto res = validate_global_header(hdr);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::PriorityCountExceedsN);
}

// ===========================================================================
// Chunk Header / Trailer
// ===========================================================================

/// Build a ChunkHeader suitable for testing.
static ChunkHeader make_test_chunk_header(uint32_t index = 0) {
    ChunkHeader hdr{};
    hdr.uuid.bytes[0]         = 0x42;
    hdr.chunk_index           = index;
    hdr.chunk_type            = ChunkType::Data;
    hdr.compressed_payload_len= 4;
    hdr.compression_algo      = 0x00;
    hdr.erasure_algo          = 0x00;
    return hdr;
}

TEST(ChunkHeader, RoundTrip) {
    auto hdr   = make_test_chunk_header(5);
    auto bytes = serialize_chunk_header(hdr);
    ASSERT_EQ(bytes.size(), 48u);

    // First 4 bytes must be "CHK\0".
    EXPECT_EQ(bytes[0], 0x43u);
    EXPECT_EQ(bytes[1], 0x48u);
    EXPECT_EQ(bytes[2], 0x4Bu);
    EXPECT_EQ(bytes[3], 0x00u);

    auto res = parse_chunk_header(std::span<const uint8_t, 48>{bytes.data(), 48});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->chunk_index,  5u);
    EXPECT_EQ(res->chunk_type,   ChunkType::Data);
    EXPECT_EQ(res->uuid,         hdr.uuid);
    EXPECT_EQ(res->erasure_algo, 0x00u);
}

TEST(ChunkHeader, BadMagic_Error) {
    auto hdr   = make_test_chunk_header();
    auto bytes = serialize_chunk_header(hdr);
    bytes[0]   = 0xFF;  // corrupt first magic byte

    auto res = parse_chunk_header(std::span<const uint8_t, 48>{bytes.data(), 48});
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(ChunkHeader, RecoveryType_RoundTrip) {
    auto hdr      = make_test_chunk_header(3);
    hdr.chunk_type = ChunkType::Recovery;
    auto bytes    = serialize_chunk_header(hdr);
    auto res      = parse_chunk_header(std::span<const uint8_t, 48>{bytes.data(), 48});
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->chunk_type, ChunkType::Recovery);
}

TEST(ChunkTrailer, RoundTrip) {
    Blake3Digest hash;
    hash.fill(0x77);

    auto bytes = serialize_chunk_trailer(hash);
    ASSERT_EQ(bytes.size(), 36u);
    // End marker "/CHK" at bytes 32-35.
    EXPECT_EQ(bytes[32], 0x2Fu);
    EXPECT_EQ(bytes[33], 0x43u);
    EXPECT_EQ(bytes[34], 0x48u);
    EXPECT_EQ(bytes[35], 0x4Bu);

    auto res = parse_chunk_trailer(std::span<const uint8_t, 36>{bytes.data(), 36});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(*res, hash);
}

TEST(ChunkTrailer, BadEndMarker_Error) {
    Blake3Digest hash;
    hash.fill(0x00);
    auto bytes = serialize_chunk_trailer(hash);
    bytes[32]  = 0xFF;  // corrupt end marker

    auto res = parse_chunk_trailer(std::span<const uint8_t, 36>{bytes.data(), 36});
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ChunkEndMarkerInvalid);
}

// ===========================================================================
// ParsedChunk — full round-trip via serialize_chunk + parse_chunk
// ===========================================================================

TEST(ParsedChunk, RoundTrip_DataChunk) {
    auto hdr = make_test_chunk_header(0);
    std::vector<uint8_t> payload = {0x01, 0x02, 0x03, 0x04};

    // serialize_chunk embeds the correct BLAKE3 hash in the trailer.
    auto chunk_bytes = serialize_chunk(hdr, payload);
    ASSERT_EQ(chunk_bytes.size(), 48u + 4u + 36u);

    auto res = parse_chunk(chunk_bytes);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->second,                       chunk_bytes.size());
    EXPECT_EQ(res->first.payload,                payload);
    EXPECT_EQ(res->first.header.chunk_index,     0u);
    EXPECT_EQ(res->first.header.chunk_type,      ChunkType::Data);
    EXPECT_EQ(res->first.header.compressed_payload_len, 4u);
}

TEST(ParsedChunk, TruncatedData_Error) {
    auto hdr         = make_test_chunk_header(0);
    auto chunk_bytes = serialize_chunk(hdr, {0xAA});
    // Provide only part of the bytes — parse should fail.
    auto truncated   = std::vector<uint8_t>(chunk_bytes.begin(),
                                            chunk_bytes.begin() + 40);
    auto res = parse_chunk(truncated);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::TruncatedChunk);
}

// ===========================================================================
// Trailer
// ===========================================================================

TEST(Trailer, RoundTrip) {
    Trailer t{};
    t.header_hash.fill(0x55);
    t.timestamp = 1700000000ULL;  // arbitrary timestamp

    auto bytes = serialize_trailer(t);
    ASSERT_EQ(bytes.size(), 64u);

    auto res = parse_trailer(std::span<const uint8_t, 64>{bytes.data(), 64});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->header_hash, t.header_hash);
    EXPECT_EQ(res->timestamp,   t.timestamp);
}

TEST(Trailer, BadMagic_Error) {
    Trailer t{};
    t.header_hash.fill(0x00);
    t.timestamp = 0;
    auto bytes  = serialize_trailer(t);
    bytes[0]    = 0xFF;  // corrupt "TRLR" magic

    auto res = parse_trailer(std::span<const uint8_t, 64>{bytes.data(), 64});
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(Trailer, ZeroTimestamp_OK) {
    // timestamp = 0 is a valid sentinel (unset) per spec.
    Trailer t{};
    t.header_hash.fill(0x11);
    t.timestamp = 0;

    auto bytes = serialize_trailer(t);
    auto res   = parse_trailer(std::span<const uint8_t, 64>{bytes.data(), 64});
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res->timestamp, 0u);
}

// ===========================================================================
// SegmentHeader
// ===========================================================================

TEST(SegmentHeader, RoundTrip_NonTerminal) {
    SegmentHeader sh{};
    sh.segment_index = 2;
    sh.total_count   = 5;
    sh.is_terminal   = false;

    auto bytes = serialize_segment_header(sh);
    ASSERT_EQ(bytes.size(), 16u);

    auto res = parse_segment_header(std::span<const uint8_t, 16>{bytes.data(), 16});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(res->segment_index, 2u);
    EXPECT_EQ(res->total_count,   5u);
    EXPECT_FALSE(res->is_terminal);
}

TEST(SegmentHeader, RoundTrip_Terminal) {
    SegmentHeader sh{};
    sh.segment_index = 4;
    sh.total_count   = 5;
    sh.is_terminal   = true;

    auto bytes = serialize_segment_header(sh);
    auto res   = parse_segment_header(std::span<const uint8_t, 16>{bytes.data(), 16});
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_TRUE(res->is_terminal);
    EXPECT_EQ(res->segment_index, 4u);
}

TEST(SegmentHeader, BadMagic_Error) {
    SegmentHeader sh{0, 1, false};
    auto bytes = serialize_segment_header(sh);
    bytes[0]   = 0xFF;  // corrupt "SEG\0" magic

    auto res = parse_segment_header(std::span<const uint8_t, 16>{bytes.data(), 16});
    ASSERT_FALSE(res.has_value());
    // Segment header uses a dedicated error code (not InvalidMagic) per the spec.
    EXPECT_EQ(res.error().code, ErrorCode::MissingOrInvalidSegmentHeader);
}

// ===========================================================================
// Manifest
// ===========================================================================

TEST(Manifest, RoundTrip_SingleEntry) {
    ManifestFileEntry e;
    e.path           = "hello.txt";
    e.byte_offset    = 0;
    e.file_size      = 42;
    e.file_hash.fill(0xAB);
    e.inner_format_id = 0x0010;

    auto bytes = serialize_manifest({e});
    auto res   = parse_manifest(bytes);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->entries.size(), 1u);
    EXPECT_EQ(res->entries[0].path,            "hello.txt");
    EXPECT_EQ(res->entries[0].byte_offset,     0u);
    EXPECT_EQ(res->entries[0].file_size,       42u);
    EXPECT_EQ(res->entries[0].file_hash,       e.file_hash);
    EXPECT_EQ(res->entries[0].inner_format_id, 0x0010u);
}

TEST(Manifest, RoundTrip_TwoEntries) {
    ManifestFileEntry e1, e2;
    e1.path = "a/b.txt"; e1.byte_offset = 0;  e1.file_size = 10;
    e1.file_hash.fill(0x11); e1.inner_format_id = 0;
    e2.path = "c.txt";   e2.byte_offset = 10; e2.file_size = 20;
    e2.file_hash.fill(0x22); e2.inner_format_id = 0;

    auto bytes = serialize_manifest({e1, e2});
    auto res   = parse_manifest(bytes);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    ASSERT_EQ(res->entries.size(), 2u);
    EXPECT_EQ(res->entries[0].path, "a/b.txt");
    EXPECT_EQ(res->entries[1].path, "c.txt");
    EXPECT_EQ(res->entries[1].byte_offset, 10u);
}

TEST(Manifest, HashIsVerified) {
    // Corrupt the hash field — parse must return ManifestBlake3Failure.
    ManifestFileEntry e;
    e.path = "x"; e.byte_offset = 0; e.file_size = 0;
    e.file_hash.fill(0); e.inner_format_id = 0;

    auto bytes = serialize_manifest({e});
    // The last 32 bytes are the BLAKE3 hash — zero them out.
    for (size_t i = bytes.size() - 32; i < bytes.size(); ++i) bytes[i] = 0xFF;

    auto res = parse_manifest(bytes);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::ManifestBlake3Failure);
}

TEST(Manifest, BadMagic_Error) {
    ManifestFileEntry e;
    e.path = "f"; e.byte_offset = 0; e.file_size = 0;
    e.file_hash.fill(0); e.inner_format_id = 0;

    auto bytes = serialize_manifest({e});
    bytes[0]   = 0xFF;  // corrupt "MFST"

    auto res = parse_manifest(bytes);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(Manifest, SizeFromChunk0_MatchesSerializedSize) {
    ManifestFileEntry e;
    e.path = "f"; e.byte_offset = 0; e.file_size = 5;
    e.file_hash.fill(0); e.inner_format_id = 0;

    auto bytes    = serialize_manifest({e});
    auto size_res = manifest_size_from_chunk0(bytes);
    ASSERT_TRUE(size_res.has_value()) << size_res.error().detail;
    EXPECT_EQ(*size_res, bytes.size());
}
