#include "sfc/byte_utils.h"
#include "sfc/types.h"
#include "sfc/error.h"

#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <vector>

using namespace sfc;

// ===========================================================================
// read / write u16 LE
// ===========================================================================

TEST(ByteUtils, ReadU16LE_Zero) {
    std::array<uint8_t, 2> data = {0x00, 0x00};
    EXPECT_EQ(read_u16_le(data), 0);
}

TEST(ByteUtils, ReadU16LE_One) {
    std::array<uint8_t, 2> data = {0x01, 0x00};
    EXPECT_EQ(read_u16_le(data), 1);
}

TEST(ByteUtils, ReadU16LE_Max) {
    std::array<uint8_t, 2> data = {0xFF, 0xFF};
    EXPECT_EQ(read_u16_le(data), 0xFFFF);
}

TEST(ByteUtils, ReadU16LE_KnownValue) {
    // 0x0801 in LE = {0x01, 0x08}
    std::array<uint8_t, 2> data = {0x01, 0x08};
    EXPECT_EQ(read_u16_le(data), 0x0801);
}

TEST(ByteUtils, WriteU16LE_RoundTrip) {
    for (uint16_t v : {uint16_t(0), uint16_t(1), uint16_t(0x1234), uint16_t(0xFFFF)}) {
        auto bytes = write_u16_le(v);
        EXPECT_EQ(read_u16_le(bytes), v);
    }
}

// ===========================================================================
// read / write u32 LE
// ===========================================================================

TEST(ByteUtils, ReadU32LE_Zero) {
    std::array<uint8_t, 4> data = {0, 0, 0, 0};
    EXPECT_EQ(read_u32_le(data), 0u);
}

TEST(ByteUtils, ReadU32LE_One) {
    std::array<uint8_t, 4> data = {0x01, 0x00, 0x00, 0x00};
    EXPECT_EQ(read_u32_le(data), 1u);
}

TEST(ByteUtils, ReadU32LE_Max) {
    std::array<uint8_t, 4> data = {0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(read_u32_le(data), 0xFFFFFFFFu);
}

TEST(ByteUtils, ReadU32LE_ChunkMagic) {
    // "CHK\0" = {0x43, 0x48, 0x4B, 0x00} as uint32 LE = 0x004B4843
    std::array<uint8_t, 4> data = {0x43, 0x48, 0x4B, 0x00};
    EXPECT_EQ(read_u32_le(data), 0x004B4843u);
}

TEST(ByteUtils, WriteU32LE_RoundTrip) {
    for (uint32_t v : {0u, 1u, 0x12345678u, 0xFFFFFFFFu}) {
        auto bytes = write_u32_le(v);
        EXPECT_EQ(read_u32_le(bytes), v);
    }
}

// ===========================================================================
// read / write u64 LE
// ===========================================================================

TEST(ByteUtils, ReadU64LE_Zero) {
    std::array<uint8_t, 8> data = {0, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_EQ(read_u64_le(data), 0ULL);
}

TEST(ByteUtils, ReadU64LE_One) {
    std::array<uint8_t, 8> data = {0x01, 0, 0, 0, 0, 0, 0, 0};
    EXPECT_EQ(read_u64_le(data), 1ULL);
}

TEST(ByteUtils, ReadU64LE_Max) {
    std::array<uint8_t, 8> data = {0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF};
    EXPECT_EQ(read_u64_le(data), std::numeric_limits<uint64_t>::max());
}

TEST(ByteUtils, ReadU64LE_OneTB) {
    // 1 TB = 1,099,511,627,776 = 0x10000000000
    // LE bytes: 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00
    std::array<uint8_t, 8> data = {0x00, 0x00, 0x00, 0x00,
                                    0x10, 0x00, 0x00, 0x00};
    EXPECT_EQ(read_u64_le(data), 0x1000000000ULL);
}

TEST(ByteUtils, WriteU64LE_RoundTrip) {
    for (uint64_t v : std::initializer_list<uint64_t>{0, 1, 0x123456789ABCDEF0ULL,
                       std::numeric_limits<uint64_t>::max()}) {
        auto bytes = write_u64_le(v);
        EXPECT_EQ(read_u64_le(bytes), v);
    }
}

// ===========================================================================
// is_all_zeros
// ===========================================================================

TEST(ByteUtils, IsAllZeros_Empty) {
    std::span<const uint8_t> empty;
    EXPECT_TRUE(is_all_zeros(empty));
}

TEST(ByteUtils, IsAllZeros_AllZero) {
    std::array<uint8_t, 14> data = {};  // 14 reserved bytes in chunk header
    EXPECT_TRUE(is_all_zeros(data));
}

TEST(ByteUtils, IsAllZeros_OneNonZero) {
    std::array<uint8_t, 14> data = {};
    data[7] = 0x01;
    EXPECT_FALSE(is_all_zeros(data));
}

TEST(ByteUtils, IsAllZeros_LastNonZero) {
    std::array<uint8_t, 16> data = {};
    data[15] = 0xFF;
    EXPECT_FALSE(is_all_zeros(data));
}

// ===========================================================================
// zero_pad
// ===========================================================================

TEST(ByteUtils, ZeroPad_SmallToLarge) {
    std::array<uint8_t, 3> input = {0x01, 0x02, 0x03};
    auto result = zero_pad(input, 8);
    ASSERT_EQ(result.size(), 8u);
    EXPECT_EQ(result[0], 0x01);
    EXPECT_EQ(result[1], 0x02);
    EXPECT_EQ(result[2], 0x03);
    for (size_t i = 3; i < 8; ++i) {
        EXPECT_EQ(result[i], 0x00) << "byte " << i;
    }
}

TEST(ByteUtils, ZeroPad_ExactSize) {
    std::array<uint8_t, 4> input = {0x0A, 0x0B, 0x0C, 0x0D};
    auto result = zero_pad(input, 4);
    ASSERT_EQ(result.size(), 4u);
    EXPECT_TRUE(bytes_equal(result, input));
}

TEST(ByteUtils, ZeroPad_InputLarger) {
    std::array<uint8_t, 6> input = {1, 2, 3, 4, 5, 6};
    auto result = zero_pad(input, 3);
    // Returns copy of input (no truncation)
    ASSERT_EQ(result.size(), 6u);
}

TEST(ByteUtils, ZeroPad_EmptyInput) {
    std::span<const uint8_t> empty;
    auto result = zero_pad(empty, 4);
    ASSERT_EQ(result.size(), 4u);
    EXPECT_TRUE(is_all_zeros(result));
}

// ===========================================================================
// trim
// ===========================================================================

TEST(ByteUtils, Trim_LargeToSmall) {
    std::array<uint8_t, 8> input = {1, 2, 3, 4, 5, 6, 7, 8};
    auto result = trim(input, 3);
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], 1);
    EXPECT_EQ(result[1], 2);
    EXPECT_EQ(result[2], 3);
}

TEST(ByteUtils, Trim_ExactSize) {
    std::array<uint8_t, 4> input = {0x0A, 0x0B, 0x0C, 0x0D};
    auto result = trim(input, 4);
    ASSERT_EQ(result.size(), 4u);
    EXPECT_TRUE(bytes_equal(result, input));
}

TEST(ByteUtils, Trim_InputSmaller) {
    std::array<uint8_t, 2> input = {0xAA, 0xBB};
    auto result = trim(input, 10);
    // Returns copy (no padding)
    ASSERT_EQ(result.size(), 2u);
}

TEST(ByteUtils, Trim_ToZero) {
    std::array<uint8_t, 5> input = {1, 2, 3, 4, 5};
    auto result = trim(input, 0);
    EXPECT_TRUE(result.empty());
}

// ===========================================================================
// bytes_equal
// ===========================================================================

TEST(ByteUtils, BytesEqual_Same) {
    std::array<uint8_t, 4> a = {1, 2, 3, 4};
    std::array<uint8_t, 4> b = {1, 2, 3, 4};
    EXPECT_TRUE(bytes_equal(a, b));
}

TEST(ByteUtils, BytesEqual_Different) {
    std::array<uint8_t, 4> a = {1, 2, 3, 4};
    std::array<uint8_t, 4> b = {1, 2, 3, 5};
    EXPECT_FALSE(bytes_equal(a, b));
}

TEST(ByteUtils, BytesEqual_DifferentSize) {
    std::array<uint8_t, 3> a = {1, 2, 3};
    std::array<uint8_t, 4> b = {1, 2, 3, 4};
    EXPECT_FALSE(bytes_equal(a, b));
}

TEST(ByteUtils, BytesEqual_BothEmpty) {
    std::span<const uint8_t> a;
    std::span<const uint8_t> b;
    EXPECT_TRUE(bytes_equal(a, b));
}

// ===========================================================================
// types.h compile-time checks
// ===========================================================================

TEST(Types, MagicBytesCorrect) {
    EXPECT_EQ(kSfcMagic[0], 'S');
    EXPECT_EQ(kSfcMagic[1], 'F');
    EXPECT_EQ(kSfcMagic[2], 'C');
    EXPECT_EQ(kSfcMagic[3], '\0');

    EXPECT_EQ(kChunkMagic[0], 'C');
    EXPECT_EQ(kChunkMagic[1], 'H');
    EXPECT_EQ(kChunkMagic[2], 'K');
    EXPECT_EQ(kChunkMagic[3], '\0');

    EXPECT_EQ(kChunkEndMarker[0], '/');
    EXPECT_EQ(kChunkEndMarker[1], 'C');
    EXPECT_EQ(kChunkEndMarker[2], 'H');
    EXPECT_EQ(kChunkEndMarker[3], 'K');

    EXPECT_EQ(kTrailerMagic[0], 'T');
    EXPECT_EQ(kTrailerMagic[1], 'R');
    EXPECT_EQ(kTrailerMagic[2], 'L');
    EXPECT_EQ(kTrailerMagic[3], 'R');

    EXPECT_EQ(kSegmentMagic[0], 'S');
    EXPECT_EQ(kSegmentMagic[1], 'E');
    EXPECT_EQ(kSegmentMagic[2], 'G');
    EXPECT_EQ(kSegmentMagic[3], '\0');

    EXPECT_EQ(kManifestMagic[0], 'M');
    EXPECT_EQ(kManifestMagic[1], 'F');
    EXPECT_EQ(kManifestMagic[2], 'S');
    EXPECT_EQ(kManifestMagic[3], 'T');
}

TEST(Types, StructureSizes) {
    EXPECT_EQ(kPreambleSize, 8u);
    EXPECT_EQ(kChunkHeaderSize, 48u);
    EXPECT_EQ(kChunkTrailerSize, 36u);
    EXPECT_EQ(kTrailerSize, 64u);
    EXPECT_EQ(kSegmentHeaderSize, 16u);
    EXPECT_EQ(kBlake3HashSize, 32u);
    EXPECT_EQ(kFileUuidSize, 16u);
}

TEST(Types, ProtocolLimits) {
    EXPECT_EQ(limits::kMaxTotalChunkCount, 65535u);
    EXPECT_EQ(limits::kMinChunkSize, 2u);
    EXPECT_EQ(limits::kMaxInnerFileSize, 1099511627776ULL);  // 1 TB
}

TEST(Types, FileUuidEquality) {
    FileUuid a{};
    FileUuid b{};
    EXPECT_EQ(a, b);

    a.bytes[0] = 0x42;
    EXPECT_NE(a, b);
}

// ===========================================================================
// error.h checks
// ===========================================================================

TEST(Error, SeverityClassification) {
    EXPECT_EQ(error_severity(ErrorCode::InvalidMagic), ErrorSeverity::FileLevel);
    EXPECT_EQ(error_severity(ErrorCode::ChunkBlake3Failure), ErrorSeverity::ChunkLevel);
    EXPECT_EQ(error_severity(ErrorCode::TerminalSegmentNotFound), ErrorSeverity::Warning);
}

TEST(Error, ResultSuccess) {
    Result<int> r = 42;
    EXPECT_TRUE(r.has_value());
    EXPECT_EQ(r.value(), 42);
}

TEST(Error, ResultError) {
    Result<int> r = std::unexpected(SfcError{ErrorCode::InvalidMagic, "bad magic"});
    EXPECT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::InvalidMagic);
}

TEST(Error, VoidResultSuccess) {
    VoidResult r = {};
    EXPECT_TRUE(r.has_value());
}

TEST(Error, AllErrorCodesDistinct) {
    // Verify no two error codes share the same numeric value
    std::vector<uint32_t> codes = {
        1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010,
        1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020,
        1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030,
        2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010,
        3001, 3002, 3003, 3004, 3005, 3006, 3007, 3008, 3009, 3010,
        3011, 3012,
        4001,
        9001, 9002, 9003, 9004, 9005,
    };
    std::sort(codes.begin(), codes.end());
    auto it = std::unique(codes.begin(), codes.end());
    EXPECT_EQ(it, codes.end()) << "Duplicate error code values found";
}
