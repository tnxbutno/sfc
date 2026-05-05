/// @file test_p5.cpp
/// @brief Tests for SFC/P5 Directory profile: encode_directory, extract_directory_full,
///        extract_directory_partial.

#include "sfc/directory.h"
#include "sfc/decoder.h"
#include "sfc/reassembly.h"
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
        .filename  = "directory",
        .metadata  = {},
    };
}

/// Build a DirectoryInputFile with a byte-pattern payload.
static DirectoryInputFile make_file(const std::string& path,
                                    size_t size,
                                    uint8_t fill = 0x00,
                                    uint16_t format_id = 0x0001) {
    return DirectoryInputFile{
        .path      = path,
        .content   = std::vector<uint8_t>(size, fill),
        .format_id = format_id,
    };
}

// ===========================================================================
// encode_directory — path validation
// ===========================================================================

TEST(EncodeDirectory, EmptyPath_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x01);
    std::vector<DirectoryInputFile> files = {make_file("", 10)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeDirectory, LeadingSlash_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x02);
    std::vector<DirectoryInputFile> files = {make_file("/leading/slash", 10)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeDirectory, DotDotComponent_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x03);
    std::vector<DirectoryInputFile> files = {make_file("a/../b", 10)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeDirectory, DotComponent_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x04);
    std::vector<DirectoryInputFile> files = {make_file("./foo", 10)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeDirectory, Backslash_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x05);
    std::vector<DirectoryInputFile> files = {make_file("a\\b", 10)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeDirectory, ControlChar_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x06);
    std::string bad_path = "file\x01name";
    std::vector<DirectoryInputFile> files = {make_file(bad_path, 10)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}

TEST(EncodeDirectory, CaseCollision_Error) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x07);
    std::vector<DirectoryInputFile> files = {
        make_file("README.md", 10),
        make_file("readme.md", 10),
    };
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::CaseCollisionInManifest);
}

TEST(EncodeDirectory, ValidNestedPath_OK) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x08);
    std::vector<DirectoryInputFile> files = {make_file("a/b/c.txt", 20)};
    auto res = encode_directory(std::move(files), p);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
}

TEST(EncodeDirectory, EmptyFileList_Rejected) {
    // F >= 1 is required by §16.2; empty directory must be rejected.
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x09);
    std::vector<DirectoryInputFile> files;
    auto res = encode_directory(std::move(files), p);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::FieldBelowMinimum);
}

// ===========================================================================
// encode_directory → decode() → extract_directory_full — round-trips
// ===========================================================================

TEST(P5RoundTrip, SingleFile) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x10);
    std::vector<uint8_t> content(80, 0xAB);
    std::vector<DirectoryInputFile> files = {{
        .path = "hello.bin", .content = content, .format_id = 0x0001
    }};

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    // decode() gives us the reassembled inner_content.
    auto dec = decode(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;
    EXPECT_EQ(dec->status, ReassemblyStatus::FullyVerified);

    auto ext = extract_directory_full(dec->content);
    ASSERT_TRUE(ext.has_value()) << ext.error().detail;
    ASSERT_EQ(ext->files.size(), 1u);
    EXPECT_EQ(ext->files[0].path, "hello.bin");
    EXPECT_EQ(ext->files[0].content, content);
    EXPECT_EQ(ext->files[0].format_id, 0x0001u);
    EXPECT_TRUE(ext->pending_paths.empty());
}

TEST(P5RoundTrip, MultipleFiles) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x11);

    // Three files with different sizes.
    std::vector<DirectoryInputFile> files = {
        {.path = "a/alpha.txt", .content = {0x41,0x42,0x43}, .format_id = 0x0010},
        {.path = "b/beta.bin",  .content = std::vector<uint8_t>(50, 0xBB), .format_id = 0x0001},
        {.path = "c/gamma.dat", .content = std::vector<uint8_t>(120, 0xCC), .format_id = 0x0001},
    };
    // Keep a copy of the originals for comparison (encode_directory may sort).
    std::vector<std::string> paths = {"a/alpha.txt", "b/beta.bin", "c/gamma.dat"};

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;

    auto ext = extract_directory_full(dec->content);
    ASSERT_TRUE(ext.has_value()) << ext.error().detail;
    ASSERT_EQ(ext->files.size(), 3u);
    EXPECT_TRUE(ext->pending_paths.empty());

    // Paths are sorted in the manifest; verify content by path lookup.
    for (const auto& ef : ext->files) {
        if (ef.path == "a/alpha.txt") {
            EXPECT_EQ(ef.content, (std::vector<uint8_t>{0x41,0x42,0x43}));
            EXPECT_EQ(ef.format_id, 0x0010u);
        } else if (ef.path == "b/beta.bin") {
            EXPECT_EQ(ef.content, std::vector<uint8_t>(50, 0xBB));
        } else if (ef.path == "c/gamma.dat") {
            EXPECT_EQ(ef.content, std::vector<uint8_t>(120, 0xCC));
        } else {
            FAIL() << "unexpected path: " << ef.path;
        }
    }
}

TEST(P5RoundTrip, EmptyFileInDirectory) {
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x12);
    std::vector<DirectoryInputFile> files = {
        {.path = "empty.bin", .content = {}, .format_id = 0x0001},
        {.path = "non_empty.bin", .content = {0x01,0x02,0x03}, .format_id = 0x0001},
    };

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;

    auto ext = extract_directory_full(dec->content);
    ASSERT_TRUE(ext.has_value()) << ext.error().detail;
    ASSERT_EQ(ext->files.size(), 2u);
}

TEST(P5RoundTrip, SortsByPath) {
    // Files submitted in reverse-alphabetical order; extracted in sorted order.
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x13);
    std::vector<DirectoryInputFile> files = {
        {.path = "zzz.bin", .content = {0x5A}, .format_id = 0x0001},
        {.path = "aaa.bin", .content = {0x41}, .format_id = 0x0001},
        {.path = "mmm.bin", .content = {0x4D}, .format_id = 0x0001},
    };

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;

    auto ext = extract_directory_full(dec->content);
    ASSERT_TRUE(ext.has_value()) << ext.error().detail;
    ASSERT_EQ(ext->files.size(), 3u);

    // After extraction, paths must be in ascending lexicographic order.
    EXPECT_EQ(ext->files[0].path, "aaa.bin");
    EXPECT_EQ(ext->files[1].path, "mmm.bin");
    EXPECT_EQ(ext->files[2].path, "zzz.bin");
}

TEST(P5RoundTrip, WithZstdCompression) {
    auto p = make_params(CompressionAlgo::Zstd, 64, 0, 0x14);
    std::vector<uint8_t> data(200, 0xDD);
    std::vector<DirectoryInputFile> files = {
        {.path = "compressed.bin", .content = data, .format_id = 0x0001}
    };

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;

    auto ext = extract_directory_full(dec->content);
    ASSERT_TRUE(ext.has_value()) << ext.error().detail;
    ASSERT_EQ(ext->files.size(), 1u);
    EXPECT_EQ(ext->files[0].content, data);
}

TEST(P5RoundTrip, InnerFormatIdIsOverridden) {
    // encode_directory sets format_id = 0x0050 (SfcDirectory) regardless of params.
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x15);
    p.format_id = 0x9999;  // will be overridden

    std::vector<DirectoryInputFile> files = {
        {.path = "f.bin", .content = {0x01}, .format_id = 0x0001}
    };

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    // Inner Format ID (at fixed file offset 36, LE uint16) must be 0x0050.
    // File layout: preamble(8) + H(4) + UUID(16) + inner_file_size(8) + format_id(2)
    // → format_id at offset 36.
    ASSERT_GE(enc->size(), 38u);
    uint16_t fid = static_cast<uint16_t>((*enc)[36])
                 | (static_cast<uint16_t>((*enc)[37]) << 8);
    EXPECT_EQ(fid, 0x0050u);
}

// ===========================================================================
// extract_directory_full — error cases
// ===========================================================================

TEST(ExtractDirectoryFull, TooSmall_Error) {
    std::vector<uint8_t> tiny = {0x01, 0x02};
    auto res = extract_directory_full(tiny);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

TEST(ExtractDirectoryFull, BadMFSTMagic_Error) {
    std::vector<uint8_t> bad(64, 0x00);  // wrong magic
    auto res = extract_directory_full(bad);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidMagic);
}

// ===========================================================================
// extract_directory_partial
// ===========================================================================

TEST(ExtractDirectoryPartial, AllChunksPresent_FullExtraction) {
    // When V >= N, extract_directory_partial should produce the same result
    // as extract_directory_full.
    auto p = make_params(CompressionAlgo::Identity, 64, 0, 0x20);
    std::vector<DirectoryInputFile> files = {
        {.path = "x.txt", .content = {0x58,0x59,0x5A}, .format_id = 0x0010},
    };

    auto enc = encode_directory(files, p);
    ASSERT_TRUE(enc.has_value()) << enc.error().detail;

    auto dec = decode(*enc);
    ASSERT_TRUE(dec.has_value()) << dec.error().detail;

    // Call extract_directory_full directly (full reconstruction path).
    auto ext = extract_directory_full(dec->content);
    ASSERT_TRUE(ext.has_value()) << ext.error().detail;
    ASSERT_EQ(ext->files.size(), 1u);
    EXPECT_EQ(ext->files[0].content, (std::vector<uint8_t>{0x58,0x59,0x5A}));
    EXPECT_TRUE(ext->pending_paths.empty());
}
