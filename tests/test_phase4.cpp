/// @file test_phase4.cpp
/// @brief Unit tests for Phase 4: filename sanitization and case folding.

#include "sfc/filename_sanitize.h"
#include <gtest/gtest.h>
#include <array>

using namespace sfc;

// Helper: build a 255-byte filename field from a string.
static std::array<uint8_t, 255> make_field(const std::string& s) {
    std::array<uint8_t, 255> arr{};
    for (size_t i = 0; i < s.size() && i < 254; ++i)
        arr[i] = static_cast<uint8_t>(s[i]);
    return arr;
}

// ===========================================================================
// replace_forbidden_bytes
// ===========================================================================

TEST(ForbiddenBytes, ControlCharsCollapsed) {
    // 0x01..0x1F are forbidden; multiple in a row become one '_'.
    std::vector<uint8_t> in = {0x01, 0x02, 0x1F, 'a'};
    auto out = replace_forbidden_bytes(in);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0], '_');
    EXPECT_EQ(out[1], 'a');
}

TEST(ForbiddenBytes, Slash_BackslashCollapsed) {
    // '/' and '\' are forbidden.
    std::vector<uint8_t> in = {'a', '/', '\\', 'b'};
    auto out = replace_forbidden_bytes(in);
    // 'a' '_' 'b' (single run of two forbidden bytes collapsed)
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 'a');
    EXPECT_EQ(out[1], '_');
    EXPECT_EQ(out[2], 'b');
}

TEST(ForbiddenBytes, NoForbidden_Unchanged) {
    std::vector<uint8_t> in = {'h', 'e', 'l', 'l', 'o'};
    auto out = replace_forbidden_bytes(in);
    EXPECT_EQ(out, in);
}

TEST(ForbiddenBytes, AllForbidden_SingleUnderscore) {
    std::vector<uint8_t> in = {'/', 0x01, '\\', 0x1F};
    auto out = replace_forbidden_bytes(in);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], '_');
}

TEST(ForbiddenBytes, Empty_ReturnsEmpty) {
    auto out = replace_forbidden_bytes(std::span<const uint8_t>{});
    EXPECT_TRUE(out.empty());
}

// ===========================================================================
// replace_invalid_utf8
// ===========================================================================

TEST(Utf8Replace, ValidAscii_Unchanged) {
    std::vector<uint8_t> in = {'a', 'b', 'c'};
    auto out = replace_invalid_utf8(in);
    EXPECT_EQ(out, in);
}

TEST(Utf8Replace, Valid2ByteSeq_Unchanged) {
    // U+00E9, Latin small letter e with acute, encoded as 0xC3 0xA9.
    std::vector<uint8_t> in = {0xC3, 0xA9};
    auto out = replace_invalid_utf8(in);
    EXPECT_EQ(out, in);
}

TEST(Utf8Replace, StrayContByte_ReplacedWithUnderscore) {
    // 0x80 is a continuation byte without a leading byte.
    std::vector<uint8_t> in = {'a', 0x80, 'b'};
    auto out = replace_invalid_utf8(in);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0], 'a');
    EXPECT_EQ(out[1], '_');
    EXPECT_EQ(out[2], 'b');
}

TEST(Utf8Replace, TruncatedSequence_Replaced) {
    // 0xC3 starts a 2-byte sequence but nothing follows.
    std::vector<uint8_t> in = {'a', 0xC3};
    auto out = replace_invalid_utf8(in);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[1], '_');
}

TEST(Utf8Replace, OverlongSequence_Replaced) {
    // 0xC0 0x80 - overlong encoding of U+0000, invalid.
    std::vector<uint8_t> in = {0xC0, 0x80};
    auto out = replace_invalid_utf8(in);
    EXPECT_EQ(out[0], '_');  // 0xC0 is invalid leading byte (< 0xC2)
}

TEST(Utf8Replace, SurrogateRange_Replaced) {
    // 0xED 0xA0 0x80 would be U+D800 (surrogate) - invalid.
    std::vector<uint8_t> in = {0xED, 0xA0, 0x80};
    auto out = replace_invalid_utf8(in);
    EXPECT_EQ(out[0], '_');
}

// ===========================================================================
// sanitize_filename
// ===========================================================================

TEST(SanitizeFilename, NormalName_ReturnsCopy) {
    auto field = make_field("hello.txt");
    auto res = sanitize_filename(field);
    ASSERT_TRUE(res.has_value()) << res.error().detail;
    EXPECT_EQ(*res, "hello.txt");
}

TEST(SanitizeFilename, PathTraversal_Sanitized) {
    // ".." as entire name is rejected.
    auto field = make_field("..");
    auto res = sanitize_filename(field);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::EmptyInnerFilename);
}

TEST(SanitizeFilename, DotName_Rejected) {
    auto field = make_field(".");
    auto res = sanitize_filename(field);
    EXPECT_FALSE(res.has_value());
}

TEST(SanitizeFilename, SlashInName_BecomesUnderscore) {
    auto field = make_field("foo/bar");
    auto res = sanitize_filename(field);
    ASSERT_TRUE(res.has_value());
    // '/' is forbidden -> replaced; "foo" + '_' + "bar"
    EXPECT_EQ(*res, "foo_bar");
}

TEST(SanitizeFilename, NonZeroAfterNull_ReturnsError) {
    std::array<uint8_t, 255> field{};
    field[0] = 'a';
    field[1] = 0x00;
    field[2] = 0x42;  // non-zero after null
    auto res = sanitize_filename(field);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::NonZeroAfterFilenameNull);
}

TEST(SanitizeFilename, EmptyResult_Rejected) {
    // A filename consisting entirely of forbidden bytes becomes "_", not empty.
    auto field = make_field("/");
    auto res = sanitize_filename(field);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, "_");  // single '_' replacing the '/'
}

// ===========================================================================
// case_fold
// ===========================================================================

TEST(CaseFold, AsciiUpperToLower) {
    EXPECT_EQ(case_fold("HELLO"), "hello");
    EXPECT_EQ(case_fold("ABC123"), "abc123");
}

TEST(CaseFold, AlreadyLower_Unchanged) {
    EXPECT_EQ(case_fold("hello"), "hello");
}

TEST(CaseFold, LatinExtended) {
    // U+00C9, Latin capital letter e with acute, folds to U+00E9.
    std::string upper = "\xC3\x89";  // UTF-8 for U+00C9
    std::string lower = "\xC3\xA9";  // UTF-8 for U+00E9
    EXPECT_EQ(case_fold(upper), lower);
}

// ===========================================================================
// paths_collide
// ===========================================================================

TEST(PathsCollide, SameName_Collide) {
    EXPECT_TRUE(paths_collide("readme.md", "readme.md"));
}

TEST(PathsCollide, DifferentCase_Collide) {
    EXPECT_TRUE(paths_collide("README.MD", "readme.md"));
    EXPECT_TRUE(paths_collide("Foo.txt", "foo.txt"));
}

TEST(PathsCollide, DifferentNames_NoCollide) {
    EXPECT_FALSE(paths_collide("foo.txt", "bar.txt"));
}

TEST(PathsCollide, Subpaths_NoCollide) {
    EXPECT_FALSE(paths_collide("src/foo.cpp", "src/bar.cpp"));
}

TEST(PathsCollide, SubpathsCaseCollide) {
    EXPECT_TRUE(paths_collide("Src/Foo.CPP", "src/foo.cpp"));
}
