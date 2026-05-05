/// @file test_cli.cpp
/// @brief End-to-end integration tests — exercises every sfc CLI command using
///        real file I/O and the compiled binary.

#include <gtest/gtest.h>

#ifdef _WIN32
#  include <process.h>
#else
#  include <sys/wait.h>
#endif

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

// SFC_BINARY_PATH is injected by CMake as the absolute path to the built binary.
#ifndef SFC_BINARY_PATH
#define SFC_BINARY_PATH "sfc"
#endif

// ===========================================================================
// Run helpers
// ===========================================================================

struct RunResult {
    int         exit_code = 0;
    std::string out;  // captured stdout
    std::string err;  // captured stderr
};

/// Wrap a token in quotes for safe shell use (paths, args).
static std::string q(const std::string& s) {
#ifdef _WIN32
    return '"' + s + '"';
#else
    return '\'' + s + '\'';
#endif
}

/// Slurp a file into a string (returns "" when missing).
static std::string slurp(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// Slurp a file into a byte vector.
static std::vector<uint8_t> slurp_bytes(const fs::path& p) {
    std::ifstream f(p, std::ios::binary | std::ios::ate);
    if (!f) return {};
    const auto sz = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> v(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(v.data()), sz);
    return v;
}

/// Build a command string from an ordered list of tokens, redirect stdout/stderr
/// to the supplied temp files, and return the exit code + captured output.
static RunResult run_cmd(const std::string& cmd,
                         const fs::path& out_f, const fs::path& err_f) {
#ifdef _WIN32
    // cmd.exe /C strips the first and last quote when the string starts with one.
    // Wrap in an extra outer pair so inner quoting survives after stripping.
    const std::string full = "\"" + cmd
        + " >\"" + out_f.string() + "\""
        + " 2>\"" + err_f.string() + "\"\"";
    const int exit_code = std::system(full.c_str()); // NOLINT(cert-env33-c)
#else
    const std::string full = cmd + " >" + out_f.string() + " 2>" + err_f.string();
    const int raw = std::system(full.c_str()); // NOLINT(cert-env33-c)
    const int exit_code = WIFEXITED(raw) ? WEXITSTATUS(raw) : -1;
#endif
    return RunResult{exit_code, slurp(out_f), slurp(err_f)};
}

// ===========================================================================
// Fixture
// ===========================================================================

class CliTest : public ::testing::Test {
protected:
    fs::path tmp;                      // per-test temp directory
    fs::path out_f;                    // reusable stdout capture file
    fs::path err_f;                    // reusable stderr capture file

    void SetUp() override {
        // Unique directory per test instance using the pointer address.
#ifdef _WIN32
        const int pid = ::_getpid();
#else
        const int pid = ::getpid();
#endif
        tmp = fs::temp_directory_path() /
              ("sfc_test_" + std::to_string(pid) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(tmp);
        out_f = tmp / "_stdout.txt";
        err_f = tmp / "_stderr.txt";
    }

    void TearDown() override { fs::remove_all(tmp); }

    // Convenience: path inside the temp dir.
    fs::path p(const std::string& rel) const { return tmp / rel; }

    // Run sfc with the given args; capture stdout/stderr.
    RunResult sfc(std::initializer_list<std::string> args) const {
        std::string cmd = q(SFC_BINARY_PATH);
        for (const auto& a : args) cmd += ' ' + q(a);
        return run_cmd(cmd, out_f, err_f);
    }

    // Run sfc with stdin fed from a file on disk.
    RunResult sfc_stdin(const fs::path& stdin_file,
                        std::initializer_list<std::string> args) const {
#ifdef _WIN32
        std::string cmd = "type " + q(stdin_file.string()) + " | " + q(SFC_BINARY_PATH);
#else
        std::string cmd = "cat " + q(stdin_file.string()) + " | " + q(SFC_BINARY_PATH);
#endif
        for (const auto& a : args) cmd += ' ' + q(a);
        return run_cmd(cmd, out_f, err_f);
    }

    // Write text content to a file inside tmp.
    fs::path make_file(const std::string& rel, std::string_view content) const {
        const fs::path dest = p(rel);
        fs::create_directories(dest.parent_path());
        std::ofstream f(dest, std::ios::binary);
        f.write(content.data(), static_cast<std::streamsize>(content.size()));
        return dest;
    }

    // Write a byte vector to a file inside tmp.
    fs::path make_file(const std::string& rel,
                       const std::vector<uint8_t>& content) const {
        const fs::path dest = p(rel);
        fs::create_directories(dest.parent_path());
        std::ofstream f(dest, std::ios::binary);
        f.write(reinterpret_cast<const char*>(content.data()),
                static_cast<std::streamsize>(content.size()));
        return dest;
    }

    // Make a byte vector of given length with an iota pattern.
    static std::vector<uint8_t> iota_bytes(size_t n, uint8_t start = 0) {
        std::vector<uint8_t> v(n);
        std::iota(v.begin(), v.end(), start);
        return v;
    }
};

// ===========================================================================
// version / help
// ===========================================================================

TEST_F(CliTest, VersionFlag) {
    auto r = sfc({"--version"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.out.find("0.1.0"), std::string::npos);
}

TEST_F(CliTest, VersionSubcommand) {
    auto r = sfc({"version"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.out.find("0.1.0"), std::string::npos);
}

TEST_F(CliTest, HelpNoArgs) {
    auto r = sfc({"help"});
    EXPECT_EQ(r.exit_code, 0);
    // Top-level help must list all core commands.
    EXPECT_NE(r.out.find("pack"),   std::string::npos);
    EXPECT_NE(r.out.find("unpack"), std::string::npos);
    EXPECT_NE(r.out.find("info"),   std::string::npos);
    EXPECT_NE(r.out.find("verify"), std::string::npos);
    EXPECT_NE(r.out.find("repair"), std::string::npos);
}

TEST_F(CliTest, HelpKnownCommand) {
    auto r = sfc({"help", "pack"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.out.find("pack"), std::string::npos);
}

TEST_F(CliTest, HelpUnknownCommand) {
    auto r = sfc({"help", "nonexistent"});
    EXPECT_EQ(r.exit_code, 1);
}

TEST_F(CliTest, HelpFlagOnSubcommand) {
    auto r = sfc({"pack", "--help"});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.out.find("pack"), std::string::npos);
}

// ===========================================================================
// pack — basic file output
// ===========================================================================

TEST_F(CliTest, PackDefaultOutputPath) {
    // "input.txt" → "input.sfc" in the same directory.
    const auto src = make_file("input.txt", "hello sfc");
    auto r = sfc({"pack", src.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(fs::exists(p("input.sfc")));
}

TEST_F(CliTest, PackCustomOutputPath) {
    const auto src = make_file("data.bin", iota_bytes(256));
    const auto out = p("custom.sfc");
    auto r = sfc({"pack", src.string(), "-o", out.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(fs::exists(out));
}

TEST_F(CliTest, PackMissingInput) {
    auto r = sfc({"pack", p("nonexistent.bin").string(), "-o", p("out.sfc").string()});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, PackEmptyFile) {
    const auto src = make_file("empty.bin", std::vector<uint8_t>{});
    const auto out = p("empty.sfc");
    auto r = sfc({"pack", src.string(), "-o", out.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_TRUE(fs::exists(out));
    EXPECT_GT(fs::file_size(out), 0u);  // container has headers even for empty content
}

// ===========================================================================
// pack → unpack round-trip: single file, various algos
// ===========================================================================

TEST_F(CliTest, RoundTrip_Zstd) {
    const auto content = iota_bytes(4096);
    const auto src     = make_file("orig.bin", content);
    const auto packed  = p("orig.sfc");
    const auto unpacked = p("out.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string(), "--algo", "zstd"}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, RoundTrip_Brotli) {
    const auto content = iota_bytes(4096, 0xAB);
    const auto src     = make_file("orig.bin", content);
    const auto packed  = p("orig.sfc");
    const auto unpacked = p("out.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string(), "--algo", "brotli"}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, RoundTrip_Lz4) {
    const auto content = iota_bytes(4096, 0x55);
    const auto src     = make_file("orig.bin", content);
    const auto packed  = p("orig.sfc");
    const auto unpacked = p("out.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string(), "--algo", "lz4"}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, RoundTrip_None) {
    const auto content  = iota_bytes(1024);
    const auto src      = make_file("orig.bin", content);
    const auto packed   = p("orig.sfc");
    const auto unpacked = p("out.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string(), "--algo", "none"}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, RoundTrip_EmptyContent) {
    const auto src      = make_file("empty.bin", std::vector<uint8_t>{});
    const auto packed   = p("empty.sfc");
    const auto unpacked = p("out.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_TRUE(slurp_bytes(unpacked).empty());
}

TEST_F(CliTest, RoundTrip_LargeFile) {
    // 512 KB — exercises multi-chunk behaviour.
    const auto content  = iota_bytes(512 * 1024);
    const auto src      = make_file("large.bin", content);
    const auto packed   = p("large.sfc");
    const auto unpacked = p("out.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, RoundTrip_UnpackToStdout) {
    // When -o is omitted unpack writes to stdout.
    const std::string content = "stdout test content";
    const auto src     = make_file("t.bin", content);
    const auto packed  = p("t.sfc");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);

    auto r = sfc({"unpack", packed.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.out, content);
}

TEST_F(CliTest, RoundTrip_StdinToPack) {
    // sfc pack - -o out.sfc reads from stdin.
    const std::string content = "piped content";
    const auto stdin_file = make_file("input.txt", content);
    const auto packed     = p("out.sfc");
    const auto unpacked   = p("recovered.bin");

    ASSERT_EQ(sfc_stdin(stdin_file, {"pack", "-", "-o", packed.string()}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp(unpacked), content);
}

// ===========================================================================
// info
// ===========================================================================

TEST_F(CliTest, InfoShowsFields) {
    const auto src    = make_file("sample.txt", "info test");
    const auto packed = p("sample.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);

    auto r = sfc({"info", packed.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.out.find("UUID"),      std::string::npos);
    EXPECT_NE(r.out.find("Profile"),   std::string::npos);
    EXPECT_NE(r.out.find("Algo"),      std::string::npos);
    EXPECT_NE(r.out.find("Filename"),  std::string::npos);
    EXPECT_NE(r.out.find("Timestamp"), std::string::npos);
    EXPECT_NE(r.out.find("Trailer"),   std::string::npos);
}

TEST_F(CliTest, InfoFilenameStored) {
    const auto src    = make_file("myfile.txt", "data");
    const auto packed = p("out.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);

    auto r = sfc({"info", packed.string()});
    EXPECT_EQ(r.exit_code, 0);
    // Inner filename should be "myfile.txt".
    EXPECT_NE(r.out.find("myfile.txt"), std::string::npos);
}

TEST_F(CliTest, InfoMultipleFiles) {
    const auto s1 = make_file("a.txt", "aaa");
    const auto s2 = make_file("b.txt", "bbb");
    const auto p1 = p("a.sfc");
    const auto p2 = p("b.sfc");
    ASSERT_EQ(sfc({"pack", s1.string(), "-o", p1.string()}).exit_code, 0);
    ASSERT_EQ(sfc({"pack", s2.string(), "-o", p2.string()}).exit_code, 0);

    auto r = sfc({"info", p1.string(), p2.string()});
    EXPECT_EQ(r.exit_code, 0);
    // Both filenames must appear as section headers.
    EXPECT_NE(r.out.find(p1.filename().string()), std::string::npos);
    EXPECT_NE(r.out.find(p2.filename().string()), std::string::npos);
}

TEST_F(CliTest, InfoMissingFile) {
    auto r = sfc({"info", p("ghost.sfc").string()});
    EXPECT_NE(r.exit_code, 0);
}

// ===========================================================================
// verify
// ===========================================================================

TEST_F(CliTest, VerifyValidFile) {
    const auto src    = make_file("v.bin", iota_bytes(1024));
    const auto packed = p("v.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);

    auto r = sfc({"verify", packed.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.out.find("OK"), std::string::npos);
}

TEST_F(CliTest, VerifyCorruptFile) {
    // Pack, then flip a byte deep in the payload, expect non-zero exit.
    const auto content = iota_bytes(8192);
    const auto src     = make_file("data.bin", content);
    const auto packed  = p("data.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string(), "--algo", "none"}).exit_code, 0);

    // Flip a byte at offset 512 — well inside the chunk payload region.
    {
        std::fstream f(packed, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(512);
        char c{};
        f.get(c);
        f.seekp(512);
        f.put(static_cast<char>(c ^ 0xFF));
    }

    auto r = sfc({"verify", packed.string()});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, VerifyMissingFile) {
    auto r = sfc({"verify", p("missing.sfc").string()});
    EXPECT_NE(r.exit_code, 0);
}

// ===========================================================================
// P2 split: pack -n, segment naming, verify, unpack with RS recovery
// ===========================================================================

TEST_F(CliTest, SplitSegmentNaming) {
    // 3 segments → base-01.sfc, base-02.sfc, base-03.sfc.
    // Use s=1024 so 3000 bytes → 3 data chunks → 3 segments (no capping).
    const auto src = make_file("data.bin", iota_bytes(3000));
    const auto out = p("archive.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(), "-n", "3", "-s", "1024"}).exit_code, 0);

    EXPECT_TRUE(fs::exists(p("archive-01.sfc")));
    EXPECT_TRUE(fs::exists(p("archive-02.sfc")));
    EXPECT_TRUE(fs::exists(p("archive-03.sfc")));
    EXPECT_FALSE(fs::exists(out));  // base path must NOT be created
}

TEST_F(CliTest, SplitVerifyAllSegments) {
    // 4096 bytes / s=1024 = 4 data chunks + M=1 parity = 5 total → n=5 segments (1 chunk each).
    const auto src = make_file("data.bin", iota_bytes(4096));
    const auto out = p("split.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    auto r = sfc({"verify",
                  p("split-01.sfc").string(),
                  p("split-02.sfc").string(),
                  p("split-03.sfc").string(),
                  p("split-04.sfc").string(),
                  p("split-05.sfc").string()});
    EXPECT_EQ(r.exit_code, 0);
}

TEST_F(CliTest, SplitUnpackAllSegments) {
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("split.sfc");
    const auto unpacked = p("recovered.bin");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    ASSERT_EQ(sfc({"unpack",
                   p("split-01.sfc").string(),
                   p("split-02.sfc").string(),
                   p("split-03.sfc").string(),
                   p("split-04.sfc").string(),
                   p("split-05.sfc").string(),
                   "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, SplitRSRecovery_DropOneWithinBudget) {
    // 4 data chunks + 1 parity = 5 segments (1 chunk each) with --algo none.
    // Dropping 1 segment = 1 missing chunk, within M=1 budget.
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("rs.sfc");
    const auto unpacked = p("recovered.bin");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    // Provide 4 of 5 segments (drop the middle one).
    ASSERT_EQ(sfc({"unpack",
                   p("rs-01.sfc").string(),
                   p("rs-02.sfc").string(),
                   p("rs-04.sfc").string(),
                   p("rs-05.sfc").string(),
                   "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, SplitRSRecovery_DropTwoExceedsBudget) {
    // M=1 → can only recover 1 loss. Dropping 2 segments (= 2 chunks) must fail.
    const auto content = iota_bytes(4096);
    const auto src     = make_file("data.bin", content);
    const auto out     = p("rs2.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    // Provide only 3 of 5 segments → 2 chunks missing, exceeds M=1.
    // verify reports degraded (exit 2); unpack refuses partial (exit 1).
    auto rv = sfc({"verify",
                   p("rs2-01.sfc").string(),
                   p("rs2-03.sfc").string(),
                   p("rs2-05.sfc").string()});
    EXPECT_NE(rv.exit_code, 0);

    auto ru = sfc({"unpack",
                   p("rs2-01.sfc").string(),
                   p("rs2-03.sfc").string(),
                   p("rs2-05.sfc").string(),
                   "-o", p("out.bin").string()});
    EXPECT_NE(ru.exit_code, 0);
}

// ===========================================================================
// repair
// ===========================================================================

TEST_F(CliTest, RepairFullRecovery) {
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("split.sfc");
    const auto repaired = p("repaired.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    auto r = sfc({"repair",
                  p("split-01.sfc").string(),
                  p("split-02.sfc").string(),
                  p("split-03.sfc").string(),
                  p("split-04.sfc").string(),
                  p("split-05.sfc").string(),
                  "-o", repaired.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(slurp_bytes(repaired), content);
}

TEST_F(CliTest, RepairWithOneDroppedSegment) {
    // Drop 1 of 5 segments (1 chunk missing, within M=1 budget): repair exits 0.
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("split.sfc");
    const auto repaired = p("repaired.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    auto r = sfc({"repair",
                  p("split-01.sfc").string(),
                  p("split-02.sfc").string(),
                  p("split-04.sfc").string(),
                  p("split-05.sfc").string(),
                  "-o", repaired.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(slurp_bytes(repaired), content);
}

TEST_F(CliTest, RepairPartialResult_ExitsTwo) {
    // Drop 2 of 5 segments (2 chunks missing, exceeds M=1): repair exits 2 (partial).
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("split.sfc");
    const auto repaired = p("repaired.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    // Provide only 3 of 5 segments; 2 data chunks are unrecoverable.
    auto r = sfc({"repair",
                  p("split-01.sfc").string(),
                  p("split-03.sfc").string(),
                  p("split-05.sfc").string(),
                  "-o", repaired.string()});
    EXPECT_EQ(r.exit_code, 2);
    EXPECT_TRUE(fs::exists(repaired));
}

// ===========================================================================
// P5 directory round-trip
// ===========================================================================

TEST_F(CliTest, DirectoryRoundTrip) {
    // Build a small directory tree.
    const auto dir = p("mydir");
    make_file("mydir/a.txt",    "alpha content");
    make_file("mydir/b.txt",    "beta content");
    make_file("mydir/sub/c.txt", "deep content");

    const auto packed  = p("mydir.sfc");
    const auto out_dir = p("unpacked");

    ASSERT_EQ(sfc({"pack", dir.string(), "-o", packed.string()}).exit_code, 0);
    EXPECT_TRUE(fs::exists(packed));

    ASSERT_EQ(sfc({"verify", packed.string()}).exit_code, 0);

    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", out_dir.string()}).exit_code, 0);

    EXPECT_EQ(slurp(out_dir / "a.txt"),    "alpha content");
    EXPECT_EQ(slurp(out_dir / "b.txt"),    "beta content");
    EXPECT_EQ(slurp(out_dir / "sub/c.txt"), "deep content");
}

TEST_F(CliTest, DirectoryRoundTrip_BinaryFiles) {
    // Verify binary content is preserved through directory packing.
    const auto content_a = iota_bytes(1024);
    const auto content_b = iota_bytes(2048, 0x80);
    const auto dir       = p("bindir");

    make_file("bindir/a.bin", content_a);
    make_file("bindir/b.bin", content_b);

    const auto packed  = p("bindir.sfc");
    const auto out_dir = p("unpacked");

    ASSERT_EQ(sfc({"pack", dir.string(), "-o", packed.string()}).exit_code, 0);
    ASSERT_EQ(sfc({"unpack", packed.string(), "-o", out_dir.string()}).exit_code, 0);

    EXPECT_EQ(slurp_bytes(out_dir / "a.bin"), content_a);
    EXPECT_EQ(slurp_bytes(out_dir / "b.bin"), content_b);
}

TEST_F(CliTest, DirectorySplitRoundTrip) {
    // Use 2 KB files so the directory blob spans multiple chunks at s=1024,
    // allowing the split into 2 real segments (no capping).
    const auto cx = iota_bytes(2048, 0x11);
    const auto cy = iota_bytes(2048, 0x22);
    make_file("d/x.bin", cx);
    make_file("d/y.bin", cy);

    const auto packed  = p("d.sfc");
    const auto out_dir = p("out");

    ASSERT_EQ(sfc({"pack", p("d").string(), "-o", packed.string(), "-n", "2", "-s", "1024", "--algo", "none"}).exit_code, 0);
    EXPECT_TRUE(fs::exists(p("d-01.sfc")));
    EXPECT_TRUE(fs::exists(p("d-02.sfc")));

    ASSERT_EQ(sfc({"unpack",
                   p("d-01.sfc").string(),
                   p("d-02.sfc").string(),
                   "-o", out_dir.string()}).exit_code, 0);

    EXPECT_EQ(slurp_bytes(out_dir / "x.bin"), cx);
    EXPECT_EQ(slurp_bytes(out_dir / "y.bin"), cy);
}

// ===========================================================================
// P2 auto-discovery: pass one segment, tool finds the rest
// ===========================================================================

TEST_F(CliTest, AutoDiscover_UnpackFromOneSegment) {
    // Pack into 5 segments; verify and unpack with only the first segment path.
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("arc.sfc");
    const auto unpacked = p("recovered.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    // Pass only segment 01 — tool should discover 02–05 automatically.
    ASSERT_EQ(sfc({"unpack", p("arc-01.sfc").string(),
                   "-o", unpacked.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

TEST_F(CliTest, AutoDiscover_VerifyFromOneSegment) {
    const auto src = make_file("data.bin", iota_bytes(4096));
    const auto out = p("arc.sfc");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    auto r = sfc({"verify", p("arc-03.sfc").string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_NE(r.err.find("discovered"), std::string::npos);
}

TEST_F(CliTest, AutoDiscover_RepairFromOneSegment) {
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("arc.sfc");
    const auto repaired = p("repaired.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    ASSERT_EQ(sfc({"repair", p("arc-02.sfc").string(),
                   "-o", repaired.string()}).exit_code, 0);
    EXPECT_EQ(slurp_bytes(repaired), content);
}

TEST_F(CliTest, AutoDiscover_NoTriggerForRegularFile) {
    // A regular (non-P2) file passed alone must not trigger discovery.
    const auto src    = make_file("solo.bin", iota_bytes(512));
    const auto packed = p("solo.sfc");
    ASSERT_EQ(sfc({"pack", src.string(), "-o", packed.string()}).exit_code, 0);

    // verify should work normally — no "discovered" message, exit 0.
    auto r = sfc({"verify", packed.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.err.find("discovered"), std::string::npos);
}

TEST_F(CliTest, AutoDiscover_MultipleInputsNotTriggered) {
    // If multiple files are given explicitly, auto-discovery must not run.
    const auto content  = iota_bytes(4096);
    const auto src      = make_file("data.bin", content);
    const auto out      = p("arc.sfc");
    const auto unpacked = p("recovered.bin");

    ASSERT_EQ(sfc({"pack", src.string(), "-o", out.string(),
                   "-n", "5", "-m", "1", "-s", "1024", "--algo", "none"}).exit_code, 0);

    // Pass all 5 explicitly — no discovery message expected.
    auto r = sfc({"unpack",
                  p("arc-01.sfc").string(), p("arc-02.sfc").string(),
                  p("arc-03.sfc").string(), p("arc-04.sfc").string(),
                  p("arc-05.sfc").string(), "-o", unpacked.string()});
    EXPECT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.err.find("discovered"), std::string::npos);
    EXPECT_EQ(slurp_bytes(unpacked), content);
}

// ===========================================================================
// error handling
// ===========================================================================

TEST_F(CliTest, PackNoArgs) {
    auto r = sfc({"pack"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, UnpackNoArgs) {
    auto r = sfc({"unpack"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, InfoNoArgs) {
    auto r = sfc({"info"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, VerifyNoArgs) {
    auto r = sfc({"verify"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, RepairNoArgs) {
    auto r = sfc({"repair"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, PackBadAlgo) {
    const auto src = make_file("f.bin", "x");
    auto r = sfc({"pack", src.string(), "--algo", "badname"});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, UnpackNotAnSfcFile) {
    // Feed random garbage — decoder must report an error, not crash.
    const auto garbage = make_file("garbage.sfc", iota_bytes(512));
    auto r = sfc({"unpack", garbage.string(), "-o", p("out.bin").string()});
    EXPECT_NE(r.exit_code, 0);
}

TEST_F(CliTest, NoSubcommand) {
    auto r = sfc({});
    EXPECT_NE(r.exit_code, 0);
}
