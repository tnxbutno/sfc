/// @file cmd_pack.cpp
/// @brief `sfc pack` — file or directory → SFC container(s).

#include "cmd_pack.h"
#include "utils.h"

#include "sfc/directory.h"
#include "sfc/encoder.h"
#include "sfc/split_encoder.h"

#include <CLI/CLI.hpp>
#include <chrono>
#include <filesystem>
#include <memory>
#include <print>
#include <string>
#include <vector>

void setup_pack(CLI::App& app) {
    auto* cmd = app.add_subcommand("pack", "Pack a file or directory into an SFC container");
    cmd->usage("sfc pack <input> [options]");

    // All option values live in a heap-allocated struct so they outlive setup_pack().
    struct Opts {
        std::string input;
        std::string output;
        uint32_t    segments   = 1;
        uint32_t    recovery   = 0;
        uint32_t    chunk_size = 65536;
        std::string algo_str   = "zstd";
        std::string filename_override;
        std::string format_id_str;
        uint64_t    timestamp  = 0;
        // Metadata fields
        std::string author;
        std::string description;
        std::string location;
        std::string software;
        std::string comment;
    };
    auto opts = std::make_shared<Opts>();

    cmd->add_option("input", opts->input, "Input file, directory, or - for stdin")
        ->required()->type_name("PATH");
    cmd->add_option("-o,--output", opts->output,
                    "Output .sfc path (default: <input>.sfc; for -n>1: base for segments)");
    cmd->add_option("-n,--segments",   opts->segments,   "Split into N P2 segments (default: 1)")
        ->check(CLI::PositiveNumber);
    cmd->add_option("-m,--recovery",   opts->recovery,   "Recovery chunks M (default: 0)");
    cmd->add_option("-s,--chunk-size", opts->chunk_size, "Chunk size bytes — must be even (default: 65536)")
        ->check(CLI::PositiveNumber);
    cmd->add_option("--algo",          opts->algo_str,   "Compression: zstd|brotli|lz4|none (default: zstd)")
        ->check(CLI::IsMember({"zstd", "brotli", "lz4", "none"}));
    cmd->add_option("--filename",      opts->filename_override, "Inner filename stored in container");
    cmd->add_option("--format-id",     opts->format_id_str,     "Inner Format ID hex (e.g. 0x0010)");
    cmd->add_option("--timestamp",     opts->timestamp,         "Unix epoch timestamp (default: now)");
    cmd->add_option("--author",        opts->author,            "Author name (metadata)");
    cmd->add_option("--description",   opts->description,       "Description (metadata)");
    cmd->add_option("--location",      opts->location,          "Location: place name or geo string (metadata)");
    cmd->add_option("--software",      opts->software,          "Creating software name (metadata)");
    cmd->add_option("--comment",       opts->comment,           "Free-form comment (metadata)");

    cmd->callback([opts] {
        const std::string& input = opts->input;

        // ── Resolve output path ───────────────────────────────────────────
        if (opts->output.empty()) {
            if (input == "-") {
                std::println(stderr, "sfc pack: --output required when reading from stdin");
                std::exit(1);
            }
            opts->output = cli::default_output_path(input);
        }
        const std::string& output = opts->output;

        // ── Determine current time if no timestamp provided ───────────────
        const uint64_t ts = (opts->timestamp != 0)
            ? opts->timestamp
            : static_cast<uint64_t>(
                  std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count());

        // ── Build EncodeParams ────────────────────────────────────────────
        sfc::EncodeParams params{
            .m         = opts->recovery,
            .s         = opts->chunk_size,
            .algo      = cli::parse_algo(opts->algo_str),
            .uuid      = cli::generate_uuid(),
            .timestamp = ts,
            .format_id = 0x0001,
            .filename  = "",
            .metadata  = {
                .author      = opts->author,
                .description = opts->description,
                .location    = opts->location,
                .software    = opts->software,
                .comment     = opts->comment,
            },
        };

        // ── Directory input ───────────────────────────────────────────────
        const bool is_dir = (input != "-") && std::filesystem::is_directory(input);

        if (is_dir) {
            std::vector<sfc::DirectoryInputFile> dir_files;
            const std::filesystem::path root(input);

            for (const auto& entry : std::filesystem::recursive_directory_iterator(root)) {
                if (!entry.is_regular_file()) continue;

                std::string rel_str = std::filesystem::relative(
                    entry.path(), root).generic_string();

                const uint16_t fid = opts->format_id_str.empty()
                    ? cli::format_id_from_extension(entry.path())
                    : static_cast<uint16_t>(
                          std::stoul(opts->format_id_str, nullptr, 16));

                dir_files.push_back(sfc::DirectoryInputFile{
                    .path      = std::move(rel_str),
                    .content   = cli::read_file(entry.path().string()),
                    .format_id = fid,
                });
            }

            if (opts->segments > 1) {
                auto result = sfc::encode_directory_split(
                    std::move(dir_files), params, opts->segments);
                if (!result) {
                    std::println(stderr, "sfc pack: {}", result.error().detail);
                    std::exit(1);
                }
                for (uint32_t i = 0; i < static_cast<uint32_t>(result->size()); ++i) {
                    const std::string path = cli::segment_path(
                        output, i, static_cast<uint32_t>(result->size()));
                    cli::write_file(path, (*result)[i]);
                    std::println(stderr, "wrote {}", path);
                }
            } else {
                auto result = sfc::encode_directory(std::move(dir_files), params);
                if (!result) {
                    std::println(stderr, "sfc pack: {}", result.error().detail);
                    std::exit(1);
                }
                cli::write_file(output, *result);
                std::println(stderr, "wrote {}", output);
            }
            return;
        }

        // ── File or stdin input ───────────────────────────────────────────
        std::vector<uint8_t> content =
            (input == "-") ? cli::read_stdin() : cli::read_file(input);

        if (!opts->filename_override.empty()) {
            params.filename = opts->filename_override;
        } else if (input != "-") {
            params.filename = std::filesystem::path(input).filename().string();
        }

        if (!opts->format_id_str.empty()) {
            params.format_id = static_cast<uint16_t>(
                std::stoul(opts->format_id_str, nullptr, 16));
        } else if (input != "-") {
            params.format_id = cli::format_id_from_extension(
                std::filesystem::path(input));
        }

        if (opts->segments > 1) {
            auto result = sfc::encode_split(content, params, opts->segments);
            if (!result) {
                std::println(stderr, "sfc pack: {}", result.error().detail);
                std::exit(1);
            }
            for (uint32_t i = 0; i < static_cast<uint32_t>(result->size()); ++i) {
                const std::string path = cli::segment_path(
                    output, i, static_cast<uint32_t>(result->size()));
                cli::write_file(path, (*result)[i]);
                std::println(stderr, "wrote {}", path);
            }
        } else {
            auto result = sfc::encode(content, params);
            if (!result) {
                std::println(stderr, "sfc pack: {}", result.error().detail);
                std::exit(1);
            }
            if (output == "-") {
                cli::write_stdout(*result);
            } else {
                cli::write_file(output, *result);
                std::println(stderr, "wrote {}", output);
            }
        }
    });
}
