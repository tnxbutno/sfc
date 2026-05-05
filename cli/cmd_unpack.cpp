/// @file cmd_unpack.cpp
/// @brief `sfc unpack` — SFC container(s) → file or directory.

#include "cmd_unpack.h"
#include "utils.h"

#include "sfc/decoder.h"
#include "sfc/directory.h"
#include "sfc/split_decoder.h"

#include <CLI/CLI.hpp>
#include <filesystem>
#include <memory>
#include <print>
#include <string>
#include <unordered_map>
#include <vector>

void setup_unpack(CLI::App& app) {
    auto* cmd = app.add_subcommand("unpack",
        "Unpack SFC container(s) to a file or directory");
    cmd->usage("sfc unpack <input>... [options]");

    struct Opts {
        std::vector<std::string> inputs;
        std::string              output;
    };
    auto opts = std::make_shared<Opts>();

    cmd->add_option("inputs", opts->inputs, "One or more .sfc files or P2 segments")
        ->required()->type_name("FILE...");
    cmd->add_option("-o,--output", opts->output,
        "Output file or directory (default: stdout for files, cwd for directories)");

    cmd->callback([opts] {
        // ── Auto-discover P2 siblings when only one file is given ─────────
        if (opts->inputs.size() == 1) {
            auto siblings = cli::discover_p2_siblings(opts->inputs[0]);
            if (siblings.size() > 1) {
                std::println(stderr, "sfc unpack: discovered {} segments for {}",
                             siblings.size(), opts->inputs[0]);
                opts->inputs = std::move(siblings);
            }
        }

        // ── Load all input files ──────────────────────────────────────────
        std::vector<std::vector<uint8_t>> file_data;
        file_data.reserve(opts->inputs.size());
        for (const auto& path : opts->inputs) {
            try {
                file_data.push_back(cli::read_file(path));
            } catch (const std::exception& e) {
                std::println(stderr, "sfc unpack: {}", e.what());
                std::exit(1);
            }
        }

        // ── Build UUID → header map for profile detection ─────────────────
        std::unordered_map<sfc::FileUuid, sfc::GlobalHeader> hdr_map;
        for (const auto& data : file_data) {
            auto hdr = cli::parse_header_from_file(data);
            if (hdr) hdr_map[hdr->uuid] = *hdr;
        }

        // ── Decode ────────────────────────────────────────────────────────
        auto results = sfc::decode_multi(std::span{file_data});
        if (!results) {
            std::println(stderr, "sfc unpack: {}", results.error().detail);
            std::exit(1);
        }

        const std::string out_dir = opts->output.empty() ? "." : opts->output;

        for (const auto& entry : *results) {
            // Reject partial reassembly — use `repair` for that.
            if (entry.result.status == sfc::ReassemblyStatus::Partial) {
                std::println(stderr,
                    "sfc unpack: UUID {} — partial reassembly. "
                    "Use `sfc repair` to extract what is available.",
                    cli::format_uuid(entry.uuid));
                std::exit(1);
            }

            // ── Detect P5 ─────────────────────────────────────────────────
            const bool p5 = [&] {
                auto it = hdr_map.find(entry.uuid);
                if (it == hdr_map.end()) return false;
                return (it->second.flags &
                        (1u << static_cast<uint16_t>(sfc::FlagBit::P5Directory))) != 0;
            }();

            if (p5) {
                // ── P5 directory ──────────────────────────────────────────
                auto dir = sfc::extract_directory_full(
                    std::span{entry.result.content});
                if (!dir) {
                    std::println(stderr, "sfc unpack: directory extraction failed: {}",
                                 dir.error().detail);
                    std::exit(1);
                }
                // Resolve output root once for path traversal checks.
                const std::filesystem::path canonical_root =
                    std::filesystem::weakly_canonical(out_dir);
                for (const auto& f : dir->files) {
                    const std::filesystem::path dest_path =
                        std::filesystem::weakly_canonical(
                            std::filesystem::path(out_dir) / f.path);
                    // Reject paths that escape the output directory (§4.8 rule d).
                    const std::string dest_str = dest_path.string();
                    const std::string root_str = canonical_root.string();
                    if (dest_str.size() < root_str.size() ||
                        dest_str.substr(0, root_str.size()) != root_str) {
                        std::println(stderr,
                            "sfc unpack: rejected path traversal attempt: {}", f.path);
                        std::exit(1);
                    }
                    try {
                        cli::write_file(dest_str, f.content);
                        std::println(stderr, "extracted {}", dest_str);
                    } catch (const std::exception& e) {
                        std::println(stderr, "sfc unpack: {}", e.what());
                        std::exit(1);
                    }
                }
            } else {
                // ── Regular file ──────────────────────────────────────────
                if (opts->output.empty()) {
                    cli::write_stdout(entry.result.content);
                } else {
                    std::string dest = opts->output;
                    if (results->size() > 1) {
                        const std::filesystem::path p(opts->output);
                        dest = (p.parent_path() /
                                (p.stem().string() + "-" +
                                 cli::format_uuid(entry.uuid).substr(0, 8) +
                                 p.extension().string())).string();
                    }
                    try {
                        cli::write_file(dest, entry.result.content);
                        std::println(stderr, "wrote {}", dest);
                    } catch (const std::exception& e) {
                        std::println(stderr, "sfc unpack: {}", e.what());
                        std::exit(1);
                    }
                }
            }
        }
    });
}
