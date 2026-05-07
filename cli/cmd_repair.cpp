/// @file cmd_repair.cpp
/// @brief `sfc repair` — best-effort recovery; accepts Partial reassembly.
///
/// Exit codes:  0 = fully recovered   2 = partial   1 = unrecoverable

#include "cmd_repair.h"
#include "utils.h"

#include "sfc/directory.h"
#include "sfc/filename_sanitize.h"
#include "sfc/split_decoder.h"

#include <CLI/CLI.hpp>
#include <filesystem>
#include <memory>
#include <print>
#include <string>
#include <unordered_map>
#include <vector>

void setup_repair(CLI::App& app) {
    auto* cmd = app.add_subcommand("repair",
        "Best-effort recovery — accepts partial reassembly");
    cmd->usage("sfc repair <input>... [options]");

    struct Opts {
        std::vector<std::string> inputs;
        std::string              output;
    };
    auto opts = std::make_shared<Opts>();

    cmd->add_option("inputs", opts->inputs, "One or more .sfc files or split-transport segments")
        ->required()->type_name("FILE...");
    cmd->add_option("-o,--output", opts->output,
        "Output file or directory (default: current working directory)");

    cmd->callback([opts] {
        // ── Auto-discover split-transport siblings when only one file is given ──
        if (opts->inputs.size() == 1) {
            auto siblings = cli::discover_split_siblings(opts->inputs[0]);
            if (siblings.size() > 1) {
                std::println(stderr, "sfc repair: discovered {} segments for {}",
                             siblings.size(), opts->inputs[0]);
                opts->inputs = std::move(siblings);
            }
        }

        std::vector<std::vector<uint8_t>> file_data;
        file_data.reserve(opts->inputs.size());
        for (const auto& path : opts->inputs) {
            try {
                file_data.push_back(cli::read_file(path));
            } catch (const std::exception& e) {
                std::println(stderr, "sfc repair: {}", e.what());
                std::exit(1);
            }
        }

        std::unordered_map<sfc::FileUuid, sfc::GlobalHeader> hdr_map;
        std::unordered_map<sfc::FileUuid, std::string>       uuid_label;
        for (size_t i = 0; i < file_data.size(); ++i) {
            auto hdr = cli::parse_header_from_file(file_data[i]);
            if (hdr) {
                hdr_map[hdr->uuid] = *hdr;
                if (uuid_label.find(hdr->uuid) == uuid_label.end())
                    uuid_label[hdr->uuid] = opts->inputs[i];
            }
        }

        auto results = sfc::decode_multi(std::span{file_data});
        if (!results) {
            std::println(stderr, "sfc repair: {}", results.error().detail);
            std::exit(1);
        }

        const std::string out_dir = opts->output.empty() ? "." : opts->output;
        int worst = 0;

        for (const auto& entry : *results) {
            const std::string label = [&] {
                auto it = uuid_label.find(entry.uuid);
                return (it != uuid_label.end()) ? it->second
                                                : cli::format_uuid(entry.uuid);
            }();

            // ── Report ────────────────────────────────────────────────────
            switch (entry.result.status) {
                case sfc::ReassemblyStatus::FullyVerified:
                    std::println(stderr, "{}: fully recovered", label);
                    break;
                case sfc::ReassemblyStatus::ContentVerified:
                    std::println(stderr, "{}: fully recovered (trailer absent)", label);
                    break;
                case sfc::ReassemblyStatus::Partial: {
                    const uint64_t full_size = [&] {
                        auto it = hdr_map.find(entry.uuid);
                        return (it != hdr_map.end()) ? it->second.inner_file_size : 0ULL;
                    }();
                    std::println(stderr, "{}: PARTIAL — {}/{} bytes recovered",
                                 label, entry.result.content.size(), full_size);
                    if (!entry.result.missing_chunks.empty()) {
                        std::print(stderr, "  missing chunks:");
                        for (const auto idx : entry.result.missing_chunks)
                            std::print(stderr, " {}", idx);
                        std::println(stderr, "");
                    }
                    if (worst < 2) worst = 2;
                    break;
                }
            }

            // ── Detect directory profile ───────────────────────────────────
            const bool p5 = [&] {
                auto it = hdr_map.find(entry.uuid);
                if (it == hdr_map.end()) return false;
                return (it->second.flags &
                        (1u << static_cast<uint16_t>(sfc::FlagBit::DirectoryProfile))) != 0;
            }();

            // ── Write output ──────────────────────────────────────────────
            try {
                if (p5) {
                    auto dir = sfc::extract_directory_full(
                        std::span{entry.result.content});
                    if (!dir) {
                        std::println(stderr, "{}: directory extraction failed: {}",
                                     label, dir.error().detail);
                        if (worst < 2) worst = 2;
                    } else {
                        const std::filesystem::path canonical_root =
                            std::filesystem::weakly_canonical(out_dir);
                        for (const auto& f : dir->files) {
                            const std::filesystem::path dest_path =
                                std::filesystem::weakly_canonical(
                                    std::filesystem::path(out_dir) / f.path);
                            const std::string dest_str = dest_path.string();
                            const auto rel = dest_path.lexically_relative(canonical_root);
                            if (rel.empty() || *rel.begin() == "..") {
                                std::println(stderr,
                                    "sfc repair: rejected path traversal: {}", f.path);
                                if (worst < 2) worst = 2;
                                continue;
                            }
                            cli::write_file(dest_str, f.content);
                            std::println(stderr, "  wrote {}", dest_str);
                        }
                        for (const auto& p : dir->pending_paths) {
                            std::println(stderr, "  pending: {}", p);
                            if (worst < 2) worst = 2;
                        }
                    }
                } else {
                    // Derive output filename: sanitize inner filename → UUID prefix fallback.
                    const std::string inner_name = [&] -> std::string {
                        auto it = hdr_map.find(entry.uuid);
                        if (it != hdr_map.end()) {
                            auto san = sfc::sanitize_filename(
                                std::span<const uint8_t, 255>{
                                    it->second.inner_filename.data(), 255});
                            if (san) return *san;
                        }
                        return cli::format_uuid(entry.uuid).substr(0, 8) + ".bin";
                    }();

                    const std::string dest =
                        (results->size() == 1 && !opts->output.empty())
                            ? opts->output
                            : (std::filesystem::path(out_dir) / inner_name).string();

                    cli::write_file(dest, entry.result.content);
                    std::println(stderr, "  wrote {}", dest);
                }
            } catch (const std::exception& e) {
                std::println(stderr, "sfc repair: {}", e.what());
                std::exit(1);
            }
        }

        std::exit(worst);
    });
}
