/// @file cmd_info.cpp
/// @brief `sfc info` — display container metadata without extracting.

#include "cmd_info.h"
#include "utils.h"

#include "sfc/tlv.h"
#include "sfc/trailer.h"

#include <CLI/CLI.hpp>
#include <memory>
#include <print>
#include <string>
#include <vector>

void setup_info(CLI::App& app) {
    auto* cmd = app.add_subcommand("info",
        "Display container metadata without extracting");
    cmd->usage("sfc info <input>...");

    struct Opts { std::vector<std::string> inputs; };
    auto opts = std::make_shared<Opts>();

    cmd->add_option("inputs", opts->inputs, "One or more .sfc files")
        ->required()
        ->type_name("FILE...");

    cmd->callback([opts] {
        bool any_error = false;

        for (const auto& path : opts->inputs) {
            // ── Load file ─────────────────────────────────────────────────
            std::vector<uint8_t> data;
            try {
                data = cli::read_file(path);
            } catch (const std::exception& e) {
                std::println(stderr, "{}: {}", path, e.what());
                any_error = true;
                continue;
            }

            // ── Parse global header ───────────────────────────────────────
            auto hdr = cli::parse_header_from_file(data);
            if (!hdr) {
                std::println(stderr, "{}: {}", path, hdr.error().detail);
                any_error = true;
                continue;
            }

            // ── Check for segment header (P2) ─────────────────────────────
            auto seg = cli::parse_segment_hdr_from_file(data);

            // ── Print ─────────────────────────────────────────────────────
            if (opts->inputs.size() > 1) std::println("── {} ──", path);

            std::println("File:       {}", path);
            std::println("UUID:       {}", cli::format_uuid(hdr->uuid));
            std::println("Version:    {}.{}", 1, 8);  // from preamble, hardcode spec version

            // Profile line: show segment info for P2
            if (seg) {
                std::println("Profile:    {} [segment {}/{}{}]",
                             cli::profile_name(hdr->flags),
                             seg->segment_index + 1,
                             seg->total_count,
                             seg->is_terminal ? ", terminal" : "");
            } else {
                std::println("Profile:    {}", cli::profile_name(hdr->flags));
            }

            std::println("N / M / S:  {} / {} / {}", hdr->n, hdr->m, hdr->s);
            std::println("Algo:       {}  ·  {}",
                         cli::compression_algo_name(hdr->compression_algo),
                         hdr->erasure_algo == 0x01 ? "RS-GF2^16" : "none");

            const std::string fname = cli::inner_filename_str(hdr->inner_filename);
            std::println("Filename:   {}", fname.empty() ? "(none)" : fname);
            std::println("Format ID:  {:#06x}  ({})",
                         hdr->inner_format_id,
                         cli::format_id_name(hdr->inner_format_id));
            std::println("Inner size: {} bytes", hdr->inner_file_size);
            std::println("Flags:      {:#06x}", hdr->flags);

            // Trailer: parse from last 64 bytes (if present).
            uint64_t timestamp = 0;
            bool has_trailer = false;
            if (data.size() >= 64) {
                auto tr = sfc::parse_trailer(
                    std::span<const uint8_t, 64>{data.data() + data.size() - 64, 64});
                if (tr) {
                    has_trailer = true;
                    timestamp   = tr->timestamp;
                }
            }
            std::println("Timestamp:  {}", cli::format_timestamp(timestamp));
            std::println("Trailer:    {}", has_trailer ? "present" : "absent");

            // Metadata TLV fields (0x0100–0x0104): display if present.
            auto get_meta = [&](uint16_t tag) -> std::string {
                for (const auto& f : hdr->tlv_fields) {
                    if (f.tag == tag)
                        return std::string(f.value.begin(), f.value.end());
                }
                return {};
            };
            const auto author      = get_meta(sfc::TlvTag::kAuthor);
            const auto description = get_meta(sfc::TlvTag::kDescription);
            const auto location    = get_meta(sfc::TlvTag::kLocation);
            const auto software    = get_meta(sfc::TlvTag::kSoftware);
            const auto comment     = get_meta(sfc::TlvTag::kComment);
            if (!author.empty() || !description.empty() || !location.empty() ||
                !software.empty() || !comment.empty()) {
                std::println("──");
                if (!author.empty())      std::println("Author:     {}", author);
                if (!description.empty()) std::println("Desc:       {}", description);
                if (!location.empty())    std::println("Location:   {}", location);
                if (!software.empty())    std::println("Software:   {}", software);
                if (!comment.empty())     std::println("Comment:    {}", comment);
            }

            if (opts->inputs.size() > 1) std::println("");
        }

        if (any_error) std::exit(1);
    });
}
