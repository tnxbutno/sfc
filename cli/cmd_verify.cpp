/// @file cmd_verify.cpp
/// @brief `sfc verify` - validate integrity without extracting content.
///
/// Exit codes:  0 = fully OK   2 = degraded (partial)   1 = unrecoverable

#include "cmd_verify.h"
#include "utils.h"

#include "sfc/split_decoder.h"

#include <CLI/CLI.hpp>
#include <memory>
#include <print>
#include <string>
#include <unordered_map>
#include <vector>

void setup_verify(CLI::App& app) {
    auto* cmd = app.add_subcommand("verify",
        "Validate integrity without extracting content");
    cmd->usage("sfc verify <input>...");

    struct Opts { std::vector<std::string> inputs; };
    auto opts = std::make_shared<Opts>();

    cmd->add_option("inputs", opts->inputs, "One or more .sfc files or split-transport segments")
        ->required()->type_name("FILE...");

    cmd->callback([opts] {
        // -- Auto-discover split-transport siblings when only one file is given --
        if (opts->inputs.size() == 1) {
            auto siblings = cli::discover_split_siblings(opts->inputs[0]);
            if (siblings.size() > 1) {
                std::println(stderr, "sfc verify: discovered {} segments for {}",
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
                std::println(stderr, "sfc verify: {}", e.what());
                std::exit(1);
            }
        }

        // Build UUID -> first filename map for display labels.
        std::unordered_map<sfc::FileUuid, std::string> uuid_label;
        for (size_t i = 0; i < file_data.size(); ++i) {
            auto hdr = cli::parse_header_from_file(file_data[i]);
            if (hdr && uuid_label.find(hdr->uuid) == uuid_label.end())
                uuid_label[hdr->uuid] = opts->inputs[i];
        }

        auto results = sfc::decode_multi(std::span{file_data});
        if (!results) {
            std::println("{:<50}  FAIL    {}",
                         opts->inputs.size() == 1 ? opts->inputs[0] : "(multiple)",
                         results.error().detail);
            std::exit(1);
        }

        int worst = 0;

        for (const auto& entry : *results) {
            const std::string label = [&] {
                auto it = uuid_label.find(entry.uuid);
                return (it != uuid_label.end()) ? it->second
                                                : cli::format_uuid(entry.uuid);
            }();

            switch (entry.result.status) {
                case sfc::ReassemblyStatus::FullyVerified:
                    std::println("{:<50}  OK      (fully verified)", label);
                    break;
                case sfc::ReassemblyStatus::ContentVerified:
                    std::println("{:<50}  OK      (content verified, trailer absent)", label);
                    break;
                case sfc::ReassemblyStatus::Partial:
                    std::println("{:<50}  DEGRADED  ({} chunk(s) missing)",
                                 label, entry.result.missing_chunks.size());
                    if (worst < 2) worst = 2;
                    break;
            }
        }

        std::exit(worst);
    });
}
