/// @file main.cpp
/// @brief sfc CLI entry point - command dispatch via CLI11.

#include "cmd_info.h"
#include "cmd_pack.h"
#include "cmd_repair.h"
#include "cmd_unpack.h"
#include "cmd_verify.h"

#include <CLI/CLI.hpp>
#include <print>
#include <string>

int main(int argc, char** argv) {
    CLI::App app{"SFC — Self-Describing Resilient Container tool"};
    app.require_subcommand(1);
    app.set_help_flag("-h,--help", "Show help and exit");
    app.set_version_flag("--version", "sfc 0.1.0");

    // -- Core commands ---------------------------------------------------------
    setup_pack(app);
    setup_unpack(app);
    setup_info(app);
    setup_verify(app);
    setup_repair(app);

    // -- version subcommand ----------------------------------------------------
    app.add_subcommand("version", "Print version and exit")
        ->callback([] { std::println("sfc 0.1.0"); });

    // -- help subcommand -------------------------------------------------------
    std::string help_topic;
    auto* help_cmd = app.add_subcommand("help", "Show help for a command");
    help_cmd->add_option("command", help_topic, "Command name")->required(false);
    help_cmd->callback([&] {
        if (help_topic.empty()) {
            std::println("sfc 0.1.0 — Self-Describing Resilient Container tool");
            std::println("");
            std::println("Usage: sfc <command> [options]");
            std::println("");
            std::println("Commands:");
            std::println("  pack     Pack a file or directory into an SFC container");
            std::println("  unpack   Unpack SFC container(s) to a file or directory");
            std::println("  info     Display container metadata without extracting");
            std::println("  verify   Validate integrity without extracting content");
            std::println("  repair   Best-effort recovery — accepts partial reassembly");
            std::println("  version  Print version and exit");
            std::println("  help     Show help for a command");
            std::println("");
            std::println("Run `sfc help <command>` or `sfc <command> --help` for details.");
            return;
        }
        // Look up the named subcommand.
        CLI::App* sub = nullptr;
        for (auto* s : app.get_subcommands({})) {
            if (s->get_name() == help_topic) { sub = s; break; }
        }
        if (sub) {
            std::print("{}", sub->help());
        } else {
            std::println(stderr, "sfc help: unknown command '{}'", help_topic);
            std::exit(1);
        }
    });

    // -- Parse -----------------------------------------------------------------
    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        std::exit(app.exit(e));
    } catch (const std::exception& e) {
        std::println(stderr, "sfc: {}", e.what());
        std::exit(1);
    }

    return 0;
}
