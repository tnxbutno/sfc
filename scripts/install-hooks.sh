#!/usr/bin/env bash
# install-hooks.sh — install git hooks for the sfc project.
#
# Usage: bash scripts/install-hooks.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
HOOKS_DIR="$ROOT/.git/hooks"

if [[ ! -d "$HOOKS_DIR" ]]; then
    echo "Error: .git/hooks directory not found. Are you inside a git repo?"
    exit 1
fi

install_hook() {
    local name="$1"
    local src="$SCRIPT_DIR/$name"
    local dst="$HOOKS_DIR/$name"

    cp "$src" "$dst"
    chmod +x "$dst"
    echo "Installed: $dst"
}

install_hook pre-commit
install_hook pre-push

echo ""
echo "Git hooks installed successfully."
echo ""
echo "The hooks require a configured build directory at ./build."
echo "If you haven't built yet:"
echo "  cmake -S . -B build"
echo "  cmake --build build"
echo ""
echo "Optional tools (install via Homebrew for full lint coverage):"
echo "  brew install llvm          # clang-tidy, clang-format"
echo "  brew install cppcheck"
echo "  brew install include-what-you-use"
