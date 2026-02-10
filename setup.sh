#!/usr/bin/env bash
#
# CodeTrust — Setup Script
# Installs CodeTrust quality gates into the current project.
#
# Usage: bash setup.sh [--mcp] [--hooks] [--claude-md] [--all]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$(pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}✅ $1${NC}"; }
warn()  { echo -e "${YELLOW}⚠️  $1${NC}"; }

install_claude_md() {
    if [ -f "$TARGET_DIR/CLAUDE.md" ]; then
        warn "CLAUDE.md already exists. Backing up to CLAUDE.md.bak"
        cp "$TARGET_DIR/CLAUDE.md" "$TARGET_DIR/CLAUDE.md.bak"
    fi
    cp "$SCRIPT_DIR/CLAUDE.md" "$TARGET_DIR/CLAUDE.md"
    info "CLAUDE.md installed"
}

install_hooks() {
    if [ ! -d "$TARGET_DIR/.git" ]; then
        warn "Not a git repository. Skipping hooks."
        return
    fi
    mkdir -p "$TARGET_DIR/.git/hooks"
    cp "$SCRIPT_DIR/hooks/pre-commit" "$TARGET_DIR/.git/hooks/pre-commit"
    chmod +x "$TARGET_DIR/.git/hooks/pre-commit"
    info "Pre-commit hook installed"
}

install_mcp() {
    echo ""
    echo "To add CodeTrust as an MCP server in Claude Code, add this to your"
    echo "Claude Code MCP config (~/.claude/mcp_servers.json or project-level):"
    echo ""
    echo "  {"
    echo "    \"codetrust\": {"
    echo "      \"command\": \"python\","
    echo "      \"args\": [\"$SCRIPT_DIR/src/server.py\"]"
    echo "    }"
    echo "  }"
    echo ""
    info "MCP config instructions printed"
}

show_help() {
    echo "CodeTrust — Setup"
    echo ""
    echo "Usage: bash setup.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all         Install everything (default)"
    echo "  --claude-md   Install CLAUDE.md only"
    echo "  --hooks       Install git hooks only"
    echo "  --mcp         Show MCP server config"
    echo "  --help        Show this help"
}

# Default: install everything
if [ $# -eq 0 ]; then
    set -- "--all"
fi

for arg in "$@"; do
    case "$arg" in
        --all)
            install_claude_md
            install_hooks
            install_mcp
            ;;
        --claude-md)  install_claude_md ;;
        --hooks)      install_hooks ;;
        --mcp)        install_mcp ;;
        --help)       show_help ;;
        *)            echo "Unknown option: $arg"; show_help; exit 1 ;;
    esac
done

echo ""
info "CodeTrust setup complete."
