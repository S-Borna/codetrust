#!/usr/bin/env bash
#
# CodeTrust — Setup Script
# Installs CodeTrust quality gates into the current project.
#
# Usage: bash setup.sh [--mcp] [--hooks] [--claude-md] [--extension] [--action] [--all]
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="$(pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${GREEN}✅ $1${NC}"; }
warn()  { echo -e "${YELLOW}⚠️  $1${NC}"; }
step()  { echo -e "${BLUE}→  $1${NC}"; }

install_claude_md() {
    if [ -f "$TARGET_DIR/CLAUDE.md" ]; then
        warn "CLAUDE.md already exists. Backing up to CLAUDE.md.bak"
        cp "$TARGET_DIR/CLAUDE.md" "$TARGET_DIR/CLAUDE.md.bak"
    fi
    cp "$SCRIPT_DIR/CLAUDE.md" "$TARGET_DIR/CLAUDE.md"

    # Also install .cursorrules for Cursor AI
    if [ -f "$SCRIPT_DIR/.cursorrules" ]; then
        cp "$SCRIPT_DIR/.cursorrules" "$TARGET_DIR/.cursorrules"
        info ".cursorrules installed (Cursor AI enforcement)"
    fi

    info "CLAUDE.md installed with enforcement rules"
}

install_hooks() {
    if [ ! -d "$TARGET_DIR/.git" ]; then
        warn "Not a git repository. Skipping hooks."
        return
    fi

    # Method 1 (recommended): Use core.hooksPath — version-controlled, cannot be deleted
    mkdir -p "$TARGET_DIR/hooks"
    cp "$SCRIPT_DIR/hooks/pre-commit" "$TARGET_DIR/hooks/pre-commit"
    chmod +x "$TARGET_DIR/hooks/pre-commit"
    git config core.hooksPath hooks
    info "Pre-commit hook installed via core.hooksPath (version-controlled)"

    # Also copy to .git/hooks as fallback
    mkdir -p "$TARGET_DIR/.git/hooks"
    cp "$SCRIPT_DIR/hooks/pre-commit" "$TARGET_DIR/.git/hooks/pre-commit"
    chmod +x "$TARGET_DIR/.git/hooks/pre-commit"
    info "Pre-commit hook also installed in .git/hooks (fallback)"
}

install_extension() {
    step "Building VS Code extension..."
    if [ -d "$SCRIPT_DIR/extension" ]; then
        cd "$SCRIPT_DIR/extension"
        if command -v npm &>/dev/null; then
            npm install --silent 2>/dev/null || true
            npm run compile 2>/dev/null || true
            if command -v npx &>/dev/null; then
                npx @vscode/vsce package --no-dependencies 2>/dev/null || true
                VSIX=$(ls -t *.vsix 2>/dev/null | head -1)
                if [ -n "$VSIX" ] && command -v code &>/dev/null; then
                    code --install-extension "$VSIX" 2>/dev/null || true
                    info "VS Code extension installed: $VSIX"
                else
                    warn "Extension built but could not install. Install manually:"
                    echo "    code --install-extension extension/$VSIX"
                fi
            fi
        else
            warn "npm not found. Install Node.js to build the VS Code extension."
        fi
        cd "$SCRIPT_DIR"
    fi
}

install_action() {
    if [ ! -d "$TARGET_DIR/.github" ]; then
        mkdir -p "$TARGET_DIR/.github/workflows"
    fi
    if [ -f "$SCRIPT_DIR/.github/workflows/codetrust-scan.yml" ]; then
        mkdir -p "$TARGET_DIR/.github/workflows"
        cp "$SCRIPT_DIR/.github/workflows/codetrust-scan.yml" \
           "$TARGET_DIR/.github/workflows/codetrust-scan.yml"
        info "GitHub Action workflow installed"
        echo ""
        echo "  To enable, add these secrets to your GitHub repo:"
        echo "    CODETRUST_API_URL  (default: https://api.codetrust.ai)"
        echo "    CODETRUST_API_KEY  (your API key)"
        echo ""
        echo "  Then enable branch protection to require the CodeTrust check to pass."
    fi
    if [ -d "$SCRIPT_DIR/action" ]; then
        cp -r "$SCRIPT_DIR/action" "$TARGET_DIR/action"
        info "GitHub Action scanner copied to action/"
    fi
}

install_mcp() {
    echo ""
    echo "  To add CodeTrust as an MCP server in Claude Code, add this to:"
    echo "  ~/.claude/claude_desktop_config.json"
    echo ""
    echo '  {'
    echo '    "mcpServers": {'
    echo '      "codetrust": {'
    echo "        \"command\": \"python\","
    echo "        \"args\": [\"-m\", \"src.server\"],"
    echo "        \"cwd\": \"$SCRIPT_DIR\""
    echo '      }'
    echo '    }'
    echo '  }'
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
    echo "  --claude-md   Install CLAUDE.md + .cursorrules"
    echo "  --hooks       Install git hooks (core.hooksPath)"
    echo "  --extension   Build and install VS Code extension"
    echo "  --action      Set up GitHub Action workflow"
    echo "  --mcp         Show MCP server config"
    echo "  --help        Show this help"
    echo ""
    echo "Enforcement layers:"
    echo "  Layer 1: CLAUDE.md / .cursorrules — AI instruction rules"
    echo "  Layer 2: VS Code extension       — real-time diagnostics"
    echo "  Layer 3: Pre-commit hook          — blocks bad commits"
    echo "  Layer 4: GitHub Action            — blocks bad merges"
}

# Default: install everything
if [ $# -eq 0 ]; then
    set -- "--all"
fi

for arg in "$@"; do
    case "$arg" in
        --all)
            echo ""
            echo "🛡️  CodeTrust — Installing all enforcement layers"
            echo ""
            install_claude_md
            install_hooks
            install_extension
            install_action
            install_mcp
            ;;
        --claude-md)  install_claude_md ;;
        --hooks)      install_hooks ;;
        --extension)  install_extension ;;
        --action)     install_action ;;
        --mcp)        install_mcp ;;
        --help)       show_help ;;
        *)            echo "Unknown option: $arg"; show_help; exit 1 ;;
    esac
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
info "CodeTrust setup complete."
echo ""
echo "  Enforcement stack:"
echo "    ✅ CLAUDE.md / .cursorrules — AI follows the rules"
echo "    ✅ VS Code extension        — see problems in real-time"
echo "    ✅ Pre-commit hook           — can't commit bad code"
echo "    ✅ GitHub Action             — can't merge bad code"
echo ""
echo "  To verify: git commit --allow-empty -m 'test codetrust'"
echo ""
