# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary - see LICENSE for terms.
"""Shield configuration and paths."""

from __future__ import annotations

import os
from pathlib import Path

# Shield runtime directory
SHIELD_DIR = Path.home() / ".codetrust" / "shield"
PID_FILE = SHIELD_DIR / "shield.pid"
LOG_FILE = SHIELD_DIR / "shield.log"
AUDIT_FILE = SHIELD_DIR / "audit.jsonl"
SHELL_WRAPPER_PATH = SHIELD_DIR / "codetrust-shell"
ORIGINAL_SHELL_BACKUP = SHIELD_DIR / "original-shell.txt"

# File watcher config
DEFAULT_WATCH_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".go", ".rs", ".rb", ".php",
    ".java", ".cs", ".cpp", ".c", ".h", ".hpp",
    ".yaml", ".yml", ".toml", ".json", ".env",
    ".tf", ".hcl", ".dockerfile", ".sh", ".bash",
    ".sql", ".graphql", ".proto",
})
IGNORE_DIRS: frozenset[str] = frozenset({
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".mypy_cache", ".ruff_cache", ".pytest_cache", "dist",
    "build", ".eggs", ".tox", ".codetrust",
})

# Scan debounce (ms) - don't re-scan the same file within this window
SCAN_DEBOUNCE_MS: int = 500

# IDE config paths (macOS)
CLAUDE_CODE_CONFIG = Path.home() / ".claude" / "settings.json"
CURSOR_SETTINGS = (
    Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json"
)
VSCODE_SETTINGS = (
    Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json"
)
WINDSURF_SETTINGS = (
    Path.home() / "Library" / "Application Support" / "Windsurf" / "User" / "settings.json"
)


def ensure_shield_dir() -> None:
    """Create Shield runtime directory if it doesn't exist."""
    SHIELD_DIR.mkdir(parents=True, exist_ok=True)


def get_user_shell() -> str:
    """Get the user's default shell."""
    return os.environ.get("SHELL", "/bin/bash")
