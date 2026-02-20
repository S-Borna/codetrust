# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Enterprise-grade file and structure rules for repository validation."""

# Files that MUST exist in a production repository
REQUIRED_FILES: list[str] = [
    "README.md",
    ".gitignore",
    "LICENSE",
]

# Files that SHOULD exist (warn if missing, don't block)
RECOMMENDED_FILES: list[str] = [
    "CHANGELOG.md",
    "pyproject.toml",
    "Dockerfile",
    ".env.example",
    "tests/",
]

# Directories that should exist in a well-structured project
RECOMMENDED_DIRS: list[str] = [
    "src",
    "tests",
]

# File patterns that should NOT be committed
FORBIDDEN_PATTERNS: list[str] = [
    ".env",
    "*.pyc",
    "__pycache__",
    "node_modules",
    ".DS_Store",
    "*.secret",
    "*.pem",
    "*.key",
]
