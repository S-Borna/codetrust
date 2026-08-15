#!/usr/bin/env python3
# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""CodeTrust File Write Hook for Claude Code.

PreToolUse hook that validates Write/Edit/MultiEdit operations.
Prevents the AI agent from modifying its own governance configuration
and blocks writes containing hardcoded secrets.

Installed by: codetrust init
Location: ~/.claude/hooks/codetrust_file_write_hook.py

Exit 0 = allow, Exit 2 = block (stderr shown as error).

Standalone — no dependencies beyond Python 3.8+ stdlib.
"""

from __future__ import annotations

import json
import re
import sys

# ── Protected paths (AI must not modify its own governance) ────────────────────

PROTECTED_PATH_PATTERNS: list = [
    (
        "selfprotect_claude_settings",
        re.compile(r"\.claude/settings\.json$"),
        "AI agent cannot modify its own Claude Code settings.",
    ),
    (
        "selfprotect_claude_hooks",
        re.compile(r"\.claude/hooks/"),
        "AI agent cannot modify its own security hooks.",
    ),
    (
        "selfprotect_codetrust_toml",
        re.compile(r"\.codetrust\.toml$"),
        "AI agent cannot modify CodeTrust governance configuration.",
    ),
    (
        "selfprotect_codetrust_policy",
        re.compile(r"\.codetrust/policy-integrity\.json$"),
        "AI agent cannot modify the policy integrity manifest.",
    ),
    (
        "selfprotect_codetrust_audit",
        re.compile(r"\.codetrust/audit\.jsonl$"),
        "AI agent cannot modify the audit log.",
    ),
    (
        "selfprotect_env_production",
        re.compile(r"\.env\.production$"),
        "AI agent cannot modify production environment files.",
    ),
    (
        "selfprotect_ssh_dir",
        re.compile(r"\.ssh/"),
        "AI agent cannot write to SSH directory.",
    ),
    (
        "selfprotect_aws_dir",
        re.compile(r"\.aws/"),
        "AI agent cannot write to AWS credentials directory.",
    ),
    (
        "selfprotect_gcloud_dir",
        re.compile(r"\.config/gcloud/"),
        "AI agent cannot write to gcloud configuration directory.",
    ),
    (
        "selfprotect_kube_dir",
        re.compile(r"\.kube/"),
        "AI agent cannot write to Kubernetes configuration directory.",
    ),
    (
        "selfprotect_precommit_hook",
        re.compile(r"(?:hooks/(?:pre-commit|codetrust_pre_commit\.py)|\.git/hooks/pre-commit)$"),
        "AI agent cannot modify pre-commit hooks.",
    ),
    (
        "selfprotect_claude_md",
        re.compile(r"CLAUDE\.md$"),
        "AI agent cannot modify CLAUDE.md governance rules.",
    ),
    (
        "selfprotect_governance_manifest",
        re.compile(r"\.codetrust/governance-manifest\.json$"),
        "AI agent cannot modify the governance integrity manifest.",
    ),
    (
        "selfprotect_definition_of_done",
        re.compile(r"\.codetrust/definition_of_done\.toml$"),
        "AI agent cannot modify Definition of Done acceptance criteria.",
    ),
]

# ── Content rules (detect hardcoded secrets) ───────────────────────────────────

SECRET_PATTERNS: list = [
    (
        "secret_api_key_assignment",
        re.compile(
            r"""(?:API_KEY|SECRET_KEY|PRIVATE_KEY|AUTH_TOKEN|ACCESS_TOKEN)"""
            r"""\s*[=:]\s*['"][A-Za-z0-9+/=_-]{16,}['"]"""
        ),
        "Hardcoded API key or secret detected. Use environment variables.",
    ),
    (
        "secret_password_assignment",
        re.compile(
            r"""(?:PASSWORD|PASSWD|DB_PASS|MYSQL_PASSWORD|POSTGRES_PASSWORD)"""
            r"""\s*[=:]\s*['"][^'"]{4,}['"]"""
        ),
        "Hardcoded password detected. Use environment variables.",
    ),
    (
        "secret_aws_key",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS access key ID detected. Use environment variables or IAM roles.",
    ),
    (
        "secret_github_token",
        re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        "GitHub token detected. Use environment variables.",
    ),
    (
        "secret_stripe_key",
        re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}"),
        "Stripe key detected. Use environment variables.",
    ),
    (
        "secret_jwt_token",
        re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
        "JWT token detected in file content. Use environment variables.",
    ),
]


def check_file_path(file_path: str) -> tuple | None:
    """Check if file path is protected. Returns (rule_id, message) or None."""
    for rule_id, pattern, message in PROTECTED_PATH_PATTERNS:
        if pattern.search(file_path):
            return (rule_id, message)
    return None


def check_content(content: str) -> tuple | None:
    """Check file content for hardcoded secrets. Returns (rule_id, message) or None."""
    for rule_id, pattern, message in SECRET_PATTERNS:
        if pattern.search(content):
            return (rule_id, message)
    return None


def main() -> int:
    """Read tool input from stdin, validate file path and content."""
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0

        data = json.loads(raw)

        tool_input = data.get("tool_input", {})
        inner = tool_input if isinstance(tool_input, dict) and tool_input else data

        file_path = inner.get("file_path", "")

        # Check protected paths
        if file_path:
            result = check_file_path(file_path)
            if result is not None:
                rule_id, message = result
                sys.stderr.write(
                    f"\n\u2554\u2550\u2550 CodeTrust Self-Protection BLOCK \u2550\u2550\u2557\n"
                    f"\u2551 Rule: {rule_id}\n"
                    f"\u2551 Path: {file_path}\n"
                    f"\u2551 {message}\n"
                    f"\u2551 Suggestion: Ask the user to make this change manually.\n"
                    f"\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
                )
                return 2

        # Check content for secrets (Write=content, Edit=new_string)
        content = inner.get("content", "") or inner.get("new_string", "")
        if content:
            result = check_content(content)
            if result is not None:
                rule_id, message = result
                sys.stderr.write(
                    f"\n\u2554\u2550\u2550 CodeTrust Secret Detection BLOCK \u2550\u2550\u2557\n"
                    f"\u2551 Rule: {rule_id}\n"
                    f"\u2551 {message}\n"
                    f"\u2551 Suggestion: Use environment variables or a secrets manager.\n"
                    f"\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d\n"
                )
                return 2

    except json.JSONDecodeError:
        return 0
    except Exception:
        # Hook must not crash — fail open
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
