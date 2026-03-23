# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary - see LICENSE for terms.
"""CodeTrust Shell Wrapper - intercepts commands before execution.

This script replaces the shell binary in IDE configurations.
Every command passes through Gateway validation before reaching
the real shell. BLOCK verdicts prevent execution entirely.

Usage (not called directly - configured as IDE shell):
    codetrust-shell -c "rm -rf /"
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

import structlog

# Shield paths
SHIELD_DIR = Path.home() / ".codetrust" / "shield"
AUDIT_FILE = SHIELD_DIR / "audit.jsonl"

logger = structlog.get_logger()

# Trivial commands that skip validation entirely
_TRIVIAL_PREFIXES: tuple[str, ...] = (
    "cd ", "echo ", "true", "false", "exit", "pwd",
    "whoami", "date", "which ", "type ", "alias ",
)

# Verdict constants
_VERDICT_BLOCK = "BLOCK"
_VERDICT_WARN = "WARN"


def _get_original_shell() -> str:
    """Read the backed-up original shell path."""
    backup = SHIELD_DIR / "original-shell.txt"
    if backup.exists():
        return backup.read_text().strip()
    return os.environ.get("SHELL", "/bin/bash")


def _validate_command(cmd: str) -> dict[str, str]:
    """Validate a command through the Gateway CommandInterceptor.

    Uses in-process import for speed (no subprocess overhead).
    Falls back to ALLOW if Gateway is unavailable.
    """
    try:
        from src.gateway.interceptor import CommandInterceptor

        interceptor = CommandInterceptor()
        result = interceptor.check_terminal(cmd)
        return result.to_dict()
    except (ImportError, OSError, ValueError) as exc:
        logger.warning("shield_gateway_unavailable", error=str(exc))
        return {
            "verdict": "ALLOW",
            "rule_id": "shield_fallback",
            "message": "Gateway unavailable - allowing",
            "suggestion": "",
        }


def _audit_log(cmd: str, verdict: dict[str, str]) -> None:
    """Append to Shield audit log (JSONL)."""
    SHIELD_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(tz=UTC).isoformat(),
        "source": "shield",
        "command": cmd[:500],
        "verdict": verdict.get("verdict", "UNKNOWN"),
        "rule_id": verdict.get("rule_id", ""),
        "message": verdict.get("message", ""),
    }
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        # Audit logging must never break command execution
        logger.warning("shield_audit_write_error", error=str(exc))


def _handle_block(verdict: dict[str, str]) -> None:
    """Print block message to stderr and exit."""
    sys.stderr.write(
        "\n\033[91mBLOCKED by CodeTrust Shield\033[0m\n"
        f"  Rule: {verdict.get('rule_id', 'unknown')}\n"
        f"  {verdict.get('message', '')}\n"
    )
    suggestion = verdict.get("suggestion", "")
    if suggestion:
        sys.stderr.write(f"  \033[93mSuggestion:\033[0m {suggestion}\n")
    sys.stderr.write(f"  Audit: {AUDIT_FILE}\n")
    sys.exit(1)


def main() -> None:
    """Entry point for codetrust-shell.

    Handles three cases:
    1. Interactive shell (no args) - pass through to real shell
    2. Command execution (-c "cmd") - validate then execute
    3. Script execution (file arg) - pass through to real shell
    """
    original_shell = _get_original_shell()

    # Case 1: Interactive shell or no -c flag
    if len(sys.argv) < 3 or sys.argv[1] != "-c":
        os.execvp(original_shell, [original_shell, *sys.argv[1:]])
        return

    # Case 2: Command execution via -c
    cmd = sys.argv[2]

    # Skip validation for trivial commands
    if cmd.strip().startswith(_TRIVIAL_PREFIXES) or not cmd.strip():
        os.execvp(original_shell, [original_shell, "-c", cmd])
        return

    # Validate through Gateway
    verdict = _validate_command(cmd)
    _audit_log(cmd, verdict)

    if verdict.get("verdict") == _VERDICT_BLOCK:
        _handle_block(verdict)

    if verdict.get("verdict") == _VERDICT_WARN:
        sys.stderr.write(
            f"\033[93mCodeTrust Shield warning:\033[0m"
            f" {verdict.get('message', '')}\n"
        )

    # ALLOW or WARN - execute the real command
    os.execvp(original_shell, [original_shell, "-c", cmd])


if __name__ == "__main__":
    main()
