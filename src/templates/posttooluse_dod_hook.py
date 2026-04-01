#!/usr/bin/env python3
# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""PostToolUse hook — Definition of Done enforcement on completion claims.

Triggers AFTER agent output. If the output contains completion markers
(done, klar, complete, leverans, all tests pass, etc.), runs codetrust dod.
If DoD fails, the agent sees the failure report before presenting to the user.

Install: copy to ~/.claude/hooks/codetrust_dod_hook.py
Register in ~/.claude/settings.json under hooks.PostToolUse
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# ── Completion markers that trigger DoD ────────────────────────────

_COMPLETION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\bleveran[st]", re.IGNORECASE),
    re.compile(r"\bklar[t]?\b", re.IGNORECASE),
    re.compile(r"\bdone\b", re.IGNORECASE),
    re.compile(r"\bcomplete[d]?\b", re.IGNORECASE),
    re.compile(r"\ball\s+checks\s+pass", re.IGNORECASE),
    re.compile(r"\ball\s+tests?\s+pass", re.IGNORECASE),
    re.compile(r"allt\s+fungerar", re.IGNORECASE),
    re.compile(r"everything\s+works", re.IGNORECASE),
    re.compile(r"acceptance\s+gate.*pass", re.IGNORECASE),
    re.compile(r"[\u2705].*(?:pass|klar|done|complete)", re.IGNORECASE),
]


def _has_completion_claim(text: str) -> bool:
    """Check if text contains any completion markers."""
    return any(p.search(text) for p in _COMPLETION_PATTERNS)


def _find_workspace() -> Path:
    """Find the workspace root by looking for .codetrust/ directory."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        if (parent / ".codetrust").is_dir():
            return parent
    return cwd


def main() -> int:
    """PostToolUse hook entry point.

    Reads agent output from stdin (JSON with tool result).
    If output contains completion markers, runs codetrust dod.
    Returns 0 always (PostToolUse hooks are informational, not blocking).
    """
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return 0

        data = json.loads(raw)
        # PostToolUse hooks receive the tool result
        result_text = str(data.get("tool_result", ""))

        if not _has_completion_claim(result_text):
            return 0

        # Completion claim detected — run DoD
        workspace = _find_workspace()
        dod_path = workspace / ".codetrust" / "definition_of_done.toml"
        if not dod_path.is_file():
            return 0

        dod_result = subprocess.run(
            [sys.executable, "-m", "src.cli", "dod"],
            capture_output=True,
            text=True,
            timeout=600,
            cwd=str(workspace),
        )

        if dod_result.returncode != 0:
            # DoD failed — output the report so the agent sees it
            sys.stderr.write(
                "\n╔══════════════════════════════════════════════════╗\n"
                "║  DoD FAILED — Do not claim work is complete.     ║\n"
                "╚══════════════════════════════════════════════════╝\n\n"
            )
            sys.stderr.write(dod_result.stdout)
            sys.stderr.write(
                "\nFix all failing checks before claiming done.\n"
            )

    except json.JSONDecodeError:
        pass
    except (subprocess.TimeoutExpired, OSError):
        pass

    # PostToolUse hooks return 0 — they are informational
    return 0


if __name__ == "__main__":
    sys.exit(main())
