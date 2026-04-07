# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Snapshot-based baseline for first-scan friction reduction.

When a user runs `codetrust scan` for the first time on a project, all existing
findings are saved as a baseline (accepted legacy code). Subsequent scans show
only NEW findings introduced after the baseline was established.

This solves the emotional friction of getting graded on existing code: a
vibe-coder installing CT to protect their AI agent shouldn't be told their
existing 5000-line codebase is 0/100. They should be told "From now on, I'll
catch new issues as you write them."

Storage: .codetrust/baseline.json
Format:
    {
        "version": "1",
        "created": "2026-04-07T20:00:00Z",
        "finding_keys": ["a.py:42:eval_exec", "b.py:15:bare_except", ...],
        "count": 142
    }

Finding key = "<file>:<line>:<rule_id>" — stable identifier for diffing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

BASELINE_FILE = "baseline.json"
BASELINE_FORMAT_VERSION = "1"


def _baseline_path(project_dir: Path) -> Path:
    """Return the baseline file path for a project."""
    return project_dir / ".codetrust" / BASELINE_FILE


def baseline_exists(project_dir: Path) -> bool:
    """Check whether a baseline has been established for this project."""
    return _baseline_path(project_dir).exists()


def finding_key(finding: dict[str, object]) -> str:
    """Compute a stable identifier for a finding.

    Format: '<file>:<line>:<rule_id>'

    Two findings with the same key are considered the same issue, even if
    the message text changes. This makes the baseline robust against minor
    rule message updates.
    """
    file = str(finding.get("file", ""))
    line = finding.get("line", 0)
    rule_id = str(finding.get("rule_id", ""))
    return f"{file}:{line}:{rule_id}"


def save_baseline(
    project_dir: Path,
    findings: list[dict[str, object]],
) -> int:
    """Save findings as the project baseline.

    Args:
        project_dir: Project root.
        findings: All findings to mark as accepted legacy.

    Returns:
        Number of findings saved.

    Raises:
        OSError: If .codetrust/ directory cannot be created or written.
    """
    keys = sorted({finding_key(f) for f in findings})
    payload = {
        "version": BASELINE_FORMAT_VERSION,
        "created": datetime.now(UTC).isoformat(),
        "finding_keys": keys,
        "count": len(keys),
    }
    path = _baseline_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return len(keys)


def load_baseline_keys(project_dir: Path) -> set[str] | None:
    """Load the set of accepted finding keys from the baseline.

    Returns:
        Set of finding keys, or None if no baseline exists.

    Note:
        Returns None on JSON parse errors or schema mismatches — caller
        should treat that as "no baseline" and re-establish.
    """
    path = _baseline_path(project_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        keys = data.get("finding_keys", [])
        if not isinstance(keys, list):
            return None
        return set(str(k) for k in keys)
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def baseline_metadata(project_dir: Path) -> dict[str, object] | None:
    """Return baseline metadata (created, count) without loading all keys.

    Returns:
        Dict with 'created' and 'count', or None if no baseline.
    """
    path = _baseline_path(project_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {
            "created": data.get("created", "unknown"),
            "count": data.get("count", 0),
        }
    except (OSError, json.JSONDecodeError, ValueError):
        return None


def filter_new_findings(
    findings: list[dict[str, object]],
    baseline_keys: set[str],
) -> list[dict[str, object]]:
    """Return only findings whose keys are not in the baseline.

    Args:
        findings: Current scan findings.
        baseline_keys: Set of accepted finding keys from baseline.

    Returns:
        New findings introduced after baseline was established.
    """
    return [f for f in findings if finding_key(f) not in baseline_keys]


def reset_baseline(project_dir: Path) -> bool:
    """Delete the baseline file. Returns True if file existed and was removed."""
    path = _baseline_path(project_dir)
    if not path.exists():
        return False
    path.unlink()
    return True
