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
        "count": 142,
        "mode": "full"
    }

Finding key = "<file>:<line>:<rule_id>" — stable identifier for diffing.

``mode`` is one of:
  * ``"full"`` — established with the complete 2,928-rule set
  * ``"reduced"`` — established under reduced mode (15 critical rules only)

Today the CLI refuses to establish a baseline in reduced mode, so every
file in the wild should carry ``"mode": "full"``. The field exists so
we can:
  1. Distinguish legitimate full baselines from older files that lack
     the field (default to "full" for backward compatibility).
  2. Later relax the reduced-mode establishment rule if product
     decisions change, without a schema migration.
  3. Surface the mode in `codetrust baseline status` so users can
     trust what the baseline represents.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

BASELINE_FILE = "baseline.json"
BASELINE_FORMAT_VERSION = "1"
BASELINE_MODE_FULL = "full"
BASELINE_MODE_REDUCED = "reduced"
_VALID_BASELINE_MODES = frozenset({BASELINE_MODE_FULL, BASELINE_MODE_REDUCED})


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
    *,
    mode: str = BASELINE_MODE_FULL,
) -> int:
    """Save findings as the project baseline.

    Args:
        project_dir: Project root.
        findings: All findings to mark as accepted legacy.
        mode: Rule-set mode under which the baseline was established.
            Must be "full" (default, all 2,928 rules) or "reduced"
            (15 critical rules only). The value is persisted so tools
            can distinguish a baseline produced with the full ruleset
            from one produced while quota was exhausted.

    Returns:
        Number of findings saved.

    Raises:
        ValueError: If mode is not a recognized value.
        OSError: If .codetrust/ directory cannot be created or written.
    """
    if mode not in _VALID_BASELINE_MODES:
        raise ValueError(
            f"Invalid baseline mode: {mode!r}. "
            f"Expected one of {sorted(_VALID_BASELINE_MODES)}."
        )

    keys = sorted({finding_key(f) for f in findings})
    payload = {
        "version": BASELINE_FORMAT_VERSION,
        "created": datetime.now(UTC).isoformat(),
        "finding_keys": keys,
        "count": len(keys),
        "mode": mode,
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
    """Return baseline metadata (created, count, mode) without loading all keys.

    Returns:
        Dict with 'created', 'count', and 'mode' (defaulting to "full"
        for baselines written before the mode field existed), or None
        if no baseline exists.
    """
    path = _baseline_path(project_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        mode = str(data.get("mode", BASELINE_MODE_FULL))
        if mode not in _VALID_BASELINE_MODES:
            mode = BASELINE_MODE_FULL
        return {
            "created": data.get("created", "unknown"),
            "count": data.get("count", 0),
            "mode": mode,
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
