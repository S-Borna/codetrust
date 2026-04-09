# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the baseline.json `mode` field (full vs reduced).

The mode field was added so future releases can distinguish a baseline
established under the full 2,928-rule set from one established while
the CLI was running in reduced mode (quota exhausted).

Backward compatibility matters: baselines written before this field
existed must still load cleanly and default to ``"full"``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.baseline import (
    BASELINE_MODE_FULL,
    BASELINE_MODE_REDUCED,
    baseline_metadata,
    save_baseline,
)


# ─────────────────────────────────────────────────────────────
#  save_baseline mode parameter
# ─────────────────────────────────────────────────────────────


def test_save_baseline_defaults_to_full_mode(tmp_path: Path) -> None:
    """Callers that don't pass a mode get 'full' — protects callers
    that haven't been updated for the new kwarg."""
    save_baseline(tmp_path, [{"file": "a.py", "line": 1, "rule_id": "eval_exec"}])
    data = json.loads((tmp_path / ".codetrust" / "baseline.json").read_text())
    assert data["mode"] == BASELINE_MODE_FULL


def test_save_baseline_accepts_full_mode_explicitly(tmp_path: Path) -> None:
    save_baseline(tmp_path, [], mode=BASELINE_MODE_FULL)
    data = json.loads((tmp_path / ".codetrust" / "baseline.json").read_text())
    assert data["mode"] == "full"


def test_save_baseline_accepts_reduced_mode(tmp_path: Path) -> None:
    """Reduced mode is permitted at the API level — the CLI policy
    layer decides whether to actually call save_baseline while
    degraded. We store what we're told to store."""
    save_baseline(tmp_path, [], mode=BASELINE_MODE_REDUCED)
    data = json.loads((tmp_path / ".codetrust" / "baseline.json").read_text())
    assert data["mode"] == "reduced"


def test_save_baseline_rejects_invalid_mode(tmp_path: Path) -> None:
    """Typos / unrecognized values must raise rather than silently
    writing garbage into baseline.json."""
    with pytest.raises(ValueError, match="Invalid baseline mode"):
        save_baseline(tmp_path, [], mode="partial")


# ─────────────────────────────────────────────────────────────
#  baseline_metadata backward compatibility
# ─────────────────────────────────────────────────────────────


def test_metadata_reads_mode_when_present(tmp_path: Path) -> None:
    save_baseline(tmp_path, [], mode=BASELINE_MODE_REDUCED)
    meta = baseline_metadata(tmp_path)
    assert meta is not None
    assert meta["mode"] == "reduced"


def test_metadata_defaults_to_full_for_legacy_baseline(tmp_path: Path) -> None:
    """A baseline.json written by an older CodeTrust version (no mode
    field) must load cleanly with mode='full' — that's what those
    older versions effectively ran with."""
    (tmp_path / ".codetrust").mkdir()
    legacy = tmp_path / ".codetrust" / "baseline.json"
    legacy.write_text(json.dumps({
        "version": "1",
        "created": "2026-03-01T00:00:00+00:00",
        "finding_keys": ["a.py:1:eval_exec"],
        "count": 1,
        # no "mode" field
    }), encoding="utf-8")

    meta = baseline_metadata(tmp_path)
    assert meta is not None
    assert meta["mode"] == "full", (
        "Legacy baselines without a mode field must default to 'full'"
    )


def test_metadata_sanitizes_unknown_mode_value(tmp_path: Path) -> None:
    """A file hand-edited or corrupted with mode='weird' must fall
    back to 'full' in the metadata rather than propagating garbage."""
    (tmp_path / ".codetrust").mkdir()
    corrupt = tmp_path / ".codetrust" / "baseline.json"
    corrupt.write_text(json.dumps({
        "version": "1",
        "created": "2026-03-01T00:00:00+00:00",
        "finding_keys": [],
        "count": 0,
        "mode": "weird",
    }), encoding="utf-8")

    meta = baseline_metadata(tmp_path)
    assert meta is not None
    assert meta["mode"] == "full"


def test_metadata_none_when_baseline_absent(tmp_path: Path) -> None:
    """baseline_metadata on a project without a baseline returns None."""
    assert baseline_metadata(tmp_path) is None


# ─────────────────────────────────────────────────────────────
#  Roundtrip
# ─────────────────────────────────────────────────────────────


def test_save_then_read_roundtrips_mode(tmp_path: Path) -> None:
    """Full save → load → verify every field survives unchanged."""
    save_baseline(
        tmp_path,
        [
            {"file": "a.py", "line": 1, "rule_id": "eval_exec"},
            {"file": "b.py", "line": 5, "rule_id": "bare_except"},
        ],
        mode=BASELINE_MODE_FULL,
    )
    meta = baseline_metadata(tmp_path)
    assert meta is not None
    assert meta["mode"] == "full"
    assert meta["count"] == 2
