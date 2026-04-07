# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for snapshot-based baseline (first-scan friction reduction)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.baseline import (
    baseline_exists,
    baseline_metadata,
    filter_new_findings,
    finding_key,
    load_baseline_keys,
    reset_baseline,
    save_baseline,
)


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    """A temporary project directory."""
    return tmp_path


@pytest.fixture()
def sample_findings() -> list[dict[str, object]]:
    """Sample findings simulating an existing codebase."""
    return [
        {"file": "src/a.py", "line": 10, "rule_id": "eval_exec", "message": "eval"},
        {"file": "src/b.py", "line": 25, "rule_id": "bare_except", "message": "bare"},
        {"file": "src/c.py", "line": 5, "rule_id": "magic_number", "message": "magic"},
    ]


class TestFindingKey:
    def test_stable_format(self) -> None:
        finding = {"file": "a.py", "line": 42, "rule_id": "eval_exec"}
        assert finding_key(finding) == "a.py:42:eval_exec"

    def test_handles_missing_fields(self) -> None:
        assert finding_key({}) == ":0:"

    def test_message_does_not_affect_key(self) -> None:
        a = {"file": "x.py", "line": 1, "rule_id": "r", "message": "old"}
        b = {"file": "x.py", "line": 1, "rule_id": "r", "message": "new"}
        assert finding_key(a) == finding_key(b)


class TestSaveAndLoad:
    def test_save_creates_codetrust_dir(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        count = save_baseline(project, sample_findings)
        assert count == 3
        assert (project / ".codetrust" / "baseline.json").exists()

    def test_save_then_load_roundtrip(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        save_baseline(project, sample_findings)
        keys = load_baseline_keys(project)
        assert keys is not None
        assert "src/a.py:10:eval_exec" in keys
        assert "src/b.py:25:bare_except" in keys
        assert "src/c.py:5:magic_number" in keys

    def test_save_dedups_duplicate_findings(self, project: Path) -> None:
        dupes = [
            {"file": "a.py", "line": 1, "rule_id": "r"},
            {"file": "a.py", "line": 1, "rule_id": "r"},
        ]
        count = save_baseline(project, dupes)
        assert count == 1

    def test_load_returns_none_when_missing(self, project: Path) -> None:
        assert load_baseline_keys(project) is None

    def test_load_returns_none_on_corrupt_json(self, project: Path) -> None:
        baseline_path = project / ".codetrust" / "baseline.json"
        baseline_path.parent.mkdir(parents=True)
        baseline_path.write_text("not valid json {")
        assert load_baseline_keys(project) is None

    def test_load_returns_none_on_wrong_schema(self, project: Path) -> None:
        baseline_path = project / ".codetrust" / "baseline.json"
        baseline_path.parent.mkdir(parents=True)
        baseline_path.write_text(json.dumps({"finding_keys": "not a list"}))
        assert load_baseline_keys(project) is None


class TestFilterNewFindings:
    def test_filters_known_findings(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        save_baseline(project, sample_findings)
        keys = load_baseline_keys(project) or set()

        # Same findings should all be filtered out
        new = filter_new_findings(sample_findings, keys)
        assert new == []

    def test_keeps_new_findings(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        save_baseline(project, sample_findings)
        keys = load_baseline_keys(project) or set()

        # Add a new finding not in baseline
        new_finding = {"file": "src/d.py", "line": 99, "rule_id": "sql_injection"}
        all_findings = [*sample_findings, new_finding]
        new = filter_new_findings(all_findings, keys)
        assert len(new) == 1
        assert new[0] == new_finding

    def test_message_change_does_not_count_as_new(
        self, project: Path,
    ) -> None:
        original = [
            {"file": "a.py", "line": 1, "rule_id": "r", "message": "old text"},
        ]
        save_baseline(project, original)
        keys = load_baseline_keys(project) or set()

        # Same finding with updated message — should still be filtered
        updated = [
            {"file": "a.py", "line": 1, "rule_id": "r", "message": "new text"},
        ]
        assert filter_new_findings(updated, keys) == []


class TestExistsAndReset:
    def test_baseline_exists_false_initially(self, project: Path) -> None:
        assert baseline_exists(project) is False

    def test_baseline_exists_after_save(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        save_baseline(project, sample_findings)
        assert baseline_exists(project) is True

    def test_reset_removes_file(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        save_baseline(project, sample_findings)
        assert reset_baseline(project) is True
        assert baseline_exists(project) is False

    def test_reset_returns_false_when_no_baseline(self, project: Path) -> None:
        assert reset_baseline(project) is False


class TestMetadata:
    def test_metadata_returns_count_and_created(
        self, project: Path, sample_findings: list[dict[str, object]],
    ) -> None:
        save_baseline(project, sample_findings)
        meta = baseline_metadata(project)
        assert meta is not None
        assert meta["count"] == 3
        assert "created" in meta
        # created should be ISO format string
        assert isinstance(meta["created"], str)
        assert "T" in str(meta["created"])

    def test_metadata_returns_none_when_missing(self, project: Path) -> None:
        assert baseline_metadata(project) is None


class TestBaselineShareMode:
    """Verify baseline can be toggled between gitignored and shared modes."""

    def test_is_shared_false_when_no_gitignore(self, project: Path) -> None:
        from src.cli import _baseline_is_shared
        assert _baseline_is_shared(project) is False

    def test_is_shared_false_when_no_unignore_line(self, project: Path) -> None:
        from src.cli import _baseline_is_shared
        (project / ".gitignore").write_text("# CodeTrust\n.codetrust/\n")
        assert _baseline_is_shared(project) is False

    def test_is_shared_true_when_unignore_line_present(self, project: Path) -> None:
        from src.cli import _baseline_is_shared
        (project / ".gitignore").write_text(
            "# CodeTrust\n.codetrust/\n!.codetrust/baseline.json\n",
        )
        assert _baseline_is_shared(project) is True
