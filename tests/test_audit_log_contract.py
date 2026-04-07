# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Audit log schema contract tests.

The status command (_status_count_blocks_24h in cli.py) reads from
.codetrust/audit.jsonl and counts BLOCK/WARN entries in the last 24h.
This relies on two field names being stable:
  - timestamp (Unix epoch float)
  - verdict (string: "BLOCK", "WARN", "ALLOW")

If the AuditEntry dataclass ever changes these field names, the status
command will silently report 0 blocks/warns instead of crashing.

These tests guarantee the contract: any rename to AuditEntry fields
must also be reflected in cli._status_count_blocks_24h.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from src.cli import _status_count_blocks_24h
from src.gateway.audit import AuditEntry


class TestAuditEntrySchema:
    """Verify AuditEntry dataclass exposes the fields status reads."""

    def test_has_timestamp_field(self) -> None:
        entry = _build_entry(verdict="BLOCK")
        assert hasattr(entry, "timestamp")
        assert isinstance(entry.timestamp, float)

    def test_has_verdict_field(self) -> None:
        entry = _build_entry(verdict="BLOCK")
        assert hasattr(entry, "verdict")
        assert entry.verdict == "BLOCK"

    def test_serializes_required_fields(self) -> None:
        entry = _build_entry(verdict="WARN")
        data = json.loads(entry.to_json())
        assert "timestamp" in data
        assert "verdict" in data
        assert data["verdict"] == "WARN"


class TestStatusReadsAuditLog:
    """Verify status command correctly counts entries from a real audit log."""

    def test_counts_recent_blocks(self, tmp_path: Path) -> None:
        audit_path = tmp_path / ".codetrust" / "audit.jsonl"
        audit_path.parent.mkdir(parents=True)
        now = time.time()
        entries = [
            _build_entry(verdict="BLOCK", timestamp=now - 3600),
            _build_entry(verdict="BLOCK", timestamp=now - 7200),
            _build_entry(verdict="WARN", timestamp=now - 1800),
            _build_entry(verdict="ALLOW", timestamp=now - 600),
        ]
        with audit_path.open("w") as f:
            for e in entries:
                f.write(e.to_json() + "\n")

        blocks, warns = _status_count_blocks_24h(tmp_path)
        assert blocks == 2
        assert warns == 1

    def test_excludes_entries_older_than_24h(self, tmp_path: Path) -> None:
        audit_path = tmp_path / ".codetrust" / "audit.jsonl"
        audit_path.parent.mkdir(parents=True)
        now = time.time()
        entries = [
            _build_entry(verdict="BLOCK", timestamp=now - 100000),  # 27h ago
            _build_entry(verdict="BLOCK", timestamp=now - 3600),    # 1h ago
        ]
        with audit_path.open("w") as f:
            for e in entries:
                f.write(e.to_json() + "\n")

        blocks, warns = _status_count_blocks_24h(tmp_path)
        assert blocks == 1
        assert warns == 0

    def test_returns_zeros_when_no_audit_log(self, tmp_path: Path) -> None:
        blocks, warns = _status_count_blocks_24h(tmp_path)
        assert blocks == 0
        assert warns == 0

    def test_handles_malformed_lines_gracefully(self, tmp_path: Path) -> None:
        """A corrupt line shouldn't crash status — it skips and continues."""
        audit_path = tmp_path / ".codetrust" / "audit.jsonl"
        audit_path.parent.mkdir(parents=True)
        now = time.time()
        good_entry = _build_entry(verdict="BLOCK", timestamp=now - 1000)
        with audit_path.open("w") as f:
            f.write(good_entry.to_json() + "\n")
            f.write("not valid json {{{\n")
            f.write("\n")  # blank line
            f.write(good_entry.to_json() + "\n")

        blocks, warns = _status_count_blocks_24h(tmp_path)
        assert blocks == 2  # both valid entries counted
        assert warns == 0

    def test_handles_missing_timestamp(self, tmp_path: Path) -> None:
        """Entry with no timestamp is skipped (treated as out-of-window)."""
        audit_path = tmp_path / ".codetrust" / "audit.jsonl"
        audit_path.parent.mkdir(parents=True)
        with audit_path.open("w") as f:
            f.write(json.dumps({"verdict": "BLOCK"}) + "\n")
            f.write(json.dumps({"verdict": "BLOCK", "timestamp": time.time()}) + "\n")

        blocks, warns = _status_count_blocks_24h(tmp_path)
        assert blocks == 1


def _build_entry(*, verdict: str = "BLOCK", timestamp: float | None = None) -> AuditEntry:
    """Build a minimal valid AuditEntry for testing."""
    return AuditEntry(
        timestamp=timestamp if timestamp is not None else time.time(),
        action_type="bash",
        verdict=verdict,
        rule_id="test_rule",
        original_action="test command",
        message="test",
        suggestion="",
    )
