# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for internal diagnostic marker rules in anti_patterns.py."""

from __future__ import annotations

from src.rules.anti_patterns import ANTI_PATTERNS

MARKER_RULE_IDS: list[str] = [
    "ct_sig_borna_2026_alpha",
    "ct_sig_governance_w7x9",
    "ct_sig_drift_k3m2_sentinel",
    "ct_sig_moat_v4_fingerprint",
    "ct_sig_sborna_proprietary_q8",
]

EXPECTED_MARKER_COUNT: int = 5


class TestIntegrityMarkerRules:
    """Verify internal diagnostic marker rules exist and are properly configured."""

    def test_marker_rules_exist(self) -> None:
        """All 5 marker rule IDs must be present in ANTI_PATTERNS."""
        rule_ids = {r["id"] for r in ANTI_PATTERNS}
        for marker_id in MARKER_RULE_IDS:
            assert marker_id in rule_ids, f"Marker rule '{marker_id}' missing"

    def test_marker_count(self) -> None:
        """Exactly 5 marker rules should exist."""
        marker_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("ct_sig_")]
        assert len(marker_rules) == EXPECTED_MARKER_COUNT

    def test_marker_severity_is_info(self) -> None:
        """Marker rules should use INFO severity (non-blocking)."""
        marker_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("ct_sig_")]
        for rule in marker_rules:
            assert rule["severity"] == "INFO", (
                f"Marker rule '{rule['id']}' has severity '{rule['severity']}', expected INFO"
            )

    def test_marker_rules_have_patterns(self) -> None:
        """Each marker rule must have a non-empty regex pattern."""
        marker_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("ct_sig_")]
        for rule in marker_rules:
            assert "pattern" in rule
            assert len(rule["pattern"]) > 0

    def test_marker_rules_have_messages(self) -> None:
        """Each marker rule must have a descriptive message."""
        marker_rules = [r for r in ANTI_PATTERNS if r["id"].startswith("ct_sig_")]
        for rule in marker_rules:
            assert "message" in rule
            assert len(rule["message"]) > 10

    def test_marker_rule_ids_unique(self) -> None:
        """Marker rule IDs must not collide with any other rule IDs."""
        all_ids = [r["id"] for r in ANTI_PATTERNS]
        marker_ids_in_list = [rid for rid in all_ids if rid.startswith("ct_sig_")]
        assert len(marker_ids_in_list) == len(set(marker_ids_in_list))

    def test_total_rule_count_includes_markers(self) -> None:
        """ANTI_PATTERNS should contain at least 199 + 5 marker rules."""
        assert len(ANTI_PATTERNS) >= 204
