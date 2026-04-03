# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Calibration tests: Agent Integrity Engine vs real session incidents.

Loads reconstructed incidents from tests/fixtures/real_session_incidents.json
(extracted from 20+ session reports) and measures detection rate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.services.agent_integrity import (
    IssueType,
    SessionMessage,
    analyze_session,
    parse_session_messages,
)

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "real_session_incidents.json"


def _load_incidents() -> list[dict[str, Any]]:
    """Load real session incidents from fixture file."""
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


def _run_incident(incident: dict[str, Any]) -> dict[str, Any]:
    """Run the integrity engine on a single incident and return results."""
    messages = parse_session_messages(incident["messages"])
    commands: list[str] = incident.get("commands", [])
    session_id = incident["id"]

    report = analyze_session(messages, commands, session_id=session_id)

    detected_types: set[str] = {issue.issue_type.value for issue in report.issues}

    expected_types: set[str] = set(incident.get("expected_issues", []))

    # True positive: expected issue was detected
    true_positives = expected_types & detected_types
    # False negative: expected issue was NOT detected
    false_negatives = expected_types - detected_types

    return {
        "id": incident["id"],
        "session": incident["session"],
        "description": incident["description"],
        "expected": list(expected_types),
        "detected": list(detected_types),
        "true_positives": list(true_positives),
        "false_negatives": list(false_negatives),
        "verdict": report.verdict.value,
        "score": report.integrity_score,
        "total_issues": len(report.issues),
    }


# ───────────────────────────────────────────────────────────────
#  Fixture-level tests
# ───────────────────────────────────────────────────────────────


class TestFixtureIntegrity:
    """Verify the fixture file is well-formed."""

    def test_fixture_file_exists(self) -> None:
        """Fixture file must exist."""
        assert FIXTURES_PATH.is_file(), f"Missing fixture: {FIXTURES_PATH}"

    def test_fixture_has_minimum_incidents(self) -> None:
        """Must have at least 10 incidents."""
        incidents = _load_incidents()
        assert len(incidents) >= 10, f"Only {len(incidents)} incidents, need 10+"

    def test_fixture_incidents_have_required_fields(self) -> None:
        """Every incident must have the required fields."""
        incidents = _load_incidents()
        required_fields = {"id", "session", "incident_type", "description", "messages", "expected_issues", "should_detect"}
        for incident in incidents:
            missing = required_fields - set(incident.keys())
            assert not missing, f"Incident {incident.get('id', '?')} missing fields: {missing}"

    def test_all_expected_issue_types_are_valid(self) -> None:
        """Expected issue types must match IssueType enum values."""
        valid_types = {e.value for e in IssueType}
        incidents = _load_incidents()
        for incident in incidents:
            for expected in incident["expected_issues"]:
                assert expected in valid_types, (
                    f"Incident {incident['id']}: '{expected}' not in {valid_types}"
                )


# ───────────────────────────────────────────────────────────────
#  Detection rate measurement
# ───────────────────────────────────────────────────────────────


class TestDetectionRate:
    """Measure detection rate against real incidents."""

    def test_overall_detection_rate_above_70_percent(self) -> None:
        """At least 70% of expected issues must be detected."""
        incidents = _load_incidents()
        total_expected = 0
        total_detected = 0

        for incident in incidents:
            if not incident.get("should_detect", True):
                continue
            result = _run_incident(incident)
            total_expected += len(result["expected"])
            total_detected += len(result["true_positives"])

        rate = total_detected / max(total_expected, 1)
        assert rate >= 0.70, (
            f"Detection rate {rate:.1%} ({total_detected}/{total_expected}) "
            f"is below 70% threshold"
        )

    def test_detection_rate_per_type(self) -> None:
        """Report detection rate per issue type (informational, not gated)."""
        incidents = _load_incidents()
        by_type: dict[str, dict[str, int]] = {}

        for incident in incidents:
            if not incident.get("should_detect", True):
                continue
            result = _run_incident(incident)
            for expected_type in result["expected"]:
                if expected_type not in by_type:
                    by_type[expected_type] = {"expected": 0, "detected": 0}
                by_type[expected_type]["expected"] += 1
                if expected_type in result["true_positives"]:
                    by_type[expected_type]["detected"] += 1

        # Print report for visibility
        for issue_type, counts in sorted(by_type.items()):
            rate = counts["detected"] / max(counts["expected"], 1)
            print(f"  {issue_type}: {counts['detected']}/{counts['expected']} ({rate:.0%})")

        # At least one type must be above 50%
        rates = [
            c["detected"] / max(c["expected"], 1)
            for c in by_type.values()
        ]
        assert max(rates) >= 0.50, "No issue type has >50% detection"


# ───────────────────────────────────────────────────────────────
#  Per-incident tests (parametrized)
# ───────────────────────────────────────────────────────────────


_INCIDENTS = _load_incidents()
_INCIDENT_IDS = [inc["id"] for inc in _INCIDENTS]


@pytest.mark.parametrize(
    "incident",
    _INCIDENTS,
    ids=_INCIDENT_IDS,
)
def test_incident_produces_issues(incident: dict[str, Any]) -> None:
    """Each incident should produce at least one integrity issue."""
    if not incident.get("should_detect", True):
        pytest.skip("Incident marked as should_detect=False")

    result = _run_incident(incident)
    assert result["total_issues"] > 0, (
        f"Incident {incident['id']} ({incident['description'][:60]}): "
        f"expected issues {incident['expected_issues']} but got 0 issues. "
        f"Verdict: {result['verdict']}, score: {result['score']}"
    )


@pytest.mark.parametrize(
    "incident",
    _INCIDENTS,
    ids=_INCIDENT_IDS,
)
def test_incident_verdict_not_trustworthy(incident: dict[str, Any]) -> None:
    """Real incidents should not produce TRUSTWORTHY verdicts."""
    if not incident.get("should_detect", True):
        pytest.skip("Incident marked as should_detect=False")

    result = _run_incident(incident)
    assert result["verdict"] != "TRUSTWORTHY", (
        f"Incident {incident['id']} ({incident['description'][:60]}): "
        f"got TRUSTWORTHY but this is a real integrity incident"
    )
