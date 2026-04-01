from __future__ import annotations

from src.services.conformity_assessment import (
    AssessmentSection,
    ConformityReport,
    format_assessment,
    sign_report,
)


def _make_report(statuses: list[str]) -> ConformityReport:
    """Build a ConformityReport with given section statuses."""
    sections = [
        AssessmentSection(name=f"Section-{i}", status=s, detail=f"detail-{i}")
        for i, s in enumerate(statuses, 1)
    ]
    return ConformityReport(
        timestamp="2026-03-30T12:00:00+00:00",
        codetrust_version="2.6.0",
        python_version="3.14.0",
        os_info="Darwin 25.4.0",
        sections=sections,
    )


class TestAllPassed:
    """Tests for ConformityReport.all_passed."""

    def test_all_pass_returns_true(self) -> None:
        report = _make_report(["PASS", "PASS", "PASS"])
        assert report.all_passed is True

    def test_one_fail_returns_false(self) -> None:
        report = _make_report(["PASS", "FAIL", "PASS"])
        assert report.all_passed is False

    def test_warn_does_not_count_as_fail(self) -> None:
        report = _make_report(["PASS", "WARN", "PASS"])
        assert report.all_passed is True

    def test_empty_sections_returns_true(self) -> None:
        report = _make_report([])
        assert report.all_passed is True


class TestSummary:
    """Tests for ConformityReport.summary."""

    def test_summary_format(self) -> None:
        report = _make_report(["PASS", "FAIL", "PASS", "WARN"])
        s = report.summary
        assert "2/4 passed" in s
        assert "1 failed" in s

    def test_summary_all_passed(self) -> None:
        report = _make_report(["PASS", "PASS"])
        assert "2/2 passed" in report.summary
        assert "0 failed" in report.summary


class TestSignReport:
    """Tests for sign_report."""

    def test_sign_produces_consistent_hash(self) -> None:
        report = _make_report(["PASS", "FAIL"])
        sig1 = sign_report(report)
        sig2 = sign_report(report)
        assert sig1 == sig2
        assert len(sig1) == 64  # SHA-256 hex digest

    def test_different_reports_produce_different_hashes(self) -> None:
        r1 = _make_report(["PASS", "PASS"])
        r2 = _make_report(["PASS", "FAIL"])
        assert sign_report(r1) != sign_report(r2)


class TestFormatAssessment:
    """Tests for format_assessment."""

    def test_format_produces_markdown(self) -> None:
        report = _make_report(["PASS", "FAIL"])
        report.signature = sign_report(report)
        md = format_assessment(report)
        assert "# Conformity Assessment Report" in md
        assert "**Date:**" in md
        assert "Section-1" in md
        assert "Section-2" in md
        assert "**Signature:**" in md

    def test_format_contains_status_icons(self) -> None:
        report = _make_report(["PASS", "FAIL", "WARN"])
        md = format_assessment(report)
        assert "PASS" in md
        assert "FAIL" in md
        assert "WARN" in md
