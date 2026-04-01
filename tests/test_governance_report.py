from __future__ import annotations

from pathlib import Path

import pytest

from src.services.governance_report import (
    GovernanceReport,
    GovernanceSection,
    format_governance_report,
    generate_governance_report,
)


class TestGovernanceSection:
    """Tests for GovernanceSection."""

    def test_default_status(self) -> None:
        section = GovernanceSection(title="Test", content="content")
        assert section.status == "documented"


class TestGovernanceReport:
    """Tests for GovernanceReport."""

    def test_summary_with_sections(self) -> None:
        report = GovernanceReport(
            timestamp="2026-03-30T12:00:00+00:00",
            sections=[
                GovernanceSection(title="A", content="a"),
                GovernanceSection(title="B", content="b"),
                GovernanceSection(title="C", content="c"),
            ],
        )
        assert report.summary == "3 governance areas documented"

    def test_summary_empty(self) -> None:
        report = GovernanceReport(timestamp="2026-03-30T12:00:00+00:00")
        assert report.summary == "0 governance areas documented"


class TestGenerateGovernanceReport:
    """Tests for generate_governance_report."""

    def test_returns_sections(self, tmp_path: Path) -> None:
        report = generate_governance_report(project_dir=tmp_path)
        assert isinstance(report, GovernanceReport)
        assert len(report.sections) > 0

    def test_has_timestamp(self, tmp_path: Path) -> None:
        report = generate_governance_report(project_dir=tmp_path)
        assert report.timestamp

    def test_includes_policy_section(self, tmp_path: Path) -> None:
        report = generate_governance_report(project_dir=tmp_path)
        titles = [s.title for s in report.sections]
        assert "Policy Configuration" in titles

    def test_includes_enforcement_section(self, tmp_path: Path) -> None:
        report = generate_governance_report(project_dir=tmp_path)
        titles = [s.title for s in report.sections]
        assert "Enforcement Architecture" in titles

    def test_with_codetrust_toml(self, tmp_path: Path) -> None:
        toml_content = (
            "[governance]\n"
            'mode = "audit"\n'
            "\n"
            "[policy]\n"
            'models_allowed = "claude"\n'
        )
        (tmp_path / ".codetrust.toml").write_text(toml_content, encoding="utf-8")
        report = generate_governance_report(project_dir=tmp_path)
        policy_section = next(s for s in report.sections if s.title == "Policy Configuration")
        assert "audit" in policy_section.content


class TestFormatGovernanceReport:
    """Tests for format_governance_report."""

    def test_produces_markdown(self) -> None:
        report = GovernanceReport(
            timestamp="2026-03-30T12:00:00+00:00",
            sections=[
                GovernanceSection(title="Section A", content="Content A"),
                GovernanceSection(title="Section B", content="Content B"),
            ],
        )
        md = format_governance_report(report)
        assert "# AI Governance Report" in md
        assert "## 1. Section A" in md
        assert "## 2. Section B" in md
        assert "Content A" in md

    def test_format_includes_timestamp(self) -> None:
        report = GovernanceReport(
            timestamp="2026-03-30T12:00:00+00:00",
            sections=[GovernanceSection(title="X", content="Y")],
        )
        md = format_governance_report(report)
        assert "2026-03-30" in md
