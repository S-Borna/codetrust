from __future__ import annotations

import pytest

from src.services.privacy import (
    NOT_COLLECTED,
    TELEMETRY_DATA,
    PrivacyReport,
    format_privacy_report,
    generate_privacy_report,
)


class TestGeneratePrivacyReport:
    """Tests for generate_privacy_report."""

    def test_returns_privacy_report(self) -> None:
        report = generate_privacy_report()
        assert isinstance(report, PrivacyReport)

    def test_has_data_categories(self) -> None:
        report = generate_privacy_report()
        assert len(report.data_categories) > 0

    def test_has_not_collected_list(self) -> None:
        report = generate_privacy_report()
        assert len(report.not_collected) > 0

    def test_respects_telemetry_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "0")
        report = generate_privacy_report()
        assert report.telemetry_enabled is False

    def test_respects_retention_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODETRUST_RETENTION_DAYS", "30")
        report = generate_privacy_report()
        assert report.retention_days == 30


class TestHasPii:
    """Tests for PrivacyReport.has_pii."""

    def test_default_report_has_no_pii(self) -> None:
        report = generate_privacy_report()
        assert report.has_pii is False

    def test_telemetry_data_has_no_pii(self) -> None:
        for category in TELEMETRY_DATA:
            assert category.contains_pii is False


class TestNotCollected:
    """Tests for NOT_COLLECTED list."""

    def test_not_collected_has_items(self) -> None:
        assert len(NOT_COLLECTED) >= 4

    def test_source_code_not_collected(self) -> None:
        combined = " ".join(NOT_COLLECTED).lower()
        assert "source code" in combined


class TestFormatPrivacyReport:
    """Tests for format_privacy_report."""

    def test_contains_required_sections(self) -> None:
        report = generate_privacy_report()
        md = format_privacy_report(report)
        assert "# Privacy & Data Governance Report" in md
        assert "## Data Collected" in md
        assert "## Data NOT Collected" in md
        assert "## GDPR Compliance" in md

    def test_contains_telemetry_status(self) -> None:
        report = generate_privacy_report()
        md = format_privacy_report(report)
        assert "**Telemetry:**" in md

    def test_contains_pii_status(self) -> None:
        report = generate_privacy_report()
        md = format_privacy_report(report)
        assert "**PII collected:** No" in md

    def test_disabled_telemetry_shown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CODETRUST_TELEMETRY", "0")
        report = generate_privacy_report()
        md = format_privacy_report(report)
        assert "DISABLED" in md
