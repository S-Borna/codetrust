from __future__ import annotations

from src.services.metrics_report import (
    Metric,
    MetricsReport,
    format_metrics_report,
)


def _make_report() -> MetricsReport:
    """Build a MetricsReport with mixed SLO status."""
    return MetricsReport(metrics=[
        Metric("Scan rules", ">= 2000", "2500", True, "rules.py"),
        Metric("Coverage", "100%", "95.0%", False, "rules.py"),
        Metric("Taint defs", ">= 300", "350", True, "taint.py"),
        Metric("Test suite", "0 failures", "2 failures", False, "pytest"),
    ])


class TestMetric:
    """Tests for the Metric dataclass."""

    def test_meeting_property_true(self) -> None:
        m = Metric("X", ">= 10", "15", True, "src")
        assert m.meeting is True

    def test_meeting_property_false(self) -> None:
        m = Metric("X", ">= 10", "5", False, "src")
        assert m.meeting is False

    def test_fields_accessible(self) -> None:
        m = Metric("Rules", ">= 2000", "2500", True, "rules.py")
        assert m.name == "Rules"
        assert m.target == ">= 2000"
        assert m.current == "2500"
        assert m.source == "rules.py"


class TestMeetingCount:
    """Tests for MetricsReport.meeting_count."""

    def test_meeting_count(self) -> None:
        report = _make_report()
        assert report.meeting_count == 2

    def test_meeting_count_all_meeting(self) -> None:
        report = MetricsReport(metrics=[
            Metric("A", "1", "1", True, "s"),
            Metric("B", "2", "2", True, "s"),
        ])
        assert report.meeting_count == 2

    def test_meeting_count_none_meeting(self) -> None:
        report = MetricsReport(metrics=[
            Metric("A", "1", "0", False, "s"),
        ])
        assert report.meeting_count == 0

    def test_meeting_count_empty(self) -> None:
        report = MetricsReport()
        assert report.meeting_count == 0


class TestSummary:
    """Tests for MetricsReport.summary."""

    def test_summary_format(self) -> None:
        report = _make_report()
        s = report.summary
        assert s == "2/4 SLOs meeting target"

    def test_summary_empty(self) -> None:
        report = MetricsReport()
        assert report.summary == "0/0 SLOs meeting target"


class TestFormatMetricsReport:
    """Tests for format_metrics_report."""

    def test_produces_markdown_table(self) -> None:
        report = _make_report()
        md = format_metrics_report(report)
        assert "# Metrics Report" in md
        assert "| Metric |" in md
        assert "Scan rules" in md
        assert "MEETING" in md

    def test_contains_status_indicators(self) -> None:
        report = _make_report()
        md = format_metrics_report(report)
        assert "NOT MEETING" in md

    def test_empty_report(self) -> None:
        md = format_metrics_report(MetricsReport())
        assert "# Metrics Report" in md
        assert "0/0" in md
