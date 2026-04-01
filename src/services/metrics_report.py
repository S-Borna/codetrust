# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Metrics Report — NIST AI RMF Measure function compliance.

Structured metrics in SLO format: target, current, status (MEETING/NOT MEETING).
Sources: scan stats, FP rates, trust score, enforcement blocks, coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Metric:
    """A single measurable metric with SLO target."""

    name: str
    target: str
    current: str
    meeting: bool
    source: str


@dataclass
class MetricsReport:
    """Collection of metrics with SLO status."""

    metrics: list[Metric] = field(default_factory=list)

    @property
    def meeting_count(self) -> int:
        """Number of metrics meeting their SLO."""
        return sum(1 for m in self.metrics if m.meeting)

    @property
    def total(self) -> int:
        """Total number of metrics."""
        return len(self.metrics)

    @property
    def summary(self) -> str:
        """Build summary string."""
        return f"{self.meeting_count}/{self.total} SLOs meeting target"


def generate_metrics_report(project_dir: Path | None = None) -> MetricsReport:
    """Generate metrics report from project state.

    Args:
        project_dir: Project root.

    Returns:
        MetricsReport with measured values.
    """
    _ = project_dir or Path.cwd()  # reserved for project-scoped metrics
    report = MetricsReport()

    # Metric 1: Scan rule count
    try:
        from src.rules.anti_patterns import ANTI_PATTERNS
        rule_count = len(ANTI_PATTERNS)
        report.metrics.append(Metric(
            name="Scan rules",
            target=">= 2000",
            current=str(rule_count),
            meeting=rule_count >= 2000,
            source="src/rules/anti_patterns.py",
        ))
    except ImportError:
        report.metrics.append(Metric(
            name="Scan rules",
            target=">= 2000",
            current="N/A",
            meeting=False,
            source="import failed",
        ))

    # Metric 2: Suggestion coverage
    try:
        from src.rules.anti_patterns import ANTI_PATTERNS
        with_suggestion = sum(1 for r in ANTI_PATTERNS if r.get("suggestion"))
        pct = (with_suggestion / len(ANTI_PATTERNS) * 100) if ANTI_PATTERNS else 0
        report.metrics.append(Metric(
            name="Suggestion coverage",
            target="100%",
            current=f"{pct:.1f}% ({with_suggestion}/{len(ANTI_PATTERNS)})",
            meeting=pct >= 99.9,
            source="src/rules/anti_patterns.py",
        ))
    except ImportError:
        pass

    # Metric 3: Taint definitions
    try:
        from src.rules.taint_rules import TAINT_SANITIZERS, TAINT_SINKS, TAINT_SOURCES
        total_taint = len(TAINT_SOURCES) + len(TAINT_SINKS) + len(TAINT_SANITIZERS)
        report.metrics.append(Metric(
            name="Taint definitions",
            target=">= 300",
            current=str(total_taint),
            meeting=total_taint >= 300,
            source="src/rules/taint_rules.py",
        ))
    except ImportError:
        pass

    # Metric 4: Compliance frameworks
    try:
        from src.services.compliance import get_compliance_report, list_frameworks
        all_full = True
        for fid in list_frameworks():
            r = get_compliance_report(fid)
            if not all(risk.coverage_level == "full" for risk in r.risks):
                all_full = False
                break
        report.metrics.append(Metric(
            name="All frameworks fully compliant",
            target="True",
            current=str(all_full),
            meeting=all_full,
            source="src/services/compliance.py",
        ))
    except (ImportError, ValueError):
        pass

    # Metric 5: Gateway rules
    try:
        from src.gateway.interceptor import CommandInterceptor
        interceptor = CommandInterceptor(enabled=True)
        rule_count = len(interceptor._terminal_rules)
        report.metrics.append(Metric(
            name="Gateway BLOCK rules",
            target=">= 30",
            current=str(rule_count),
            meeting=rule_count >= 30,
            source="src/gateway/interceptor.py",
        ))
    except (ImportError, AttributeError):
        pass

    # Metric 6: Test count (from latest pytest output if available)
    report.metrics.append(Metric(
        name="Test suite",
        target="0 failures",
        current="Run 'pytest tests/ -x -q' to measure",
        meeting=False,
        source="pytest",
    ))

    return report


def format_metrics_report(report: MetricsReport) -> str:
    """Format metrics report as Markdown with SLO status.

    Args:
        report: Report to format.

    Returns:
        Markdown string.
    """
    lines: list[str] = [
        "# Metrics Report",
        "",
        f"**{report.summary}**",
        "",
        "| Metric | Target | Current | Status | Source |",
        "|--------|--------|---------|--------|--------|",
    ]

    for m in report.metrics:
        status = "MEETING" if m.meeting else "NOT MEETING"
        icon = "✅" if m.meeting else "❌"
        lines.append(
            f"| {m.name} | {m.target} | {m.current} | {icon} {status} | {m.source} |",
        )

    return "\n".join(lines)
