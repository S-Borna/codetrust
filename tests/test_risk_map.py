from __future__ import annotations

from src.services.risk_map import (
    RiskItem,
    RiskMap,
)


def _make_risk_map() -> RiskMap:
    """Build a RiskMap with varied severities."""
    return RiskMap(risks=[
        RiskItem("vuln", "CRITICAL", "SQL injection found", "scan", count=2),
        RiskItem("vuln", "HIGH", "XSS in template", "scan", count=3),
        RiskItem("config", "MEDIUM", "Debug mode enabled", "audit", count=1),
        RiskItem("perm", "LOW", "Broad file permissions", "audit", count=5),
        RiskItem("vuln", "CRITICAL", "RCE via eval", "scan", count=1),
    ])


class TestBySeverity:
    """Tests for RiskMap.by_severity grouping."""

    def test_counts_per_severity(self) -> None:
        rm = _make_risk_map()
        sev = rm.by_severity
        assert sev["CRITICAL"] == 3  # 2 + 1
        assert sev["HIGH"] == 3
        assert sev["MEDIUM"] == 1
        assert sev["LOW"] == 5

    def test_empty_map_has_zero_counts(self) -> None:
        rm = RiskMap()
        sev = rm.by_severity
        assert sev["CRITICAL"] == 0
        assert sev["HIGH"] == 0
        assert sev["MEDIUM"] == 0
        assert sev["LOW"] == 0


class TestTopRisks:
    """Tests for RiskMap.top_risks ordering."""

    def test_critical_first(self) -> None:
        rm = _make_risk_map()
        top = rm.top_risks
        assert len(top) > 0
        assert top[0].severity == "CRITICAL"

    def test_ordering_by_severity_then_count(self) -> None:
        rm = _make_risk_map()
        top = rm.top_risks
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for i in range(len(top) - 1):
            a_sev = severity_order[top[i].severity]
            b_sev = severity_order[top[i + 1].severity]
            if a_sev == b_sev:
                assert top[i].count >= top[i + 1].count
            else:
                assert a_sev <= b_sev

    def test_max_10_results(self) -> None:
        risks = [
            RiskItem("cat", "HIGH", f"risk-{i}", "src", count=1)
            for i in range(15)
        ]
        rm = RiskMap(risks=risks)
        assert len(rm.top_risks) == 10

    def test_empty_map_returns_empty(self) -> None:
        rm = RiskMap()
        assert rm.top_risks == []


class TestSummary:
    """Tests for RiskMap.summary."""

    def test_summary_format_with_risks(self) -> None:
        rm = _make_risk_map()
        s = rm.summary
        assert "CRITICAL" in s
        assert "HIGH" in s

    def test_summary_empty_map(self) -> None:
        rm = RiskMap()
        assert rm.summary == "No risks identified"

    def test_summary_omits_zero_severity(self) -> None:
        rm = RiskMap(risks=[
            RiskItem("cat", "HIGH", "desc", "src", count=2),
        ])
        s = rm.summary
        assert "HIGH" in s
        assert "CRITICAL" not in s
        assert "MEDIUM" not in s
        assert "LOW" not in s
