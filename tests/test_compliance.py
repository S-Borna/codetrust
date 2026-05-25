"""Tests for OWASP ASI 2026 and multi-framework compliance mapping."""

from __future__ import annotations

import json

import pytest

from src.services.compliance import (
    ComplianceReport,
    compliance_summary,
    get_compliance_report,
    is_fully_compliant,
    list_frameworks,
)


class TestListFrameworks:
    """Tests for framework enumeration."""

    def test_returns_dict(self) -> None:
        """list_frameworks returns a dict of id → display name."""
        result = list_frameworks()
        assert isinstance(result, dict)

    def test_contains_owasp_asi(self) -> None:
        """OWASP ASI 2026 is a supported framework."""
        result = list_frameworks()
        assert "owasp-asi-2026" in result

    def test_contains_eu_ai_act(self) -> None:
        """EU AI Act is a supported framework."""
        result = list_frameworks()
        assert "eu-ai-act" in result

    def test_contains_nist_ai_rmf(self) -> None:
        """NIST AI RMF is a supported framework."""
        result = list_frameworks()
        assert "nist-ai-rmf" in result

    def test_at_least_three_frameworks(self) -> None:
        """At least three frameworks are supported."""
        result = list_frameworks()
        assert len(result) >= 3

    def test_contains_nis2(self) -> None:
        """NIS2 (folded in from Guardian) is a supported framework."""
        result = list_frameworks()
        assert "nis2" in result


class TestNIS2Framework:
    """NIS2 is mapped honestly — technical measures covered, org measures gapped."""

    def test_report_generates(self) -> None:
        report = get_compliance_report("nis2")
        assert report.framework_id == "nis2"
        assert len(report.risks) >= 5

    def test_every_risk_has_valid_coverage(self) -> None:
        report = get_compliance_report("nis2")
        for r in report.risks:
            assert r.coverage_level in ("full", "partial", "planned")

    def test_not_claimed_fully_compliant(self) -> None:
        """NIS2 is largely organizational — we must NOT claim full compliance."""
        assert is_fully_compliant("nis2") is False

    def test_supply_chain_and_dev_are_full(self) -> None:
        """The technical measures CodeTrust genuinely covers map to full."""
        report = get_compliance_report("nis2")
        full_ids = {r.risk_id for r in report.risks if r.coverage_level == "full"}
        assert "NIS2-21d" in full_ids  # supply chain
        assert "NIS2-21e" in full_ids  # secure development

    def test_organizational_measures_are_gapped(self) -> None:
        """Incident reporting / continuity must carry honest gaps, not false claims."""
        report = get_compliance_report("nis2")
        by_id = {r.risk_id: r for r in report.risks}
        assert by_id["NIS2-21c"].coverage_level == "planned"
        assert by_id["NIS2-21c"].gap  # non-empty gap note

    def test_full_coverage_risks_have_evidence(self) -> None:
        report = get_compliance_report("nis2")
        for r in report.risks:
            if r.coverage_level == "full":
                assert r.evidence, f"{r.risk_id} claims full coverage without evidence"


class TestGetComplianceReport:
    """Tests for compliance report generation."""

    def test_owasp_asi_returns_report(self) -> None:
        """OWASP ASI report has correct structure."""
        report = get_compliance_report("owasp-asi-2026")
        assert isinstance(report, ComplianceReport)
        assert report.framework_id == "owasp-asi-2026"

    def test_owasp_asi_has_10_risks(self) -> None:
        """OWASP ASI Top 10 must have exactly 10 risk mappings."""
        report = get_compliance_report("owasp-asi-2026")
        assert len(report.risks) == 10

    def test_owasp_asi_risk_ids_sequential(self) -> None:
        """Risk IDs are OWASP-ASI-01 through OWASP-ASI-10."""
        report = get_compliance_report("owasp-asi-2026")
        expected_ids = [f"OWASP-ASI-{i:02d}" for i in range(1, 11)]
        actual_ids = [r.risk_id for r in report.risks]
        assert actual_ids == expected_ids

    def test_every_risk_has_evidence(self) -> None:
        """Every risk mapping must have at least one evidence item."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            assert len(risk.evidence) >= 1, f"{risk.risk_id} has no evidence"

    def test_every_risk_has_coverage(self) -> None:
        """Every risk mapping must have at least one coverage item."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            assert len(risk.codetrust_coverage) >= 1, f"{risk.risk_id} has no coverage"

    def test_coverage_levels_valid(self) -> None:
        """All coverage levels are 'full', 'partial', or 'planned'."""
        report = get_compliance_report("owasp-asi-2026")
        valid_levels = {"full", "partial", "planned"}
        for risk in report.risks:
            assert risk.coverage_level in valid_levels, (
                f"{risk.risk_id} has invalid level: {risk.coverage_level}"
            )

    def test_partial_risks_have_gap(self) -> None:
        """Risks with partial coverage must document a gap."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            if risk.coverage_level == "partial":
                assert risk.gap, f"{risk.risk_id} is partial but has no documented gap"

    def test_full_risks_have_empty_gap(self) -> None:
        """Risks with full coverage should have no gap."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            if risk.coverage_level == "full":
                assert not risk.gap, f"{risk.risk_id} is full but has a gap: {risk.gap}"

    def test_eu_ai_act_returns_report(self) -> None:
        """EU AI Act report has correct structure."""
        report = get_compliance_report("eu-ai-act")
        assert report.framework_id == "eu-ai-act"
        assert len(report.risks) >= 5

    def test_nist_ai_rmf_returns_report(self) -> None:
        """NIST AI RMF report has correct structure."""
        report = get_compliance_report("nist-ai-rmf")
        assert report.framework_id == "nist-ai-rmf"
        assert len(report.risks) >= 4

    def test_unknown_framework_raises(self) -> None:
        """Unknown framework ID raises ValueError."""
        with pytest.raises(ValueError, match="Unknown framework"):
            get_compliance_report("unknown-framework")


class TestComplianceReportSerialization:
    """Tests for report output formats."""

    def test_to_dict(self) -> None:
        """to_dict returns a JSON-serializable dict."""
        report = get_compliance_report("owasp-asi-2026")
        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["framework_id"] == "owasp-asi-2026"
        assert len(d["risks"]) == 10

    def test_to_json_valid(self) -> None:
        """to_json returns valid JSON."""
        report = get_compliance_report("owasp-asi-2026")
        j = report.to_json()
        parsed = json.loads(j)
        assert parsed["framework_id"] == "owasp-asi-2026"
        assert len(parsed["risks"]) == 10

    def test_to_markdown_contains_headers(self) -> None:
        """Markdown output contains framework name and risk headers."""
        report = get_compliance_report("owasp-asi-2026")
        md = report.to_markdown()
        assert "OWASP Agentic Security Initiative" in md
        assert "OWASP-ASI-01" in md
        assert "OWASP-ASI-10" in md
        assert "| Risk ID |" in md

    def test_to_markdown_contains_evidence_table(self) -> None:
        """Markdown output contains evidence tables."""
        report = get_compliance_report("owasp-asi-2026")
        md = report.to_markdown()
        assert "| File |" in md
        assert "src/gateway/interceptor.py" in md

    def test_to_json_roundtrip(self) -> None:
        """JSON can be parsed back to matching structure."""
        report = get_compliance_report("owasp-asi-2026")
        parsed = json.loads(report.to_json())
        assert parsed["risks"][0]["risk_id"] == "OWASP-ASI-01"
        assert parsed["risks"][0]["evidence"][0]["file"] == "src/gateway/interceptor.py"


class TestEvidenceItems:
    """Tests for evidence integrity."""

    def test_evidence_has_file_paths(self) -> None:
        """Every evidence item references a real file path."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            for ev in risk.evidence:
                assert ev.file.startswith("src/"), (
                    f"{risk.risk_id}: evidence file '{ev.file}' does not start with src/"
                )

    def test_evidence_has_detail(self) -> None:
        """Every evidence item has a non-empty detail string."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            for ev in risk.evidence:
                assert ev.detail, f"{risk.risk_id}: evidence for {ev.file} has no detail"

    def test_evidence_has_component(self) -> None:
        """Every evidence item names a function or component."""
        report = get_compliance_report("owasp-asi-2026")
        for risk in report.risks:
            for ev in risk.evidence:
                assert ev.function_or_component, (
                    f"{risk.risk_id}: evidence for {ev.file} has no component"
                )


class TestCrossFramework:
    """Tests that apply to all frameworks."""

    @pytest.mark.parametrize("framework_id", ["owasp-asi-2026", "eu-ai-act", "nist-ai-rmf"])
    def test_generated_by_codetrust(self, framework_id: str) -> None:
        """All reports identify CodeTrust as the generator."""
        report = get_compliance_report(framework_id)
        assert "CodeTrust" in report.generated_by

    @pytest.mark.parametrize("framework_id", ["owasp-asi-2026", "eu-ai-act", "nist-ai-rmf"])
    def test_all_risks_have_names(self, framework_id: str) -> None:
        """Every risk has a non-empty name."""
        report = get_compliance_report(framework_id)
        for risk in report.risks:
            assert risk.risk_name, f"{risk.risk_id} has no name"

    @pytest.mark.parametrize("framework_id", ["owasp-asi-2026", "eu-ai-act", "nist-ai-rmf"])
    def test_markdown_not_empty(self, framework_id: str) -> None:
        """Markdown output is non-trivial."""
        report = get_compliance_report(framework_id)
        md = report.to_markdown()
        assert len(md) > 500, f"{framework_id} markdown is suspiciously short"

    @pytest.mark.parametrize("framework_id", ["owasp-asi-2026", "eu-ai-act", "nist-ai-rmf"])
    def test_json_not_empty(self, framework_id: str) -> None:
        """JSON output is non-trivial."""
        report = get_compliance_report(framework_id)
        j = report.to_json()
        assert len(j) > 500, f"{framework_id} JSON is suspiciously short"


class TestComplianceEnforcement:
    """Tests for is_fully_compliant and compliance_summary."""

    def test_owasp_asi_fully_compliant(self) -> None:
        """OWASP ASI 2026 should be fully compliant (10/10 full)."""
        assert is_fully_compliant("owasp-asi-2026") is True

    def test_eu_ai_act_fully_compliant(self) -> None:
        """EU AI Act should be fully compliant (7/7 full)."""
        assert is_fully_compliant("eu-ai-act") is True

    def test_nist_fully_compliant(self) -> None:
        """NIST AI RMF should be fully compliant (4/4 full)."""
        assert is_fully_compliant("nist-ai-rmf") is True

    def test_unknown_framework_raises(self) -> None:
        """is_fully_compliant raises ValueError for unknown framework."""
        with pytest.raises(ValueError, match="Unknown framework"):
            is_fully_compliant("nonexistent")

    def test_summary_owasp_all_full(self) -> None:
        """Summary for OWASP ASI should be '10/10 full' with no partial."""
        report = get_compliance_report("owasp-asi-2026")
        s = compliance_summary(report)
        assert s == "10/10 full"

    def test_summary_eu_all_full(self) -> None:
        """Summary for EU AI Act should be '7/7 full'."""
        report = get_compliance_report("eu-ai-act")
        s = compliance_summary(report)
        assert s == "7/7 full"

    def test_summary_nist_all_full(self) -> None:
        """Summary for NIST should be '4/4 full'."""
        report = get_compliance_report("nist-ai-rmf")
        s = compliance_summary(report)
        assert s == "4/4 full"
