"""Tests for SARIF output formatter."""

import json

import pytest

from src.formatters.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    TOOL_NAME,
    _build_location,
    _build_results,
    _build_rules,
    deep_scan_to_sarif,
    findings_to_sarif,
    static_scan_to_sarif,
)
from src.models.enums import Severity
from src.models.responses import (
    AstScanResponse,
    DeepScanResponse,
    Finding,
    StaticScanResponse,
)

# --- Fixtures ---


@pytest.fixture()
def block_finding() -> Finding:
    """Create a BLOCK severity finding."""
    return Finding(
        rule_id="eval_exec",
        severity=Severity.BLOCK,
        message="eval/exec is a security risk",
        file="app.py",
        line=10,
        suggestion="Use safe alternatives",
        confidence=1.0,
    )


@pytest.fixture()
def warn_finding() -> Finding:
    """Create a WARN severity finding."""
    return Finding(
        rule_id="todo_marker",
        severity=Severity.WARN,
        message="TODO marker found",
        file="utils.py",
        line=25,
    )


@pytest.fixture()
def info_finding() -> Finding:
    """Create an INFO severity finding."""
    return Finding(
        rule_id="missing_docstring",
        severity=Severity.INFO,
        message="Function missing docstring",
        file="helpers.py",
        line=5,
    )


@pytest.fixture()
def sample_findings(
    block_finding: Finding,
    warn_finding: Finding,
    info_finding: Finding,
) -> list[Finding]:
    """List of mixed-severity findings."""
    return [block_finding, warn_finding, info_finding]


# --- SARIF structure tests ---


class TestSarifStructure:
    """Test overall SARIF document structure."""

    def test_schema_present(self, sample_findings: list[Finding]) -> None:
        """SARIF output includes $schema."""
        sarif = findings_to_sarif(sample_findings)
        assert sarif["$schema"] == SARIF_SCHEMA

    def test_version_present(self, sample_findings: list[Finding]) -> None:
        """SARIF output includes version."""
        sarif = findings_to_sarif(sample_findings)
        assert sarif["version"] == SARIF_VERSION

    def test_has_runs(self, sample_findings: list[Finding]) -> None:
        """SARIF output has exactly one run."""
        sarif = findings_to_sarif(sample_findings)
        assert len(sarif["runs"]) == 1

    def test_tool_name(self, sample_findings: list[Finding]) -> None:
        """Tool driver name is CodeTrust."""
        sarif = findings_to_sarif(sample_findings)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == TOOL_NAME

    def test_tool_version(self, sample_findings: list[Finding]) -> None:
        """Tool version can be overridden."""
        sarif = findings_to_sarif(sample_findings, tool_version="1.2.3")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["version"] == "1.2.3"

    def test_default_version_from_settings(
        self, sample_findings: list[Finding],
    ) -> None:
        """Tool version defaults to settings.version."""
        sarif = findings_to_sarif(sample_findings)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert isinstance(driver["version"], str)
        assert len(driver["version"]) > 0

    def test_valid_json(self, sample_findings: list[Finding]) -> None:
        """SARIF output is valid JSON when serialized."""
        sarif = findings_to_sarif(sample_findings)
        text = json.dumps(sarif, indent=2)
        parsed = json.loads(text)
        assert parsed["$schema"] == SARIF_SCHEMA


class TestSarifRules:
    """Test SARIF rule descriptor generation."""

    def test_rule_count_matches_unique_ids(
        self, sample_findings: list[Finding],
    ) -> None:
        """Number of rules matches unique rule_ids."""
        rules = _build_rules(sample_findings)
        unique_ids = {f.rule_id for f in sample_findings}
        assert len(rules) == len(unique_ids)

    def test_rule_has_id(self, block_finding: Finding) -> None:
        """Each rule has an id."""
        rules = _build_rules([block_finding])
        assert rules[0]["id"] == "eval_exec"

    def test_rule_has_description(self, block_finding: Finding) -> None:
        """Each rule has a short description."""
        rules = _build_rules([block_finding])
        assert "text" in rules[0]["shortDescription"]

    def test_block_rule_level_is_error(self, block_finding: Finding) -> None:
        """BLOCK severity maps to error level."""
        rules = _build_rules([block_finding])
        assert rules[0]["defaultConfiguration"]["level"] == "error"

    def test_warn_rule_level_is_warning(self, warn_finding: Finding) -> None:
        """WARN severity maps to warning level."""
        rules = _build_rules([warn_finding])
        assert rules[0]["defaultConfiguration"]["level"] == "warning"

    def test_info_rule_level_is_note(self, info_finding: Finding) -> None:
        """INFO severity maps to note level."""
        rules = _build_rules([info_finding])
        assert rules[0]["defaultConfiguration"]["level"] == "note"

    def test_security_severity_present(self, block_finding: Finding) -> None:
        """Rules include security-severity property."""
        rules = _build_rules([block_finding])
        assert "security-severity" in rules[0]["properties"]
        assert rules[0]["properties"]["security-severity"] == "high"

    def test_duplicate_rules_deduplicated(self) -> None:
        """Same rule_id appearing multiple times creates one rule."""
        findings = [
            Finding(
                rule_id="eval_exec", severity=Severity.BLOCK,
                message="eval found", file="a.py", line=1,
            ),
            Finding(
                rule_id="eval_exec", severity=Severity.BLOCK,
                message="exec found", file="b.py", line=5,
            ),
        ]
        rules = _build_rules(findings)
        assert len(rules) == 1


class TestSarifResults:
    """Test SARIF result generation."""

    def test_result_count_matches_findings(
        self, sample_findings: list[Finding],
    ) -> None:
        """Number of results matches number of findings."""
        results = _build_results(sample_findings)
        assert len(results) == len(sample_findings)

    def test_result_has_rule_id(self, block_finding: Finding) -> None:
        """Each result references its rule id."""
        results = _build_results([block_finding])
        assert results[0]["ruleId"] == "eval_exec"

    def test_result_has_message(self, block_finding: Finding) -> None:
        """Each result has a message."""
        results = _build_results([block_finding])
        assert "text" in results[0]["message"]

    def test_result_level_matches_severity(
        self, block_finding: Finding,
    ) -> None:
        """Result level matches the finding severity."""
        results = _build_results([block_finding])
        assert results[0]["level"] == "error"

    def test_result_has_location(self, block_finding: Finding) -> None:
        """Each result has at least one location."""
        results = _build_results([block_finding])
        assert len(results[0]["locations"]) == 1

    def test_suggestion_appended_to_message(self, block_finding: Finding) -> None:
        """Finding with suggestion includes it in the message text."""
        results = _build_results([block_finding])
        msg = results[0]["message"]["text"]
        assert "Use safe alternatives" in msg
        assert "→" in msg
        assert "fixes" not in results[0]

    def test_no_suggestion_plain_message(self, warn_finding: Finding) -> None:
        """Finding without suggestion has plain message text."""
        results = _build_results([warn_finding])
        msg = results[0]["message"]["text"]
        assert "→" not in msg
        assert "fixes" not in results[0]


class TestSarifLocations:
    """Test SARIF location building."""

    def test_location_has_uri(self, block_finding: Finding) -> None:
        """Location includes artifact URI."""
        loc = _build_location(block_finding)
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "app.py"

    def test_location_has_line(self, block_finding: Finding) -> None:
        """Location includes the start line."""
        loc = _build_location(block_finding)
        region = loc["physicalLocation"]["region"]
        assert region["startLine"] == 10

    def test_zero_line_becomes_one(self) -> None:
        """Line 0 is clamped to 1 (SARIF is 1-indexed)."""
        finding = Finding(
            rule_id="test", severity=Severity.INFO,
            message="test", file="x.py", line=0,
        )
        loc = _build_location(finding)
        assert loc["physicalLocation"]["region"]["startLine"] == 1

    def test_empty_file_uses_unknown(self) -> None:
        """Empty file field uses 'unknown'."""
        finding = Finding(
            rule_id="test", severity=Severity.INFO,
            message="test",
        )
        loc = _build_location(finding)
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "unknown"


class TestStaticScanToSarif:
    """Test static scan response to SARIF conversion."""

    def test_converts_static_scan(
        self, sample_findings: list[Finding],
    ) -> None:
        """StaticScanResponse converts to valid SARIF."""
        response = StaticScanResponse(
            total_findings=3, blocks=1, warnings=1,
            infos=1, findings=sample_findings, verdict="BLOCK",
        )
        sarif = static_scan_to_sarif(response)
        assert sarif["version"] == SARIF_VERSION
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_empty_findings(self) -> None:
        """Empty findings produce valid SARIF with no results."""
        response = StaticScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )
        sarif = static_scan_to_sarif(response)
        assert len(sarif["runs"][0]["results"]) == 0


class TestDeepScanToSarif:
    """Test deep scan response to SARIF conversion."""

    def test_merges_static_and_ast(self) -> None:
        """Deep scan merges static and AST findings."""
        static_findings = [
            Finding(
                rule_id="eval_exec", severity=Severity.BLOCK,
                message="eval found", file="a.py", line=1,
            ),
        ]
        ast_findings = [
            Finding(
                rule_id="deep_nesting", severity=Severity.WARN,
                message="Deep nesting", file="a.py", line=5,
            ),
        ]

        static = StaticScanResponse(
            total_findings=1, blocks=1, warnings=0,
            infos=0, findings=static_findings, verdict="BLOCK",
        )
        ast = AstScanResponse(
            total_findings=1, blocks=0, warnings=1,
            infos=0, findings=ast_findings, verdict="WARN",
        )
        deep = DeepScanResponse(
            static_scan=static,
            ast_scan=ast,
            overall_verdict="BLOCK",
            total_findings=2,
            latency_ms=100,
        )

        sarif = deep_scan_to_sarif(deep)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2

    def test_no_ast_scan(self) -> None:
        """Deep scan without AST only includes static findings."""
        static = StaticScanResponse(
            total_findings=1, blocks=1, warnings=0,
            infos=0,
            findings=[
                Finding(
                    rule_id="eval_exec", severity=Severity.BLOCK,
                    message="eval found", file="a.py", line=1,
                ),
            ],
            verdict="BLOCK",
        )
        deep = DeepScanResponse(
            static_scan=static,
            overall_verdict="BLOCK",
            total_findings=1,
            latency_ms=50,
        )

        sarif = deep_scan_to_sarif(deep)
        results = sarif["runs"][0]["results"]
        assert len(results) == 1

    def test_empty_deep_scan(self) -> None:
        """Deep scan with no findings produces empty results."""
        static = StaticScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )
        deep = DeepScanResponse(
            static_scan=static,
            overall_verdict="PASS",
            total_findings=0,
            latency_ms=10,
        )

        sarif = deep_scan_to_sarif(deep)
        assert len(sarif["runs"][0]["results"]) == 0


class TestSarifSerialization:
    """Test SARIF JSON serialization."""

    def test_roundtrip(self, sample_findings: list[Finding]) -> None:
        """SARIF survives JSON roundtrip."""
        sarif = findings_to_sarif(sample_findings)
        text = json.dumps(sarif)
        parsed = json.loads(text)
        assert parsed["version"] == SARIF_VERSION
        assert len(parsed["runs"][0]["results"]) == 3

    def test_no_none_values(self, sample_findings: list[Finding]) -> None:
        """SARIF output doesn't contain None values."""
        sarif = findings_to_sarif(sample_findings)
        text = json.dumps(sarif)
        assert "null" not in text
