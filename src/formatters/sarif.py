"""SARIF v2.1.0 output formatter for CodeTrust findings.

Converts CodeTrust Finding objects into SARIF (Static Analysis Results
Interchange Format) JSON, compatible with GitHub Security tab and other
SARIF-consuming tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import structlog

from src.config import settings
from src.models.enums import Severity
from src.models.responses import (
    DeepScanResponse,
    Finding,
    StaticScanResponse,
)

logger = structlog.get_logger()

# SARIF severity mapping
_SEVERITY_MAP: dict[Severity, str] = {
    Severity.BLOCK: "error",
    Severity.WARN: "warning",
    Severity.INFO: "note",
}

# SARIF security severity mapping (for GitHub)
_SECURITY_SEVERITY_MAP: dict[Severity, str] = {
    Severity.BLOCK: "high",
    Severity.WARN: "medium",
    Severity.INFO: "low",
}

SARIF_SCHEMA = settings.sarif_schema_url
SARIF_VERSION = "2.1.0"
TOOL_NAME = "CodeTrust"
TOOL_INFO_URI = settings.tool_info_uri


def findings_to_sarif(
    findings: list[Finding],
    tool_version: str = "",
) -> dict[str, object]:
    """Convert a list of Finding objects to SARIF JSON.

    Args:
        findings: List of CodeTrust findings.
        tool_version: Tool version string.

    Returns:
        SARIF v2.1.0 compliant dictionary.
    """
    version = tool_version or settings.version
    rules = _build_rules(findings)
    results = _build_results(findings)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": version,
                        "informationUri": TOOL_INFO_URI,
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }


def static_scan_to_sarif(
    response: StaticScanResponse,
    tool_version: str = "",
) -> dict[str, object]:
    """Convert a StaticScanResponse to SARIF JSON.

    Args:
        response: Static scan response with findings.
        tool_version: Tool version string.

    Returns:
        SARIF v2.1.0 compliant dictionary.
    """
    return findings_to_sarif(response.findings, tool_version)


def deep_scan_to_sarif(
    response: DeepScanResponse,
    tool_version: str = "",
) -> dict[str, object]:
    """Convert a DeepScanResponse to SARIF JSON.

    Merges findings from static scan, AST scan, and import/docker
    verification into a single SARIF document.

    Args:
        response: Deep scan response with all layers.
        tool_version: Tool version string.

    Returns:
        SARIF v2.1.0 compliant dictionary.
    """
    all_findings: list[Finding] = list(response.static_scan.findings)

    if response.ast_scan is not None:
        all_findings.extend(response.ast_scan.findings)

    return findings_to_sarif(all_findings, tool_version)


def _build_rules(findings: list[Finding]) -> list[dict[str, object]]:
    """Build unique SARIF rule descriptors from findings.

    Returns one rule entry per unique rule_id found in the findings list.
    """
    seen: set[str] = set()
    rules: list[dict[str, object]] = []

    for finding in findings:
        if finding.rule_id in seen:
            continue
        seen.add(finding.rule_id)

        rule: dict[str, object] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.message},
            "defaultConfiguration": {
                "level": _SEVERITY_MAP.get(finding.severity, "note"),
            },
            "properties": {
                "security-severity": _SECURITY_SEVERITY_MAP.get(
                    finding.severity, "low",
                ),
            },
        }
        rules.append(rule)

    return rules


def _build_results(findings: list[Finding]) -> list[dict[str, object]]:
    """Build SARIF result entries from findings."""
    results: list[dict[str, object]] = []

    for finding in findings:
        message_text = finding.message
        if finding.suggestion:
            message_text = f"{finding.message} → {finding.suggestion}"

        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "level": _SEVERITY_MAP.get(finding.severity, "note"),
            "message": {"text": message_text},
            "locations": [
                _build_location(finding),
            ],
        }

        results.append(result)

    return results


def _build_location(finding: Finding) -> dict[str, object]:
    """Build a SARIF location object from a finding."""
    uri = finding.file or "unknown"
    line = max(finding.line, 1)

    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {
                "startLine": line,
                "startColumn": 1,
            },
        },
    }
