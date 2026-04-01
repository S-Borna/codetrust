# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Risk Map — NIST AI RMF Map function compliance.

Automated risk catalog generated from scan results, taint analysis,
fleet discovery, allow-list audit, and trust score trends.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class RiskItem:
    """A single identified risk from automated analysis."""

    category: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description: str
    source: str
    count: int = 1


@dataclass
class RiskMap:
    """Aggregated risk map from multiple sources."""

    risks: list[RiskItem] = field(default_factory=list)

    @property
    def by_category(self) -> dict[str, list[RiskItem]]:
        """Group risks by category."""
        grouped: dict[str, list[RiskItem]] = {}
        for r in self.risks:
            grouped.setdefault(r.category, []).append(r)
        return grouped

    @property
    def by_severity(self) -> dict[str, int]:
        """Count risks per severity."""
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for r in self.risks:
            counts[r.severity] = counts.get(r.severity, 0) + r.count
        return counts

    @property
    def top_risks(self) -> list[RiskItem]:
        """Top 10 risks by severity."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_risks = sorted(
            self.risks,
            key=lambda r: (severity_order.get(r.severity, 4), -r.count),
        )
        return sorted_risks[:10]

    @property
    def summary(self) -> str:
        """Build summary string."""
        sev = self.by_severity
        parts = []
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if sev[level]:
                parts.append(f"{sev[level]} {level}")
        return ", ".join(parts) if parts else "No risks identified"


def generate_risk_map(project_dir: Path | None = None) -> RiskMap:
    """Generate an automated risk map from project state.

    Args:
        project_dir: Project root. Defaults to CWD.

    Returns:
        RiskMap with identified risks.
    """
    root = project_dir or Path.cwd()
    risk_map = RiskMap()

    # Source 1: Allow-list audit
    try:
        from src.cli import audit_allow_list
        findings = audit_allow_list(root)
        for f in findings:
            risk_map.risks.append(RiskItem(
                category="permission_bypass",
                severity="CRITICAL",
                description=f"Allow-list bypass: {f['entry']} — {f['reason']}",
                source="allow-list audit",
            ))
    except (ImportError, OSError):
        pass

    # Source 2: Scan findings from latest report
    report_dir = root / ".codetrust" / "reports"
    if report_dir.is_dir():
        try:
            import json
            reports = sorted(report_dir.glob("*.json"), reverse=True)
            if reports:
                data = json.loads(reports[0].read_text(encoding="utf-8"))
                for finding in data.get("files", {}).values():
                    if isinstance(finding, list):
                        for f in finding:
                            sev = f.get("severity", "WARN")
                            risk_map.risks.append(RiskItem(
                                category=f.get("rule_id", "unknown")[:30],
                                severity="HIGH" if sev == "BLOCK" else "MEDIUM",
                                description=f.get("message", "")[:200],
                                source="scan report",
                            ))
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    # Source 3: Risk register open items
    reg_path = root / ".codetrust" / "risk-register.toml"
    if reg_path.is_file():
        try:
            from src.services.risk_register import load_register
            register = load_register(reg_path)
            for risk in register.open_risks:
                severity = "CRITICAL" if risk.risk_score >= 20 else (
                    "HIGH" if risk.risk_score >= 15 else (
                        "MEDIUM" if risk.risk_score >= 10 else "LOW"
                    )
                )
                risk_map.risks.append(RiskItem(
                    category="registered_risk",
                    severity=severity,
                    description=risk.title,
                    source="risk register",
                ))
        except (ImportError, OSError):
            pass

    return risk_map


def format_risk_map(risk_map: RiskMap) -> str:
    """Format risk map as Markdown.

    Args:
        risk_map: Map to format.

    Returns:
        Markdown string.
    """
    lines: list[str] = [
        "# Risk Map",
        "",
        f"**{risk_map.summary}**",
        "",
        "## Severity Distribution",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev, count in risk_map.by_severity.items():
        lines.append(f"| {sev} | {count} |")

    lines.extend(["", "## Top 10 Risks", ""])
    if risk_map.top_risks:
        lines.append("| # | Severity | Category | Description | Source |")
        lines.append("|---|----------|----------|-------------|--------|")
        for i, r in enumerate(risk_map.top_risks, 1):
            lines.append(
                f"| {i} | {r.severity} | {r.category} | {r.description[:60]} | {r.source} |",
            )
    else:
        lines.append("No risks identified.")

    return "\n".join(lines)
