# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Governance Report — NIST AI RMF Govern function compliance.

Generates formal governance documentation from:
- .codetrust.toml policy config
- Policy engine settings
- Doctor output (enforcement layers)
- DoD checks
- Risk register
- Compliance status
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class GovernanceSection:
    """A section of the governance report."""

    title: str
    content: str
    status: str = "documented"


@dataclass
class GovernanceReport:
    """Full governance documentation report."""

    timestamp: str
    sections: list[GovernanceSection] = field(default_factory=list)

    @property
    def summary(self) -> str:
        """Build summary."""
        return f"{len(self.sections)} governance areas documented"


def _load_toml_config(path: Path) -> dict:
    """Load a TOML config file.

    Args:
        path: Path to the TOML file.

    Returns:
        Parsed dict or empty dict if not found.
    """
    if not path.is_file():
        return {}
    try:
        return tomllib.loads(path.read_bytes().decode("utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def generate_governance_report(project_dir: Path | None = None) -> GovernanceReport:
    """Generate a formal governance report.

    Args:
        project_dir: Project root. Defaults to CWD.

    Returns:
        GovernanceReport with all sections.
    """
    root = project_dir or Path.cwd()
    report = GovernanceReport(timestamp=datetime.now(tz=UTC).isoformat())

    # Section 1: Policy Configuration
    toml_config = _load_toml_config(root / ".codetrust.toml")
    policy = toml_config.get("policy", {})
    mode = toml_config.get("governance", {}).get("mode", "enforce")
    report.sections.append(GovernanceSection(
        title="Policy Configuration",
        content=(
            f"Governance mode: {mode}\n"
            f"Allowed models: {policy.get('models_allowed', 'all')}\n"
            f"Blocked models: {policy.get('models_blocked', 'none')}\n"
            f"Max AI ratio: {policy.get('max_ai_ratio', 1.0)}\n"
            f"Require human review: {policy.get('require_human_review', False)}"
        ),
    ))

    # Section 2: Enforcement Layers
    layers = [
        "BASH_ENV guard (universal shell enforcement)",
        "PreToolUse hooks (CLI real-time interception)",
        "MCP Gateway + Guardian (proxy validation)",
        "Pre-commit hook (commit gate)",
        "GitHub Action (PR gate)",
        "Advisory files (CLAUDE.md, .cursorrules)",
        "Governance config (.codetrust.toml)",
        "Allow-list audit (bypass detection)",
        "Compliance coverage (framework mapping)",
    ]
    report.sections.append(GovernanceSection(
        title="Enforcement Architecture",
        content=f"{len(layers)} enforcement layers:\n" + "\n".join(
            f"  {i}. {layer}" for i, layer in enumerate(layers, 1)
        ),
    ))

    # Section 3: Definition of Done
    dod_path = root / ".codetrust" / "definition_of_done.toml"
    if dod_path.is_file():
        dod_config = _load_toml_config(dod_path)
        checks = dod_config.get("checks", [])
        check_names = [c.get("name", "") for c in checks if isinstance(c, dict)]
        report.sections.append(GovernanceSection(
            title="Definition of Done",
            content=f"{len(check_names)} acceptance checks:\n" + "\n".join(
                f"  - {name}" for name in check_names
            ),
        ))
    else:
        report.sections.append(GovernanceSection(
            title="Definition of Done",
            content="No DoD file found. Run 'codetrust init' to create one.",
            status="missing",
        ))

    # Section 4: Risk Register
    reg_path = root / ".codetrust" / "risk-register.toml"
    if reg_path.is_file():
        from src.services.risk_register import load_register
        register = load_register(reg_path)
        report.sections.append(GovernanceSection(
            title="Risk Register",
            content=register.summary(),
        ))
    else:
        report.sections.append(GovernanceSection(
            title="Risk Register",
            content="No risk register found. Run 'codetrust risk-register init' to create one.",
            status="missing",
        ))

    # Section 5: Compliance Frameworks
    try:
        from src.services.compliance import (
            compliance_summary,
            get_compliance_report,
            list_frameworks,
        )
        fw_lines: list[str] = []
        for fid, fname in list_frameworks().items():
            r = get_compliance_report(fid)
            fw_lines.append(f"  {fname}: {compliance_summary(r)}")
        report.sections.append(GovernanceSection(
            title="Compliance Frameworks",
            content="\n".join(fw_lines),
        ))
    except (ImportError, ValueError) as exc:
        report.sections.append(GovernanceSection(
            title="Compliance Frameworks",
            content=f"Error loading compliance module: {exc}",
            status="error",
        ))

    return report


def format_governance_report(report: GovernanceReport) -> str:
    """Format governance report as Markdown.

    Args:
        report: Report to format.

    Returns:
        Markdown string.
    """
    lines: list[str] = [
        "# AI Governance Report",
        "",
        f"**Generated:** {report.timestamp}",
        f"**{report.summary}**",
        "",
    ]

    for i, section in enumerate(report.sections, 1):
        lines.append(f"## {i}. {section.title}")
        lines.append("")
        lines.append(section.content)
        lines.append("")

    return "\n".join(lines)
