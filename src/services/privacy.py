# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Privacy Report — EU AI Act data governance compliance.

Documents what data CodeTrust collects, where it's stored, retention policy,
and how to disable collection. GDPR-relevant: no PII by design.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class DataCategory:
    """A category of collected data."""

    name: str
    description: str
    contains_pii: bool
    storage: str
    retention: str
    opt_out: str


TELEMETRY_DATA: list[DataCategory] = [
    DataCategory(
        name="Scan events",
        description="Anonymous scan count, severity distribution, language",
        contains_pii=False,
        storage="Redis (ephemeral) + PostgreSQL (persistent)",
        retention="90 days default (configurable via CODETRUST_RETENTION_DAYS)",
        opt_out="Set CODETRUST_TELEMETRY=0 or codetrust.telemetry_enabled=false in .codetrust.toml",
    ),
    DataCategory(
        name="Installation ID",
        description="Random UUID per installation, not linked to user identity",
        contains_pii=False,
        storage="Local file (~/.codetrust/installation_id)",
        retention="Permanent (local only)",
        opt_out="Delete ~/.codetrust/installation_id",
    ),
    DataCategory(
        name="Audit log",
        description="Commands validated by gateway, verdicts (ALLOW/WARN/BLOCK), rule IDs",
        contains_pii=False,
        storage="Local JSONL file (.codetrust/audit.jsonl)",
        retention="90 days default (purge via: codetrust audit --purge)",
        opt_out="Set audit_enabled=false in .codetrust.toml",
    ),
    DataCategory(
        name="Attribution events",
        description="AI model name, editor name, timestamp per file edit",
        contains_pii=False,
        storage="Local JSONL file (.codetrust/attribution.jsonl)",
        retention="Permanent (local only, never transmitted)",
        opt_out="Disable VS Code extension LLM interceptor",
    ),
]

NOT_COLLECTED: list[str] = [
    "Source code content — never transmitted, scanned locally",
    "File paths — never included in telemetry events",
    "IP addresses — not logged by the API",
    "User names or email addresses — not part of telemetry schema",
    "Git commit content — attribution uses trailers only",
    "Credentials or API keys — redacted from all logs",
]


@dataclass
class PrivacyReport:
    """Full privacy and data governance report."""

    data_categories: list[DataCategory] = field(default_factory=lambda: list(TELEMETRY_DATA))
    not_collected: list[str] = field(default_factory=lambda: list(NOT_COLLECTED))
    telemetry_enabled: bool = True
    retention_days: int = 90

    @property
    def has_pii(self) -> bool:
        """True if any data category contains PII."""
        return any(d.contains_pii for d in self.data_categories)


def generate_privacy_report() -> PrivacyReport:
    """Generate a privacy report based on current configuration.

    Returns:
        PrivacyReport reflecting current telemetry settings.
    """
    telemetry_enabled = os.environ.get("CODETRUST_TELEMETRY", "1") != "0"
    try:
        retention_days = int(os.environ.get("CODETRUST_RETENTION_DAYS", "90"))
    except (ValueError, TypeError):
        retention_days = 90

    return PrivacyReport(
        telemetry_enabled=telemetry_enabled,
        retention_days=retention_days,
    )


def format_privacy_report(report: PrivacyReport) -> str:
    """Format privacy report as Markdown.

    Args:
        report: The report to format.

    Returns:
        Markdown string.
    """
    status = "ENABLED" if report.telemetry_enabled else "DISABLED"
    lines: list[str] = [
        "# Privacy & Data Governance Report",
        "",
        f"**Telemetry:** {status}",
        f"**Retention:** {report.retention_days} days",
        f"**PII collected:** {'Yes' if report.has_pii else 'No'}",
        "",
        "## Data Collected",
        "",
        "| Category | PII | Storage | Retention | Opt-out |",
        "|----------|-----|---------|-----------|---------|",
    ]

    for d in report.data_categories:
        pii = "Yes" if d.contains_pii else "No"
        lines.append(f"| {d.name} | {pii} | {d.storage} | {d.retention} | {d.opt_out} |")

    lines.extend([
        "",
        "## Data NOT Collected",
        "",
    ])
    for item in report.not_collected:
        lines.append(f"- {item}")

    lines.extend([
        "",
        "## GDPR Compliance",
        "",
        "- No PII collected by design",
        "- Anonymous installation IDs (random UUID, not linked to identity)",
        "- All telemetry can be disabled via environment variable",
        "- Local audit logs never transmitted to external servers",
        "- Retention configurable and enforceable via purge command",
    ])

    return "\n".join(lines)
