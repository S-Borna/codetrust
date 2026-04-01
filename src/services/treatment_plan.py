# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Treatment Plan — NIST AI RMF Manage function compliance.

Risk treatment tracking: import BLOCK findings, track resolution status,
connect to guided remediation, measure progress.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

PLAN_PATH = Path(".codetrust") / "treatment-plan.toml"


def _toml_escape(value: str) -> str:
    """Escape a string for use in a TOML basic string (double-quoted)."""
    return (
        value
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )

VALID_TREATMENT_STATUSES = frozenset({
    "open", "in_progress", "mitigated", "accepted", "false_positive",
})


@dataclass
class TreatmentItem:
    """A single finding under treatment."""

    finding_id: str
    rule_id: str
    file: str
    message: str
    severity: str
    status: str
    remediation: str
    assigned_to: str = ""
    updated: str = ""


@dataclass
class TreatmentPlan:
    """Collection of treatment items."""

    items: list[TreatmentItem] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Total items in plan."""
        return len(self.items)

    @property
    def addressed(self) -> int:
        """Items that are not 'open'."""
        return sum(1 for i in self.items if i.status != "open")

    @property
    def progress(self) -> str:
        """Progress string like '47/89 findings addressed (53%)'."""
        if self.total == 0:
            return "0 findings"
        pct = self.addressed / self.total * 100
        return f"{self.addressed}/{self.total} findings addressed ({pct:.0f}%)"

    @property
    def open_items(self) -> list[TreatmentItem]:
        """Items still open."""
        return [i for i in self.items if i.status == "open"]


def load_treatment_plan(path: Path | None = None) -> TreatmentPlan:
    """Load treatment plan from TOML file.

    Args:
        path: Path to treatment-plan.toml.

    Returns:
        TreatmentPlan with all items.
    """
    plan_path = path or PLAN_PATH
    if not plan_path.is_file():
        return TreatmentPlan()

    data = tomllib.loads(plan_path.read_bytes().decode("utf-8"))
    items: list[TreatmentItem] = []
    for entry in data.get("items", []):
        if not isinstance(entry, dict):
            continue
        items.append(TreatmentItem(
            finding_id=str(entry.get("finding_id", "")),
            rule_id=str(entry.get("rule_id", "")),
            file=str(entry.get("file", "")),
            message=str(entry.get("message", "")),
            severity=str(entry.get("severity", "")),
            status=str(entry.get("status", "open")),
            remediation=str(entry.get("remediation", "")),
            assigned_to=str(entry.get("assigned_to", "")),
            updated=str(entry.get("updated", "")),
        ))
    return TreatmentPlan(items=items)


def import_findings_to_plan(
    plan: TreatmentPlan,
    scan_report_path: Path,
) -> int:
    """Import BLOCK findings from a scan report into the treatment plan.

    Args:
        plan: Existing plan to add to.
        scan_report_path: Path to JSON scan report.

    Returns:
        Number of new findings imported.
    """
    try:
        data = json.loads(scan_report_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return 0

    existing_ids = {i.finding_id for i in plan.items}
    imported = 0

    files_data = data.get("files", {})
    for filepath, findings in files_data.items():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if finding.get("severity") != "BLOCK":
                continue
            fid = f"{finding.get('rule_id', '')}:{filepath}:{finding.get('line', 0)}"
            if fid in existing_ids:
                continue
            plan.items.append(TreatmentItem(
                finding_id=fid,
                rule_id=str(finding.get("rule_id", "")),
                file=filepath,
                message=str(finding.get("message", ""))[:200],
                severity="BLOCK",
                status="open",
                remediation=str(finding.get("suggestion", "")),
                updated=datetime.now(tz=UTC).date().isoformat(),
            ))
            imported += 1

    return imported


def save_treatment_plan(plan: TreatmentPlan, path: Path | None = None) -> Path:
    """Save treatment plan to TOML file.

    Args:
        plan: Plan to save.
        path: Output path.

    Returns:
        Path to saved file.
    """
    plan_path = path or PLAN_PATH
    plan_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [
        "# Treatment Plan — NIST AI RMF Risk Management",
        f"# Updated: {datetime.now(tz=UTC).isoformat()}",
        f"# Progress: {plan.progress}",
        "",
    ]
    for item in plan.items:
        lines.append("[[items]]")
        lines.append(f'finding_id = "{_toml_escape(item.finding_id)}"')
        lines.append(f'rule_id = "{_toml_escape(item.rule_id)}"')
        lines.append(f'file = "{_toml_escape(item.file)}"')
        lines.append(f'message = "{_toml_escape(item.message[:100])}"')
        lines.append(f'severity = "{_toml_escape(item.severity)}"')
        lines.append(f'status = "{_toml_escape(item.status)}"')
        lines.append(f'remediation = "{_toml_escape(item.remediation[:200])}"')
        lines.append(f'assigned_to = "{_toml_escape(item.assigned_to)}"')
        lines.append(f'updated = "{_toml_escape(item.updated)}"')
        lines.append("")

    plan_path.write_text("\n".join(lines), encoding="utf-8")
    return plan_path


def format_treatment_plan(plan: TreatmentPlan) -> str:
    """Format treatment plan as Markdown.

    Args:
        plan: Plan to format.

    Returns:
        Markdown string.
    """
    lines: list[str] = [
        "# Treatment Plan",
        "",
        f"**{plan.progress}**",
        "",
        "| ID | Rule | File | Severity | Status | Remediation |",
        "|-----|------|------|----------|--------|-------------|",
    ]
    for item in plan.items:
        lines.append(
            f"| {item.finding_id[:20]} | {item.rule_id} | {item.file[:30]} "
            f"| {item.severity} | {item.status} | {item.remediation[:40]} |",
        )
    return "\n".join(lines)
