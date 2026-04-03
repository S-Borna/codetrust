# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Risk Register — formal risk tracking for EU AI Act Article 9 compliance.

Each risk has: ID, title, likelihood (1-5), impact (1-5), score, mitigation,
owner, review date, status. Stored in .codetrust/risk-register.toml.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

REGISTER_PATH = Path(".codetrust") / "risk-register.toml"


def _toml_escape(value: str) -> str:
    """Escape a string for safe use in a TOML basic string (double-quoted).

    Handles: backslash, quotes, common whitespace, control characters (U+0000-U+001F
    excluding already-handled \\n/\\r/\\t), and the DEL character (U+007F).
    Conforms to TOML v1.0 basic string escaping rules.
    """
    # Order matters: backslash first to avoid double-escaping
    result = value.replace("\\", "\\\\")
    result = result.replace('"', '\\"')
    result = result.replace("\b", "\\b")
    result = result.replace("\f", "\\f")
    result = result.replace("\n", "\\n")
    result = result.replace("\r", "\\r")
    result = result.replace("\t", "\\t")
    # Remaining control characters → \uXXXX
    cleaned: list[str] = []
    for ch in result:
        cp = ord(ch)
        if cp <= 0x1F or cp == 0x7F:
            cleaned.append(f"\\u{cp:04X}")
        else:
            cleaned.append(ch)
    return "".join(cleaned)

VALID_STATUSES = frozenset({"open", "mitigated", "accepted", "closed"})
LIKELIHOOD_RANGE = range(1, 6)
IMPACT_RANGE = range(1, 6)


@dataclass
class Risk:
    """A single risk entry."""

    risk_id: str
    title: str
    description: str
    likelihood: int
    impact: int
    mitigation: str
    owner: str
    review_date: str
    status: str

    @property
    def risk_score(self) -> int:
        """Likelihood * impact."""
        return self.likelihood * self.impact


@dataclass
class RiskRegister:
    """Collection of risks."""

    risks: list[Risk] = field(default_factory=list)

    @property
    def open_risks(self) -> list[Risk]:
        """Risks that are not closed."""
        return [r for r in self.risks if r.status != "closed"]

    @property
    def high_risks(self) -> list[Risk]:
        """Risks with score >= 15."""
        return [r for r in self.risks if r.risk_score >= 15]

    def summary(self) -> str:
        """Build summary string."""
        total = len(self.risks)
        by_status = {}
        for r in self.risks:
            by_status[r.status] = by_status.get(r.status, 0) + 1
        parts = [f"{total} risks"]
        for status in ("open", "mitigated", "accepted", "closed"):
            count = by_status.get(status, 0)
            if count:
                parts.append(f"{count} {status}")
        return ", ".join(parts)


def load_register(path: Path | None = None) -> RiskRegister:
    """Load risk register from TOML file.

    Args:
        path: Path to risk-register.toml.

    Returns:
        RiskRegister with all risks.
    """
    register_path = path or REGISTER_PATH
    if not register_path.is_file():
        return RiskRegister()

    data = tomllib.loads(register_path.read_bytes().decode("utf-8"))
    risks: list[Risk] = []
    for entry in data.get("risks", []):
        if not isinstance(entry, dict):
            continue
        risks.append(Risk(
            risk_id=str(entry.get("risk_id", "")),
            title=str(entry.get("title", "")),
            description=str(entry.get("description", "")),
            likelihood=int(entry.get("likelihood", 1)),
            impact=int(entry.get("impact", 1)),
            mitigation=str(entry.get("mitigation", "")),
            owner=str(entry.get("owner", "")),
            review_date=str(entry.get("review_date", "")),
            status=str(entry.get("status", "open")),
        ))
    return RiskRegister(risks=risks)


def add_risk(
    register: RiskRegister,
    title: str,
    description: str,
    likelihood: int,
    impact: int,
    mitigation: str,
    owner: str,
) -> Risk:
    """Add a new risk to the register.

    Args:
        register: The register to add to.
        title: Short risk title.
        description: Detailed description.
        likelihood: 1-5 probability.
        impact: 1-5 consequence.
        mitigation: Planned mitigation.
        owner: Person responsible.

    Returns:
        The created Risk.
    """
    risk_id = f"RISK-{len(register.risks) + 1:03d}"
    risk = Risk(
        risk_id=risk_id,
        title=title,
        description=description,
        likelihood=max(1, min(5, likelihood)),
        impact=max(1, min(5, impact)),
        mitigation=mitigation,
        owner=owner,
        review_date=datetime.now(tz=UTC).date().isoformat(),
        status="open",
    )
    register.risks.append(risk)
    return risk


def save_register(register: RiskRegister, path: Path | None = None) -> Path:
    """Save risk register to TOML file.

    Args:
        register: The register to save.
        path: Output path.

    Returns:
        Path to saved file.
    """
    register_path = path or REGISTER_PATH
    register_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = [
        "# Risk Register — EU AI Act Article 9 compliance",
        f"# Generated: {datetime.now(tz=UTC).isoformat()}",
        "",
    ]
    for risk in register.risks:
        lines.append("[[risks]]")
        lines.append(f'risk_id = "{_toml_escape(risk.risk_id)}"')
        lines.append(f'title = "{_toml_escape(risk.title)}"')
        lines.append(f'description = "{_toml_escape(risk.description)}"')
        lines.append(f"likelihood = {risk.likelihood}")
        lines.append(f"impact = {risk.impact}")
        lines.append(f'mitigation = "{_toml_escape(risk.mitigation)}"')
        lines.append(f'owner = "{_toml_escape(risk.owner)}"')
        lines.append(f'review_date = "{_toml_escape(risk.review_date)}"')
        lines.append(f'status = "{_toml_escape(risk.status)}"')
        lines.append("")

    register_path.write_text("\n".join(lines), encoding="utf-8")
    return register_path


def format_register(register: RiskRegister) -> str:
    """Format register as Markdown table.

    Args:
        register: The register to format.

    Returns:
        Markdown string.
    """
    lines: list[str] = [
        "# Risk Register",
        "",
        f"**{register.summary()}**",
        "",
        "| ID | Title | L | I | Score | Status | Owner | Review |",
        "|----|-------|---|---|-------|--------|-------|--------|",
    ]
    for r in register.risks:
        lines.append(
            f"| {r.risk_id} | {r.title} | {r.likelihood} | {r.impact} "
            f"| {r.risk_score} | {r.status} | {r.owner} | {r.review_date} |",
        )
    return "\n".join(lines)


def export_register_json(register: RiskRegister) -> list[dict]:
    """Export register as JSON-serializable list.

    Args:
        register: The register to export.

    Returns:
        List of risk dicts.
    """
    return [
        {**asdict(r), "risk_score": r.risk_score}
        for r in register.risks
    ]


def sign_register(register: RiskRegister) -> str:
    """Compute SHA-256 signature of the register content.

    Args:
        register: The register to sign.

    Returns:
        Hex digest string.
    """
    content = format_register(register)
    return hashlib.sha256(content.encode("utf-8")).hexdigest()
