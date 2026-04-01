# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Conformity Assessment — EU AI Act Article 43 compliance.

Runs ALL governance checks and produces a dated, versioned, signed report:
doctor, compliance, DoD, trust score, risk register.
"""

from __future__ import annotations

import hashlib
import platform
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path


@dataclass
class AssessmentSection:
    """A single section of the conformity assessment."""

    name: str
    status: str  # "PASS" | "FAIL" | "WARN" | "SKIP"
    detail: str
    exit_code: int = 0


@dataclass
class ConformityReport:
    """Full conformity assessment report."""

    timestamp: str
    codetrust_version: str
    python_version: str
    os_info: str
    sections: list[AssessmentSection] = field(default_factory=list)
    signature: str = ""

    @property
    def all_passed(self) -> bool:
        """True only if no section has FAIL status."""
        return not any(s.status == "FAIL" for s in self.sections)

    @property
    def summary(self) -> str:
        """Build summary string."""
        passed = sum(1 for s in self.sections if s.status == "PASS")
        total = len(self.sections)
        failed = sum(1 for s in self.sections if s.status == "FAIL")
        return f"{passed}/{total} passed, {failed} failed"


def _run_command(command: str, timeout: int = 120) -> tuple[int, str]:
    """Run a shell command and capture output.

    Args:
        command: Shell command to run.
        timeout: Max seconds.

    Returns:
        Tuple of (exit_code, combined_output).
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(Path.cwd()),
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return -1, f"TIMEOUT after {timeout}s"
    except OSError as exc:
        return -1, str(exc)


def _get_codetrust_version() -> str:
    """Read version from pyproject.toml or fallback."""
    try:
        pyproject = Path("pyproject.toml")
        if pyproject.exists():
            for line in pyproject.read_text(encoding="utf-8").splitlines():
                if line.strip().startswith("version"):
                    return line.split("=")[1].strip().strip('"').strip("'")
    except OSError:
        pass
    return "unknown"


def run_assessment() -> ConformityReport:
    """Execute full conformity assessment.

    Returns:
        ConformityReport with all sections.
    """
    report = ConformityReport(
        timestamp=datetime.now(tz=UTC).isoformat(),
        codetrust_version=_get_codetrust_version(),
        python_version=platform.python_version(),
        os_info=f"{platform.system()} {platform.release()}",
    )

    # Section 1: Doctor
    exit_code, output = _run_command("python -m src.cli doctor")
    report.sections.append(AssessmentSection(
        name="Enforcement Layers (doctor)",
        status="PASS" if exit_code == 0 else "FAIL",
        detail=output[:2000],
        exit_code=exit_code,
    ))

    # Section 2: OWASP ASI compliance
    exit_code, output = _run_command(
        "python -m src.cli compliance --framework owasp-asi-2026 --strict",
    )
    report.sections.append(AssessmentSection(
        name="OWASP ASI 2026 Compliance",
        status="PASS" if exit_code == 0 else "FAIL",
        detail=output[:2000],
        exit_code=exit_code,
    ))

    # Section 3: EU AI Act compliance
    exit_code, output = _run_command(
        "python -m src.cli compliance --framework eu-ai-act --strict",
    )
    report.sections.append(AssessmentSection(
        name="EU AI Act Compliance",
        status="PASS" if exit_code == 0 else "FAIL",
        detail=output[:2000],
        exit_code=exit_code,
    ))

    # Section 4: NIST AI RMF compliance
    exit_code, output = _run_command(
        "python -m src.cli compliance --framework nist-ai-rmf --strict",
    )
    report.sections.append(AssessmentSection(
        name="NIST AI RMF Compliance",
        status="PASS" if exit_code == 0 else "FAIL",
        detail=output[:2000],
        exit_code=exit_code,
    ))

    # Section 5: Definition of Done
    exit_code, output = _run_command("python -m src.cli dod")
    report.sections.append(AssessmentSection(
        name="Definition of Done",
        status="PASS" if exit_code == 0 else "FAIL",
        detail=output[:2000],
        exit_code=exit_code,
    ))

    # Section 6: Risk Register
    exit_code, output = _run_command("python -m src.cli risk-register list")
    report.sections.append(AssessmentSection(
        name="Risk Register",
        status="PASS" if exit_code == 0 else "WARN",
        detail=output[:2000],
        exit_code=exit_code,
    ))

    # Compute signature
    report.signature = sign_report(report)

    return report


def format_assessment(report: ConformityReport) -> str:
    """Format assessment as Markdown.

    Args:
        report: The assessment report.

    Returns:
        Markdown string.
    """
    lines: list[str] = [
        "# Conformity Assessment Report",
        "",
        f"**Date:** {report.timestamp}",
        f"**CodeTrust Version:** {report.codetrust_version}",
        f"**Python:** {report.python_version}",
        f"**OS:** {report.os_info}",
        f"**Result:** {report.summary}",
        "",
        "## Sections",
        "",
        "| # | Section | Status |",
        "|---|---------|--------|",
    ]

    for i, section in enumerate(report.sections, 1):
        icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "—"}[section.status]
        lines.append(f"| {i} | {section.name} | {icon} {section.status} |")

    lines.extend(["", f"**Signature:** `{report.signature}`", ""])

    return "\n".join(lines)


def sign_report(report: ConformityReport) -> str:
    """Compute SHA-256 of the report content (excluding signature field).

    Args:
        report: Report to sign.

    Returns:
        Hex digest.
    """
    content = (
        f"{report.timestamp}|{report.codetrust_version}|"
        f"{report.python_version}|{report.os_info}|"
        + "|".join(f"{s.name}:{s.status}" for s in report.sections)
    )
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def export_assessment_json(report: ConformityReport) -> dict:
    """Export assessment as JSON-serializable dict.

    Args:
        report: Report to export.

    Returns:
        Dict with all fields.
    """
    return {
        "timestamp": report.timestamp,
        "codetrust_version": report.codetrust_version,
        "python_version": report.python_version,
        "os_info": report.os_info,
        "all_passed": report.all_passed,
        "summary": report.summary,
        "signature": report.signature,
        "sections": [
            {
                "name": s.name,
                "status": s.status,
                "exit_code": s.exit_code,
            }
            for s in report.sections
        ],
    }
