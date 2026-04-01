# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Definition of Done enforcement engine.

Runs acceptance checks as real subprocess commands.
Not Python imports. Not simulation. The actual CLI command.
stdout/stderr captured. Exit code measured. Output compared to expected.

The DoD file (.codetrust/definition_of_done.toml) is a governance file
protected by the file-write hook — agents cannot modify acceptance criteria.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


DOD_FILENAME = "definition_of_done.toml"
DOD_DEFAULT_PATH = Path(".codetrust") / DOD_FILENAME


@dataclass(frozen=True)
class DoDCheck:
    """A single Definition of Done acceptance check."""

    name: str
    command: str
    expected_exit_code: int = 0
    expected_output_contains: list[str] = field(default_factory=list)
    expected_output_excludes: list[str] = field(default_factory=list)


@dataclass
class DoDResult:
    """Result of running a single DoD check."""

    check: DoDCheck
    actual_exit_code: int
    actual_output: str
    passed: bool
    failure_reason: str | None = None


@dataclass
class DoDReport:
    """Full Definition of Done report."""

    checks: list[DoDResult]

    @property
    def all_passed(self) -> bool:
        """True only if every check passed."""
        return all(r.passed for r in self.checks)

    @property
    def failed_checks(self) -> list[DoDResult]:
        """Return only the failed checks."""
        return [r for r in self.checks if not r.passed]

    @property
    def summary(self) -> str:
        """Build summary like '5/5 PASSED' or '3/5 PASSED — 2 FAILED'."""
        total = len(self.checks)
        passed = sum(1 for r in self.checks if r.passed)
        failed = total - passed
        if failed == 0:
            return f"{passed}/{total} PASSED"
        return f"{passed}/{total} PASSED — {failed} FAILED"


def load_checks(dod_path: Path | None = None) -> list[DoDCheck]:
    """Load DoD checks from a TOML file.

    Args:
        dod_path: Path to definition_of_done.toml. Defaults to .codetrust/definition_of_done.toml.

    Returns:
        List of DoDCheck from the file.

    Raises:
        FileNotFoundError: If the DoD file does not exist.
        ValueError: If the file has invalid structure.
    """
    path = dod_path or DOD_DEFAULT_PATH
    if not path.is_file():
        msg = f"DoD file not found: {path}"
        raise FileNotFoundError(msg)

    raw = path.read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))

    checks_raw = data.get("checks", [])
    if not isinstance(checks_raw, list):
        msg = "DoD file must contain [[checks]] array"
        raise ValueError(msg)

    checks: list[DoDCheck] = []
    for entry in checks_raw:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name", "")
        command = entry.get("command", "")
        if not name or not command:
            continue
        checks.append(DoDCheck(
            name=name,
            command=command,
            expected_exit_code=int(entry.get("expected_exit_code", 0)),
            expected_output_contains=list(entry.get("expected_output_contains", [])),
            expected_output_excludes=list(entry.get("expected_output_excludes", [])),
        ))

    return checks


def _run_single_check(check: DoDCheck) -> DoDResult:
    """Execute a single DoD check as a subprocess.

    Args:
        check: The check specification.

    Returns:
        DoDResult with actual exit code, output, and pass/fail.
    """
    try:
        result = subprocess.run(
            check.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300,
            cwd=Path.cwd(),
        )
        actual_exit = result.returncode
        actual_output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return DoDResult(
            check=check,
            actual_exit_code=-1,
            actual_output="TIMEOUT: command exceeded 300s",
            passed=False,
            failure_reason="Command timed out after 300 seconds",
        )
    except OSError as exc:
        return DoDResult(
            check=check,
            actual_exit_code=-1,
            actual_output=str(exc),
            passed=False,
            failure_reason=f"Command execution failed: {exc}",
        )

    # Check exit code
    if actual_exit != check.expected_exit_code:
        return DoDResult(
            check=check,
            actual_exit_code=actual_exit,
            actual_output=actual_output,
            passed=False,
            failure_reason=(
                f"Exit code mismatch: got {actual_exit}, expected {check.expected_exit_code}"
            ),
        )

    # Check expected_output_contains
    output_lower = actual_output.lower()
    for expected in check.expected_output_contains:
        if expected.lower() not in output_lower:
            return DoDResult(
                check=check,
                actual_exit_code=actual_exit,
                actual_output=actual_output,
                passed=False,
                failure_reason=f'Output does not contain expected string: "{expected}"',
            )

    # Check expected_output_excludes
    for excluded in check.expected_output_excludes:
        if excluded.lower() in output_lower:
            return DoDResult(
                check=check,
                actual_exit_code=actual_exit,
                actual_output=actual_output,
                passed=False,
                failure_reason=f'Output contains excluded string: "{excluded}"',
            )

    return DoDResult(
        check=check,
        actual_exit_code=actual_exit,
        actual_output=actual_output,
        passed=True,
        failure_reason=None,
    )


def run_dod(
    checks: list[DoDCheck],
    check_filter: str | None = None,
) -> DoDReport:
    """Run all DoD checks and return a full report.

    Args:
        checks: List of checks to run.
        check_filter: Optional substring to filter checks by name.

    Returns:
        DoDReport with results for each check.
    """
    filtered = checks
    if check_filter:
        filter_lower = check_filter.lower()
        filtered = [c for c in checks if filter_lower in c.name.lower()]

    results = [_run_single_check(check) for check in filtered]
    return DoDReport(checks=results)


def format_report(report: DoDReport) -> str:
    """Format a DoD report as human-readable text.

    Args:
        report: The DoD report to format.

    Returns:
        Formatted string with check-by-check results.
    """
    lines: list[str] = [
        f"Definition of Done — {len(report.checks)} checks",
        "",
    ]

    for i, result in enumerate(report.checks, 1):
        check = result.check
        status = "PASSED" if result.passed else "FAILED"
        lines.append(f"[{i}/{len(report.checks)}] {check.name}")
        lines.append(f"      Command: {check.command}")
        lines.append(
            f"      Exit code: {result.actual_exit_code} "
            f"(expected {check.expected_exit_code}) "
            f"{'✅' if result.actual_exit_code == check.expected_exit_code else '❌'}",
        )

        for expected in check.expected_output_contains:
            found = expected.lower() in result.actual_output.lower()
            icon = "✅" if found else "❌"
            lines.append(f'      Output contains "{expected}" {icon}')

        for excluded in check.expected_output_excludes:
            found = excluded.lower() in result.actual_output.lower()
            icon = "✅" if not found else "❌"
            lines.append(f'      Output excludes "{excluded}" {icon}')

        if result.failure_reason:
            lines.append(f"      FAILED: {result.failure_reason}")
        lines.append(f"      {status}")
        lines.append("")

    lines.append(f"RESULT: {report.summary}")
    lines.append(f"Exit code: {0 if report.all_passed else 1}")

    return "\n".join(lines)
