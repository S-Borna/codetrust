# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for Definition of Done enforcement engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.services.definition_of_done import (
    DoDCheck,
    DoDReport,
    DoDResult,
    format_report,
    load_checks,
    run_dod,
)

# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture()
def dod_file(tmp_path: Path) -> Path:
    """Create a temporary DoD TOML file with test checks."""
    content = (
        '[[checks]]\n'
        'name = "Echo test"\n'
        'command = "echo hello world"\n'
        'expected_exit_code = 0\n'
        'expected_output_contains = ["hello"]\n'
        'expected_output_excludes = ["error"]\n'
        '\n'
        '[[checks]]\n'
        'name = "Always fails"\n'
        'command = "python3 -c \\"import sys; sys.exit(1)\\""\n'
        'expected_exit_code = 0\n'
    )
    dod_path = tmp_path / "definition_of_done.toml"
    dod_path.write_text(content, encoding="utf-8")
    return dod_path


@pytest.fixture()
def all_pass_dod(tmp_path: Path) -> Path:
    """Create a DoD file where all checks pass."""
    content = (
        '[[checks]]\n'
        'name = "True command"\n'
        'command = "python3 -c pass"\n'
        'expected_exit_code = 0\n'
    )
    dod_path = tmp_path / "definition_of_done.toml"
    dod_path.write_text(content, encoding="utf-8")
    return dod_path


# ── TOML parsing ──────────────────────────────────────────────────


class TestLoadChecks:
    """Tests for TOML DoD file parsing."""

    def test_loads_checks_from_toml(self, dod_file: Path) -> None:
        """Parses two checks from TOML file."""
        checks = load_checks(dod_file)
        assert len(checks) == 2

    def test_first_check_fields(self, dod_file: Path) -> None:
        """First check has correct name, command, expected values."""
        checks = load_checks(dod_file)
        assert checks[0].name == "Echo test"
        assert "echo" in checks[0].command
        assert checks[0].expected_exit_code == 0
        assert "hello" in checks[0].expected_output_contains

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        """FileNotFoundError for missing DoD file."""
        with pytest.raises(FileNotFoundError):
            load_checks(tmp_path / "nonexistent.toml")

    def test_empty_file_returns_empty(self, tmp_path: Path) -> None:
        """Empty TOML returns empty list."""
        dod_path = tmp_path / "definition_of_done.toml"
        dod_path.write_text("", encoding="utf-8")
        checks = load_checks(dod_path)
        assert checks == []


# ── Check execution ───────────────────────────────────────────────


class TestRunDod:
    """Tests for DoD check execution."""

    def test_passing_check(self, all_pass_dod: Path) -> None:
        """A simple passing check returns all_passed=True."""
        checks = load_checks(all_pass_dod)
        report = run_dod(checks)
        assert report.all_passed is True
        assert len(report.failed_checks) == 0

    def test_failing_check_exit_code(self) -> None:
        """Check with wrong exit code is marked as failed."""
        check = DoDCheck(
            name="Should fail",
            command='python3 -c "import sys; sys.exit(42)"',
            expected_exit_code=0,
        )
        report = run_dod([check])
        assert report.all_passed is False
        assert len(report.failed_checks) == 1
        assert "Exit code mismatch" in (report.failed_checks[0].failure_reason or "")

    def test_output_contains_check(self) -> None:
        """Check that expected_output_contains is verified."""
        check = DoDCheck(
            name="Contains test",
            command='python3 -c "print(\'hello world\')"',
            expected_exit_code=0,
            expected_output_contains=["hello"],
        )
        report = run_dod([check])
        assert report.all_passed is True

    def test_output_contains_missing(self) -> None:
        """Fails when expected string not in output."""
        check = DoDCheck(
            name="Missing output",
            command='python3 -c "print(\'hello\')"',
            expected_exit_code=0,
            expected_output_contains=["NEVER_IN_OUTPUT"],
        )
        report = run_dod([check])
        assert report.all_passed is False
        assert "does not contain" in (report.failed_checks[0].failure_reason or "")

    def test_output_excludes_check(self) -> None:
        """Passes when excluded string not in output."""
        check = DoDCheck(
            name="Excludes test",
            command='python3 -c "print(\'hello\')"',
            expected_exit_code=0,
            expected_output_excludes=["error"],
        )
        report = run_dod([check])
        assert report.all_passed is True

    def test_output_excludes_present(self) -> None:
        """Fails when excluded string IS in output."""
        check = DoDCheck(
            name="Excluded present",
            command='python3 -c "print(\'error found\')"',
            expected_exit_code=0,
            expected_output_excludes=["error"],
        )
        report = run_dod([check])
        assert report.all_passed is False
        assert "contains excluded" in (report.failed_checks[0].failure_reason or "")

    def test_filter_by_name(self) -> None:
        """check_filter limits which checks run."""
        checks = [
            DoDCheck(name="Alpha test", command="python3 -c pass"),
            DoDCheck(name="Beta test", command="python3 -c pass"),
        ]
        report = run_dod(checks, check_filter="Alpha")
        assert len(report.checks) == 1
        assert report.checks[0].check.name == "Alpha test"


# ── Report ────────────────────────────────────────────────────────


class TestDoDReport:
    """Tests for report properties and formatting."""

    def test_summary_all_passed(self) -> None:
        """Summary shows N/N PASSED when all pass."""
        results = [
            DoDResult(
                check=DoDCheck(name="A", command="echo"),
                actual_exit_code=0,
                actual_output="ok",
                passed=True,
            ),
        ]
        report = DoDReport(checks=results)
        assert report.summary == "1/1 PASSED"
        assert report.all_passed is True

    def test_summary_with_failures(self) -> None:
        """Summary shows X FAILED when some fail."""
        results = [
            DoDResult(
                check=DoDCheck(name="A", command="echo"),
                actual_exit_code=0, actual_output="ok", passed=True,
            ),
            DoDResult(
                check=DoDCheck(name="B", command="false"),
                actual_exit_code=1, actual_output="", passed=False,
                failure_reason="Exit code mismatch",
            ),
        ]
        report = DoDReport(checks=results)
        assert "1/2 PASSED" in report.summary
        assert "1 FAILED" in report.summary
        assert report.all_passed is False

    def test_format_report_contains_details(self) -> None:
        """Formatted report includes check names and commands."""
        check = DoDCheck(name="My Check", command="echo test")
        result = DoDResult(
            check=check, actual_exit_code=0,
            actual_output="test", passed=True,
        )
        report = DoDReport(checks=[result])
        text = format_report(report)
        assert "My Check" in text
        assert "echo test" in text
        assert "PASSED" in text


# ── Governance protection ─────────────────────────────────────────


class TestDoDProtection:
    """Tests that DoD file is in the protected paths list."""

    def test_dod_in_file_write_hook_protected_paths(self) -> None:
        """definition_of_done.toml is listed in file-write hook protection."""
        hook_path = Path("src/templates/pretooluse_file_write_hook.py")
        content = hook_path.read_text(encoding="utf-8")
        assert "definition_of_done" in content
        assert "selfprotect_definition_of_done" in content
