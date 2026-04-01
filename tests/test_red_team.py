from __future__ import annotations

import pytest

from src.services.red_team import (
    EVASION_TESTS,
    EvasionResult,
    EvasionTest,
    RedTeamReport,
)


class TestEvasionTests:
    """Tests for the EVASION_TESTS catalog."""

    def test_catalog_has_at_least_20_tests(self) -> None:
        assert len(EVASION_TESTS) >= 20

    def test_all_entries_are_evasion_tests(self) -> None:
        for t in EVASION_TESTS:
            assert isinstance(t, EvasionTest)
            assert t.test_id
            assert t.category
            assert t.command

    def test_catalog_includes_safe_commands(self) -> None:
        safe = [t for t in EVASION_TESTS if not t.expect_blocked]
        assert len(safe) >= 1

    def test_unique_test_ids(self) -> None:
        ids = [t.test_id for t in EVASION_TESTS]
        assert len(ids) == len(set(ids))


class TestEvasionResult:
    """Tests for EvasionResult.passed property."""

    def test_passed_when_blocked_matches_expectation(self) -> None:
        test = EvasionTest("RT-X", "cat", "desc", "rm -rf /", expect_blocked=True)
        result = EvasionResult(test=test, blocked=True, exit_code=2, output="blocked")
        assert result.passed is True

    def test_failed_when_blocked_does_not_match(self) -> None:
        test = EvasionTest("RT-X", "cat", "desc", "rm -rf /", expect_blocked=True)
        result = EvasionResult(test=test, blocked=False, exit_code=0, output="allowed")
        assert result.passed is False

    def test_safe_command_passes_when_not_blocked(self) -> None:
        test = EvasionTest("RT-S", "safe", "ls", "ls -la", expect_blocked=False)
        result = EvasionResult(test=test, blocked=False, exit_code=0, output="ok")
        assert result.passed is True

    def test_safe_command_fails_when_blocked(self) -> None:
        test = EvasionTest("RT-S", "safe", "ls", "ls -la", expect_blocked=False)
        result = EvasionResult(test=test, blocked=True, exit_code=2, output="blocked")
        assert result.passed is False


class TestRedTeamReport:
    """Tests for RedTeamReport."""

    def _make_report(self) -> RedTeamReport:
        """Build a report with 3 passed, 1 failed."""
        t1 = EvasionTest("RT-1", "c", "d", "cmd1", expect_blocked=True)
        t2 = EvasionTest("RT-2", "c", "d", "cmd2", expect_blocked=True)
        t3 = EvasionTest("RT-3", "c", "d", "cmd3", expect_blocked=True)
        t4 = EvasionTest("RT-4", "safe", "d", "ls", expect_blocked=False)
        return RedTeamReport(results=[
            EvasionResult(test=t1, blocked=True, exit_code=2, output=""),
            EvasionResult(test=t2, blocked=False, exit_code=0, output=""),  # bypass
            EvasionResult(test=t3, blocked=True, exit_code=2, output=""),
            EvasionResult(test=t4, blocked=False, exit_code=0, output=""),
        ])

    def test_summary_format(self) -> None:
        report = self._make_report()
        s = report.summary
        assert "3/4" in s
        assert "1 bypass" in s

    def test_bypasses_returns_only_failed(self) -> None:
        report = self._make_report()
        bypasses = report.bypasses
        assert len(bypasses) == 1
        assert bypasses[0].test.test_id == "RT-2"

    def test_total_count(self) -> None:
        report = self._make_report()
        assert report.total == 4

    def test_passed_count(self) -> None:
        report = self._make_report()
        assert report.passed == 3

    def test_zero_bypasses_summary(self) -> None:
        t = EvasionTest("RT-1", "c", "d", "cmd", expect_blocked=True)
        report = RedTeamReport(results=[
            EvasionResult(test=t, blocked=True, exit_code=2, output=""),
        ])
        assert "0 bypasses" in report.summary
