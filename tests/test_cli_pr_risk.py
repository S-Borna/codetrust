from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

import src.cli as cli


@dataclass(frozen=True)
class _RunResult:
    stdout: str


def test_extract_touched_endpoints_dedup_and_limit() -> None:
    diff_lines = [
        "+ const a = '/api/v1/users'",
        "+ const b = \"/api/v1/users\"",
        "+ const c = '/api/v1/orders'",
        "- const removed = '/api/v1/removed'",
        "+++ b/src/api.py",
    ]
    for i in range(30):
        diff_lines.append(f"+ const x{i} = '/api/v1/ep{i}'")

    endpoints = cli._extract_touched_endpoints("\n".join(diff_lines))

    assert endpoints[0] == "/api/v1/users"
    assert "/api/v1/orders" in endpoints
    assert "/api/v1/removed" not in endpoints
    assert len(endpoints) <= 20
    assert len(endpoints) == len(set(endpoints))


def test_parse_unified0_changed_ranges() -> None:
    diff_text = """
@@ -1,2 +10,3 @@
@@ -5 +20 @@
""".strip()

    ranges = cli._parse_unified0_changed_ranges(diff_text)
    assert ranges == [(10, 12), (20, 20)]


def test_get_git_numstat_parses_digits_and_non_digits(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(
        args: list[str],
        *,
        cwd: Path,
        capture_output: bool,
        text: bool,
        check: bool,
    ) -> _RunResult:
        assert args[:3] == ["git", "diff", "--numstat"]
        assert isinstance(cwd, Path)
        assert capture_output is True
        assert text is True
        assert check is False
        return _RunResult(stdout="3\t1\tsrc/api.py\n-\t-\tfoo.bin\n")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    out = cli._get_git_numstat(cwd=Path("."), staged=False)
    assert out["src/api.py"] == (3, 1)
    assert out["foo.bin"] == (0, 0)


def test_compute_pr_risk_high_with_endpoints_and_large_diff(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    project_dir = tmp_path

    changed_files = [
        "src/api.py",
        "alembic/versions/0001_test.py",
        "src/gateway/policies.py",
    ]

    numstat = {
        "src/api.py": (200, 10),
        "alembic/versions/0001_test.py": (50, 0),
        "src/gateway/policies.py": (60, 40),
    }

    diff_by_file: dict[str, str] = {
        "src/api.py": "\n".join(
            [
                "@@ -1 +1 @@",
                "+ const ep = '/api/v1/users'",
                "+ const hdr = 'Authorization: Bearer xyz'",
            ]
        ),
        "alembic/versions/0001_test.py": "\n".join(
            [
                "@@ -1 +1 @@",
                "+ -- alter table users add column x int;",
            ]
        ),
        "src/gateway/policies.py": "\n".join(
            [
                "@@ -1 +1 @@",
                "+ uses: actions/checkout@v4",
            ]
        ),
    }

    def fake_get_git_numstat(*, cwd: Path, staged: bool) -> dict[str, tuple[int, int]]:
        assert cwd == project_dir
        assert staged is False
        return numstat

    def fake_get_git_file_diff(*, cwd: Path, staged: bool, path: str) -> str:
        assert cwd == project_dir
        assert staged is False
        return diff_by_file.get(path, "")

    monkeypatch.setattr(cli, "_get_git_numstat", fake_get_git_numstat)
    monkeypatch.setattr(cli, "_get_git_file_diff", fake_get_git_file_diff)

    risk = cli._compute_pr_risk(project_dir=project_dir, changed_files=changed_files, staged=False)

    assert int(risk["score"]) >= cli.PR_RISK_HIGH_THRESHOLD
    assert risk["level"] == "HIGH"
    assert int(risk["changed_files_count"]) == len(set(changed_files))
    assert int(risk["touched_endpoints_count"]) >= 1

    touched = risk["touched_endpoints"]
    assert isinstance(touched, list)
    assert "/api/v1/users" in touched

    signals = risk["signals"]
    assert isinstance(signals, list)
    assert any(isinstance(s, dict) and s.get("label") == "API endpoints touched" for s in signals)
