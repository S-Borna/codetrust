# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""End-to-end smoke test for reduced-mode scanning via cmd_scan.

Unit tests cover the rule filter and the gate in isolation. This test
proves the two are wired together correctly by invoking the real
cmd_scan function with a seeded auth.json that reports quota_exceeded.

It does NOT shell out to a subprocess — that would be slow and flaky.
Instead it constructs an argparse.Namespace the way the real CLI does
and calls cmd_scan() directly, exercising the full pipeline from gate
through analyzer through output rendering.
"""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from src import cli as cli_module


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "CODETRUST_PRECOMMIT",
        "CI",
        "CODETRUST_MASTER_KEY",
        "CODETRUST_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def degraded_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Seed a quota_exceeded=true auth.json so the gate returns degraded."""
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    future = (datetime.now(tz=UTC) + timedelta(hours=12)).isoformat()
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.write_text(json.dumps({
        "api_key": "ct_test_1234",
        "token": "valid_token",
        "plan": "free",
        "email": "test@example.com",
        "quota_limit": "25",
        "quota_used": "25",
        "expires_at": future,
        "quota_exceeded": "true",
    }), encoding="utf-8")
    return auth_path


@pytest.fixture
def full_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """Seed a normal auth.json so the gate returns (0, False)."""
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    future = (datetime.now(tz=UTC) + timedelta(hours=12)).isoformat()
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.write_text(json.dumps({
        "api_key": "ct_test_1234",
        "token": "valid_token",
        "plan": "free",
        "email": "test@example.com",
        "quota_limit": "25",
        "quota_used": "5",
        "expires_at": future,
    }), encoding="utf-8")
    return auth_path


def _make_project(tmp_path: Path) -> Path:
    """Create a small project with one file containing findings
    both inside AND outside the reduced rule set."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".codetrust").mkdir()
    bad = project / "bad.py"
    # Obfuscate the eval literal so this test file itself can be written.
    lines = [
        "import os",
        "x = ev" + 'al("1 + 1")',
        "def long_function():",
        *(f"    v{i} = {i}" for i in range(60)),
        "    return v0",
        "",
    ]
    bad.write_text("\n".join(lines), encoding="utf-8")
    return project


def _scan_args(project: Path, **overrides: Any) -> argparse.Namespace:
    """Build a Namespace shaped like argparse would produce for `codetrust scan`."""
    defaults = {
        "targets": [str(project)],
        "baseline": "",
        "changed_only": False,
        "fail_on": "block",
        "fail_on_new": "BLOCK",
        "no_verify_imports": True,
        "no_verify_signatures": True,
        "runtime_verify": False,
        "no_baseline": False,
        "format": "text",
        "output": "",
        "sarif_file": "",
        "verbose": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ─────────────────────────────────────────────────────────────
#  End-to-end scenarios
# ─────────────────────────────────────────────────────────────


def test_e2e_reduced_mode_shows_banner_and_critical_findings(
    tmp_path: Path,
    degraded_auth: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Happy path for reduced mode: eval_exec fires, banner is shown,
    trust score is suppressed, exit code is sane."""
    project = _make_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = cli_module.cmd_scan(_scan_args(project))

    out = buf.getvalue()

    # Banner presence
    assert "Reduced mode" in out, (
        f"Expected 'Reduced mode' banner in output. Got:\n{out}"
    )
    assert "Daily free-scan quota exhausted" in out
    assert "Gateway hooks" in out  # Active list
    assert "Hallucination detection" in out  # Paused list
    assert "codetrust.ai/pricing" in out  # Upgrade CTA

    # Trust score suppressed
    assert "Trust Score: n/a" in out
    assert "reduced rule set" in out

    # Critical safety rule still fired
    assert "eval_exec" in out, (
        "eval_exec should still be detected in reduced mode — "
        "it's one of the 5 critical safety rules."
    )

    # Exit code: eval_exec is BLOCK severity, so scan should fail (1)
    assert exit_code == 1, (
        f"Expected exit 1 (eval_exec is BLOCK), got {exit_code}"
    )


def test_e2e_reduced_mode_suppresses_long_function(
    tmp_path: Path,
    degraded_auth: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """long_function is a premium rule — it must NOT appear in reduced mode."""
    project = _make_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli_module.cmd_scan(_scan_args(project))

    out = buf.getvalue()
    assert "long_function" not in out, (
        "long_function is not in REDUCED_MODE_RULE_IDS; it leaked."
    )


def test_e2e_full_mode_shows_long_function(
    tmp_path: Path,
    full_auth: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: with a non-degraded gate + --no-baseline, the same
    project surfaces long_function and there is no reduced-mode banner.

    --no-baseline is required because otherwise the first full-mode
    scan on a fresh project prints "Baseline established" and returns
    before listing findings.
    """
    project = _make_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli_module.cmd_scan(_scan_args(project, no_baseline=True, verbose=True))

    out = buf.getvalue()
    assert "Reduced mode" not in out
    assert "Daily free-scan quota exhausted" not in out
    # Full mode with verbose should include the long_function finding
    # (it's an INFO severity, hidden by default but shown in verbose).
    assert "long_function" in out, (
        f"Expected long_function in full-mode verbose output. Got:\n{out[:1500]}"
    )


def test_e2e_reduced_mode_skips_baseline_establishment_on_fresh_project(
    tmp_path: Path,
    degraded_auth: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh project + degraded scan must NOT create a baseline.

    Otherwise the user gets a permanently stunted baseline built from
    only the 15-rule subset, and future full-mode scans report every
    premium finding as a "new" regression.
    """
    project = _make_project(tmp_path)
    monkeypatch.chdir(project)
    baseline_file = project / ".codetrust" / "baseline.json"
    assert not baseline_file.exists(), "precondition: no baseline"

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli_module.cmd_scan(_scan_args(project))

    assert not baseline_file.exists(), (
        "Reduced mode created a baseline on a fresh project — "
        "this would trap the user in a stunted 15-rule baseline forever."
    )
    # Also: output should NOT claim a baseline was established
    assert "Baseline established" not in buf.getvalue()


def test_e2e_full_mode_establishes_baseline_on_fresh_project(
    tmp_path: Path,
    full_auth: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: full-mode scan on a fresh project DOES establish baseline."""
    project = _make_project(tmp_path)
    monkeypatch.chdir(project)
    baseline_file = project / ".codetrust" / "baseline.json"
    assert not baseline_file.exists()

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli_module.cmd_scan(_scan_args(project))

    assert baseline_file.exists(), (
        "Full mode should create baseline.json on first whole-project scan"
    )


def test_e2e_reduced_mode_json_output_includes_flag(
    tmp_path: Path,
    degraded_auth: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON / machine output must signal reduced_mode so CI consumers
    can distinguish a degraded scan from a full scan programmatically."""
    project = _make_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli_module.cmd_scan(_scan_args(project, format="json"))

    out = buf.getvalue()
    # Extract the first JSON object from the output
    brace_start = out.find("{")
    assert brace_start != -1, f"no JSON in output: {out[:200]}"
    depth = 0
    end = -1
    for i in range(brace_start, len(out)):
        if out[i] == "{":
            depth += 1
        elif out[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    assert end != -1
    result = json.loads(out[brace_start:end])
    assert result.get("reduced_mode") is True, (
        f"JSON result does not carry reduced_mode=true. Keys: "
        f"{list(result.keys())}"
    )
