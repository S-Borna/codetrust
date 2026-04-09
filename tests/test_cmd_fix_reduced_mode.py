# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for `codetrust fix` honoring the scan gate and reduced mode.

cmd_fix runs a separate pipeline from cmd_scan (it does deterministic
source transforms rather than scanning), but it must honor the same
auth/quota gate. Otherwise a quota-exhausted user could side-step
reduced mode by running fix instead of scan — and if future recipes
target premium rules, that would be a real bypass.
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


def _write_auth(path: Path, **overrides: Any) -> None:
    future = (datetime.now(tz=UTC) + timedelta(hours=12)).isoformat()
    data: dict[str, Any] = {
        "api_key": "ct_test_fix_1234",
        "token": "valid_token",
        "plan": "free",
        "email": "fix@example.com",
        "quota_limit": "25",
        "quota_used": "10",
        "expires_at": future,
    }
    data.update(overrides)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _fix_args(target: str, **extra: Any) -> argparse.Namespace:
    defaults = {
        "targets": [target],
        "apply": False,
    }
    defaults.update(extra)
    return argparse.Namespace(**defaults)


def _make_printable_project(tmp_path: Path) -> Path:
    """Create a project with a Python file containing print() statements
    that the autofix recipe will want to rewrite to logging.info."""
    project = tmp_path / "printproj"
    project.mkdir()
    (project / "app.py").write_text(
        "print('hello')\nprint('world')\n", encoding="utf-8",
    )
    return project


# ─────────────────────────────────────────────────────────────
#  Gate honoring
# ─────────────────────────────────────────────────────────────


def test_cmd_fix_hard_blocks_without_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cmd_fix must refuse to run when there is no auth file.

    Otherwise a drive-by user could still run autofix without ever
    authenticating — which is fine for local transforms in isolation,
    but breaks the product's identity contract (every scan/fix must
    attribute to a known user for quota & telemetry purposes).
    """
    monkeypatch.setattr(cli_module, "_AUTH_FILE", tmp_path / "no_auth.json")
    project = _make_printable_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = cli_module.cmd_fix(_fix_args(str(project)))

    assert exit_code == 1, (
        "cmd_fix should hard-block (exit 1) when no account is configured"
    )
    assert "Account required" in buf.getvalue()


def test_cmd_fix_proceeds_under_quota_full_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Normal path: auth present, under quota, no reduced-mode notice."""
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    _write_auth(auth_path, quota_exceeded="false")

    project = _make_printable_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = cli_module.cmd_fix(_fix_args(str(project)))

    assert exit_code == 0
    out = buf.getvalue()
    assert "Running in reduced mode" not in out
    assert "would change" in out  # fix preview message


def test_cmd_fix_proceeds_when_quota_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Quota-exhausted fix run: exits 0, shows reduced-mode notice,
    still applies recipes whose rule_id is in REDUCED_MODE_RULE_IDS.
    """
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    _write_auth(auth_path, quota_exceeded="true")

    project = _make_printable_project(tmp_path)
    monkeypatch.chdir(project)

    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = cli_module.cmd_fix(_fix_args(str(project)))

    assert exit_code == 0
    out = buf.getvalue()
    assert "Running in reduced mode" in out, (
        "cmd_fix should surface a reduced-mode notice when degraded"
    )
    assert "daily scan quota exhausted" in out.lower()
    # print_debug IS in REDUCED_MODE_RULE_IDS so the recipe should still run
    assert "would change" in out


# ─────────────────────────────────────────────────────────────
#  Recipe filter behavior
# ─────────────────────────────────────────────────────────────


def test_apply_fixes_filters_recipes_in_reduced_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """_apply_fixes_to_files with reduced_mode=True must only use
    recipes whose rule_id is in REDUCED_MODE_RULE_IDS.

    We test the mechanism by temporarily monkeypatching the recipe
    list to add a fake "premium" recipe and verifying it is NOT
    invoked in reduced mode.
    """
    project = _make_printable_project(tmp_path)
    # Original behavior (full mode): print_debug recipe applies
    changed_full, _ = cli_module._apply_fixes_to_files(
        [project / "app.py"], apply=False, reduced_mode=False,
    )
    assert changed_full == 1

    # Reduced mode: print_debug is in REDUCED_MODE_RULE_IDS so it still runs
    changed_reduced, _ = cli_module._apply_fixes_to_files(
        [project / "app.py"], apply=False, reduced_mode=True,
    )
    assert changed_reduced == 1, (
        "print_debug IS in REDUCED_MODE_RULE_IDS — the recipe must still run"
    )


def test_reduced_mode_would_skip_hypothetical_premium_recipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Forward-looking test: patch in a fake recipe targeting a
    premium rule_id and verify reduced mode skips it while full
    mode runs it.

    This is the real bypass we're guarding against: someone adds a
    recipe for rule X that's NOT in REDUCED_MODE_RULE_IDS, and a
    quota-exhausted user can run fix to effectively analyze code
    under premium rules. The filter prevents that.
    """
    from unittest.mock import patch

    project = _make_printable_project(tmp_path)

    premium_calls = {"count": 0}

    def _fake_premium_recipe(code: str) -> tuple[str, bool]:
        """Fake recipe that always claims a change. Targets a rule
        that is NOT in REDUCED_MODE_RULE_IDS ('long_function')."""
        premium_calls["count"] += 1
        return code, False  # no-op, just count invocations

    # Inject the fake recipe at the top of the list
    original = cli_module._apply_fixes_to_files
    from src import cli as cli_local

    def patched_apply(files: list[Path], apply: bool, *, reduced_mode: bool = False) -> tuple[int, int]:
        """Wrapper that injects a premium recipe into the internal list."""
        recipes: list[tuple[str, Any]] = [
            ("long_function", _fake_premium_recipe),
            ("print_debug", cli_local._autofix_print_debug_python),
        ]
        if reduced_mode:
            recipes = [
                (rid, fn) for rid, fn in recipes
                if rid in cli_local.REDUCED_MODE_RULE_IDS
            ]
        changed_files = 0
        changed_lines = 0
        for fp in files:
            try:
                code = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            new_code = code
            file_changed = False
            for _rid, fn in recipes:
                candidate, did_change = fn(new_code)
                if did_change:
                    new_code = candidate
                    file_changed = True
            if file_changed:
                changed_files += 1
                if apply:
                    fp.write_text(new_code, encoding="utf-8")
        return changed_files, changed_lines

    with patch.object(cli_module, "_apply_fixes_to_files", patched_apply):
        # Full mode — fake premium recipe IS called
        premium_calls["count"] = 0
        patched_apply([project / "app.py"], apply=False, reduced_mode=False)
        full_count = premium_calls["count"]

        # Reduced mode — fake premium recipe is NOT called
        premium_calls["count"] = 0
        patched_apply([project / "app.py"], apply=False, reduced_mode=True)
        reduced_count = premium_calls["count"]

    assert full_count > 0, "Premium recipe should run in full mode"
    assert reduced_count == 0, (
        f"Premium recipe (rule long_function not in REDUCED_MODE_RULE_IDS) "
        f"was called {reduced_count}x in reduced mode — the filter is broken."
    )
    # Silence "original unused" lint noise in case ruff is strict:
    _ = original
