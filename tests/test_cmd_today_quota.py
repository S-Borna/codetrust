# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for cmd_today's scan quota rendering.

cmd_today pulls quota state from auth.json so users see a quota
summary next to their daily audit activity. The rendering has
several branches (not logged in, under quota, near quota, exceeded)
that each need verification — and a negative branch where missing
fields cause silent skip rather than broken output.
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
    for var in ("CODETRUST_PRECOMMIT", "CI", "CODETRUST_MASTER_KEY", "CODETRUST_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def _seed_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **fields: Any) -> Path:
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    future = (datetime.now(tz=UTC) + timedelta(hours=12)).isoformat()
    data: dict[str, Any] = {
        "api_key": "ct_test_today",
        "token": "valid",
        "plan": "free",
        "email": "today@example.com",
        "quota_limit": "25",
        "quota_used": "5",
        "expires_at": future,
    }
    data.update(fields)
    auth_path.parent.mkdir(parents=True, exist_ok=True)
    auth_path.write_text(json.dumps(data), encoding="utf-8")
    return auth_path


def _run_today(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.chdir(tmp_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli_module.cmd_today(argparse.Namespace())
    return buf.getvalue()


# ─────────────────────────────────────────────────────────────
#  _today_quota_line unit branches
# ─────────────────────────────────────────────────────────────


def test_quota_line_none_when_no_api_key() -> None:
    """Not logged in → no quota line (silent skip)."""
    assert cli_module._today_quota_line({}) is None
    assert cli_module._today_quota_line({"api_key": ""}) is None


def test_quota_line_none_when_quota_fields_missing() -> None:
    """Old auth.json without quota fields → silent skip, never crash."""
    assert cli_module._today_quota_line({"api_key": "ct_1"}) is None
    assert cli_module._today_quota_line(
        {"api_key": "ct_1", "quota_used": "10"},
    ) is None
    assert cli_module._today_quota_line(
        {"api_key": "ct_1", "quota_limit": "25"},
    ) is None


def test_quota_line_none_when_limit_not_numeric() -> None:
    """Garbage values → silent skip, no exception."""
    line = cli_module._today_quota_line(
        {"api_key": "ct_1", "quota_used": "abc", "quota_limit": "25"},
    )
    assert line is None


def test_quota_line_normal_usage_shows_plan() -> None:
    """Under 80% quota → neutral rendering with plan name."""
    line = cli_module._today_quota_line({
        "api_key": "ct_1",
        "quota_used": "5",
        "quota_limit": "25",
        "plan": "free",
    })
    assert line is not None
    assert "5/25" in line
    assert "free plan" in line
    assert "reduced mode" not in line
    assert "remaining" not in line


def test_quota_line_near_limit_shows_remaining() -> None:
    """≥80% usage → yellow + remaining count."""
    line = cli_module._today_quota_line({
        "api_key": "ct_1",
        "quota_used": "22",
        "quota_limit": "25",
        "plan": "free",
    })
    assert line is not None
    assert "22/25" in line
    assert "3 remaining" in line
    assert "reduced mode" not in line


def test_quota_line_exceeded_shows_reduced_badge() -> None:
    """quota_exceeded=true → 'reduced mode active' badge + reset hint."""
    line = cli_module._today_quota_line({
        "api_key": "ct_1",
        "quota_used": "25",
        "quota_limit": "25",
        "plan": "free",
        "quota_exceeded": "true",
    })
    assert line is not None
    assert "25/25" in line
    assert "reduced mode active" in line
    assert "UTC midnight" in line


def test_quota_line_over_limit_without_flag_still_shows_reduced() -> None:
    """Defensive: if quota_used > quota_limit even without the flag,
    render the reduced badge. Handles stale auth files after a
    server-side reset miss."""
    line = cli_module._today_quota_line({
        "api_key": "ct_1",
        "quota_used": "30",
        "quota_limit": "25",
        "plan": "free",
    })
    assert line is not None
    assert "reduced mode active" in line


# ─────────────────────────────────────────────────────────────
#  cmd_today end-to-end rendering
# ─────────────────────────────────────────────────────────────


def test_cmd_today_shows_quota_line_when_logged_in(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: logged-in user sees the quota line in today output."""
    _seed_auth(tmp_path, monkeypatch, quota_used="10", quota_limit="25")
    out = _run_today(tmp_path, monkeypatch)
    assert "Scans today: 10/25" in out
    assert "free plan" in out


def test_cmd_today_shows_reduced_badge_when_exhausted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exhausted quota → cmd_today renders the reduced badge AND the
    upgrade CTA at the bottom."""
    _seed_auth(
        tmp_path, monkeypatch,
        quota_used="25", quota_limit="25", quota_exceeded="true",
    )
    out = _run_today(tmp_path, monkeypatch)
    assert "Scans today: 25/25" in out
    assert "reduced mode active" in out
    assert "Upgrade to Pro" in out
    assert "codetrust.ai/pricing" in out


def test_cmd_today_silent_without_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not logged in → no quota line, no upgrade CTA, no crash.

    A brand-new user should get a clean output even before `codetrust
    login`. The quota section simply does not render.
    """
    # Point AUTH_FILE at a nonexistent path
    monkeypatch.setattr(cli_module, "_AUTH_FILE", tmp_path / "missing.json")
    out = _run_today(tmp_path, monkeypatch)
    assert "Scans today" not in out
    assert "Upgrade to Pro" not in out
    # The existing "no activity" or activity-summary branch still ran
    assert "CodeTrust Today" in out


def test_cmd_today_no_upgrade_cta_under_quota(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A healthy free user should NOT see the upgrade CTA — it only
    fires when they actually hit the wall. Otherwise every today run
    becomes an ad."""
    _seed_auth(tmp_path, monkeypatch, quota_used="3", quota_limit="25")
    out = _run_today(tmp_path, monkeypatch)
    assert "Upgrade to Pro" not in out
