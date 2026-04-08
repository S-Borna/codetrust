# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for _check_local_scan_gate and its ScanGate return type.

The gate is the single enforcement point for scan authorization in the
CLI. Every branch matters because a bug here either:
  * lets unauthorized users scan (quota enforcement lost), or
  * blocks legitimate users (product breaks).

These tests pin each branch explicitly, with no reliance on the real
auth file or network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from src import cli as cli_module


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Strip env vars that would short-circuit the gate so each test
    sees a known baseline."""
    for var in (
        "CODETRUST_PRECOMMIT",
        "CI",
        "CODETRUST_MASTER_KEY",
        "CODETRUST_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def fake_auth_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect _AUTH_FILE to a temp path so tests can seed auth data."""
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    return auth_path


def _write_auth(path: Path, **fields: Any) -> None:
    """Seed an auth.json with reasonable defaults plus overrides."""
    future = (datetime.now(tz=UTC) + timedelta(hours=12)).isoformat()
    defaults: dict[str, Any] = {
        "api_key": "ct_test_abcd1234",
        "token": "signed_token_value",
        "plan": "free",
        "email": "user@example.com",
        "quota_limit": "25",
        "quota_used": "10",
        "expires_at": future,
    }
    defaults.update(fields)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(defaults), encoding="utf-8")


# ─────────────────────────────────────────────────────────────
#  Environment-variable bypasses
# ─────────────────────────────────────────────────────────────


def test_gate_bypasses_on_precommit_env(
    monkeypatch: pytest.MonkeyPatch, fake_auth_file: Path,
) -> None:
    """CODETRUST_PRECOMMIT=1 must proceed even with no auth file."""
    monkeypatch.setenv("CODETRUST_PRECOMMIT", "1")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0
    assert gate.degraded is False


def test_gate_bypasses_on_ci_env(
    monkeypatch: pytest.MonkeyPatch, fake_auth_file: Path,
) -> None:
    """CI=true must proceed for GitHub Actions / Jenkins etc."""
    monkeypatch.setenv("CI", "true")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0
    assert gate.degraded is False


def test_gate_bypasses_on_master_key(
    monkeypatch: pytest.MonkeyPatch, fake_auth_file: Path,
) -> None:
    """CODETRUST_MASTER_KEY must proceed for self-hosted / admin use."""
    monkeypatch.setenv("CODETRUST_MASTER_KEY", "mk_live_1234")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0
    assert gate.degraded is False


def test_gate_bypasses_on_api_key_env(
    monkeypatch: pytest.MonkeyPatch, fake_auth_file: Path,
) -> None:
    """CODETRUST_API_KEY env var is equivalent to master key bypass."""
    monkeypatch.setenv("CODETRUST_API_KEY", "ct_test_envkey")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0
    assert gate.degraded is False


def test_gate_ignores_placeholder_api_key_env(
    monkeypatch: pytest.MonkeyPatch, fake_auth_file: Path,
) -> None:
    """The literal placeholder string must NOT count as a real key."""
    monkeypatch.setenv("CODETRUST_API_KEY", "[I will paste the key myself]")
    # No auth file → should hard block
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 1
    assert gate.degraded is False


# ─────────────────────────────────────────────────────────────
#  Auth file states
# ─────────────────────────────────────────────────────────────


def test_gate_hard_blocks_without_auth_file(
    fake_auth_file: Path,
) -> None:
    """No auth.json at all → return (1, False)."""
    assert not fake_auth_file.exists()
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 1
    assert gate.degraded is False


def test_gate_hard_blocks_without_api_key(
    fake_auth_file: Path,
) -> None:
    """auth.json exists but has no api_key → hard block."""
    _write_auth(fake_auth_file, api_key="")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 1
    assert gate.degraded is False


def test_gate_proceeds_on_valid_auth_under_quota(
    fake_auth_file: Path,
) -> None:
    """Normal path: valid auth, unexpired token, under quota → full mode."""
    _write_auth(fake_auth_file, quota_exceeded="false")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0
    assert gate.degraded is False


# ─────────────────────────────────────────────────────────────
#  Quota exceeded → soft block (the whole point of Alt 3)
# ─────────────────────────────────────────────────────────────


def test_gate_returns_degraded_when_quota_exceeded(
    fake_auth_file: Path,
) -> None:
    """Quota exceeded → (0, True). Scan proceeds in reduced mode.

    This is the core behavioral change: a quota-exhausted user no
    longer hits a terminal error — they continue scanning with the
    reduced rule set and see the upgrade banner in their output.
    """
    _write_auth(fake_auth_file, quota_exceeded="true")
    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0, (
        "Quota exceeded should NOT hard-block — the whole point of "
        "reduced mode is that the scan keeps running."
    )
    assert gate.degraded is True


def test_gate_degraded_survives_quota_exceeded_with_valid_token(
    fake_auth_file: Path,
) -> None:
    """Valid token + quota_exceeded=true must still produce degraded,
    not accidentally proceed as full mode. Regression guard against
    someone reordering the quota check."""
    _write_auth(fake_auth_file, quota_exceeded="true")
    gate = cli_module._check_local_scan_gate()
    assert gate.degraded is True


# ─────────────────────────────────────────────────────────────
#  Offline / server-unreachable
# ─────────────────────────────────────────────────────────────


def test_gate_proceeds_offline_with_cached_token(
    fake_auth_file: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired token + server unreachable + cached token = full mode.

    Offline users with a recently-valid token should keep scanning.
    We have no way to verify their quota state so we fail open.
    """
    # Token expired yesterday
    past = (datetime.now(tz=UTC) - timedelta(days=1)).isoformat()
    _write_auth(fake_auth_file, expires_at=past)
    # _refresh_token returns None → simulate server unreachable
    monkeypatch.setattr(cli_module, "_refresh_token", lambda auth: None)

    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 0
    assert gate.degraded is False


def test_gate_hard_blocks_offline_without_cached_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Expired token + no cached token value + server unreachable = hard block."""
    auth_path = tmp_path / "auth.json"
    monkeypatch.setattr(cli_module, "_AUTH_FILE", auth_path)
    auth_path.write_text(json.dumps({
        "api_key": "ct_test_1234",
        # no token, no expires_at → cached-token branch fails
    }), encoding="utf-8")
    monkeypatch.setattr(cli_module, "_refresh_token", lambda auth: None)

    gate = cli_module._check_local_scan_gate()
    assert gate.exit_code == 1
    assert gate.degraded is False


# ─────────────────────────────────────────────────────────────
#  ScanGate NamedTuple contract
# ─────────────────────────────────────────────────────────────


def test_scan_gate_is_a_named_tuple() -> None:
    """ScanGate must be a NamedTuple so callers can unpack
    (exit_code, degraded) AND access fields by name."""
    gate = cli_module.ScanGate(exit_code=0, degraded=True)
    assert gate[0] == 0
    assert gate[1] is True
    assert gate.exit_code == 0
    assert gate.degraded is True
