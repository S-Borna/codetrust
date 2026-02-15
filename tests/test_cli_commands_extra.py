from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

import src.cli as cli

if TYPE_CHECKING:
    from pathlib import Path


@dataclass(frozen=True)
class _FakeGovernanceMode:
    value: str


@dataclass(frozen=True)
class _FakeConfig:
    mode: _FakeGovernanceMode
    enabled: bool = True
    audit_path: str = ".codetrust/audit.jsonl"
    audit_enabled: bool = True
    retention_days: int = 90

    block_heredoc: bool = True
    block_eval: bool = True
    block_sudo: bool = True
    block_rm_rf: bool = True
    block_curl_pipe_sh: bool = True
    block_git_push: bool = True
    block_chmod_777: bool = True

    protected_paths: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _FakePolicy:
    enabled: bool


@dataclass(frozen=True)
class _FakeEngine:
    config: _FakeConfig

    def get_policies(self) -> list[_FakePolicy]:
        return [
            _FakePolicy(enabled=True),
            _FakePolicy(enabled=False),
        ]


def _patch_policy_engine(monkeypatch: pytest.MonkeyPatch, mode: str = "audit") -> None:
    import src.gateway.policies as policies

    def fake_from_workspace(_: str) -> _FakeEngine:
        return _FakeEngine(config=_FakeConfig(mode=_FakeGovernanceMode(value=mode), protected_paths=[]))

    monkeypatch.setattr(policies.PolicyEngine, "from_workspace", staticmethod(fake_from_workspace))


def test_cmd_pr_risk_json_emits_staged(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli, "_get_git_changed_files", lambda *, cwd: (["src/api.py"], True))
    monkeypatch.setattr(
        cli,
        "_compute_pr_risk",
        lambda **_: {
            "score": 10,
            "level": "LOW",
            "signals": [],
            "changed_files": ["src/api.py"],
            "changed_files_count": 1,
            "changed_lines": 0,
            "touched_endpoints": [],
            "touched_endpoints_count": 0,
        },
    )

    rc = cli.cmd_pr_risk(argparse.Namespace(json=True))
    assert rc == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["staged"] is True
    assert payload["changed_files_count"] == 1


def test_cmd_pr_risk_human_prints_signals_and_endpoints(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli, "_get_git_changed_files", lambda *, cwd: (["src/api.py"], False))
    monkeypatch.setattr(
        cli,
        "_compute_pr_risk",
        lambda **_: {
            "score": 80,
            "level": "HIGH",
            "signals": [
                {"label": "Auth / identity", "points": 25, "matched": ["src/auth.py"]},
                {"label": "API endpoints touched", "points": 20, "matched": ["/api/v1/x"]},
            ],
            "changed_files": ["src/api.py"],
            "changed_files_count": 1,
            "changed_lines": 123,
            "touched_endpoints": [f"/api/v1/ep{i}" for i in range(12)],
            "touched_endpoints_count": 12,
        },
    )

    rc = cli.cmd_pr_risk(argparse.Namespace(json=False))
    assert rc == 0

    out = capsys.readouterr().out
    assert "CodeTrust PR Risk Radar" in out
    assert "Top signals" in out
    assert "Touched endpoints" in out
    assert "... and" in out


def test_main_routes_to_pr_risk(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(cli, "_get_git_changed_files", lambda *, cwd: ([], False))
    monkeypatch.setattr(
        cli,
        "_compute_pr_risk",
        lambda **_: {
            "score": 0,
            "level": "LOW",
            "signals": [],
            "changed_files": [],
            "changed_files_count": 0,
            "changed_lines": 0,
            "touched_endpoints": [],
            "touched_endpoints_count": 0,
        },
    )

    monkeypatch.setattr(cli.sys, "argv", ["codetrust", "pr-risk", "--json"])
    rc = cli.main()
    assert rc == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["staged"] is False


def test_main_add_defaults_enable_bootstrap(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, argparse.Namespace] = {}

    def fake_cmd_add(args: argparse.Namespace) -> int:
        called["args"] = args
        return 0

    monkeypatch.setattr(cli, "cmd_add", fake_cmd_add)
    monkeypatch.setattr(cli.sys, "argv", ["codetrust", "add"])

    rc = cli.main()
    assert rc == 0

    args = called["args"]
    assert bool(getattr(args, "settings", False)) is True
    assert bool(getattr(args, "devcontainer", False)) is True
    assert bool(getattr(args, "contributing", False)) is True


def test_cmd_governance_setup_prints_instructions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _patch_policy_engine(monkeypatch, mode="audit")

    rc = cli.cmd_governance(argparse.Namespace(setup=True, status=False, mode=None))
    assert rc == 0

    out = capsys.readouterr().out
    assert "MCP" in out
    assert ".codetrust.toml" in out


def test_cmd_governance_mode_updates_config(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    _patch_policy_engine(monkeypatch, mode="audit")

    toml_path = tmp_path / ".codetrust.toml"
    toml_path.write_text('[tool.codetrust.governance]\nmode = "audit"\n', encoding="utf-8")

    rc = cli.cmd_governance(argparse.Namespace(setup=False, status=False, mode="enforce"))
    assert rc == 0

    assert 'mode = "enforce"' in toml_path.read_text(encoding="utf-8")


@dataclass(frozen=True)
class _FakeAuditEntry:
    timestamp: float
    verdict: str
    rule_id: str
    original_action: str


def test_cmd_audit_stats_no_entries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)

    _patch_policy_engine(monkeypatch, mode="audit")

    import src.gateway.audit as audit_mod

    class FakeAuditLogger:
        def __init__(self, path: Path, *, enabled: bool) -> None:
            _ = (path, enabled)
            pass

        def purge(self, *, older_than_days: int) -> int:
            return 0

        def entry_count(self) -> int:
            return 0

        def get_stats(self) -> dict[str, object]:
            return {"total": 0, "by_verdict": {}, "top_rules": []}

        def get_entries(self, *, since: float, verdict: str | None, limit: int) -> list[_FakeAuditEntry]:
            _ = (since, verdict, limit)
            return []

    monkeypatch.setattr(audit_mod, "AuditLogger", FakeAuditLogger)

    args = argparse.Namespace(
        hours=24,
        verdict=None,
        stats=True,
        format="table",
        export="",
        purge=False,
    )
    rc = cli.cmd_audit(args)
    assert rc == 0

    out = capsys.readouterr().out
    assert "Audit Statistics" in out
    assert "No audit entries found" in out


def test_cmd_audit_table_prints_entries(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.chdir(tmp_path)

    _patch_policy_engine(monkeypatch, mode="audit")

    import src.gateway.audit as audit_mod

    entries = [
        _FakeAuditEntry(
            timestamp=0.0,
            verdict="WARN",
            rule_id="eval_exec",
            original_action="x" * 200,
        )
    ]

    class FakeAuditLogger:
        def __init__(self, path: Path, *, enabled: bool) -> None:
            _ = (path, enabled)
            pass

        def purge(self, *, older_than_days: int) -> int:
            return 0

        def entry_count(self) -> int:
            return 1

        def get_stats(self) -> dict[str, object]:
            return {"total": 1, "by_verdict": {"WARN": 1}, "top_rules": [{"rule_id": "eval_exec", "count": 1}]}

        def get_entries(self, *, since: float, verdict: str | None, limit: int) -> list[_FakeAuditEntry]:
            _ = (since, verdict, limit)
            return entries

    monkeypatch.setattr(audit_mod, "AuditLogger", FakeAuditLogger)

    args = argparse.Namespace(
        hours=24,
        verdict=None,
        stats=False,
        format="table",
        export="",
        purge=False,
    )

    rc = cli.cmd_audit(args)
    assert rc == 0

    out = capsys.readouterr().out
    assert "Audit Log" in out
    assert "eval_exec" in out
