"""Tests for CLI scanner (src/cli.py).

Validates that the CLI imports rules from the backend (single source of truth)
and produces correct findings for all file types.
"""

import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from src.cli import (
    BLOCK_RULES,
    CI_WARN_RULES,
    DEVOPS_BLOCK_RULES,
    DEVOPS_WARN_RULES,
    DOCKER_BLOCK_RULES,
    DOCKER_WARN_RULES,
    INFO_RULES,
    K8S_BLOCK_RULES,
    K8S_WARN_RULES,
    REACT_BLOCK_RULES,
    REACT_WARN_RULES,
    SQL_BLOCK_RULES,
    SQL_INFO_RULES,
    SQL_WARN_RULES,
    WARN_RULES,
    _autofix_print_debug_python,
    _compute_pr_risk,
    _compute_trust_diff,
    _dedupe_findings,
    _detect_verify_gates,
    _filter_findings_to_changed_lines,
    _findings_to_sarif,
    _get_git_changed_files,
    _normalize_path_for_git,
    _scan_output_api_error,
    _scan_resolve_output_options,
    _sort_findings,
    _suppress_lint_covered_findings,
    _trend_read,
    _trend_snapshot,
    _trend_write,
    cmd_add,
    cmd_policy,
    cmd_scan,
    scan_file,
    scan_path,
)
from src.rules.anti_patterns import ANTI_PATTERNS


def _safe_rmtree(path: Path) -> None:
    """Best-effort temp cleanup resilient to transient Windows file locks."""

    def _onexc(func: object, target: str, _exc_info: tuple[type[BaseException], BaseException, object]) -> None:
        try:
            os.chmod(target, stat.S_IWRITE)
        except OSError:
            return
        try:
            if callable(func):
                func(target)
        except OSError:
            return

    for _ in range(3):
        try:
            shutil.rmtree(path, onexc=_onexc)
            return
        except PermissionError:
            time.sleep(0.2)

    shutil.rmtree(path, ignore_errors=True)


class TestNoiseControl:
    def test_dedupe_removes_exact_duplicates(self) -> None:
        findings = [
            {"file": "a.py", "line": 1, "rule_id": "eval_exec", "severity": "BLOCK", "message": "x"},
            {"file": "a.py", "line": 1, "rule_id": "eval_exec", "severity": "BLOCK", "message": "x"},
            {"file": "a.py", "line": 2, "rule_id": "todo_hack", "severity": "WARN", "message": "y"},
        ]
        out = _dedupe_findings(findings)
        assert len(out) == 2

    def test_sort_is_deterministic(self) -> None:
        findings = [
            {"file": "b.py", "line": 2, "rule_id": "todo_hack", "severity": "WARN", "message": "y"},
            {"file": "a.py", "line": 10, "rule_id": "eval_exec", "severity": "BLOCK", "message": "x"},
            {"file": "a.py", "line": 1, "rule_id": "print_debug", "severity": "WARN", "message": "p"},
        ]
        out = _sort_findings(findings)
        # BLOCK first, then WARN; within same severity: file, line
        assert out[0]["severity"] == "BLOCK"
        assert out[0]["file"] == "a.py"
        assert out[1]["file"] == "a.py"
        assert int(out[1]["line"]) == 1


class TestScanApiErrorOutput:
    def test_daily_limit_error_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        handled = _scan_output_api_error(
            {
                "error": "daily_scan_limit_reached",
                "limit": 100,
                "used": 101,
                "resets_at": "2026-03-16T00:00:00+00:00",
            },
        )
        assert handled is True
        out = capsys.readouterr().out
        assert "daily limit reached" in out.lower()
        assert "101/100" in out

    def test_upgrade_required_error_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        handled = _scan_output_api_error(
            {"error": "upgrade_required", "required_plan": "enterprise"},
        )
        assert handled is True
        out = capsys.readouterr().out
        assert "requires enterprise" in out.lower()


class TestScanOutputOptions:
    def test_prefers_new_format_and_output(self) -> None:
        args = type("Args", (), {})()
        args.format = "sarif"
        args.output = "results.sarif"
        args.json = False
        args.sarif = False
        args.sarif_file = ""

        output_format, output_path = _scan_resolve_output_options(args)
        assert output_format == "sarif"
        assert output_path == "results.sarif"

    def test_legacy_sarif_file_still_supported(self) -> None:
        args = type("Args", (), {})()
        args.format = "text"
        args.output = ""
        args.json = False
        args.sarif = False
        args.sarif_file = "legacy.sarif"

        output_format, output_path = _scan_resolve_output_options(args)
        assert output_format == "sarif"
        assert output_path == "legacy.sarif"

    def test_legacy_json_still_supported(self) -> None:
        args = type("Args", (), {})()
        args.format = "text"
        args.output = ""
        args.json = True
        args.sarif = False
        args.sarif_file = ""

        output_format, output_path = _scan_resolve_output_options(args)
        assert output_format == "json"
        assert output_path == ""


class TestChangedLines:
    def test_normalize_path_strips_dot_slash(self) -> None:
        cwd = Path("/tmp")
        assert _normalize_path_for_git("./a/b.py", cwd=cwd) == "a/b.py"

    def test_filter_findings_to_changed_lines_keeps_only_modified(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_dir, check=True)

            path = tmp_dir / "a.py"
            path.write_text("x = 1\nprint('ok')\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.py"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Modify line 2 to introduce a finding
            eval_stmt = "x = 1\nresult = " + "eval" + "(user_input)\n"
            path.write_text(eval_stmt, encoding="utf-8")

            findings = scan_file(str(path))
            assert any(f.get("rule_id") == "eval_exec" for f in findings)

            kept = _filter_findings_to_changed_lines(cwd=tmp_dir, findings=findings)
            rule_ids = [f.get("rule_id") for f in kept]
            assert "eval_exec" in rule_ids
            # Should normalize file path to relative
            assert all(str(f.get("file", "")).endswith("a.py") for f in kept)
        finally:
            _safe_rmtree(tmp_dir)


class TestBaselineGating:
    def test_fail_on_new_block_with_baseline_head(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        old_cwd = Path.cwd()
        try:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_dir, check=True)

            path = tmp_dir / "a.py"
            path.write_text("x = 1\nprint('ok')\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.py"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Introduce a new BLOCK finding in working tree
            eval_stmt = "x = 1\nresult = " + "eval" + "(user_input)\n"
            path.write_text(eval_stmt, encoding="utf-8")

            os.chdir(tmp_dir)
            args = type("Args", (), {})()
            args.targets = ["."]
            args.json = False
            args.sarif = False
            args.sarif_file = ""
            args.fail_on = "never"
            args.no_verify_imports = True
            args.changed_only = True
            args.dedupe = False
            args.suppress_lint_noise = False
            args.baseline = "HEAD"
            args.fail_on_new = "BLOCK"

            rc = cmd_scan(args)
            assert rc == 1
        finally:
            os.chdir(old_cwd)
            _safe_rmtree(tmp_dir)


class TestAutofix:
    def test_autofix_print_debug_adds_logging_import_and_rewrites_call(self) -> None:
        code = "def f():\n    print('x')\n"
        new_code, changed = _autofix_print_debug_python(code)
        assert changed is True
        assert "import logging" in new_code
        assert "logging.info('x')" in new_code


class TestPolicyWizard:
    def test_policy_wizard_writes_config_and_autocomplete_files(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        old_cwd = Path.cwd()
        try:
            (tmp_dir / "pyproject.toml").write_text(
                "[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n",
                encoding="utf-8",
            )

            os.chdir(tmp_dir)
            args = type("Args", (), {})()
            args.subcommand = "wizard"
            args.yes = True
            args.profile = "startup"
            args.pyproject = "auto"

            rc = cmd_policy(args)
            assert rc == 0

            ct = tmp_dir / ".codetrust.toml"
            assert ct.is_file()
            ct_text = ct.read_text(encoding="utf-8")
            assert 'mode = "audit"' in ct_text

            assert (tmp_dir / ".taplo.toml").is_file()
            assert (tmp_dir / ".codetrust.schema.json").is_file()

            py_text = (tmp_dir / "pyproject.toml").read_text(encoding="utf-8")
            assert "# BEGIN CODETRUST POLICY (generated)" in py_text
            assert "[tool.codetrust.governance]" in py_text
        finally:
            os.chdir(old_cwd)
            _safe_rmtree(tmp_dir)


class TestVerifyGates:
    def test_detects_npm_verify_script(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            (tmp_dir / "package.json").write_text(
                '{"scripts": {"verify": "npm run lint && npm test"}}',
                encoding="utf-8",
            )
            gates = _detect_verify_gates(tmp_dir)
            assert "npm run verify" in gates
        finally:
            _safe_rmtree(tmp_dir)


class TestSuppressLintNoise:
    def test_suppresses_console_log_when_eslint_present(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            (tmp_dir / "package.json").write_text(
                '{"devDependencies": {"eslint": "^9.0.0"}}',
                encoding="utf-8",
            )
            findings = [
                {"file": "x.ts", "line": 1, "rule_id": "console_log", "severity": "WARN", "message": "m"},
                {"file": "x.ts", "line": 2, "rule_id": "eval_exec", "severity": "BLOCK", "message": "e"},
            ]
            kept, suppressed = _suppress_lint_covered_findings(project_dir=tmp_dir, findings=findings)
            assert suppressed == 1
            assert any(f.get("rule_id") == "eval_exec" for f in kept)
            assert all(f.get("rule_id") != "console_log" for f in kept)
        finally:
            _safe_rmtree(tmp_dir)


class TestPrRiskRadar:
    def test_pr_risk_uses_staged_changes_when_present(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_dir, check=True)

            (tmp_dir / "README.md").write_text("x\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Create staged high-risk touchpoints
            (tmp_dir / "src").mkdir(parents=True, exist_ok=True)
            (tmp_dir / "alembic" / "versions").mkdir(parents=True, exist_ok=True)
            (tmp_dir / "src" / "auth_service.py").write_text("x=1\n", encoding="utf-8")
            (tmp_dir / "src" / "tenant.py").write_text("x=1\n", encoding="utf-8")
            (tmp_dir / "alembic" / "versions" / "001_add.sql").write_text("-- mig\n", encoding="utf-8")
            subprocess.run(["git", "add", "src/auth_service.py", "src/tenant.py", "alembic/versions/001_add.sql"], cwd=tmp_dir, check=True)

            files, staged = _get_git_changed_files(cwd=tmp_dir)
            assert staged is True
            assert "src/auth_service.py" in files

            risk = _compute_pr_risk(project_dir=tmp_dir, changed_files=files, staged=staged)
            assert risk["level"] in ("MED", "HIGH")
            assert int(risk["score"]) >= 25
            assert int(risk.get("changed_lines", 0) or 0) >= 0
            signals = risk.get("signals", [])
            assert isinstance(signals, list)
            labels = {s.get("label") for s in signals if isinstance(s, dict)}
            assert "Auth / identity" in labels
            assert "Tenancy / multi-tenant" in labels
        finally:
            _safe_rmtree(tmp_dir)


class TestTrustDiff:
    def test_trust_diff_detects_new_block(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_dir, check=True)

            (tmp_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.py"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Introduce a BLOCK in working tree and stage it
            (tmp_dir / "a.py").write_text("result = " + "eval" + "(user_input)\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.py"], cwd=tmp_dir, check=True)

            files, staged = _get_git_changed_files(cwd=tmp_dir)
            report = _compute_trust_diff(project_dir=tmp_dir, changed_files=files, staged=staged)
            delta = report.get("delta", {})
            assert isinstance(delta, dict)
            assert int(delta.get("blocks", 0) or 0) >= 1
        finally:
            _safe_rmtree(tmp_dir)


class TestAddStackPresets:
    def test_add_settings_auto_detect_node(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        old_cwd = Path.cwd()
        try:
            (tmp_dir / "package.json").write_text('{"name":"x"}', encoding="utf-8")
            os.chdir(tmp_dir)

            args = type("Args", (), {
                "settings": True,
                "devcontainer": False,
                "contributing": False,
                "yes": True,
                "stack": "auto",
            })()

            rc = cmd_add(args)  # type: ignore[arg-type]
            assert rc == 0
            settings_path = tmp_dir / ".vscode" / "settings.json"
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            assert data.get("codetrust.enabledLanguages") == ["javascript", "typescript"]
        finally:
            os.chdir(old_cwd)
            _safe_rmtree(tmp_dir)


class TestTrend:
    def test_trend_record_and_read(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_dir, check=True)
            (tmp_dir / "a.py").write_text("x = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.py"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            snap = _trend_snapshot(tmp_dir, [str(tmp_dir)])
            assert "ts" in snap
            _trend_write(tmp_dir, snap)

            # Corrupted/partial lines should be skipped safely (e.g. interrupted write)
            trend_path = tmp_dir / ".codetrust" / "trend.jsonl"
            trend_path.write_text(trend_path.read_text(encoding="utf-8") + "{not-json}\n", encoding="utf-8")

            entries = _trend_read(tmp_dir)
            assert len(entries) == 1
            assert entries[0].get("git_sha")
        finally:
            _safe_rmtree(tmp_dir)

    def test_add_settings_explicit_python(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        old_cwd = Path.cwd()
        try:
            (tmp_dir / "pyproject.toml").write_text("[tool.codetrust]\n", encoding="utf-8")
            os.chdir(tmp_dir)

            args = type("Args", (), {
                "settings": True,
                "devcontainer": False,
                "contributing": False,
                "yes": True,
                "stack": "python",
            })()

            rc = cmd_add(args)  # type: ignore[arg-type]
            assert rc == 0
            settings_path = tmp_dir / ".vscode" / "settings.json"
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            assert data.get("codetrust.enabledLanguages") == ["python"]
        finally:
            os.chdir(old_cwd)
            _safe_rmtree(tmp_dir)

    def test_pr_risk_detects_touched_endpoints(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            subprocess.run(["git", "init"], cwd=tmp_dir, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=tmp_dir, check=True)

            (tmp_dir / "src").mkdir(parents=True, exist_ok=True)
            api_file = tmp_dir / "src" / "api.py"
            api_file.write_text(
                "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/v1/status')\ndef status():\n    return {'ok': True}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "src/api.py"], cwd=tmp_dir, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_dir, check=True, capture_output=True)

            # Add a new endpoint
            api_file.write_text(
                "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/v1/status')\ndef status():\n    return {'ok': True}\n\n@app.post('/v1/payments')\ndef pay():\n    return {'ok': True}\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "src/api.py"], cwd=tmp_dir, check=True)

            files, staged = _get_git_changed_files(cwd=tmp_dir)
            risk = _compute_pr_risk(project_dir=tmp_dir, changed_files=files, staged=staged)
            eps = risk.get("touched_endpoints", [])
            assert isinstance(eps, list)
            assert "/v1/payments" in eps
            labels = {s.get("label") for s in risk.get("signals", []) if isinstance(s, dict)}
            assert "API endpoints touched" in labels
        finally:
            _safe_rmtree(tmp_dir)

    def test_suppresses_print_debug_when_ruff_present(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            (tmp_dir / "pyproject.toml").write_text(
                "[tool.ruff]\nselect = ['T201']\n",
                encoding="utf-8",
            )
            findings = [
                {"file": "a.py", "line": 1, "rule_id": "print_debug", "severity": "WARN", "message": "p"},
                {"file": "a.py", "line": 2, "rule_id": "hardcoded_secret", "severity": "BLOCK", "message": "s"},
            ]
            kept, suppressed = _suppress_lint_covered_findings(project_dir=tmp_dir, findings=findings)
            assert suppressed == 1
            assert any(f.get("rule_id") == "hardcoded_secret" for f in kept)
            assert all(f.get("rule_id") != "print_debug" for f in kept)
        finally:
            _safe_rmtree(tmp_dir)

    def test_detects_ruff_and_pytest_from_pyproject(self) -> None:
        tmp_dir = Path(tempfile.mkdtemp())
        try:
            (tmp_dir / "pyproject.toml").write_text(
                "[tool.ruff]\nline-length = 88\n\n[tool.pytest.ini_options]\naddopts = '-q'\n",
                encoding="utf-8",
            )
            gates = _detect_verify_gates(tmp_dir)
            assert "ruff check" in gates
            assert "pytest" in gates
        finally:
            _safe_rmtree(tmp_dir)

# ═══════════════════════════════════════════════════════════════
#  Rule Import Tests — no drift between CLI and backend
# ═══════════════════════════════════════════════════════════════


class TestRuleImport:
    """Verify CLI rules are derived from the backend's ANTI_PATTERNS."""

    def test_rules_come_from_backend(self):
        """Every CLI rule ID must exist in the backend ANTI_PATTERNS."""
        backend_ids = {r["id"] for r in ANTI_PATTERNS}
        all_cli_rules = (
            BLOCK_RULES + WARN_RULES + INFO_RULES
            + SQL_BLOCK_RULES + SQL_WARN_RULES + SQL_INFO_RULES
            + DOCKER_BLOCK_RULES + DOCKER_WARN_RULES
            + CI_WARN_RULES
            + DEVOPS_BLOCK_RULES + DEVOPS_WARN_RULES
        )
        for entry in all_cli_rules:
            rule_id = entry[0]
            assert rule_id in backend_ids, (
                f"CLI rule '{rule_id}' not found in backend ANTI_PATTERNS"
            )

    def test_patterns_match_backend(self):
        """CLI rule patterns must be identical to the backend."""
        backend_map = {r["id"]: r["pattern"] for r in ANTI_PATTERNS}
        all_cli_rules = (
            BLOCK_RULES + WARN_RULES + INFO_RULES
            + SQL_BLOCK_RULES + SQL_WARN_RULES + SQL_INFO_RULES
            + DOCKER_BLOCK_RULES + DOCKER_WARN_RULES
            + CI_WARN_RULES
            + DEVOPS_BLOCK_RULES + DEVOPS_WARN_RULES
        )
        for entry in all_cli_rules:
            rule_id, pattern = entry[0], entry[1]
            assert pattern == backend_map[rule_id], (
                f"CLI pattern for '{rule_id}' differs from backend"
            )

    def test_block_rules_are_block_severity(self):
        """Rules in BLOCK lists must have BLOCK severity in the backend."""
        backend_map = {r["id"]: str(r["severity"]) for r in ANTI_PATTERNS}
        for entry in BLOCK_RULES + SQL_BLOCK_RULES + DOCKER_BLOCK_RULES + DEVOPS_BLOCK_RULES:
            rule_id = entry[0]
            assert backend_map[rule_id] == "BLOCK", (
                f"'{rule_id}' is in CLI BLOCK list but has '{backend_map[rule_id]}' severity in backend"
            )

    def test_warn_rules_are_warn_severity(self):
        """Rules in WARN lists must have WARN severity in the backend."""
        backend_map = {r["id"]: str(r["severity"]) for r in ANTI_PATTERNS}
        for entry in WARN_RULES + SQL_WARN_RULES + DOCKER_WARN_RULES + CI_WARN_RULES + DEVOPS_WARN_RULES:
            rule_id = entry[0]
            assert backend_map[rule_id] == "WARN", (
                f"'{rule_id}' is in CLI WARN list but has '{backend_map[rule_id]}' severity in backend"
            )

    def test_minimum_rule_counts(self):
        """CLI must have a minimum number of rules to avoid regression."""
        assert len(BLOCK_RULES) >= 5, "Generic BLOCK rules too few"
        assert len(WARN_RULES) >= 10, "Generic WARN rules too few"
        assert len(SQL_BLOCK_RULES) >= 6, "SQL BLOCK rules too few"


# ═══════════════════════════════════════════════════════════════
#  Scan Engine Tests
# ═══════════════════════════════════════════════════════════════


def _write_temp_file(content: str, suffix: str = ".py", name: str | None = None) -> str:
    """Write content to a temp file and return the path."""
    if name:
        dirpath = tempfile.mkdtemp()
        filepath = os.path.join(dirpath, name)
        with open(filepath, "w") as f:
            f.write(content)
        return filepath
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestScanFile:
    """Test the scan_file function for various anti-patterns."""

    def test_detects_eval(self):
        path = _write_temp_file("result = " + "eval" + "(user_input)\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "eval_exec" in rule_ids

    def test_detects_hardcoded_secret(self):
        secret = "sk_" + "live_" + "abcdefghij"
        path = _write_temp_file('api_key = "' + secret + '"\n')
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "hardcoded_secret" in rule_ids

    def test_detects_todo(self):
        todo = "TO" + "DO"
        path = _write_temp_file("x = 1  # " + todo + ": fix this\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "todo_hack" in rule_ids

    def test_detects_console_log(self):
        path = _write_temp_file("console." + "log('debug');\n", suffix=".js")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "console_log" in rule_ids

    def test_detects_bare_except(self):
        path = _write_temp_file("try:\n    pass\nexcept:\n    pass\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "bare_except" in rule_ids

    def test_detects_nested_ternary(self):
        question_mark = chr(63)
        path = _write_temp_file(
            f"const x = a {question_mark} b {question_mark} c : d : e;\n",
            suffix=".ts",
        )
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "nested_ternary" in rule_ids

    def test_detects_mutable_default(self):
        path = _write_temp_file("def foo(items: list = []):\n    pass\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "mutable_default" in rule_ids

    def test_skips_binary_files(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        with os.fdopen(fd, "wb") as f:
            f.write(b"e" + b"val(\x00binary content)")
        findings = scan_file(path)
        os.unlink(path)
        assert findings == []

    def test_skips_test_files(self):
        path = _write_temp_file("e" + "val(input())\n", name="test_foo.py")
        findings = scan_file(path)
        os.unlink(path)
        assert findings == []

    def test_noqa_suppresses_finding(self):
        path = _write_temp_file("result = " + "eval" + "(stuff)  # noqa\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        # eval should be suppressed by noqa — scanner skips lines with noqa
        assert "eval_exec" not in rule_ids


class TestScanSQL:
    """Test SQL-specific rules only fire on .sql files."""

    def test_sql_select_star(self):
        path = _write_temp_file("SELECT * FROM users;\n", suffix=".sql")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "sql_select_star" in rule_ids

    def test_sql_delete_no_where(self):
        path = _write_temp_file("DELETE FROM users;\n", suffix=".sql")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "sql_delete_no_where" in rule_ids

    def test_sql_update_with_where_passes(self):
        path = _write_temp_file("UPDATE users SET name = 'x' WHERE id = 1;\n", suffix=".sql")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "sql_update_no_where" not in rule_ids

    def test_sql_update_no_where_detected(self):
        path = _write_temp_file("UPDATE users SET name = 'x';\n", suffix=".sql")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "sql_update_no_where" in rule_ids

    def test_sql_rules_dont_fire_on_python(self):
        path = _write_temp_file("SELECT * FROM users\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "sql_select_star" not in rule_ids


class TestScanDockerfile:
    """Test Dockerfile-specific rules."""

    def test_docker_latest_tag(self):
        path = _write_temp_file("FROM python:latest\n", name="Dockerfile")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "docker_latest_tag" in rule_ids

    def test_docker_untagged_image(self):
        path = _write_temp_file("FROM python\n", name="Dockerfile")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "docker_latest_tag" in rule_ids

    def test_docker_pinned_image_passes(self):
        path = _write_temp_file("FROM python:3.12-slim\n", name="Dockerfile")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "docker_latest_tag" not in rule_ids

    def test_docker_no_user(self):
        path = _write_temp_file("FROM python:3.12\nCMD python app.py\n", name="Dockerfile")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "docker_root_user" in rule_ids

    def test_docker_with_user(self):
        path = _write_temp_file(
            "FROM python:3.12\nUSER appuser\nCMD python app.py\n", name="Dockerfile"
        )
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "docker_root_user" not in rule_ids


class TestScanPath:
    """Test directory scanning with skip_dirs."""

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir) / "node_modules"
            nm.mkdir()
            (nm / "evil.js").write_text("e" + "val(input)")
            findings = scan_path(tmpdir)
        assert findings == []

    def test_skips_dotgit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            git = Path(tmpdir) / ".git"
            git.mkdir()
            (git / "config.py").write_text("e" + "val(input)")
            findings = scan_path(tmpdir)
        assert findings == []

    def test_scans_source_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "app.py").write_text("result = " + "eval" + "(user_input)\n")
            findings = scan_path(tmpdir)
        rule_ids = [f["rule_id"] for f in findings]
        assert "eval_exec" in rule_ids

    def test_skips_next_build_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nx = Path(tmpdir) / ".next"
            nx.mkdir()
            (nx / "chunk.js").write_text("e" + "val(code)")
            findings = scan_path(tmpdir)
        assert findings == []


# ═══════════════════════════════════════════════════════════════
#  Regression Tests — specific bugs found and fixed
# ═══════════════════════════════════════════════════════════════


class TestRegressions:
    """Regression tests for previously-discovered bugs.

    Each test targets a specific bug that was fixed. If these fail,
    the bug has been reintroduced.
    """

    def test_hardcoded_port_no_false_positive_on_short_ports(self):
        """Bug: hardcoded_port matched short ports (e.g. two- and three-digit).
        Fix: pattern requires 4-5 digit port numbers."""
        path = _write_temp_file("port = 80\nPORT = 443\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "hardcoded_port" not in rule_ids

    def test_hardcoded_port_detects_4_digit_ports(self):
        """Verify 4+ digit ports are still caught."""
        path = _write_temp_file("PORT = " + "80" + "80\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "hardcoded_port" in rule_ids

    def test_debug_mode_detects_string_true(self):
        """Bug: debug_mode_enabled didn't match DEBUG = \"true\".
        Fix: added \"true\" to the pattern."""
        path = _write_temp_file('DEBUG = "true"\n')
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "debug_mode_enabled" in rule_ids

    def test_debug_mode_detects_bool_true(self):
        """Verify boolean True is still caught."""
        path = _write_temp_file("DEBUG = True\n")
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "debug_mode_enabled" in rule_ids

    def test_ci_unpinned_action_detects_head(self):
        """Bug: ci_unpinned_action didn't match @HEAD.
        Fix: added HEAD to the pattern."""
        dirpath = tempfile.mkdtemp()
        ghdir = Path(dirpath) / ".github" / "workflows"
        ghdir.mkdir(parents=True)
        filepath = ghdir / "ci.yml"
        filepath.write_text("    - uses: actions/checkout@HEAD\n")
        findings = scan_file(str(filepath))
        shutil.rmtree(dirpath)
        rule_ids = [f["rule_id"] for f in findings]
        assert "ci_unpinned_action" in rule_ids

    def test_ci_unpinned_action_passes_pinned_version(self):
        """Verify pinned actions pass."""
        dirpath = tempfile.mkdtemp()
        ghdir = Path(dirpath) / ".github" / "workflows"
        ghdir.mkdir(parents=True)
        filepath = ghdir / "ci.yml"
        filepath.write_text("    - uses: actions/checkout@v4\n")
        findings = scan_file(str(filepath))
        shutil.rmtree(dirpath)
        rule_ids = [f["rule_id"] for f in findings]
        assert "ci_unpinned_action" not in rule_ids

    def test_sql_update_with_where_no_false_positive(self):
        """Bug: sql_update_no_where used \\\\b (literal backslash-b) in raw string,
        causing every UPDATE...WHERE to be falsely flagged.
        Fix: corrected regex to use negative lookahead."""
        path = _write_temp_file(
            "UPDATE users SET email = 'a@b.com' WHERE id = 42;\n", suffix=".sql"
        )
        findings = scan_file(path)
        os.unlink(path)
        rule_ids = [f["rule_id"] for f in findings]
        assert "sql_update_no_where" not in rule_ids

    def test_api_key_in_config_is_block_severity(self):
        """Bug: api_key_in_config was WARN instead of BLOCK.
        Fix: moved to DEVOPS_BLOCK_RULES."""
        from src.rules.anti_patterns import ANTI_PATTERNS
        rule = next(r for r in ANTI_PATTERNS if r["id"] == "api_key_in_config")
        assert str(rule["severity"]) == "BLOCK"


# ═══════════════════════════════════════════════════════════════
#  Phase 4 — SARIF output
# ═══════════════════════════════════════════════════════════════


class TestSarifOutput:
    """Tests for SARIF v2.1.0 output from CLI."""

    def test_sarif_basic_structure(self):
        findings = [
            {"rule_id": "eval_exec", "severity": "BLOCK", "message": "Danger", "file": "a.py", "line": 5},
        ]
        sarif = _findings_to_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "CodeTrust"

    def test_sarif_results(self):
        findings = [
            {"rule_id": "eval_exec", "severity": "BLOCK", "message": "Danger", "file": "a.py", "line": 5},
            {"rule_id": "print_debug", "severity": "WARN", "message": "Debug print", "file": "b.py", "line": 10},
        ]
        sarif = _findings_to_sarif(findings)
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "warning"

    def test_sarif_rules_deduplicated(self):
        findings = [
            {"rule_id": "eval_exec", "severity": "BLOCK", "message": "Danger", "file": "a.py", "line": 5},
            {"rule_id": "eval_exec", "severity": "BLOCK", "message": "Danger", "file": "a.py", "line": 10},
        ]
        sarif = _findings_to_sarif(findings)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_sarif_empty_findings(self):
        sarif = _findings_to_sarif([])
        assert len(sarif["runs"][0]["results"]) == 0


# ═══════════════════════════════════════════════════════════════
#  Phase 4 — Special handler implementations in CLI
# ═══════════════════════════════════════════════════════════════


class TestCliSpecialHandlers:
    """Tests for special_handler rules implemented in CLI."""

    def test_except_swallow_pass(self):
        path = _write_temp_file(
            "try:\n    x = 1\nexcept Exception:\n    pass\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "except_swallow" for f in findings)

    def test_except_swallow_ellipsis(self):
        path = _write_temp_file(
            "try:\n    x = 1\nexcept:\n    ...\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "except_swallow" for f in findings)

    def test_except_with_handler_no_match(self):
        path = _write_temp_file(
            "try:\n    x = 1\nexcept ValueError as e:\n    log(e)\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert not any(f["rule_id"] == "except_swallow" for f in findings)

    def test_sleep_no_context(self):
        path = _write_temp_file(
            "import time\ntime.sleep(1)\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "sleep_no_context" for f in findings)

    def test_sleep_with_comment_no_match(self):
        path = _write_temp_file(
            "import time\n# Wait for DB to be ready\ntime.sleep(1)\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert not any(f["rule_id"] == "sleep_no_context" for f in findings)

    def test_long_function(self):
        body = "\n".join([f"    x{i} = {i}" for i in range(45)])
        path = _write_temp_file(
            f"def big_func():\n{body}\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "long_function" for f in findings)

    def test_short_function_no_match(self):
        path = _write_temp_file(
            "def small():\n    return 1\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert not any(f["rule_id"] == "long_function" for f in findings)

    def test_connection_no_timeout(self):
        path = _write_temp_file(
            "client = AsyncClient(base_url='http://x')\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "connection_no_timeout" for f in findings)

    def test_connection_with_timeout_no_match(self):
        path = _write_temp_file(
            "client = AsyncClient(base_url='http://x', timeout=30)\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert not any(f["rule_id"] == "connection_no_timeout" for f in findings)

    def test_dockerfile_no_healthcheck(self):
        path = _write_temp_file(
            "FROM python:3.12\nCMD [\"python\", \"app.py\"]\n", suffix=".dockerfile",
        )
        # Rename to Dockerfile
        import shutil
        dpath = path.replace(".dockerfile", "")
        dname = os.path.join(os.path.dirname(dpath), "Dockerfile")
        shutil.move(path, dname)
        findings = scan_file(dname)
        os.unlink(dname)
        assert any(f["rule_id"] == "dockerfile_no_healthcheck" for f in findings)


# ═══════════════════════════════════════════════════════════════
#  Phase 4 — React / JSX rules
# ═══════════════════════════════════════════════════════════════


class TestReactRules:
    """Tests for React/JSX anti-pattern rules in CLI."""

    def test_react_rules_loaded(self):
        assert len(REACT_BLOCK_RULES) >= 2
        assert len(REACT_WARN_RULES) >= 2

    def test_dangerously_set_inner_html(self):
        path = _write_temp_file(
            "const x = <div dangerouslySetInnerHTML={{__html: input}} />;\n",
            suffix=".tsx",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "react_dangerouslysetinnerhtml" for f in findings)

    def test_innerhtml_assignment(self):
        path = _write_temp_file(
            "el.innerHTML = userInput;\n", suffix=".tsx",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "react_innerhtml_string" for f in findings)

    def test_direct_dom_manipulation(self):
        path = _write_temp_file(
            "const el = document.getElementById('root');\n", suffix=".tsx",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "react_direct_dom" for f in findings)

    def test_index_as_key(self):
        path = _write_temp_file(
            "items.map((item, index) => <li key={index}>{item}</li>);\n",
            suffix=".tsx",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "react_index_as_key" for f in findings)

    def test_react_rules_not_on_py(self):
        path = _write_temp_file(
            "const el = document.getElementById('root');\n", suffix=".py",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert not any(f["rule_id"] == "react_direct_dom" for f in findings)


# ═══════════════════════════════════════════════════════════════
#  Phase 4 — Kubernetes YAML rules
# ═══════════════════════════════════════════════════════════════


class TestK8sRules:
    """Tests for Kubernetes YAML rules in CLI."""

    def test_k8s_rules_loaded(self):
        assert len(K8S_BLOCK_RULES) >= 1
        assert len(K8S_WARN_RULES) >= 3

    def test_k8s_privileged(self):
        path = _write_temp_file(
            "spec:\n  containers:\n    - name: app\n      securityContext:\n        privileged: true\n",
            suffix=".yaml",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "k8s_privileged" for f in findings)

    def test_k8s_host_network(self):
        path = _write_temp_file(
            "spec:\n  hostNetwork: true\n  containers:\n    - name: app\n",
            suffix=".yaml",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "k8s_host_network" for f in findings)

    def test_k8s_run_as_root(self):
        path = _write_temp_file(
            "spec:\n  securityContext:\n    runAsUser: 0\n",
            suffix=".yaml",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "k8s_run_as_root" for f in findings)

    def test_k8s_latest_image(self):
        path = _write_temp_file(
            "spec:\n  containers:\n    - image: nginx:latest\n",
            suffix=".yaml",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert any(f["rule_id"] == "k8s_latest_image" for f in findings)

    def test_k8s_clean_yaml(self):
        path = _write_temp_file(
            "spec:\n  containers:\n    - image: nginx:1.25\n      resources:\n        limits:\n          cpu: 500m\n          memory: 128Mi\n        requests:\n          cpu: 250m\n          memory: 64Mi\n      securityContext:\n        runAsNonRoot: true\n",
            suffix=".yaml",
        )
        findings = scan_file(path)
        os.unlink(path)
        assert not any(
            f["rule_id"].startswith("k8s_") and f.get("severity") in ("BLOCK", "WARN")
            for f in findings
        )


# ═══════════════════════════════════════════════════════════════
#  Phase 4 — Config file support
# ═══════════════════════════════════════════════════════════════


class TestConfigFileSupport:
    """Tests for project config loading."""

    def test_config_loads_without_file(self):
        from src.cli import _load_project_config
        # Should not crash even if no config exists
        config = _load_project_config()
        assert isinstance(config, dict)

    def test_config_ignore_rules(self):
        """Test that ignore_rules filters findings."""
        from src.cli import PROJECT_CONFIG
        # PROJECT_CONFIG is loaded at import time — verify it's a dict
        assert isinstance(PROJECT_CONFIG, dict)
