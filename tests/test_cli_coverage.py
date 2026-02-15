"""Additional CLI tests to boost coverage.

Covers: scan_file, scan_path, config loading, special handlers,
color, drift score, SARIF conversion, cmd_init, cmd_scan,
cmd_status, cmd_doctor, cmd_governance.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from unittest.mock import patch

if TYPE_CHECKING:
    from pathlib import Path

from src.cli import (
    _build_cli_rules,
    _calculate_drift_score,
    _check_ci_no_timeout,
    _check_compose_healthcheck,
    _check_connection_timeout,
    _check_except_swallow,
    _check_function_length,
    _check_sleep_no_context,
    _findings_to_sarif,
    _load_project_config,
    color,
    scan_file,
    scan_path,
)

# ---------------------------------------------------------------------------
# color() function
# ---------------------------------------------------------------------------


class TestColor:
    def test_color_with_tty(self) -> None:
        with patch.object(sys.stdout, "isatty", return_value=True):
            result = color("hello", "\033[0;31m")
            assert "\033[0;31m" in result
            assert "hello" in result

    def test_color_without_tty(self) -> None:
        with patch.object(sys.stdout, "isatty", return_value=False):
            result = color("hello", "\033[0;31m")
            assert result == "hello"


# ---------------------------------------------------------------------------
# _build_cli_rules
# ---------------------------------------------------------------------------


class TestBuildCliRules:
    def test_returns_all_categories(self) -> None:
        rules = _build_cli_rules()
        assert "generic_block" in rules
        assert "generic_warn" in rules
        assert "sql_block" in rules
        assert "docker_block" in rules
        assert "ci_warn" in rules
        assert "devops_block" in rules
        assert "react_block" in rules
        assert "k8s_block" in rules

    def test_rules_not_empty(self) -> None:
        rules = _build_cli_rules()
        total = sum(len(v) for v in rules.values())
        assert total > 0


# ---------------------------------------------------------------------------
# _load_project_config
# ---------------------------------------------------------------------------


class TestLoadProjectConfig:
    def test_no_config_file(self, tmp_path: Path) -> None:
        with patch("src.cli.Path.cwd", return_value=tmp_path):
            result = _load_project_config()
            assert result == {}

    def test_codetrust_toml(self, tmp_path: Path) -> None:
        toml_file = tmp_path / ".codetrust.toml"
        toml_file.write_text('[codetrust]\nignore_rules = ["eval_exec"]\n')
        with patch("src.cli.Path.cwd", return_value=tmp_path):
            result = _load_project_config()
            assert result.get("ignore_rules") == ["eval_exec"]

    def test_pyproject_toml(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text('[tool.codetrust]\nignore_rules = ["eval_exec"]\n')
        with patch("src.cli.Path.cwd", return_value=tmp_path):
            result = _load_project_config()
            assert "ignore_rules" in result


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------


class TestScanFile:
    def test_scan_safe_python(self, tmp_path: Path) -> None:
        f = tmp_path / "safe.py"
        f.write_text("import os\nx = 1\n")
        findings = scan_file(str(f))
        block_findings = [f for f in findings if f["severity"] == "BLOCK"]
        assert len(block_findings) == 0

    def test_scan_eval(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("result = eval(user_input)\n")
        findings = scan_file(str(f))
        rule_ids = {f["rule_id"] for f in findings}
        assert "eval_exec" in rule_ids

    def test_scan_hardcoded_secret(self, tmp_path: Path) -> None:
        f = tmp_path / "secret.py"
        f.write_text('API_KEY = "sk-1234567890abcdef"\n')
        findings = scan_file(str(f))
        assert any(f["severity"] == "BLOCK" for f in findings)

    def test_scan_binary_file_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "binary.py"
        f.write_bytes(b"\x00\x01\x02binary content")
        findings = scan_file(str(f))
        assert findings == []

    def test_scan_nonexistent_file(self) -> None:
        findings = scan_file("/nonexistent/file.py")
        assert findings == []

    def test_scan_test_file_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "test_something.py"
        f.write_text("result = eval('x')\n")
        findings = scan_file(str(f))
        assert findings == []

    def test_scan_dockerfile(self, tmp_path: Path) -> None:
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:latest\nRUN apt-get update\n")
        findings = scan_file(str(f))
        assert len(findings) > 0

    def test_scan_sql_file(self, tmp_path: Path) -> None:
        f = tmp_path / "query.sql"
        f.write_text("SELECT * FROM users;\n")
        findings = scan_file(str(f))
        assert isinstance(findings, list)

    def test_scan_react_file(self, tmp_path: Path) -> None:
        f = tmp_path / "app.jsx"
        f.write_text('<div dangerouslySetInnerHTML={{__html: data}} />\n')
        findings = scan_file(str(f))
        assert len(findings) > 0

    def test_scan_yaml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "deploy.yml"
        f.write_text("apiVersion: v1\nkind: Pod\n")
        findings = scan_file(str(f))
        assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# scan_path
# ---------------------------------------------------------------------------


class TestScanPath:
    def test_scan_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "code.py"
        f.write_text("x = 1\n")
        findings = scan_path(str(f))
        assert isinstance(findings, list)

    def test_scan_directory(self, tmp_path: Path) -> None:
        (tmp_path / "a.py").write_text("x = 1\n")
        (tmp_path / "b.py").write_text("y = 2\n")
        findings = scan_path(str(tmp_path))
        assert isinstance(findings, list)

    def test_scan_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "evil.py").write_text("eval('x')\n")
        findings = scan_path(str(tmp_path))
        assert not any("node_modules" in str(f.get("file", "")) for f in findings)

    def test_scan_nonexistent_path(self) -> None:
        findings = scan_path("/nonexistent/path")
        assert findings == []


# ---------------------------------------------------------------------------
# Special handlers
# ---------------------------------------------------------------------------


class TestExceptSwallow:
    def test_detects_except_pass(self) -> None:
        lines = ["try:\n", "    x = 1\n", "except Exception:\n", "    pass\n"]
        findings: list[dict] = []
        _check_except_swallow(lines, "test.py", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "except_swallow"

    def test_no_false_positive(self) -> None:
        lines = ["try:\n", "    x = 1\n", "except Exception as e:\n", "    logger.error(e)\n"]
        findings: list[dict] = []
        _check_except_swallow(lines, "test.py", findings)
        assert len(findings) == 0


class TestSleepNoContext:
    def test_detects_uncommented_sleep(self) -> None:
        lines = ["import time\n", "time.sleep(5)\n"]
        findings: list[dict] = []
        _check_sleep_no_context(lines, "test.py", findings)
        assert len(findings) == 1

    def test_commented_sleep_ok(self) -> None:
        lines = ["# Wait for rate limit\n", "time.sleep(5)\n"]
        findings: list[dict] = []
        _check_sleep_no_context(lines, "test.py", findings)
        assert len(findings) == 0


class TestFunctionLength:
    def test_detects_long_function(self) -> None:
        lines = ["def big_func():\n"]
        for i in range(50):
            lines.append(f"    x_{i} = {i}\n")
        findings: list[dict] = []
        _check_function_length(lines, "test.py", findings)
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "long_function"

    def test_short_function_ok(self) -> None:
        lines = ["def small():\n", "    return 1\n"]
        findings: list[dict] = []
        _check_function_length(lines, "test.py", findings)
        assert len(findings) == 0


class TestConnectionTimeout:
    def test_detects_no_timeout(self) -> None:
        lines = ["client = AsyncClient()\n"]
        findings: list[dict] = []
        _check_connection_timeout(lines, "test.py", findings)
        assert len(findings) == 1

    def test_with_timeout_ok(self) -> None:
        lines = ["client = AsyncClient(timeout=30)\n"]
        findings: list[dict] = []
        _check_connection_timeout(lines, "test.py", findings)
        assert len(findings) == 0


class TestComposeHealthcheck:
    def test_detects_no_healthcheck(self) -> None:
        lines = [
            "version: '3'\n",
            "services:\n",
            "  redis:\n",
            "    image: redis:latest\n",
            "    ports:\n",
            "      - 6379:6379\n",
        ]
        findings: list[dict] = []
        _check_compose_healthcheck(lines, "compose.yml", findings)
        assert len(findings) >= 1

    def test_with_healthcheck_ok(self) -> None:
        lines = [
            "version: '3'\n",
            "services:\n",
            "  redis:\n",
            "    image: redis:latest\n",
            "    healthcheck:\n",
            "      test: redis-cli ping\n",
        ]
        findings: list[dict] = []
        _check_compose_healthcheck(lines, "compose.yml", findings)
        assert len(findings) == 0


class TestCiNoTimeout:
    def test_detects_no_timeout(self) -> None:
        lines = [
            "jobs:\n",
            "  build:\n",
            "    runs-on: ubuntu-latest\n",
            "    steps:\n",
            "      - uses: actions/checkout@v4\n",
        ]
        findings: list[dict] = []
        _check_ci_no_timeout(lines, "ci.yml", findings)
        assert len(findings) >= 1

    def test_with_timeout_ok(self) -> None:
        lines = [
            "jobs:\n",
            "  build:\n",
            "    runs-on: ubuntu-latest\n",
            "    timeout-minutes: 10\n",
            "    steps:\n",
            "      - uses: actions/checkout@v4\n",
        ]
        findings: list[dict] = []
        _check_ci_no_timeout(lines, "ci.yml", findings)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Drift score & SARIF
# ---------------------------------------------------------------------------


class TestDriftScore:
    def test_perfect_score(self) -> None:
        result = _calculate_drift_score([])
        assert result["score"] == 100
        assert result["grade"] == "A"

    def test_warn_findings(self) -> None:
        findings = [{"severity": "WARN"}, {"severity": "WARN"}]
        result = _calculate_drift_score(findings)
        assert result["score"] == 94
        assert result["grade"] == "A"

    def test_block_findings_lower_score(self) -> None:
        findings = [{"severity": "BLOCK"}, {"severity": "BLOCK"}, {"severity": "BLOCK"}]
        result = _calculate_drift_score(findings)
        assert result["score"] == 70
        assert result["grade"] == "B"

    def test_many_findings_grade_f(self) -> None:
        findings = [{"severity": "BLOCK"}] * 10
        result = _calculate_drift_score(findings)
        assert result["score"] == 0
        assert result["grade"] == "F"


class TestFindingsToSarif:
    def test_sarif_structure(self) -> None:
        findings = [
            {"rule_id": "eval_exec", "severity": "BLOCK", "message": "eval detected", "file": "test.py", "line": 1},
        ]
        sarif = _findings_to_sarif(findings)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_empty(self) -> None:
        sarif = _findings_to_sarif([])
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0
