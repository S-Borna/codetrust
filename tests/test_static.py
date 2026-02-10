"""Tests for the static analysis engine (Layer 1)."""

import tempfile
from pathlib import Path

import pytest

from src.models.enums import Severity
from src.models.responses import Finding
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def analyzer() -> StaticAnalyzer:
    """Create a StaticAnalyzer instance."""
    return StaticAnalyzer()


# ---------------------------------------------------------------------------
# scan_code — BLOCK severity
# ---------------------------------------------------------------------------


class TestScanCodeBlock:
    """Tests for BLOCK-severity anti-pattern detection."""

    def test_detects_heredoc(self, analyzer: StaticAnalyzer) -> None:
        code = "cat <<EOF\nhello\nEOF"
        findings = analyzer.scan_code(code, "script.sh")
        block_findings = [f for f in findings if f.rule_id == "heredoc"]
        assert len(block_findings) >= 1
        assert block_findings[0].severity == Severity.BLOCK

    def test_detects_hardcoded_secret(self, analyzer: StaticAnalyzer) -> None:
        code = 'API_KEY = "supersecretkey12345"'
        findings = analyzer.scan_code(code, "config.py")
        secret_findings = [f for f in findings if f.rule_id == "hardcoded_secret"]
        assert len(secret_findings) >= 1
        assert secret_findings[0].severity == Severity.BLOCK

    def test_detects_eval(self, analyzer: StaticAnalyzer) -> None:
        code = "result = eval(user_input)"
        findings = analyzer.scan_code(code, "app.py")
        eval_findings = [f for f in findings if f.rule_id == "eval_exec"]
        assert len(eval_findings) >= 1
        assert eval_findings[0].severity == Severity.BLOCK

    def test_detects_exec(self, analyzer: StaticAnalyzer) -> None:
        code = "exec(code_string)"
        findings = analyzer.scan_code(code, "app.py")
        exec_findings = [f for f in findings if f.rule_id == "eval_exec"]
        assert len(exec_findings) >= 1

    def test_detects_sql_injection(self, analyzer: StaticAnalyzer) -> None:
        code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        findings = analyzer.scan_code(code, "db.py")
        sql_findings = [f for f in findings if f.rule_id == "sql_injection"]
        assert len(sql_findings) >= 1
        assert sql_findings[0].severity == Severity.BLOCK

    def test_detects_pickle_load(self, analyzer: StaticAnalyzer) -> None:
        code = "data = pickle.load(file)"
        findings = analyzer.scan_code(code, "data.py")
        pickle_findings = [f for f in findings if f.rule_id == "pickle_load"]
        assert len(pickle_findings) >= 1
        assert pickle_findings[0].severity == Severity.BLOCK


# ---------------------------------------------------------------------------
# scan_code — WARN severity
# ---------------------------------------------------------------------------


class TestScanCodeWarn:
    """Tests for WARN-severity anti-pattern detection."""

    def test_detects_todo(self, analyzer: StaticAnalyzer) -> None:
        code = "x = 1  # TODO fix this later"
        findings = analyzer.scan_code(code, "app.py")
        todo_findings = [f for f in findings if f.rule_id == "todo_hack"]
        assert len(todo_findings) >= 1
        assert todo_findings[0].severity == Severity.WARN

    def test_detects_hack_marker(self, analyzer: StaticAnalyzer) -> None:
        code = "# HACK: workaround for bug"
        findings = analyzer.scan_code(code, "app.py")
        hack_findings = [f for f in findings if f.rule_id == "todo_hack"]
        assert len(hack_findings) >= 1

    def test_detects_console_log(self, analyzer: StaticAnalyzer) -> None:
        code = "console.log('debug output')"
        findings = analyzer.scan_code(code, "app.js")
        log_findings = [f for f in findings if f.rule_id == "console_log"]
        assert len(log_findings) >= 1

    def test_detects_print_debug(self, analyzer: StaticAnalyzer) -> None:
        code = "print(some_variable)"
        findings = analyzer.scan_code(code, "app.py")
        print_findings = [f for f in findings if f.rule_id == "print_debug"]
        assert len(print_findings) >= 1

    def test_detects_any_type(self, analyzer: StaticAnalyzer) -> None:
        code = "def foo(x: Any) -> None: ..."
        findings = analyzer.scan_code(code, "app.py")
        any_findings = [f for f in findings if f.rule_id == "any_type"]
        assert len(any_findings) >= 1

    def test_detects_wildcard_import(self, analyzer: StaticAnalyzer) -> None:
        code = "from os import *"
        findings = analyzer.scan_code(code, "app.py")
        wildcard_findings = [f for f in findings if f.rule_id == "wildcard_import"]
        assert len(wildcard_findings) >= 1

    def test_detects_bare_except(self, analyzer: StaticAnalyzer) -> None:
        code = "try:\n    pass\nexcept:\n    pass"
        findings = analyzer.scan_code(code, "app.py")
        bare_findings = [f for f in findings if f.rule_id == "bare_except"]
        assert len(bare_findings) >= 1

    def test_detects_mutable_default(self, analyzer: StaticAnalyzer) -> None:
        code = "def foo(items: list = []):\n    pass"
        findings = analyzer.scan_code(code, "app.py")
        mutable_findings = [f for f in findings if f.rule_id == "mutable_default"]
        assert len(mutable_findings) >= 1

    def test_detects_nested_ternary(self, analyzer: StaticAnalyzer) -> None:
        code = "x = a ? b ? c : d : e"
        findings = analyzer.scan_code(code, "app.js")
        ternary_findings = [f for f in findings if f.rule_id == "nested_ternary"]
        assert len(ternary_findings) >= 1


# ---------------------------------------------------------------------------
# scan_code — clean code produces no findings
# ---------------------------------------------------------------------------


class TestScanCodeClean:
    """Tests for clean code that should produce no findings."""

    def test_clean_python_code(self, analyzer: StaticAnalyzer) -> None:
        code = (
            "import os\n"
            "from pathlib import Path\n"
            "\n"
            "def greet(name: str) -> str:\n"
            '    return f"Hello, {name}"\n'
        )
        findings = analyzer.scan_code(code, "clean.py")
        # Should have no BLOCK or WARN findings
        serious = [f for f in findings if f.severity in (Severity.BLOCK, Severity.WARN)]
        assert len(serious) == 0

    def test_empty_code(self, analyzer: StaticAnalyzer) -> None:
        findings = analyzer.scan_code("", "empty.py")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# scan_code — function length check
# ---------------------------------------------------------------------------


class TestFunctionLength:
    """Tests for the function length checking."""

    def test_short_function_no_finding(self, analyzer: StaticAnalyzer) -> None:
        code = "def short_func():\n" + "    x = 1\n" * 10
        findings = analyzer.scan_code(code, "app.py")
        long_findings = [f for f in findings if f.rule_id == "long_function"]
        assert len(long_findings) == 0

    def test_long_function_triggers_finding(self, analyzer: StaticAnalyzer) -> None:
        lines = ["def long_func():"]
        lines.extend(["    x = 1"] * 50)
        code = "\n".join(lines)
        findings = analyzer.scan_code(code, "app.py")
        long_findings = [f for f in findings if f.rule_id == "long_function"]
        assert len(long_findings) >= 1
        assert long_findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# scan_code — line numbers
# ---------------------------------------------------------------------------


class TestLineNumbers:
    """Tests that findings report correct line numbers."""

    def test_finding_has_correct_line_number(self, analyzer: StaticAnalyzer) -> None:
        code = "x = 1\ny = 2\nresult = eval(user_input)\nz = 3"
        findings = analyzer.scan_code(code, "app.py")
        eval_findings = [f for f in findings if f.rule_id == "eval_exec"]
        assert len(eval_findings) == 1
        assert eval_findings[0].line == 3

    def test_finding_has_filename(self, analyzer: StaticAnalyzer) -> None:
        code = "result = eval(user_input)"
        findings = analyzer.scan_code(code, "myfile.py")
        assert findings[0].file == "myfile.py"


# ---------------------------------------------------------------------------
# check_repo_structure
# ---------------------------------------------------------------------------


class TestRepoStructure:
    """Tests for repository structure validation."""

    def test_missing_required_files(self, analyzer: StaticAnalyzer) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = analyzer.check_repo_structure(tmpdir)
            required_findings = [
                f for f in findings if f.rule_id == "missing_required_file"
            ]
            # README.md, .gitignore, LICENSE should be missing
            assert len(required_findings) == 3

    def test_all_required_files_present(self, analyzer: StaticAnalyzer) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            for name in ["README.md", ".gitignore", "LICENSE"]:
                Path(tmpdir, name).touch()
            findings = analyzer.check_repo_structure(tmpdir)
            required_findings = [
                f for f in findings if f.rule_id == "missing_required_file"
            ]
            assert len(required_findings) == 0

    def test_missing_recommended_files(self, analyzer: StaticAnalyzer) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = analyzer.check_repo_structure(tmpdir)
            recommended_findings = [
                f
                for f in findings
                if f.rule_id == "missing_recommended_file"
            ]
            assert len(recommended_findings) > 0

    def test_forbidden_file_detected(self, analyzer: StaticAnalyzer) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, ".env").touch()
            findings = analyzer.check_repo_structure(tmpdir)
            forbidden_findings = [
                f for f in findings if f.rule_id == "forbidden_file"
            ]
            assert len(forbidden_findings) >= 1

    def test_complete_project_structure(self, analyzer: StaticAnalyzer) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create all required and recommended files
            for name in ["README.md", ".gitignore", "LICENSE", "CHANGELOG.md",
                         "pyproject.toml", "Dockerfile", ".env.example"]:
                Path(tmpdir, name).touch()
            for dirname in ["src", "tests"]:
                Path(tmpdir, dirname).mkdir()
            Path(tmpdir, "tests").mkdir(exist_ok=True)

            findings = analyzer.check_repo_structure(tmpdir)
            block_findings = [
                f for f in findings if f.severity == Severity.BLOCK
            ]
            assert len(block_findings) == 0


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------


class TestBuildReport:
    """Tests for the markdown report builder."""

    def test_empty_findings_pass(self, analyzer: StaticAnalyzer) -> None:
        report = analyzer.build_report([], title="Test Report")
        assert "PASS" in report
        assert "No issues found" in report

    def test_report_contains_block_section(self, analyzer: StaticAnalyzer) -> None:
        findings = [
            Finding(
                rule_id="eval_exec",
                severity=Severity.BLOCK,
                message="eval/exec detected",
                file="app.py",
                line=5,
            )
        ]
        report = analyzer.build_report(findings, title="Test")
        assert "BLOCK" in report
        assert "eval_exec" in report

    def test_report_contains_all_sections(self, analyzer: StaticAnalyzer) -> None:
        findings = [
            Finding(rule_id="rule1", severity=Severity.BLOCK, message="block msg"),
            Finding(rule_id="rule2", severity=Severity.WARN, message="warn msg"),
            Finding(rule_id="rule3", severity=Severity.INFO, message="info msg"),
        ]
        report = analyzer.build_report(findings, title="Test")
        assert "BLOCK" in report
        assert "WARN" in report
        assert "INFO" in report


# ---------------------------------------------------------------------------
# build_scan_response
# ---------------------------------------------------------------------------


class TestBuildScanResponse:
    """Tests for the scan response builder."""

    def test_empty_findings(self, analyzer: StaticAnalyzer) -> None:
        response = analyzer.build_scan_response([])
        assert response.total_findings == 0
        assert response.verdict == "PASS"
        assert response.blocks == 0

    def test_counts_severities(self, analyzer: StaticAnalyzer) -> None:
        findings = [
            Finding(rule_id="r1", severity=Severity.BLOCK, message="m1"),
            Finding(rule_id="r2", severity=Severity.BLOCK, message="m2"),
            Finding(rule_id="r3", severity=Severity.WARN, message="m3"),
            Finding(rule_id="r4", severity=Severity.INFO, message="m4"),
        ]
        response = analyzer.build_scan_response(findings)
        assert response.total_findings == 4
        assert response.blocks == 2
        assert response.warnings == 1
        assert response.infos == 1
        assert response.verdict == "BLOCK"

    def test_warn_verdict(self, analyzer: StaticAnalyzer) -> None:
        findings = [
            Finding(rule_id="r1", severity=Severity.WARN, message="m1"),
        ]
        response = analyzer.build_scan_response(findings)
        assert response.verdict == "WARN"
