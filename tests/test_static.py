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
        code = "cat <" + "<EOF\nhello\nEOF"
        findings = analyzer.scan_code(code, "script.sh")
        block_findings = [f for f in findings if f.rule_id == "heredoc"]
        assert len(block_findings) >= 1
        assert block_findings[0].severity == Severity.BLOCK

    def test_detects_hardcoded_secret(self, analyzer: StaticAnalyzer) -> None:
        code = "API_" + 'KEY = "supersecretkey12345"'
        findings = analyzer.scan_code(code, "config.py")
        secret_findings = [f for f in findings if f.rule_id == "hardcoded_secret"]
        assert len(secret_findings) >= 1
        assert secret_findings[0].severity == Severity.BLOCK

    def test_detects_eval(self, analyzer: StaticAnalyzer) -> None:
        code = "result = " + "ev" + "al(user_input)"
        findings = analyzer.scan_code(code, "app.py")
        eval_findings = [f for f in findings if f.rule_id == "eval_exec"]
        assert len(eval_findings) >= 1
        assert eval_findings[0].severity == Severity.BLOCK

    def test_detects_exec(self, analyzer: StaticAnalyzer) -> None:
        code = "ex" + "ec(code_string)"
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

    # --- AI Agent Enforcement ---

    def test_detects_tee_heredoc(self, analyzer: StaticAnalyzer) -> None:
        code = "tee /etc/config.yml <" + "<EOF\nkey: value\nEOF"
        findings = analyzer.scan_code(code, "deploy.sh")
        matched = [f for f in findings if f.rule_id == "agent_tee_heredoc"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_detects_echo_multiline_redirect(self, analyzer: StaticAnalyzer) -> None:
        code = 'echo -e "line1\\nline2" > output.py'
        findings = analyzer.scan_code(code, "setup.sh")
        matched = [f for f in findings if f.rule_id == "agent_echo_multiline_redirect"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_detects_cat_heredoc(self, analyzer: StaticAnalyzer) -> None:
        code = "cat > config.py <" + "<EOF\nprint('hi')\nEOF"
        findings = analyzer.scan_code(code, "install.sh")
        matched = [f for f in findings if f.rule_id == "agent_cat_heredoc"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_detects_subprocess_shell_true(self, analyzer: StaticAnalyzer) -> None:
        code = "subprocess.run('ls -la', shell=True)"
        findings = analyzer.scan_code(code, "app.py")
        matched = [f for f in findings if f.rule_id == "agent_subprocess_shell_true"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_detects_os_system(self, analyzer: StaticAnalyzer) -> None:
        code = "os.system('rm -rf /tmp/build')"
        findings = analyzer.scan_code(code, "cleanup.py")
        matched = [f for f in findings if f.rule_id == "agent_os_system"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_detects_os_popen(self, analyzer: StaticAnalyzer) -> None:
        code = "result = os.popen('whoami').read()"
        findings = analyzer.scan_code(code, "utils.py")
        matched = [f for f in findings if f.rule_id == "agent_os_popen"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK


# ---------------------------------------------------------------------------
# scan_code — WARN severity
# ---------------------------------------------------------------------------


class TestScanCodeWarn:
    """Tests for WARN-severity anti-pattern detection."""

    def test_detects_todo(self, analyzer: StaticAnalyzer) -> None:
        code = "x = 1  # TO" + "DO fix this later"
        findings = analyzer.scan_code(code, "app.py")
        todo_findings = [f for f in findings if f.rule_id == "todo_hack"]
        assert len(todo_findings) >= 1
        assert todo_findings[0].severity == Severity.INFO

    def test_detects_hack_marker(self, analyzer: StaticAnalyzer) -> None:
        code = "# HA" + "CK: workaround for bug"
        findings = analyzer.scan_code(code, "app.py")
        hack_findings = [f for f in findings if f.rule_id == "todo_hack"]
        assert len(hack_findings) >= 1

    def test_detects_console_log(self, analyzer: StaticAnalyzer) -> None:
        code = "console." + "log('debug output')"
        findings = analyzer.scan_code(code, "app.js")
        log_findings = [f for f in findings if f.rule_id == "console_log"]
        assert len(log_findings) >= 1

    def test_detects_print_debug(self, analyzer: StaticAnalyzer) -> None:
        code = "print(some_variable)"
        findings = analyzer.scan_code(code, "app.py")
        print_findings = [f for f in findings if f.rule_id == "print_debug"]
        assert len(print_findings) >= 1

    def test_detects_any_type(self, analyzer: StaticAnalyzer) -> None:
        code = "def foo(x: " + "Any" + ") -> None: ..."
        findings = analyzer.scan_code(code, "app.py")
        any_findings = [f for f in findings if f.rule_id == "any_type"]
        assert len(any_findings) >= 1

    def test_detects_wildcard_import(self, analyzer: StaticAnalyzer) -> None:
        code = "from os import " + "*"
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
        question_mark = chr(63)
        code = f"x = a {question_mark} b {question_mark} c : d : e"
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
        code = "x = 1\ny = 2\nresult = " + "ev" + "al(user_input)\nz = 3"
        findings = analyzer.scan_code(code, "app.py")
        eval_findings = [f for f in findings if f.rule_id == "eval_exec"]
        assert len(eval_findings) == 1
        assert eval_findings[0].line == 3

    def test_finding_has_filename(self, analyzer: StaticAnalyzer) -> None:
        code = "result = " + "ev" + "al(user_input)"
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


# ---------------------------------------------------------------------------
# Phase 1 Expansion — sample tests for new rule categories
# ---------------------------------------------------------------------------


class TestPhase1SecurityRules:
    """Tests for Phase 1 expanded security rules."""

    def test_yaml_unsafe_load(self, analyzer: StaticAnalyzer) -> None:
        code = "data = yaml.load(file_content)"
        findings = analyzer.scan_code(code, "parser.py")
        matched = [f for f in findings if f.rule_id == "py_yaml_unsafe_load"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_flask_debug_mode(self, analyzer: StaticAnalyzer) -> None:
        code = "app.run(host='0.0.0.0', debug=True)"
        findings = analyzer.scan_code(code, "app.py")
        matched = [f for f in findings if f.rule_id == "py_flask_debug_mode"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_django_debug_true(self, analyzer: StaticAnalyzer) -> None:
        code = "DEBUG = True"
        findings = analyzer.scan_code(code, "settings.py")
        matched = [f for f in findings if f.rule_id == "py_django_debug_true"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_tempfile_mktemp(self, analyzer: StaticAnalyzer) -> None:
        code = "tmp_path = tempfile.mktemp(suffix='.py')"
        findings = analyzer.scan_code(code, "utils.py")
        matched = [f for f in findings if f.rule_id == "py_tempfile_mktemp"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_github_token_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz123456789012'"
        findings = analyzer.scan_code(code, "config.py")
        matched = [f for f in findings if f.rule_id == "secret_github_token"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_openai_key_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "OPENAI_KEY = 'sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX'"
        findings = analyzer.scan_code(code, "config.py")
        matched = [f for f in findings if f.rule_id == "secret_openai_key"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_private_key_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "key = '-----BEGIN RSA PRIVATE KEY-----\\n...'"
        findings = analyzer.scan_code(code, "server.py")
        matched = [f for f in findings if f.rule_id == "secret_private_key_header"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_md5_weak_hash(self, analyzer: StaticAnalyzer) -> None:
        code = "digest = hashlib.md5(data).hexdigest()"
        findings = analyzer.scan_code(code, "hash_util.py")
        matched = [f for f in findings if f.rule_id == "crypto_md5_weak"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_ssl_no_verify(self, analyzer: StaticAnalyzer) -> None:
        code = "response = requests.get(url, verify=False)"
        findings = analyzer.scan_code(code, "client.py")
        matched = [f for f in findings if f.rule_id == "crypto_ssl_no_verify"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_crypto_weak_random(self, analyzer: StaticAnalyzer) -> None:
        code = "token = random.randint(100000, 999999)"
        findings = analyzer.scan_code(code, "auth.py")
        matched = [f for f in findings if f.rule_id == "crypto_weak_random"]
        assert len(matched) >= 1

    def test_ecb_mode_detected(self, analyzer: StaticAnalyzer) -> None:
        code = "cipher = AES.new(key, AES.MODE_ECB)"
        findings = analyzer.scan_code(code, "crypto.py")
        matched = [f for f in findings if f.rule_id == "crypto_ecb_mode"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_jwt_none_algorithm(self, analyzer: StaticAnalyzer) -> None:
        code = "token = jwt.encode(payload, key, algorithm='none')"
        findings = analyzer.scan_code(code, "auth.py")
        matched = [f for f in findings if f.rule_id == "crypto_jwt_none_algorithm"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_innerhtml_xss(self, analyzer: StaticAnalyzer) -> None:
        code = "element.innerHTML = userData;"
        findings = analyzer.scan_code(code, "app.js")
        matched = [f for f in findings if f.rule_id == "js_innerhtml_xss"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_js_child_process_exec(self, analyzer: StaticAnalyzer) -> None:
        code = "require('child_process').exec(userCmd);"
        findings = analyzer.scan_code(code, "runner.js")
        matched = [f for f in findings if f.rule_id == "js_child_process_exec"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_go_tls_insecure_skip(self, analyzer: StaticAnalyzer) -> None:
        code = "TLSClientConfig: &tls.Config{InsecureSkipVerify: true}"
        findings = analyzer.scan_code(code, "client.go")
        matched = [f for f in findings if f.rule_id == "go_tls_insecure_skip"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_java_deserialize_object(self, analyzer: StaticAnalyzer) -> None:
        code = "Object obj = new ObjectInputStream(is).readObject();"
        findings = analyzer.scan_code(code, "Deserializer.java")
        matched = [f for f in findings if f.rule_id == "java_deserialize_object"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_c_gets_unsafe(self, analyzer: StaticAnalyzer) -> None:
        code = "gets(buffer);"
        findings = analyzer.scan_code(code, "input.c")
        matched = [f for f in findings if f.rule_id == "c_gets_unsafe"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_c_strcpy_unsafe(self, analyzer: StaticAnalyzer) -> None:
        code = "strcpy(dest, src);"
        findings = analyzer.scan_code(code, "utils.c")
        matched = [f for f in findings if f.rule_id == "c_strcpy_unsafe"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_sh_curl_bash_pipe(self, analyzer: StaticAnalyzer) -> None:
        code = "curl -sL https://example.com/install.sh | bash"
        findings = analyzer.scan_code(code, "setup.sh")
        matched = [f for f in findings if f.rule_id == "sh_curl_bash_pipe"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_sh_chmod_777(self, analyzer: StaticAnalyzer) -> None:
        code = "chmod 777 /var/app/uploads"
        findings = analyzer.scan_code(code, "deploy.sh")
        matched = [f for f in findings if f.rule_id == "sh_chmod_777"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_log_sensitive_data(self, analyzer: StaticAnalyzer) -> None:
        code = "logger.info('User login with password: %s', user_password)"
        findings = analyzer.scan_code(code, "auth.py")
        matched = [f for f in findings if f.rule_id == "log_sensitive_data"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_db_connection_string_hardcoded(self, analyzer: StaticAnalyzer) -> None:
        code = "db = connect('postgres://admin:secret123@db.example.com/prod')"
        findings = analyzer.scan_code(code, "db.py")
        matched = [f for f in findings if f.rule_id == "db_connection_string_hardcoded"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_iac_s3_public_acl(self, analyzer: StaticAnalyzer) -> None:
        code = 'resource "aws_s3_bucket" "data" { acl = "public-read" }'
        findings = analyzer.scan_code(code, "main.tf")
        matched = [f for f in findings if f.rule_id == "iac_s3_public_acl"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_iac_iam_star_action(self, analyzer: StaticAnalyzer) -> None:
        code = '{"Action": "*", "Resource": "arn:aws:s3:::*"}'
        findings = analyzer.scan_code(code, "policy.json")
        matched = [f for f in findings if f.rule_id == "iac_iam_star_action"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_api_cors_wildcard(self, analyzer: StaticAnalyzer) -> None:
        code = "allow_origins=['*']"
        findings = analyzer.scan_code(code, "main.py")
        matched = [f for f in findings if f.rule_id == "api_cors_wildcard"]
        assert len(matched) >= 1

    def test_rust_unwrap_warn(self, analyzer: StaticAnalyzer) -> None:
        code = "let value = some_result.unwrap();"
        findings = analyzer.scan_code(code, "lib.rs")
        matched = [f for f in findings if f.rule_id == "rust_unwrap_in_production"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.WARN

    def test_ai_prompt_injection_warn(self, analyzer: StaticAnalyzer) -> None:
        code = 'prompt = f"Answer this: {user_query}"'
        findings = analyzer.scan_code(code, "chat.py")
        matched = [f for f in findings if f.rule_id == "ai_prompt_user_input"]
        assert len(matched) >= 1

    def test_document_write_xss(self, analyzer: StaticAnalyzer) -> None:
        code = "document.write('<script>' + userData + '</script>');"
        findings = analyzer.scan_code(code, "page.js")
        matched = [f for f in findings if f.rule_id == "js_document_write"]
        assert len(matched) >= 1
        assert matched[0].severity == Severity.BLOCK

    def test_graphql_introspection(self, analyzer: StaticAnalyzer) -> None:
        code = "schema = graphene.Schema(query=Query, introspection=True)"
        findings = analyzer.scan_code(code, "schema.py")
        matched = [f for f in findings if f.rule_id == "graphql_introspection_enabled"]
        assert len(matched) >= 1
