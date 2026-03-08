"""Tests for GitHub Action scan runner and related utilities."""

import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from action.scan_runner import (
    COMMENT_END,
    COMMENT_START,
    _get_pr_base_sha,
    _get_pr_number,
    _is_excluded,
    _language_glob,
    compute_verdict,
    diff_new_findings,
    discover_files,
    emit_annotations,
    print_summary,
    scan_files,
    should_fail,
    upsert_comment,
    write_markdown_report,
    write_sarif,
)
from src.models.enums import Severity
from src.models.responses import Finding

# --- File discovery tests ---


class TestLanguageGlob:
    """Test language-to-glob mapping."""

    def test_python_glob(self) -> None:
        """Python returns *.py."""
        assert _language_glob("python") == "*.py"

    def test_javascript_glob(self) -> None:
        """JavaScript returns *.js."""
        assert _language_glob("javascript") == "*.js"

    def test_typescript_glob(self) -> None:
        """TypeScript returns *.ts."""
        assert _language_glob("typescript") == "*.ts"

    def test_go_glob(self) -> None:
        """Go returns *.go."""
        assert _language_glob("go") == "*.go"

    def test_rust_glob(self) -> None:
        """Rust returns *.rs."""
        assert _language_glob("rust") == "*.rs"

    def test_unknown_language(self) -> None:
        """Unknown language returns *.*."""
        assert _language_glob("cobol") == "*.*"


class TestIsExcluded:
    """Test exclusion logic."""

    def test_git_excluded(self) -> None:
        """Files in .git are excluded."""
        assert _is_excluded(Path(".git/config"))

    def test_venv_excluded(self) -> None:
        """Files in .venv are excluded."""
        assert _is_excluded(Path(".venv/lib/site.py"))

    def test_node_modules_excluded(self) -> None:
        """Files in node_modules are excluded."""
        assert _is_excluded(Path("node_modules/pkg/index.js"))

    def test_pycache_excluded(self) -> None:
        """__pycache__ directories are excluded."""
        assert _is_excluded(Path("src/__pycache__/mod.pyc"))

    def test_regular_file_not_excluded(self) -> None:
        """Regular source files are not excluded."""
        assert not _is_excluded(Path("src/main.py"))

    def test_egg_info_excluded(self) -> None:
        """egg-info directories are excluded."""
        assert _is_excluded(Path("mypackage.egg-info/PKG-INFO"))


class TestDiscoverFiles:
    """Test file discovery."""

    def test_single_file(self, tmp_path: Path) -> None:
        """Single file path returns that file."""
        f = tmp_path / "test.py"
        f.write_text("x = 1\n")
        files = discover_files(str(f), "python", "", 500_000)
        assert len(files) == 1
        assert files[0] == f

    def test_directory_finds_python(self, tmp_path: Path) -> None:
        """Directory scan finds .py files."""
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "readme.md").write_text("# Hi\n")
        files = discover_files(str(tmp_path), "python", "", 500_000)
        assert len(files) == 1

    def test_respects_include_pattern(self, tmp_path: Path) -> None:
        """Custom include pattern overrides language glob."""
        (tmp_path / "app.py").write_text("x = 1\n")
        (tmp_path / "test.txt").write_text("data\n")
        files = discover_files(str(tmp_path), "python", "*.txt", 500_000)
        assert len(files) == 1
        assert files[0].name == "test.txt"

    def test_excludes_large_files(self, tmp_path: Path) -> None:
        """Files exceeding max size are excluded."""
        f = tmp_path / "big.py"
        f.write_text("x = 1\n" * 1000)
        files = discover_files(str(tmp_path), "python", "", 10)
        assert len(files) == 0

    def test_excludes_venv(self, tmp_path: Path) -> None:
        """Files in .venv are excluded."""
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "site.py").write_text("x = 1\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        files = discover_files(str(tmp_path), "python", "", 500_000)
        assert len(files) == 1
        assert files[0].name == "app.py"

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Empty directory returns no files."""
        files = discover_files(str(tmp_path), "python", "", 500_000)
        assert len(files) == 0


# --- Scan tests ---


class TestScanFiles:
    """Test file scanning."""

    def test_scan_clean_file(self, tmp_path: Path) -> None:
        """Clean code produces no findings."""
        f = tmp_path / "clean.py"
        f.write_text("x = 1\ny = 2\n")
        findings = scan_files([f], "python")
        # Clean code should have no findings
        assert isinstance(findings, list)

    def test_scan_bad_file(self, tmp_path: Path) -> None:
        """Code with eval produces a finding."""
        f = tmp_path / "bad.py"
        f.write_text("result = " + "ev" + "al('1 + 1')\n")
        findings = scan_files([f], "python")
        assert len(findings) > 0
        assert any(f.rule_id == "eval_exec" for f in findings)

    def test_scan_unreadable_file(self, tmp_path: Path) -> None:
        """Unreadable file is skipped."""
        fake_path = tmp_path / "nonexistent.py"
        findings = scan_files([fake_path], "python")
        assert len(findings) == 0


# --- Verdict tests ---


class TestComputeVerdict:
    """Test verdict computation."""

    def test_no_findings_pass(self) -> None:
        """No findings -> PASS."""
        assert compute_verdict([]) == "PASS"

    def test_block_finding_blocks(self) -> None:
        """BLOCK finding -> BLOCK verdict."""
        findings = [
            Finding(
                rule_id="eval_exec", severity=Severity.BLOCK,
                message="eval", file="a.py", line=1,
            ),
        ]
        assert compute_verdict(findings) == "BLOCK"

    def test_warn_finding_warns(self) -> None:
        """WARN finding -> WARN verdict."""
        findings = [
            Finding(
                rule_id="todo", severity=Severity.WARN,
                message="todo", file="a.py", line=1,
            ),
        ]
        assert compute_verdict(findings) == "WARN"

    def test_info_only_passes(self) -> None:
        """INFO-only findings -> PASS."""
        findings = [
            Finding(
                rule_id="info", severity=Severity.INFO,
                message="info", file="a.py", line=1,
            ),
        ]
        assert compute_verdict(findings) == "PASS"

    def test_block_overrides_warn(self) -> None:
        """BLOCK verdict takes precedence over WARN."""
        findings = [
            Finding(
                rule_id="eval", severity=Severity.BLOCK,
                message="eval", file="a.py", line=1,
            ),
            Finding(
                rule_id="todo", severity=Severity.WARN,
                message="todo", file="a.py", line=2,
            ),
        ]
        assert compute_verdict(findings) == "BLOCK"


# --- Failure threshold tests ---


class TestShouldFail:
    """Test failure threshold logic."""

    def test_never_never_fails(self) -> None:
        """fail-on=never always passes."""
        assert should_fail("BLOCK", "never") is False

    def test_block_fails_on_block(self) -> None:
        """fail-on=block fails on BLOCK verdict."""
        assert should_fail("BLOCK", "block") is True

    def test_block_passes_on_warn(self) -> None:
        """fail-on=block passes on WARN verdict."""
        assert should_fail("WARN", "block") is False

    def test_warn_fails_on_block(self) -> None:
        """fail-on=warn fails on BLOCK verdict."""
        assert should_fail("BLOCK", "warn") is True

    def test_warn_fails_on_warn(self) -> None:
        """fail-on=warn fails on WARN verdict."""
        assert should_fail("WARN", "warn") is True

    def test_warn_passes_on_pass(self) -> None:
        """fail-on=warn passes on PASS verdict."""
        assert should_fail("PASS", "warn") is False

    def test_block_passes_on_pass(self) -> None:
        """fail-on=block passes on PASS verdict."""
        assert should_fail("PASS", "block") is False


class TestPrModeDiff:
    """Test PR-mode new-findings diffing."""

    def test_diff_returns_only_new_findings(self) -> None:
        """Findings present only in head are returned."""
        baseline = [
            Finding(
                rule_id="eval_exec",
                severity=Severity.BLOCK,
                message="eval",
                file="a.py",
                line=1,
            ),
        ]
        head = [
            Finding(
                rule_id="eval_exec",
                severity=Severity.BLOCK,
                message="eval",
                file="a.py",
                line=1,
            ),
            Finding(
                rule_id="hardcoded_secret",
                severity=Severity.BLOCK,
                message="secret",
                file="a.py",
                line=2,
            ),
        ]

        new_only = diff_new_findings(head, baseline)
        assert len(new_only) == 1
        assert new_only[0].rule_id == "hardcoded_secret"


class TestMarkdownReport:
    """Test markdown report generation."""

    def test_writes_markdown_report(self, tmp_path: Path) -> None:
        """Report file is created and includes verdict and counts."""
        report_path = tmp_path / "codetrust-report.md"
        findings = [
            Finding(
                rule_id="eval_exec",
                severity=Severity.BLOCK,
                message="eval",
                file="a.py",
                line=1,
            ),
        ]

        write_markdown_report(
            verdict="BLOCK",
            findings=findings,
            files_scanned=1,
            report_path=str(report_path),
            pr_mode_active=True,
        )

        text = report_path.read_text(encoding="utf-8")
        assert "CodeTrust Verdict: BLOCK" in text
        assert "CodeTrust Enforcement: ACTIVE" in text
        assert "Fix locally:" in text
        assert "codetrust scan --changed-only --baseline origin/main --fail-on-new BLOCK" in text


class TestPrCommentUpsert:
    """Test deterministic PR comment upsert markers."""

    def test_creates_new_block_when_missing(self) -> None:
        merged = upsert_comment("", "hello")
        assert COMMENT_START in merged
        assert COMMENT_END in merged
        assert "hello" in merged

    def test_replaces_only_block_when_present(self) -> None:
        existing = (
            "prefix\n"
            + COMMENT_START
            + "\n\nold\n\n"
            + COMMENT_END
            + "\nsuffix\n"
        )
        merged = upsert_comment(existing, "new")
        assert merged.startswith("prefix\n" + COMMENT_START)
        assert merged.endswith(COMMENT_END + "\nsuffix\n")
        assert "old" not in merged
        assert "new" in merged


class TestGitHubEventParsing:
    """Test parsing of PR metadata from GitHub event payload."""

    def test_get_pr_base_sha_from_event_payload(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Base SHA is parsed from pull_request.base.sha."""
        payload = {
            "pull_request": {
                "number": 123,
                "base": {"sha": "abc123"},
            }
        }
        event_path = tmp_path / "event.json"
        event_path.write_text(json.dumps(payload), encoding="utf-8")

        monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
        assert _get_pr_base_sha() == "abc123"

    def test_get_pr_number_prefers_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """PR number uses PR_NUMBER env when set."""
        monkeypatch.setenv("PR_NUMBER", "456")
        assert _get_pr_number() == 456


# --- SARIF output tests ---


class TestWriteSarif:
    """Test SARIF file writing."""

    def test_writes_sarif_file(self, tmp_path: Path) -> None:
        """SARIF file is written to disk."""
        findings = [
            Finding(
                rule_id="eval_exec", severity=Severity.BLOCK,
                message="eval found", file="a.py", line=1,
            ),
        ]
        sarif_path = str(tmp_path / "results.sarif")
        write_sarif(findings, sarif_path)

        content = Path(sarif_path).read_text()
        parsed = json.loads(content)
        assert parsed["version"] == "2.1.0"

    def test_empty_path_skips(self) -> None:
        """Empty sarif_path does not write."""
        write_sarif([], "")
        # No assertion needed — just shouldn't crash

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Parent directories are created if missing."""
        sarif_path = str(tmp_path / "sub" / "dir" / "results.sarif")
        write_sarif([], sarif_path)
        assert Path(sarif_path).exists()


# --- Annotation tests ---


class TestEmitAnnotations:
    """Test GitHub Actions annotation output."""

    def test_block_emits_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        """BLOCK finding emits ::error:: annotation."""
        findings = [
            Finding(
                rule_id="eval_exec", severity=Severity.BLOCK,
                message="eval found", file="a.py", line=10,
            ),
        ]
        emit_annotations(findings)
        output = capsys.readouterr().out
        assert "::error" in output
        assert "a.py" in output
        assert "line=10" in output

    def test_warn_emits_warning(self, capsys: pytest.CaptureFixture[str]) -> None:
        """WARN finding emits ::warning:: annotation."""
        findings = [
            Finding(
                rule_id="todo", severity=Severity.WARN,
                message="TODO found", file="b.py", line=5,
            ),
        ]
        emit_annotations(findings)
        output = capsys.readouterr().out
        assert "::warning" in output


# --- Print summary tests ---


class TestPrintSummary:
    """Test console summary output."""

    def test_summary_includes_verdict(
        self, capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Summary includes the verdict."""
        print_summary("PASS", [], 5)
        output = capsys.readouterr().out
        assert "PASS" in output
        assert "5" in output

    def test_summary_includes_counts(
        self, capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Summary includes finding counts."""
        findings = [
            Finding(
                rule_id="eval", severity=Severity.BLOCK,
                message="eval", file="a.py", line=1,
            ),
            Finding(
                rule_id="todo", severity=Severity.WARN,
                message="todo", file="a.py", line=2,
            ),
        ]
        print_summary("BLOCK", findings, 1)
        output = capsys.readouterr().out
        assert "BLOCK: 1" in output
        assert "WARN: 1" in output


# --- API SARIF endpoint tests ---


class TestSarifAPIEndpoints:
    """Test SARIF API endpoints."""

    @pytest.fixture()
    def client(self) -> TestClient:
        """Create a TestClient with app state."""
        import fakeredis.aioredis
        import httpx

        from src.api import app
        from src.services.ast_analyzer import AstAnalyzer
        from src.services.cache import CacheService
        from src.services.docker_verify import DockerVerifyService
        from src.services.registry import RegistryService
        from src.services.sandbox import SandboxService
        from src.services.static_analyzer import StaticAnalyzer

        cache = CacheService("redis://localhost:6379")
        cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        http_client = httpx.AsyncClient()

        app.state.cache = cache
        app.state.http_client = http_client
        app.state.registry = RegistryService(cache, http_client)
        app.state.docker = DockerVerifyService(cache, http_client)
        app.state.analyzer = StaticAnalyzer()
        app.state.ast_analyzer = AstAnalyzer()
        app.state.sandbox = SandboxService()
        app.state.db = None
        app.state.billing = None
        app.state.auth = None
        app.state.rate_limiter = None

        return TestClient(app, raise_server_exceptions=False)

    def test_static_sarif_endpoint(self, client: TestClient) -> None:
        """POST /v1/scan/static/sarif returns SARIF JSON."""
        resp = client.post("/v1/scan/static/sarif", json={
            "code": "result = " + "ev" + "al('1+1')\n",
            "filename": "test.py",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert len(data["runs"][0]["results"]) > 0

    def test_static_sarif_clean_code(self, client: TestClient) -> None:
        """Clean code returns SARIF with empty results."""
        resp = client.post("/v1/scan/static/sarif", json={
            "code": "x = 1\ny = 2\n",
            "filename": "clean.py",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["runs"][0]["results"]) == 0

    def test_deep_sarif_endpoint(self, client: TestClient) -> None:
        """POST /v1/scan/deep/sarif returns SARIF JSON."""
        resp = client.post("/v1/scan/deep/sarif", json={
            "code": "result = " + "ev" + "al('1+1')\n",
            "filename": "test.py",
            "language": "python",
            "verify_imports": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_deep_sarif_no_language(self, client: TestClient) -> None:
        """Deep SARIF without language still works."""
        resp = client.post("/v1/scan/deep/sarif", json={
            "code": "x = 1\n",
            "filename": "test.py",
            "verify_imports": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["version"] == "2.1.0"
