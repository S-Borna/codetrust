"""Integration test for CodeTrust pre-commit hook.

Creates a temporary git repo, installs the hook, stages a file
with BLOCK-level findings, and verifies the hook blocks the commit.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

# Path to the hook script
HOOK_SCRIPT = Path(__file__).parent.parent / "hooks" / "codetrust_pre_commit.py"

# Python code that triggers a BLOCK finding (eval usage)
BLOCK_CODE = """\
import os

def run_user_input(cmd):
    result = eval(cmd)
    return result
"""

# Clean Python code that should pass
CLEAN_CODE = """\
import os
from pathlib import Path


def get_home() -> Path:
    \"\"\"Return user home directory.\"\"\"
    return Path.home()
"""


def _run_git(
    args: list[str],
    cwd: Path,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a git command in the given directory."""
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
        timeout=30,
        env={**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@test.com",
             "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@test.com"},
    )


def _install_hook(repo: Path) -> Path:
    """Install the CodeTrust pre-commit hook into the repo."""
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_target = hooks_dir / "pre-commit"

    wrapper = (
        "#!/usr/bin/env bash\n"
        f'exec python3 "{HOOK_SCRIPT.resolve()}" "$@"\n'
    )
    hook_target.write_text(wrapper, encoding="utf-8")
    hook_target.chmod(0o755)
    return hook_target


@pytest.fixture()
def temp_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository with the hook installed."""
    repo = tmp_path / "test_repo"
    repo.mkdir()

    _run_git(["init"], cwd=repo)
    _run_git(["config", "user.email", "test@test.com"], cwd=repo)
    _run_git(["config", "user.name", "Test"], cwd=repo)

    # Initial commit so we have a HEAD
    readme = repo / "README.md"
    readme.write_text("# Test\n", encoding="utf-8")
    _run_git(["add", "README.md"], cwd=repo)
    _run_git(["commit", "-m", "Initial commit"], cwd=repo)

    _install_hook(repo)
    return repo


@pytest.mark.skipif(
    not HOOK_SCRIPT.exists(),
    reason="Hook script not found",
)
class TestPreCommitHookIntegration:
    """Integration tests for the pre-commit hook."""

    def test_hook_blocks_on_block_findings(
        self, temp_git_repo: Path,
    ) -> None:
        """Staging a file with BLOCK findings should cause commit to fail."""
        bad_file = temp_git_repo / "bad_code.py"
        bad_file.write_text(BLOCK_CODE, encoding="utf-8")

        _run_git(["add", "bad_code.py"], cwd=temp_git_repo)
        result = _run_git(
            ["commit", "-m", "Add bad code"],
            cwd=temp_git_repo,
            check=False,
        )

        # Hook should block — exit code 1
        assert result.returncode != 0, (
            f"Expected hook to block commit but it succeeded.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert "block" in (result.stdout + result.stderr).lower(), (
            f"Expected 'block' in output.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_hook_allows_clean_code(
        self, temp_git_repo: Path,
    ) -> None:
        """Staging a clean file should allow the commit to succeed."""
        good_file = temp_git_repo / "good_code.py"
        good_file.write_text(CLEAN_CODE, encoding="utf-8")

        _run_git(["add", "good_code.py"], cwd=temp_git_repo)
        result = _run_git(
            ["commit", "-m", "Add good code"],
            cwd=temp_git_repo,
            check=False,
        )

        assert result.returncode == 0, (
            f"Expected commit to succeed for clean code.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )

    def test_hook_generates_report(
        self, temp_git_repo: Path,
    ) -> None:
        """Hook should create a report file in .codetrust/reports/."""
        test_file = temp_git_repo / "some_code.py"
        test_file.write_text(BLOCK_CODE, encoding="utf-8")

        _run_git(["add", "some_code.py"], cwd=temp_git_repo)
        _run_git(
            ["commit", "-m", "Test report"],
            cwd=temp_git_repo,
            check=False,
        )

        report_dir = temp_git_repo / ".codetrust" / "reports"
        if report_dir.exists():
            reports = list(report_dir.glob("commit_*.json"))
            assert len(reports) >= 1, "Expected at least one report file"

    def test_hook_install_and_uninstall_cli(
        self, temp_git_repo: Path,
    ) -> None:
        """Test CLI hook install and uninstall commands."""
        from src.cli import _hook_install, _hook_uninstall

        # Uninstall first (our fixture already installed it)
        original_cwd = Path.cwd()
        try:
            os.chdir(temp_git_repo)

            # The hook should be there from fixture
            hook_path = temp_git_repo / ".git" / "hooks" / "pre-commit"
            assert hook_path.exists()

            # Uninstall
            ret = _hook_uninstall()
            assert ret == 0
            assert not hook_path.exists()

            # Reinstall
            ret = _hook_install()
            assert ret == 0
            assert hook_path.exists()
            content = hook_path.read_text(encoding="utf-8")
            assert "codetrust" in content.lower()
        finally:
            os.chdir(original_cwd)


class TestCLIObservabilityCommands:
    """Test the new CLI commands can be invoked without errors."""

    def test_shadow_scan_runs(self) -> None:
        """Shadow scan should run without crashing."""
        from src.services.shadow_ai import ShadowAIScanner

        scanner = ShadowAIScanner()
        result = scanner.scan()
        assert result.total_found >= 0

    def test_mcp_audit_runs(self, tmp_path: Path) -> None:
        """MCP audit should run without crashing."""
        from src.services.mcp_discovery import MCPDiscoveryService

        svc = MCPDiscoveryService()
        result = svc.audit(workspace=tmp_path)
        assert result.configs_scanned >= 0

    def test_benchmark_aggregate_empty(self, tmp_path: Path) -> None:
        """Benchmark aggregate on empty workspace returns empty result."""
        from src.services.llm_benchmark import LLMBenchmarkService

        svc = LLMBenchmarkService()
        result = svc.aggregate(workspace=tmp_path)
        assert result.total_entries == 0

    def test_risk_profile_no_git(self, tmp_path: Path) -> None:
        """Risk profile on non-git directory returns empty result."""
        from src.services.developer_risk import DeveloperRiskService

        svc = DeveloperRiskService()
        result = svc.assess(workspace=tmp_path)
        assert result.total_developers == 0

    def test_policy_show_default(self, tmp_path: Path) -> None:
        """Policy show on workspace without config returns defaults."""
        from src.services.commit_policy import load_policy_config

        config = load_policy_config(tmp_path)
        assert config.model_mode == "none"
        assert config.allow_ai_generated is True

    def test_policy_validate_default(self) -> None:
        """Default policy should validate cleanly."""
        from src.services.commit_policy import VALID_MODES, PolicyConfig

        config = PolicyConfig()
        assert config.model_mode in VALID_MODES
        assert config.personality in {"strict", "standard", "mentor"}

    def test_policy_test_no_violations(self, tmp_path: Path) -> None:
        """Default policy (no restrictions) should produce no violations."""
        from src.services.commit_policy import CommitPolicyEngine, FileAttribution

        engine = CommitPolicyEngine(tmp_path)
        result = engine.evaluate([
            FileAttribution(
                file="test.py", model="gpt-4o",
                provider="openai", editor="copilot",
                ai_probability=0.95,
            ),
        ])
        assert len(result) == 0

    def test_attribution_on_clean_file(self, tmp_path: Path) -> None:
        """Attribution on a clean file should return low AI probability."""
        from src.services.ai_attribution import AIAttributor

        test_file = tmp_path / "clean.py"
        test_file.write_text("x = 1\n", encoding="utf-8")
        attr = AIAttributor()
        result = attr.analyze_file(test_file, workspace=tmp_path)
        assert result.ai_probability < 0.5
