"""Tests for Commit Policy Engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.services.commit_policy import (
    CommitPolicyEngine,
    FileAttribution,
    PolicyViolation,
    load_policy_config,
)


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    """Create a workspace with no policy file."""
    return tmp_path


def _write_policy(workspace: Path, policy_toml: str) -> None:
    """Write a .codetrust.toml policy file."""
    (workspace / ".codetrust.toml").write_text(policy_toml)


class TestLoadPolicyConfig:
    """Tests for policy config loading."""

    def test_no_config_file(self, workspace: Path) -> None:
        """Missing config returns permissive defaults."""
        config = load_policy_config(workspace)
        assert config.model_mode == "none"
        assert config.allow_ai_generated is True
        assert config.max_ai_ratio == 1.0

    def test_valid_config(self, workspace: Path) -> None:
        """Valid TOML config is parsed correctly."""
        _write_policy(workspace, """
[policy]
contact = "security@corp.com"

[policy.models]
mode = "allowlist"
allowed = ["claude-sonnet-4"]

[policy.editors]
mode = "blocklist"
blocked = ["github.copilot"]

[policy.ai_commits]
allow_ai_generated = true
max_ai_ratio = 0.5
""")
        config = load_policy_config(workspace)
        assert config.model_mode == "allowlist"
        assert "claude-sonnet-4" in config.models_allowed
        assert config.editor_mode == "blocklist"
        assert "github.copilot" in config.editors_blocked
        assert config.max_ai_ratio == 0.5
        assert config.contact == "security@corp.com"

    def test_invalid_toml(self, workspace: Path) -> None:
        """Invalid TOML returns defaults."""
        (workspace / ".codetrust.toml").write_text("not valid toml [[[")
        config = load_policy_config(workspace)
        assert config.model_mode == "none"

    def test_invalid_mode(self, workspace: Path) -> None:
        """Invalid mode falls back to 'none'."""
        _write_policy(workspace, """
[policy.models]
mode = "invalid_mode"
""")
        config = load_policy_config(workspace)
        assert config.model_mode == "none"


class TestModelPolicy:
    """Tests for model allowlist/blocklist enforcement."""

    def test_allowlist_blocks_unknown_model(self, workspace: Path) -> None:
        """Model not in allowlist is blocked."""
        _write_policy(workspace, """
[policy.models]
mode = "allowlist"
allowed = ["claude-sonnet-4"]
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", model="gpt-4o", ai_probability=0.9),
        ])
        assert len(violations) == 1
        assert violations[0].rule == "blocked_model"
        assert violations[0].severity == "BLOCK"

    def test_allowlist_allows_matching_model(self, workspace: Path) -> None:
        """Model matching allowlist prefix is allowed."""
        _write_policy(workspace, """
[policy.models]
mode = "allowlist"
allowed = ["claude-sonnet-4"]
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(
                file="test.py", model="claude-sonnet-4-20250514",
                ai_probability=0.9,
            ),
        ])
        model_violations = [v for v in violations if v.rule == "blocked_model"]
        assert len(model_violations) == 0

    def test_blocklist_blocks_listed_model(self, workspace: Path) -> None:
        """Model in blocklist is blocked."""
        _write_policy(workspace, """
[policy.models]
mode = "blocklist"
blocked = ["gpt-3.5-turbo"]
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", model="gpt-3.5-turbo", ai_probability=0.9),
        ])
        assert any(v.rule == "blocked_model" for v in violations)

    def test_audit_mode_warns_not_blocks(self, workspace: Path) -> None:
        """Audit mode produces WARN instead of BLOCK."""
        _write_policy(workspace, """
[policy.models]
mode = "audit"
blocked = ["gpt-4o"]
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", model="gpt-4o", ai_probability=0.9),
        ])
        assert all(v.severity == "WARN" for v in violations)

    def test_no_restrictions(self, workspace: Path) -> None:
        """No policy file = no violations."""
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", model="gpt-4o", ai_probability=0.9),
        ])
        assert len(violations) == 0


class TestEditorPolicy:
    """Tests for editor allowlist/blocklist."""

    def test_blocklist_blocks_editor(self, workspace: Path) -> None:
        """Editor in blocklist is blocked."""
        _write_policy(workspace, """
[policy.editors]
mode = "blocklist"
blocked = ["github.copilot"]
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", editor="github.copilot", ai_probability=0.9),
        ])
        assert any(v.rule == "blocked_editor" for v in violations)

    def test_allowlist_allows_known_editor(self, workspace: Path) -> None:
        """Editor in allowlist passes."""
        _write_policy(workspace, """
[policy.editors]
mode = "allowlist"
allowed = ["saoudrizwan.claude-dev"]
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(
                file="test.py", editor="saoudrizwan.claude-dev",
                ai_probability=0.9,
            ),
        ])
        editor_violations = [v for v in violations if v.rule == "blocked_editor"]
        assert len(editor_violations) == 0


class TestAICommitControls:
    """Tests for AI commit-level controls."""

    def test_ai_not_allowed(self, workspace: Path) -> None:
        """AI commits blocked when allow_ai_generated=false."""
        _write_policy(workspace, """
[policy.ai_commits]
allow_ai_generated = false
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", model="gpt-4o", ai_probability=0.9),
        ])
        assert any(v.rule == "ai_not_allowed" for v in violations)

    def test_ai_ratio_exceeded(self, workspace: Path) -> None:
        """AI ratio above max_ai_ratio is blocked."""
        _write_policy(workspace, """
[policy.ai_commits]
max_ai_ratio = 0.5
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="a.py", model="gpt-4o", ai_probability=0.9),
            FileAttribution(file="b.py", model="claude-sonnet-4", ai_probability=0.9),
            FileAttribution(file="c.py"),  # human
        ])
        ratio_violations = [v for v in violations if v.rule == "ai_ratio_exceeded"]
        assert len(ratio_violations) == 1

    def test_ai_ratio_within_limit(self, workspace: Path) -> None:
        """AI ratio within limit passes."""
        _write_policy(workspace, """
[policy.ai_commits]
max_ai_ratio = 0.5
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="a.py", model="claude", ai_probability=0.9),
            FileAttribution(file="b.py"),
            FileAttribution(file="c.py"),
        ])
        ratio_violations = [v for v in violations if v.rule == "ai_ratio_exceeded"]
        assert len(ratio_violations) == 0

    def test_require_human_review(self, workspace: Path) -> None:
        """Human review requirement produces WARN."""
        _write_policy(workspace, """
[policy.ai_commits]
require_human_review = true
""")
        engine = CommitPolicyEngine(workspace)
        violations = engine.evaluate([
            FileAttribution(file="test.py", model="gpt-4o", ai_probability=0.9),
        ])
        review_violations = [v for v in violations if v.rule == "ai_requires_review"]
        assert len(review_violations) == 1
        assert review_violations[0].severity == "WARN"


class TestBuildReport:
    """Tests for report building."""

    def test_no_violations(self, workspace: Path) -> None:
        """No violations produce PASS report."""
        engine = CommitPolicyEngine(workspace)
        report = engine.build_report([])
        assert "PASS" in report

    def test_violations_in_report(self, workspace: Path) -> None:
        """Violations appear in report."""
        engine = CommitPolicyEngine(workspace)
        violations = [
            PolicyViolation(
                rule="blocked_model", severity="BLOCK",
                file="test.py", message="Model gpt-4o not allowed",
            ),
        ]
        report = engine.build_report(violations)
        assert "REJECTED" in report
        assert "gpt-4o" in report

    def test_has_blocks(self, workspace: Path) -> None:
        """has_blocks helper works."""
        engine = CommitPolicyEngine(workspace)
        assert engine.has_blocks([
            PolicyViolation(rule="x", severity="BLOCK", file="f", message="m"),
        ])
        assert not engine.has_blocks([
            PolicyViolation(rule="x", severity="WARN", file="f", message="m"),
        ])
