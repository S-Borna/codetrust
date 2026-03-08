# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the Agent Optimizer CLI command (codetrust setup)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from src.cli import (
    _setup_install_agent_claude,
    _setup_install_cursorrules,
    _setup_install_session_log,
    _setup_install_vscode_settings,
    cmd_setup,
)


class TestSetupInstallAgentClaude:
    """Tests for _setup_install_agent_claude."""

    def test_creates_claude_md(self, tmp_path: Path) -> None:
        """Should create CLAUDE.md in project directory."""
        result = _setup_install_agent_claude(tmp_path, force=False)
        assert result is True
        assert (tmp_path / "CLAUDE.md").exists()

    def test_content_has_codetrust_header(self, tmp_path: Path) -> None:
        """Generated CLAUDE.md should reference CodeTrust."""
        _setup_install_agent_claude(tmp_path, force=False)
        content = (tmp_path / "CLAUDE.md").read_text()
        assert "CodeTrust" in content
        assert "Agent Operating System" in content

    def test_skips_existing_without_force(self, tmp_path: Path) -> None:
        """Should not overwrite existing CLAUDE.md without --force."""
        (tmp_path / "CLAUDE.md").write_text("existing content")
        result = _setup_install_agent_claude(tmp_path, force=False)
        assert result is False
        assert (tmp_path / "CLAUDE.md").read_text() == "existing content"

    def test_overwrites_with_force(self, tmp_path: Path) -> None:
        """Should overwrite existing CLAUDE.md with --force."""
        (tmp_path / "CLAUDE.md").write_text("old content")
        result = _setup_install_agent_claude(tmp_path, force=True)
        assert result is True
        content = (tmp_path / "CLAUDE.md").read_text()
        assert "CodeTrust" in content
        assert content != "old content"

    def test_creates_backup_when_force(self, tmp_path: Path) -> None:
        """Should create .md.bak when overwriting with --force."""
        (tmp_path / "CLAUDE.md").write_text("backup me")
        _setup_install_agent_claude(tmp_path, force=True)
        assert (tmp_path / "CLAUDE.md.bak").exists()
        assert (tmp_path / "CLAUDE.md.bak").read_text() == "backup me"


class TestSetupInstallSessionLog:
    """Tests for _setup_install_session_log."""

    def test_creates_session_log(self, tmp_path: Path) -> None:
        """Should create SESSION_LOG.md."""
        result = _setup_install_session_log(tmp_path)
        assert result is True
        assert (tmp_path / "SESSION_LOG.md").exists()

    def test_content_has_project_name(self, tmp_path: Path) -> None:
        """Should replace [PROJECT_NAME] with directory name."""
        _setup_install_session_log(tmp_path)
        content = (tmp_path / "SESSION_LOG.md").read_text()
        assert tmp_path.name in content

    def test_preserves_existing(self, tmp_path: Path) -> None:
        """Should not overwrite existing SESSION_LOG.md."""
        (tmp_path / "SESSION_LOG.md").write_text("existing sessions")
        result = _setup_install_session_log(tmp_path)
        assert result is False
        assert (tmp_path / "SESSION_LOG.md").read_text() == "existing sessions"


class TestSetupInstallVscodeSettings:
    """Tests for _setup_install_vscode_settings."""

    def test_creates_vscode_dir_and_settings(self, tmp_path: Path) -> None:
        """Should create .vscode/settings.json."""
        result = _setup_install_vscode_settings(tmp_path, force=False)
        assert result is True
        settings_path = tmp_path / ".vscode" / "settings.json"
        assert settings_path.exists()
        settings = json.loads(settings_path.read_text())
        assert settings["github.copilot.chat.useInstructionFiles"] is True

    def test_merges_into_existing(self, tmp_path: Path) -> None:
        """Should merge agent settings into existing settings."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        settings_path = vscode_dir / "settings.json"
        settings_path.write_text(json.dumps({"editor.fontSize": 14}))

        result = _setup_install_vscode_settings(tmp_path, force=False)
        assert result is True
        settings = json.loads(settings_path.read_text())
        assert settings["editor.fontSize"] == 14
        assert settings["github.copilot.chat.useInstructionFiles"] is True

    def test_skips_if_already_configured(self, tmp_path: Path) -> None:
        """Should skip if agent settings already present."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        settings_path = vscode_dir / "settings.json"
        settings_path.write_text(json.dumps({
            "github.copilot.chat.useInstructionFiles": True,
            "chat.agent.instructions": [],
        }))

        result = _setup_install_vscode_settings(tmp_path, force=False)
        assert result is False

    def test_force_overwrites(self, tmp_path: Path) -> None:
        """Should overwrite with --force."""
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        (vscode_dir / "settings.json").write_text('{"old": true}')

        result = _setup_install_vscode_settings(tmp_path, force=True)
        assert result is True


class TestSetupInstallCursorrules:
    """Tests for _setup_install_cursorrules."""

    def test_creates_cursorrules(self, tmp_path: Path) -> None:
        """Should create .cursorrules file."""
        result = _setup_install_cursorrules(tmp_path, force=False)
        assert result is True
        assert (tmp_path / ".cursorrules").exists()

    def test_skips_existing(self, tmp_path: Path) -> None:
        """Should not overwrite existing .cursorrules."""
        (tmp_path / ".cursorrules").write_text("existing rules")
        result = _setup_install_cursorrules(tmp_path, force=False)
        assert result is False


class TestCmdSetup:
    """Tests for the full cmd_setup command."""

    def test_returns_zero(self, tmp_path: Path) -> None:
        """Setup command should return 0 (success)."""
        import argparse
        args = argparse.Namespace(force=False)
        with patch("src.cli.Path.cwd", return_value=tmp_path):
            result = cmd_setup(args)
        assert result == 0

    def test_creates_all_files(self, tmp_path: Path) -> None:
        """Setup should create all expected files."""
        import argparse
        args = argparse.Namespace(force=False)
        with patch("src.cli.Path.cwd", return_value=tmp_path):
            cmd_setup(args)

        assert (tmp_path / "CLAUDE.md").exists()
        assert (tmp_path / "SESSION_LOG.md").exists()
        assert (tmp_path / ".vscode" / "settings.json").exists()
        assert (tmp_path / ".cursorrules").exists()
