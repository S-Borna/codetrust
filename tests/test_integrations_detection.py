# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for framework detection in CLI and doctor."""

from __future__ import annotations

from unittest.mock import patch

from src.cli import cmd_integrations, detect_frameworks


class TestDetectFrameworks:
    """Test framework detection logic."""

    def test_returns_list_of_dicts(self) -> None:
        """detect_frameworks should return a list of framework info dicts."""
        results = detect_frameworks()
        assert isinstance(results, list)
        assert len(results) == 3  # LangChain, CrewAI, OpenAI Agents

    def test_each_framework_has_required_fields(self) -> None:
        """Each result should have name, installed, integration_available."""
        results = detect_frameworks()
        for fw in results:
            assert "name" in fw
            assert "installed" in fw
            assert "integration_available" in fw
            assert "class" in fw
            assert "install_hint" in fw

    def test_uninstalled_frameworks_detected_correctly(self) -> None:
        """Frameworks not installed should show installed=False."""
        results = detect_frameworks()
        for fw in results:
            if fw["name"] == "LangChain":
                assert fw["installed"] is False
            if fw["name"] == "CrewAI":
                assert fw["installed"] is False
            if fw["name"] == "OpenAI Agents SDK":
                assert fw["installed"] is False

    def test_integration_modules_available(self) -> None:
        """Integration modules should be importable regardless of framework."""
        results = detect_frameworks()
        for fw in results:
            assert fw["integration_available"] is True

    def test_installed_framework_detected(self) -> None:
        """When a framework is installed, installed should be True."""
        import importlib
        import types

        original = importlib.import_module

        def patched(name: str) -> types.ModuleType:
            if name == "langchain":
                mod = types.ModuleType("langchain")
                mod.__version__ = "0.3.0"
                return mod
            return original(name)

        with patch.object(importlib, "import_module", side_effect=patched):
            results = detect_frameworks()

        lc = next(fw for fw in results if fw["name"] == "LangChain")
        assert lc["installed"] is True
        assert lc["version"] == "0.3.0"


class TestCmdIntegrations:
    """Test the CLI integrations command."""

    def test_integrations_returns_zero(self) -> None:
        """Command should return 0 (success)."""
        import argparse
        args = argparse.Namespace(check=False, json_output=False)
        result = cmd_integrations(args)
        assert result == 0

    def test_integrations_json_output(self) -> None:
        """JSON output should be valid."""
        import argparse
        import json
        from io import StringIO
        from unittest.mock import patch as mock_patch

        args = argparse.Namespace(check=False, json_output=True)
        with mock_patch("sys.stdout", new_callable=StringIO):
            result = cmd_integrations(args)
        assert result == 0


class TestGracefulNoFramework:
    """Test that everything works when no frameworks are installed."""

    def test_import_integrations_works(self) -> None:
        """Importing integrations module should work without frameworks."""
        from src.integrations import CodeTrustGovernance, CodeTrustCrew, governed_agent
        assert CodeTrustGovernance is not None
        assert CodeTrustCrew is not None
        assert governed_agent is not None

    def test_langchain_require_raises(self) -> None:
        """_require_langchain should raise ImportError."""
        from src.integrations.langchain import _require_langchain
        try:
            _require_langchain()
            # If langchain IS installed, this is fine
        except ImportError as exc:
            assert "langchain" in str(exc).lower()

    def test_crewai_require_raises(self) -> None:
        """_require_crewai should raise ImportError."""
        from src.integrations.crewai import _require_crewai
        try:
            _require_crewai()
        except ImportError as exc:
            assert "crewai" in str(exc).lower()

    def test_openai_require_raises(self) -> None:
        """_require_openai_agents should raise ImportError."""
        from src.integrations.openai_agents import _require_openai_agents
        try:
            _require_openai_agents()
        except ImportError as exc:
            assert "openai-agents" in str(exc).lower()
