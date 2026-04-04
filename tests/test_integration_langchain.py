# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for LangChain integration — all mocked, no langchain dependency."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.integrations.langchain import CodeTrustGovernance, GovernedChain


class TestOnToolStart:
    """Test tool validation before execution."""

    def test_safe_command_allowed(self) -> None:
        """Safe tool input should be allowed."""
        gov = CodeTrustGovernance()
        result = gov.on_tool_start("file_read", "cat README.md")
        assert result["verdict"] == "ALLOW"

    def test_dangerous_command_blocked(self) -> None:
        """Dangerous tool input should be blocked."""
        gov = CodeTrustGovernance(block_on_violation=True)
        with pytest.raises(PermissionError, match="BLOCKED"):
            gov.on_tool_start("terminal", "rm -rf /")

    def test_dangerous_command_logged_not_blocked(self) -> None:
        """With block_on_violation=False, dangerous commands are logged but not blocked."""
        gov = CodeTrustGovernance(block_on_violation=False)
        result = gov.on_tool_start("terminal", "rm -rf /")
        assert result["verdict"] == "BLOCK"
        assert gov.log.blocked_count == 1

    def test_git_push_blocked(self) -> None:
        """git push should be blocked by governance."""
        gov = CodeTrustGovernance()
        with pytest.raises(PermissionError, match="BLOCKED"):
            gov.on_tool_start("git", "git push origin main")

    def test_events_logged(self) -> None:
        """Tool start events should be logged."""
        gov = CodeTrustGovernance()
        gov.on_tool_start("search", "grep -r pattern .")
        assert len(gov.log.events) == 1
        assert gov.log.events[0].event_type == "tool_start"
        assert gov.log.events[0].tool_name == "search"


class TestOnToolEnd:
    """Test output scanning after tool execution."""

    def test_clean_output_no_findings(self) -> None:
        """Clean output should produce no findings."""
        gov = CodeTrustGovernance(scan_outputs=True)
        findings = gov.on_tool_end("search", "line 1: hello world")
        # Simple text unlikely to trigger anti-patterns
        assert isinstance(findings, list)

    def test_scan_disabled_returns_empty(self) -> None:
        """When scan_outputs=False, should return empty list."""
        gov = CodeTrustGovernance(scan_outputs=False)
        findings = gov.on_tool_end("search", "eval(user_input)")
        assert findings == []

    def test_empty_output_returns_empty(self) -> None:
        """Empty output should return empty list."""
        gov = CodeTrustGovernance(scan_outputs=True)
        findings = gov.on_tool_end("search", "")
        assert findings == []

    def test_session_history_accumulates(self) -> None:
        """Tool outputs should be added to session history."""
        gov = CodeTrustGovernance()
        gov.on_tool_end("tool1", "output1")
        gov.on_tool_end("tool2", "output2")
        assert len(gov._session_history) == 2


class TestOnLlmStart:
    """Test model attribution logging."""

    def test_model_attribution_logged(self) -> None:
        """LLM start should log provider and model."""
        gov = CodeTrustGovernance()
        gov.on_llm_start("openai", "gpt-4o")
        assert "openai/gpt-4o" in gov.log.models_seen
        assert gov.log.events[-1].event_type == "llm_start"
        assert gov.log.events[-1].provider == "openai"
        assert gov.log.events[-1].model == "gpt-4o"

    def test_multiple_models_tracked(self) -> None:
        """Multiple different models should all be tracked."""
        gov = CodeTrustGovernance()
        gov.on_llm_start("openai", "gpt-4o")
        gov.on_llm_start("anthropic", "claude-sonnet-4-20250514")
        assert len(gov.log.models_seen) == 2


class TestOnLlmEnd:
    """Test completion hallucination detection on LLM output."""

    def test_hallucination_detection_runs(self) -> None:
        """LLM end should run hallucination detection."""
        gov = CodeTrustGovernance(detect_hallucination=True)
        # This text contains a completion claim without evidence
        results = gov.on_llm_end("All tests pass. Everything is fully functional.")
        assert isinstance(results, list)

    def test_hallucination_disabled_returns_empty(self) -> None:
        """When detect_hallucination=False, should return empty."""
        gov = CodeTrustGovernance(detect_hallucination=False)
        results = gov.on_llm_end("All tests pass.")
        assert results == []


class TestOnChainError:
    """Test error logging."""

    def test_error_logged(self) -> None:
        """Chain errors should be logged."""
        gov = CodeTrustGovernance()
        gov.on_chain_error(RuntimeError("Connection failed"))
        assert len(gov.log.events) == 1
        assert gov.log.events[0].event_type == "chain_error"
        assert "Connection failed" in gov.log.events[0].message


class TestWrap:
    """Test chain wrapping."""

    def test_wrap_returns_governed_chain(self) -> None:
        """wrap() should return a GovernedChain."""
        gov = CodeTrustGovernance()
        mock_chain = MagicMock()
        wrapped = gov.wrap(mock_chain)
        assert isinstance(wrapped, GovernedChain)
        assert wrapped.governance is gov

    def test_governed_chain_proxies_attributes(self) -> None:
        """GovernedChain should proxy attribute access to underlying chain."""
        gov = CodeTrustGovernance()
        mock_chain = MagicMock()
        mock_chain.some_attr = "test_value"
        wrapped = gov.wrap(mock_chain)
        assert wrapped.some_attr == "test_value"


class TestGetReport:
    """Test governance report generation."""

    def test_report_structure(self) -> None:
        """Report should have expected fields."""
        gov = CodeTrustGovernance()
        gov.on_tool_start("search", "grep pattern .")
        gov.on_llm_start("openai", "gpt-4o")
        report = gov.get_report()
        assert "events" in report
        assert "blocked_count" in report
        assert "scanned_outputs" in report
        assert "models_seen" in report
        assert report["blocked_count"] == 0
        assert "openai/gpt-4o" in report["models_seen"]
