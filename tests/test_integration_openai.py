# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for OpenAI Agents SDK integration — all mocked, no openai-agents dependency."""

from __future__ import annotations

import pytest

from src.integrations.openai_agents import GovernedAgent, governed_agent


class TestGovernedAgent:
    """Test governed agent creation and tool wrapping."""

    def test_governed_agent_created(self) -> None:
        """governed_agent() should return a GovernedAgent."""
        def my_tool(query: str) -> str:
            return f"result: {query}"

        agent = governed_agent(
            name="researcher",
            model="gpt-4o",
            tools=[my_tool],
        )
        assert isinstance(agent, GovernedAgent)
        assert agent.name == "researcher"
        assert agent.model == "gpt-4o"

    def test_tools_are_wrapped(self) -> None:
        """Original tools should be wrapped with governance."""
        def my_tool(query: str) -> str:
            return f"result: {query}"

        agent = governed_agent(name="test", tools=[my_tool])
        assert len(agent.governed_tools) == 1
        assert agent.governed_tools[0] is not my_tool  # wrapped

    def test_safe_tool_input_passes(self) -> None:
        """Safe tool input should pass through."""
        def search(query: str) -> str:
            return f"found: {query}"

        agent = governed_agent(name="researcher", tools=[search])
        result = agent.governed_tools[0]("python best practices")
        assert "found: python best practices" in result

    def test_dangerous_tool_input_blocked(self) -> None:
        """Dangerous tool input should be blocked."""
        def run_cmd(cmd: str) -> str:
            return cmd

        agent = governed_agent(name="researcher", tools=[run_cmd])
        with pytest.raises(PermissionError, match="BLOCKED"):
            agent.governed_tools[0]("rm -rf /")

    def test_git_push_blocked(self) -> None:
        """git push via tool should be blocked."""
        def shell(cmd: str) -> str:
            return "done"

        agent = governed_agent(name="deployer", tools=[shell])
        with pytest.raises(PermissionError, match="BLOCKED"):
            agent.governed_tools[0]("git push origin main")


class TestAttributionLogging:
    """Test that attribution is logged correctly."""

    def test_model_attribution_stored(self) -> None:
        """Agent model should be stored in governance log."""
        agent = governed_agent(name="researcher", model="gpt-4o", tools=[])
        assert agent.log.model == "gpt-4o"
        assert agent.log.agent_name == "researcher"

    def test_tool_events_logged(self) -> None:
        """Tool calls should produce governance events."""
        def search(q: str) -> str:
            return "found"

        agent = governed_agent(name="researcher", tools=[search])
        agent.governed_tools[0]("safe query")
        assert len(agent.log.events) == 1
        assert agent.log.events[0].agent_name == "researcher"
        assert agent.log.events[0].event_type == "tool_call"

    def test_blocked_count_incremented(self) -> None:
        """Blocked tools should increment blocked_count."""
        def shell(cmd: str) -> str:
            return cmd

        agent = governed_agent(name="test", tools=[shell])
        try:
            agent.governed_tools[0]("rm -rf /")
        except PermissionError:
            pass
        assert agent.log.blocked_count == 1


class TestGovernedAgentReport:
    """Test governance report generation."""

    def test_report_structure(self) -> None:
        """Report should have expected fields."""
        agent = governed_agent(name="test", model="gpt-4o", tools=[])
        report = agent.get_report()
        assert report["agent_name"] == "test"
        assert report["model"] == "gpt-4o"
        assert "events" in report
        assert "blocked_count" in report

    def test_report_reflects_activity(self) -> None:
        """Report should reflect tool calls and blocks."""
        def safe(q: str) -> str:
            return q

        def dangerous(cmd: str) -> str:
            return cmd

        agent = governed_agent(name="test", tools=[safe, dangerous])
        agent.governed_tools[0]("hello")
        try:
            agent.governed_tools[1]("rm -rf /")
        except PermissionError:
            pass

        report = agent.get_report()
        assert len(report["events"]) == 2
        assert report["blocked_count"] == 1


class TestOpenAIAgentImportError:
    """Test graceful handling when openai-agents is not installed."""

    def test_to_openai_agent_raises_import_error(self) -> None:
        """to_openai_agent() should raise ImportError when SDK not installed."""
        agent = governed_agent(name="test", tools=[])
        with pytest.raises(ImportError, match="openai-agents"):
            agent.to_openai_agent()
