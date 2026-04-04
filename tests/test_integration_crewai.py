# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for CrewAI integration — all mocked, no crewai dependency."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.integrations.crewai import CodeTrustCrew, _wrap_tool, CrewGovernanceLog


class TestToolCallInterception:
    """Test that agent tool calls are intercepted and validated."""

    def test_safe_tool_call_passes(self) -> None:
        """Safe tool input should be allowed through."""
        log = CrewGovernanceLog()

        def my_tool(query: str) -> str:
            return f"result for {query}"

        my_tool.__name__ = "web_search"
        wrapped = _wrap_tool(my_tool, "researcher", log, blocked_tools=set())
        result = wrapped("python tutorials")
        assert "result for python tutorials" in result
        assert log.blocked_tools == 0

    def test_dangerous_tool_input_blocked(self) -> None:
        """Dangerous tool input should be blocked."""
        log = CrewGovernanceLog()

        def my_tool(cmd: str) -> str:
            return cmd

        my_tool.__name__ = "terminal"
        wrapped = _wrap_tool(my_tool, "researcher", log, blocked_tools=set())
        with pytest.raises(PermissionError, match="BLOCKED"):
            wrapped("rm -rf /")
        assert log.blocked_tools == 1

    def test_git_push_blocked_for_agent(self) -> None:
        """git push should be blocked even via agent tools."""
        log = CrewGovernanceLog()

        def run_cmd(cmd: str) -> str:
            return "done"

        run_cmd.__name__ = "shell"
        wrapped = _wrap_tool(run_cmd, "deployer", log, blocked_tools=set())
        with pytest.raises(PermissionError, match="BLOCKED"):
            wrapped("git push origin main")

    def test_events_logged_per_call(self) -> None:
        """Each tool call should produce an event."""
        log = CrewGovernanceLog()

        def search(q: str) -> str:
            return "found"

        search.__name__ = "search"
        wrapped = _wrap_tool(search, "researcher", log, blocked_tools=set())
        wrapped("safe query")
        assert len(log.events) == 1
        assert log.events[0].agent_name == "researcher"
        assert log.events[0].tool_name == "search"


class TestPolicyEnforcement:
    """Test that forbidden tools are blocked by policy."""

    def test_forbidden_tool_blocked(self) -> None:
        """Tools in the blocked set should be rejected."""
        log = CrewGovernanceLog()

        def dangerous_tool(cmd: str) -> str:
            return cmd

        dangerous_tool.__name__ = "shell_exec"
        dangerous_tool.name = "shell_exec"
        wrapped = _wrap_tool(
            dangerous_tool, "writer", log,
            blocked_tools={"shell_exec"},
        )
        with pytest.raises(PermissionError, match="policy"):
            wrapped("ls")
        assert log.blocked_tools == 1

    def test_allowed_tool_not_blocked_by_policy(self) -> None:
        """Tools NOT in the blocked set should be allowed."""
        log = CrewGovernanceLog()

        def search(q: str) -> str:
            return "found"

        search.__name__ = "search"
        wrapped = _wrap_tool(
            search, "researcher", log,
            blocked_tools={"shell_exec", "file_delete"},
        )
        result = wrapped("safe query")
        assert result == "found"
        assert log.blocked_tools == 0


class TestCodeTrustCrew:
    """Test the CodeTrustCrew wrapper."""

    def test_crew_wraps_agent_tools(self) -> None:
        """CodeTrustCrew should wrap all agent tools."""
        agent = MagicMock()
        agent.role = "researcher"
        agent.llm = "gpt-4o"

        def original_tool(q: str) -> str:
            return q

        original_tool.__name__ = "search"
        agent.tools = [original_tool]

        task = MagicMock()
        task.description = "Research topic"

        crew = CodeTrustCrew(agents=[agent], tasks=[task])

        # Tools should be replaced with wrapped versions
        assert len(agent.tools) == 1
        assert agent.tools[0] is not original_tool  # wrapped

    def test_crew_tracks_attribution(self) -> None:
        """CodeTrustCrew should track model attribution per agent."""
        agent1 = MagicMock()
        agent1.role = "researcher"
        agent1.llm = "gpt-4o"
        agent1.tools = []

        agent2 = MagicMock()
        agent2.role = "writer"
        agent2.llm = "claude-sonnet-4-20250514"
        agent2.tools = []

        crew = CodeTrustCrew(agents=[agent1, agent2], tasks=[])
        assert crew.log.agent_attributions["researcher"] == "gpt-4o"
        assert crew.log.agent_attributions["writer"] == "claude-sonnet-4-20250514"

    def test_crew_blocked_tools_per_agent(self) -> None:
        """Different agents can have different tool restrictions."""
        agent = MagicMock()
        agent.role = "writer"
        agent.llm = "gpt-4o"

        def shell(cmd: str) -> str:
            return cmd

        shell.__name__ = "shell"
        shell.name = "shell"
        agent.tools = [shell]

        crew = CodeTrustCrew(
            agents=[agent],
            tasks=[],
            blocked_tools={"writer": {"shell"}},
        )

        # The wrapped tool should block shell for writer
        with pytest.raises(PermissionError, match="policy"):
            agent.tools[0]("ls")


class TestCrewReport:
    """Test governance report generation."""

    def test_report_structure(self) -> None:
        """Report should have expected fields."""
        agent = MagicMock()
        agent.role = "researcher"
        agent.llm = "gpt-4o"
        agent.tools = []

        crew = CodeTrustCrew(agents=[agent], tasks=[])
        report = crew.get_report()
        assert "events" in report
        assert "blocked_tools" in report
        assert "scanned_outputs" in report
        assert "agent_attributions" in report
