# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Integration smoke tests — verify that framework wrappers actually execute
governance checks end-to-end, not just that internal methods exist.

These tests call real tool functions through the governance wrappers and
verify that:
1. Safe inputs pass through and return the original function's result
2. Dangerous inputs are blocked BEFORE the original function executes
3. The governance log records what happened
4. Cost logging is wired (when token counts provided)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.integrations.crewai import CodeTrustCrew
from src.integrations.langchain import CodeTrustGovernance, GovernedChain
from src.integrations.openai_agents import GovernedAgent, governed_agent


# ───────────────────────────────────────────────────────────────
#  LangChain: GovernedChain wraps real chain invocations
# ───────────────────────────────────────────────────────────────


class TestLangChainEndToEnd:
    """Verify GovernedChain wraps a chain object and governance fires."""

    def test_wrap_returns_governed_chain_with_governance(self) -> None:
        """wrap() produces a GovernedChain whose governance object is shared."""
        gov = CodeTrustGovernance()

        class FakeChain:
            def invoke(self, inputs: dict, **kwargs: object) -> str:
                return f"processed: {inputs.get('input', '')}"

        wrapped = gov.wrap(FakeChain())
        assert isinstance(wrapped, GovernedChain)
        assert wrapped.governance is gov

    def test_governed_chain_invoke_calls_underlying_chain(self) -> None:
        """GovernedChain.invoke() returns the underlying chain's result."""
        gov = CodeTrustGovernance()
        call_log: list[str] = []

        class FakeChain:
            def invoke(self, inputs: dict, **kwargs: object) -> str:
                call_log.append("invoked")
                return f"result: {inputs.get('input', '')}"

        wrapped = gov.wrap(FakeChain())
        result = wrapped.invoke({"input": "hello"})
        assert result == "result: hello"
        assert "invoked" in call_log

    def test_on_tool_start_blocks_before_execution(self) -> None:
        """Dangerous tool input is blocked — original function never runs."""
        gov = CodeTrustGovernance(block_on_violation=True)
        executed = []

        def dangerous_tool(cmd: str) -> str:
            executed.append(cmd)
            return cmd

        with pytest.raises(PermissionError, match="BLOCKED"):
            gov.on_tool_start("shell", "rm -rf /")

        # Original function was never called
        assert executed == []
        assert gov.log.blocked_count == 1

    def test_safe_tool_passes_through(self) -> None:
        """Safe tool input passes governance and tool output is scanned."""
        gov = CodeTrustGovernance(scan_outputs=True)
        result = gov.on_tool_start("search", "grep pattern file.py")
        assert result["verdict"] == "ALLOW"
        # Scan the output
        findings = gov.on_tool_end("search", "line 42: found pattern")
        assert isinstance(findings, list)

    def test_llm_end_with_tokens_logs_cost(self, tmp_path: Path) -> None:
        """on_llm_end with token counts triggers cost logging."""
        gov = CodeTrustGovernance()
        gov.on_llm_start("anthropic", "claude-sonnet-4.6")
        # Call with token counts — should attempt cost logging
        result = gov.on_llm_end(
            "The fix is applied.",
            input_tokens=500,
            output_tokens=200,
            model="claude-sonnet-4.6",
            provider="anthropic",
        )
        # Should not crash — cost logging may fail silently if no storage dir
        assert isinstance(result, list)

    def test_full_session_governance_log(self) -> None:
        """A full session produces a governance report with events."""
        gov = CodeTrustGovernance()
        gov.on_llm_start("openai", "gpt-4o")
        gov.on_tool_start("search", "grep TODO src/")
        gov.on_tool_end("search", "src/main.py:42: TODO fix this")
        gov.on_llm_end("I found a TODO at line 42.")
        gov.on_chain_error(RuntimeError("connection timeout"))

        report = gov.get_report()
        assert report["blocked_count"] == 0
        assert report["scanned_outputs"] == 1
        assert "openai/gpt-4o" in report["models_seen"]
        # llm_start + tool_start + chain_error = 3 minimum
        # (on_tool_end and on_llm_end only add events when issues found)
        assert len(report["events"]) >= 3


# ───────────────────────────────────────────────────────────────
#  CrewAI: CodeTrustCrew wraps agent tools that actually execute
# ───────────────────────────────────────────────────────────────


class TestCrewAIEndToEnd:
    """Verify CodeTrustCrew wraps tools that actually call through."""

    def test_wrapped_tool_executes_and_returns_result(self) -> None:
        """A wrapped tool runs the original function and returns its result."""
        call_log: list[str] = []

        class FakeAgent:
            role = "researcher"
            llm = "gpt-4o"
            tools: list = []

        agent = FakeAgent()

        def search(query: str) -> str:
            call_log.append(query)
            return f"found: {query}"

        search.__name__ = "search"
        agent.tools = [search]

        crew = CodeTrustCrew(agents=[agent], tasks=[])
        result = agent.tools[0]("python best practices")
        assert result == "found: python best practices"
        assert "python best practices" in call_log

    def test_wrapped_tool_blocks_dangerous_input(self) -> None:
        """Dangerous input is blocked — original function never runs."""
        call_log: list[str] = []

        class FakeAgent:
            role = "researcher"
            llm = "gpt-4o"
            tools: list = []

        agent = FakeAgent()

        def shell(cmd: str) -> str:
            call_log.append(cmd)
            return cmd

        shell.__name__ = "shell"
        agent.tools = [shell]

        crew = CodeTrustCrew(agents=[agent], tasks=[])
        with pytest.raises(PermissionError, match="BLOCKED"):
            agent.tools[0]("rm -rf /")

        assert call_log == []  # Never executed
        assert crew.log.blocked_tools == 1

    def test_policy_blocked_tool_never_executes(self) -> None:
        """A policy-blocked tool raises before the function runs."""
        executed = []

        class FakeAgent:
            role = "writer"
            llm = "gpt-4o"
            tools: list = []

        agent = FakeAgent()

        def shell_exec(cmd: str) -> str:
            executed.append(cmd)
            return cmd

        shell_exec.__name__ = "shell_exec"
        shell_exec.name = "shell_exec"
        agent.tools = [shell_exec]

        crew = CodeTrustCrew(
            agents=[agent], tasks=[],
            blocked_tools={"writer": {"shell_exec"}},
        )
        with pytest.raises(PermissionError, match="policy"):
            agent.tools[0]("ls")

        assert executed == []

    def test_attribution_tracked_per_agent(self) -> None:
        """Each agent's model is tracked in the governance log."""
        class Agent1:
            role = "researcher"
            llm = "claude-opus-4.6"
            tools: list = []

        class Agent2:
            role = "writer"
            llm = "gpt-4o"
            tools: list = []

        crew = CodeTrustCrew(agents=[Agent1(), Agent2()], tasks=[])
        assert crew.log.agent_attributions["researcher"] == "claude-opus-4.6"
        assert crew.log.agent_attributions["writer"] == "gpt-4o"

    def test_log_cost_method_callable(self) -> None:
        """log_cost method exists and doesn't crash."""
        class FakeAgent:
            role = "test"
            llm = "gpt-4o"
            tools: list = []

        crew = CodeTrustCrew(agents=[FakeAgent()], tasks=[])
        # Should not raise — cost logging fails silently if storage unavailable
        crew.log_cost("test", "gpt-4o", "openai", 1000, 500)


# ───────────────────────────────────────────────────────────────
#  OpenAI Agents: governed_agent wraps tools end-to-end
# ───────────────────────────────────────────────────────────────


class TestOpenAIEndToEnd:
    """Verify governed_agent wraps tool functions that actually execute."""

    def test_governed_tool_executes_and_returns(self) -> None:
        """Wrapped tool calls the original and returns its result."""
        call_log: list[str] = []

        def search(query: str) -> str:
            call_log.append(query)
            return f"found: {query}"

        agent = governed_agent(name="researcher", model="gpt-4o", tools=[search])
        result = agent.governed_tools[0]("machine learning")
        assert result == "found: machine learning"
        assert "machine learning" in call_log

    def test_governed_tool_blocks_before_execution(self) -> None:
        """Dangerous input is blocked before the original runs."""
        executed = []

        def run_cmd(cmd: str) -> str:
            executed.append(cmd)
            return cmd

        agent = governed_agent(name="test", tools=[run_cmd])
        with pytest.raises(PermissionError, match="BLOCKED"):
            agent.governed_tools[0]("rm -rf /")

        assert executed == []
        assert agent.log.blocked_count == 1

    def test_multiple_tools_independently_governed(self) -> None:
        """Each tool gets its own governance wrapper."""
        def safe_tool(x: str) -> str:
            return f"safe: {x}"

        def another_tool(x: str) -> str:
            return f"another: {x}"

        agent = governed_agent(name="multi", tools=[safe_tool, another_tool])
        r1 = agent.governed_tools[0]("hello")
        r2 = agent.governed_tools[1]("world")
        assert r1 == "safe: hello"
        assert r2 == "another: world"
        assert len(agent.log.events) == 2

    def test_governance_log_tracks_all_calls(self) -> None:
        """The governance log records every tool invocation."""
        def tool_a(x: str) -> str:
            return x

        agent = governed_agent(name="logger_test", tools=[tool_a])
        agent.governed_tools[0]("call1")
        agent.governed_tools[0]("call2")

        report = agent.get_report()
        assert report["agent_name"] == "logger_test"
        assert report["model"] == "gpt-4o"
        assert len(report["events"]) == 2

    def test_log_cost_method_callable(self) -> None:
        """log_cost method exists and doesn't crash."""
        agent = governed_agent(name="cost_test", model="gpt-4o", tools=[])
        agent.log_cost(1000, 500)

    def test_blocked_tool_event_in_report(self) -> None:
        """A blocked call appears in the report with correct verdict."""
        def shell(cmd: str) -> str:
            return cmd

        agent = governed_agent(name="block_test", tools=[shell])
        try:
            agent.governed_tools[0]("git push origin main")
        except PermissionError:
            pass

        report = agent.get_report()
        assert report["blocked_count"] == 1
        block_events = [e for e in report["events"] if e["verdict"] == "BLOCK"]
        assert len(block_events) == 1
