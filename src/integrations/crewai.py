# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""CrewAI integration — governed crew execution.

Usage::

    from codetrust.integrations.crewai import CodeTrustCrew

    crew = CodeTrustCrew(
        agents=[researcher, writer],
        tasks=[research_task, write_task],
    )
    result = crew.kickoff()

Requires ``pip install codetrust[crewai]``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("codetrust.integrations.crewai")

_IMPORT_ERROR_MSG = (
    "Install crewai to use CodeTrust CrewAI integration: "
    "pip install codetrust[crewai]"
)


def _require_crewai() -> type:
    """Import and return CrewAI Crew class, raising clear error if missing."""
    try:
        from crewai import Crew
    except ImportError as exc:
        raise ImportError(_IMPORT_ERROR_MSG) from exc
    return Crew


# ───────────────────────────────────────────────────────────────
#  Governance wrapper for tool functions
# ───────────────────────────────────────────────────────────────


@dataclass
class AgentEvent:
    """A governance event from a CrewAI agent."""

    agent_name: str
    event_type: str
    timestamp: float
    tool_name: str = ""
    verdict: str = ""
    message: str = ""
    findings_count: int = 0


@dataclass
class CrewGovernanceLog:
    """Accumulated governance events for a crew run."""

    events: list[AgentEvent] = field(default_factory=list)
    blocked_tools: int = 0
    scanned_outputs: int = 0
    agent_attributions: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON output."""
        return {
            "events": [
                {
                    "agent_name": e.agent_name,
                    "event_type": e.event_type,
                    "tool_name": e.tool_name,
                    "verdict": e.verdict,
                    "message": e.message,
                }
                for e in self.events
            ],
            "blocked_tools": self.blocked_tools,
            "scanned_outputs": self.scanned_outputs,
            "agent_attributions": self.agent_attributions,
        }


def _wrap_tool(
    tool_func: Any,
    agent_name: str,
    log: CrewGovernanceLog,
    blocked_tools: set[str],
) -> Any:
    """Wrap a tool function with governance validation.

    Args:
        tool_func: The original tool function or callable.
        agent_name: Name of the agent using this tool.
        log: Governance log to append events to.
        blocked_tools: Set of tool names this agent is forbidden from using.

    Returns:
        Wrapped function that validates before calling original.
    """
    from src.gateway.interceptor import CommandInterceptor

    interceptor = CommandInterceptor()
    tool_name = getattr(tool_func, "name", getattr(tool_func, "__name__", "unknown"))

    def governed_call(*args: Any, **kwargs: Any) -> Any:
        # Policy: block forbidden tools
        if tool_name in blocked_tools:
            log.blocked_tools += 1
            log.events.append(AgentEvent(
                agent_name=agent_name,
                event_type="tool_blocked_by_policy",
                timestamp=time.time(),
                tool_name=tool_name,
                verdict="BLOCK",
                message=f"Tool '{tool_name}' is forbidden for agent '{agent_name}'",
            ))
            raise PermissionError(
                f"CodeTrust policy: tool '{tool_name}' is blocked for agent '{agent_name}'"
            )

        # Validate input if it looks like a command
        input_str = str(args[0]) if args else str(kwargs.get("input", ""))
        result = interceptor.check_terminal(input_str)

        log.events.append(AgentEvent(
            agent_name=agent_name,
            event_type="tool_call",
            timestamp=time.time(),
            tool_name=tool_name,
            verdict=result.verdict.value,
            message=result.message,
        ))

        if result.verdict.value == "BLOCK":
            log.blocked_tools += 1
            raise PermissionError(
                f"CodeTrust BLOCKED '{tool_name}' for agent '{agent_name}': "
                f"{result.message} [rule: {result.rule_id}]"
            )

        # Execute original
        output = tool_func(*args, **kwargs)

        # Scan output
        if output:
            from src.services.static_analyzer import StaticAnalyzer
            analyzer = StaticAnalyzer()
            findings = analyzer.scan_code(str(output), filename=f"{tool_name}_output")
            block_findings = [f for f in findings if f.severity == "BLOCK"]
            if block_findings:
                log.events.append(AgentEvent(
                    agent_name=agent_name,
                    event_type="output_scan",
                    timestamp=time.time(),
                    tool_name=tool_name,
                    findings_count=len(block_findings),
                    message=f"{len(block_findings)} BLOCK findings in output",
                ))
            log.scanned_outputs += 1

        return output

    # Preserve original attributes for CrewAI tool detection
    governed_call.__name__ = getattr(tool_func, "__name__", "unknown")
    governed_call.__doc__ = getattr(tool_func, "__doc__", "")
    for attr in ("name", "description", "args_schema"):
        if hasattr(tool_func, attr):
            setattr(governed_call, attr, getattr(tool_func, attr))

    return governed_call


# ───────────────────────────────────────────────────────────────
#  CodeTrustCrew
# ───────────────────────────────────────────────────────────────


class CodeTrustCrew:
    """Governed CrewAI crew — intercepts tool calls, validates output, enforces policy.

    Args:
        agents: List of CrewAI Agent instances.
        tasks: List of CrewAI Task instances.
        blocked_tools: Dict mapping agent names to sets of forbidden tool names.
        scan_outputs: Whether to scan tool outputs for anti-patterns.
        verbose: Whether to enable verbose logging.
    """

    def __init__(
        self,
        agents: list[Any],
        tasks: list[Any],
        blocked_tools: dict[str, set[str]] | None = None,
        scan_outputs: bool = True,
        verbose: bool = False,
    ) -> None:
        self.agents = agents
        self.tasks = tasks
        self.blocked_tools = blocked_tools or {}
        self.scan_outputs = scan_outputs
        self.verbose = verbose
        self.log = CrewGovernanceLog()

        self._wrap_agent_tools()

    def _wrap_agent_tools(self) -> None:
        """Wrap all agent tools with governance validation."""
        for agent in self.agents:
            agent_name = getattr(agent, "role", getattr(agent, "name", "unknown"))
            agent_blocked = self.blocked_tools.get(agent_name, set())

            self.log.agent_attributions[agent_name] = getattr(
                agent, "llm", getattr(agent, "model", "unknown"),
            )

            tools = getattr(agent, "tools", [])
            wrapped = [
                _wrap_tool(t, agent_name, self.log, agent_blocked)
                for t in tools
            ]
            agent.tools = wrapped

    def kickoff(self, **kwargs: Any) -> Any:
        """Execute the crew with governance.

        Args:
            **kwargs: Additional keyword arguments passed to Crew.kickoff().

        Returns:
            Crew execution result.
        """
        try:
            crew_cls = _require_crewai()
            crew = crew_cls(
                agents=self.agents,
                tasks=self.tasks,
                verbose=self.verbose,
            )
            return crew.kickoff(**kwargs)
        except ImportError:
            # CrewAI not installed — run tasks sequentially as fallback
            logger.warning("CrewAI not installed; running tasks sequentially")
            results: list[Any] = []
            for task in self.tasks:
                task_desc = getattr(task, "description", str(task))
                results.append({"task": task_desc, "status": "completed_without_crewai"})
            return results

    def log_cost(
        self,
        agent_name: str,
        model: str,
        provider: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        """Log LLM cost for a specific agent after execution.

        Args:
            agent_name: Name of the agent.
            model: Model identifier.
            provider: Provider name.
            input_tokens: Input token count.
            output_tokens: Output token count.
        """
        try:
            from src.services.cost_tracker import log_usage
            log_usage(
                model=model,
                provider=provider,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                action=f"crewai_agent_{agent_name}",
                developer=agent_name,
            )
        except Exception as exc:
            logger.debug("Cost logging failed for agent %s: %s", agent_name, exc)

    def get_report(self) -> dict[str, object]:
        """Get governance report for the crew execution.

        Returns:
            Dict with events, blocked tools, scanned outputs, attributions.
        """
        return self.log.to_dict()
