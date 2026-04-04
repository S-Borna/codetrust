# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""OpenAI Agents SDK integration — governed agent with tool validation.

Usage::

    from codetrust.integrations.openai_agents import governed_agent

    agent = governed_agent(
        name="researcher",
        model="gpt-4o",
        tools=[web_search, file_read],
    )

Requires ``pip install codetrust[openai-agents]``.
"""

from __future__ import annotations

import functools
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("codetrust.integrations.openai_agents")

_IMPORT_ERROR_MSG = (
    "Install openai-agents to use CodeTrust OpenAI Agents integration: "
    "pip install codetrust[openai-agents]"
)


def _require_openai_agents() -> Any:
    """Import and return openai-agents Agent class, raising clear error if missing."""
    try:
        from agents import Agent
    except ImportError as exc:
        raise ImportError(_IMPORT_ERROR_MSG) from exc
    return Agent


# ───────────────────────────────────────────────────────────────
#  Governance log
# ───────────────────────────────────────────────────────────────


@dataclass
class ToolEvent:
    """A governance event from an OpenAI agent tool call."""

    agent_name: str
    tool_name: str
    event_type: str
    timestamp: float
    verdict: str = ""
    message: str = ""


@dataclass
class AgentGovernanceLog:
    """Accumulated governance events for an agent."""

    events: list[ToolEvent] = field(default_factory=list)
    blocked_count: int = 0
    model: str = ""
    agent_name: str = ""

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON output."""
        return {
            "agent_name": self.agent_name,
            "model": self.model,
            "events": [
                {
                    "tool_name": e.tool_name,
                    "event_type": e.event_type,
                    "verdict": e.verdict,
                    "message": e.message,
                }
                for e in self.events
            ],
            "blocked_count": self.blocked_count,
        }


# ───────────────────────────────────────────────────────────────
#  Tool wrapper
# ───────────────────────────────────────────────────────────────


def _governed_tool_wrapper(
    func: Any,
    agent_name: str,
    gov_log: AgentGovernanceLog,
) -> Any:
    """Wrap a tool function with CodeTrust governance.

    Validates tool input via CommandInterceptor before execution,
    and scans output via StaticAnalyzer after execution.

    Args:
        func: Original tool function.
        agent_name: Name of the agent using this tool.
        gov_log: Governance log to append events to.

    Returns:
        Wrapped function with governance checks.
    """
    from src.gateway.interceptor import CommandInterceptor

    interceptor = CommandInterceptor()
    tool_name = getattr(func, "__name__", "unknown_tool")

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        input_str = str(args[0]) if args else str(next(iter(kwargs.values()), ""))
        result = interceptor.check_terminal(input_str)

        gov_log.events.append(ToolEvent(
            agent_name=agent_name,
            tool_name=tool_name,
            event_type="tool_call",
            timestamp=time.time(),
            verdict=result.verdict.value,
            message=result.message,
        ))

        if result.verdict.value == "BLOCK":
            gov_log.blocked_count += 1
            logger.warning(
                "BLOCKED %s/%s: %s [%s]",
                agent_name, tool_name, result.message, result.rule_id,
            )
            raise PermissionError(
                f"CodeTrust BLOCKED '{tool_name}' for agent '{agent_name}': "
                f"{result.message} [rule: {result.rule_id}]"
            )

        output = func(*args, **kwargs)

        # Scan output for anti-patterns
        if output:
            from src.services.static_analyzer import StaticAnalyzer
            analyzer = StaticAnalyzer()
            findings = analyzer.scan_code(str(output), filename=f"{tool_name}_output")
            block_findings = [f for f in findings if f.severity == "BLOCK"]
            if block_findings:
                gov_log.events.append(ToolEvent(
                    agent_name=agent_name,
                    tool_name=tool_name,
                    event_type="output_scan",
                    timestamp=time.time(),
                    message=f"{len(block_findings)} BLOCK findings",
                ))

        return output

    return wrapper


# ───────────────────────────────────────────────────────────────
#  Public API
# ───────────────────────────────────────────────────────────────


class GovernedAgent:
    """An OpenAI Agents SDK agent with CodeTrust governance on all tools.

    Args:
        name: Agent name.
        model: Model identifier (e.g. "gpt-4o").
        tools: List of tool functions.
        instructions: System instructions for the agent.
    """

    def __init__(
        self,
        name: str,
        model: str = "gpt-4o",
        tools: list[Any] | None = None,
        instructions: str = "",
    ) -> None:
        self.name = name
        self.model = model
        self.instructions = instructions
        self.log = AgentGovernanceLog(agent_name=name, model=model)

        # Wrap each tool with governance
        self.original_tools = tools or []
        self.governed_tools = [
            _governed_tool_wrapper(t, name, self.log) for t in self.original_tools
        ]

    def to_openai_agent(self) -> Any:
        """Create an OpenAI Agents SDK Agent with governed tools.

        Returns:
            An ``agents.Agent`` instance with wrapped tools.

        Raises:
            ImportError: If openai-agents is not installed.
        """
        agent_cls = _require_openai_agents()
        return agent_cls(
            name=self.name,
            model=self.model,
            tools=self.governed_tools,
            instructions=self.instructions,
        )

    def log_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        model: str = "",
        provider: str = "",
    ) -> None:
        """Log LLM cost for this agent.

        Args:
            input_tokens: Input token count.
            output_tokens: Output token count.
            model: Override model (defaults to agent's model).
            provider: Override provider.
        """
        try:
            from src.services.cost_tracker import log_usage
            log_usage(
                model=model or self.model,
                provider=provider or "openai",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                action=f"openai_agent_{self.name}",
            )
        except Exception as exc:
            logger.debug("Cost logging failed for agent %s: %s", self.name, exc)

    def get_report(self) -> dict[str, object]:
        """Get governance report for this agent.

        Returns:
            Dict with agent name, model, events, blocked count.
        """
        return self.log.to_dict()


def governed_agent(
    name: str,
    model: str = "gpt-4o",
    tools: list[Any] | None = None,
    instructions: str = "",
) -> GovernedAgent:
    """Create a governed OpenAI agent with CodeTrust tool validation.

    This is the primary entry point. Tools are wrapped with governance
    checks that validate inputs and scan outputs.

    Args:
        name: Agent name.
        model: Model identifier.
        tools: List of tool functions to govern.
        instructions: System instructions.

    Returns:
        GovernedAgent with governance-wrapped tools.

    Example::

        agent = governed_agent(
            name="researcher",
            model="gpt-4o",
            tools=[web_search, file_read],
        )
    """
    logger.info("Creating governed agent: %s (model: %s, tools: %d)", name, model, len(tools or []))
    return GovernedAgent(name=name, model=model, tools=tools, instructions=instructions)
