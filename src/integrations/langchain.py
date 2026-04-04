# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""LangChain integration — CodeTrust governance as a callback handler.

Usage::

    from codetrust.integrations.langchain import CodeTrustGovernance

    governance = CodeTrustGovernance()
    chain = governance.wrap(my_chain)
    result = chain.invoke({"input": "..."})

Requires ``pip install codetrust[langchain]``.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("codetrust.integrations.langchain")

# ───────────────────────────────────────────────────────────────
#  Lazy framework import
# ───────────────────────────────────────────────────────────────

_IMPORT_ERROR_MSG = (
    "Install langchain to use CodeTrust LangChain integration: "
    "pip install codetrust[langchain]"
)


def _require_langchain() -> type:
    """Import and return BaseCallbackHandler, raising clear error if missing."""
    try:
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError as exc:
        raise ImportError(_IMPORT_ERROR_MSG) from exc
    return BaseCallbackHandler


# ───────────────────────────────────────────────────────────────
#  Governance event log
# ───────────────────────────────────────────────────────────────


@dataclass
class GovernanceEvent:
    """A single governance event recorded during chain execution."""

    event_type: str
    timestamp: float
    tool_name: str = ""
    verdict: str = ""
    message: str = ""
    model: str = ""
    provider: str = ""
    claims_detected: int = 0
    findings_count: int = 0


@dataclass
class GovernanceLog:
    """Accumulates governance events during a chain/agent run."""

    events: list[GovernanceEvent] = field(default_factory=list)
    blocked_count: int = 0
    scanned_outputs: int = 0
    models_seen: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, object]:
        """Serialize for JSON output."""
        return {
            "events": [
                {
                    "event_type": e.event_type,
                    "timestamp": e.timestamp,
                    "tool_name": e.tool_name,
                    "verdict": e.verdict,
                    "message": e.message,
                    "model": e.model,
                    "provider": e.provider,
                }
                for e in self.events
            ],
            "blocked_count": self.blocked_count,
            "scanned_outputs": self.scanned_outputs,
            "models_seen": sorted(self.models_seen),
        }


# ───────────────────────────────────────────────────────────────
#  CodeTrust LangChain Callback Handler
# ───────────────────────────────────────────────────────────────


class CodeTrustGovernance:
    """LangChain callback handler that enforces CodeTrust governance.

    Intercepts tool calls, scans outputs, logs attribution, and detects
    completion hallucination — all transparently during chain execution.

    Args:
        block_on_violation: If True, raise on BLOCK verdicts (default True).
        scan_outputs: If True, scan tool outputs for anti-patterns (default True).
        detect_hallucination: If True, run completion hallucination detection (default True).
    """

    def __init__(
        self,
        block_on_violation: bool = True,
        scan_outputs: bool = True,
        detect_hallucination: bool = True,
    ) -> None:
        self.block_on_violation = block_on_violation
        self.scan_outputs = scan_outputs
        self.detect_hallucination = detect_hallucination
        self.log = GovernanceLog()
        self._session_history: list[str] = []

    def _get_interceptor(self) -> Any:
        """Lazy-load CommandInterceptor."""
        from src.gateway.interceptor import CommandInterceptor
        return CommandInterceptor()

    def _get_analyzer(self) -> Any:
        """Lazy-load StaticAnalyzer."""
        from src.services.static_analyzer import StaticAnalyzer
        return StaticAnalyzer()

    def on_tool_start(self, tool_name: str, tool_input: str) -> dict[str, str]:
        """Validate tool invocation before execution.

        Args:
            tool_name: Name of the tool being called.
            tool_input: Input string or command for the tool.

        Returns:
            Dict with verdict and message. Raises on BLOCK if configured.

        Raises:
            PermissionError: When block_on_violation is True and verdict is BLOCK.
        """
        interceptor = self._get_interceptor()
        result = interceptor.check_terminal(tool_input)

        event = GovernanceEvent(
            event_type="tool_start",
            timestamp=time.time(),
            tool_name=tool_name,
            verdict=result.verdict.value,
            message=result.message,
        )
        self.log.events.append(event)

        if result.verdict.value == "BLOCK":
            self.log.blocked_count += 1
            logger.warning(
                "Tool blocked: %s — %s (rule: %s)",
                tool_name, result.message, result.rule_id,
            )
            if self.block_on_violation:
                raise PermissionError(
                    f"CodeTrust BLOCKED tool '{tool_name}': {result.message} "
                    f"[rule: {result.rule_id}]"
                )

        return {"verdict": result.verdict.value, "message": result.message}

    def on_tool_end(self, tool_name: str, output: str) -> list[dict[str, str]]:
        """Scan tool output for anti-patterns.

        Args:
            tool_name: Name of the tool that produced output.
            output: The tool's output text.

        Returns:
            List of findings (empty if output is clean).
        """
        self._session_history.append(f"{tool_name}: {output}")

        if not self.scan_outputs or not output:
            return []

        analyzer = self._get_analyzer()
        findings = analyzer.scan_code(output, filename=f"{tool_name}_output")
        self.log.scanned_outputs += 1

        finding_dicts = [
            {"rule_id": f.rule_id, "severity": f.severity, "message": f.message}
            for f in findings
            if f.severity in ("BLOCK", "WARN")
        ]

        if finding_dicts:
            self.log.events.append(GovernanceEvent(
                event_type="tool_output_scan",
                timestamp=time.time(),
                tool_name=tool_name,
                findings_count=len(finding_dicts),
                message=f"{len(finding_dicts)} findings in output",
            ))

        return finding_dicts

    def on_llm_start(self, provider: str, model: str) -> None:
        """Log model attribution when an LLM call starts.

        Args:
            provider: LLM provider name (e.g. "openai", "anthropic").
            model: Model identifier (e.g. "gpt-4o", "claude-sonnet-4-20250514").
        """
        self.log.models_seen.add(f"{provider}/{model}")
        self.log.events.append(GovernanceEvent(
            event_type="llm_start",
            timestamp=time.time(),
            provider=provider,
            model=model,
        ))
        logger.info("LLM call: %s/%s", provider, model)

    def on_llm_end(
        self,
        output: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        model: str = "",
        provider: str = "",
    ) -> list[dict[str, str]]:
        """Run completion hallucination detection and log token usage.

        Args:
            output: The LLM's response text.
            input_tokens: Number of input tokens (0 if unknown).
            output_tokens: Number of output tokens (0 if unknown).
            model: Model name (uses last seen if empty).
            provider: Provider name (uses last seen if empty).

        Returns:
            List of unverified claims detected (empty if clean).
        """
        # Log cost if token counts are available
        if input_tokens > 0 or output_tokens > 0:
            effective_model = model
            effective_provider = provider
            if not effective_model and self.log.models_seen:
                last = sorted(self.log.models_seen)[-1]
                parts = last.split("/", 1)
                effective_provider = parts[0] if len(parts) > 1 else provider
                effective_model = parts[-1]
            if effective_model:
                try:
                    from src.services.cost_tracker import log_usage
                    log_usage(
                        model=effective_model,
                        provider=effective_provider or "unknown",
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        action="langchain_llm_call",
                    )
                except Exception as exc:
                    logger.debug("Cost logging failed: %s", exc)

        if not self.detect_hallucination or not output:
            return []

        from src.services.completion_hallucination import verify_claims

        results = verify_claims(output, self._session_history)
        unverified = [
            {"claim": r.claim.text, "verdict": r.verdict, "reason": r.reason}
            for r in results
            if r.verdict != "VERIFIED"
        ]

        if unverified:
            self.log.events.append(GovernanceEvent(
                event_type="hallucination_check",
                timestamp=time.time(),
                claims_detected=len(results),
                message=f"{len(unverified)} unverified claims",
            ))

        return unverified

    def on_chain_error(self, error: BaseException) -> None:
        """Log chain errors to audit trail.

        Args:
            error: The exception that occurred.
        """
        self.log.events.append(GovernanceEvent(
            event_type="chain_error",
            timestamp=time.time(),
            message=str(error)[:300],
        ))
        logger.error("Chain error: %s", error)

    def wrap(self, chain: Any) -> Any:
        """Wrap a LangChain chain/agent with CodeTrust governance callbacks.

        Returns the chain configured with this handler as a callback.
        For chains that support ``callbacks`` parameter, injects this handler.
        For other objects, returns a ``GovernedChain`` wrapper.

        Args:
            chain: A LangChain Runnable, Chain, or AgentExecutor.

        Returns:
            The chain with governance callbacks attached.
        """
        return GovernedChain(chain=chain, governance=self)

    def get_report(self) -> dict[str, object]:
        """Get governance report for the session.

        Returns:
            Dict with events, blocked count, scanned outputs, models seen.
        """
        return self.log.to_dict()


class GovernedChain:
    """Wrapper that applies CodeTrust governance to a LangChain chain.

    Args:
        chain: The underlying LangChain chain/agent.
        governance: The CodeTrustGovernance handler instance.
    """

    def __init__(self, chain: Any, governance: CodeTrustGovernance) -> None:
        self.chain = chain
        self.governance = governance

    def invoke(self, inputs: dict[str, Any], **kwargs: Any) -> Any:
        """Invoke the chain with governance.

        Args:
            inputs: Input dict for the chain.
            **kwargs: Additional keyword arguments passed to chain.invoke().

        Returns:
            Chain output after governance checks.
        """
        config = kwargs.pop("config", {})
        if "callbacks" not in config:
            config["callbacks"] = []

        # Inject our handler if LangChain BaseCallbackHandler is available
        try:
            base_cls = _require_langchain()

            class _LCHandler(base_cls):
                """Internal LangChain callback bridge."""

                def __init__(self, gov: CodeTrustGovernance) -> None:
                    self._gov = gov

                def on_tool_start(
                    self, serialized: dict[str, Any], input_str: str, **kw: Any,
                ) -> None:
                    name = serialized.get("name", "unknown_tool")
                    self._gov.on_tool_start(name, input_str)

                def on_tool_end(self, output: str, **kw: Any) -> None:
                    self._gov.on_tool_end("tool", output)

                def on_llm_start(
                    self, serialized: dict[str, Any], prompts: list[str], **kw: Any,
                ) -> None:
                    model = serialized.get("kwargs", {}).get("model_name", "unknown")
                    provider = serialized.get("id", ["unknown"])[0] if serialized.get("id") else "unknown"
                    self._gov.on_llm_start(provider, model)

                def on_llm_end(self, response: Any, **kw: Any) -> None:
                    text = str(response) if response else ""
                    self._gov.on_llm_end(text)

                def on_chain_error(self, error: BaseException, **kw: Any) -> None:
                    self._gov.on_chain_error(error)

            config["callbacks"].append(_LCHandler(self.governance))
        except ImportError:
            # LangChain not installed — governance methods called directly by user
            pass

        return self.chain.invoke(inputs, config=config, **kwargs)

    def __getattr__(self, name: str) -> Any:
        """Proxy attribute access to the underlying chain."""
        return getattr(self.chain, name)
