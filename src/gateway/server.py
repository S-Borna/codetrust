# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""MCP Gateway Server — AI action governance as an MCP tool layer.

This server provides governance tools that AI agents and MCP clients
can use to validate actions BEFORE executing them. It also wraps
the existing CodeTrust scanning tools with automatic governance checks.

Architecture:
    AI Agent → MCP Client → Gateway Server → Validate → Allow/Block
                                          ↓
                                     Audit Log

Usage:
    # Standalone gateway (validates terminal commands, file writes, etc.)
    codetrust-gateway-mcp

    # In Claude Desktop config:
    {
        "mcpServers": {
            "codetrust-gateway": {
                "command": "codetrust-gateway-mcp"
            }
        }
    }
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path

import structlog
from mcp.server.fastmcp import FastMCP

from src.config import settings
from src.gateway.approvals import ApprovalExceptionStore, apply_exception_override
from src.gateway.audit import AuditEntry, AuditLogger
from src.gateway.interceptor import CommandInterceptor, InterceptResult, Verdict
from src.gateway.policies import GovernancePolicy, PolicyEngine
from src.gateway.policy_integrity import (
    PolicyIntegrityResult,
    build_current_hashes,
    get_policy_manifest_hash,
    verify_policy_integrity,
)
from src.services.governance_bundles import get_bundle_policy
from src.telemetry_client import send_telemetry


def _configure_mcp_stdio_logging() -> None:
    """Route structured logs to stderr to keep stdout clean for JSON-RPC."""
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            structlog.processors.KeyValueRenderer(key_order=["event"]),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


_configure_mcp_stdio_logging()
logger = structlog.get_logger()

SECONDS_PER_HOUR: int = 3_600
POLICY_INTEGRITY_CACHE_TTL_SECONDS: float = 5.0
TRUSTED_SESSION_TTL_SECONDS: int = 3_600
TRUSTED_SESSION_MIN_TTL_SECONDS: int = 300
TRUSTED_SESSION_MAX_TTL_SECONDS: int = 10_800
ALLOW_REASON_FALLBACK_MIN_LEN: int = 12
PREFLIGHT_FALLBACK_TTL_SECONDS: int = 900
NATIVE_TOOL_NAMES: set[str] = {
    "run_in_terminal",
    "create_file",
    "replace_string_in_file",
    "edit_notebook_file",
}

# ═══════════════════════════════════════════════════════════════
#  Initialize gateway components
# ═══════════════════════════════════════════════════════════════

_workspace = os.environ.get("CODETRUST_WORKSPACE", os.getcwd())


def _detect_agent() -> str:
    """Auto-detect the calling AI agent from environment signals.

    Returns:
        Agent identifier string (e.g. "claude", "copilot", "cursor").
    """
    # Claude Code / Claude Desktop
    if os.environ.get("CLAUDE_CODE") or os.environ.get("ANTHROPIC_API_KEY"):
        return "claude"
    # GitHub Copilot
    if os.environ.get("GITHUB_COPILOT") or os.environ.get("COPILOT_AGENT"):
        return "copilot"
    # Cursor IDE
    if os.environ.get("CURSOR_SESSION") or "cursor" in os.environ.get("TERM_PROGRAM", "").lower():
        return "cursor"
    # Windsurf / Codeium
    if os.environ.get("WINDSURF_SESSION") or os.environ.get("CODEIUM_API_KEY"):
        return "windsurf"
    # GitHub Actions CI
    if os.environ.get("GITHUB_ACTIONS"):
        return "github-actions"
    return "unknown"


def _load_policy_engine(workspace: str) -> PolicyEngine:
    """Load workspace policy engine without crashing gateway startup."""
    try:
        return PolicyEngine.from_workspace(workspace)
    except OSError as exc:
        logger.warning(
            "gateway_policy_engine_workspace_unreadable",
            workspace=workspace,
            error=str(exc),
        )
        return PolicyEngine()


_engine = _load_policy_engine(_workspace)
_interceptor = CommandInterceptor(
    enabled=_engine.active or _engine.auditing,
    disabled_rules=_engine.get_disabled_rules(),
    protected_paths=_engine.get_protected_paths(),
)
_audit = AuditLogger(
    os.path.join(_workspace, _engine.config.audit_path),
    enabled=_engine.config.audit_enabled,
)

_session_id = f"gateway-{int(time.time())}"
_agent_id = os.environ.get("CODETRUST_AGENT_ID", _detect_agent())
_session_policy_hash = get_policy_manifest_hash(_workspace)
_last_integrity_check_at: float = 0.0
_last_integrity_result: PolicyIntegrityResult | None = None
_trusted_tokens: dict[str, dict[str, object]] = {}
_preflight_sessions: dict[str, dict[str, object]] = {}

# --- Session action-count limiter (OWASP ASI-03: Excessive Agency) ---
_SESSION_ACTION_LIMIT: int = int(
    os.environ.get("CODETRUST_SESSION_ACTION_LIMIT", "500"),
)
_session_action_count: int = 0


def _check_session_action_limit() -> dict[str, str] | None:
    """Enforce per-session action limit. Returns BLOCK payload or None.

    Uses a process-level counter. In production each gateway process serves
    one session. The counter resets on process restart (new session).
    """
    global _session_action_count
    _session_action_count += 1
    if _SESSION_ACTION_LIMIT <= 0:
        return None
    if _session_action_count > _SESSION_ACTION_LIMIT:
        return {
            "status": "BLOCKED",
            "verdict": "BLOCK",
            "rule_id": "session_action_limit_exceeded",
            "message": (
                f"Session action limit reached ({_SESSION_ACTION_LIMIT}). "
                "Start a new session or raise CODETRUST_SESSION_ACTION_LIMIT."
            ),
            "suggestion": "Begin a new trusted session or request limit increase.",
        }
    return None


_approval_store = ApprovalExceptionStore(
    _workspace,
    approval_ttl_minutes=_engine.config.approval_ttl_minutes,
    exception_ttl_minutes=_engine.config.exception_ttl_minutes,
)

gateway = FastMCP("codetrust-gateway")


def _resolve_policy_sign_key() -> str:
    """Resolve signing key with env precedence for runtime/test consistency."""
    env_key = os.environ.get("CODETRUST_RULES_HMAC_SECRET")
    if env_key:
        return env_key
    return settings.rules_hmac_secret or settings.jwt_secret or "codetrust"


def _evaluate_policy_integrity(force: bool = False) -> PolicyIntegrityResult:
    """Evaluate policy integrity with short-lived cache."""
    global _last_integrity_check_at, _last_integrity_result

    now = time.time()
    if (
        not force
        and _last_integrity_result is not None
        and (now - _last_integrity_check_at) < POLICY_INTEGRITY_CACHE_TTL_SECONDS
    ):
        return _last_integrity_result

    result = verify_policy_integrity(_workspace, sign_key=_resolve_policy_sign_key())
    _last_integrity_check_at = now
    _last_integrity_result = result
    return result


def _audit_policy_integrity(result: PolicyIntegrityResult, *, action: str) -> None:
    """Record policy-integrity checks in audit log."""
    attestation = _build_attestation(result)
    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="policy_integrity",
        verdict=result.verdict,
        rule_id=result.rule_id,
        original_action=action,
        message=result.message,
        suggestion=result.suggestion,
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
        metadata={
            **asdict(result).get("metadata", {}),
            "attestation": attestation,
        },
    ))


def _build_attestation(result: PolicyIntegrityResult | None = None) -> dict[str, str]:
    """Build runtime attestation payload for gateway responses and audit metadata."""
    integrity = result if result is not None else _evaluate_policy_integrity()
    return {
        "session_id": _session_id,
        "policy_hash": get_policy_manifest_hash(_workspace),
        "session_policy_hash": _session_policy_hash,
        "policy_verdict": integrity.verdict,
        "policy_rule_id": integrity.rule_id,
    }


def _policy_pin_gate(*, proxy: bool = False) -> dict[str, object] | None:
    """Block actions when policy hash drifts from the session-pinned hash."""
    if not _engine.active:
        return None

    current_hash = get_policy_manifest_hash(_workspace)
    if hmac.compare_digest(current_hash, _session_policy_hash):
        return None

    payload = {
        "verdict": "BLOCK",
        "rule_id": "gateway_policy_hash_drift",
        "message": "Policy hash changed since this gateway session started.",
        "suggestion": "Restart trusted session and rerun preflight simulation.",
        "root_cause": "Session policy pin mismatch.",
        "safe_fix": "Open a new trusted session bound to the new policy hash.",
        "pinned_policy_hash": _session_policy_hash,
        "current_policy_hash": current_hash,
    }
    if proxy:
        payload = {
            **payload,
            "status": _BLOCKED_PREFIX,
            "instruction": (
                "MANDATORY: Do NOT proceed with native tool calls while policy hash drifts."
            ),
        }
    return _attach_attestation_payload(payload)


def _prune_preflight_sessions(now: float) -> None:
    """Drop expired preflight sessions."""
    expired = [
        agent for agent, payload in _preflight_sessions.items()
        if float(payload.get("expires_at", 0.0)) <= now
    ]
    for agent in expired:
        _preflight_sessions.pop(agent, None)


def _mark_preflight(*, agent_id: str, bundle_id: str, commands_count: int) -> float:
    """Mark preflight as completed for an agent and return expiry timestamp."""
    ttl = max(PREFLIGHT_FALLBACK_TTL_SECONDS, _engine.config.preflight_ttl_seconds)
    expires_at = time.time() + float(ttl)
    _preflight_sessions[agent_id] = {
        "bundle_id": bundle_id,
        "commands_count": commands_count,
        "expires_at": expires_at,
    }
    return expires_at


def _has_valid_preflight(agent_id: str) -> bool:
    """Return True when preflight simulation is active for the given agent."""
    now = time.time()
    _prune_preflight_sessions(now)
    payload = _preflight_sessions.get(agent_id)
    if payload is None:
        return False
    return float(payload.get("expires_at", 0.0)) > now


def _preflight_gate(*, agent_id: str) -> dict[str, object] | None:
    """Enforce mandatory preflight policy simulation before proxy actions."""
    if not _engine.config.preflight_required:
        return None
    if _has_valid_preflight(agent_id):
        return None
    return _attach_attestation_payload({
        "status": _BLOCKED_PREFIX,
        "verdict": "BLOCK",
        "rule_id": "gateway_preflight_required",
        "message": "Preflight simulation is required before actionable proxy calls.",
        "suggestion": "Call codetrust_simulate_policy with representative commands first.",
        "root_cause": "trusted_execution.preflight_required is enabled.",
        "safe_fix": "Run codetrust_simulate_policy and retry while preflight is active.",
        "instruction": "MANDATORY: Complete preflight simulation before continuing.",
    })


def _attach_attestation_payload(
    payload: dict[str, object],
    *,
    result: PolicyIntegrityResult | None = None,
) -> dict[str, object]:
    """Attach attestation block to response payload."""
    payload["attestation"] = _build_attestation(result)
    return payload


def _attach_attestation_metadata(result: InterceptResult) -> None:
    """Attach attestation metadata to intercept result for audit trail."""
    attestation = _build_attestation()
    result.metadata = {
        **result.metadata,
        "attestation": attestation,
    }


def _prune_trusted_tokens(now: float) -> None:
    """Drop expired trusted-session tokens."""
    expired = [
        token for token, payload in _trusted_tokens.items()
        if float(payload.get("expires_at", 0.0)) <= now
    ]
    for token in expired:
        _trusted_tokens.pop(token, None)


def _issue_trusted_token(
    *,
    reason: str,
    agent_id: str,
    ttl_seconds: int,
    scope_repo: str,
    scope_branch: str,
    task_id: str,
) -> tuple[str, float]:
    """Create and store a trusted-session token."""
    token = os.urandom(16).hex()
    bounded_ttl = min(
        TRUSTED_SESSION_MAX_TTL_SECONDS,
        max(TRUSTED_SESSION_MIN_TTL_SECONDS, ttl_seconds),
    )
    expires_at = time.time() + float(bounded_ttl)
    _trusted_tokens[token] = {
        "expires_at": expires_at,
        "agent_id": agent_id,
        "session_id": _session_id,
        "reason": reason,
        "scope_repo": scope_repo,
        "scope_branch": scope_branch,
        "task_id": task_id,
    }
    return token, expires_at


def _has_valid_trusted_token(token: str, *, agent_id: str) -> bool:
    """Validate trusted-session token expiry."""
    now = time.time()
    _prune_trusted_tokens(now)
    if not token:
        return False
    payload = _trusted_tokens.get(token)
    if payload is None:
        return False
    expires_at = float(payload.get("expires_at", 0.0))
    token_agent_id = str(payload.get("agent_id", ""))
    token_session_id = str(payload.get("session_id", ""))
    token_scope_repo = str(payload.get("scope_repo", "")).strip()
    token_scope_branch = str(payload.get("scope_branch", "")).strip()
    if token_agent_id and token_agent_id != agent_id:
        return False
    if token_session_id and token_session_id != _session_id:
        return False
    if token_scope_repo and os.path.abspath(token_scope_repo) != os.path.abspath(_workspace):
        return False
    current_branch = os.environ.get("CODETRUST_BRANCH", "").strip()
    if token_scope_branch and current_branch and token_scope_branch != current_branch:
        return False
    return expires_at > now


def _trusted_execution_gate(*, trusted_token: str, agent_id: str) -> dict[str, object] | None:
    """Block actionable operations unless trusted execution session is active."""
    if not _engine.config.trusted_execution_mode:
        return None
    if _has_valid_trusted_token(trusted_token, agent_id=agent_id):
        return None
    return _attach_attestation_payload({
        "status": _BLOCKED_PREFIX,
        "verdict": "BLOCK",
        "rule_id": "gateway_trusted_execution_required",
        "message": "Trusted execution mode is enabled for this workspace.",
        "suggestion": "Call codetrust_begin_trusted_session, then retry with trusted_token.",
        "root_cause": "Native/proxy actions require active trusted execution session.",
        "safe_fix": "Start trusted session and provide trusted_token on proxy calls.",
        "instruction": (
            "MANDATORY: Start trusted execution first. "
            "Do NOT proceed with native tools until trusted session is active."
        ),
    })


def _native_enforcement_gate(*, tool_name: str) -> dict[str, object] | None:
    """Return blocking payload when global deny-native mode is enabled."""
    if not _engine.config.deny_native_execution:
        return None
    if tool_name not in NATIVE_TOOL_NAMES:
        return None
    return _attach_attestation_payload({
        "status": _BLOCKED_PREFIX,
        "verdict": "BLOCK",
        "rule_id": "gateway_native_tool_denied",
        "message": "Native tool execution is denied by active governance policy.",
        "suggestion": "Use the corresponding codetrust_* proxy tool first.",
        "root_cause": "deny_native_execution policy is enabled.",
        "safe_fix": "Call codetrust proxy and use native tool only after APPROVED.",
        "instruction": "MANDATORY: Native tool calls are disallowed in enforced mode.",
    })


def _allow_reason_gate(*, allow_reason: str) -> dict[str, object] | None:
    """Enforce explicit allow reason in strict governance mode."""
    if not _engine.config.require_allow_reason:
        return None
    min_length = max(ALLOW_REASON_FALLBACK_MIN_LEN, _engine.config.allow_reason_min_length)
    if len(allow_reason.strip()) >= min_length:
        return None
    return _attach_attestation_payload({
        "status": "REQUIRES_ALLOW_REASON",
        "verdict": "BLOCK",
        "rule_id": "gateway_allow_reason_required",
        "message": "Explicit allow reason is required before this action can proceed.",
        "suggestion": f"Provide allow_reason with at least {min_length} characters.",
        "instruction": "MANDATORY: include allow_reason to continue.",
    })


def _apply_exception_if_present(
    result: InterceptResult,
    *,
    session_id: str,
    agent_id: str,
) -> InterceptResult:
    """Allow blocked action when an active governance exception matches."""
    if not result.blocked:
        return result
    exception = _approval_store.find_matching_exception(
        result,
        session_id=session_id,
        agent_id=agent_id,
    )
    if exception is None:
        return result
    return apply_exception_override(result, exception=exception)


def _requires_approval(result: InterceptResult) -> bool:
    """Return True if blocked result requires explicit user approval."""
    if not _engine.active:
        return False
    if not result.blocked:
        return False
    return result.rule_id in set(_engine.config.require_approval_for)


def _integrity_block_payload(*, proxy: bool = False) -> dict[str, object] | None:
    """Return blocking payload if policy integrity fails in enforce mode."""
    result = _evaluate_policy_integrity()

    if result.verdict == "ALLOW":
        return None

    _audit_policy_integrity(result, action="gateway_integrity_guard")

    if result.verdict == "WARN":
        return None

    if not _engine.active:
        return None

    if proxy:
        return _attach_attestation_payload({
            "status": _BLOCKED_PREFIX,
            "verdict": "BLOCK",
            "rule_id": result.rule_id,
            "message": result.message,
            "suggestion": result.suggestion,
            "root_cause": result.message,
            "safe_fix": result.suggestion,
            "instruction": (
                "MANDATORY: Do NOT proceed with the native tool. "
                "Policy integrity must pass before any action is allowed."
            ),
        }, result=result)

    return _attach_attestation_payload({
        "verdict": "BLOCK",
        "action_type": "policy_integrity",
        "original_action": "gateway_integrity_guard",
        "rule_id": result.rule_id,
        "message": result.message,
        "suggestion": result.suggestion,
        "root_cause": result.message,
        "safe_fix": result.suggestion,
        "action": "BLOCKED — Policy integrity check failed.",
        "alternative": result.suggestion,
    }, result=result)


def _emit_gateway_telemetry(*, result: InterceptResult, effective_verdict: str) -> None:
    """Best-effort anonymous telemetry for gateway checks.

    Privacy: never sends the original command/path/content; only aggregate-friendly labels.
    """

    action = "ALLOWED"
    if effective_verdict == "BLOCK":
        action = "BLOCKED"
    elif effective_verdict == "WARN":
        action = "WARNED"

    send_telemetry(
        event_type="gateway_check",
        source="mcp",
        version=settings.version,
        payload={
            "action": action,
            "rule_triggered": result.rule_id,
            "action_type": result.action_type.value,
        },
    )


# ═══════════════════════════════════════════════════════════════
#  Gateway tools — AI agents call these before acting
# ═══════════════════════════════════════════════════════════════


@gateway.tool(name="codetrust_validate_command")
async def validate_command(command: str) -> str:
    """Validate a terminal command BEFORE execution.

    Call this tool before running any terminal command. It checks for
    dangerous patterns: heredoc, eval, curl|sh, rm -rf, git push,
    secret exports, and other destructive operations.

    Args:
        command: The terminal command to validate.

    Returns:
        JSON with verdict (ALLOW/WARN/BLOCK), message, and suggestion.
    """
    logger.info("gateway_validate_command", command=command[:100])

    action_limit = _check_session_action_limit()
    if action_limit is not None:
        return json.dumps(_attach_attestation_payload(action_limit), indent=2)

    integrity_block = _integrity_block_payload()
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    policy_pin_block = _policy_pin_gate()
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    result = _interceptor.check_terminal(command)
    _attach_attestation_metadata(result)

    # In audit mode, never actually block
    effective_verdict = result.verdict.value
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        result_dict = result.to_dict()
        result_dict["verdict"] = "WARN"
        result_dict["message"] = f"[AUDIT MODE] {result.message}"
        effective_verdict = "WARN"
    else:
        result_dict = result.to_dict()

    _emit_gateway_telemetry(result=result, effective_verdict=effective_verdict)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    if result.blocked and _engine.active:
        return json.dumps(_attach_attestation_payload({
            **result_dict,
            "action": "BLOCKED — Do not execute this command.",
            "alternative": result.suggestion,
            "root_cause": result.root_cause or result.message,
            "safe_fix": result.safe_fix or result.suggestion,
        }), indent=2)

    return json.dumps(_attach_attestation_payload(result_dict), indent=2)


@gateway.tool(name="codetrust_validate_file_write")
async def validate_file_write(
    path: str,
    content: str,
) -> str:
    """Validate file content BEFORE writing to disk.

    Call this before creating or editing files. Checks for hardcoded
    secrets, eval/exec, and writes to protected files.

    Args:
        path: The file path to write to.
        content: The content to write.

    Returns:
        JSON with verdict and any findings.
    """
    logger.info("gateway_validate_file_write", path=path)

    integrity_block = _integrity_block_payload()
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    policy_pin_block = _policy_pin_gate()
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    result = _interceptor.check_file_write(path, content)
    _attach_attestation_metadata(result)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    result_dict = result.to_dict()
    effective_verdict = result.verdict.value
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        result_dict["verdict"] = "WARN"
        result_dict["message"] = f"[AUDIT MODE] {result.message}"
        effective_verdict = "WARN"

    _emit_gateway_telemetry(result=result, effective_verdict=effective_verdict)

    return json.dumps(_attach_attestation_payload(result_dict), indent=2)


@gateway.tool(name="codetrust_validate_file_delete")
async def validate_file_delete(path: str) -> str:
    """Validate file deletion BEFORE removing.

    Checks if the file is in the protected paths list.

    Args:
        path: The file path to delete.

    Returns:
        JSON with verdict.
    """
    logger.info("gateway_validate_file_delete", path=path)

    integrity_block = _integrity_block_payload()
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    policy_pin_block = _policy_pin_gate()
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    result = _interceptor.check_file_delete(path)
    _attach_attestation_metadata(result)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    _emit_gateway_telemetry(result=result, effective_verdict=result.verdict.value)

    return json.dumps(_attach_attestation_payload(result.to_dict()), indent=2)


@gateway.tool(name="codetrust_validate_package")
async def validate_package(
    package: str,
    registry: str = "pypi",
) -> str:
    """Validate a package name before installation.

    Checks for typosquatting indicators and suspicious names.
    For live registry verification, use codetrust_verify_imports.

    Args:
        package: Package name to validate.
        registry: Target registry (pypi, npm, crates, go).

    Returns:
        JSON with verdict and warnings.
    """
    logger.info("gateway_validate_package", package=package, registry=registry)

    integrity_block = _integrity_block_payload()
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    policy_pin_block = _policy_pin_gate()
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    result = _interceptor.check_package_install(package, registry=registry)
    _attach_attestation_metadata(result)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    _emit_gateway_telemetry(result=result, effective_verdict=result.verdict.value)

    return json.dumps(_attach_attestation_payload(result.to_dict()), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Proxy enforcement tools — AI MUST call these INSTEAD of
#  the native VS Code tools: run_in_terminal, create_file,
#  replace_string_in_file, and edit_notebook_file.
#
#  Workflow:
#    1. AI calls codetrust_run_in_terminal(command).
#    2. If APPROVED → AI may call native run_in_terminal with
#       the EXACT same command string.
#    3. If BLOCKED → AI MUST NOT proceed. No exceptions.
# ═══════════════════════════════════════════════════════════════

_APPROVED_PREFIX = "APPROVED"
_BLOCKED_PREFIX = "BLOCKED"


def _proxy_result(
    result: InterceptResult,
    *,
    allow_reason: str,
    session_id: str,
    agent_id: str,
) -> str:
    """Serialise a proxy intercept result with APPROVED / BLOCKED header."""
    result = _apply_exception_if_present(result, session_id=session_id, agent_id=agent_id)
    _attach_attestation_metadata(result)
    effective_verdict = result.verdict.value
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        effective_verdict = "WARN"

    _emit_gateway_telemetry(result=result, effective_verdict=effective_verdict)
    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    if _requires_approval(result):
        pending = _approval_store.create_pending(
            result,
            session_id=session_id,
            agent_id=agent_id,
        )
        return json.dumps(_attach_attestation_payload({
            "status": "REQUIRES_APPROVAL",
            "verdict": "BLOCK",
            "rule_id": result.rule_id,
            "message": result.message,
            "suggestion": result.suggestion,
            "root_cause": result.root_cause or result.message,
            "safe_fix": "Call codetrust_approve_action with explicit reason, then retry.",
            "approval_request_id": pending.request_id,
            "approval_expires_at": pending.expires_at,
            "instruction": (
                "MANDATORY: Action requires explicit allow-before-continue approval."
            ),
            "allow_reason": allow_reason,
        }), indent=2)

    if result.blocked and _engine.active:
        return json.dumps(_attach_attestation_payload({
            "status": _BLOCKED_PREFIX,
            "verdict": "BLOCK",
            "rule_id": result.rule_id,
            "message": result.message,
            "suggestion": result.suggestion,
            "root_cause": result.root_cause or result.message,
            "safe_fix": result.safe_fix or result.suggestion,
            "instruction": (
                "MANDATORY: Do NOT proceed with the native tool. "
                "This action is blocked by CodeTrust governance policy."
            ),
        }), indent=2)

    return json.dumps(_attach_attestation_payload({
        "status": _APPROVED_PREFIX,
        "verdict": effective_verdict,
        "rule_id": result.rule_id,
        "message": result.message or "Action validated — you may proceed.",
        "allow_reason": allow_reason,
        "instruction": (
            "You may now call the native tool with the EXACT same parameters."
        ),
    }), indent=2)


@gateway.tool(name="codetrust_run_in_terminal")
async def proxy_run_in_terminal(
    command: str,
    trusted_token: str = "",
    allow_reason: str = "",
    agent_id: str = "",
) -> str:
    """Mandatory proxy gate for run_in_terminal.

    You MUST call this tool BEFORE calling run_in_terminal.
    - If status=APPROVED → call run_in_terminal with the EXACT same command.
    - If status=BLOCKED  → do NOT call run_in_terminal. Use the suggestion instead.

    Args:
        command: The exact terminal command you intend to run.

    Returns:
        JSON with status (APPROVED/BLOCKED), verdict, and instruction.
    """
    logger.info("proxy_run_in_terminal", command=command[:120])

    resolved_agent_id = agent_id or _agent_id

    preflight_block = _preflight_gate(agent_id=resolved_agent_id)
    if preflight_block is not None:
        return json.dumps(preflight_block, indent=2)

    native_block = _native_enforcement_gate(tool_name="run_in_terminal")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

    policy_pin_block = _policy_pin_gate(proxy=True)
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    allow_reason_block = _allow_reason_gate(allow_reason=allow_reason)
    if allow_reason_block is not None:
        return json.dumps(allow_reason_block, indent=2)

    trusted_block = _trusted_execution_gate(trusted_token=trusted_token, agent_id=resolved_agent_id)
    if trusted_block is not None:
        return json.dumps(trusted_block, indent=2)

    integrity_block = _integrity_block_payload(proxy=True)
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    result = _interceptor.check_terminal(command)
    return _proxy_result(
        result,
        allow_reason=allow_reason,
        session_id=_session_id,
        agent_id=resolved_agent_id,
    )


@gateway.tool(name="codetrust_create_file")
async def proxy_create_file(
    path: str,
    content: str,
    trusted_token: str = "",
    allow_reason: str = "",
    agent_id: str = "",
) -> str:
    """Mandatory proxy gate for create_file.

    You MUST call this tool BEFORE calling create_file.
    - If status=APPROVED → call create_file with the EXACT same path and content.
    - If status=BLOCKED  → do NOT create the file.

    Args:
        path: Absolute path of the file to create.
        content: Full content to write to the file.

    Returns:
        JSON with status (APPROVED/BLOCKED), verdict, and instruction.
    """
    logger.info("proxy_create_file", path=path)

    resolved_agent_id = agent_id or _agent_id

    preflight_block = _preflight_gate(agent_id=resolved_agent_id)
    if preflight_block is not None:
        return json.dumps(preflight_block, indent=2)

    native_block = _native_enforcement_gate(tool_name="create_file")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

    policy_pin_block = _policy_pin_gate(proxy=True)
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    allow_reason_block = _allow_reason_gate(allow_reason=allow_reason)
    if allow_reason_block is not None:
        return json.dumps(allow_reason_block, indent=2)

    trusted_block = _trusted_execution_gate(trusted_token=trusted_token, agent_id=resolved_agent_id)
    if trusted_block is not None:
        return json.dumps(trusted_block, indent=2)

    integrity_block = _integrity_block_payload(proxy=True)
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    result = _interceptor.check_file_write(path, content)
    return _proxy_result(
        result,
        allow_reason=allow_reason,
        session_id=_session_id,
        agent_id=resolved_agent_id,
    )


@gateway.tool(name="codetrust_replace_string_in_file")
async def proxy_replace_string_in_file(
    path: str,
    old_string: str,
    new_string: str,
    trusted_token: str = "",
    allow_reason: str = "",
    agent_id: str = "",
) -> str:
    """Mandatory proxy gate for replace_string_in_file.

    You MUST call this tool BEFORE calling replace_string_in_file.
    - If status=APPROVED → call replace_string_in_file with the EXACT same parameters.
    - If status=BLOCKED  → do NOT edit the file.

    Args:
        path: Absolute path of the file to edit.
        old_string: The exact string to be replaced.
        new_string: The exact replacement content.

    Returns:
        JSON with status (APPROVED/BLOCKED), verdict, and instruction.
    """
    logger.info("proxy_replace_string_in_file", path=path)

    resolved_agent_id = agent_id or _agent_id

    preflight_block = _preflight_gate(agent_id=resolved_agent_id)
    if preflight_block is not None:
        return json.dumps(preflight_block, indent=2)

    native_block = _native_enforcement_gate(tool_name="replace_string_in_file")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

    policy_pin_block = _policy_pin_gate(proxy=True)
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    allow_reason_block = _allow_reason_gate(allow_reason=allow_reason)
    if allow_reason_block is not None:
        return json.dumps(allow_reason_block, indent=2)

    trusted_block = _trusted_execution_gate(trusted_token=trusted_token, agent_id=resolved_agent_id)
    if trusted_block is not None:
        return json.dumps(trusted_block, indent=2)

    integrity_block = _integrity_block_payload(proxy=True)
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    # Delta-only validation: scan only new_string (what the agent writes),
    # not old_string (what already exists in the file). This prevents
    # IDE freezing on large files — a 1-line edit in a 30K-line file
    # validates in milliseconds instead of seconds.
    result = _interceptor.check_file_write(path, new_string)
    return _proxy_result(
        result,
        allow_reason=allow_reason,
        session_id=_session_id,
        agent_id=resolved_agent_id,
    )


@gateway.tool(name="codetrust_edit_notebook")
async def proxy_edit_notebook(
    path: str,
    new_code: str,
    trusted_token: str = "",
    allow_reason: str = "",
    agent_id: str = "",
) -> str:
    """Mandatory proxy gate for edit_notebook_file.

    You MUST call this tool BEFORE calling edit_notebook_file.
    - If status=APPROVED → call edit_notebook_file with the EXACT same parameters.
    - If status=BLOCKED  → do NOT edit the notebook.

    Args:
        path: Absolute path of the notebook file (.ipynb).
        new_code: The code content for the new or edited cell.

    Returns:
        JSON with status (APPROVED/BLOCKED), verdict, and instruction.
    """
    logger.info("proxy_edit_notebook", path=path)

    resolved_agent_id = agent_id or _agent_id

    preflight_block = _preflight_gate(agent_id=resolved_agent_id)
    if preflight_block is not None:
        return json.dumps(preflight_block, indent=2)

    native_block = _native_enforcement_gate(tool_name="edit_notebook_file")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

    policy_pin_block = _policy_pin_gate(proxy=True)
    if policy_pin_block is not None:
        return json.dumps(policy_pin_block, indent=2)

    allow_reason_block = _allow_reason_gate(allow_reason=allow_reason)
    if allow_reason_block is not None:
        return json.dumps(allow_reason_block, indent=2)

    trusted_block = _trusted_execution_gate(trusted_token=trusted_token, agent_id=resolved_agent_id)
    if trusted_block is not None:
        return json.dumps(trusted_block, indent=2)

    integrity_block = _integrity_block_payload(proxy=True)
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    result = _interceptor.check_file_write(path, new_code)
    return _proxy_result(
        result,
        allow_reason=allow_reason,
        session_id=_session_id,
        agent_id=resolved_agent_id,
    )


def _build_governance_policy_lines(
    policies: list[GovernancePolicy],
) -> list[str]:
    """Build the policy table rows for the governance status report."""
    lines = [
        "",
        "## Active Policies",
        "",
        "| Policy | Status | Description |",
        "|--------|--------|-------------|",
    ]
    for policy in policies:
        status = "Active" if policy.enabled else "Disabled"
        lines.append(f"| `{policy.id}` | {status} | {policy.description} |")
    return lines


def _build_governance_extras(
    protected_paths: list[str],
    stats: dict,
) -> list[str]:
    """Build protected files and audit statistics sections."""
    lines: list[str] = []
    if protected_paths:
        lines.extend(["", "## Protected Files", ""])
        for path in protected_paths:
            lines.append(f"- `{path}`")

    if stats["total"] > 0:
        lines.extend([
            "",
            "## Audit Statistics",
            "",
            f"- Total actions logged: {stats['total']}",
        ])
        for verdict, count in stats.get("by_verdict", {}).items():
            lines.append(f"- {verdict}: {count}")

        if stats.get("top_rules"):
            lines.extend(["", "### Most Triggered Rules", ""])
            for rule in stats["top_rules"][:5]:
                lines.append(f"- `{rule['rule_id']}`: {rule['count']} times")
    return lines


def _build_governance_posture_payload() -> dict[str, object]:
    """Return current governance posture snapshot."""
    integrity = _evaluate_policy_integrity()
    current_policy_hash = get_policy_manifest_hash(_workspace)
    policy_pin_match = hmac.compare_digest(current_policy_hash, _session_policy_hash)
    readiness_reasons: list[str] = []
    if integrity.verdict != "ALLOW":
        readiness_reasons.append("policy_integrity_not_allow")
    if not policy_pin_match:
        readiness_reasons.append("policy_hash_drift")
    if _engine.config.preflight_required and not _has_valid_preflight(_agent_id):
        readiness_reasons.append("preflight_missing_or_expired")

    control_plane_ready = (
        _engine.config.enabled
        and _engine.config.trusted_execution_mode
        and _engine.config.deny_native_execution
        and _engine.config.require_allow_reason
        and _engine.config.session_binding_required
        and _engine.config.anti_bypass_checks
        and integrity.verdict == "ALLOW"
        and policy_pin_match
        and (
            not _engine.config.preflight_required
            or _has_valid_preflight(_agent_id)
        )
    )

    return {
        "session_id": _session_id,
        "agent_id": _agent_id,
        "mode": _engine.config.mode.value,
        "enabled": _engine.config.enabled,
        "trusted_execution_mode": _engine.config.trusted_execution_mode,
        "deny_native_execution": _engine.config.deny_native_execution,
        "require_allow_reason": _engine.config.require_allow_reason,
        "session_binding_enforced": _engine.config.session_binding_required,
        "anti_bypass_enabled": _engine.config.anti_bypass_checks,
        "policy_integrity": {
            "verdict": integrity.verdict,
            "rule_id": integrity.rule_id,
            "policy_hash": current_policy_hash,
            "session_policy_hash": _session_policy_hash,
            "policy_pin_match": policy_pin_match,
        },
        "preflight_required": _engine.config.preflight_required,
        "preflight_ready": _has_valid_preflight(_agent_id),
        "pending_approvals": len(_approval_store.list_pending()),
        "active_exceptions": len(_approval_store.list_active_exceptions()),
        "control_plane_ready": control_plane_ready,
        "readiness": "ready" if control_plane_ready else "not-ready",
        "readiness_reasons": readiness_reasons,
    }


@gateway.tool(name="codetrust_governance_status")
async def governance_status() -> str:
    """Show current governance configuration and policy status.

    Returns the active mode, enabled/disabled rules, protected paths,
    and audit statistics.

    Returns:
        Markdown-formatted governance status report.
    """
    config = _engine.config
    policies = _engine.get_policies()
    stats = _audit.get_stats()

    enabled_count = sum(1 for p in policies if p.enabled)
    disabled_count = sum(1 for p in policies if not p.enabled)

    lines = [
        "# CodeTrust Governance Status",
        "",
        f"**Mode:** {config.mode.value}",
        f"**Enabled:** {config.enabled}",
        f"**Trusted execution:** {config.trusted_execution_mode}",
        f"**Agent:** {_agent_id}",
        f"**Session:** {_session_id}",
        f"**Policies:** {enabled_count} active, {disabled_count} disabled",
        f"**Audit log:** {_audit.path}",
        f"**Pending approvals:** {len(_approval_store.list_pending())}",
        f"**Active exceptions:** {len(_approval_store.list_active_exceptions())}",
    ]

    lines.extend(_build_governance_policy_lines(policies))
    lines.extend(_build_governance_extras(config.protected_paths, stats))

    return "\n".join(lines)


MAX_AUDIT_ACTION_LEN: int = 50


def _format_audit_entry_row(entry: AuditEntry) -> str:
    """Format a single audit entry as a markdown table row."""
    ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
    action = entry.original_action[:MAX_AUDIT_ACTION_LEN]
    if len(entry.original_action) > MAX_AUDIT_ACTION_LEN:
        action += "..."
    agent = entry.agent_id or "—"
    return f"| {ts} | {agent} | {entry.verdict} | `{entry.rule_id}` | {action} |"


@gateway.tool(name="codetrust_audit_history")
async def audit_history(
    hours: int = 24,
    verdict: str = "",
    limit: int = 50,
    export_format: str = "markdown",
) -> str:
    """Query the governance audit log.

    Shows recent AI agent actions — what was allowed, warned, or blocked.

    Args:
        hours: How many hours back to search (default: 24).
        verdict: Filter by verdict: ALLOW, WARN, BLOCK, or empty for all.
        limit: Maximum entries to return (default: 50).

    Returns:
        Markdown table of recent audit entries.
    """
    since = time.time() - (hours * SECONDS_PER_HOUR)
    entries = _audit.get_entries(since=since, verdict=verdict or None, limit=limit)

    if not entries:
        return f"No audit entries found in the last {hours} hours."

    if export_format.lower() == "json":
        timeline = []
        for entry in list(reversed(entries)):
            timeline.append({
                "timestamp": entry.timestamp,
                "action_type": entry.action_type,
                "verdict": entry.verdict,
                "rule_id": entry.rule_id,
                "original_action": entry.original_action,
                "message": entry.message,
                "suggestion": entry.suggestion,
                "session_id": entry.session_id,
                "agent_id": entry.agent_id,
                "workspace": entry.workspace,
                "metadata": entry.metadata,
            })
        return json.dumps(_attach_attestation_payload({
            "hours": hours,
            "verdict_filter": verdict or None,
            "entry_count": len(entries),
            "timeline": timeline,
        }), indent=2)

    lines = [
        f"# Audit Log — Last {hours} Hours",
        "",
        f"Showing {len(entries)} entries" + (f" (filtered: {verdict})" if verdict else ""),
        "",
        "| Time | Agent | Verdict | Rule | Action |",
        "|------|-------|---------|------|--------|",
    ]

    for entry in entries:
        lines.append(_format_audit_entry_row(entry))

    return "\n".join(lines)


@gateway.tool(name="codetrust_list_gateway_rules")
async def list_gateway_rules() -> str:
    """List all gateway interception rules and their status.

    Returns:
        Markdown table of all rules.
    """
    rules = _interceptor.get_rules()

    lines = [
        "# CodeTrust Gateway Rules",
        "",
        "| Rule ID | Severity | Status | Description |",
        "|---------|----------|--------|-------------|",
    ]

    for rule in rules:
        status = "Active" if rule["enabled"] else "Disabled"
        lines.append(
            f"| `{rule['id']}` | {rule['severity']} | {status} | {rule['message']} |"
        )

    return "\n".join(lines)


@gateway.tool(name="codetrust_begin_trusted_session")
async def begin_trusted_session(
    reason: str,
    agent_id: str = "",
    ttl_minutes: int = 60,
    scope_repo: str = "",
    scope_branch: str = "",
    task_id: str = "",
) -> str:
    """Start trusted execution session and return temporary trusted token."""
    actor = agent_id or _agent_id
    ttl_seconds = int(ttl_minutes * 60)
    repo_scope = scope_repo.strip() or _workspace
    token, expires_at = _issue_trusted_token(
        reason=reason,
        agent_id=actor,
        ttl_seconds=ttl_seconds,
        scope_repo=repo_scope,
        scope_branch=scope_branch.strip(),
        task_id=task_id.strip(),
    )
    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="trusted_session_begin",
        verdict="ALLOW",
        rule_id="trusted_execution_session_started",
        original_action=reason,
        message="Trusted execution session started.",
        suggestion="Use trusted_token on proxy calls while session is active.",
        session_id=_session_id,
        agent_id=actor,
        workspace=_workspace,
        metadata={
            "expires_at": expires_at,
            "scope_repo": repo_scope,
            "scope_branch": scope_branch.strip(),
            "task_id": task_id.strip(),
        },
    ))
    return json.dumps(_attach_attestation_payload({
        "status": _APPROVED_PREFIX,
        "trusted_token": token,
        "expires_at": expires_at,
        "scope_repo": repo_scope,
        "scope_branch": scope_branch.strip(),
        "task_id": task_id.strip(),
        "instruction": "Pass trusted_token to codetrust_* proxy tools.",
    }), indent=2)


@gateway.tool(name="codetrust_approve_action")
async def approve_action(
    request_id: str,
    approver: str,
    approver_role: str,
    reason: str,
    ttl_minutes: int = 60,
) -> str:
    """Approve pending action and issue time-bound governance exception."""
    if approver_role not in set(_engine.config.allowed_approver_roles):
        return json.dumps(_attach_attestation_payload({
            "status": _BLOCKED_PREFIX,
            "verdict": "BLOCK",
            "rule_id": "approval_role_not_allowed",
            "message": "Approver role is not allowed by governance policy.",
            "suggestion": "Use one of the configured allowed roles.",
            "allowed_roles": _engine.config.allowed_approver_roles,
        }), indent=2)

    approved = _approval_store.approve(
        request_id,
        approver=approver,
        approver_role=approver_role,
        reason=reason,
        ttl_minutes=ttl_minutes,
    )
    if approved is None:
        return json.dumps(_attach_attestation_payload({
            "status": _BLOCKED_PREFIX,
            "verdict": "BLOCK",
            "rule_id": "approval_request_not_found",
            "message": "Approval request not found or expired.",
            "suggestion": "Retry the original action to generate a fresh approval request.",
            "instruction": "Do not proceed without valid approval.",
        }), indent=2)

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="approval_granted",
        verdict="ALLOW",
        rule_id="governance_exception_created",
        original_action=request_id,
        message="Approval granted and exception created.",
        suggestion="Retry the original action before exception expiry.",
        session_id=_session_id,
        agent_id=approver,
        workspace=_workspace,
        metadata={
            "exception_id": approved.exception_id,
            "expires_at": approved.expires_at,
            "rule_id": approved.rule_id,
            "approver_role": approver_role,
        },
    ))
    return json.dumps(_attach_attestation_payload({
        "status": _APPROVED_PREFIX,
        "verdict": "ALLOW",
        "exception_id": approved.exception_id,
        "expires_at": approved.expires_at,
        "instruction": "Retry the original action. Exception is now active.",
    }), indent=2)


@gateway.tool(name="codetrust_list_exceptions")
async def list_exceptions() -> str:
    """List active governance exceptions and pending approvals."""
    pending = [asdict(item) for item in _approval_store.list_pending()]
    active = [asdict(item) for item in _approval_store.list_active_exceptions()]
    return json.dumps(_attach_attestation_payload({
        "pending_approvals": pending,
        "active_exceptions": active,
    }), indent=2)


@gateway.tool(name="codetrust_revoke_exception")
async def revoke_exception(exception_id: str, revoked_by: str) -> str:
    """Revoke active governance exception by identifier."""
    revoked = _approval_store.revoke(exception_id, revoked_by=revoked_by)
    verdict = _APPROVED_PREFIX if revoked else _BLOCKED_PREFIX
    return json.dumps(_attach_attestation_payload({
        "status": verdict,
        "revoked": revoked,
        "exception_id": exception_id,
        "instruction": "Exception revoked." if revoked else "No matching active exception.",
    }), indent=2)


@gateway.tool(name="codetrust_simulate_policy")
async def simulate_policy(
    bundle_id: str,
    commands: list[str],
    agent_id: str = "",
) -> str:
    """Simulate governance outcomes for sample commands against a policy bundle."""
    try:
        bundle_policy = get_bundle_policy(bundle_id)
    except ValueError:
        return json.dumps(_attach_attestation_payload({
            "status": _BLOCKED_PREFIX,
            "verdict": "BLOCK",
            "rule_id": "unsupported_bundle_id",
            "message": "Unsupported policy bundle id.",
            "suggestion": "Use one of: startup, team, enterprise.",
        }), indent=2)

    disabled_rules: set[str] = set()
    if not bool(bundle_policy.get("block_heredoc", True)):
        disabled_rules.add("gateway_heredoc")
    if not bool(bundle_policy.get("block_eval", True)):
        disabled_rules.add("gateway_eval")
    if not bool(bundle_policy.get("block_git_push", True)):
        disabled_rules.add("gateway_git_push")
        disabled_rules.add("gateway_git_force_push")
    if not bool(bundle_policy.get("block_rm_rf", True)):
        disabled_rules.add("gateway_rm_rf_root")
        disabled_rules.add("gateway_rm_rf_home")
    if not bool(bundle_policy.get("block_curl_pipe_sh", True)):
        disabled_rules.add("gateway_curl_pipe_sh")
    if not bool(bundle_policy.get("block_chmod_777", True)):
        disabled_rules.add("gateway_chmod_777")

    sim = CommandInterceptor(
        enabled=True,
        disabled_rules=disabled_rules,
        protected_paths=list(bundle_policy.get("protected_paths", [])),
    )
    outcomes: list[dict[str, object]] = []
    for command in commands:
        res = sim.check_terminal(command)
        outcomes.append({
            "command": command,
            "verdict": res.verdict.value,
            "rule_id": res.rule_id,
            "message": res.message,
        })

    resolved_agent_id = agent_id or _agent_id
    preflight_expires_at = _mark_preflight(
        agent_id=resolved_agent_id,
        bundle_id=bundle_id,
        commands_count=len(commands),
    )

    return json.dumps(_attach_attestation_payload({
        "bundle_id": bundle_id,
        "outcomes": outcomes,
        "preflight_agent_id": resolved_agent_id,
        "preflight_expires_at": preflight_expires_at,
    }), indent=2)


@gateway.tool(name="codetrust_governance_posture")
async def governance_posture() -> str:
    """Return machine-readable governance posture snapshot."""
    return json.dumps(_attach_attestation_payload(_build_governance_posture_payload()), indent=2)


@gateway.tool(name="codetrust_governance_integrity")
async def governance_integrity(workspace: str | None = None) -> str:
    """Verify SHA-256 integrity of all governance files against signed manifest.

    Computes current hashes of governance-critical files (.codetrust.toml,
    CLAUDE.md, .cursorrules, .windsurfrules, etc.) and compares them against
    the signed policy-integrity manifest, flagging any files that have changed
    since the last manifest signing. Hash mismatches are treated as BLOCK-level
    findings by the underlying integrity engine.

    Args:
        workspace: Optional workspace path override. Defaults to gateway workspace.

    Returns:
        JSON report with per-file hash comparison and overall verdict.
    """
    target_workspace = workspace or _workspace
    sign_key = _resolve_policy_sign_key()

    integrity_result = verify_policy_integrity(target_workspace, sign_key=sign_key)
    _audit_policy_integrity(integrity_result, action="governance_integrity_check")

    current_hashes = build_current_hashes(Path(target_workspace))

    report: dict[str, object] = {
        "verdict": integrity_result.verdict,
        "rule_id": integrity_result.rule_id,
        "message": integrity_result.message,
        "suggestion": integrity_result.suggestion,
        "workspace": target_workspace,
        "file_hashes": {
            rel_path: file_hash
            for rel_path, file_hash in current_hashes.items()
        },
        "metadata": integrity_result.metadata,
    }

    logger.info(
        "governance_integrity_check",
        verdict=integrity_result.verdict,
        files_checked=len(current_hashes),
        workspace=target_workspace,
    )

    return json.dumps(_attach_attestation_payload(report), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Completion Hallucination Detection
# ═══════════════════════════════════════════════════════════════


@gateway.tool(name="codetrust_verify_claim")
async def verify_claim(
    agent_output: str,
    session_history: str = "[]",
) -> str:
    """Verify agent claims — completion hallucination + behavioral integrity.

    Analyzes agent output for two categories of trust issues:

    1. **Completion hallucination**: claims like "done", "all tests pass",
       checkmarks — without corresponding verification commands in history.

    2. **Behavioral integrity** (when structured messages provided):
       sycophantic retraction, unsubstantiated facts, unverified file
       references, contradictory positions without new evidence.

    Args:
        agent_output: The agent's output text to analyze.
        session_history: JSON input, accepts two formats:
            - **Flat list of strings** (legacy): commands and outputs.
              Runs completion hallucination detection only.
            - **Object with "messages" and "commands"**: structured session.
              Runs BOTH completion hallucination AND integrity analysis.
              Messages: [{"role": "assistant"|"user"|"tool", "content": "..."}]

    Returns:
        JSON report with completion_claims + integrity sections.
    """
    from src.services.completion_hallucination import verify_claims

    try:
        raw = json.loads(session_history) if session_history else []
    except json.JSONDecodeError:
        raw = [session_history] if session_history else []

    # Detect input format: structured (dict with messages) or flat (list of strings)
    structured = isinstance(raw, dict) and "messages" in raw
    if structured:
        flat_commands: list[str] = raw.get("commands", [])
        raw_messages: list[dict[str, str]] = raw.get("messages", [])
        # Build flat history for completion hallucination from tool messages
        flat_history = list(flat_commands)
        for msg in raw_messages:
            if msg.get("role") == "tool":
                flat_history.append(str(msg.get("content", "")))
    elif isinstance(raw, list):
        flat_history = [str(item) for item in raw]
        flat_commands = flat_history
        raw_messages = []
    else:
        flat_history = [str(raw)]
        flat_commands = flat_history
        raw_messages = []

    # ── Pipeline 1: Completion hallucination ──
    completion_results = verify_claims(agent_output, flat_history)

    report: dict[str, object] = {
        "completion_claims": {
            "claims_detected": len(completion_results),
            "unverified_count": sum(
                1 for r in completion_results if r.verdict != "VERIFIED"
            ),
            "results": [
                {
                    "verdict": r.verdict,
                    "claim_text": r.claim.text,
                    "marker": r.claim.marker_matched,
                    "has_numeric_target": r.claim.has_numeric_target,
                    "evidence_count": len(r.evidence),
                    "evidence": [
                        {"category": e.category, "text": e.text[:100]}
                        for e in r.evidence
                    ],
                    "reason": r.reason,
                }
                for r in completion_results
            ],
        },
    }

    # ── Pipeline 2: Integrity analysis (only with structured input) ──
    if structured and raw_messages:
        from src.services.agent_integrity import analyze_session, parse_session_messages

        msgs_with_output = list(raw_messages)
        if agent_output:
            msgs_with_output.append({"role": "assistant", "content": agent_output})

        messages = parse_session_messages(msgs_with_output)
        integrity = analyze_session(messages, flat_commands, session_id=_session_id)
        report["integrity"] = integrity.to_dict()
    else:
        report["integrity"] = None

    # ── Summary ──
    total_completion_unverified = report["completion_claims"]["unverified_count"]
    integrity_data = report.get("integrity")
    total_integrity_issues = len(integrity_data["issues"]) if integrity_data else 0

    report["summary"] = {
        "completion_unverified": total_completion_unverified,
        "integrity_issues": total_integrity_issues,
        "total_issues": total_completion_unverified + total_integrity_issues,
    }

    # Backward compatibility: old consumers access claims_detected and results
    # at top level. New consumers use completion_claims.claims_detected etc.
    report["claims_detected"] = report["completion_claims"]["claims_detected"]
    report["results"] = report["completion_claims"]["results"]

    logger.info(
        "verify_claim",
        completion_claims=len(completion_results),
        completion_unverified=total_completion_unverified,
        integrity_issues=total_integrity_issues,
    )

    return json.dumps(_attach_attestation_payload(report), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Agent Integrity Verification
# ═══════════════════════════════════════════════════════════════


@gateway.tool(name="codetrust_integrity_check")
async def integrity_check(
    agent_output: str,
    session_history: str = "[]",
) -> str:
    """Analyze agent output for behavioral integrity patterns.

    Detects four categories of trust-damaging agent behavior:
    - Sycophantic retraction: agrees then reverses without new evidence
    - Unsubstantiated claims: states facts without verification commands
    - Unverified references: cites files/lines without reading them
    - Contradictory positions: takes opposite stances without new info

    These patterns are more trust-damaging than completion hallucination
    because they erode confidence in everything the agent says.

    Args:
        agent_output: The agent's latest output text to analyze.
        session_history: JSON array of message objects with "role" and "content"
            keys, or a JSON object with "messages" and "commands" arrays.

    Returns:
        JSON integrity report with per-issue details, score, and verdict
        (TRUSTWORTHY / QUESTIONABLE / UNRELIABLE).
    """
    from src.services.agent_integrity import (
        analyze_session,
        parse_session_messages,
    )

    try:
        raw = json.loads(session_history) if session_history else {}
    except json.JSONDecodeError:
        raw = {}

    if isinstance(raw, list):
        raw_messages = raw
        raw_commands: list[str] = []
    elif isinstance(raw, dict):
        raw_messages = raw.get("messages", [])
        raw_commands = raw.get("commands", [])
    else:
        raw_messages = []
        raw_commands = []

    # If agent_output is provided separately, add it as the last assistant message
    if agent_output and isinstance(raw_messages, list):
        raw_messages = list(raw_messages)
        raw_messages.append({"role": "assistant", "content": agent_output})

    messages = parse_session_messages(raw_messages)
    report = analyze_session(messages, raw_commands, session_id=_session_id)

    result = report.to_dict()

    logger.info(
        "integrity_check",
        total_claims=report.total_claims,
        verified=report.verified_claims,
        issues=len(report.issues),
        verdict=report.verdict.value,
    )

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="integrity_check",
        verdict="ALLOW" if report.verdict == "TRUSTWORTHY" else "WARN",
        rule_id="agent_integrity",
        original_action=f"Integrity check: {report.total_claims} claims",
        message=f"{report.verdict.value} — score {report.integrity_score:.2f}",
        suggestion="Review flagged issues for trust-damaging patterns.",
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
    ))

    return json.dumps(_attach_attestation_payload(result), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Definition of Done
# ═══════════════════════════════════════════════════════════════


@gateway.tool(name="codetrust_run_dod")
async def run_dod_tool(
    check_name: str = "",
) -> str:
    """Run Definition of Done acceptance checks from .codetrust/definition_of_done.toml.

    Every check runs as a real subprocess — no simulation.
    Returns full report with pass/fail per check and overall verdict.

    Args:
        check_name: Optional filter — only run checks whose name contains this substring.

    Returns:
        JSON report with per-check results, summary, and overall pass/fail.
    """
    from pathlib import Path as _Path

    from src.services.definition_of_done import load_checks, run_dod

    logger.info("gateway_run_dod", check_name=check_name)

    dod_path = _Path(_workspace) / ".codetrust" / "definition_of_done.toml"
    try:
        checks = load_checks(dod_path)
    except (FileNotFoundError, ValueError) as exc:
        return json.dumps({"error": str(exc)}, indent=2)

    report = run_dod(checks, check_filter=check_name or None)

    result = {
        "summary": report.summary,
        "all_passed": report.all_passed,
        "checks": [
            {
                "name": r.check.name,
                "command": r.check.command,
                "passed": r.passed,
                "actual_exit_code": r.actual_exit_code,
                "failure_reason": r.failure_reason,
            }
            for r in report.checks
        ],
    }

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="definition_of_done",
        verdict="ALLOW" if report.all_passed else "WARN",
        rule_id="dod_enforcement",
        original_action=f"DoD check: {check_name or 'all'}",
        message=report.summary,
        suggestion="Fix failing checks before claiming work is done.",
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
    ))

    return json.dumps(_attach_attestation_payload(result), indent=2)


# ═══════════════════════════════════════════════════════════════
#  PII Detection
# ═══════════════════════════════════════════════════════════════


async def pii_scan(
    text: str,
    min_confidence: float = 0.7,
) -> str:
    """Scan text for personally identifiable information (PII).

    Detects 15+ categories: email, phone, credit card, personnummer,
    API keys, private keys, JWT, IBAN, IP addresses, passwords,
    URLs with credentials, names, addresses, dates of birth, passport, SSN.

    Args:
        text: Text to scan for PII.
        min_confidence: Minimum confidence threshold (0.0-1.0).

    Returns:
        JSON report with findings, risk level, redacted text, and summary.
    """
    from src.services.pii_detector import apply_policy, load_pii_policy, scan_text

    report = scan_text(text, min_confidence=min_confidence)
    policy = load_pii_policy()
    policy_result = apply_policy(report, policy)

    result = report.to_dict()
    result["redacted_text"] = report.redacted_text
    result["policy"] = policy_result

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="pii_scan",
        verdict="BLOCK" if policy_result["overall_action"] == "block" else "ALLOW",
        rule_id="pii_detection",
        original_action=f"PII scan ({len(text)} chars)",
        message=report.summary,
        suggestion="Remove or redact PII before sharing.",
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
    ))

    return json.dumps(_attach_attestation_payload(result), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Data Classification + Model Routing
# ═══════════════════════════════════════════════════════════════


async def classify_data(
    text: str,
    file_path: str = "",
) -> str:
    """Classify text content by data sensitivity level.

    Returns PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED with
    confidence score, PII findings, and content/path indicators.

    Args:
        text: Content to classify.
        file_path: Optional file path for path-based classification.

    Returns:
        JSON classification result.
    """
    from src.services.data_classifier import classify_text

    result = classify_text(text, file_path=file_path)

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="classify_data",
        verdict="ALLOW",
        rule_id="data_classification",
        original_action=f"classify ({result.sensitivity.label})",
        message=f"{result.sensitivity.label} (confidence {result.confidence})",
        suggestion="Review classification before sharing data externally.",
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
    ))

    return json.dumps(_attach_attestation_payload(result.to_dict()), indent=2)


async def check_model_routing(
    text: str,
    model: str,
    file_path: str = "",
) -> str:
    """Check if a model is allowed to access the given content.

    Classifies the content and evaluates model routing policy.
    Returns allow/warn/block/redact decision.

    Args:
        text: Content the model would receive.
        model: Model identifier (e.g. "gpt-4o", "claude-opus-4-20250514").
        file_path: Optional file path for classification context.

    Returns:
        JSON routing decision with action and reason.
    """
    from src.services.model_router import evaluate_routing

    decision = evaluate_routing(text, model, file_path=file_path)

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="check_model_routing",
        verdict="BLOCK" if decision.action == "block" else "ALLOW",
        rule_id="model_routing",
        original_action=f"route {model} for {decision.classification.sensitivity.label} data",
        message=decision.reason,
        suggestion="Use an approved model or redact sensitive data.",
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
    ))

    return json.dumps(_attach_attestation_payload(decision.to_dict()), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Cost Tracking
# ═══════════════════════════════════════════════════════════════


async def cost_report(
    period: str = "monthly",
    developer: str = "",
    team: str = "",
    model_filter: str = "",
) -> str:
    """Generate LLM cost report — aggregated by developer, team, model.

    Args:
        period: "daily", "weekly", or "monthly".
        developer: Filter by developer name.
        team: Filter by team name.
        model_filter: Filter by model pattern (wildcards supported).

    Returns:
        JSON cost report with breakdowns, trends, anomalies, and budget status.
    """
    from src.services.cost_tracker import generate_report

    report = generate_report(
        period=period, developer=developer, team=team,
        model_filter=model_filter,
    )

    _audit.log(AuditEntry(
        timestamp=time.time(),
        action_type="cost_report",
        verdict="ALLOW",
        rule_id="cost_tracking",
        original_action=f"cost report ({period})",
        message=f"${report.total_cost_usd:.2f} total, {report.event_count} events",
        suggestion="Review cost trends and anomalies regularly.",
        session_id=_session_id,
        agent_id=_agent_id,
        workspace=_workspace,
    ))

    return json.dumps(_attach_attestation_payload(report.to_dict()), indent=2)


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════


def main() -> None:
    """Run the gateway MCP server."""
    startup_integrity = _evaluate_policy_integrity(force=True)
    _audit_policy_integrity(startup_integrity, action="gateway_startup_integrity")

    logger.info(
        "gateway_starting",
        mode=_engine.config.mode.value,
        workspace=_workspace,
        policies=len(_engine.get_policies()),
        policy_integrity_verdict=startup_integrity.verdict,
        policy_integrity_rule=startup_integrity.rule_id,
    )
    gateway.run()


if __name__ == "__main__":
    main()
