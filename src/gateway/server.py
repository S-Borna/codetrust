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

import json
import os
import time
from dataclasses import asdict

import structlog
from mcp.server.fastmcp import FastMCP

from src.config import settings
from src.gateway.approvals import ApprovalExceptionStore, apply_exception_override
from src.gateway.audit import AuditEntry, AuditLogger
from src.gateway.interceptor import CommandInterceptor, InterceptResult, Verdict
from src.gateway.policies import GovernancePolicy, PolicyEngine
from src.gateway.policy_integrity import (
    PolicyIntegrityResult,
    get_policy_manifest_hash,
    verify_policy_integrity,
)
from src.services.governance_bundles import get_bundle_policy
from src.telemetry_client import send_telemetry

logger = structlog.get_logger()

SECONDS_PER_HOUR: int = 3_600
POLICY_INTEGRITY_CACHE_TTL_SECONDS: float = 5.0
TRUSTED_SESSION_TTL_SECONDS: int = 3_600
ALLOW_REASON_FALLBACK_MIN_LEN: int = 12
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


_engine = PolicyEngine.from_workspace(_workspace)
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
_last_integrity_check_at: float = 0.0
_last_integrity_result: PolicyIntegrityResult | None = None
_trusted_tokens: dict[str, dict[str, object]] = {}
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
        "policy_verdict": integrity.verdict,
        "policy_rule_id": integrity.rule_id,
    }


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


def _issue_trusted_token(*, reason: str, agent_id: str) -> tuple[str, float]:
    """Create and store a trusted-session token."""
    token = os.urandom(16).hex()
    expires_at = time.time() + TRUSTED_SESSION_TTL_SECONDS
    _trusted_tokens[token] = {
        "expires_at": expires_at,
        "agent_id": agent_id,
        "session_id": _session_id,
        "reason": reason,
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
    if token_agent_id and token_agent_id != agent_id:
        return False
    if token_session_id and token_session_id != _session_id:
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

    integrity_block = _integrity_block_payload()
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

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

    native_block = _native_enforcement_gate(tool_name="run_in_terminal")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

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

    native_block = _native_enforcement_gate(tool_name="create_file")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

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

    native_block = _native_enforcement_gate(tool_name="replace_string_in_file")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

    allow_reason_block = _allow_reason_gate(allow_reason=allow_reason)
    if allow_reason_block is not None:
        return json.dumps(allow_reason_block, indent=2)

    trusted_block = _trusted_execution_gate(trusted_token=trusted_token, agent_id=resolved_agent_id)
    if trusted_block is not None:
        return json.dumps(trusted_block, indent=2)

    integrity_block = _integrity_block_payload(proxy=True)
    if integrity_block is not None:
        return json.dumps(integrity_block, indent=2)

    # Validate the incoming new content as a file write
    combined_content = f"{old_string}\n---replaced-by---\n{new_string}"
    result = _interceptor.check_file_write(path, combined_content)
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

    native_block = _native_enforcement_gate(tool_name="edit_notebook_file")
    if native_block is not None:
        return json.dumps(native_block, indent=2)

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
            "policy_hash": get_policy_manifest_hash(_workspace),
        },
        "pending_approvals": len(_approval_store.list_pending()),
        "active_exceptions": len(_approval_store.list_active_exceptions()),
        "control_plane_ready": (
            _engine.config.enabled
            and _engine.config.trusted_execution_mode
            and _engine.config.deny_native_execution
            and _engine.config.require_allow_reason
            and _engine.config.session_binding_required
            and _engine.config.anti_bypass_checks
        ),
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
async def begin_trusted_session(reason: str, agent_id: str = "") -> str:
    """Start trusted execution session and return temporary trusted token."""
    actor = agent_id or _agent_id
    token, expires_at = _issue_trusted_token(reason=reason, agent_id=actor)
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
        metadata={"expires_at": expires_at},
    ))
    return json.dumps(_attach_attestation_payload({
        "status": _APPROVED_PREFIX,
        "trusted_token": token,
        "expires_at": expires_at,
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
async def simulate_policy(bundle_id: str, commands: list[str]) -> str:
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

    return json.dumps(_attach_attestation_payload({
        "bundle_id": bundle_id,
        "outcomes": outcomes,
    }), indent=2)


@gateway.tool(name="codetrust_governance_posture")
async def governance_posture() -> str:
    """Return machine-readable governance posture snapshot."""
    return json.dumps(_attach_attestation_payload(_build_governance_posture_payload()), indent=2)


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
