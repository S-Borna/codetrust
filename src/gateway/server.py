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

import structlog
from mcp.server.fastmcp import FastMCP

from src.config import settings
from src.gateway.audit import AuditEntry, AuditLogger
from src.gateway.interceptor import CommandInterceptor, InterceptResult, Verdict
from src.gateway.policies import GovernancePolicy, PolicyEngine
from src.telemetry_client import send_telemetry

logger = structlog.get_logger()

SECONDS_PER_HOUR: int = 3_600

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

gateway = FastMCP("codetrust-gateway")


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
    result = _interceptor.check_terminal(command)

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
        return json.dumps({
            **result_dict,
            "action": "BLOCKED — Do not execute this command.",
            "alternative": result.suggestion,
            "root_cause": result.root_cause or result.message,
            "safe_fix": result.safe_fix or result.suggestion,
        }, indent=2)

    return json.dumps(result_dict, indent=2)


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
    result = _interceptor.check_file_write(path, content)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    result_dict = result.to_dict()
    effective_verdict = result.verdict.value
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        result_dict["verdict"] = "WARN"
        result_dict["message"] = f"[AUDIT MODE] {result.message}"
        effective_verdict = "WARN"

    _emit_gateway_telemetry(result=result, effective_verdict=effective_verdict)

    return json.dumps(result_dict, indent=2)


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
    result = _interceptor.check_file_delete(path)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    _emit_gateway_telemetry(result=result, effective_verdict=result.verdict.value)

    return json.dumps(result.to_dict(), indent=2)


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
    result = _interceptor.check_package_install(package, registry=registry)

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    _emit_gateway_telemetry(result=result, effective_verdict=result.verdict.value)

    return json.dumps(result.to_dict(), indent=2)


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


def _proxy_result(result: InterceptResult) -> str:
    """Serialise a proxy intercept result with APPROVED / BLOCKED header."""
    effective_verdict = result.verdict.value
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        effective_verdict = "WARN"

    _emit_gateway_telemetry(result=result, effective_verdict=effective_verdict)
    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    if result.blocked and _engine.active:
        return json.dumps({
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
        }, indent=2)

    return json.dumps({
        "status": _APPROVED_PREFIX,
        "verdict": effective_verdict,
        "rule_id": result.rule_id,
        "message": result.message or "Action validated — you may proceed.",
        "instruction": (
            "You may now call the native tool with the EXACT same parameters."
        ),
    }, indent=2)


@gateway.tool(name="codetrust_run_in_terminal")
async def proxy_run_in_terminal(command: str) -> str:
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
    result = _interceptor.check_terminal(command)
    return _proxy_result(result)


@gateway.tool(name="codetrust_create_file")
async def proxy_create_file(path: str, content: str) -> str:
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
    result = _interceptor.check_file_write(path, content)
    return _proxy_result(result)


@gateway.tool(name="codetrust_replace_string_in_file")
async def proxy_replace_string_in_file(
    path: str,
    old_string: str,
    new_string: str,
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
    # Validate the incoming new content as a file write
    combined_content = f"{old_string}\n---replaced-by---\n{new_string}"
    result = _interceptor.check_file_write(path, combined_content)
    return _proxy_result(result)


@gateway.tool(name="codetrust_edit_notebook")
async def proxy_edit_notebook(path: str, new_code: str) -> str:
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
    result = _interceptor.check_file_write(path, new_code)
    return _proxy_result(result)


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
        f"**Agent:** {_agent_id}",
        f"**Session:** {_session_id}",
        f"**Policies:** {enabled_count} active, {disabled_count} disabled",
        f"**Audit log:** {_audit.path}",
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


# ═══════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════


def main() -> None:
    """Run the gateway MCP server."""
    logger.info(
        "gateway_starting",
        mode=_engine.config.mode.value,
        workspace=_workspace,
        policies=len(_engine.get_policies()),
    )
    gateway.run()


if __name__ == "__main__":
    main()
