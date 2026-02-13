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
    python -m src.gateway.server

    # In Claude Desktop config:
    {
        "mcpServers": {
            "codetrust-gateway": {
                "command": "python",
                "args": ["-m", "src.gateway.server"],
                "cwd": "/path/to/codetrust"
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

from src.gateway.audit import AuditLogger
from src.gateway.interceptor import CommandInterceptor, Verdict
from src.gateway.policies import PolicyEngine

logger = structlog.get_logger()

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
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        result_dict = result.to_dict()
        result_dict["verdict"] = "WARN"
        result_dict["message"] = f"[AUDIT MODE] {result.message}"
    else:
        result_dict = result.to_dict()

    _audit.log_intercept(result, workspace=_workspace, session_id=_session_id, agent_id=_agent_id)

    if result.blocked and _engine.active:
        return json.dumps({
            **result_dict,
            "action": "BLOCKED — Do not execute this command.",
            "alternative": result.suggestion,
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
    if _engine.auditing and result.verdict == Verdict.BLOCK:
        result_dict["verdict"] = "WARN"
        result_dict["message"] = f"[AUDIT MODE] {result.message}"

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

    return json.dumps(result.to_dict(), indent=2)


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
        "",
        "## Active Policies",
        "",
        "| Policy | Status | Description |",
        "|--------|--------|-------------|",
    ]

    for policy in policies:
        status = "Active" if policy.enabled else "Disabled"
        lines.append(f"| `{policy.id}` | {status} | {policy.description} |")

    if config.protected_paths:
        lines.extend([
            "",
            "## Protected Files",
            "",
        ])
        for path in config.protected_paths:
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

    return "\n".join(lines)


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
    since = time.time() - (hours * 3600)
    entries = _audit.get_entries(
        since=since,
        verdict=verdict if verdict else None,
        limit=limit,
    )

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
        ts = time.strftime("%H:%M:%S", time.localtime(entry.timestamp))
        action = entry.original_action[:50]
        if len(entry.original_action) > 50:
            action += "..."
        agent = entry.agent_id or "—"
        lines.append(f"| {ts} | {agent} | {entry.verdict} | `{entry.rule_id}` | {action} |")

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
