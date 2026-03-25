# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""MCP Discovery & Supply Chain Audit.

Scans IDE configuration files for MCP server definitions.
Classifies each as vetted or unvetted. Flags risky ones.
"""

from __future__ import annotations

import json
import platform
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger()

# ─────────────────────────────────────────────────────────────────
#  Known-safe MCP servers
# ─────────────────────────────────────────────────────────────────

KNOWN_SAFE_SERVERS: frozenset[str] = frozenset({
    "codetrust", "codetrust-gateway",
    "filesystem", "github", "gitlab", "bitbucket",
    "slack", "notion", "linear",
    "postgres", "sqlite", "mysql", "redis",
    "puppeteer", "playwright",
    "brave-search", "tavily",
    "memory", "sequential-thinking",
    "fetch", "everything",
    "docker", "kubernetes",
    "sentry", "datadog",
    "stripe",
})

# ─────────────────────────────────────────────────────────────────
#  Config file locations per IDE
# ─────────────────────────────────────────────────────────────────

_IS_MACOS = platform.system() == "Darwin"
_IS_LINUX = platform.system() == "Linux"

_HOME = Path.home()

_APP_SUPPORT = _HOME / "Library" / "Application Support" if _IS_MACOS else _HOME / ".config"


def _build_config_paths() -> dict[str, list[Path]]:
    """Build IDE-specific MCP config paths for the current OS."""
    paths: dict[str, list[Path]] = {
        "claude_desktop": [
            _APP_SUPPORT / "Claude" / "claude_desktop_config.json",
            _HOME / ".config" / "claude" / "claude_desktop_config.json",
        ],
        "claude_code": [
            _HOME / ".claude" / "settings.json",
            _HOME / ".claude.json",
        ],
        "cursor": [
            _APP_SUPPORT / "Cursor" / "User" / "globalStorage" / "cursor.mcp" / "config.json",
            _HOME / ".cursor" / "mcp.json",
        ],
        "vscode": [
            _APP_SUPPORT / "Code" / "User" / "settings.json",
        ],
        "cline": [
            _APP_SUPPORT / "Code" / "User" / "globalStorage"
            / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
        ],
        "windsurf": [
            _APP_SUPPORT / "Windsurf" / "User" / "settings.json",
            _HOME / ".windsurf" / "mcp.json",
        ],
    }
    return paths


# Project-local config filenames (relative to workspace root)
PROJECT_LOCAL_CONFIGS: list[str] = [
    ".mcp.json",
    ".mcp/config.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
]

# ─────────────────────────────────────────────────────────────────
#  Types
# ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MCPServer:
    """A discovered MCP server definition."""

    name: str
    command: str
    args: list[str]
    source_config: str
    source_ide: str
    risk_level: str  # "low", "medium", "high"
    risk_reason: str


@dataclass
class MCPAuditResult:
    """Result of an MCP discovery audit."""

    servers: list[MCPServer] = field(default_factory=list)
    total_found: int = 0
    vetted_count: int = 0
    unvetted_count: int = 0
    high_risk_count: int = 0
    configs_scanned: int = 0
    configs_found: int = 0


# ─────────────────────────────────────────────────────────────────
#  Risk assessment
# ─────────────────────────────────────────────────────────────────

_HIGH_RISK_PATTERNS: list[str] = [
    "npx", "uvx", "bunx", "pnpx",  # Runtime package pull
    "curl", "wget",                  # Remote fetch
    "http://", "https://",           # External URLs
]


def _assess_risk(name: str, command: str, args: list[str]) -> tuple[str, str]:
    """Assess risk level of an MCP server.

    Returns (risk_level, risk_reason).
    """
    name_lower = name.lower()

    # Known-safe
    for safe in KNOWN_SAFE_SERVERS:
        if safe in name_lower:
            return "low", "known-safe server"

    # High risk: runtime package pull
    full_cmd = f"{command} {' '.join(args)}".lower()
    for pattern in _HIGH_RISK_PATTERNS:
        if pattern in full_cmd:
            return "high", f"runtime dependency pull via '{pattern}'"

    # Medium: unknown local binary
    return "medium", "unknown server — not in vetted list"


# ─────────────────────────────────────────────────────────────────
#  Config parsing
# ─────────────────────────────────────────────────────────────────


def _extract_servers_from_config(
    data: dict[str, object],
    source_path: str,
    source_ide: str,
) -> list[MCPServer]:
    """Extract MCP server definitions from a parsed JSON config."""
    servers: list[MCPServer] = []

    # Standard format: {"mcpServers": {"name": {"command": "...", "args": [...]}}}
    mcp_section = data.get("mcpServers")
    if mcp_section is None:
        # Alternative: nested under a key
        mcp_section = data.get("mcp", {})
        if isinstance(mcp_section, dict):
            mcp_section = mcp_section.get("servers", mcp_section.get("mcpServers"))

    if not isinstance(mcp_section, dict):
        return servers

    for name, config in mcp_section.items():
        if not isinstance(config, dict):
            continue
        command = str(config.get("command", ""))
        args_raw = config.get("args", [])
        args = [str(a) for a in args_raw] if isinstance(args_raw, list) else []

        risk_level, risk_reason = _assess_risk(name, command, args)

        servers.append(MCPServer(
            name=name,
            command=command,
            args=args,
            source_config=source_path,
            source_ide=source_ide,
            risk_level=risk_level,
            risk_reason=risk_reason,
        ))

    return servers


# ─────────────────────────────────────────────────────────────────
#  MCPDiscoveryService
# ─────────────────────────────────────────────────────────────────


class MCPDiscoveryService:
    """Scan IDE configs for MCP server definitions."""

    def audit(
        self,
        workspace: Path | None = None,
        include_project_local: bool = True,
    ) -> MCPAuditResult:
        """Run MCP discovery audit across all known IDE config locations.

        Args:
            workspace: Project root for project-local config scanning.
            include_project_local: Whether to scan .mcp.json etc.
        """
        result = MCPAuditResult()
        config_paths = _build_config_paths()

        # Scan IDE-global configs
        for ide, paths in config_paths.items():
            for config_path in paths:
                result.configs_scanned += 1
                expanded = config_path.expanduser()
                if not expanded.exists():
                    continue
                result.configs_found += 1
                servers = self._scan_config_file(expanded, ide)
                result.servers.extend(servers)

        # Scan project-local configs
        if include_project_local and workspace is not None:
            for rel_path in PROJECT_LOCAL_CONFIGS:
                result.configs_scanned += 1
                config_path = workspace / rel_path
                if config_path.exists():
                    result.configs_found += 1
                    servers = self._scan_config_file(config_path, "project_local")
                    result.servers.extend(servers)

        # Deduplicate by name + source
        seen: set[tuple[str, str]] = set()
        unique: list[MCPServer] = []
        for server in result.servers:
            key = (server.name, server.source_ide)
            if key not in seen:
                seen.add(key)
                unique.append(server)
        result.servers = unique

        # Compute summary
        result.total_found = len(result.servers)
        result.vetted_count = sum(1 for s in result.servers if s.risk_level == "low")
        result.unvetted_count = sum(1 for s in result.servers if s.risk_level != "low")
        result.high_risk_count = sum(1 for s in result.servers if s.risk_level == "high")

        logger.info(
            "mcp_audit_complete",
            total=result.total_found,
            vetted=result.vetted_count,
            unvetted=result.unvetted_count,
            high_risk=result.high_risk_count,
            configs_scanned=result.configs_scanned,
            configs_found=result.configs_found,
        )
        return result

    def _scan_config_file(
        self,
        path: Path,
        source_ide: str,
    ) -> list[MCPServer]:
        """Parse a single config file and extract MCP servers."""
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
            if not isinstance(data, dict):
                return []
            return _extract_servers_from_config(data, str(path), source_ide)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug(
                "mcp_config_parse_error",
                path=str(path),
                error=str(exc),
            )
            return []

    def build_report(self, result: MCPAuditResult) -> str:
        """Build markdown report from audit result."""
        lines: list[str] = [
            "## MCP Server Audit",
            "",
            f"Scanned {result.configs_scanned} config locations, "
            f"found {result.configs_found} config files.",
            f"**{result.total_found} servers** | "
            f"{result.vetted_count} vetted | "
            f"{result.unvetted_count} unvetted | "
            f"{result.high_risk_count} high-risk",
            "",
        ]

        if not result.servers:
            lines.append("No MCP servers found.")
            return "\n".join(lines)

        # Group by risk
        for risk in ("high", "medium", "low"):
            group = [s for s in result.servers if s.risk_level == risk]
            if not group:
                continue
            emoji = {"high": "!!!", "medium": "!", "low": ""}[risk]
            lines.append(f"### {risk.upper()} risk {emoji}")
            lines.append("")
            for s in group:
                cmd_preview = f"`{s.command} {' '.join(s.args[:3])}`"
                lines.append(
                    f"- **{s.name}** ({s.source_ide}) — {cmd_preview}"
                )
                lines.append(f"  {s.risk_reason}")
            lines.append("")

        return "\n".join(lines)
