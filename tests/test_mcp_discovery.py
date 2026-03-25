"""Tests for MCP Discovery & Supply Chain Audit."""

from __future__ import annotations

import json
from pathlib import Path

from src.services.mcp_discovery import (
    MCPAuditResult,
    MCPDiscoveryService,
    MCPServer,
    _assess_risk,
    _extract_servers_from_config,
)


class TestAssessRisk:
    """Tests for risk assessment logic."""

    def test_known_safe_server(self) -> None:
        """Known-safe servers get low risk."""
        level, reason = _assess_risk("codetrust-gateway", "python", ["-m", "src.gateway"])
        assert level == "low"
        assert "known-safe" in reason

    def test_npx_is_high_risk(self) -> None:
        """npx runtime pull is high risk."""
        level, reason = _assess_risk("my-server", "npx", ["some-package"])
        assert level == "high"
        assert "npx" in reason

    def test_uvx_is_high_risk(self) -> None:
        """uvx runtime pull is high risk."""
        level, _reason = _assess_risk("my-server", "uvx", ["--from", "pkg"])
        assert level == "high"

    def test_curl_is_high_risk(self) -> None:
        """curl in command is high risk."""
        level, _reason = _assess_risk("remote", "bash", ["-c", "curl http://evil.com"])
        assert level == "high"

    def test_unknown_binary_is_medium(self) -> None:
        """Unknown local binary gets medium risk."""
        level, reason = _assess_risk("custom-tool", "/usr/local/bin/custom", [])
        assert level == "medium"
        assert "unknown" in reason


class TestExtractServers:
    """Tests for config file parsing."""

    def test_standard_mcp_format(self) -> None:
        """Parse standard mcpServers format."""
        data = {
            "mcpServers": {
                "custom-llm-proxy": {
                    "command": "npx",
                    "args": ["-y", "@someone/mcp-server"],
                },
            },
        }
        servers = _extract_servers_from_config(data, "test.json", "claude_desktop")
        assert len(servers) == 1
        assert servers[0].name == "custom-llm-proxy"
        assert servers[0].command == "npx"
        assert servers[0].risk_level == "high"  # npx = high risk

    def test_nested_mcp_format(self) -> None:
        """Parse nested mcp.servers format."""
        data = {
            "mcp": {
                "servers": {
                    "codetrust": {
                        "command": "python",
                        "args": ["-m", "src.server"],
                    },
                },
            },
        }
        servers = _extract_servers_from_config(data, "test.json", "vscode")
        assert len(servers) == 1
        assert servers[0].name == "codetrust"
        assert servers[0].risk_level == "low"

    def test_empty_config(self) -> None:
        """Empty config returns no servers."""
        servers = _extract_servers_from_config({}, "test.json", "test")
        assert len(servers) == 0

    def test_invalid_server_entry(self) -> None:
        """Non-dict server entry is skipped."""
        data = {"mcpServers": {"bad": "not a dict"}}
        servers = _extract_servers_from_config(data, "test.json", "test")
        assert len(servers) == 0


class TestMCPDiscoveryService:
    """Tests for the discovery service."""

    def test_audit_returns_result(self) -> None:
        """Audit returns an MCPAuditResult."""
        svc = MCPDiscoveryService()
        result = svc.audit()
        assert isinstance(result, MCPAuditResult)
        assert result.configs_scanned > 0

    def test_audit_with_workspace(self, tmp_path: Path) -> None:
        """Audit scans project-local configs."""
        # Create a project-local .mcp.json
        mcp_config = tmp_path / ".mcp.json"
        mcp_config.write_text(json.dumps({
            "mcpServers": {
                "test-server": {"command": "node", "args": ["server.js"]},
            },
        }))
        svc = MCPDiscoveryService()
        result = svc.audit(workspace=tmp_path, include_project_local=True)
        local_servers = [s for s in result.servers if s.source_ide == "project_local"]
        assert len(local_servers) >= 1
        assert local_servers[0].name == "test-server"

    def test_build_report(self) -> None:
        """Report builds without error."""
        svc = MCPDiscoveryService()
        result = MCPAuditResult(
            servers=[
                MCPServer("test", "node", [], "config.json", "vscode", "medium", "unknown"),
            ],
            total_found=1, vetted_count=0, unvetted_count=1,
            high_risk_count=0, configs_scanned=1, configs_found=1,
        )
        report = svc.build_report(result)
        assert "MEDIUM" in report
        assert "test" in report
