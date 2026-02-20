# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Policy engine — configurable governance rules for AI agent behavior.

Policies define what an AI agent is allowed to do within a workspace.
They are loaded from .codetrust.toml and can be overridden per-project
or disabled entirely by the user.

Hierarchy:
    1. Built-in defaults (always present)
    2. .codetrust.toml [codetrust.governance] (project override)
    3. Environment variable CODETRUST_GOVERNANCE_MODE (global override)
    4. User can disable any policy via disabled_rules
"""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


class GovernanceMode(StrEnum):
    """Operating mode for the governance engine."""

    ENFORCE = "enforce"   # Block violations, log everything
    AUDIT = "audit"       # Allow all, but log violations
    OFF = "off"           # Disabled — no interception


class PolicyVerdict(StrEnum):
    """Policy evaluation result."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class GovernancePolicy:
    """A single governance policy definition."""

    id: str
    description: str
    enabled: bool = True
    severity: PolicyVerdict = PolicyVerdict.BLOCK


@dataclass
class GovernanceConfig:
    """Full governance configuration for a workspace."""

    # Master switch
    enabled: bool = True
    mode: GovernanceMode = GovernanceMode.ENFORCE

    # Terminal command governance
    block_heredoc: bool = True
    block_eval: bool = True
    block_sudo: bool = False
    block_rm_rf: bool = True
    block_curl_pipe_sh: bool = True
    block_git_push: bool = True
    block_chmod_777: bool = True

    # File governance
    protected_paths: list[str] = field(default_factory=lambda: [
        "LICENSE", ".env", ".env.production",
    ])
    scan_before_write: bool = True

    # Package governance
    verify_before_install: bool = True
    block_suspicious_packages: bool = True

    # Audit
    audit_enabled: bool = True
    audit_path: str = ".codetrust/audit.jsonl"

    # Webhooks
    webhook_url: str = ""
    webhook_provider: str = "generic"   # slack, teams, pagerduty, generic
    webhook_on_block: bool = True
    webhook_on_warn: bool = False

    # Data retention
    retention_days: int = 90

    # User overrides
    disabled_rules: set[str] = field(default_factory=set)


class PolicyEngine:
    """Evaluates actions against governance policies.

    Loads configuration from .codetrust.toml and environment,
    applies policies, and returns verdicts.

    Usage:
        engine = PolicyEngine.from_workspace("/path/to/project")
        config = engine.config

        # Check if heredoc is blocked
        if engine.is_blocked("gateway_heredoc"):
            ...
    """

    def __init__(self, config: GovernanceConfig | None = None):
        self._config = config or GovernanceConfig()

    @property
    def config(self) -> GovernanceConfig:
        return self._config

    @property
    def active(self) -> bool:
        """Whether governance is actively enforcing."""
        return self._config.enabled and self._config.mode == GovernanceMode.ENFORCE

    @property
    def auditing(self) -> bool:
        """Whether governance is in audit mode (log but don't block)."""
        return self._config.enabled and self._config.mode == GovernanceMode.AUDIT

    def is_blocked(self, rule_id: str) -> bool:
        """Check if a specific rule would block in current mode."""
        if not self._config.enabled:
            return False
        if self._config.mode == GovernanceMode.OFF:
            return False
        if rule_id in self._config.disabled_rules:
            return False
        return self._config.mode != GovernanceMode.AUDIT

    def should_log(self, rule_id: str) -> bool:
        """Check if a rule violation should be logged."""
        if not self._config.enabled:
            return False
        return self._config.audit_enabled

    def get_disabled_rules(self) -> set[str]:
        """Get the set of currently disabled rules."""
        disabled = set(self._config.disabled_rules)

        # Map config flags to rule IDs
        flag_map = {
            "block_heredoc": "gateway_heredoc",
            "block_eval": "gateway_eval",
            "block_sudo": "gateway_sudo_su",
            "block_rm_rf": "gateway_rm_rf_root",
            "block_curl_pipe_sh": "gateway_curl_pipe_sh",
            "block_git_push": "gateway_git_push",
            "block_chmod_777": "gateway_chmod_777",
        }

        for flag, rule_id in flag_map.items():
            if not getattr(self._config, flag, True):
                disabled.add(rule_id)
                # Also add the force variant
                if rule_id == "gateway_git_push":
                    disabled.add("gateway_git_force_push")

        return disabled

    def get_protected_paths(self) -> list[str]:
        """Get the list of protected file paths."""
        return list(self._config.protected_paths)

    def get_policies(self) -> list[GovernancePolicy]:
        """Return all policies with current enabled state."""
        flag_map = {
            "gateway_heredoc": ("Block heredoc in terminal commands", "block_heredoc"),
            "gateway_eval": ("Block eval in terminal commands", "block_eval"),
            "gateway_curl_pipe_sh": ("Block curl|sh piping", "block_curl_pipe_sh"),
            "gateway_rm_rf_root": ("Block rm -rf / at root", "block_rm_rf"),
            "gateway_chmod_777": ("Block chmod " + "777", "block_chmod_777"),
            "gateway_sudo_su": ("Warn on sudo su", "block_sudo"),
            "gateway_git_push": ("Block git push by AI agent", "block_git_push"),
            "gateway_git_force_push": ("Block git force push", "block_git_push"),
            "gateway_dd_of": ("Block dd to block device", None),
            "gateway_pip_install_unverified": ("Block unverified pip install", None),
            "gateway_env_secret_export": ("Block secret export in terminal", None),
            "gateway_content_eval": ("Warn on eval/exec in file writes", None),
            "gateway_content_secret": ("Block hardcoded secrets in file writes", None),
            "gateway_protected_path": ("Warn on protected file writes", None),
            "gateway_delete_protected": ("Block protected file deletion", None),
            "gateway_suspicious_package": ("Warn on suspicious package names", "block_suspicious_packages"),
        }

        policies = []
        disabled = self.get_disabled_rules()

        for rule_id, (desc, _flag) in flag_map.items():
            enabled = rule_id not in disabled
            if rule_id in self._config.disabled_rules:
                enabled = False
            policies.append(GovernancePolicy(
                id=rule_id,
                description=desc,
                enabled=enabled,
            ))

        return policies

    @staticmethod
    def _load_toml_data(workspace: Path) -> dict:
        """Load TOML configuration from .codetrust.toml or pyproject.toml."""
        codetrust_toml = workspace / ".codetrust.toml"
        pyproject_toml = workspace / "pyproject.toml"

        if codetrust_toml.is_file():
            with open(codetrust_toml, "rb") as f:
                raw = tomllib.load(f)
                return raw.get("codetrust", raw)
        if pyproject_toml.is_file():
            with open(pyproject_toml, "rb") as f:
                raw = tomllib.load(f)
                return raw.get("tool", {}).get("codetrust", {})
        return {}

    @staticmethod
    def _apply_terminal_config(config: GovernanceConfig, terminal: dict) -> None:
        """Apply terminal governance policy settings from TOML."""
        config.block_heredoc = terminal.get("block_heredoc", config.block_heredoc)
        config.block_eval = terminal.get("block_eval", config.block_eval)
        config.block_sudo = terminal.get("block_sudo", config.block_sudo)
        config.block_rm_rf = terminal.get("block_rm_rf", config.block_rm_rf)
        config.block_curl_pipe_sh = terminal.get("block_curl_pipe_sh", config.block_curl_pipe_sh)
        config.block_git_push = terminal.get("block_git_push", config.block_git_push)
        config.block_chmod_777 = terminal.get("block_chmod_777", config.block_chmod_777)

    @staticmethod
    def _apply_resource_config(config: GovernanceConfig, gov: dict) -> None:
        """Apply file, package, audit, and webhook settings from TOML."""
        files = gov.get("files", {})
        config.protected_paths = files.get("protected_paths", config.protected_paths)
        config.scan_before_write = files.get("scan_before_write", config.scan_before_write)

        packages = gov.get("packages", {})
        config.verify_before_install = packages.get(
            "verify_before_install", config.verify_before_install,
        )
        config.block_suspicious_packages = packages.get(
            "block_suspicious_packages", config.block_suspicious_packages,
        )

        audit = gov.get("audit", {})
        config.audit_enabled = audit.get("enabled", config.audit_enabled)
        config.audit_path = audit.get("path", config.audit_path)
        config.retention_days = audit.get("retention_days", config.retention_days)

        webhooks = gov.get("webhooks", {})
        config.webhook_url = webhooks.get("url", config.webhook_url)
        config.webhook_provider = webhooks.get("provider", config.webhook_provider)
        config.webhook_on_block = webhooks.get("on_block", config.webhook_on_block)
        config.webhook_on_warn = webhooks.get("on_warn", config.webhook_on_warn)

    @staticmethod
    def _apply_governance_section(config: GovernanceConfig, gov: dict) -> None:
        """Apply the [codetrust.governance] TOML section to config."""
        if not gov:
            return

        config.enabled = gov.get("enabled", config.enabled)
        mode_str = gov.get("mode", config.mode.value)
        with contextlib.suppress(ValueError):
            config.mode = GovernanceMode(mode_str)

        PolicyEngine._apply_terminal_config(config, gov.get("terminal", {}))
        PolicyEngine._apply_resource_config(config, gov)

        disabled = gov.get("disabled_rules", [])
        config.disabled_rules = set(disabled)

    @staticmethod
    def _apply_env_overrides(config: GovernanceConfig) -> None:
        """Apply environment variable overrides to governance config."""
        env_mode = os.environ.get("CODETRUST_GOVERNANCE_MODE")
        if env_mode:
            with contextlib.suppress(ValueError):
                config.mode = GovernanceMode(env_mode.lower())

        env_enabled = os.environ.get("CODETRUST_GOVERNANCE_ENABLED")
        if env_enabled is not None:
            config.enabled = env_enabled.lower() in ("true", "1", "yes")

    @classmethod
    def from_workspace(cls, workspace_path: str | Path) -> PolicyEngine:
        """Load governance config from workspace .codetrust.toml or pyproject.toml.

        Falls back to defaults if no config file exists.
        Environment variable CODETRUST_GOVERNANCE_MODE overrides file config.

        Args:
            workspace_path: Path to the workspace root.

        Returns:
            Configured PolicyEngine instance.
        """
        workspace = Path(workspace_path)
        config = GovernanceConfig()

        toml_data = cls._load_toml_data(workspace)
        gov = toml_data.get("governance", {})
        cls._apply_governance_section(config, gov)
        cls._apply_env_overrides(config)

        return cls(config)

    def _build_core_toml_lines(self) -> list[str]:
        """Build core TOML governance configuration lines."""
        return [
            "[codetrust.governance]",
            f'enabled = {str(self._config.enabled).lower()}',
            f'mode = "{self._config.mode.value}"',
            "",
            "[codetrust.governance.terminal]",
            f"block_heredoc = {str(self._config.block_heredoc).lower()}",
            f"block_eval = {str(self._config.block_eval).lower()}",
            f"block_sudo = {str(self._config.block_sudo).lower()}",
            f"block_rm_rf = {str(self._config.block_rm_rf).lower()}",
            f"block_curl_pipe_sh = {str(self._config.block_curl_pipe_sh).lower()}",
            f"block_git_push = {str(self._config.block_git_push).lower()}",
            f"block_chmod_777 = {str(self._config.block_chmod_777).lower()}",
            "",
            "[codetrust.governance.files]",
            f"protected_paths = {self._config.protected_paths!r}",
            f"scan_before_write = {str(self._config.scan_before_write).lower()}",
            "",
            "[codetrust.governance.packages]",
            f"verify_before_install = {str(self._config.verify_before_install).lower()}",
            f"block_suspicious_packages = {str(self._config.block_suspicious_packages).lower()}",
            "",
            "[codetrust.governance.audit]",
            f"enabled = {str(self._config.audit_enabled).lower()}",
            f'path = "{self._config.audit_path}"',
            f"retention_days = {self._config.retention_days}",
        ]

    def _build_webhook_toml_lines(self) -> list[str]:
        """Build TOML lines for webhooks and disabled rules."""
        lines = ["", "[codetrust.governance.webhooks]"]
        if self._config.webhook_url:
            lines.append(f'url = "{self._config.webhook_url}"')
            lines.append(f'provider = "{self._config.webhook_provider}"')
            lines.append(f"on_block = {str(self._config.webhook_on_block).lower()}")
            lines.append(f"on_warn = {str(self._config.webhook_on_warn).lower()}")
        else:
            lines.append('# url = "https://hooks.slack' + '.com/services/T.../B.../xxx"')
            lines.append('# provider = "slack"')

        if self._config.disabled_rules:
            lines.append("")
            sorted_rules = sorted(self._config.disabled_rules)
            lines.append(f"disabled_rules = {sorted_rules!r}")
        return lines

    def to_toml_section(self) -> str:
        """Generate TOML configuration section for .codetrust.toml.

        Returns:
            TOML string for the [codetrust.governance] section.
        """
        lines = self._build_core_toml_lines()
        lines.extend(self._build_webhook_toml_lines())
        return "\n".join(lines)
