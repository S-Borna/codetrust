"""Command interceptor — validates AI agent actions before execution.

Parses terminal commands, file write operations, and tool calls
against governance policies. Returns ALLOW/BLOCK/WARN verdicts
with explanations and suggested alternatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class ActionType(StrEnum):
    """Types of actions an AI agent can take."""

    TERMINAL_COMMAND = "terminal_command"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    PACKAGE_INSTALL = "package_install"
    HTTP_REQUEST = "http_request"


class Verdict(StrEnum):
    """Interceptor verdict for an action."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARN = "WARN"


@dataclass
class InterceptResult:
    """Result of intercepting an action."""

    verdict: Verdict
    action_type: ActionType
    original_action: str
    rule_id: str = ""
    message: str = ""
    suggestion: str = ""
    metadata: dict = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.verdict == Verdict.BLOCK

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "action_type": self.action_type.value,
            "original_action": self.original_action,
            "rule_id": self.rule_id,
            "message": self.message,
            "suggestion": self.suggestion,
        }


# ═══════════════════════════════════════════════════════════════
#  Terminal command patterns — deterministic regex matching
# ═══════════════════════════════════════════════════════════════

_TERMINAL_RULES: list[dict] = [
    {
        "id": "gateway_heredoc",
        "pattern": r"<<[-']?\s*[\w\"']+",
        "message": "Heredoc detected in terminal command. Heredocs corrupt files via shell escaping.",
        "suggestion": "Use the create_file or replace_string_in_file tool instead.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_eval",
        "pattern": r"\beval\s+",
        "message": "Shell eval detected. Arbitrary code execution risk.",
        "suggestion": "Execute commands directly without eval.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_curl_pipe_sh",
        "pattern": r"curl\s+.*\|\s*(ba)?sh",
        "message": "Piping curl to shell is a remote code execution vector.",
        "suggestion": "Download the script first, inspect it, then execute.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_rm_rf_root",
        "pattern": r"rm\s+-[rR]f?\s+/(?:\s|$)",
        "message": "Recursive delete at root path. Catastrophic data loss risk.",
        "suggestion": "Specify an explicit subdirectory path.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_chmod_777",
        "pattern": r"chmod\s+777\b",
        "message": "chmod 777 grants all permissions to all users.",
        "suggestion": "Use specific permissions like chmod 755 or chmod 644.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_sudo_su",
        "pattern": r"\bsudo\s+su\b",
        "message": "Switching to root user. Elevated privilege risk.",
        "suggestion": "Run specific commands with sudo instead of opening a root shell.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_dd_of",
        "pattern": r"\bdd\s+.*of=/dev/",
        "message": "Writing directly to block device. Data destruction risk.",
        "suggestion": "Verify the target device carefully before proceeding.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_git_push",
        "pattern": r"\bgit\s+push\b",
        "message": "AI agents must not push to remote repositories.",
        "suggestion": "Stage and commit changes. The user will push manually.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_git_force_push",
        "pattern": r"\bgit\s+push\s+.*--force",
        "message": "Force push rewrites remote history. Forbidden for AI agents.",
        "suggestion": "Never force push. Let the user handle remote operations.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_pip_install_unverified",
        "pattern": r"pip\s+install\s+--no-verify",
        "message": "Installing packages without verification bypasses integrity checks.",
        "suggestion": "Remove --no-verify flag.",
        "severity": Verdict.BLOCK,
    },
    {
        "id": "gateway_env_secret_export",
        "pattern": (
            r"export\s+(?:API_KEY|SECRET|PASSWORD|TOKEN|CREDENTIALS)\s*="
            r'["\'][^"\']{8,}["\']'
        ),
        "message": "Exporting secret value in terminal. Will appear in shell history.",
        "suggestion": "Use .env files or a secrets manager.",
        "severity": Verdict.BLOCK,
    },
]

# ═══════════════════════════════════════════════════════════════
#  File content patterns — catch dangerous writes
# ═══════════════════════════════════════════════════════════════

_CONTENT_RULES: list[dict] = [
    {
        "id": "gateway_content_eval",
        "pattern": r"\b(eval|exec)\s*\(",
        "message": "eval/exec detected in file content.",
        "suggestion": "Use safe alternatives to eval/exec.",
        "severity": Verdict.WARN,
    },
    {
        "id": "gateway_content_secret",
        "pattern": (
            r'(?i)(api[_-]?key|secret|password|token|credentials)'
            r'\s*[:=]\s*["\'][^"\']{8,}["\']'
        ),
        "message": "Hardcoded secret detected in file content.",
        "suggestion": "Use environment variables or a secrets manager.",
        "severity": Verdict.BLOCK,
    },
]


class CommandInterceptor:
    """Validates AI agent actions against governance rules.

    Usage:
        interceptor = CommandInterceptor()
        result = interceptor.check_terminal("cat > file.py << 'EOF'")
        if result.blocked:
            return result.message  # Don't execute
    """

    def __init__(
        self,
        *,
        enabled: bool = True,
        disabled_rules: set[str] | None = None,
        protected_paths: list[str] | None = None,
        workspace: str | None = None,
    ):
        self._enabled = enabled
        self._disabled_rules = disabled_rules or set()
        self._protected_paths = protected_paths or []

        # Merge built-in + custom rules
        terminal_rules = list(_TERMINAL_RULES)
        content_rules = list(_CONTENT_RULES)

        if workspace:
            from src.gateway.custom_rules import load_custom_rules

            custom_terminal, custom_content = load_custom_rules(workspace)
            terminal_rules.extend(custom_terminal)
            content_rules.extend(custom_content)

        self._compiled_terminal = [
            {**rule, "_re": re.compile(rule["pattern"])}
            for rule in terminal_rules
        ]
        self._compiled_content = [
            {**rule, "_re": re.compile(rule["pattern"])}
            for rule in content_rules
        ]

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    def check_terminal(self, command: str) -> InterceptResult:
        """Validate a terminal command before execution.

        Args:
            command: The shell command to validate.

        Returns:
            InterceptResult with verdict ALLOW, WARN, or BLOCK.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.TERMINAL_COMMAND,
                original_action=command,
                rule_id="governance_disabled",
                message="Governance is disabled.",
            )

        for rule in self._compiled_terminal:
            if rule["id"] in self._disabled_rules:
                continue
            if rule["_re"].search(command):
                return InterceptResult(
                    verdict=rule["severity"],
                    action_type=ActionType.TERMINAL_COMMAND,
                    original_action=command,
                    rule_id=rule["id"],
                    message=rule["message"],
                    suggestion=rule["suggestion"],
                )

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.TERMINAL_COMMAND,
            original_action=command,
        )

    def check_file_write(
        self,
        path: str,
        content: str,
    ) -> InterceptResult:
        """Validate file content before writing.

        Args:
            path: Target file path.
            content: Content to be written.

        Returns:
            InterceptResult with verdict.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.FILE_WRITE,
                original_action=path,
            )

        # Check protected paths
        for protected in self._protected_paths:
            if path.endswith(protected):
                return InterceptResult(
                    verdict=Verdict.WARN,
                    action_type=ActionType.FILE_WRITE,
                    original_action=path,
                    rule_id="gateway_protected_path",
                    message=f"Writing to protected file: {protected}",
                    suggestion="Verify this write is intentional.",
                )

        # Check content rules
        for rule in self._compiled_content:
            if rule["id"] in self._disabled_rules:
                continue
            if rule["_re"].search(content):
                return InterceptResult(
                    verdict=rule["severity"],
                    action_type=ActionType.FILE_WRITE,
                    original_action=path,
                    rule_id=rule["id"],
                    message=rule["message"],
                    suggestion=rule["suggestion"],
                    metadata={"file": path},
                )

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.FILE_WRITE,
            original_action=path,
        )

    def check_file_delete(self, path: str) -> InterceptResult:
        """Validate file deletion.

        Args:
            path: File path to be deleted.

        Returns:
            InterceptResult with verdict.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.FILE_DELETE,
                original_action=path,
            )

        for protected in self._protected_paths:
            if path.endswith(protected):
                return InterceptResult(
                    verdict=Verdict.BLOCK,
                    action_type=ActionType.FILE_DELETE,
                    original_action=path,
                    rule_id="gateway_delete_protected",
                    message=f"Cannot delete protected file: {protected}",
                    suggestion="Protected files require manual deletion.",
                )

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.FILE_DELETE,
            original_action=path,
        )

    def check_package_install(
        self,
        package: str,
        *,
        registry: str = "pypi",
    ) -> InterceptResult:
        """Validate a package before installation.

        Note: This is a structural check only. Live registry
        verification is handled by the existing RegistryService.

        Args:
            package: Package name to install.
            registry: Target registry (pypi, npm, etc.).

        Returns:
            InterceptResult with verdict.
        """
        if not self._enabled:
            return InterceptResult(
                verdict=Verdict.ALLOW,
                action_type=ActionType.PACKAGE_INSTALL,
                original_action=package,
            )

        # Flag suspicious package names (typosquatting indicators)
        suspicious_patterns = [
            (r"^[a-z]{1,2}$", "Single/double-letter package names are suspicious."),
            (r"[-_](dev|test|debug|hack|pwn|exploit)", "Package name contains suspicious suffix."),
            (r"^(python|pip|setup|install|os|sys|http)[-_]", "Package name mimics stdlib module."),
        ]

        for pattern, msg in suspicious_patterns:
            if re.search(pattern, package, re.IGNORECASE):
                return InterceptResult(
                    verdict=Verdict.WARN,
                    action_type=ActionType.PACKAGE_INSTALL,
                    original_action=package,
                    rule_id="gateway_suspicious_package",
                    message=msg,
                    suggestion=f"Verify '{package}' exists on {registry} before installing.",
                    metadata={"registry": registry},
                )

        return InterceptResult(
            verdict=Verdict.ALLOW,
            action_type=ActionType.PACKAGE_INSTALL,
            original_action=package,
        )

    def get_rules(self) -> list[dict]:
        """Return all interceptor rules with their current status."""
        rules = []
        for rule in _TERMINAL_RULES + _CONTENT_RULES:
            rules.append({
                "id": rule["id"],
                "message": rule["message"],
                "severity": rule["severity"].value,
                "enabled": rule["id"] not in self._disabled_rules,
            })
        return rules
