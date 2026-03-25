# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Shadow AI Detection — discover installed AI coding tools.

Scans for AI-powered coding assistants across VS Code extensions,
desktop applications, CLI tools, and configuration directories.
"""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import structlog

logger = structlog.get_logger()

# ─────────────────────────────────────────────────────────────────
#  AI tool definitions
# ─────────────────────────────────────────────────────────────────

_HOME = Path.home()
_IS_MACOS = platform.system() == "Darwin"


@dataclass(frozen=True)
class AIToolDef:
    """Definition of a known AI coding tool and its detection artifacts."""

    tool_id: str
    display_name: str
    vscode_extensions: tuple[str, ...] = ()
    app_paths: tuple[str, ...] = ()
    config_dirs: tuple[str, ...] = ()
    cli_commands: tuple[str, ...] = ()


AI_TOOLS: tuple[AIToolDef, ...] = (
    AIToolDef(
        tool_id="github_copilot",
        display_name="GitHub Copilot",
        vscode_extensions=("github.copilot", "github.copilot-chat"),
    ),
    AIToolDef(
        tool_id="cursor",
        display_name="Cursor",
        app_paths=(
            "/Applications/Cursor.app",
            str(_HOME / "AppData" / "Local" / "Programs" / "Cursor" / "Cursor.exe"),
        ),
        config_dirs=(str(_HOME / ".cursor"),),
    ),
    AIToolDef(
        tool_id="cline",
        display_name="Cline",
        vscode_extensions=("saoudrizwan.claude-dev",),
    ),
    AIToolDef(
        tool_id="roo_code",
        display_name="Roo Code",
        vscode_extensions=("rooveterinaryinc.roo-cline",),
    ),
    AIToolDef(
        tool_id="continue",
        display_name="Continue",
        vscode_extensions=("continue.continue",),
        config_dirs=(str(_HOME / ".continue"),),
    ),
    AIToolDef(
        tool_id="aider",
        display_name="Aider",
        cli_commands=("aider",),
        config_dirs=(str(_HOME / ".aider.conf.yml"),),
    ),
    AIToolDef(
        tool_id="windsurf",
        display_name="Windsurf",
        app_paths=(
            "/Applications/Windsurf.app",
        ),
        config_dirs=(str(_HOME / ".windsurf"),),
    ),
    AIToolDef(
        tool_id="supermaven",
        display_name="Supermaven",
        vscode_extensions=("supermaven.supermaven",),
    ),
    AIToolDef(
        tool_id="tabnine",
        display_name="Tabnine",
        vscode_extensions=("tabnine.tabnine-vscode",),
    ),
    AIToolDef(
        tool_id="codeium",
        display_name="Codeium",
        vscode_extensions=("codeium.codeium",),
    ),
    AIToolDef(
        tool_id="sourcegraph_cody",
        display_name="Sourcegraph Cody",
        vscode_extensions=("sourcegraph.cody-ai",),
    ),
    AIToolDef(
        tool_id="claude_code",
        display_name="Claude Code",
        cli_commands=("claude",),
        config_dirs=(str(_HOME / ".claude"),),
    ),
)

# ─────────────────────────────────────────────────────────────────
#  Types
# ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AIToolDetection:
    """A single detected AI coding tool."""

    tool_id: str
    display_name: str
    detected_via: str       # "vscode_extension", "app_path", "config_dir", "cli_command"
    detail: str             # e.g. extension ID, path, command name


@dataclass
class ShadowScanResult:
    """Result of a shadow AI scan."""

    detections: list[AIToolDetection] = field(default_factory=list)
    unapproved: list[AIToolDetection] = field(default_factory=list)
    approved: list[AIToolDetection] = field(default_factory=list)
    total_found: int = 0


# ─────────────────────────────────────────────────────────────────
#  Detection logic
# ─────────────────────────────────────────────────────────────────


def _get_vscode_extensions_dir() -> Path | None:
    """Get the VS Code extensions directory."""
    ext_dir = _HOME / ".vscode" / "extensions"
    return ext_dir if ext_dir.is_dir() else None


def _get_installed_vscode_extensions(ext_dir: Path) -> frozenset[str]:
    """List installed VS Code extension IDs from the extensions directory."""
    extensions: set[str] = set()
    try:
        for entry in ext_dir.iterdir():
            if entry.is_dir():
                # Extension dirs are formatted as "publisher.name-version"
                name = entry.name
                # Remove version suffix
                parts = name.rsplit("-", maxsplit=1)
                if parts:
                    extensions.add(parts[0].lower())
    except OSError:
        pass
    return frozenset(extensions)


# ─────────────────────────────────────────────────────────────────
#  ShadowAIScanner
# ─────────────────────────────────────────────────────────────────


class ShadowAIScanner:
    """Detect installed AI coding tools on the machine."""

    def scan(
        self,
        approved_tools: frozenset[str] | None = None,
    ) -> ShadowScanResult:
        """Scan for AI coding tools.

        Args:
            approved_tools: Set of tool_ids that are approved by policy.
                           If None, no tool is flagged as unapproved.
        """
        result = ShadowScanResult()

        # Get VS Code extensions once
        ext_dir = _get_vscode_extensions_dir()
        installed_extensions = (
            _get_installed_vscode_extensions(ext_dir) if ext_dir else frozenset()
        )

        for tool_def in AI_TOOLS:
            detections = self._detect_tool(tool_def, installed_extensions)
            result.detections.extend(detections)

        # Classify approved vs unapproved
        for detection in result.detections:
            if approved_tools is None or detection.tool_id in approved_tools:
                result.approved.append(detection)
            else:
                result.unapproved.append(detection)

        result.total_found = len(result.detections)

        logger.info(
            "shadow_scan_complete",
            total=result.total_found,
            approved=len(result.approved),
            unapproved=len(result.unapproved),
        )
        return result

    def _detect_tool(
        self,
        tool_def: AIToolDef,
        installed_extensions: frozenset[str],
    ) -> list[AIToolDetection]:
        """Detect a single AI tool via all methods."""
        detections: list[AIToolDetection] = []

        # VS Code extensions
        for ext_id in tool_def.vscode_extensions:
            if ext_id.lower() in installed_extensions:
                detections.append(AIToolDetection(
                    tool_id=tool_def.tool_id,
                    display_name=tool_def.display_name,
                    detected_via="vscode_extension",
                    detail=ext_id,
                ))

        # Application paths
        for app_path in tool_def.app_paths:
            if Path(app_path).exists():
                detections.append(AIToolDetection(
                    tool_id=tool_def.tool_id,
                    display_name=tool_def.display_name,
                    detected_via="app_path",
                    detail=app_path,
                ))

        # Config directories/files
        for config_path in tool_def.config_dirs:
            expanded = Path(config_path).expanduser()
            if expanded.exists():
                detections.append(AIToolDetection(
                    tool_id=tool_def.tool_id,
                    display_name=tool_def.display_name,
                    detected_via="config_dir",
                    detail=str(expanded),
                ))

        # CLI commands
        for cmd in tool_def.cli_commands:
            if shutil.which(cmd) is not None:
                detections.append(AIToolDetection(
                    tool_id=tool_def.tool_id,
                    display_name=tool_def.display_name,
                    detected_via="cli_command",
                    detail=cmd,
                ))

        # Deduplicate: one detection per tool is enough for identification
        if detections:
            return [detections[0]]
        return []

    def build_report(self, result: ShadowScanResult) -> str:
        """Build markdown report from scan result."""
        lines: list[str] = [
            "## Shadow AI Scan",
            "",
            f"**{result.total_found} AI tools detected**",
            "",
        ]

        if not result.detections:
            lines.append("No AI coding tools found on this machine.")
            return "\n".join(lines)

        if result.unapproved:
            lines.append(f"### Unapproved ({len(result.unapproved)})")
            lines.append("")
            for d in result.unapproved:
                lines.append(
                    f"- **{d.display_name}** — {d.detected_via}: `{d.detail}`"
                )
            lines.append("")

        if result.approved:
            lines.append(f"### Approved ({len(result.approved)})")
            lines.append("")
            for d in result.approved:
                lines.append(
                    f"- **{d.display_name}** — {d.detected_via}: `{d.detail}`"
                )
            lines.append("")

        return "\n".join(lines)
