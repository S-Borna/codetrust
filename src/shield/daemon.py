# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary - see LICENSE for terms.
"""CodeTrust Shield Daemon - orchestrates shell wrapper + file watcher.

Lifecycle:
    codetrust shield start  -> writes PID, installs wrapper, starts watcher
    codetrust shield stop   -> kills daemon, removes wrapper, restores shell
    codetrust shield status -> reads PID file, checks process alive
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import stat
import sys
from pathlib import Path

import structlog

from src.shield.config import (
    AUDIT_FILE,
    CLAUDE_CODE_CONFIG,
    CURSOR_SETTINGS,
    ORIGINAL_SHELL_BACKUP,
    PID_FILE,
    SHELL_WRAPPER_PATH,
    VSCODE_SETTINGS,
    WINDSURF_SETTINGS,
    ensure_shield_dir,
    get_user_shell,
)
from src.shield.file_watcher import FileWatcher

logger = structlog.get_logger()

# IDE config key used for VS Code-based editors
_PROFILES_KEY = "terminal.integrated.profiles.osx"
_DEFAULT_PROFILE_KEY = "terminal.integrated.defaultProfile.osx"
_SHELL_PROFILE_NAME = "codetrust-shell"


class ShieldDaemon:
    """Manages the Shield lifecycle."""

    def __init__(self, workspace: Path | None = None) -> None:
        self.workspace = (workspace or Path.cwd()).resolve()

    # -- Start ---------------------------------------------------------

    def start(self) -> dict[str, str | int]:
        """Start Shield: install wrapper, start file watcher, write PID."""
        if self.is_running():
            pid = self._read_pid()
            return {"status": "already_running", "pid": str(pid or "")}

        ensure_shield_dir()

        # Step 1: Back up original shell
        original = get_user_shell()
        ORIGINAL_SHELL_BACKUP.write_text(original)

        # Step 2: Install shell wrapper
        self._install_shell_wrapper(original)

        # Step 3: Write PID
        PID_FILE.write_text(str(os.getpid()))

        # Step 4: Start file watcher
        watcher = FileWatcher(self.workspace)
        watcher.start()

        logger.info(
            "shield_started",
            workspace=str(self.workspace),
            shell_wrapper=str(SHELL_WRAPPER_PATH),
            pid=os.getpid(),
        )

        return {
            "status": "started",
            "pid": str(os.getpid()),
            "workspace": str(self.workspace),
            "shell_wrapper": str(SHELL_WRAPPER_PATH),
            "file_watcher": "active",
            "audit_log": str(AUDIT_FILE),
        }

    # -- Stop ----------------------------------------------------------

    def stop(self) -> dict[str, str]:
        """Stop Shield: kill daemon, restore shell, stop watcher."""
        pid = self._read_pid()
        if pid and self._is_process_alive(pid):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGTERM)

        if PID_FILE.exists():
            PID_FILE.unlink()

        logger.info("shield_stopped")
        return {"status": "stopped", "pid": str(pid or "")}

    # -- Status --------------------------------------------------------

    def status(self) -> dict[str, str | int | bool]:
        """Get Shield status."""
        pid = self._read_pid()
        running = pid is not None and self._is_process_alive(pid)
        wrapper_installed = SHELL_WRAPPER_PATH.exists()

        audit_count, block_count = self._count_audit_entries()

        return {
            "running": running,
            "pid": pid or 0,
            "workspace": str(self.workspace),
            "shell_wrapper_installed": wrapper_installed,
            "shell_wrapper_path": str(SHELL_WRAPPER_PATH),
            "audit_entries": audit_count,
            "blocks": block_count,
            "audit_log": str(AUDIT_FILE),
        }

    def is_running(self) -> bool:
        """Check if Shield daemon is running."""
        pid = self._read_pid()
        return pid is not None and self._is_process_alive(pid)

    # -- IDE Auto-Configuration ----------------------------------------

    def install_ide_hooks(self) -> dict[str, str]:
        """Auto-configure IDE shell settings to use codetrust-shell."""
        results: dict[str, str] = {}
        wrapper = str(SHELL_WRAPPER_PATH)

        for name, config_path in self._ide_config_paths().items():
            results[name] = self._install_single_ide(
                name, config_path, wrapper,
            )

        return results

    def uninstall_ide_hooks(self) -> dict[str, str]:
        """Restore original shell in all IDE configurations."""
        original = "/bin/zsh"
        if ORIGINAL_SHELL_BACKUP.exists():
            original = ORIGINAL_SHELL_BACKUP.read_text().strip()

        results: dict[str, str] = {}
        for name, config_path in self._ide_config_paths().items():
            results[name] = self._uninstall_single_ide(
                name, config_path, original,
            )

        return results

    # -- Shell Wrapper Installation ------------------------------------

    def _install_shell_wrapper(self, original_shell: str) -> None:
        """Generate and install the shell wrapper script."""
        python_bin = sys.executable
        wrapper_content = (
            "#!/bin/bash\n"
            "# CodeTrust Shield - shell interceptor\n"
            f"# Original shell: {original_shell}\n"
            "# Do not edit - managed by codetrust shield start/stop\n"
            "\n"
            f'exec {python_bin} -m src.shield.shell_wrapper "$@"\n'
        )
        SHELL_WRAPPER_PATH.write_text(wrapper_content)
        SHELL_WRAPPER_PATH.chmod(
            SHELL_WRAPPER_PATH.stat().st_mode
            | stat.S_IEXEC
            | stat.S_IXGRP
            | stat.S_IXOTH
        )

    # -- Helpers -------------------------------------------------------

    @staticmethod
    def _ide_config_paths() -> dict[str, Path]:
        """Return map of IDE name to config file path."""
        return {
            "claude_code": CLAUDE_CODE_CONFIG,
            "cursor": CURSOR_SETTINGS,
            "vscode": VSCODE_SETTINGS,
            "windsurf": WINDSURF_SETTINGS,
        }

    @staticmethod
    def _install_single_ide(
        name: str,
        config_path: Path,
        wrapper: str,
    ) -> str:
        """Configure a single IDE to use codetrust-shell."""
        if not config_path.exists():
            return "not_installed"
        try:
            config = json.loads(config_path.read_text())
            if name == "claude_code":
                config["shell"] = wrapper
            else:
                config.setdefault(_PROFILES_KEY, {})[_SHELL_PROFILE_NAME] = {
                    "path": wrapper,
                    "args": [],
                }
                config[_DEFAULT_PROFILE_KEY] = _SHELL_PROFILE_NAME
            config_path.write_text(json.dumps(config, indent=2))
            return "configured"
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("ide_hook_install_error", ide=name, error=str(exc))
            return f"error: {exc}"

    @staticmethod
    def _uninstall_single_ide(
        name: str,
        config_path: Path,
        original_shell: str,
    ) -> str:
        """Restore a single IDE to its original shell configuration."""
        if not config_path.exists():
            return "not_installed"
        try:
            config = json.loads(config_path.read_text())
            if name == "claude_code" and "shell" in config:
                config["shell"] = original_shell
            else:
                if _PROFILES_KEY in config:
                    config[_PROFILES_KEY].pop(_SHELL_PROFILE_NAME, None)
                config.pop(_DEFAULT_PROFILE_KEY, None)
            config_path.write_text(json.dumps(config, indent=2))
            return "restored"
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("ide_hook_uninstall_error", ide=name, error=str(exc))
            return f"error: {exc}"

    @staticmethod
    def _count_audit_entries() -> tuple[int, int]:
        """Count total and blocked audit entries."""
        if not AUDIT_FILE.exists():
            return 0, 0
        try:
            lines = AUDIT_FILE.read_text().strip().split("\n")
            total = len([ln for ln in lines if ln.strip()])
            blocks = sum(1 for ln in lines if '"BLOCK"' in ln)
            return total, blocks
        except OSError:
            logger.warning("audit_file_read_error", path=str(AUDIT_FILE))
            return 0, 0

    def _read_pid(self) -> int | None:
        """Read PID from pidfile."""
        if not PID_FILE.exists():
            return None
        try:
            return int(PID_FILE.read_text().strip())
        except (ValueError, OSError):
            return None

    @staticmethod
    def _is_process_alive(pid: int) -> bool:
        """Check if a process is still running."""
        try:
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False
