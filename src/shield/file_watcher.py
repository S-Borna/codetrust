# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary - see LICENSE for terms.
"""CodeTrust File Watcher - monitors workspace for file changes.

Uses fswatch (macOS) or inotifywait (Linux) to detect file
modifications in near-real-time. Each changed file is scanned
through the static analyzer within milliseconds.
"""

from __future__ import annotations

import json
import platform
import subprocess
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import structlog

from src.shield.config import (
    AUDIT_FILE,
    DEFAULT_WATCH_EXTENSIONS,
    IGNORE_DIRS,
    SCAN_DEBOUNCE_MS,
    ensure_shield_dir,
)

logger = structlog.get_logger()


class FileWatcher:
    """Watches a directory for file changes and scans them."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.resolve()
        self._process: subprocess.Popen[str] | None = None
        self._running = False
        self._last_scan: dict[str, float] = {}

    def start(self) -> None:
        """Start the file watcher in a background thread."""
        self._running = True
        system = platform.system()

        if system == "Darwin":
            self._start_fswatch()
        elif system == "Linux":
            self._start_inotify()
        else:
            logger.warning("file_watcher_unsupported", system=system)

    def stop(self) -> None:
        """Stop the file watcher."""
        self._running = False
        if self._process:
            self._process.terminate()
            self._process = None

    def _start_fswatch(self) -> None:
        """Start fswatch on macOS."""
        exclude_args: list[str] = []
        for d in IGNORE_DIRS:
            exclude_args.extend(["--exclude", f".*/{d}/.*"])

        cmd = [
            "fswatch",
            "-r",
            "--event=Created",
            "--event=Updated",
            "--event=Renamed",
            *exclude_args,
            str(self.workspace),
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            thread = threading.Thread(target=self._read_events, daemon=True)
            thread.start()
            logger.info(
                "file_watcher_started",
                backend="fswatch",
                workspace=str(self.workspace),
            )
        except FileNotFoundError:
            logger.warning("fswatch_not_found", hint="brew install fswatch")

    def _start_inotify(self) -> None:
        """Start inotifywait on Linux."""
        exclude_pattern = "|".join(IGNORE_DIRS)
        cmd = [
            "inotifywait",
            "-m", "-r",
            "--format", "%w%f",
            "-e", "modify,create,moved_to",
            "--exclude", f"({exclude_pattern})",
            str(self.workspace),
        ]

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            thread = threading.Thread(target=self._read_events, daemon=True)
            thread.start()
            logger.info(
                "file_watcher_started",
                backend="inotifywait",
                workspace=str(self.workspace),
            )
        except FileNotFoundError:
            logger.warning(
                "inotifywait_not_found",
                hint="apt install inotify-tools",
            )

    def _read_events(self) -> None:
        """Read file change events from the watcher process."""
        if not self._process or not self._process.stdout:
            return

        for line in self._process.stdout:
            if not self._running:
                break

            filepath = line.strip()
            if not filepath:
                continue

            path = Path(filepath)
            if path.suffix not in DEFAULT_WATCH_EXTENSIONS:
                continue

            # Debounce: skip if same file was scanned within SCAN_DEBOUNCE_MS
            now = time.time() * 1000
            last = self._last_scan.get(filepath, 0)
            if now - last < SCAN_DEBOUNCE_MS:
                continue
            self._last_scan[filepath] = now

            self._scan_file(path)

    def _scan_file(self, path: Path) -> None:
        """Scan a single file through the static analyzer."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return

        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        findings = analyzer.scan(content, filename=str(path))

        block_findings = [
            f for f in findings if f.get("severity") == "BLOCK"
        ]

        if block_findings:
            logger.warning(
                "shield_file_block",
                file=str(path),
                findings=len(block_findings),
                rules=[f.get("rule_id") for f in block_findings],
            )
            self._audit_log(path, block_findings)

    def _audit_log(self, path: Path, findings: list[dict[str, str]]) -> None:
        """Log file scan findings to audit trail."""
        ensure_shield_dir()
        for finding in findings:
            self._write_audit_entry(path, finding)

    @staticmethod
    def _write_audit_entry(path: Path, finding: dict[str, str]) -> None:
        """Write a single audit entry to the JSONL audit file."""
        entry = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "source": "shield_file_watcher",
            "file": str(path),
            "rule_id": finding.get("rule_id", ""),
            "severity": finding.get("severity", ""),
            "message": finding.get("message", ""),
            "line": finding.get("line", 0),
        }
        try:
            with open(AUDIT_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as exc:
            logger.warning("shield_audit_write_error", error=str(exc))
