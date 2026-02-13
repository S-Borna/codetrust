"""Audit logger — structured logging of all AI agent actions.

Records every intercepted action (allowed, warned, or blocked)
to a JSONL file for compliance, debugging, and drift analysis.

File format: One JSON object per line (.jsonl).
Location: Configurable via .codetrust.toml, defaults to .codetrust/audit.jsonl.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class AuditEntry:
    """A single audit log entry."""

    timestamp: float
    action_type: str
    verdict: str
    rule_id: str
    original_action: str
    message: str
    suggestion: str
    session_id: str = ""
    agent_id: str = ""
    workspace: str = ""
    metadata: dict = field(default_factory=dict)

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), ensure_ascii=False)

    @classmethod
    def from_json(cls, line: str) -> AuditEntry:
        """Deserialize from JSON string."""
        data = json.loads(line)
        return cls(**data)


class AuditLogger:
    """Append-only audit logger for governance actions.

    Usage:
        logger = AuditLogger("/path/to/project/.codetrust/audit.jsonl")
        logger.log(entry)
        # Or from an InterceptResult:
        logger.log_intercept(result, workspace="/path/to/project")

        # Query history:
        violations = logger.get_violations(since=time.time() - 86400)
        stats = logger.get_stats()
    """

    def __init__(self, log_path: str | Path, *, enabled: bool = True):
        self._path = Path(log_path)
        self._enabled = enabled
        self._buffer: list[AuditEntry] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def path(self) -> Path:
        return self._path

    def log(self, entry: AuditEntry) -> None:
        """Write an audit entry to the log file.

        Creates the directory structure if it doesn't exist.
        Appends atomically (single write per entry).
        """
        if not self._enabled:
            return

        self._path.parent.mkdir(parents=True, exist_ok=True)

        with open(self._path, "a", encoding="utf-8") as f:
            f.write(entry.to_json() + "\n")

    def log_intercept(
        self,
        result: InterceptResult,  # noqa: F821
        *,
        workspace: str = "",
        session_id: str = "",
        agent_id: str = "",
    ) -> None:
        """Create and write an audit entry from an InterceptResult.

        Args:
            result: The intercept result to log.
            workspace: Workspace root path.
            session_id: Current session identifier.
            agent_id: AI agent identifier (e.g. "claude", "copilot").
        """
        # Import here to avoid circular dependency
        from src.gateway.interceptor import InterceptResult

        if not isinstance(result, InterceptResult):
            return

        entry = AuditEntry(
            timestamp=time.time(),
            action_type=result.action_type.value,
            verdict=result.verdict.value,
            rule_id=result.rule_id,
            original_action=result.original_action,
            message=result.message,
            suggestion=result.suggestion,
            session_id=session_id,
            agent_id=agent_id,
            workspace=workspace,
            metadata=result.metadata,
        )
        self.log(entry)

    def get_entries(
        self,
        *,
        since: float | None = None,
        verdict: str | None = None,
        limit: int = 1000,
    ) -> list[AuditEntry]:
        """Read audit entries with optional filtering.

        Args:
            since: Unix timestamp — only return entries after this time.
            verdict: Filter by verdict (ALLOW, WARN, BLOCK).
            limit: Maximum number of entries to return.

        Returns:
            List of matching AuditEntry objects, newest first.
        """
        if not self._path.is_file():
            return []

        entries: list[AuditEntry] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    continue

                if since and entry.timestamp < since:
                    continue
                if verdict and entry.verdict != verdict:
                    continue

                entries.append(entry)

        # Return newest first, limited
        entries.reverse()
        return entries[:limit]

    def get_violations(
        self,
        *,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Get only BLOCK and WARN entries.

        Args:
            since: Unix timestamp — entries after this time.
            limit: Maximum entries.

        Returns:
            List of violation entries, newest first.
        """
        if not self._path.is_file():
            return []

        entries: list[AuditEntry] = []
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    continue

                if entry.verdict not in ("BLOCK", "WARN"):
                    continue
                if since and entry.timestamp < since:
                    continue

                entries.append(entry)

        entries.reverse()
        return entries[:limit]

    def get_stats(self) -> dict:
        """Get aggregate statistics from the audit log.

        Returns:
            Dict with counts by verdict, action_type, and top violated rules.
        """
        if not self._path.is_file():
            return {
                "total": 0,
                "by_verdict": {},
                "by_action_type": {},
                "top_rules": [],
            }

        by_verdict: dict[str, int] = {}
        by_action_type: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        total = 0

        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    continue

                total += 1
                by_verdict[entry.verdict] = by_verdict.get(entry.verdict, 0) + 1
                by_action_type[entry.action_type] = (
                    by_action_type.get(entry.action_type, 0) + 1
                )
                if entry.rule_id:
                    by_rule[entry.rule_id] = by_rule.get(entry.rule_id, 0) + 1

        top_rules = sorted(by_rule.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total": total,
            "by_verdict": by_verdict,
            "by_action_type": by_action_type,
            "top_rules": [{"rule_id": r, "count": c} for r, c in top_rules],
        }

    def clear(self) -> None:
        """Remove the audit log file. Use with caution."""
        if self._path.is_file():
            self._path.unlink()

    def purge(self, *, older_than_days: int = 90) -> int:
        """Remove audit entries older than the specified number of days.

        Rewrites the log file keeping only entries within the retention window.
        This is the primary data retention mechanism for compliance (GDPR, SOC 2).

        Args:
            older_than_days: Entries older than this many days are deleted.

        Returns:
            Number of entries purged.
        """
        if not self._path.is_file():
            return 0

        cutoff = time.time() - (older_than_days * 86400)
        kept: list[str] = []
        purged = 0

        with open(self._path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = AuditEntry.from_json(line)
                except (json.JSONDecodeError, TypeError):
                    continue

                if entry.timestamp < cutoff:
                    purged += 1
                else:
                    kept.append(entry.to_json())

        # Atomic rewrite
        tmp_path = self._path.with_suffix(".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            for line in kept:
                f.write(line + "\n")
        tmp_path.replace(self._path)

        return purged

    def entry_count(self) -> int:
        """Count total entries in the audit log."""
        if not self._path.is_file():
            return 0
        count = 0
        with open(self._path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count
