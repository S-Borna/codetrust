# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Cost event storage — append-only JSONL local storage.

Stores LLM usage events in `.codetrust/cost-events.jsonl`.
Append-only for auditability. Aggregation at query time.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("codetrust.cost_storage")

_DEFAULT_STORAGE_PATH = ".codetrust/cost-events.jsonl"


@dataclass
class LLMUsageEvent:
    """A single LLM usage event with cost information."""

    timestamp: str
    model: str
    provider: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost_usd: float
    developer: str
    team: str
    project: str
    session_id: str
    action: str
    cost_estimated: bool = False  # True if model not in pricing table

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dictionary."""
        return asdict(self)


def _storage_path(project_dir: Path | None = None) -> Path:
    """Get the cost events storage path."""
    root = project_dir or Path.cwd()
    return root / _DEFAULT_STORAGE_PATH


def append_event(event: LLMUsageEvent, project_dir: Path | None = None) -> None:
    """Append a usage event to the JSONL storage file.

    Args:
        event: The LLM usage event to store.
        project_dir: Project root directory.
    """
    path = _storage_path(project_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")
    except OSError as exc:
        logger.warning("Failed to write cost event: %s", exc)


def read_events(
    project_dir: Path | None = None,
    start_date: str = "",
    end_date: str = "",
) -> list[LLMUsageEvent]:
    """Read usage events from storage, optionally filtered by date range.

    Args:
        project_dir: Project root directory.
        start_date: ISO 8601 start date filter (inclusive).
        end_date: ISO 8601 end date filter (inclusive).

    Returns:
        List of LLMUsageEvent instances.
    """
    path = _storage_path(project_dir)
    if not path.is_file():
        return []

    events: list[LLMUsageEvent] = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    raw = json.loads(line)
                    ts = raw.get("timestamp", "")
                    if start_date and ts < start_date:
                        continue
                    if end_date and ts > end_date:
                        continue
                    events.append(LLMUsageEvent(**{
                        k: raw[k] for k in LLMUsageEvent.__dataclass_fields__
                        if k in raw
                    }))
                except (json.JSONDecodeError, TypeError, KeyError):
                    continue
    except OSError as exc:
        logger.warning("Failed to read cost events: %s", exc)

    return events


def clear_events(project_dir: Path | None = None) -> None:
    """Remove all stored events (for testing only).

    Args:
        project_dir: Project root directory.
    """
    path = _storage_path(project_dir)
    if path.is_file():
        path.unlink()
