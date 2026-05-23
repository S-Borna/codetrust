# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Session grouping — turn the flat audit log into reviewable agent sessions.

A "session" is a coherent unit of AI-agent activity: the scans, gateway checks,
and verdicts that belong together. Entries carry a session_id when the agent
provides one; when they don't, contiguous activity is grouped by an idle gap so
the view is useful regardless. This is the foundation the CLI (`codetrust
sessions`) and the dashboard both render.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.gateway.audit import AuditEntry

DEFAULT_IDLE_GAP_SECONDS: int = 1800  # 30 min of silence starts a new session
_TOP_RULES_LIMIT: int = 5


@dataclass
class Session:
    """A grouped unit of agent activity."""

    session_id: str
    start: float
    end: float
    synthetic: bool                       # grouped by idle gap, no real id
    total: int = 0
    allowed: int = 0
    warned: int = 0
    blocked: int = 0
    agents: list[str] = field(default_factory=list)
    top_rules: list[tuple[str, int]] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.end - self.start)

    def to_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "start": self.start,
            "end": self.end,
            "duration_seconds": round(self.duration_seconds, 1),
            "synthetic": self.synthetic,
            "total": self.total,
            "allowed": self.allowed,
            "warned": self.warned,
            "blocked": self.blocked,
            "agents": list(self.agents),
            "top_rules": [{"rule_id": r, "count": c} for r, c in self.top_rules],
        }


def _summarize(session_id: str, synthetic: bool, entries: list[AuditEntry]) -> Session:
    """Build a Session summary from its entries (assumed time-ordered)."""
    verdicts = Counter(e.verdict for e in entries)
    agents = sorted({e.agent_id for e in entries if e.agent_id})
    rules = Counter(e.rule_id for e in entries if e.rule_id)
    return Session(
        session_id=session_id,
        start=entries[0].timestamp,
        end=entries[-1].timestamp,
        synthetic=synthetic,
        total=len(entries),
        allowed=verdicts.get("ALLOW", 0),
        warned=verdicts.get("WARN", 0),
        blocked=verdicts.get("BLOCK", 0),
        agents=agents,
        top_rules=rules.most_common(_TOP_RULES_LIMIT),
    )


def group_into_sessions(
    entries: list[AuditEntry],
    *,
    idle_gap_seconds: int = DEFAULT_IDLE_GAP_SECONDS,
) -> list[Session]:
    """Group audit entries into sessions, newest first.

    Entries with a session_id are grouped by that id. Entries without one are
    split into synthetic sessions wherever the gap between consecutive entries
    exceeds idle_gap_seconds.
    """
    if not entries:
        return []

    ordered = sorted(entries, key=lambda e: e.timestamp)
    with_id: dict[str, list[AuditEntry]] = {}
    no_id: list[AuditEntry] = []
    for e in ordered:
        if e.session_id:
            with_id.setdefault(e.session_id, []).append(e)
        else:
            no_id.append(e)

    sessions: list[Session] = [
        _summarize(sid, synthetic=False, entries=group)
        for sid, group in with_id.items()
    ]

    # Time-gap sessionize the entries that carry no explicit session id.
    bucket: list[AuditEntry] = []
    seq = 0
    for e in no_id:
        if bucket and (e.timestamp - bucket[-1].timestamp) > idle_gap_seconds:
            seq += 1
            sessions.append(_summarize(f"local-{seq}", synthetic=True, entries=bucket))
            bucket = []
        bucket.append(e)
    if bucket:
        seq += 1
        sessions.append(_summarize(f"local-{seq}", synthetic=True, entries=bucket))

    sessions.sort(key=lambda s: s.start, reverse=True)
    return sessions


def find_session(sessions: list[Session], session_id: str) -> Session | None:
    """Return the session matching an id (exact, or unique prefix)."""
    for s in sessions:
        if s.session_id == session_id:
            return s
    matches = [s for s in sessions if s.session_id.startswith(session_id)]
    return matches[0] if len(matches) == 1 else None
