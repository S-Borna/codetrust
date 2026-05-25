# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Threat intelligence — aggregate observed agent activity into signal.

This is the moat machinery. CodeTrust already records every agent action; this
module turns that record into intelligence: which threats dominate, which are
emerging (rising recently), and which are novel (rarely seen). The same pure
aggregation runs over a single workspace's audit log (local mode) or, when fed
cross-installation telemetry in the backend, over the whole fleet — where the
network effect lives: every agent's blocked action sharpens detection for all.

Read-only by design. It computes over data already collected and never touches
the live counter, warmup, or Redis write paths.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from src.services.impact_categories import get_rule_category

if TYPE_CHECKING:
    from src.gateway.audit import AuditEntry

DEFAULT_RECENT_WINDOW_SECONDS: int = 7 * 86_400  # last 7 days = "recent"
_TOP_LIMIT: int = 10
_NOVEL_MAX_COUNT: int = 2          # seen this few times → candidate novel pattern
_SIGNAL_SEVERITIES: frozenset[str] = frozenset({"BLOCK", "WARN"})


@dataclass(frozen=True)
class ThreatSignal:
    """A single ranked threat with its category and counts."""

    rule_id: str
    category: str
    count: int
    recent: int          # occurrences inside the recent window
    prior: int           # occurrences inside the preceding window of equal length

    @property
    def delta(self) -> int:
        """Rise in frequency: recent minus prior window."""
        return self.recent - self.prior

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "count": self.count,
            "recent": self.recent,
            "prior": self.prior,
            "delta": self.delta,
        }


@dataclass
class ThreatIntel:
    """Aggregate threat intelligence over a set of observed events."""

    total_events: int
    window_seconds: int
    top_threats: list[ThreatSignal] = field(default_factory=list)
    emerging: list[ThreatSignal] = field(default_factory=list)
    novel: list[ThreatSignal] = field(default_factory=list)
    by_category: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "total_events": self.total_events,
            "window_seconds": self.window_seconds,
            "top_threats": [s.to_dict() for s in self.top_threats],
            "emerging": [s.to_dict() for s in self.emerging],
            "novel": [s.to_dict() for s in self.novel],
            "by_category": dict(self.by_category),
        }


def _signal_events(entries: list[AuditEntry]) -> list[AuditEntry]:
    """Keep only BLOCK/WARN entries that carry a rule id."""
    return [
        e for e in entries
        if str(getattr(e, "verdict", "")).upper() in _SIGNAL_SEVERITIES
        and getattr(e, "rule_id", "")
    ]


def compute_threat_intel(
    entries: list[AuditEntry],
    *,
    now: float,
    recent_window_seconds: int = DEFAULT_RECENT_WINDOW_SECONDS,
) -> ThreatIntel:
    """Aggregate audit entries into ranked threat intelligence.

    - top_threats: most frequent rules overall (BLOCK/WARN).
    - emerging: rules whose recent-window frequency exceeds the preceding
      window of equal length (rising threats).
    - novel: rules seen at most _NOVEL_MAX_COUNT times (candidate new patterns).
    """
    signal = _signal_events(entries)
    if not signal:
        return ThreatIntel(total_events=0, window_seconds=recent_window_seconds)

    recent_start = now - recent_window_seconds
    prior_start = now - 2 * recent_window_seconds

    total = Counter(e.rule_id for e in signal)
    recent = Counter(
        e.rule_id for e in signal if e.timestamp >= recent_start
    )
    prior = Counter(
        e.rule_id for e in signal
        if prior_start <= e.timestamp < recent_start
    )

    def _mk(rule_id: str) -> ThreatSignal:
        return ThreatSignal(
            rule_id=rule_id,
            category=get_rule_category(rule_id),
            count=total[rule_id],
            recent=recent.get(rule_id, 0),
            prior=prior.get(rule_id, 0),
        )

    top_threats = [_mk(r) for r, _ in total.most_common(_TOP_LIMIT)]

    emerging = sorted(
        (s for s in (_mk(r) for r in total) if s.delta > 0),
        key=lambda s: s.delta,
        reverse=True,
    )[:_TOP_LIMIT]

    novel = sorted(
        (s for s in (_mk(r) for r in total) if s.count <= _NOVEL_MAX_COUNT),
        key=lambda s: s.recent,
        reverse=True,
    )[:_TOP_LIMIT]

    by_category: dict[str, int] = dict(
        Counter(get_rule_category(e.rule_id) for e in signal),
    )

    return ThreatIntel(
        total_events=len(signal),
        window_seconds=recent_window_seconds,
        top_threats=top_threats,
        emerging=emerging,
        novel=novel,
        by_category=by_category,
    )


def format_threat_intel(intel: ThreatIntel) -> str:
    """Render threat intelligence for the terminal."""
    days = intel.window_seconds // 86_400
    lines = [
        "",
        "  🛡️  CodeTrust — Threat Intelligence",
        "",
        f"  {intel.total_events} signal event(s) analyzed   |   recent window: {days}d",
        "",
    ]
    if intel.total_events == 0:
        lines.append("  No BLOCK/WARN activity yet. Intelligence builds as agents act.\n")
        return "\n".join(lines)

    lines.append("  Top threats:")
    for s in intel.top_threats:
        lines.append(f"    {s.rule_id:<32} {s.count:>5}  [{s.category}]")
    if intel.emerging:
        lines.append("")
        lines.append("  Emerging (rising vs prior window):")
        for s in intel.emerging:
            lines.append(f"    {s.rule_id:<32} +{s.delta:<4} (recent {s.recent}, prior {s.prior})")
    if intel.novel:
        lines.append("")
        lines.append("  Novel (rarely seen — candidate new patterns):")
        for s in intel.novel:
            lines.append(f"    {s.rule_id:<32} seen {s.count}")
    lines.append("")
    return "\n".join(lines)
