"""Tests for session grouping of the audit log."""

from src.gateway.audit import AuditEntry
from src.gateway.sessions import (
    find_session,
    group_into_sessions,
)


def _entry(ts: float, verdict: str = "ALLOW", rule: str = "", sid: str = "",
           agent: str = "") -> AuditEntry:
    return AuditEntry(
        timestamp=ts, action_type="bash", verdict=verdict, rule_id=rule,
        original_action="x", message=rule or "m", suggestion="",
        session_id=sid, agent_id=agent,
    )


class TestGrouping:
    def test_empty(self) -> None:
        assert group_into_sessions([]) == []

    def test_groups_by_session_id(self) -> None:
        entries = [
            _entry(100, "ALLOW", sid="A", agent="claude"),
            _entry(110, "BLOCK", "gateway_rm", sid="A", agent="claude"),
            _entry(120, "ALLOW", sid="B", agent="copilot"),
        ]
        sessions = group_into_sessions(entries)
        assert len(sessions) == 2
        a = find_session(sessions, "A")
        assert a is not None
        assert a.total == 2
        assert a.blocked == 1
        assert a.synthetic is False
        assert a.agents == ["claude"]

    def test_time_gap_splits_unsessioned_entries(self) -> None:
        entries = [
            _entry(1000, "ALLOW"),
            _entry(1100, "WARN", "gateway_sudo"),   # same session (gap 100s)
            _entry(5000, "ALLOW"),                   # new session (gap 3900s > 1800)
        ]
        sessions = group_into_sessions(entries, idle_gap_seconds=1800)
        assert len(sessions) == 2
        assert all(s.synthetic for s in sessions)
        totals = sorted(s.total for s in sessions)
        assert totals == [1, 2]

    def test_sessions_sorted_newest_first(self) -> None:
        entries = [
            _entry(100, sid="old"),
            _entry(9000, sid="new"),
        ]
        sessions = group_into_sessions(entries)
        assert sessions[0].session_id == "new"
        assert sessions[1].session_id == "old"

    def test_verdict_counts_and_duration(self) -> None:
        entries = [
            _entry(200, "ALLOW", sid="S"),
            _entry(210, "WARN", "r1", sid="S"),
            _entry(260, "BLOCK", "r2", sid="S"),
        ]
        s = group_into_sessions(entries)[0]
        assert (s.allowed, s.warned, s.blocked) == (1, 1, 1)
        assert s.duration_seconds == 60.0

    def test_to_dict_serializable(self) -> None:
        s = group_into_sessions([_entry(1, "BLOCK", "r", sid="X")])[0]
        d = s.to_dict()
        assert d["session_id"] == "X"
        assert d["blocked"] == 1
        assert d["top_rules"] == [{"rule_id": "r", "count": 1}]


class TestFindSession:
    def test_exact_match(self) -> None:
        sessions = group_into_sessions([_entry(1, sid="abc123")])
        assert find_session(sessions, "abc123") is not None

    def test_unique_prefix(self) -> None:
        sessions = group_into_sessions([_entry(1, sid="abc123def")])
        assert find_session(sessions, "abc1") is not None

    def test_ambiguous_prefix_returns_none(self) -> None:
        sessions = group_into_sessions([
            _entry(1, sid="abc111"),
            _entry(2, sid="abc222"),
        ])
        assert find_session(sessions, "abc") is None

    def test_no_match(self) -> None:
        sessions = group_into_sessions([_entry(1, sid="xyz")])
        assert find_session(sessions, "nope") is None
