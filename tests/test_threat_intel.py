"""Tests for threat-intelligence aggregation (the moat machinery)."""

from src.gateway.audit import AuditEntry
from src.services.threat_intel import (
    compute_threat_intel,
    format_threat_intel,
)

DAY = 86_400
NOW = 1_000 * DAY  # fixed reference time


def _e(ts: float, verdict: str, rule: str) -> AuditEntry:
    return AuditEntry(
        timestamp=ts, action_type="bash", verdict=verdict, rule_id=rule,
        original_action="x", message=rule, suggestion="",
    )


class TestComputeThreatIntel:
    def test_empty(self) -> None:
        intel = compute_threat_intel([], now=NOW)
        assert intel.total_events == 0
        assert intel.top_threats == []

    def test_only_block_warn_counted(self) -> None:
        entries = [
            _e(NOW - DAY, "BLOCK", "eval_exec"),
            _e(NOW - DAY, "INFO", "magic_number"),   # excluded
            _e(NOW - DAY, "ALLOW", ""),               # excluded (no rule, allow)
        ]
        intel = compute_threat_intel(entries, now=NOW)
        assert intel.total_events == 1

    def test_top_threats_ranked_by_count(self) -> None:
        entries = (
            [_e(NOW - DAY, "BLOCK", "eval_exec") for _ in range(5)]
            + [_e(NOW - DAY, "WARN", "print_debug") for _ in range(2)]
        )
        intel = compute_threat_intel(entries, now=NOW)
        assert intel.top_threats[0].rule_id == "eval_exec"
        assert intel.top_threats[0].count == 5

    def test_emerging_detects_rising_rule(self) -> None:
        # 2 in prior window, 5 in recent window → rising
        entries = (
            [_e(NOW - 10 * DAY, "BLOCK", "hardcoded_secret") for _ in range(2)]
            + [_e(NOW - 2 * DAY, "BLOCK", "hardcoded_secret") for _ in range(5)]
        )
        intel = compute_threat_intel(entries, now=NOW, recent_window_seconds=7 * DAY)
        emerging_ids = {s.rule_id for s in intel.emerging}
        assert "hardcoded_secret" in emerging_ids
        sig = next(s for s in intel.emerging if s.rule_id == "hardcoded_secret")
        assert sig.recent == 5
        assert sig.prior == 2
        assert sig.delta == 3

    def test_stable_rule_not_emerging(self) -> None:
        # equal counts in both windows → delta 0 → not emerging
        entries = (
            [_e(NOW - 10 * DAY, "BLOCK", "eval_exec") for _ in range(3)]
            + [_e(NOW - 2 * DAY, "BLOCK", "eval_exec") for _ in range(3)]
        )
        intel = compute_threat_intel(entries, now=NOW, recent_window_seconds=7 * DAY)
        assert all(s.rule_id != "eval_exec" for s in intel.emerging)

    def test_novel_flags_rare_rule(self) -> None:
        entries = (
            [_e(NOW - DAY, "BLOCK", "eval_exec") for _ in range(10)]
            + [_e(NOW - DAY, "BLOCK", "ssrf_dns_rebinding")]
        )
        intel = compute_threat_intel(entries, now=NOW)
        novel_ids = {s.rule_id for s in intel.novel}
        assert "ssrf_dns_rebinding" in novel_ids
        assert "eval_exec" not in novel_ids

    def test_category_distribution(self) -> None:
        entries = [_e(NOW - DAY, "BLOCK", "hardcoded_secret")]
        intel = compute_threat_intel(entries, now=NOW)
        assert intel.by_category.get("secrets_exposure", 0) == 1

    def test_to_dict_serializable(self) -> None:
        entries = [_e(NOW - DAY, "BLOCK", "eval_exec")]
        d = compute_threat_intel(entries, now=NOW).to_dict()
        assert "top_threats" in d and "emerging" in d and "novel" in d

    def test_format_handles_empty(self) -> None:
        out = format_threat_intel(compute_threat_intel([], now=NOW))
        assert "builds as agents act" in out

    def test_format_renders_sections(self) -> None:
        entries = [_e(NOW - DAY, "BLOCK", "eval_exec") for _ in range(3)]
        out = format_threat_intel(compute_threat_intel(entries, now=NOW))
        assert "Top threats" in out
        assert "eval_exec" in out
