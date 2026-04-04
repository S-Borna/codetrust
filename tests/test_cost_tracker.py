# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for LLM Cost Tracking Engine."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from src.services.cost_storage import LLMUsageEvent, append_event, clear_events, read_events
from src.services.cost_tracker import (
    CostReport,
    calculate_cost,
    check_budget,
    detect_anomalies,
    generate_report,
    get_model_pricing,
    log_usage,
)


@pytest.fixture(autouse=True)
def _clean_cost_storage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate cost storage to tmp_path so tests don't write to project CWD."""
    monkeypatch.setattr(
        "src.services.cost_storage._DEFAULT_STORAGE_PATH",
        str(tmp_path / ".codetrust" / "cost-events.jsonl"),
    )


# ───────────────────────────────────────────────────────────────
#  Pricing tests
# ───────────────────────────────────────────────────────────────


class TestPricing:
    """Test model pricing lookup and cost calculation."""

    def test_known_model_exact(self) -> None:
        pricing, estimated = get_model_pricing("claude-opus-4.6")
        assert pricing == (15.0, 75.0)
        assert estimated is False

    def test_known_model_prefix(self) -> None:
        pricing, estimated = get_model_pricing("claude-opus-4-some-date")
        assert pricing[0] == 15.0
        assert estimated is False

    def test_unknown_model_returns_default(self) -> None:
        pricing, estimated = get_model_pricing("totally-unknown-model")
        assert estimated is True
        assert pricing[0] > 0

    def test_calculate_cost_opus(self) -> None:
        cost, est = calculate_cost("claude-opus-4.6", 1_000_000, 100_000)
        assert cost == 15.0 + 7.5  # 15/M input + 75/M * 0.1M output
        assert est is False

    def test_calculate_cost_zero_tokens(self) -> None:
        cost, est = calculate_cost("gpt-4o", 0, 0)
        assert cost == 0.0
        assert est is False

    def test_calculate_cost_small(self) -> None:
        cost, est = calculate_cost("gpt-4.1", 1000, 500)
        # (1000/1M)*2.0 + (500/1M)*8.0 = 0.002 + 0.004 = 0.006
        assert abs(cost - 0.006) < 0.001
        assert est is False

    def test_gpt_41_mini_pricing(self) -> None:
        pricing, est = get_model_pricing("gpt-4.1-mini")
        assert pricing == (0.40, 1.60)
        assert est is False

    def test_o3_mini_pricing(self) -> None:
        pricing, est = get_model_pricing("o3-mini")
        assert pricing == (1.10, 4.40)
        assert est is False

    def test_gemini_flash_pricing(self) -> None:
        pricing, est = get_model_pricing("gemini-2.5-flash")
        assert pricing == (0.15, 0.60)
        assert est is False


# ───────────────────────────────────────────────────────────────
#  Storage tests
# ───────────────────────────────────────────────────────────────


class TestStorage:
    """Test JSONL event storage."""

    def test_append_and_read(self, tmp_path: Path) -> None:
        event = LLMUsageEvent(
            timestamp=datetime.now(UTC).isoformat(),
            model="gpt-4o", provider="openai",
            input_tokens=100, output_tokens=50, total_tokens=150,
            estimated_cost_usd=0.001, developer="test", team="eng",
            project="myapp", session_id="s1", action="scan",
        )
        append_event(event, tmp_path)
        events = read_events(tmp_path)
        assert len(events) == 1
        assert events[0].model == "gpt-4o"
        assert events[0].developer == "test"

    def test_read_empty_returns_empty(self, tmp_path: Path) -> None:
        events = read_events(tmp_path)
        assert events == []

    def test_date_filtering(self, tmp_path: Path) -> None:
        old = LLMUsageEvent(
            timestamp="2025-01-01T00:00:00+00:00",
            model="gpt-4o", provider="openai",
            input_tokens=100, output_tokens=50, total_tokens=150,
            estimated_cost_usd=0.001, developer="old", team="",
            project="p", session_id="", action="scan",
        )
        new = LLMUsageEvent(
            timestamp="2026-04-01T00:00:00+00:00",
            model="gpt-4o", provider="openai",
            input_tokens=200, output_tokens=100, total_tokens=300,
            estimated_cost_usd=0.002, developer="new", team="",
            project="p", session_id="", action="scan",
        )
        append_event(old, tmp_path)
        append_event(new, tmp_path)

        filtered = read_events(tmp_path, start_date="2026-01-01")
        assert len(filtered) == 1
        assert filtered[0].developer == "new"

    def test_clear_events(self, tmp_path: Path) -> None:
        event = LLMUsageEvent(
            timestamp=datetime.now(UTC).isoformat(),
            model="gpt-4o", provider="openai",
            input_tokens=100, output_tokens=50, total_tokens=150,
            estimated_cost_usd=0.001, developer="test", team="",
            project="p", session_id="", action="scan",
        )
        append_event(event, tmp_path)
        clear_events(tmp_path)
        assert read_events(tmp_path) == []


# ───────────────────────────────────────────────────────────────
#  Aggregation / report tests
# ───────────────────────────────────────────────────────────────


class TestAggregation:
    """Test cost report aggregation."""

    def test_report_structure(self, tmp_path: Path) -> None:
        log_usage("gpt-4o", "openai", 1000, 500, developer="alice", project_dir=tmp_path)
        report = generate_report(project_dir=tmp_path)
        assert isinstance(report, CostReport)
        assert report.total_cost_usd > 0
        assert report.total_tokens == 1500
        assert report.event_count == 1
        assert "alice" in report.by_developer

    def test_by_model_aggregation(self, tmp_path: Path) -> None:
        log_usage("gpt-4o", "openai", 1000, 500, developer="a", project_dir=tmp_path)
        log_usage("claude-opus-4.6", "anthropic", 1000, 500, developer="b", project_dir=tmp_path)
        report = generate_report(project_dir=tmp_path)
        assert "gpt-4o" in report.by_model
        assert "claude-opus-4.6" in report.by_model

    def test_by_team_aggregation(self, tmp_path: Path) -> None:
        log_usage("gpt-4o", "openai", 1000, 500, developer="a", team="eng", project_dir=tmp_path)
        log_usage("gpt-4o", "openai", 2000, 1000, developer="b", team="eng", project_dir=tmp_path)
        report = generate_report(project_dir=tmp_path)
        assert "eng" in report.by_team
        assert report.by_team["eng"] > 0

    def test_developer_filter(self, tmp_path: Path) -> None:
        log_usage("gpt-4o", "openai", 1000, 500, developer="alice", project_dir=tmp_path)
        log_usage("gpt-4o", "openai", 2000, 1000, developer="bob", project_dir=tmp_path)
        report = generate_report(developer="alice", project_dir=tmp_path)
        assert report.event_count == 1
        assert "alice" in report.by_developer

    def test_to_dict_serializable(self, tmp_path: Path) -> None:
        log_usage("gpt-4o", "openai", 1000, 500, developer="a", project_dir=tmp_path)
        report = generate_report(project_dir=tmp_path)
        d = report.to_dict()
        json.dumps(d)
        assert "total_cost_usd" in d
        assert "by_developer" in d


# ───────────────────────────────────────────────────────────────
#  Anomaly tests
# ───────────────────────────────────────────────────────────────


class TestAnomalyDetection:
    """Test cost anomaly detection."""

    def test_no_events_no_anomalies(self) -> None:
        anomalies = detect_anomalies([])
        assert anomalies == []

    def test_team_concentration_flagged(self, tmp_path: Path) -> None:
        today = datetime.now(UTC).isoformat()
        events = [
            LLMUsageEvent(
                timestamp=today, model="gpt-4o", provider="openai",
                input_tokens=100000, output_tokens=50000, total_tokens=150000,
                estimated_cost_usd=10.0, developer="big_spender", team="eng",
                project="p", session_id="", action="scan",
            ),
            LLMUsageEvent(
                timestamp=today, model="gpt-4o", provider="openai",
                input_tokens=1000, output_tokens=500, total_tokens=1500,
                estimated_cost_usd=0.01, developer="small_user", team="eng",
                project="p", session_id="", action="scan",
            ),
        ]
        anomalies = detect_anomalies(events, tmp_path)
        team_anomalies = [a for a in anomalies if a["type"] == "team_concentration"]
        assert len(team_anomalies) >= 1
        assert team_anomalies[0]["developer"] == "big_spender"

    def test_high_daily_spend_flagged(self, tmp_path: Path) -> None:
        now = datetime.now(UTC)
        today = now.isoformat()

        # Create 7 days of low historical usage
        for i in range(7):
            day = (now - timedelta(days=i + 1)).isoformat()
            event = LLMUsageEvent(
                timestamp=day, model="gpt-4o", provider="openai",
                input_tokens=1000, output_tokens=500, total_tokens=1500,
                estimated_cost_usd=0.01, developer="dev1", team="",
                project="p", session_id="", action="scan",
            )
            append_event(event, tmp_path)

        # Today: 10x the normal cost
        today_event = LLMUsageEvent(
            timestamp=today, model="gpt-4o", provider="openai",
            input_tokens=100000, output_tokens=50000, total_tokens=150000,
            estimated_cost_usd=1.00, developer="dev1", team="",
            project="p", session_id="", action="scan",
        )

        anomalies = detect_anomalies([today_event], tmp_path)
        high_spend = [a for a in anomalies if a["type"] == "high_daily_spend"]
        assert len(high_spend) >= 1
        assert high_spend[0]["developer"] == "dev1"


# ───────────────────────────────────────────────────────────────
#  Budget tests
# ───────────────────────────────────────────────────────────────


class TestBudget:
    """Test budget checking."""

    def test_no_budget_configured(self) -> None:
        status = check_budget(100.0, {"dev": 100.0}, Path("/nonexistent"))
        assert status["configured"] is False
        assert status["level"] == "ok"

    def test_under_budget_ok(self, tmp_path: Path) -> None:
        # Write a config with budget
        config = tmp_path / ".codetrust.toml"
        config.write_text('[cost.budget]\nmonthly_limit = 1000.0\n', encoding="utf-8")
        status = check_budget(100.0, {"dev": 100.0}, tmp_path)
        assert status["configured"] is True
        assert status["level"] == "ok"

    def test_warn_at_80_percent(self, tmp_path: Path) -> None:
        config = tmp_path / ".codetrust.toml"
        config.write_text('[cost.budget]\nmonthly_limit = 100.0\n', encoding="utf-8")
        status = check_budget(85.0, {"dev": 85.0}, tmp_path)
        assert status["level"] == "warn"

    def test_alert_at_95_percent(self, tmp_path: Path) -> None:
        config = tmp_path / ".codetrust.toml"
        config.write_text('[cost.budget]\nmonthly_limit = 100.0\n', encoding="utf-8")
        status = check_budget(96.0, {"dev": 96.0}, tmp_path)
        assert status["level"] == "alert"

    def test_exceeded_at_100_percent(self, tmp_path: Path) -> None:
        config = tmp_path / ".codetrust.toml"
        config.write_text('[cost.budget]\nmonthly_limit = 100.0\n', encoding="utf-8")
        status = check_budget(105.0, {"dev": 105.0}, tmp_path)
        assert status["level"] == "exceeded"

    def test_per_developer_limit(self, tmp_path: Path) -> None:
        config = tmp_path / ".codetrust.toml"
        config.write_text(
            '[cost.budget]\nmonthly_limit = 5000.0\n'
            '[cost.budget.per_developer]\nmonthly_limit = 100.0\n',
            encoding="utf-8",
        )
        status = check_budget(200.0, {"alice": 120.0, "bob": 80.0}, tmp_path)
        assert status["configured"] is True
        dev_alerts = status.get("developer_alerts", [])
        alice_alerts = [a for a in dev_alerts if a["developer"] == "alice"]
        assert len(alice_alerts) >= 1
        assert alice_alerts[0]["level"] == "exceeded"


# ───────────────────────────────────────────────────────────────
#  CLI tests
# ───────────────────────────────────────────────────────────────


class TestCLI:
    """Test cost CLI commands."""

    def test_cost_default_report(self) -> None:
        from src.cli import cmd_cost
        args = argparse.Namespace(
            cost_action=None, period="monthly", developer="",
            team="", model="", project="", json_output=False, export=None,
        )
        result = cmd_cost(args)
        assert result == 0

    def test_cost_budget(self) -> None:
        from src.cli import cmd_cost
        args = argparse.Namespace(cost_action="budget")
        result = cmd_cost(args)
        assert result == 0

    def test_cost_anomalies(self) -> None:
        from src.cli import cmd_cost
        args = argparse.Namespace(cost_action="anomalies")
        result = cmd_cost(args)
        assert result == 0

    def test_cost_log_event(self, tmp_path: Path) -> None:
        from src.cli import cmd_cost
        event_json = json.dumps({
            "model": "gpt-4o", "provider": "openai",
            "input_tokens": 100, "output_tokens": 50,
        })
        args = argparse.Namespace(cost_action="log", event_json=event_json)
        result = cmd_cost(args)
        assert result == 0

    def test_cost_json_output(self) -> None:
        from src.cli import cmd_cost
        args = argparse.Namespace(
            cost_action=None, period="monthly", developer="",
            team="", model="", project="", json_output=True, export=None,
        )
        result = cmd_cost(args)
        assert result == 0
