from __future__ import annotations

import pytest

from src.services.ai_attribution import (
    LineAttribution,
    per_line_summary,
)


class TestLineAttribution:
    """Tests for LineAttribution dataclass fields."""

    def test_fields_accessible(self) -> None:
        attr = LineAttribution(
            line_number=10,
            commit="abc123def456",
            author="dev",
            ai_model="claude-opus-4-6",
            timestamp="1711814400",
        )
        assert attr.line_number == 10
        assert attr.commit == "abc123def456"
        assert attr.author == "dev"
        assert attr.ai_model == "claude-opus-4-6"
        assert attr.timestamp == "1711814400"

    def test_empty_ai_model_means_human(self) -> None:
        attr = LineAttribution(
            line_number=1, commit="aaa", author="dev", ai_model="", timestamp="0",
        )
        assert attr.ai_model == ""


class TestPerLineSummary:
    """Tests for per_line_summary aggregation."""

    def test_aggregation_with_mixed_models(self) -> None:
        attrs = [
            LineAttribution(1, "c1", "dev", "claude-opus-4-6", "0"),
            LineAttribution(2, "c1", "dev", "claude-opus-4-6", "0"),
            LineAttribution(3, "c2", "dev", "", "0"),
            LineAttribution(4, "c3", "dev", "gpt-4o", "0"),
        ]
        result = per_line_summary(attrs)
        assert result["claude-opus-4-6"] == 50.0
        assert result["human"] == 25.0
        assert result["gpt-4o"] == 25.0

    def test_all_human(self) -> None:
        attrs = [
            LineAttribution(i, "c1", "dev", "", "0")
            for i in range(1, 6)
        ]
        result = per_line_summary(attrs)
        assert result == {"human": 100.0}

    def test_all_ai(self) -> None:
        attrs = [
            LineAttribution(i, "c1", "dev", "copilot", "0")
            for i in range(1, 4)
        ]
        result = per_line_summary(attrs)
        assert result == {"copilot": 100.0}

    def test_empty_input_returns_empty(self) -> None:
        result = per_line_summary([])
        assert result == {}

    def test_percentages_sum_to_100(self) -> None:
        attrs = [
            LineAttribution(1, "c1", "dev", "model-a", "0"),
            LineAttribution(2, "c1", "dev", "model-b", "0"),
            LineAttribution(3, "c1", "dev", "", "0"),
        ]
        result = per_line_summary(attrs)
        total = sum(result.values())
        assert abs(total - 100.0) < 0.5
