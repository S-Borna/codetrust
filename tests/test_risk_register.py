from __future__ import annotations

from pathlib import Path

from src.services.risk_register import (
    Risk,
    RiskRegister,
    add_risk,
    format_register,
    load_register,
    save_register,
)


class TestRisk:
    """Tests for the Risk dataclass."""

    def test_risk_score_property(self) -> None:
        """risk_score returns likelihood * impact."""
        risk = Risk(
            risk_id="RISK-001",
            title="Test risk",
            description="desc",
            likelihood=3,
            impact=4,
            mitigation="mitigate",
            owner="owner",
            review_date="2026-03-30",
            status="open",
        )
        assert risk.risk_score == 12

    def test_risk_score_boundary_values(self) -> None:
        """Score at boundaries: 1*1=1, 5*5=25."""
        low = Risk("R1", "low", "", 1, 1, "", "", "", "open")
        high = Risk("R2", "high", "", 5, 5, "", "", "", "open")
        assert low.risk_score == 1
        assert high.risk_score == 25


class TestRiskRegister:
    """Tests for the RiskRegister collection."""

    def _make_register(self) -> RiskRegister:
        """Build a register with mixed statuses."""
        return RiskRegister(risks=[
            Risk("R1", "A", "", 5, 5, "", "", "", "open"),
            Risk("R2", "B", "", 3, 3, "", "", "", "mitigated"),
            Risk("R3", "C", "", 2, 2, "", "", "", "closed"),
            Risk("R4", "D", "", 5, 4, "", "", "", "open"),
        ])

    def test_open_risks_excludes_closed(self) -> None:
        reg = self._make_register()
        ids = [r.risk_id for r in reg.open_risks]
        assert "R3" not in ids
        assert len(ids) == 3

    def test_high_risks_threshold(self) -> None:
        reg = self._make_register()
        high = reg.high_risks
        assert all(r.risk_score >= 15 for r in high)
        assert len(high) == 2  # R1 (25), R4 (20)

    def test_summary_format(self) -> None:
        reg = self._make_register()
        s = reg.summary()
        assert "4 risks" in s
        assert "open" in s
        assert "closed" in s


class TestLoadRegister:
    """Tests for load_register from TOML."""

    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        reg = load_register(tmp_path / "nonexistent.toml")
        assert len(reg.risks) == 0

    def test_load_valid_toml(self, tmp_path: Path) -> None:
        toml_content = (
            "[[risks]]\n"
            'risk_id = "RISK-001"\n'
            'title = "Data leak"\n'
            'description = "Possible data exfiltration"\n'
            "likelihood = 4\n"
            "impact = 5\n"
            'mitigation = "Encrypt at rest"\n'
            'owner = "security-team"\n'
            'review_date = "2026-04-01"\n'
            'status = "open"\n'
        )
        path = tmp_path / "risk-register.toml"
        path.write_text(toml_content, encoding="utf-8")

        reg = load_register(path)
        assert len(reg.risks) == 1
        assert reg.risks[0].risk_id == "RISK-001"
        assert reg.risks[0].likelihood == 4
        assert reg.risks[0].impact == 5


class TestAddRisk:
    """Tests for add_risk."""

    def test_add_risk_creates_correct_fields(self) -> None:
        reg = RiskRegister()
        risk = add_risk(reg, "Title", "Desc", 3, 4, "Fix it", "owner")
        assert risk.risk_id == "RISK-001"
        assert risk.title == "Title"
        assert risk.likelihood == 3
        assert risk.impact == 4
        assert risk.status == "open"
        assert len(reg.risks) == 1

    def test_add_risk_clamps_values(self) -> None:
        reg = RiskRegister()
        risk = add_risk(reg, "T", "D", 99, -5, "m", "o")
        assert risk.likelihood == 5
        assert risk.impact == 1

    def test_add_risk_increments_id(self) -> None:
        reg = RiskRegister()
        add_risk(reg, "A", "d", 1, 1, "m", "o")
        r2 = add_risk(reg, "B", "d", 1, 1, "m", "o")
        assert r2.risk_id == "RISK-002"


class TestSaveLoadRoundtrip:
    """Test save_register + load_register roundtrip."""

    def test_roundtrip_preserves_data(self, tmp_path: Path) -> None:
        reg = RiskRegister()
        add_risk(reg, "Risk Alpha", "Alpha desc", 3, 4, "Mitigate alpha", "team-a")
        add_risk(reg, "Risk Beta", "Beta desc", 2, 5, "Mitigate beta", "team-b")

        path = tmp_path / "register.toml"
        save_register(reg, path)
        loaded = load_register(path)

        assert len(loaded.risks) == 2
        assert loaded.risks[0].title == "Risk Alpha"
        assert loaded.risks[0].likelihood == 3
        assert loaded.risks[1].title == "Risk Beta"
        assert loaded.risks[1].impact == 5


class TestFormatRegister:
    """Test format_register produces Markdown."""

    def test_format_contains_markdown_table(self) -> None:
        reg = RiskRegister()
        add_risk(reg, "Test Risk", "desc", 3, 4, "mitigate", "owner")
        md = format_register(reg)
        assert "# Risk Register" in md
        assert "| ID |" in md
        assert "RISK-001" in md
        assert "Test Risk" in md

    def test_format_empty_register(self) -> None:
        md = format_register(RiskRegister())
        assert "# Risk Register" in md
        assert "0 risks" in md
