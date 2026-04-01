from __future__ import annotations

import json
from pathlib import Path

from src.services.treatment_plan import (
    TreatmentItem,
    TreatmentPlan,
    import_findings_to_plan,
    load_treatment_plan,
    save_treatment_plan,
)


def _make_item(
    finding_id: str = "rule1:file.py:10",
    status: str = "open",
) -> TreatmentItem:
    """Build a TreatmentItem with defaults."""
    return TreatmentItem(
        finding_id=finding_id,
        rule_id="rule1",
        file="file.py",
        message="Issue found",
        severity="BLOCK",
        status=status,
        remediation="Fix the issue",
        assigned_to="dev",
        updated="2026-03-30",
    )


class TestLoadTreatmentPlan:
    """Tests for load_treatment_plan from TOML."""

    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        plan = load_treatment_plan(tmp_path / "nonexistent.toml")
        assert len(plan.items) == 0

    def test_load_valid_toml(self, tmp_path: Path) -> None:
        toml_content = (
            "[[items]]\n"
            'finding_id = "eval_usage:app.py:42"\n'
            'rule_id = "eval_usage"\n'
            'file = "app.py"\n'
            'message = "Use of eval"\n'
            'severity = "BLOCK"\n'
            'status = "open"\n'
            'remediation = "Replace eval with ast.literal_eval"\n'
            'assigned_to = "security"\n'
            'updated = "2026-03-30"\n'
        )
        path = tmp_path / "treatment-plan.toml"
        path.write_text(toml_content, encoding="utf-8")

        plan = load_treatment_plan(path)
        assert len(plan.items) == 1
        assert plan.items[0].rule_id == "eval_usage"
        assert plan.items[0].status == "open"


class TestTreatmentPlanProgress:
    """Tests for TreatmentPlan.progress."""

    def test_progress_with_mixed_statuses(self) -> None:
        plan = TreatmentPlan(items=[
            _make_item("f1", "open"),
            _make_item("f2", "mitigated"),
            _make_item("f3", "in_progress"),
            _make_item("f4", "open"),
        ])
        assert plan.progress == "2/4 findings addressed (50%)"

    def test_progress_all_open(self) -> None:
        plan = TreatmentPlan(items=[
            _make_item("f1", "open"),
            _make_item("f2", "open"),
        ])
        assert plan.progress == "0/2 findings addressed (0%)"

    def test_progress_all_addressed(self) -> None:
        plan = TreatmentPlan(items=[
            _make_item("f1", "mitigated"),
            _make_item("f2", "accepted"),
        ])
        assert plan.progress == "2/2 findings addressed (100%)"

    def test_progress_empty(self) -> None:
        plan = TreatmentPlan()
        assert plan.progress == "0 findings"


class TestSaveLoadRoundtrip:
    """Test save + load roundtrip."""

    def test_roundtrip_preserves_data(self, tmp_path: Path) -> None:
        plan = TreatmentPlan(items=[
            _make_item("rule1:a.py:1", "open"),
            _make_item("rule2:b.py:5", "mitigated"),
        ])

        path = tmp_path / "plan.toml"
        save_treatment_plan(plan, path)
        loaded = load_treatment_plan(path)

        assert len(loaded.items) == 2
        assert loaded.items[0].finding_id == "rule1:a.py:1"
        assert loaded.items[0].status == "open"
        assert loaded.items[1].finding_id == "rule2:b.py:5"
        assert loaded.items[1].status == "mitigated"


class TestImportFindingsToPlan:
    """Tests for import_findings_to_plan from JSON scan report."""

    def test_imports_block_findings(self, tmp_path: Path) -> None:
        scan_data = {
            "files": {
                "app.py": [
                    {
                        "rule_id": "eval_usage",
                        "severity": "BLOCK",
                        "message": "eval() is dangerous",
                        "line": 10,
                        "suggestion": "Use ast.literal_eval",
                    },
                    {
                        "rule_id": "long_function",
                        "severity": "WARN",
                        "message": "Function too long",
                        "line": 20,
                    },
                ],
            },
        }
        report_path = tmp_path / "scan.json"
        report_path.write_text(json.dumps(scan_data), encoding="utf-8")

        plan = TreatmentPlan()
        imported = import_findings_to_plan(plan, report_path)

        assert imported == 1  # Only BLOCK, not WARN
        assert len(plan.items) == 1
        assert plan.items[0].rule_id == "eval_usage"
        assert plan.items[0].severity == "BLOCK"

    def test_skips_duplicate_findings(self, tmp_path: Path) -> None:
        scan_data = {
            "files": {
                "app.py": [
                    {"rule_id": "eval_usage", "severity": "BLOCK", "message": "bad", "line": 10},
                ],
            },
        }
        report_path = tmp_path / "scan.json"
        report_path.write_text(json.dumps(scan_data), encoding="utf-8")

        plan = TreatmentPlan()
        import_findings_to_plan(plan, report_path)
        second_import = import_findings_to_plan(plan, report_path)

        assert second_import == 0
        assert len(plan.items) == 1

    def test_handles_invalid_json(self, tmp_path: Path) -> None:
        report_path = tmp_path / "bad.json"
        report_path.write_text("not json", encoding="utf-8")

        plan = TreatmentPlan()
        imported = import_findings_to_plan(plan, report_path)
        assert imported == 0

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        plan = TreatmentPlan()
        imported = import_findings_to_plan(plan, tmp_path / "missing.json")
        assert imported == 0
