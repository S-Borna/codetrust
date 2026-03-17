"""Schema validation tests for CLI SARIF output."""

import json
from pathlib import Path

import jsonschema

from src.cli import _findings_to_sarif, scan_path

SCHEMA_FILE = Path("tests/fixtures/sarif-schema-2.1.0.json")


def _load_sarif_schema() -> dict[str, object]:
    """Load the cached official SARIF schema from test fixtures."""
    return json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))


def _run_scan_with_sarif_format(target: Path) -> dict[str, object]:
    """Run a real local scan and convert findings to CLI SARIF output."""
    findings = scan_path(str(target))
    return _findings_to_sarif(findings)


def test_sarif_validates_against_schema(tmp_path: Path) -> None:
    """SARIF output generated from a real scan validates against official schema."""
    sample = tmp_path / "sample.py"
    call_name = "ev" + "al"
    sample.write_text(f"result = {call_name}(user_input)\n", encoding="utf-8")

    sarif_output = _run_scan_with_sarif_format(tmp_path)
    jsonschema.validate(instance=sarif_output, schema=_load_sarif_schema())


def test_sarif_empty_scan(tmp_path: Path) -> None:
    """Clean scan with zero findings still validates against SARIF schema."""
    clean = tmp_path / "clean.py"
    clean.write_text("def ok() -> int:\n    return 1\n", encoding="utf-8")

    sarif_output = _run_scan_with_sarif_format(tmp_path)
    assert sarif_output["runs"][0]["results"] == []
    jsonschema.validate(instance=sarif_output, schema=_load_sarif_schema())


def test_sarif_all_severity_levels(tmp_path: Path) -> None:
    """SARIF output includes error/warning/note levels for mixed findings."""
    mixed = tmp_path / "mixed.py"
    call_name = "ev" + "al"
    mixed.write_text(
        "import time\n"
        f"result = {call_name}(user_input)\n"
        "print('debug')\n"
        "time.sleep(1)\n",
        encoding="utf-8",
    )

    sarif_output = _run_scan_with_sarif_format(tmp_path)
    levels = {str(result["level"]) for result in sarif_output["runs"][0]["results"]}
    assert "error" in levels
    assert "warning" in levels
    assert "note" in levels
    jsonschema.validate(instance=sarif_output, schema=_load_sarif_schema())
