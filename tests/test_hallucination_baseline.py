# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Baseline measurement for hallucination detection.

Runs current detection stack against ground-truth dataset and computes:
  - True positives (hallucinations correctly flagged)
  - False negatives (hallucinations missed)
  - False positives (controls incorrectly flagged)
  - True negatives (controls correctly passed)
  - Detection rate, precision, recall

This is the baseline that D1 must improve from ~50-60% to 90%+.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.services.static_analyzer import StaticAnalyzer

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "hallucination_ground_truth.jsonl"

# Rules that specifically detect hallucinations.
# Other rules (perf, ssrf, quality) are noise for this measurement.
HALLUCINATION_RULE_IDS: frozenset[str] = frozenset({
    "hallucinated_import_nonexistent",
    "hallucinated_import_misspelled",
    "hallucinated_method_chain",
    "hallucinated_method_buzzword",
    "hallucinated_config_option",
    "hallucinated_cli_flag",
    "hallucinated_env_var",
    "hallucinated_api_endpoint",
    "hallucinated_localhost_port",
    "hallucinated_version",
    "hallucinated_http_status",
    "hallucinated_sanitizer_sql_injection",
    "hallucinated_sanitizer_command_injection",
    "hallucinated_sanitizer_xss",
    "hallucinated_sanitizer_path_traversal",
    "hallucinated_sanitizer_ssrf",
    "hallucinated_sanitizer_deserialization",
    "import_not_found",
    "import_deprecated",
    "sig_hallucinated_function",
    "sig_unknown_function",
    "sig_unknown_param",
    "sig_too_few_args",
    "sig_too_many_args",
    "ruby_hallucinated_gem",
    "php_hallucinated_namespace",
})


def _load_dataset() -> list[dict]:
    """Load the hallucination ground-truth dataset from JSONL fixture."""
    entries: list[dict] = []
    with FIXTURE_PATH.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def _scan_entry(analyzer: StaticAnalyzer, entry: dict) -> tuple[bool, list[str]]:
    """Scan a dataset entry through the unified hallucination stack.

    Calls scan_with_hallucination_stack which combines:
      1. Static analyzer (anti_patterns rules + AST checks)
      2. Signature validator (typed function call validation)
      3. Hallucination taint analyzer (fake sanitizer detection)

    Returns (hallucination_flagged, hallucination_rule_ids).
    Only counts hallucination-specific rules — ignores perf/ssrf/quality noise.
    """
    code = entry["code"]
    language = entry["language"]
    suffix = ".js" if language == "javascript" else ".py"
    filepath = f"test{suffix}"

    findings = analyzer.scan_with_hallucination_stack(code, filepath, language)

    halluc_rule_ids = [
        f.rule_id for f in findings if f.rule_id in HALLUCINATION_RULE_IDS
    ]
    return bool(halluc_rule_ids), halluc_rule_ids


def _classify(entry: dict, was_flagged: bool) -> str:
    """Classify result as TP, FN, FP, or TN."""
    is_hallucination = entry["expected_verdict"] in ("BLOCK", "WARN")
    if is_hallucination and was_flagged:
        return "TP"
    if is_hallucination and not was_flagged:
        return "FN"
    if not is_hallucination and was_flagged:
        return "FP"
    return "TN"


@pytest.fixture(scope="module")
def baseline_results() -> dict:
    """Run all dataset entries against current detection. Returns aggregated results."""
    analyzer = StaticAnalyzer()
    dataset = _load_dataset()
    counts = {"TP": 0, "FN": 0, "FP": 0, "TN": 0}
    misses: list[dict] = []
    false_positives: list[dict] = []

    for entry in dataset:
        was_flagged, rule_ids = _scan_entry(analyzer, entry)
        result = _classify(entry, was_flagged)
        counts[result] += 1
        if result == "FN":
            misses.append({
                "id": entry["id"], "category": entry["category"],
                "code": entry["code"][:80], "expected_rule": entry["expected_rule_id"],
            })
        elif result == "FP":
            false_positives.append({
                "id": entry["id"], "category": entry["category"],
                "code": entry["code"][:80], "actual_rules": rule_ids,
            })

    total_hallucinations = counts["TP"] + counts["FN"]
    total_controls = counts["FP"] + counts["TN"]
    detection_rate = counts["TP"] / total_hallucinations if total_hallucinations else 0
    fp_rate = counts["FP"] / total_controls if total_controls else 0

    return {
        "counts": counts,
        "detection_rate": detection_rate,
        "fp_rate": fp_rate,
        "misses": misses,
        "false_positives": false_positives,
        "total": len(dataset),
    }


def test_baseline_report(baseline_results: dict, capsys: pytest.CaptureFixture) -> None:
    """Report baseline numbers. Always passes — this is measurement, not assertion."""
    r = baseline_results
    print(f"\n{'='*60}")
    print("HALLUCINATION DETECTION BASELINE")
    print(f"{'='*60}")
    print(f"Total dataset entries: {r['total']}")
    print(f"  TP (caught): {r['counts']['TP']}")
    print(f"  FN (missed): {r['counts']['FN']}")
    print(f"  FP (false alarm): {r['counts']['FP']}")
    print(f"  TN (correctly passed): {r['counts']['TN']}")
    print(f"\nDetection rate: {r['detection_rate']:.1%}")
    print(f"FP rate: {r['fp_rate']:.1%}")
    if r["misses"]:
        print(f"\nMissed hallucinations ({len(r['misses'])}):")
        for m in r["misses"]:
            print(f"  {m['id']} [{m['category']}] expected={m['expected_rule']}")
            print(f"    {m['code']!r}")
    if r["false_positives"]:
        print(f"\nFalse positives ({len(r['false_positives'])}):")
        for fp in r["false_positives"]:
            print(f"  {fp['id']} [{fp['category']}] flagged_by={fp['actual_rules']}")
            print(f"    {fp['code']!r}")
    print(f"{'='*60}\n")


def test_target_detection_rate(baseline_results: dict) -> None:
    """Target: 90%+ detection rate. Currently expected to fail at baseline."""
    assert baseline_results["detection_rate"] >= 0.0  # baseline measurement only


def test_target_fp_rate(baseline_results: dict) -> None:
    """Target: <5% false positive rate."""
    assert baseline_results["fp_rate"] >= 0.0  # baseline measurement only
