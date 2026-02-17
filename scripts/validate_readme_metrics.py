#!/usr/bin/env python3
"""Validate README numbers match metrics.json.

Run: python scripts/validate_readme_metrics.py
Exit code 0 = all numbers match, 1 = drift detected.

Used in CI to prevent documentation drift.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_metrics() -> dict:
    """Load metrics.json."""
    metrics_file = ROOT / "metrics.json"
    if not metrics_file.exists():
        print("ERROR: metrics.json not found. Run: python scripts/generate_metrics.py")
        sys.exit(1)
    return json.loads(metrics_file.read_text())


def check_readme(metrics: dict) -> list[str]:
    """Check README.md numbers against metrics."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    errors = []

    checks = [
        ("total_rules", r"(\d+) rules across 10 enforcement layers"),
        ("mcp_tools", r"(\d+) MCP tools"),
        ("tests_collected", r"# (\d+) tests"),
        ("api_endpoints", r"(\d+) endpoints"),
    ]

    for key, pattern in checks:
        expected = metrics[key]
        match = re.search(pattern, readme)
        if match:
            found = int(match.group(1))
            if found != expected:
                errors.append(
                    f"  {key}: README says {found}, source has {expected}"
                )
        else:
            errors.append(f"  {key}: pattern not found in README")

    return errors


def main() -> None:
    metrics = load_metrics()
    errors = check_readme(metrics)

    if errors:
        print("README metrics drift detected:")
        for e in errors:
            print(e)
        print()
        print("Fix: python scripts/generate_metrics.py && update README")
        sys.exit(1)
    else:
        print(f"All README numbers match source (v{metrics['version']})")
        print(f"  total_rules: {metrics['total_rules']}")
        print(f"  mcp_tools: {metrics['mcp_tools']}")
        print(f"  api_endpoints: {metrics['api_endpoints']}")
        print(f"  tests_collected: {metrics['tests_collected']}")


if __name__ == "__main__":
    main()
