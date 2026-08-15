#!/usr/bin/env python3
"""Generate metrics.json from source code.

Counts rules, tools, endpoints, and tests directly from the codebase.
Run: python scripts/generate_metrics.py
Output: metrics.json in project root.

Used in CI to validate that README numbers match reality.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def count_pattern(filepath: Path, pattern: str) -> int:
    """Count occurrences of a regex pattern in a file."""
    text = filepath.read_text(encoding="utf-8")
    return len(re.findall(pattern, text))


def count_scan_rules() -> int:
    """Count rules in ANTI_PATTERNS list via '"id":' entries."""
    return count_pattern(SRC / "rules" / "anti_patterns.py", r'"id"\s*:')


def count_enterprise_rule_ids() -> int:
    """Count distinct enterprise rule IDs (one per list)."""
    # 4 lists: REQUIRED_FILES, RECOMMENDED_FILES, RECOMMENDED_DIRS, FORBIDDEN_PATTERNS
    # Each produces one rule ID in the analyzer
    return 4


def count_gateway_terminal_rules() -> int:
    """Count terminal interception rules."""
    return count_pattern(SRC / "gateway" / "interceptor.py", r'"id"\s*:')


def count_gateway_content_rules() -> int:
    """Count content interception rules separately."""
    text = (SRC / "gateway" / "interceptor.py").read_text(encoding="utf-8")
    # Content rules start after _CONTENT_RULES assignment
    content_section = text.split("_CONTENT_RULES")[1] if "_CONTENT_RULES" in text else ""
    return len(re.findall(r'"id"\s*:', content_section))


def count_gateway_rules() -> tuple[int, int]:
    """Count gateway rules: (terminal, content)."""
    text = (SRC / "gateway" / "interceptor.py").read_text(encoding="utf-8")

    # Only count "id": inside list definitions, not runtime references like rule["id"]
    # Split at _CONTENT_RULES list definition
    content_start = text.find("_CONTENT_RULES: list[dict]")
    if content_start == -1:
        content_start = text.find("_CONTENT_RULES =")

    if content_start != -1:
        # Find end of _CONTENT_RULES list (next class/function def or top-level variable)
        terminal_section = text[:content_start]
        content_section = text[content_start:]
        # Stop counting at the class definition
        class_start = content_section.find("\nclass ")
        if class_start != -1:
            content_section = content_section[:class_start]

        terminal = len(re.findall(r'^\s+"id"\s*:', terminal_section, re.MULTILINE))
        content = len(re.findall(r'^\s+"id"\s*:', content_section, re.MULTILINE))
    else:
        terminal = len(re.findall(r'^\s+"id"\s*:', text, re.MULTILINE))
        content = 0

    return terminal, content


def count_mcp_tools_scanner() -> int:
    """Count MCP tool registrations in scanner server."""
    return count_pattern(SRC / "server.py", r"@mcp\.tool")


def count_mcp_tools_gateway() -> int:
    """Count MCP tool registrations in gateway server."""
    return count_pattern(SRC / "gateway" / "server.py", r"@gateway\.tool")


def count_api_endpoints() -> int:
    """Count public REST API endpoints (method+path operations, not unique paths)."""
    try:
        from src.api import app

        schema = app.openapi()
        methods = {"get", "post", "put", "delete", "patch"}
        return sum(
            len(methods & set(operations))
            for operations in schema.get("paths", {}).values()
        )
    except Exception:
        # Fallback to decorator counting if OpenAPI generation fails.
        return count_pattern(
            SRC / "api.py",
            r"@app\.(get|post|put|delete|patch)|app\.add_route",
        )


def count_tests() -> int:
    """Count tests via pytest --collect-only."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "--co", "-q"],
            capture_output=True,
            text=True,
            cwd=ROOT,
            timeout=30,
        )
        # Last line: "1314 tests collected in 0.56s"
        for line in result.stdout.strip().splitlines()[::-1]:
            m = re.search(r"(\d+)\s+tests?\s+collected", line)
            if m:
                return int(m.group(1))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return 0  # pytest unavailable or too slow — fall back to 0
    return 0


def get_coverage() -> float | None:
    """Get coverage percentage if available."""
    cov_file = ROOT / "coverage.json"
    if cov_file.exists():
        data = json.loads(cov_file.read_text())
        return data.get("totals", {}).get("percent_covered", None)
    return None


def get_version() -> str:
    """Extract version from pyproject.toml."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*"([^"]+)"', text)
    return m.group(1) if m else "unknown"


def generate() -> dict:
    """Generate all metrics from source."""
    terminal_rules, content_rules = count_gateway_rules()
    gateway_total = terminal_rules + content_rules
    scan_rules = count_scan_rules()
    mcp_scanner = count_mcp_tools_scanner()
    mcp_gateway = count_mcp_tools_gateway()

    metrics = {
        "version": get_version(),
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_rules": scan_rules,
        "enterprise_rule_ids": count_enterprise_rule_ids(),
        "gateway_terminal_rules": terminal_rules,
        "gateway_content_rules": content_rules,
        "gateway_rules": gateway_total,
        "total_rules": scan_rules + gateway_total,
        "mcp_tools_scanner": mcp_scanner,
        "mcp_tools_gateway": mcp_gateway,
        "mcp_tools": mcp_scanner + mcp_gateway,
        "api_endpoints": count_api_endpoints(),
        "tests_collected": count_tests(),
        "coverage_percent": get_coverage(),
    }
    return metrics


def main() -> None:
    metrics = generate()
    output = ROOT / "metrics.json"
    output.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")

    print(f"metrics.json generated (v{metrics['version']})")
    print()
    for key, val in metrics.items():
        if key in ("version", "generated_at"):
            continue
        print(f"  {key}: {val}")


if __name__ == "__main__":
    main()
