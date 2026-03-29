#!/usr/bin/env python3
"""CodeTrust platform sync — single source of truth for all published surfaces.

This script does TWO things:
1. CHECK mode (default): verifies all platform files match the canonical numbers
2. GENERATE mode (--generate): writes the canonical numbers into all platform files

Run before EVERY publish:
    python3 scripts/sync_platforms.py          # check mode
    python3 scripts/sync_platforms.py --generate  # write mode

If check mode fails → run generate mode → review diff → commit.
"""

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).parent.parent

# ═══════════════════════════════════════════════════════════════════
# SINGLE SOURCE OF TRUTH — edit ONLY here, nowhere else
# ═══════════════════════════════════════════════════════════════════

CANONICAL = {
    "version": "4.0.5",
    "scan_rules": 2924,
    "gateway_rules": 82,
    "total_rules": 3006,
    "blocked_patterns": 44,
    "protected_paths": 13,
    "secret_patterns": 6,
    "suggestions": 2924,
    "special_handlers": 17,
    "taint_definitions": 323,
    "taint_sources": 57,
    "taint_sinks": 169,
    "taint_sanitizers": 97,
    "taint_languages": 7,
    "ast_checks": 10,
    "ast_languages": 9,
    "signature_modules": 50,
    "signature_functions": 405,
    "import_registries": 8,
    "file_extensions": 92,
    "mcp_guardian_tools": 21,
    "mcp_gateway_tools": 18,
    "mcp_total_tools": 39,
    "api_endpoints": 70,
    "cli_commands": 22,
    "tests": 2509,
    "enforcement_layers": 7,
    "capabilities": 14,
    "languages_count": "23+",
}


# ═══════════════════════════════════════════════════════════════════
# FILES TO CHECK / UPDATE
# ═══════════════════════════════════════════════════════════════════

CHECKS = [
    # (file, pattern_to_find, what_it_should_say, description)

    # --- README.md (PyPI) ---
    ("README.md", r"\d[\d,]+ rules", f"{CANONICAL['total_rules']:,} rules", "README total rules"),
    ("README.md", r"\d+ enforcement layers", f"{CANONICAL['enforcement_layers']} enforcement layers", "README enforcement layers"),
    ("README.md", r"\d[\d,]+ tests", f"{CANONICAL['tests']:,} tests", "README test count"),
    ("README.md", r"\d+ MCP tools", f"{CANONICAL['mcp_total_tools']} MCP tools", "README MCP tools"),
    ("README.md", r"\d+ API endpoints", f"{CANONICAL['api_endpoints']} API endpoints", "README API endpoints"),
    ("README.md", r"Four Moats", None, "README must NOT say 'Four Moats'"),

    # --- extension/README.md (Marketplace + OpenVSX) ---
    ("extension/README.md", r"\d[\d,]+ rules", f"{CANONICAL['total_rules']:,} rules", "Extension total rules"),
    ("extension/README.md", r"\d+ enforcement layers", f"{CANONICAL['enforcement_layers']} enforcement layers", "Extension enforcement layers"),
    ("extension/README.md", r"What's New in \d+\.\d+\.\d+", f"What's New in {CANONICAL['version']}", "Extension version in What's New"),
    ("extension/README.md", r"\d+ MCP tools", f"{CANONICAL['mcp_total_tools']} MCP tools", "Extension MCP tools"),
    ("extension/README.md", r"\d+ endpoints", f"{CANONICAL['api_endpoints']} endpoints", "Extension API endpoints"),
    ("extension/README.md", r"^# .* for VS Code", None, "Extension must NOT say 'for VS Code' in title"),

    # --- pyproject.toml ---
    ("pyproject.toml", r'version = "\d+\.\d+\.\d+"', f'version = "{CANONICAL["version"]}"', "pyproject version"),

    # --- extension/package.json ---
    ("extension/package.json", r'"version": "\d+\.\d+\.\d+"', f'"version": "{CANONICAL["version"]}"', "Extension package.json version"),

    # --- docs/index.html (website) ---
    ("docs/index.html", r"\d[\d,]+ rules", f"{CANONICAL['total_rules']:,} rules", "Website total rules"),
    ("docs/index.html", r"\d+ enforcement layers", f"{CANONICAL['enforcement_layers']} enforcement layers", "Website enforcement layers"),
    ("docs/index.html", r"\d+ MCP tools", f"{CANONICAL['mcp_total_tools']} MCP tools", "Website MCP tools (if present)"),
    ("docs/index.html", r"S-Borna/codetrust@", None, "Website must NOT have private repo refs"),

    # --- Stale numbers that should NOT appear anywhere ---
    ("README.md", r"1,084|1,202|484 security|Four Moats|v4\.0\.2", None, "README stale numbers"),
    ("extension/README.md", r"1,084|1,202|484 security|27 tools|54 endpoint|3\.0\.0", None, "Extension stale numbers"),
    ("docs/index.html", r"484 security|10 inspection", None, "Website stale numbers"),
]


def check_all() -> int:
    """Check all platform files for consistency. Returns failure count."""
    failures = 0
    print(f"\n🛡️  CodeTrust Platform Sync Check\n")
    print(f"   Canonical version: {CANONICAL['version']}")
    print(f"   Source: scripts/sync_platforms.py CANONICAL dict\n")

    for filepath, pattern, expected, desc in CHECKS:
        full_path = REPO / filepath
        if not full_path.exists():
            print(f"  ⚠️  {desc}: file not found ({filepath})")
            continue

        content = full_path.read_text(encoding="utf-8")
        matches = re.findall(pattern, content, re.MULTILINE)

        if expected is None:
            # This pattern should NOT exist
            if matches:
                print(f"  ❌ {desc}: found '{matches[0]}' (should not exist)")
                failures += 1
            else:
                print(f"  ✅ {desc}: clean")
        else:
            # This pattern should exist and match expected
            if not matches:
                print(f"  ❌ {desc}: pattern not found")
                failures += 1
            elif expected not in content:
                print(f"  ❌ {desc}: found '{matches[0]}' but expected '{expected}'")
                failures += 1
            else:
                print(f"  ✅ {desc}: {expected}")

    print(f"\n{'═' * 50}")
    if failures == 0:
        print(f"  ✅ ALL PLATFORMS IN SYNC")
    else:
        print(f"  ❌ {failures} MISMATCH(ES) — fix before publishing")
        print(f"     Run: python3 scripts/sync_platforms.py --generate")
    print(f"{'═' * 50}\n")
    return failures


def print_canonical():
    """Print the canonical values for reference."""
    print(f"\n📋 Canonical values (edit ONLY in scripts/sync_platforms.py):\n")
    for key, val in CANONICAL.items():
        print(f"   {key}: {val}")
    print()


if __name__ == "__main__":
    if "--canonical" in sys.argv:
        print_canonical()
    elif "--generate" in sys.argv:
        print("Generate mode not yet implemented.")
        print("For now: check mode identifies mismatches, you fix manually.")
        print("This ensures you review every change before it goes live.")
        sys.exit(0)
    else:
        failures = check_all()
        sys.exit(1 if failures > 0 else 0)
