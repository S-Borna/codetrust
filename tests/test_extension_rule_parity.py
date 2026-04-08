# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Drift prevention: extension embedded scanner vs backend anti-patterns.

The VS Code extension ships an offline fallback scanner (TypeScript) with
a subset of the backend's anti-pattern rules. When the backend grows a
rule and the extension doesn't, or when an extension rule ID drifts from
its backend counterpart, users get inconsistent findings depending on
whether the API is reachable.

This test pins the contract:

  * every rule ID in extension/src/embedded-scanner.ts MUST also exist
    in the backend ANTI_PATTERNS (or be one of the explicitly-allowed
    special-handler IDs like long_function/untyped_function)

If a rule is legitimately extension-only it must be added to
_EXTENSION_ONLY_RULES below with a comment explaining why.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.rules.anti_patterns import ANTI_PATTERNS

EXTENSION_SCANNER_PATH = (
    Path(__file__).parent.parent
    / "extension" / "src" / "embedded-scanner.ts"
)

# Rule IDs that exist only in the extension by design. Each entry needs
# a one-line reason so a future reader knows whether to add it to the
# backend or delete it from the extension.
_EXTENSION_ONLY_RULES: dict[str, str] = {
    # file-level checks that the backend implements in static_analyzer.py
    # as Python AST passes rather than regex rules:
    "long_function": "StaticAnalyzer computes function length via AST, not a regex rule",
    "untyped_function": (
        "StaticAnalyzer has no equivalent — this is a Python-only ergonomic "
        "check for IDE diagnostics; not part of the backend rule taxonomy"
    ),
}


def _extract_extension_rule_ids() -> set[str]:
    """Parse embedded-scanner.ts and return every rule_id literal used."""
    if not EXTENSION_SCANNER_PATH.exists():
        pytest.skip("extension/ not checked out in this tree")

    text = EXTENSION_SCANNER_PATH.read_text(encoding="utf-8")
    ids: set[str] = set()

    # Three forms in the file:
    # 1. { id: "foo", pattern: ... }     — regex rule definitions
    # 2. rule_id: "foo"                  — Finding emit sites
    # 3. makeFinding("foo", "INFO", ...) — helper-based file-level checks
    for match in re.finditer(r'(?:id|rule_id):\s*"([a-z0-9_]+)"', text):
        ids.add(match.group(1))
    for match in re.finditer(r'makeFinding\(\s*"([a-z0-9_]+)"', text):
        ids.add(match.group(1))

    return ids


def _backend_rule_ids() -> set[str]:
    """Return the set of rule IDs present in backend ANTI_PATTERNS."""
    return {
        str(rule["id"])
        for rule in ANTI_PATTERNS
        if isinstance(rule, dict) and rule.get("id")
    }


def test_extension_rule_ids_are_subset_of_backend() -> None:
    """No extension rule may diverge from the backend without a waiver.

    Catches the common drift patterns:
      1. renaming a backend rule without updating the extension
      2. adding an extension-only rule without a deliberate waiver
      3. letting the offline and online scanners produce different IDs
    """
    extension_ids = _extract_extension_rule_ids()
    backend_ids = _backend_rule_ids()

    # Subtract explicit waivers
    extension_only = extension_ids - backend_ids - set(_EXTENSION_ONLY_RULES)

    assert not extension_only, (
        f"Extension has {len(extension_only)} rule IDs not present in backend "
        f"and not waived in _EXTENSION_ONLY_RULES: {sorted(extension_only)}.\n"
        f"Either rename them to match backend IDs, add them to backend, "
        f"or add a waiver with justification."
    )


def test_extension_rule_count_is_reasonable() -> None:
    """Sanity check: extension should have at least 100 rules.

    If someone accidentally empties a rule array, this catches it before
    shipping a neutered offline scanner.
    """
    extension_ids = _extract_extension_rule_ids()
    assert len(extension_ids) >= 100, (
        f"Extension has only {len(extension_ids)} rule IDs — suspiciously low. "
        f"Expected at least 100 in the offline fallback scanner."
    )


def test_waived_extension_only_rules_still_exist_in_extension() -> None:
    """Waivers in _EXTENSION_ONLY_RULES must reference real extension rules.

    If someone removes a rule from the extension but forgets to clean
    up its waiver, the waiver becomes a lie. Catch that.
    """
    extension_ids = _extract_extension_rule_ids()
    stale_waivers = [
        rule_id
        for rule_id in _EXTENSION_ONLY_RULES
        if rule_id not in extension_ids
    ]
    assert not stale_waivers, (
        f"Waivers in _EXTENSION_ONLY_RULES reference rules that no longer "
        f"exist in the extension: {stale_waivers}. Remove these entries."
    )
