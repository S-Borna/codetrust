# Copyright (c) Said Borna. All rights reserved.
"""Complete CodeTrust rule catalog with SARIF-oriented metadata."""

from src.models.enums import Severity
from src.rules.anti_patterns import ANTI_PATTERNS

RULE_HELP_BASE_URI = "https://docs.codetrust.ai/rules"

RULE_CWE_MAP: dict[str, str] = {
    "eval_exec": "CWE-95",
    "hardcoded_secret": "CWE-798",
    "sql_injection": "CWE-89",
    "pickle_load": "CWE-502",
    "path_traversal": "CWE-22",
}


def _humanize_rule_name(rule_id: str) -> str:
    """Convert a snake_case rule ID into a human-friendly title."""
    words = rule_id.replace("-", "_").split("_")
    return " ".join(word.capitalize() for word in words if word)


def _normalize_severity(value: object) -> str:
    """Normalize severity values to BLOCK/WARN/INFO string constants."""
    if isinstance(value, Severity):
        return value.value
    text = str(value).upper().strip()
    if text in {"BLOCK", "WARN", "INFO"}:
        return text
    return Severity.INFO.value


def _build_rule_catalog() -> dict[str, dict[str, str | list[str]]]:
    """Build a complete catalog for all anti-pattern rules."""
    catalog: dict[str, dict[str, str | list[str]]] = {}

    for rule in ANTI_PATTERNS:
        rule_id = str(rule.get("id", "")).strip()
        if not rule_id:
            continue

        severity = _normalize_severity(rule.get("severity", Severity.INFO))
        description = str(rule.get("message", "")).strip() or "CodeTrust rule finding."
        cwe = RULE_CWE_MAP.get(rule_id, "")

        entry: dict[str, str | list[str]] = {
            "name": _humanize_rule_name(rule_id),
            "description": description,
            "severity": severity,
            "help_uri": f"{RULE_HELP_BASE_URI}#{rule_id}",
            "tags": ["codetrust", "static-analysis"],
        }
        if cwe:
            entry["cwe"] = cwe

        catalog[rule_id] = entry

    return catalog


RULE_CATALOG: dict[str, dict[str, str | list[str]]] = _build_rule_catalog()
