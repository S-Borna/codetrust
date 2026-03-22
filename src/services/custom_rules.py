# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Custom scan rules engine for StaticAnalyzer.

Loads user-defined rules from `.codetrust-rules.yml` in a project root,
validates them, and merges with built-in ANTI_PATTERNS so that StaticAnalyzer
can process them in one pass.

Usage (CLI concept):
    codetrust scan --rules .codetrust-rules.yml
    # or auto-detect in workspace root

YAML format:
    rules:
      - id: my_company_no_print
        pattern: "print\\("
        message: "Use structured logging instead of print()"
        severity: WARN
        file_types: [".py"]

      - id: require_error_boundary
        pattern: "<ErrorBoundary"
        message: "All page components must have ErrorBoundary"
        severity: WARN
        file_types: [".tsx", ".jsx"]
        negate: true  # WARN if pattern is NOT found
"""

from __future__ import annotations

import re
from pathlib import Path

import structlog

from src.models.enums import Severity

logger = structlog.get_logger()

# Filename to auto-detect in workspace root
CUSTOM_RULES_FILENAME: str = ".codetrust-rules.yml"
CUSTOM_RULES_FILENAME_ALT: str = ".codetrust-rules.yaml"

# Maximum custom rules per file to prevent abuse
MAX_CUSTOM_RULES: int = 200

# Valid severity values for custom rules
_VALID_SEVERITIES: frozenset[str] = frozenset({"BLOCK", "WARN", "INFO"})

# Required fields in every custom rule
_REQUIRED_FIELDS: tuple[str, ...] = ("id", "pattern", "message")


def _validate_single_rule(rule: dict[str, object], index: int) -> str | None:
    """Validate a single custom rule dict.

    Args:
        rule: The rule definition dict.
        index: Zero-based index for error reporting.

    Returns:
        Error message string if invalid, None if valid.
    """
    if not isinstance(rule, dict):
        return f"Rule at index {index} is not a mapping"

    for field in _REQUIRED_FIELDS:
        if field not in rule:
            return f"Rule at index {index} missing required field '{field}'"

    rule_id = rule.get("id", "")
    if not isinstance(rule_id, str) or not rule_id.strip():
        return f"Rule at index {index} has empty or non-string 'id'"

    pattern = rule.get("pattern", "")
    if not isinstance(pattern, str) or not pattern:
        return f"Rule '{rule_id}' has empty or non-string 'pattern'"

    try:
        re.compile(pattern)
    except re.error as exc:
        return f"Rule '{rule_id}' has invalid regex pattern: {exc}"

    message = rule.get("message", "")
    if not isinstance(message, str) or not message:
        return f"Rule '{rule_id}' has empty or non-string 'message'"

    severity = rule.get("severity", "WARN")
    if isinstance(severity, str):
        severity = severity.upper()
    if severity not in _VALID_SEVERITIES:
        return f"Rule '{rule_id}' has invalid severity '{severity}' (must be BLOCK, WARN, or INFO)"

    file_types = rule.get("file_types")
    if file_types is not None and not isinstance(file_types, list):
        return f"Rule '{rule_id}' file_types must be a list"

    return None


def validate_custom_rules(rules: list[dict[str, object]]) -> list[str]:
    """Validate a list of custom rule definitions.

    Args:
        rules: List of rule dicts parsed from YAML.

    Returns:
        List of validation error strings. Empty list means all rules are valid.
    """
    errors: list[str] = []

    if not isinstance(rules, list):
        return ["Rules must be a list"]

    if len(rules) > MAX_CUSTOM_RULES:
        errors.append(
            f"Too many custom rules ({len(rules)}). Maximum is {MAX_CUSTOM_RULES}."
        )

    for idx, rule in enumerate(rules):
        err = _validate_single_rule(rule, idx)
        if err is not None:
            errors.append(err)

    return errors


def _normalize_rule(rule: dict[str, object]) -> dict[str, object]:
    """Normalize a validated custom rule to the ANTI_PATTERNS dict format.

    Converts severity strings to Severity enum and ensures all expected
    keys are present so StaticAnalyzer can process the rule directly.

    Args:
        rule: A validated custom rule dict from YAML.

    Returns:
        Rule dict compatible with ANTI_PATTERNS format.
    """
    severity_raw = rule.get("severity", "WARN")
    severity = Severity(severity_raw.upper()) if isinstance(severity_raw, str) else severity_raw

    normalized: dict[str, object] = {
        "id": f"custom_{rule['id']}" if not str(rule["id"]).startswith("custom_") else str(rule["id"]),
        "pattern": str(rule["pattern"]),
        "message": str(rule["message"]),
        "severity": severity,
    }

    # Optional fields
    file_types = rule.get("file_types")
    if file_types is not None:
        normalized["file_types"] = list(file_types)

    suggestion = rule.get("suggestion")
    if suggestion is not None:
        normalized["suggestion"] = str(suggestion)

    skip_comments = rule.get("skip_comments")
    if skip_comments is not None:
        normalized["skip_comments"] = bool(skip_comments)

    negate = rule.get("negate")
    if negate is not None:
        normalized["negate"] = bool(negate)

    exclude_path_contains = rule.get("exclude_path_contains")
    if exclude_path_contains is not None:
        normalized["exclude_path_contains"] = list(exclude_path_contains)

    return normalized


def load_custom_rules(workspace_path: str) -> list[dict[str, object]]:
    """Load custom scan rules from .codetrust-rules.yml in workspace root.

    Searches for `.codetrust-rules.yml` (then `.codetrust-rules.yaml`) in the
    given workspace directory. Parses, validates, and normalizes the rules into
    the ANTI_PATTERNS dict format used by StaticAnalyzer.

    Invalid rules are skipped with a warning log; the function never raises.

    Args:
        workspace_path: Path to the project/workspace root directory.

    Returns:
        List of normalized rule dicts compatible with ANTI_PATTERNS.
        Empty list if file is missing, unreadable, or has no valid rules.
    """
    ws = Path(workspace_path)
    rules_file: Path | None = None

    for filename in (CUSTOM_RULES_FILENAME, CUSTOM_RULES_FILENAME_ALT):
        candidate = ws / filename
        if candidate.is_file():
            rules_file = candidate
            break

    if rules_file is None:
        logger.debug("custom_rules_file_not_found", workspace=workspace_path)
        return []

    try:
        import yaml
    except ModuleNotFoundError:
        logger.warning(
            "custom_rules_yaml_unavailable",
            detail="PyYAML is not installed. Cannot load custom rules.",
        )
        return []

    try:
        raw_text = rules_file.read_text(encoding="utf-8")
        data = yaml.safe_load(raw_text)
    except (OSError, yaml.YAMLError) as exc:
        logger.warning(
            "custom_rules_load_failed",
            path=str(rules_file),
            error=str(exc),
        )
        return []

    if not isinstance(data, dict):
        logger.warning(
            "custom_rules_invalid_format",
            path=str(rules_file),
            detail="Expected a YAML mapping with a 'rules' key",
        )
        return []

    raw_rules = data.get("rules", [])
    if not isinstance(raw_rules, list):
        logger.warning(
            "custom_rules_invalid_rules_key",
            path=str(rules_file),
            detail="'rules' must be a list",
        )
        return []

    # Validate all rules, skip invalid ones
    valid_rules: list[dict[str, object]] = []
    for idx, rule in enumerate(raw_rules):
        err = _validate_single_rule(rule, idx)
        if err is not None:
            logger.warning("custom_rule_skipped", error=err, path=str(rules_file))
            continue
        valid_rules.append(_normalize_rule(rule))

    logger.info(
        "custom_rules_loaded",
        path=str(rules_file),
        total=len(raw_rules),
        valid=len(valid_rules),
        skipped=len(raw_rules) - len(valid_rules),
    )
    return valid_rules


def merge_with_builtin(
    custom: list[dict[str, object]],
    builtin: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Merge custom rules with built-in rules, custom overriding by ID.

    When a custom rule has the same ID as a built-in rule, the custom
    version replaces the built-in. All other rules are preserved.

    Args:
        custom: Custom rules (from .codetrust-rules.yml).
        builtin: Built-in rules (ANTI_PATTERNS).

    Returns:
        Merged list with custom rules taking precedence over built-in
        rules that share the same ID.
    """
    custom_ids: set[str] = {str(r.get("id", "")) for r in custom}
    merged: list[dict[str, object]] = []

    # Add built-in rules that are NOT overridden by custom
    for rule in builtin:
        rule_id = str(rule.get("id", ""))
        if rule_id not in custom_ids:
            merged.append(rule)

    # Append all custom rules
    merged.extend(custom)

    logger.info(
        "rules_merged",
        builtin_count=len(builtin),
        custom_count=len(custom),
        overridden=len(custom_ids & {str(r.get("id", "")) for r in builtin}),
        total=len(merged),
    )
    return merged
