# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Custom rule loader — load user-defined governance rules from YAML/TOML.

Users can define additional terminal or content rules in:
  1. `.codetrust/custom_rules.yaml`
  2. `.codetrust.toml` under `[codetrust.governance.custom_rules]`

Rule format (YAML):
    terminal_rules:
      - id: custom_no_docker_run
        pattern: "docker\\s+run\\s+--privileged"
        message: "Privileged Docker containers are not allowed"
        suggestion: "Remove --privileged flag"
        severity: BLOCK          # BLOCK or WARN

    content_rules:
      - id: custom_no_console_log
        pattern: "console\\.log\\("
        message: "Console.log found in production code"
        suggestion: "Use a structured logger"
        severity: WARN
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("codetrust.custom_rules")

try:
    import yaml

    _HAS_YAML = True
except ModuleNotFoundError:
    _HAS_YAML = False

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None


_VALID_SEVERITIES = {"BLOCK", "WARN"}


def _validate_rule(rule: dict, rule_type: str) -> str | None:
    """Validate a single rule dict. Returns error message or None."""
    if not isinstance(rule, dict):
        return f"{rule_type} rule is not a dict"
    for field in ("id", "pattern", "message"):
        if field not in rule:
            return f"{rule_type} rule missing required field '{field}'"
    if not isinstance(rule["id"], str) or not rule["id"]:
        return f"{rule_type} rule has invalid id"
    severity = rule.get("severity", "BLOCK")
    if severity not in _VALID_SEVERITIES:
        return f"{rule_type} rule '{rule['id']}' has invalid severity '{severity}'"
    try:
        re.compile(rule["pattern"])
    except re.error as exc:
        return f"{rule_type} rule '{rule['id']}' has invalid regex: {exc}"
    return None


def _normalize_rule(raw: dict) -> dict:
    """Normalize a raw rule dict to internal format."""
    return {
        "id": f"custom_{raw['id']}" if not raw["id"].startswith("custom_") else raw["id"],
        "pattern": raw["pattern"],
        "message": raw["message"],
        "suggestion": raw.get("suggestion", ""),
        "severity": raw.get("severity", "BLOCK"),
    }


def _collect_valid_rules(raw_rules: list[dict], rule_type: str) -> list[dict]:
    """Validate and normalize a list of raw rule dicts."""
    result: list[dict] = []
    for raw in raw_rules:
        err = _validate_rule(raw, rule_type)
        if err:
            logger.warning("Skipping invalid custom rule: %s", err)
            continue
        result.append(_normalize_rule(raw))
    return result


def load_custom_rules_yaml(path: Path) -> tuple[list[dict], list[dict]]:
    """Load custom rules from a YAML file.

    Args:
        path: Path to the YAML file.

    Returns:
        Tuple of (terminal_rules, content_rules).

    Raises:
        FileNotFoundError: If file doesn't exist.
        ValueError: If YAML parsing fails.
    """
    if not _HAS_YAML:
        logger.debug("PyYAML not installed — skipping YAML custom rules")
        return [], []

    if not path.is_file():
        return [], []

    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    terminal = _collect_valid_rules(data.get("terminal_rules", []), "terminal")
    content = _collect_valid_rules(data.get("content_rules", []), "content")

    logger.info(
        "Loaded %d terminal + %d content custom rules from %s",
        len(terminal), len(content), path,
    )
    return terminal, content


def load_custom_rules_toml(data: dict) -> tuple[list[dict], list[dict]]:
    """Load custom rules from parsed TOML data.

    Expects the `codetrust.governance.custom_rules` section:
        [codetrust.governance.custom_rules]
        terminal_rules = [
            { id = "no_docker_priv", pattern = "...", message = "..." },
        ]

    Args:
        data: Parsed TOML dict (the full file, or already the governance section).

    Returns:
        Tuple of (terminal_rules, content_rules).
    """
    # Navigate to the custom_rules section
    gov = data.get("codetrust", data).get("governance", data.get("governance", data))
    custom = gov.get("custom_rules", {}) if isinstance(gov, dict) else {}

    terminal = []
    content = []

    for raw in custom.get("terminal_rules", []):
        err = _validate_rule(raw, "terminal")
        if err:
            logger.warning("Skipping invalid TOML custom rule: %s", err)
            continue
        terminal.append(_normalize_rule(raw))

    for raw in custom.get("content_rules", []):
        err = _validate_rule(raw, "content")
        if err:
            logger.warning("Skipping invalid TOML custom rule: %s", err)
            continue
        content.append(_normalize_rule(raw))

    return terminal, content


def _merge_rules(
    target: list[dict],
    source: list[dict],
    seen_ids: set[str],
) -> None:
    """Append rules from source to target, skipping duplicate IDs."""
    for rule in source:
        if rule["id"] not in seen_ids:
            target.append(rule)
            seen_ids.add(rule["id"])


def load_custom_rules(workspace: str | Path) -> tuple[list[dict], list[dict]]:
    """Load custom rules from workspace, trying YAML then TOML.

    Looks for:
      1. <workspace>/.codetrust/custom_rules.yaml
      2. <workspace>/.codetrust/custom_rules.yml
      3. <workspace>/.codetrust.toml [codetrust.governance.custom_rules]

    Rules from all sources are merged (YAML takes priority for same IDs).

    Args:
        workspace: Path to workspace root.

    Returns:
        Tuple of (terminal_rules, content_rules).
    """
    ws = Path(workspace)
    terminal_all: list[dict] = []
    content_all: list[dict] = []
    seen_ids: set[str] = set()

    # Try YAML files
    for name in ("custom_rules.yaml", "custom_rules.yml"):
        yaml_path = ws / ".codetrust" / name
        terminal, content = load_custom_rules_yaml(yaml_path)
        _merge_rules(terminal_all, terminal, seen_ids)
        _merge_rules(content_all, content, seen_ids)

    # Try TOML
    toml_path = ws / ".codetrust.toml"
    if toml_path.is_file() and tomllib is not None:
        with open(toml_path, "rb") as f:
            toml_data = tomllib.load(f)
        terminal, content = load_custom_rules_toml(toml_data)
        _merge_rules(terminal_all, terminal, seen_ids)
        _merge_rules(content_all, content, seen_ids)

    return terminal_all, content_all
