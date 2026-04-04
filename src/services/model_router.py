# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Model Routing Engine — enforce which LLM models can access which data.

Routes data to models based on sensitivity classification:
- PUBLIC: any model
- INTERNAL: approved models only
- CONFIDENTIAL: restricted model list
- RESTRICTED: no models (block) or auto-redact before sending

Reads policy from .codetrust/model-routing.toml, with fallback defaults.
Integrates with existing .codetrust.toml policy (allowed_models/blocked_models).
Most restrictive policy wins when both exist.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.services.data_classifier import ClassificationResult, classify_text
from src.services.pii_detector import redact as pii_redact

# ───────────────────────────────────────────────────────────────
#  Routing decision
# ───────────────────────────────────────────────────────────────


@dataclass
class RoutingDecision:
    """Result of evaluating whether a model may access given content."""

    classification: ClassificationResult
    model: str
    action: str  # "allow" | "warn" | "block" | "redact"
    reason: str
    redacted_content: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dictionary."""
        return {
            "sensitivity": self.classification.sensitivity.label,
            "model": self.model,
            "action": self.action,
            "reason": self.reason,
            "classification": self.classification.to_dict(),
            "has_redacted_content": self.redacted_content is not None,
        }


# ───────────────────────────────────────────────────────────────
#  Default routing policy
# ───────────────────────────────────────────────────────────────

_DEFAULT_ROUTING_POLICY: dict[str, Any] = {
    "enabled": True,
    "default_action": "warn",
    "levels": {
        "public": {
            "allowed_models": ["*"],
            "blocked_models": [],
        },
        "internal": {
            "allowed_models": ["claude-*", "gpt-4o", "gpt-4o-mini"],
            "blocked_models": ["*-preview", "experimental-*"],
        },
        "confidential": {
            "allowed_models": ["claude-opus-*", "claude-sonnet-*", "gpt-4o"],
            "blocked_models": ["*"],
        },
        "restricted": {
            "allowed_models": [],
            "action": "block",
            "redact_before_send": True,
        },
    },
}


# ───────────────────────────────────────────────────────────────
#  Policy loading
# ───────────────────────────────────────────────────────────────


def load_routing_policy(project_dir: Path | None = None) -> dict[str, Any]:
    """Load model routing policy from .codetrust/model-routing.toml.

    Falls back to default policy if file not found or invalid.

    Args:
        project_dir: Project root directory. Defaults to CWD.

    Returns:
        Policy dict with enabled, default_action, levels.
    """
    root = project_dir or Path.cwd()
    policy_path = root / ".codetrust" / "model-routing.toml"

    if not policy_path.is_file():
        return _deep_copy_policy(_DEFAULT_ROUTING_POLICY)

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return _deep_copy_policy(_DEFAULT_ROUTING_POLICY)

    try:
        raw = tomllib.loads(policy_path.read_text(encoding="utf-8"))
        routing = raw.get("model_routing", {})
        policy = _deep_copy_policy(_DEFAULT_ROUTING_POLICY)
        for key in ("enabled", "default_action"):
            if key in routing:
                policy[key] = routing[key]
        if "levels" in routing:
            for level_name, level_config in routing["levels"].items():
                if level_name in policy["levels"]:
                    policy["levels"][level_name].update(level_config)
                else:
                    policy["levels"][level_name] = level_config
        return policy
    except (OSError, ValueError, KeyError):
        return _deep_copy_policy(_DEFAULT_ROUTING_POLICY)


def _deep_copy_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Deep copy a policy dict (avoids mutating the default)."""
    result: dict[str, Any] = {}
    for key, value in policy.items():
        if isinstance(value, dict):
            result[key] = _deep_copy_policy(value)
        elif isinstance(value, list):
            result[key] = list(value)
        else:
            result[key] = value
    return result


# ───────────────────────────────────────────────────────────────
#  Wildcard model matching
# ───────────────────────────────────────────────────────────────


def _model_matches_pattern(model: str, pattern: str) -> bool:
    """Check if a model name matches a wildcard pattern.

    Args:
        model: Model name (e.g. "gpt-4o", "claude-opus-4-20250514").
        pattern: Pattern with optional wildcards (e.g. "claude-*", "*-preview").

    Returns:
        True if the model matches the pattern.
    """
    return fnmatch.fnmatch(model.lower(), pattern.lower())


def _model_in_list(model: str, patterns: list[str]) -> bool:
    """Check if a model matches any pattern in a list.

    Args:
        model: Model name.
        patterns: List of patterns (may include wildcards).

    Returns:
        True if the model matches any pattern.
    """
    return any(_model_matches_pattern(model, p) for p in patterns)


# ───────────────────────────────────────────────────────────────
#  Existing policy integration
# ───────────────────────────────────────────────────────────────


def _load_baseline_policy(project_dir: Path | None = None) -> dict[str, list[str]]:
    """Load allowed_models/blocked_models from .codetrust.toml.

    Args:
        project_dir: Project root.

    Returns:
        Dict with "allowed" and "blocked" model lists.
    """
    root = project_dir or Path.cwd()
    config_path = root / ".codetrust.toml"

    if not config_path.is_file():
        return {"allowed": [], "blocked": []}

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return {"allowed": [], "blocked": []}

    try:
        raw = tomllib.loads(config_path.read_text(encoding="utf-8"))
        policy_section = raw.get("policy", {})
        return {
            "allowed": policy_section.get("allowed_models", []),
            "blocked": policy_section.get("blocked_models", []),
        }
    except (OSError, ValueError, KeyError):
        return {"allowed": [], "blocked": []}


# ───────────────────────────────────────────────────────────────
#  Routing evaluation
# ───────────────────────────────────────────────────────────────


def evaluate_routing(
    content: str,
    model: str,
    policy_path: Path | None = None,
    file_path: str = "",
) -> RoutingDecision:
    """Evaluate whether a model may access the given content.

    Classifies the content, checks routing policy for the sensitivity level,
    and returns an allow/warn/block/redact decision.

    Args:
        content: Text content to evaluate.
        model: Model identifier (e.g. "gpt-4o").
        policy_path: Project root for policy files.
        file_path: Optional file path for classification context.

    Returns:
        RoutingDecision with action and reason.
    """
    classification = classify_text(content, file_path=file_path)
    routing_policy = load_routing_policy(policy_path)
    baseline = _load_baseline_policy(policy_path)

    if not routing_policy.get("enabled", True):
        return RoutingDecision(
            classification=classification,
            model=model,
            action="allow",
            reason="Model routing is disabled",
        )

    # Check baseline policy first (most restrictive wins)
    if baseline["blocked"] and _model_in_list(model, baseline["blocked"]):
        return RoutingDecision(
            classification=classification,
            model=model,
            action="block",
            reason=f"Model '{model}' is blocked by baseline policy (.codetrust.toml)",
        )

    if baseline["allowed"] and not _model_in_list(model, baseline["allowed"]):
        return RoutingDecision(
            classification=classification,
            model=model,
            action="block",
            reason=f"Model '{model}' is not in baseline allowed list (.codetrust.toml)",
        )

    # Get level-specific policy
    level_name = classification.sensitivity.label
    level_policy = routing_policy.get("levels", {}).get(level_name, {})

    # Level override action (e.g. restricted always blocks)
    level_action = level_policy.get("action")

    # Check if model should be blocked at this level
    blocked_patterns = level_policy.get("blocked_models", [])
    allowed_patterns = level_policy.get("allowed_models", [])
    redact_flag = level_policy.get("redact_before_send", False)

    # Explicit block action for this level
    if level_action == "block":
        if redact_flag:
            redacted = pii_redact(content, min_confidence=0.7)
            return RoutingDecision(
                classification=classification,
                model=model,
                action="redact",
                reason=f"Data classified as {level_name} — auto-redacted before sending to '{model}'",
                redacted_content=redacted,
            )
        return RoutingDecision(
            classification=classification,
            model=model,
            action="block",
            reason=f"Data classified as {level_name} — no model access allowed",
        )

    # Check blocked list (explicit deny, unless also explicitly allowed)
    if (blocked_patterns
            and _model_in_list(model, blocked_patterns)
            and not (allowed_patterns and _model_in_list(model, allowed_patterns))):
            return RoutingDecision(
                classification=classification,
                model=model,
                action="block",
                reason=f"Model '{model}' is blocked for {level_name} data",
            )

    # Check allowed list
    if allowed_patterns:
        if _model_in_list(model, allowed_patterns):
            return RoutingDecision(
                classification=classification,
                model=model,
                action="allow",
                reason=f"Model '{model}' is allowed for {level_name} data",
            )
        # Model not in allowed list
        default_action = routing_policy.get("default_action", "warn")
        return RoutingDecision(
            classification=classification,
            model=model,
            action=default_action,
            reason=f"Model '{model}' is not in allowed list for {level_name} data",
        )

    # No specific rules — use default
    default_action = routing_policy.get("default_action", "warn")
    return RoutingDecision(
        classification=classification,
        model=model,
        action=default_action,
        reason=f"No specific routing rule for '{model}' at {level_name} level",
    )
