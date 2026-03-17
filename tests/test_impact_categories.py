# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Unit tests for impact category mapping."""

from src.rules.anti_patterns import ANTI_PATTERNS
from src.services.impact_categories import (
    IMPACT_CATEGORIES,
    IMPACT_CATEGORY_OTHER,
    PUBLIC_IMPACT_CATEGORIES,
    RULE_TO_CATEGORY,
    get_rule_category,
)


def test_spec_rule_examples_are_mapped_to_expected_categories() -> None:
    """Spec examples must resolve to expected impact categories."""
    assert get_rule_category("agent_os_system") == "destructive_commands"
    assert get_rule_category("import_not_found") == "hallucinations"
    assert get_rule_category("hardcoded_secret") == "secrets_exposure"
    assert get_rule_category("eval_exec") == "injection_attacks"
    assert get_rule_category("config_world_writable") == "unsafe_config"
    assert get_rule_category("cve_detected") == "supply_chain"


def test_unknown_rule_falls_back_to_other() -> None:
    """Unknown rule ids must safely fall back to 'other'."""
    assert get_rule_category("__unknown_rule__") == IMPACT_CATEGORY_OTHER


def test_public_categories_exclude_fallback_other() -> None:
    """Public impact payload must hide fallback/internal bucket."""
    assert IMPACT_CATEGORY_OTHER not in PUBLIC_IMPACT_CATEGORIES


def test_rule_mapping_keys_are_unique() -> None:
    """Dict keys must remain unique to avoid category collisions."""
    assert len(RULE_TO_CATEGORY) == len(set(RULE_TO_CATEGORY.keys()))


def test_all_static_rules_map_or_fall_back_to_other() -> None:
    """Every static analyzer rule maps to a valid impact category or 'other'."""
    for rule in ANTI_PATTERNS:
        rule_id = str(rule["id"])
        category = get_rule_category(rule_id)
        assert category in IMPACT_CATEGORIES
