"""Tests for centralized rule catalog metadata."""

from src.rules.anti_patterns import ANTI_PATTERNS
from src.services.rule_catalog import RULE_CATALOG


def test_rule_catalog_matches_anti_patterns_count() -> None:
    """Catalog must include every anti-pattern rule exactly once."""
    anti_pattern_ids = {str(rule["id"]) for rule in ANTI_PATTERNS}
    assert len(RULE_CATALOG) == len(anti_pattern_ids)
    assert set(RULE_CATALOG.keys()) == anti_pattern_ids


def test_rule_catalog_entries_have_required_fields() -> None:
    """Each catalog entry must provide minimum SARIF metadata fields."""
    for rule_id, entry in RULE_CATALOG.items():
        assert entry["name"]
        assert entry["description"]
        assert entry["severity"] in {"BLOCK", "WARN", "INFO"}
        assert entry["help_uri"].endswith(f"#{rule_id}")
