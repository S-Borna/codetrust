# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for server-side rule delivery service."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from src.models.enums import Severity
from src.services.rule_delivery import (
    FREE_TIER_RULE_COUNT,
    FREE_TIER_RULE_IDS,
    RuleBundle,
    _compute_rules_signature,
    _verify_rules_signature,
    build_signed_bundle,
    fetch_premium_rules,
    filter_free_tier_rules,
    filter_premium_rules,
    merge_rules,
)

# --- Sample rules for testing ---

SAMPLE_RULES: list[dict[str, object]] = [
    {
        "id": "heredoc",
        "pattern": r"<<",
        "message": "Heredoc detected",
        "severity": Severity.BLOCK,
    },
    {
        "id": "eval_exec",
        "pattern": r"\beval\b",
        "message": "eval is unsafe",
        "severity": Severity.BLOCK,
    },
    {
        "id": "hardcoded_secret",
        "pattern": r"secret",
        "message": "Secret detected",
        "severity": Severity.BLOCK,
    },
    {
        "id": "premium_rule_1",
        "pattern": r"foo",
        "message": "Premium rule",
        "severity": Severity.WARN,
    },
    {
        "id": "premium_rule_2",
        "pattern": r"bar",
        "message": "Another premium rule",
        "severity": Severity.INFO,
    },
]


class TestFreeTierFiltering:
    """Test rule tier filtering."""

    def test_free_tier_rule_count(self) -> None:
        """Free tier should have exactly 15 rules."""
        assert FREE_TIER_RULE_COUNT == 15

    def test_filter_free_tier_returns_only_free_rules(self) -> None:
        """filter_free_tier_rules should only return rules with free tier IDs."""
        free = filter_free_tier_rules(SAMPLE_RULES)
        for rule in free:
            assert rule["id"] in FREE_TIER_RULE_IDS

    def test_filter_premium_excludes_free_rules(self) -> None:
        """filter_premium_rules should exclude all free tier rules."""
        premium = filter_premium_rules(SAMPLE_RULES)
        for rule in premium:
            assert rule["id"] not in FREE_TIER_RULE_IDS

    def test_free_plus_premium_equals_total(self) -> None:
        """Free + premium should equal the total rule count."""
        free = filter_free_tier_rules(SAMPLE_RULES)
        premium = filter_premium_rules(SAMPLE_RULES)
        assert len(free) + len(premium) == len(SAMPLE_RULES)

    def test_filter_free_from_real_rules(self) -> None:
        """Verify free tier filtering works on the actual ANTI_PATTERNS."""
        from src.rules.anti_patterns import ANTI_PATTERNS

        free = filter_free_tier_rules(ANTI_PATTERNS)
        assert len(free) == FREE_TIER_RULE_COUNT
        for rule in free:
            assert rule["id"] in FREE_TIER_RULE_IDS

    def test_filter_premium_from_real_rules(self) -> None:
        """Premium rules should be the majority."""
        from src.rules.anti_patterns import ANTI_PATTERNS

        premium = filter_premium_rules(ANTI_PATTERNS)
        assert len(premium) > 100  # Most rules are premium


class TestRuleSigning:
    """Test HMAC signing and verification."""

    def test_compute_signature_deterministic(self) -> None:
        """Same input should produce same signature."""
        rules = [{"id": "a"}, {"id": "b"}]
        sig1 = _compute_rules_signature(rules, "secret", "2026-01-01T00:00:00")
        sig2 = _compute_rules_signature(rules, "secret", "2026-01-01T00:00:00")
        assert sig1 == sig2

    def test_compute_signature_varies_with_secret(self) -> None:
        """Different secrets should produce different signatures."""
        rules = [{"id": "a"}]
        sig1 = _compute_rules_signature(rules, "secret1", "2026-01-01T00:00:00")
        sig2 = _compute_rules_signature(rules, "secret2", "2026-01-01T00:00:00")
        assert sig1 != sig2

    def test_verify_valid_signature(self) -> None:
        """Valid bundle should pass verification."""
        bundle = build_signed_bundle(
            [{"id": "test", "severity": Severity.WARN, "message": "x", "pattern": "x"}],
            secret="test_secret",
            version="2.6.1",
        )
        assert _verify_rules_signature(bundle, "test_secret")

    def test_verify_tampered_bundle(self) -> None:
        """Tampered bundle should fail verification."""
        bundle = build_signed_bundle(
            [{"id": "test", "severity": Severity.WARN, "message": "x", "pattern": "x"}],
            secret="test_secret",
            version="2.6.1",
        )
        # Tamper with the rules
        bundle.rules.append({"id": "injected", "severity": "WARN"})
        assert not _verify_rules_signature(bundle, "test_secret")

    def test_verify_wrong_secret(self) -> None:
        """Wrong secret should fail verification."""
        bundle = build_signed_bundle(
            [{"id": "test", "severity": Severity.WARN, "message": "x", "pattern": "x"}],
            secret="correct_secret",
            version="2.6.1",
        )
        assert not _verify_rules_signature(bundle, "wrong_secret")


class TestBuildSignedBundle:
    """Test bundle construction."""

    def test_bundle_has_correct_count(self) -> None:
        """Bundle should report correct rule count."""
        rules = [
            {"id": "r1", "severity": Severity.WARN, "message": "x", "pattern": "x"},
            {"id": "r2", "severity": Severity.BLOCK, "message": "y", "pattern": "y"},
        ]
        bundle = build_signed_bundle(rules, "secret", "2.6.1")
        assert bundle.rule_count == 2
        assert len(bundle.rules) == 2

    def test_bundle_serializes_severity(self) -> None:
        """Bundle should convert Severity enum to string."""
        rules = [{"id": "r1", "severity": Severity.BLOCK, "message": "x", "pattern": "x"}]
        bundle = build_signed_bundle(rules, "secret", "2.6.1")
        assert bundle.rules[0]["severity"] == "BLOCK"

    def test_bundle_has_timestamps(self) -> None:
        """Bundle should have issued_at and expires_at."""
        bundle = build_signed_bundle([], "secret", "2.6.1")
        assert bundle.issued_at
        assert bundle.expires_at

    def test_bundle_has_signature(self) -> None:
        """Bundle should have a non-empty signature."""
        bundle = build_signed_bundle([], "secret", "2.6.1")
        assert len(bundle.signature) == 64  # SHA-256 hex


class TestMergeRules:
    """Test rule merging logic."""

    def test_merge_deduplicates(self) -> None:
        """Merge should not produce duplicate rule IDs."""
        free = [{"id": "a"}, {"id": "b"}]
        premium = [{"id": "b"}, {"id": "c"}]
        merged = merge_rules(free, premium)
        ids = [r["id"] for r in merged]
        assert ids == ["a", "b", "c"]

    def test_merge_preserves_order(self) -> None:
        """Free rules should come first in merged output."""
        free = [{"id": "free1"}, {"id": "free2"}]
        premium = [{"id": "premium1"}]
        merged = merge_rules(free, premium)
        assert merged[0]["id"] == "free1"
        assert merged[-1]["id"] == "premium1"

    def test_merge_empty_premium(self) -> None:
        """Merging with empty premium returns only free rules."""
        free = [{"id": "a"}]
        merged = merge_rules(free, [])
        assert len(merged) == 1


class TestFetchPremiumRules:
    """Test rule fetching (mocked HTTP)."""

    @pytest.mark.asyncio
    async def test_fetch_without_key_returns_empty(self) -> None:
        """No license key should return empty rules."""
        result = await fetch_premium_rules("", "secret")
        assert result == []

    @pytest.mark.asyncio
    async def test_fetch_uses_cache(self) -> None:
        """Cached rules should be returned without HTTP call."""
        bundle = RuleBundle(
            rules=[{"id": "cached_rule", "severity": "WARN"}],
            signature="",
            issued_at="2026-02-20T00:00:00",
            expires_at="2099-01-01T00:00:00",
            rule_count=1,
            version="2.6.1",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "rules_cache.json"
            cache_file.write_text(json.dumps(bundle.model_dump()))

            with patch(
                "src.services.rule_delivery.RULES_CACHE_FILE", cache_file,
            ):
                result = await fetch_premium_rules("ct_live_test", "")
                assert len(result) == 1
                assert result[0]["id"] == "cached_rule"


class TestStaticAnalyzerWithPremiumRules:
    """Test StaticAnalyzer integration with server-side rules."""

    def test_analyzer_default_loads_all_rules(self) -> None:
        """Analyzer without premium_rules should use all bundled rules."""
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        assert analyzer.active_rule_count > 100

    def test_analyzer_with_empty_premium_uses_free_only(self) -> None:
        """Analyzer with empty premium_rules should use free tier only."""
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer(premium_rules=[])
        assert analyzer.active_rule_count == FREE_TIER_RULE_COUNT

    def test_analyzer_with_premium_merges(self) -> None:
        """Analyzer with premium rules should merge them with free tier."""
        from src.services.static_analyzer import StaticAnalyzer

        premium = [
            {"id": "custom_premium", "pattern": r"foo", "message": "test", "severity": "WARN"},
        ]
        analyzer = StaticAnalyzer(premium_rules=premium)
        assert analyzer.active_rule_count == FREE_TIER_RULE_COUNT + 1

    def test_analyzer_free_only_scans(self) -> None:
        """Free-tier analyzer should still detect free-tier violations."""
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer(premium_rules=[])
        findings = analyzer.scan_code('eval("danger")', "test.py")
        rule_ids = {f.rule_id for f in findings}
        assert "eval_exec" in rule_ids
