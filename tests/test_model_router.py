# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for Model Routing Engine."""

from __future__ import annotations

from pathlib import Path

from src.services.model_router import (
    RoutingDecision,
    _model_in_list,
    _model_matches_pattern,
    evaluate_routing,
    load_routing_policy,
)


class TestWildcardMatching:
    """Test model name wildcard matching."""

    def test_exact_match(self) -> None:
        assert _model_matches_pattern("gpt-4o", "gpt-4o") is True

    def test_star_prefix(self) -> None:
        assert _model_matches_pattern("claude-opus-4-20250514", "claude-*") is True

    def test_star_suffix(self) -> None:
        assert _model_matches_pattern("gpt-4o-preview", "*-preview") is True

    def test_wildcard_all(self) -> None:
        assert _model_matches_pattern("any-model", "*") is True

    def test_no_match(self) -> None:
        assert _model_matches_pattern("gpt-4o", "claude-*") is False

    def test_case_insensitive(self) -> None:
        assert _model_matches_pattern("GPT-4o", "gpt-*") is True

    def test_model_in_list(self) -> None:
        assert _model_in_list("gpt-4o", ["claude-*", "gpt-4o", "gemini-*"]) is True

    def test_model_not_in_list(self) -> None:
        assert _model_in_list("llama-3", ["claude-*", "gpt-*"]) is False

    def test_empty_list(self) -> None:
        assert _model_in_list("gpt-4o", []) is False


class TestRoutingPublic:
    """Test routing decisions for PUBLIC data."""

    def test_any_model_allowed(self) -> None:
        decision = evaluate_routing("# Installation guide", "llama-3", file_path="README.md")
        assert decision.action == "allow"

    def test_public_data_allows_all(self) -> None:
        decision = evaluate_routing("MIT License text", "gpt-4o-mini", file_path="LICENSE")
        assert decision.action == "allow"


class TestRoutingInternal:
    """Test routing decisions for INTERNAL data."""

    def test_approved_model_allowed(self) -> None:
        decision = evaluate_routing("def func():\n    pass", "gpt-4o", file_path="src/utils.py")
        assert decision.action == "allow"

    def test_preview_model_blocked(self) -> None:
        decision = evaluate_routing("def func():\n    pass", "gpt-5-preview", file_path="src/utils.py")
        assert decision.action in ("block", "warn")


class TestRoutingConfidential:
    """Test routing decisions for CONFIDENTIAL data."""

    def test_approved_model_allowed(self) -> None:
        decision = evaluate_routing(
            "SELECT email FROM customers",
            "gpt-4o", file_path="src/query.py",
        )
        assert decision.action == "allow"

    def test_unapproved_model_restricted(self) -> None:
        decision = evaluate_routing(
            "SELECT email FROM customers",
            "llama-3-70b", file_path="src/query.py",
        )
        assert decision.action in ("block", "warn")


class TestRoutingRestricted:
    """Test routing decisions for RESTRICTED data."""

    def test_restricted_data_blocked(self) -> None:
        decision = evaluate_routing("DB_HOST=prod", "gpt-4o", file_path=".env")
        assert decision.action in ("block", "redact")

    def test_restricted_redacts_content(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        decision = evaluate_routing(text, "gpt-4o", file_path="config.py")
        if decision.action == "redact":
            assert decision.redacted_content is not None
            assert "sk-" not in decision.redacted_content

    def test_no_model_allowed_for_restricted(self) -> None:
        decision = evaluate_routing("-----BEGIN RSA PRIVATE KEY-----", "claude-opus-4-20250514", file_path="src/auth.py")
        assert decision.action in ("block", "redact")


class TestPolicyLoading:
    """Test routing policy loading."""

    def test_default_policy_structure(self) -> None:
        policy = load_routing_policy(Path("/nonexistent"))
        assert policy["enabled"] is True
        assert "levels" in policy
        assert "public" in policy["levels"]
        assert "restricted" in policy["levels"]

    def test_default_action_is_warn(self) -> None:
        policy = load_routing_policy(Path("/nonexistent"))
        assert policy["default_action"] == "warn"

    def test_restricted_has_block_action(self) -> None:
        policy = load_routing_policy(Path("/nonexistent"))
        assert policy["levels"]["restricted"]["action"] == "block"

    def test_restricted_has_redact_flag(self) -> None:
        policy = load_routing_policy(Path("/nonexistent"))
        assert policy["levels"]["restricted"]["redact_before_send"] is True


class TestRoutingDecisionSerialization:
    """Test RoutingDecision serialization."""

    def test_to_dict_fields(self) -> None:
        import json
        decision = evaluate_routing("hello", "gpt-4o", file_path="README.md")
        d = decision.to_dict()
        json.dumps(d)
        assert "sensitivity" in d
        assert "model" in d
        assert "action" in d
        assert "reason" in d
        assert "classification" in d

    def test_model_preserved(self) -> None:
        decision = evaluate_routing("test", "gpt-4o", file_path="README.md")
        assert decision.model == "gpt-4o"
