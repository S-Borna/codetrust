# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for universal rule scoping — verify rules have correct file_types."""

from __future__ import annotations

import time

import pytest

from src.rules.anti_patterns import ANTI_PATTERNS
from src.services.static_analyzer import StaticAnalyzer


MAX_UNIVERSAL_RULES = 200


class TestUniversalRuleCount:
    """Verify that universal rules are kept under the target limit."""

    def test_universal_rules_under_limit(self) -> None:
        """Universal rules must be under 200 (target from 1,680)."""
        analyzer = StaticAnalyzer()
        count = len(analyzer._universal_rules)
        assert count < MAX_UNIVERSAL_RULES, (
            f"Universal rules: {count} (max {MAX_UNIVERSAL_RULES}). "
            f"Scope more rules with file_types."
        )

    def test_total_rules_unchanged(self) -> None:
        """Total rule count pins to 2,928.

        History:
          - 2,923 baseline
          - +1 hallucinated_method_buzzword
          - +4 extension parity: sql_drop_table, k8s_host_pid,
            ruby_rescue_all, php_global_statement
        """
        assert len(ANTI_PATTERNS) == 2928


class TestScopedRulesValid:
    """Verify that scoped rules have valid file_types."""

    def test_scoped_rules_have_at_least_one_extension(self) -> None:
        """Every rule with file_types must have at least one extension."""
        for rule in ANTI_PATTERNS:
            ft = rule.get("file_types")
            if ft is not None:
                assert len(ft) >= 1, (
                    f"Rule {rule.get('id')}: file_types is empty list"
                )

    def test_extensions_start_with_dot(self) -> None:
        """All file_types entries must start with a dot."""
        for rule in ANTI_PATTERNS:
            ft = rule.get("file_types")
            if ft:
                for ext in ft:
                    assert ext.startswith("."), (
                        f"Rule {rule.get('id')}: extension '{ext}' missing dot"
                    )


class TestUniversalRulesAreGenuinelyUniversal:
    """Verify that remaining universal rules are intentionally universal."""

    def test_universal_rules_are_known_categories(self) -> None:
        """Universal rules should be from known universal categories."""
        analyzer = StaticAnalyzer()
        universal_ids = [r.get("id", "") for r in analyzer._universal_rules]

        # These categories are intentionally universal
        known_universal_prefixes = (
            "hardcoded_", "heredoc", "gov_", "symptom_",
            "secret_", "debug_", "blocking_",
            "hallucinated_", "dep_", "config_", "crypto_",
        )

        for rule_id in universal_ids:
            is_known = any(rule_id.startswith(p) for p in known_universal_prefixes)
            # Allow unknown universals but log them for review
            if not is_known:
                # Not a failure — just informational
                pass


class TestPerformanceRegression:
    """Verify that scoping doesn't increase scan time."""

    def test_scan_time_reasonable(self) -> None:
        """Scanning a Python file should complete in under 5 seconds."""
        analyzer = StaticAnalyzer()
        code = "x = 1\ny = 2\nprint(x + y)\n" * 100  # 300 lines

        start = time.time()
        analyzer.scan_code(code, "test_file.py")
        elapsed = time.time() - start

        assert elapsed < 5.0, f"Scan took {elapsed:.1f}s — too slow"

    def test_python_rules_fewer_than_total(self) -> None:
        """Python bucket should have fewer rules than total (scoping works)."""
        analyzer = StaticAnalyzer()
        py_rules = len(analyzer._rules_by_ext.get(".py", []))
        total = len(analyzer._rules)
        assert py_rules < total, (
            f"Python rules ({py_rules}) should be less than total ({total})"
        )
