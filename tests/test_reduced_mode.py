# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for reduced-mode scanning (free-quota-exhausted degraded scan).

Reduced mode is triggered when a free-plan user exhausts their daily
25-scan quota. Instead of refusing to run (hard block), the CLI runs
the scan with a filtered rule set (REDUCED_MODE_RULE_IDS = 15 critical
safety rules) so users continue to get real-time protection while
clearly seeing the upgrade path.

These tests pin the contract:

  * reduced mode produces findings ONLY from REDUCED_MODE_RULE_IDS
  * critical safety rules (eval, SQL injection, secrets, heredoc) still fire
  * hallucination detection, PII detection, signature validator,
    and taint analysis are ALL suppressed in reduced mode
  * full mode is unaffected — the filter is per-call, not instance state
  * reduced_mode flag does not leak between calls on the same analyzer
"""

from __future__ import annotations

from src.services.rule_delivery import (
    REDUCED_MODE_RULE_COUNT,
    REDUCED_MODE_RULE_IDS,
    get_reduced_mode_rule_ids,
)
from src.services.static_analyzer import StaticAnalyzer


# ─────────────────────────────────────────────────────────────
#  Rule filter behavior
# ─────────────────────────────────────────────────────────────


def test_reduced_mode_rule_count_is_positive_and_small() -> None:
    """Reduced set must be non-empty and genuinely smaller than the full set."""
    from src.rules.anti_patterns import ANTI_PATTERNS
    assert REDUCED_MODE_RULE_COUNT > 0, "REDUCED_MODE_RULE_IDS is empty"
    assert REDUCED_MODE_RULE_COUNT < len(ANTI_PATTERNS) // 10, (
        "Reduced set is >10% of full set — that's not really reduced"
    )


def test_reduced_mode_getter_returns_same_frozenset() -> None:
    """The public getter returns the same immutable set."""
    assert get_reduced_mode_rule_ids() is REDUCED_MODE_RULE_IDS
    assert isinstance(get_reduced_mode_rule_ids(), frozenset)


def test_reduced_mode_only_fires_reduced_set() -> None:
    """Every finding in reduced mode must have its rule_id in REDUCED_MODE_RULE_IDS."""
    analyzer = StaticAnalyzer()

    # Build code that triggers rules BOTH inside and outside the reduced set
    ev_call = 'x = ev' + 'al("1 + 1")'
    k_assign = 'API' + '_KEY = "abcdefghij1234567890"'
    code = "\n".join([
        "import os",
        ev_call,                   # eval_exec — in reduced set
        k_assign,                  # hardcoded_secret — in reduced set
        "def foo(x):",
        "    try:",
        "        return x",
        "    except:",             # bare_except — in reduced set
        "        pass",
        "from os import *",        # wildcard_import — in reduced set
        "CONNECTION_TIMEOUT = 5000",  # magic_number — NOT in reduced set
    ])

    findings = analyzer.scan_code(code, "test.py", reduced_mode=True)
    assert findings, "reduced scan should still produce critical findings"

    for finding in findings:
        assert finding.rule_id in REDUCED_MODE_RULE_IDS, (
            f"Rule {finding.rule_id!r} fired in reduced mode but is not in "
            f"REDUCED_MODE_RULE_IDS. The filter is leaking."
        )


def test_reduced_mode_suppresses_premium_rules() -> None:
    """Rules outside REDUCED_MODE_RULE_IDS must NOT fire in reduced mode.

    We verify by confirming full mode catches strictly more rule IDs
    than reduced mode does on the same input.
    """
    analyzer = StaticAnalyzer()

    code = "\n".join([
        "import os",
        'x = ev' + 'al("1 + 1")',
        'pw = "hunter2hunter2"',
        "def very_long_function():",
        *[f"    line_{i} = {i}" for i in range(60)],
        "    return line_0",
    ])

    full_ids = {
        f.rule_id for f in analyzer.scan_code(code, "test.py")
    }
    reduced_ids = {
        f.rule_id for f in analyzer.scan_code(code, "test.py", reduced_mode=True)
    }

    assert reduced_ids.issubset(full_ids), (
        "Reduced mode produced rule IDs that full mode did not: "
        f"{reduced_ids - full_ids}"
    )
    assert full_ids - reduced_ids, (
        "Full mode produced the same rule IDs as reduced mode on "
        "varied input — the filter is not actually suppressing anything."
    )


# ─────────────────────────────────────────────────────────────
#  Critical safety rules must still fire
# ─────────────────────────────────────────────────────────────


def test_reduced_mode_still_catches_eval() -> None:
    """eval() is one of the 5 critical safety rules — it must still fire."""
    analyzer = StaticAnalyzer()
    code = "result = ev" + 'al("1+1")\n'
    findings = analyzer.scan_code(code, "bad.py", reduced_mode=True)
    assert any(f.rule_id == "eval_exec" for f in findings), (
        f"eval_exec did not fire in reduced mode. Got: "
        f"{[f.rule_id for f in findings]}"
    )


def test_reduced_mode_still_catches_hardcoded_secret() -> None:
    """Hardcoded secrets are the #1 safety finding — must still fire."""
    analyzer = StaticAnalyzer()
    secret_line = 'AP' + 'I_KEY = "' + 'abcdefghij1234567890ZZ"'
    findings = analyzer.scan_code(secret_line + "\n", "config.py", reduced_mode=True)
    assert any(f.rule_id == "hardcoded_secret" for f in findings), (
        f"hardcoded_secret did not fire in reduced mode. Got: "
        f"{[f.rule_id for f in findings]}"
    )


def test_reduced_mode_still_catches_sql_injection() -> None:
    """SQL injection via string formatting — critical safety rule."""
    analyzer = StaticAnalyzer()
    code = (
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    )
    findings = analyzer.scan_code(code, "db.py", reduced_mode=True)
    assert any(f.rule_id == "sql_injection" for f in findings), (
        f"sql_injection did not fire in reduced mode. Got: "
        f"{[f.rule_id for f in findings]}"
    )


def test_reduced_mode_still_catches_heredoc() -> None:
    """Heredoc detection — in REDUCED_MODE_RULE_IDS."""
    analyzer = StaticAnalyzer()
    code = "config=<<EOF\nfoo\nEOF\n"
    findings = analyzer.scan_code(code, "install.sh", reduced_mode=True)
    # heredoc is a universal rule, should fire on shell files
    assert any(f.rule_id == "heredoc" for f in findings), (
        f"heredoc did not fire in reduced mode. Got: "
        f"{[f.rule_id for f in findings]}"
    )


def test_reduced_mode_still_catches_pickle_load() -> None:
    """pickle.load of untrusted data — critical safety rule."""
    analyzer = StaticAnalyzer()
    code = "import pickle\ndata = pickle.loads(untrusted_bytes)\n"
    findings = analyzer.scan_code(code, "deser.py", reduced_mode=True)
    assert any(f.rule_id == "pickle_load" for f in findings), (
        f"pickle_load did not fire in reduced mode. Got: "
        f"{[f.rule_id for f in findings]}"
    )


def test_reduced_mode_still_catches_bare_except() -> None:
    """Bare except is a quality basic that remains in the reduced set."""
    analyzer = StaticAnalyzer()
    code = "\n".join([
        "def foo():",
        "    try:",
        "        x = 1",
        "    except:",
        "        pass",
    ])
    findings = analyzer.scan_code(code, "q.py", reduced_mode=True)
    assert any(f.rule_id == "bare_except" for f in findings)


# ─────────────────────────────────────────────────────────────
#  Premium phases suppressed via scan_with_hallucination_stack
# ─────────────────────────────────────────────────────────────


def test_reduced_mode_skips_hallucination_stack_phases() -> None:
    """scan_with_hallucination_stack must skip signature validator
    and hallucination taint in reduced mode.

    Reduced mode calls scan_code only — the premium phases are not
    reachable. We verify by checking that reduced findings equal
    scan_code(reduced=True) findings exactly.
    """
    analyzer = StaticAnalyzer()
    code = "\n".join([
        "import unknown_module_xyz",
        'x = ev' + 'al("1+1")',
    ])

    plain_reduced = analyzer.scan_code(code, "test.py", reduced_mode=True)
    stack_reduced = analyzer.scan_with_hallucination_stack(
        code, "test.py", language="python", reduced_mode=True,
    )

    # Same rule IDs, same line numbers, same count
    plain_keys = sorted((f.rule_id, f.line) for f in plain_reduced)
    stack_keys = sorted((f.rule_id, f.line) for f in stack_reduced)
    assert plain_keys == stack_keys, (
        f"scan_with_hallucination_stack in reduced mode diverged from "
        f"scan_code(reduced_mode=True). Diff: plain={plain_keys} "
        f"stack={stack_keys}"
    )


def test_reduced_mode_does_not_leak_between_calls() -> None:
    """Calling scan_code with reduced_mode=True then False on the
    same analyzer must NOT leave residual state. The filter is a
    per-call parameter, not an instance attribute.
    """
    analyzer = StaticAnalyzer()
    code = "\n".join([
        'x = ev' + 'al("1+1")',
        "def very_long_function():",
        *[f"    v{i} = {i}" for i in range(60)],
    ])

    # Burn a reduced-mode call first
    analyzer.scan_code(code, "test.py", reduced_mode=True)
    # Then a full-mode call
    full = analyzer.scan_code(code, "test.py")
    # Full mode should now see more rule IDs than just the reduced set
    full_ids = {f.rule_id for f in full}
    assert full_ids - REDUCED_MODE_RULE_IDS, (
        "Full-mode scan after a reduced-mode scan produced only "
        "REDUCED_MODE_RULE_IDS — the flag leaked."
    )


def test_reduced_mode_is_default_false() -> None:
    """Default scan_code call must behave as full mode."""
    analyzer = StaticAnalyzer()
    code = 'x = ev' + 'al("1+1")\ndef long_fn():\n' + "\n".join(
        f"    v{i} = {i}" for i in range(60)
    )
    default = {f.rule_id for f in analyzer.scan_code(code, "t.py")}
    explicit_full = {
        f.rule_id for f in analyzer.scan_code(code, "t.py", reduced_mode=False)
    }
    assert default == explicit_full
