# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for Completion Hallucination Detection."""

from __future__ import annotations

import pytest

from src.services.completion_hallucination import (
    ClaimVerdict,
    CompletionClaim,
    check_claim,
    detect_completion_claims,
    detect_partial_as_complete,
    find_evidence,
    verify_claims,
)

# ───────────────────────────────────────────────────────────────
#  detect_completion_claims
# ───────────────────────────────────────────────────────────────


class TestDetectCompletionClaims:
    """Tests for detecting completion markers in agent output."""

    def test_checkmark_detected(self) -> None:
        claims = detect_completion_claims("Tests \u2705 — all passing")
        assert len(claims) >= 1
        assert any(c.marker_matched == "\u2705" for c in claims)

    def test_all_tests_pass(self) -> None:
        claims = detect_completion_claims("All tests pass, ready to merge.")
        assert len(claims) >= 1
        assert any("tests pass" in c.text.lower() for c in claims)

    def test_zero_errors(self) -> None:
        claims = detect_completion_claims("Scan complete: 0 errors found.")
        assert len(claims) >= 1

    def test_done_keyword(self) -> None:
        claims = detect_completion_claims("Feature implementation is done.")
        assert len(claims) >= 1
        assert any("done" in c.text.lower() for c in claims)

    def test_numeric_target_detected(self) -> None:
        claims = detect_completion_claims("2,509 tests pass, 0 fail")
        assert len(claims) >= 1
        numeric_claims = [c for c in claims if c.has_numeric_target]
        assert len(numeric_claims) >= 1

    def test_fp_rate_claim(self) -> None:
        claims = detect_completion_claims("FP rate 0% on own code")
        assert len(claims) >= 1

    def test_no_claims_in_normal_text(self) -> None:
        claims = detect_completion_claims(
            "I need to investigate the test failures and fix the root cause."
        )
        assert len(claims) == 0

    def test_verified_keyword(self) -> None:
        claims = detect_completion_claims("All endpoints verified and working.")
        assert len(claims) >= 1

    def test_completed_keyword(self) -> None:
        claims = detect_completion_claims("Migration completed successfully.")
        assert len(claims) >= 1


# ───────────────────────────────────────────────────────────────
#  find_evidence
# ───────────────────────────────────────────────────────────────


class TestFindEvidence:
    """Tests for finding verification evidence in session history."""

    def test_pytest_evidence(self) -> None:
        history = ["pytest tests/ -x -q", "2510 passed, 0 failed, 8 skipped"]
        evidence = find_evidence(history)
        categories = {e.category for e in evidence}
        assert "test_execution" in categories
        assert "measurement" in categories

    def test_ruff_evidence(self) -> None:
        history = ["ruff check src/ --ignore RUF001"]
        evidence = find_evidence(history)
        assert any(e.category == "linter_execution" for e in evidence)

    def test_scan_evidence(self) -> None:
        history = ["codetrust doctor", "8/8 layers active"]
        evidence = find_evidence(history)
        assert any(e.category == "scan_execution" for e in evidence)

    def test_no_evidence(self) -> None:
        history = ["git status", "ls -la src/"]
        evidence = find_evidence(history)
        # git status and ls are not verification commands
        assert not any(e.category == "test_execution" for e in evidence)

    def test_exit_code_evidence(self) -> None:
        history = ["exit code: 0"]
        evidence = find_evidence(history)
        assert any(e.category == "measurement" for e in evidence)


# ───────────────────────────────────────────────────────────────
#  check_claim
# ───────────────────────────────────────────────────────────────


class TestCheckClaim:
    """Tests for checking individual claims against evidence."""

    def test_test_claim_with_evidence(self) -> None:
        claim = CompletionClaim(
            text="All tests pass",
            marker_matched="pass",
            has_numeric_target=False,
        )
        evidence = find_evidence(["pytest tests/", "2510 passed, 0 failed"])
        result = check_claim(claim, evidence)
        assert result.verdict == ClaimVerdict.VERIFIED

    def test_test_claim_without_evidence(self) -> None:
        claim = CompletionClaim(
            text="All tests pass",
            marker_matched="pass",
            has_numeric_target=False,
        )
        result = check_claim(claim, [])
        assert result.verdict == ClaimVerdict.UNVERIFIED
        assert "no test runner" in result.reason.lower()

    def test_lint_claim_with_evidence(self) -> None:
        claim = CompletionClaim(
            text="Ruff clean, 0 warnings",
            marker_matched="0 warnings",
            has_numeric_target=False,
        )
        evidence = find_evidence(["ruff check src/", "0 warnings"])
        result = check_claim(claim, evidence)
        assert result.verdict == ClaimVerdict.VERIFIED

    def test_lint_claim_without_evidence(self) -> None:
        claim = CompletionClaim(
            text="0 warnings from linter",
            marker_matched="0 warnings",
            has_numeric_target=False,
        )
        result = check_claim(claim, [])
        assert result.verdict == ClaimVerdict.UNVERIFIED

    def test_scan_claim_with_evidence(self) -> None:
        claim = CompletionClaim(
            text="FP rate 0% on own code",
            marker_matched="0%",
            has_numeric_target=True,
            numeric_value="0%",
        )
        evidence = find_evidence(["codetrust scan src/", "0 BLOCK findings"])
        result = check_claim(claim, evidence)
        assert result.verdict == ClaimVerdict.VERIFIED

    def test_generic_done_without_evidence(self) -> None:
        claim = CompletionClaim(
            text="Feature implementation is done",
            marker_matched="done",
            has_numeric_target=False,
        )
        result = check_claim(claim, [])
        assert result.verdict == ClaimVerdict.INSUFFICIENT_EVIDENCE


# ───────────────────────────────────────────────────────────────
#  verify_claims (full pipeline)
# ───────────────────────────────────────────────────────────────


class TestVerifyClaims:
    """Integration tests for the full claim verification pipeline."""

    def test_unverified_test_claim(self) -> None:
        """Agent claims tests pass but never ran pytest."""
        results = verify_claims(
            agent_output="All tests pass \u2705. Ready to merge.",
            session_history=["git add .", "git status"],
        )
        assert len(results) >= 1
        unverified = [r for r in results if r.verdict != ClaimVerdict.VERIFIED]
        assert len(unverified) >= 1

    def test_verified_test_claim(self) -> None:
        """Agent claims tests pass AND ran pytest with evidence."""
        results = verify_claims(
            agent_output="All tests pass \u2705. 2510 passed, 0 failed.",
            session_history=[
                "pytest tests/ -x -q",
                "2510 passed, 0 failed, 8 skipped (83.12s)",
            ],
        )
        assert len(results) >= 1
        # At least one claim should be verified
        verified = [r for r in results if r.verdict == ClaimVerdict.VERIFIED]
        assert len(verified) >= 1

    def test_no_claims_returns_empty(self) -> None:
        """Normal discussion text should not trigger detection."""
        results = verify_claims(
            agent_output="I need to investigate this further before making changes.",
            session_history=["git log --oneline -5"],
        )
        assert results == []

    def test_mixed_claims(self) -> None:
        """Multiple claims, some verified some not."""
        results = verify_claims(
            agent_output=(
                "Tests \u2705 all pass. Ruff \u2705 clean. "
                "Deployment verified \u2705."
            ),
            session_history=[
                "pytest tests/ -x -q",
                "2510 passed, 0 failed, 8 skipped",
            ],
        )
        assert len(results) >= 2
        # Test claim should be verified, deployment probably not
        verdicts = {r.claim.text: r.verdict for r in results}
        has_verified = any(v == ClaimVerdict.VERIFIED for v in verdicts.values())
        assert has_verified

    def test_checkmark_with_numeric_target(self) -> None:
        """Checkmark on a task with a numeric target without measurement."""
        results = verify_claims(
            agent_output="FP rate \u2705 — 0% on own code",
            session_history=["git diff --stat"],
        )
        assert len(results) >= 1
        fp_claims = [r for r in results if "fp" in r.claim.text.lower() or "0%" in r.claim.text]
        assert len(fp_claims) >= 1
        assert fp_claims[0].verdict != ClaimVerdict.VERIFIED


class TestPartialAsComplete:
    """Tests for pattern 10: partial delivery framed as complete."""

    def test_partial_with_completion_frame_detected(self) -> None:
        """Output with 6/10 partial AND 'done' → UNVERIFIED."""
        text = (
            "Compliance mapping done. Coverage: 6/10 full, 4/10 partial. "
            "All checks complete."
        )
        result = detect_partial_as_complete(text)
        assert result is not None
        assert result.verdict == ClaimVerdict.UNVERIFIED
        assert "incomplete items" in result.reason.lower() or "partial" in result.reason.lower()

    def test_partial_without_completion_frame_returns_none(self) -> None:
        """Output with partial indicators but no completion frame → None."""
        text = "Coverage: 6/10 full, 4/10 partial. Gaps remain."
        result = detect_partial_as_complete(text)
        assert result is None

    def test_full_coverage_with_completion_frame_returns_none(self) -> None:
        """10/10 with 'done' → no issue (everything IS complete)."""
        text = "Compliance mapping done. Coverage: 10/10 full."
        result = detect_partial_as_complete(text)
        assert result is None

    def test_verify_claims_includes_partial_as_complete(self) -> None:
        """verify_claims pipeline catches partial-as-complete."""
        results = verify_claims(
            agent_output="Summary: 6/10 full, 4/10 partial. Everything works.",
            session_history=["git status"],
        )
        partial_results = [
            r for r in results
            if r.claim.marker_matched == "partial-as-complete"
        ]
        assert len(partial_results) == 1
        assert partial_results[0].verdict == ClaimVerdict.UNVERIFIED

    def test_fraction_detail_in_reason(self) -> None:
        """Reason includes the specific incomplete fraction."""
        text = "Leverans klar. OWASP: 6/10 full."
        result = detect_partial_as_complete(text)
        assert result is not None
        assert "6/10" in result.reason


# ───────────────────────────────────────────────────────────────
#  Unified verify_claim gateway tool (completion + integrity)
# ───────────────────────────────────────────────────────────────


class TestUnifiedVerifyClaim:
    """Test that verify_claim runs both pipelines with structured input."""

    @pytest.mark.asyncio()
    async def test_flat_input_returns_completion_only(self) -> None:
        """Legacy flat list input → completion claims only, integrity is None."""
        import json

        from src.gateway.server import verify_claim

        result = await verify_claim(
            agent_output="All tests pass ✅",
            session_history='["pytest tests/", "50 passed"]',
        )
        data = json.loads(result)
        assert "completion_claims" in data
        assert data["integrity"] is None
        assert "summary" in data

    @pytest.mark.asyncio()
    async def test_structured_input_returns_both(self) -> None:
        """Structured input with messages → both pipelines run."""
        import json

        from src.gateway.server import verify_claim

        session = json.dumps({
            "messages": [
                {"role": "assistant", "content": "This cannot be done."},
                {"role": "user", "content": "Do it."},
                {"role": "assistant", "content": "Du har absolut rätt."},
                {"role": "tool", "content": "pytest tests/ → 50 passed"},
            ],
            "commands": ["pytest tests/", "50 passed"],
        })

        result = await verify_claim(
            agent_output="All tests pass. Done ✅",
            session_history=session,
        )
        data = json.loads(result)
        assert "completion_claims" in data
        assert data["integrity"] is not None
        assert "verdict" in data["integrity"]
        assert "issues" in data["integrity"]
        assert data["summary"]["total_issues"] >= 0

    @pytest.mark.asyncio()
    async def test_backward_compatible_with_empty_list(self) -> None:
        """Empty list input works as before."""
        import json

        from src.gateway.server import verify_claim

        result = await verify_claim(
            agent_output="Everything is done.",
            session_history="[]",
        )
        data = json.loads(result)
        assert "completion_claims" in data
        assert data["integrity"] is None

    @pytest.mark.asyncio()
    async def test_top_level_aliases_for_old_consumers(self) -> None:
        """Old consumers access claims_detected and results at top level."""
        import json

        from src.gateway.server import verify_claim

        result = await verify_claim(
            agent_output="All tests pass ✅. Fully functional.",
            session_history="[]",
        )
        data = json.loads(result)

        # New format: nested under completion_claims
        assert "completion_claims" in data
        nested_count = data["completion_claims"]["claims_detected"]
        nested_results = data["completion_claims"]["results"]

        # Old format: top-level aliases must exist and match
        assert "claims_detected" in data, "Missing top-level claims_detected alias"
        assert "results" in data, "Missing top-level results alias"
        assert data["claims_detected"] == nested_count
        assert data["results"] == nested_results
        assert data["claims_detected"] > 0
