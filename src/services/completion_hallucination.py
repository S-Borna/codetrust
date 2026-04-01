# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Completion Hallucination Detection — detects agent claims without evidence.

AI agents frequently claim tasks are complete without running verification
commands. This module detects common completion markers and correlates
them against session evidence (test output, scan results, measurements).

This is a 60% solution — catches obvious cases, not subtle interpretation
errors. No competitor operates in the agent decision loop, so even partial
detection is a unique capability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class ClaimVerdict(StrEnum):
    """Verdict for a completion claim check."""

    VERIFIED = "VERIFIED"
    UNVERIFIED = "UNVERIFIED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


# ───────────────────────────────────────────────────────────────
#  Completion claim patterns
# ───────────────────────────────────────────────────────────────

_COMPLETION_MARKERS: list[re.Pattern[str]] = [
    re.compile(r"[\u2705\u2714]"),                          # ✅ ✔
    re.compile(r"\ball\s+tests?\s+pass", re.IGNORECASE),
    re.compile(r"\b0\s+(errors?|fail(?:ures?|ed)?|warnings?)\b", re.IGNORECASE),
    re.compile(r"\bPASS(?:ED|ING)?\b", re.IGNORECASE),
    re.compile(r"\d[\d,]*\s+tests?\s+pass", re.IGNORECASE),
    re.compile(r"\b(?:done|complete|completed|finished|verified|confirmed)\b", re.IGNORECASE),
    re.compile(r"\bfully\s+(?:functional|working|operational)\b", re.IGNORECASE),
    re.compile(r"\bno\s+(?:issues?|problems?|errors?)\s+found\b", re.IGNORECASE),
    re.compile(r"\b(?:FP|false.?positive)\s+(?:rate\s+)?\d+(?:\.\d+)?\s*%", re.IGNORECASE),
]

# Patterns that indicate numeric claims (e.g., "FP rate 0%", "2,509 tests pass")
_NUMERIC_CLAIM_RE = re.compile(
    r"(\d[\d,]*)\s+(?:tests?\s+pass|passed|pass\b)"
    r"|(?:FP|false.?positive)\s+(?:rate\s+)?(\d+(?:\.\d+)?)\s*%"
    r"|(\d[\d,]*)\s*/\s*(\d[\d,]*)\s+",
    re.IGNORECASE,
)


# ───────────────────────────────────────────────────────────────
#  Evidence patterns (what we expect to see in session history)
# ───────────────────────────────────────────────────────────────

_EVIDENCE_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "test_execution": [
        re.compile(r"pytest\b"),
        re.compile(r"jest\b"),
        re.compile(r"go\s+test\b"),
        re.compile(r"npm\s+(?:run\s+)?test\b"),
        re.compile(r"vitest\b"),
        re.compile(r"cargo\s+test\b"),
        re.compile(r"rspec\b"),
        re.compile(r"\d+\s+passed"),
    ],
    "linter_execution": [
        re.compile(r"ruff\s+check\b"),
        re.compile(r"eslint\b"),
        re.compile(r"pylint\b"),
        re.compile(r"flake8\b"),
        re.compile(r"mypy\b"),
        re.compile(r"tsc\s+--noEmit\b"),
    ],
    "scan_execution": [
        re.compile(r"codetrust.*scan\b"),
        re.compile(r"codetrust.*doctor\b"),
        re.compile(r"semgrep\b"),
        re.compile(r"bandit\b"),
    ],
    "measurement": [
        re.compile(r"\d+\s+passed,\s+\d+\s+failed"),
        re.compile(r"exit\s+code\s*[=:]\s*0\b"),
        re.compile(r"0\s+(?:error|warning|failure)s?\b"),
        re.compile(r"\d+(?:\.\d+)?%"),
        re.compile(r"HTTP\s+[2345]\d\d\b"),
    ],
}


@dataclass
class CompletionClaim:
    """A detected completion claim."""

    text: str
    marker_matched: str
    has_numeric_target: bool = False
    numeric_value: str = ""


@dataclass
class EvidenceMatch:
    """Evidence found in session history."""

    category: str
    text: str
    pattern_matched: str


@dataclass
class ClaimCheckResult:
    """Result of checking a completion claim against evidence."""

    verdict: ClaimVerdict
    claim: CompletionClaim
    evidence: list[EvidenceMatch]
    reason: str


def detect_completion_claims(text: str) -> list[CompletionClaim]:
    """Detect completion claims in agent output text.

    Args:
        text: Agent output text to analyze.

    Returns:
        List of detected completion claims.
    """
    claims: list[CompletionClaim] = []
    seen_positions: set[int] = set()

    for marker_re in _COMPLETION_MARKERS:
        for match in marker_re.finditer(text):
            start = match.start()
            # Avoid duplicate detections on overlapping text
            if any(abs(start - pos) < 20 for pos in seen_positions):
                continue
            seen_positions.add(start)

            # Extract surrounding context (the sentence containing the claim)
            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", start)
            if line_end == -1:
                line_end = len(text)
            context = text[line_start:line_end].strip()

            # Check for numeric target in the claim
            numeric_match = _NUMERIC_CLAIM_RE.search(context)
            has_numeric = numeric_match is not None
            numeric_val = numeric_match.group(0).strip() if numeric_match else ""

            claims.append(CompletionClaim(
                text=context,
                marker_matched=match.group(0),
                has_numeric_target=has_numeric,
                numeric_value=numeric_val,
            ))

    return claims


def find_evidence(session_history: list[str]) -> list[EvidenceMatch]:
    """Search session history for verification evidence.

    Args:
        session_history: List of commands/outputs from the session.

    Returns:
        List of evidence matches found.
    """
    evidence: list[EvidenceMatch] = []

    for entry in session_history:
        for category, patterns in _EVIDENCE_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(entry)
                if match:
                    evidence.append(EvidenceMatch(
                        category=category,
                        text=entry[:200],
                        pattern_matched=pattern.pattern,
                    ))
                    break  # One match per category per entry is enough

    return evidence


def check_claim(
    claim: CompletionClaim,
    evidence: list[EvidenceMatch],
) -> ClaimCheckResult:
    """Check a single completion claim against available evidence.

    Args:
        claim: The completion claim to verify.
        evidence: Evidence collected from session history.

    Returns:
        ClaimCheckResult with verdict and reasoning.
    """
    claim_lower = claim.text.lower()

    # Test-related claims need test execution evidence
    if any(kw in claim_lower for kw in ("test", "pass", "fail")):
        test_evidence = [e for e in evidence if e.category in ("test_execution", "measurement")]
        if test_evidence:
            return ClaimCheckResult(
                verdict=ClaimVerdict.VERIFIED,
                claim=claim,
                evidence=test_evidence,
                reason="Test execution evidence found in session.",
            )
        return ClaimCheckResult(
            verdict=ClaimVerdict.UNVERIFIED,
            claim=claim,
            evidence=[],
            reason="Claim references tests but no test runner execution found in session history.",
        )

    # Lint/warning claims need linter evidence
    if any(kw in claim_lower for kw in ("warning", "lint", "ruff", "eslint", "clean")):
        lint_evidence = [e for e in evidence if e.category in ("linter_execution", "measurement")]
        if lint_evidence:
            return ClaimCheckResult(
                verdict=ClaimVerdict.VERIFIED,
                claim=claim,
                evidence=lint_evidence,
                reason="Linter execution evidence found in session.",
            )
        return ClaimCheckResult(
            verdict=ClaimVerdict.UNVERIFIED,
            claim=claim,
            evidence=[],
            reason="Claim references linting but no linter execution found in session history.",
        )

    # Scan/security claims need scan evidence
    if any(kw in claim_lower for kw in ("scan", "security", "vulnerability", "fp rate", "false positive")):
        scan_evidence = [e for e in evidence if e.category in ("scan_execution", "measurement")]
        if scan_evidence:
            return ClaimCheckResult(
                verdict=ClaimVerdict.VERIFIED,
                claim=claim,
                evidence=scan_evidence,
                reason="Scan execution evidence found in session.",
            )
        return ClaimCheckResult(
            verdict=ClaimVerdict.UNVERIFIED,
            claim=claim,
            evidence=[],
            reason="Claim references scanning but no scan execution found in session history.",
        )

    # Generic completion claims — any measurement evidence is acceptable
    if evidence:
        return ClaimCheckResult(
            verdict=ClaimVerdict.VERIFIED,
            claim=claim,
            evidence=evidence,
            reason="General verification evidence found in session.",
        )

    return ClaimCheckResult(
        verdict=ClaimVerdict.INSUFFICIENT_EVIDENCE,
        claim=claim,
        evidence=[],
        reason="Completion claim detected but no verification commands found in session history.",
    )


# ───────────────────────────────────────────────────────────────
#  Pattern 10: Partial delivery framed as complete
# ───────────────────────────────────────────────────────────────

_PARTIAL_INDICATORS: list[re.Pattern[str]] = [
    re.compile(r"\bpartial\b", re.IGNORECASE),
    re.compile(r"\bplanned\b", re.IGNORECASE),
    re.compile(r"\b\d+\s*/\s*\d+\b"),                              # "6/10"
    re.compile(r"coverage_level.*partial", re.IGNORECASE),
    re.compile(r"coverage_level.*planned", re.IGNORECASE),
    re.compile(r"gap[s]?\s*:", re.IGNORECASE),
    re.compile(r"what.*missing", re.IGNORECASE),
    re.compile(r"\bnot\s+yet\b", re.IGNORECASE),
]

_COMPLETION_FRAMES: list[re.Pattern[str]] = [
    re.compile(r"\bleveran[st]", re.IGNORECASE),
    re.compile(r"\bklar[t]?\b", re.IGNORECASE),
    re.compile(r"\bdone\b", re.IGNORECASE),
    re.compile(r"\bcomplete[d]?\b", re.IGNORECASE),
    re.compile(r"\bsammanfattning\b", re.IGNORECASE),
    re.compile(r"\bsummary\b", re.IGNORECASE),
    re.compile(r"\ball\s+checks\s+pass", re.IGNORECASE),
    re.compile(r"allt\s+fungerar", re.IGNORECASE),
    re.compile(r"everything\s+works", re.IGNORECASE),
]

_FRACTION_RE = re.compile(r"\b(\d+)\s*/\s*(\d+)\b")


def detect_partial_as_complete(text: str) -> ClaimCheckResult | None:
    """Detect when output contains incomplete items but frames delivery as complete.

    Args:
        text: Agent output text to analyze.

    Returns:
        ClaimCheckResult with UNVERIFIED verdict if partial-as-complete detected,
        or None if no issue found.
    """
    has_partial = any(p.search(text) for p in _PARTIAL_INDICATORS)
    has_completion = any(p.search(text) for p in _COMPLETION_FRAMES)

    if not (has_partial and has_completion):
        return None

    # Check if fractions indicate < 100%
    fractions = _FRACTION_RE.findall(text)
    incomplete_fractions = [
        f"{num}/{denom}"
        for num, denom in fractions
        if num != denom and int(denom) > 0
    ]

    # If we have fractions but they're all N/N (100%), no problem
    if fractions and not incomplete_fractions:
        return None

    # Build reason with specifics
    partial_matches = [
        p.pattern for p in _PARTIAL_INDICATORS if p.search(text)
    ]
    frame_matches = [
        p.pattern for p in _COMPLETION_FRAMES if p.search(text)
    ]

    fraction_detail = ""
    if incomplete_fractions:
        fraction_detail = f" Incomplete items: {', '.join(incomplete_fractions[:3])}."

    return ClaimCheckResult(
        verdict=ClaimVerdict.UNVERIFIED,
        claim=CompletionClaim(
            text=text[:200],
            marker_matched="partial-as-complete",
            has_numeric_target=bool(incomplete_fractions),
            numeric_value=incomplete_fractions[0] if incomplete_fractions else "",
        ),
        evidence=[],
        reason=(
            "Output contains incomplete items but frames delivery as complete."
            f"{fraction_detail}"
            f" Partial indicators: {len(partial_matches)}."
            f" Completion frames: {len(frame_matches)}."
        ),
    )


def verify_claims(
    agent_output: str,
    session_history: list[str],
) -> list[ClaimCheckResult]:
    """Full pipeline: detect claims, find evidence, check each claim.

    Also checks for partial-as-complete framing (pattern 10).

    Args:
        agent_output: The agent's latest output text.
        session_history: List of commands/outputs from the session.

    Returns:
        List of claim check results. Empty if no claims detected.
    """
    results: list[ClaimCheckResult] = []

    # Pattern 10: partial-as-complete
    partial_result = detect_partial_as_complete(agent_output)
    if partial_result is not None:
        results.append(partial_result)

    claims = detect_completion_claims(agent_output)
    if not claims:
        return results

    evidence = find_evidence(session_history)
    results.extend(check_claim(claim, evidence) for claim in claims)

    return results
