# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Developer Risk Scoring — correlate AI usage with code quality.

Scores developers based on:
1. BLOCK-rate in their commits (from CodeTrust scans)
2. Which AI models they use (from IDE hook attribution)
3. AI-assisted commit ratio
"""

from __future__ import annotations

import contextlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003 — used at runtime

import structlog

logger = structlog.get_logger()

# ─────────────────────────────────────────────────────────────────
#  Constants
# ─────────────────────────────────────────────────────────────────

TRUST_LEVELS: list[tuple[int, str]] = [
    (25, "trusted"),
    (50, "standard"),
    (75, "elevated"),
    (100, "high_risk"),
]

SCORE_BASE = 20
SCORE_BLOCK_RATE_MAX = 30
SCORE_AI_RATIO_MAX = 20
SCORE_BLOCKED_MODEL_MAX = 15
SCORE_NO_SCAN_MAX = 15


# ─────────────────────────────────────────────────────────────────
#  Types
# ─────────────────────────────────────────────────────────────────


@dataclass
class DeveloperProfile:
    """Risk profile for a single developer."""

    author: str
    email: str = ""
    total_commits: int = 0
    files_touched: int = 0
    ai_commits: int = 0
    ai_ratio: float = 0.0
    models_used: list[str] = field(default_factory=list)
    block_count: int = 0
    warn_count: int = 0
    block_rate: float = 0.0  # blocks per 100 lines
    risk_score: int = 0
    trust_level: str = "standard"


@dataclass
class RiskAssessmentResult:
    """Result of a risk assessment across all developers."""

    profiles: list[DeveloperProfile] = field(default_factory=list)
    total_developers: int = 0
    high_risk_count: int = 0


# ─────────────────────────────────────────────────────────────────
#  DeveloperRiskService
# ─────────────────────────────────────────────────────────────────


class DeveloperRiskService:
    """Compute risk profiles for repository contributors."""

    def assess(
        self,
        workspace: Path,
        max_commits: int = 200,
    ) -> RiskAssessmentResult:
        """Assess risk for all contributors in a git repository.

        Args:
            workspace: Repository root.
            max_commits: Max commits to analyze per author.
        """
        result = RiskAssessmentResult()
        authors = self._get_authors(workspace)

        for author_name, author_email in authors:
            profile = self._build_profile(
                workspace, author_name, author_email, max_commits,
            )
            profile.risk_score = self._compute_score(profile)
            profile.trust_level = self._score_to_level(profile.risk_score)
            result.profiles.append(profile)

        result.total_developers = len(result.profiles)
        result.high_risk_count = sum(
            1 for p in result.profiles if p.trust_level == "high_risk"
        )

        logger.info(
            "risk_assessment_complete",
            developers=result.total_developers,
            high_risk=result.high_risk_count,
        )
        return result

    def _get_authors(self, workspace: Path) -> list[tuple[str, str]]:
        """Get unique authors from git log."""
        try:
            result = subprocess.run(
                ["git", "shortlog", "-sne", "--all"],
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=10,
            )
            authors: list[tuple[str, str]] = []
            for line in result.stdout.strip().split("\n"):
                if not line.strip():
                    continue
                # Format: "  123\tName <email>"
                parts = line.strip().split("\t", maxsplit=1)
                if len(parts) < 2:
                    continue
                name_email = parts[1]
                if "<" in name_email and ">" in name_email:
                    name = name_email[:name_email.index("<")].strip()
                    email = name_email[name_email.index("<") + 1:name_email.index(">")]
                else:
                    name = name_email.strip()
                    email = ""
                authors.append((name, email))
            return authors
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

    def _build_profile(
        self,
        workspace: Path,
        author: str,
        email: str,
        max_commits: int,
    ) -> DeveloperProfile:
        """Build a profile for a single author."""
        profile = DeveloperProfile(author=author, email=email)

        try:
            result = subprocess.run(
                ["git", "log", f"--author={author}", f"-{max_commits}",
                 "--format=%H", "--shortstat"],
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=10,
            )
            commit_count = 0
            files_count = 0
            for line in result.stdout.strip().split("\n"):
                stripped = line.strip()
                if len(stripped) == 40:  # SHA hash
                    commit_count += 1
                elif "file" in stripped and "changed" in stripped:
                    parts = stripped.split(",")
                    for part in parts:
                        if "file" in part:
                            with contextlib.suppress(ValueError, IndexError):
                                files_count += int(part.strip().split()[0])
            profile.total_commits = commit_count
            profile.files_touched = files_count
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # Check for AI attribution signals in commit messages
        try:
            result = subprocess.run(
                ["git", "log", f"--author={author}", f"-{max_commits}",
                 "--format=%B---COMMIT_SEP---"],
                cwd=workspace,
                capture_output=True,
                text=True,
                timeout=10,
            )
            ai_markers = [
                "co-authored-by: claude", "co-authored-by: copilot",
                "co-authored-by: gpt", "generated-by:", "ai-assisted",
                "aider:", "noreply@anthropic.com",
            ]
            messages = result.stdout.lower().split("---commit_sep---")
            ai_count = sum(
                1 for msg in messages
                if any(marker in msg for marker in ai_markers)
            )
            profile.ai_commits = ai_count
            if profile.total_commits > 0:
                profile.ai_ratio = ai_count / profile.total_commits
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return profile

    def _compute_score(self, profile: DeveloperProfile) -> int:
        """Compute risk score 0-100.

        Higher = more risk. Based on:
        - Base score (everyone starts at 20)
        - Block rate
        - AI ratio without review
        - Use of blocked/deprecated models
        - Commit frequency without scans
        """
        score = SCORE_BASE

        # Block rate contribution
        if profile.total_commits > 0:
            block_per_commit = profile.block_count / max(profile.total_commits, 1)
            score += min(int(block_per_commit * 100), SCORE_BLOCK_RATE_MAX)

        # AI ratio contribution (high AI ratio without human review = risk)
        if profile.ai_ratio > 0.8:
            score += SCORE_AI_RATIO_MAX
        elif profile.ai_ratio > 0.5:
            score += int(SCORE_AI_RATIO_MAX * 0.5)

        return min(score, 100)

    def _score_to_level(self, score: int) -> str:
        """Convert risk score to trust level."""
        for threshold, level in TRUST_LEVELS:
            if score <= threshold:
                return level
        return "high_risk"

    def build_report(self, result: RiskAssessmentResult) -> str:
        """Build markdown report from risk assessment."""
        lines: list[str] = [
            "## Developer Risk Profiles",
            "",
            f"**{result.total_developers} developers** | "
            f"{result.high_risk_count} high-risk",
            "",
            "| Developer | Commits | AI% | Score | Level |",
            "|-----------|---------|-----|-------|-------|",
        ]

        for p in sorted(result.profiles, key=lambda x: -x.risk_score):
            ai_pct = f"{p.ai_ratio:.0%}"
            lines.append(
                f"| {p.author} | {p.total_commits} | {ai_pct} | "
                f"{p.risk_score} | {p.trust_level} |"
            )

        return "\n".join(lines)
