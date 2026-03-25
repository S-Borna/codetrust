# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Commit Policy Engine — enforces model, editor, and AI controls.

Reads policy from ``[policy]`` section of ``.codetrust.toml``.
Evaluates file attributions against allowlists, blocklists,
AI ratio limits, and review requirements.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003 — used at runtime

import structlog

logger = structlog.get_logger()

# ─────────────────────────────────────────────────────────────────
#  Types
# ─────────────────────────────────────────────────────────────────

VALID_MODES: frozenset[str] = frozenset({"allowlist", "blocklist", "audit", "none"})
VALID_PERSONALITIES: frozenset[str] = frozenset({"strict", "standard", "mentor"})


@dataclass(frozen=True)
class PolicyViolation:
    """A single policy violation."""

    rule: str       # "blocked_model", "blocked_editor", "ai_not_allowed", etc.
    severity: str   # "BLOCK" or "WARN"
    file: str
    message: str
    detail: str = ""


@dataclass
class PolicyConfig:
    """Parsed policy configuration from .codetrust.toml."""

    # Model controls
    model_mode: str = "none"
    models_allowed: list[str] = field(default_factory=list)
    models_blocked: list[str] = field(default_factory=list)

    # Editor controls
    editor_mode: str = "none"
    editors_allowed: list[str] = field(default_factory=list)
    editors_blocked: list[str] = field(default_factory=list)

    # AI commit controls
    allow_ai_generated: bool = True
    require_human_review: bool = False
    max_ai_ratio: float = 1.0

    # Review personality
    personality: str = "strict"
    contact: str = ""
    block_header: str = "COMMIT REJECTED by CodeTrust"
    ai_block_message: str = "AI-generated code is not allowed in this repository."
    model_block_message: str = "Model '{model}' is not approved. Approved: {allowed}."
    editor_block_message: str = "Editor '{editor}' is not approved. Contact {contact}."


@dataclass(frozen=True)
class FileAttribution:
    """Attribution data for a single file in a commit."""

    file: str
    model: str = "unknown"
    provider: str = "unknown"
    editor: str = "unknown"
    ai_probability: float = 0.0


# ─────────────────────────────────────────────────────────────────
#  Config loading
# ─────────────────────────────────────────────────────────────────


def load_policy_config(workspace: Path) -> PolicyConfig:
    """Load policy from .codetrust.toml in workspace root.

    Returns default (no restrictions) if file doesn't exist or is invalid.
    """
    config_path = workspace / ".codetrust.toml"
    if not config_path.exists():
        return PolicyConfig()

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        logger.warning("policy_config_load_error", path=str(config_path), error=str(exc))
        return PolicyConfig()

    policy = data.get("policy", {})
    if not isinstance(policy, dict):
        return PolicyConfig()

    models = policy.get("models", {})
    editors = policy.get("editors", {})
    ai = policy.get("ai_commits", {})
    review = policy.get("review", {})

    model_mode = str(models.get("mode", "none"))
    editor_mode = str(editors.get("mode", "none"))

    if model_mode not in VALID_MODES:
        logger.warning("policy_invalid_model_mode", mode=model_mode)
        model_mode = "none"
    if editor_mode not in VALID_MODES:
        logger.warning("policy_invalid_editor_mode", mode=editor_mode)
        editor_mode = "none"

    personality = str(review.get("personality", "strict"))
    if personality not in VALID_PERSONALITIES:
        personality = "strict"

    return PolicyConfig(
        model_mode=model_mode,
        models_allowed=[str(m) for m in models.get("allowed", [])],
        models_blocked=[str(m) for m in models.get("blocked", [])],
        editor_mode=editor_mode,
        editors_allowed=[str(e) for e in editors.get("allowed", [])],
        editors_blocked=[str(e) for e in editors.get("blocked", [])],
        allow_ai_generated=bool(ai.get("allow_ai_generated", True)),
        require_human_review=bool(ai.get("require_human_review", False)),
        max_ai_ratio=float(ai.get("max_ai_ratio", 1.0)),
        personality=personality,
        contact=str(policy.get("contact", "")),
        block_header=str(review.get("block_header", "COMMIT REJECTED by CodeTrust")),
        ai_block_message=str(review.get(
            "ai_block_message",
            "AI-generated code is not allowed in this repository.",
        )),
        model_block_message=str(review.get(
            "model_block_message",
            "Model '{model}' is not approved. Approved: {allowed}.",
        )),
        editor_block_message=str(review.get(
            "editor_block_message",
            "Editor '{editor}' is not approved. Contact {contact}.",
        )),
    )


# ─────────────────────────────────────────────────────────────────
#  CommitPolicyEngine
# ─────────────────────────────────────────────────────────────────


class CommitPolicyEngine:
    """Evaluate commit file attributions against repository policy."""

    def __init__(self, workspace: Path) -> None:
        """Initialize with workspace root."""
        self.workspace = workspace
        self.config = load_policy_config(workspace)

    def evaluate(
        self,
        file_attributions: list[FileAttribution],
    ) -> list[PolicyViolation]:
        """Evaluate a set of file attributions against the loaded policy.

        Returns list of violations. Empty list = commit is allowed.
        """
        violations: list[PolicyViolation] = []
        ai_file_count = 0
        total_files = len(file_attributions)

        for fa in file_attributions:
            is_ai = fa.ai_probability > 0.5 or fa.model != "unknown"
            if is_ai:
                ai_file_count += 1

            violations.extend(self._check_model(fa))
            violations.extend(self._check_editor(fa))
            violations.extend(self._check_ai_allowed(fa, is_ai))

        # AI ratio check (commit-level)
        violations.extend(self._check_ai_ratio(ai_file_count, total_files))

        logger.info(
            "policy_evaluation_complete",
            total_files=total_files,
            ai_files=ai_file_count,
            violations=len(violations),
            blocks=sum(1 for v in violations if v.severity == "BLOCK"),
        )
        return violations

    def _check_model(self, fa: FileAttribution) -> list[PolicyViolation]:
        """Check model against policy."""
        if fa.model == "unknown" or self.config.model_mode == "none":
            return []

        severity = "BLOCK" if self.config.model_mode != "audit" else "WARN"

        if self.config.model_mode == "allowlist" and not any(
            fa.model.startswith(m) for m in self.config.models_allowed
        ):
                msg = self.config.model_block_message.format(
                    model=fa.model,
                    allowed=", ".join(self.config.models_allowed),
                )
                return [PolicyViolation(
                    rule="blocked_model",
                    severity=severity,
                    file=fa.file,
                    message=msg,
                    detail=f"Model {fa.model} not in allowlist",
                )]

        if self.config.model_mode in ("blocklist", "audit") and any(
            fa.model.startswith(m) for m in self.config.models_blocked
        ):
                return [PolicyViolation(
                    rule="blocked_model",
                    severity=severity,
                    file=fa.file,
                    message=f"Model '{fa.model}' is explicitly blocked.",
                    detail=f"Model {fa.model} in blocklist",
                )]

        return []

    def _check_editor(self, fa: FileAttribution) -> list[PolicyViolation]:
        """Check editor against policy."""
        if fa.editor == "unknown" or self.config.editor_mode == "none":
            return []

        severity = "BLOCK" if self.config.editor_mode != "audit" else "WARN"

        if self.config.editor_mode == "allowlist" and fa.editor not in self.config.editors_allowed:
                msg = self.config.editor_block_message.format(
                    editor=fa.editor,
                    contact=self.config.contact,
                )
                return [PolicyViolation(
                    rule="blocked_editor",
                    severity=severity,
                    file=fa.file,
                    message=msg,
                )]

        if self.config.editor_mode in ("blocklist", "audit") and fa.editor in self.config.editors_blocked:
                return [PolicyViolation(
                    rule="blocked_editor",
                    severity=severity,
                    file=fa.file,
                    message=f"Editor '{fa.editor}' is not allowed.",
                )]

        return []

    def _check_ai_allowed(
        self,
        fa: FileAttribution,
        is_ai: bool,
    ) -> list[PolicyViolation]:
        """Check AI commit controls."""
        violations: list[PolicyViolation] = []

        if is_ai and not self.config.allow_ai_generated:
            violations.append(PolicyViolation(
                rule="ai_not_allowed",
                severity="BLOCK",
                file=fa.file,
                message=self.config.ai_block_message,
            ))

        if is_ai and self.config.require_human_review:
            violations.append(PolicyViolation(
                rule="ai_requires_review",
                severity="WARN",
                file=fa.file,
                message="AI-generated file requires human review approval.",
            ))

        return violations

    def _check_ai_ratio(
        self,
        ai_count: int,
        total: int,
    ) -> list[PolicyViolation]:
        """Check AI file ratio at commit level."""
        if total == 0 or self.config.max_ai_ratio >= 1.0:
            return []

        ratio = ai_count / total
        if ratio > self.config.max_ai_ratio:
            return [PolicyViolation(
                rule="ai_ratio_exceeded",
                severity="BLOCK",
                file="(commit-level)",
                message=(
                    f"AI-generated ratio {ratio:.0%} exceeds max "
                    f"{self.config.max_ai_ratio:.0%}."
                ),
                detail=f"{ai_count}/{total} files are AI-generated",
            )]
        return []

    def has_blocks(self, violations: list[PolicyViolation]) -> bool:
        """Check if any violations are blocking."""
        return any(v.severity == "BLOCK" for v in violations)

    def build_report(self, violations: list[PolicyViolation]) -> str:
        """Build markdown report from violations."""
        if not violations:
            return "Policy: PASS — no violations."

        lines: list[str] = []
        blocks = [v for v in violations if v.severity == "BLOCK"]
        warns = [v for v in violations if v.severity == "WARN"]

        if blocks:
            lines.append(f"## {self.config.block_header}")
            lines.append("")
            for v in blocks:
                lines.append(f"- **{v.file}**: {v.message}")
            lines.append("")

        if warns:
            lines.append("### Warnings")
            lines.append("")
            for v in warns:
                lines.append(f"- {v.file}: {v.message}")
            lines.append("")

        lines.append(
            f"{len(blocks)} blocks, {len(warns)} warnings"
        )
        return "\n".join(lines)
