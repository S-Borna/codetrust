# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Data Classification Engine — automatic sensitivity assessment for content.

Classifies text and files into four sensitivity levels:
- PUBLIC: open source, docs, README, examples
- INTERNAL: standard business code, internal APIs
- CONFIDENTIAL: customer data, financial, emails, phone numbers
- RESTRICTED: credentials, PII critical/high, regulated data

Integrates with PII detector: PII findings automatically raise the
classification level based on their risk category.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path  # noqa: TC003 — used at runtime in classify_file()
from typing import Any

from src.services.pii_detector import _CATEGORY_RISK, PIIFinding
from src.services.pii_detector import detect as pii_detect

# ───────────────────────────────────────────────────────────────
#  Sensitivity levels (IntEnum for ordering — higher = more sensitive)
# ───────────────────────────────────────────────────────────────


class DataSensitivity(IntEnum):
    """Data sensitivity level, ordered from least to most sensitive."""

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @property
    def label(self) -> str:
        """Return lowercase label string."""
        return self.name.lower()


# ───────────────────────────────────────────────────────────────
#  Classification result
# ───────────────────────────────────────────────────────────────


@dataclass
class ClassificationResult:
    """Result of classifying a piece of content."""

    sensitivity: DataSensitivity
    confidence: float
    reasons: list[str]
    pii_findings: list[PIIFinding]
    indicators: list[str]
    recommended_models: list[str] = field(default_factory=list)
    blocked_models: list[str] = field(default_factory=list)
    file_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-safe dictionary."""
        return {
            "sensitivity": self.sensitivity.label,
            "confidence": round(self.confidence, 2),
            "reasons": self.reasons,
            "pii_findings_count": len(self.pii_findings),
            "indicators": self.indicators,
            "recommended_models": self.recommended_models,
            "blocked_models": self.blocked_models,
            "file_path": self.file_path,
        }


# ───────────────────────────────────────────────────────────────
#  Path-based indicators
# ───────────────────────────────────────────────────────────────

_PUBLIC_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|/)(?:README|LICENSE|CHANGELOG|CONTRIBUTING)", re.IGNORECASE),
    re.compile(r"(?:^|/)docs/", re.IGNORECASE),
    re.compile(r"(?:^|/)examples?/", re.IGNORECASE),
    re.compile(r"(?:^|/)public/", re.IGNORECASE),
    re.compile(r"\.md$", re.IGNORECASE),
]

_INTERNAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|/)src/", re.IGNORECASE),
    re.compile(r"(?:^|/)lib/", re.IGNORECASE),
    re.compile(r"(?:^|/)tests?/", re.IGNORECASE),
    re.compile(r"(?:^|/)scripts?/", re.IGNORECASE),
]

_CONFIDENTIAL_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|/)(?:internal|hr|finance|customer|billing|accounting)/", re.IGNORECASE),
    re.compile(r"(?:^|/)(?:private|restricted)/", re.IGNORECASE),
]

_RESTRICTED_PATH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:^|/)(?:secrets?|credentials?|certs?|keys?)/", re.IGNORECASE),
    re.compile(r"(?:^|/)\.env(?:\.|$)", re.IGNORECASE),
    re.compile(r"(?:private[_-]?key|id_rsa|id_ed25519)", re.IGNORECASE),
    re.compile(r"\.pem$|\.key$|\.p12$|\.pfx$", re.IGNORECASE),
]

# ───────────────────────────────────────────────────────────────
#  Content-based indicators
# ───────────────────────────────────────────────────────────────

_PUBLIC_CONTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:MIT|Apache|BSD|GPL|ISC)\s+License", re.IGNORECASE), "open source license header"),
    (re.compile(r"^#\s+(?:Installation|Usage|Getting Started|API Reference)", re.MULTILINE | re.IGNORECASE), "documentation header"),
    (re.compile(r"```(?:python|javascript|bash|shell)", re.IGNORECASE), "code example block"),
]

_CONFIDENTIAL_CONTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?:customer|kund|client)[\s_]*(?:name|id|number|data)", re.IGNORECASE), "customer data reference"),
    (re.compile(r"(?:salary|revenue|profit|invoice|contract|billing|faktura|lon)[\s_]", re.IGNORECASE), "financial reference"),
    (re.compile(r"(?:employee|anstall|personal)[\s_]*(?:id|data|record|number)", re.IGNORECASE), "employee data reference"),
    (re.compile(r"\bSELECT\b.*\b(?:email|phone|name|address|ssn)\b", re.IGNORECASE), "SQL query with personal columns"),
]

_RESTRICTED_CONTENT_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:GDPR|HIPAA|PCI[\s-]?DSS|SOX)\b"), "regulatory marker"),
    (re.compile(r"\bpatient\s*(?:data|record|id|name)", re.IGNORECASE), "patient data reference"),
    (re.compile(r"\bfinancial\s*records?\b", re.IGNORECASE), "financial records reference"),
    (re.compile(r"\btrade\s*secrets?\b", re.IGNORECASE), "trade secret reference"),
    (re.compile(r"(?:jdbc|mysql|postgres|mongodb|redis)://\S+", re.IGNORECASE), "connection string"),
]


# ───────────────────────────────────────────────────────────────
#  PII risk → sensitivity mapping
# ───────────────────────────────────────────────────────────────

_PII_RISK_TO_SENSITIVITY: dict[str, DataSensitivity] = {
    "critical": DataSensitivity.RESTRICTED,
    "high": DataSensitivity.RESTRICTED,
    "medium": DataSensitivity.CONFIDENTIAL,
    "low": DataSensitivity.INTERNAL,
}


# ───────────────────────────────────────────────────────────────
#  Classification engine
# ───────────────────────────────────────────────────────────────


def classify_text(
    text: str,
    file_path: str = "",
    min_pii_confidence: float = 0.7,
) -> ClassificationResult:
    """Classify text content by sensitivity level.

    Uses path indicators, content patterns, and PII detection to determine
    the highest applicable sensitivity level.

    Args:
        text: Content to classify.
        file_path: Optional file path for path-based indicators.
        min_pii_confidence: Minimum PII confidence threshold.

    Returns:
        ClassificationResult with sensitivity, confidence, and reasons.
    """
    level = DataSensitivity.PUBLIC
    confidence = 0.5
    reasons: list[str] = []
    indicators: list[str] = []

    # ── Phase 1: Path-based classification ──
    if file_path:
        path_str = str(file_path)

        for pattern in _RESTRICTED_PATH_PATTERNS:
            if pattern.search(path_str):
                level = max(level, DataSensitivity.RESTRICTED)
                confidence = max(confidence, 0.90)
                indicators.append(f"path:{pattern.pattern}")
                reasons.append("File path matches restricted pattern")
                break

        if level < DataSensitivity.RESTRICTED:
            for pattern in _CONFIDENTIAL_PATH_PATTERNS:
                if pattern.search(path_str):
                    level = max(level, DataSensitivity.CONFIDENTIAL)
                    confidence = max(confidence, 0.80)
                    indicators.append(f"path:{pattern.pattern}")
                    reasons.append("File path matches confidential pattern")
                    break

        if level < DataSensitivity.CONFIDENTIAL:
            for pattern in _PUBLIC_PATH_PATTERNS:
                if pattern.search(path_str):
                    # Public path — keep as public but boost confidence
                    confidence = max(confidence, 0.85)
                    indicators.append("path:public_documentation")
                    reasons.append("File path matches public/docs pattern")
                    break

        if level == DataSensitivity.PUBLIC and not indicators:
            for pattern in _INTERNAL_PATH_PATTERNS:
                if pattern.search(path_str):
                    level = DataSensitivity.INTERNAL
                    confidence = max(confidence, 0.70)
                    indicators.append("path:internal_code")
                    reasons.append("File path matches internal code pattern")
                    break

    # ── Phase 2: Content-based classification ──
    # Skip restricted content patterns for files in public/docs paths — these
    # files DESCRIBE regulations (GDPR, HIPAA) but don't CONTAIN regulated data.
    is_public_path = any(p.search(str(file_path)) for p in _PUBLIC_PATH_PATTERNS) if file_path else False

    if not is_public_path:
        for pattern, description in _RESTRICTED_CONTENT_PATTERNS:
            if pattern.search(text):
                level = max(level, DataSensitivity.RESTRICTED)
                confidence = max(confidence, 0.85)
                indicators.append(f"content:{description}")
                reasons.append(f"Content contains {description}")

    for pattern, description in _CONFIDENTIAL_CONTENT_PATTERNS:
        if pattern.search(text):
            level = max(level, DataSensitivity.CONFIDENTIAL)
            confidence = max(confidence, 0.80)
            indicators.append(f"content:{description}")
            reasons.append(f"Content contains {description}")

    for pattern, description in _PUBLIC_CONTENT_PATTERNS:
        if pattern.search(text) and level <= DataSensitivity.PUBLIC:
            confidence = max(confidence, 0.85)
            indicators.append(f"content:{description}")
            reasons.append(f"Content contains {description}")

    # ── Phase 3: PII-based classification ──
    pii_findings = pii_detect(text, min_confidence=min_pii_confidence)
    for finding in pii_findings:
        pii_risk = _CATEGORY_RISK.get(finding.category, "low")
        pii_sensitivity = _PII_RISK_TO_SENSITIVITY.get(pii_risk, DataSensitivity.INTERNAL)
        if pii_sensitivity > level:
            level = pii_sensitivity
            confidence = max(confidence, finding.confidence)
            indicators.append(f"pii:{finding.category}")
            reasons.append(f"PII detected: {finding.category} (risk: {pii_risk})")

    # ── Default: INTERNAL if no other indicators ──
    if not indicators and level == DataSensitivity.PUBLIC and text.strip() and not file_path:
        level = DataSensitivity.INTERNAL
        confidence = 0.50
        reasons.append("No specific indicators — defaulting to INTERNAL")

    if not reasons:
        reasons.append("No sensitivity indicators detected")

    return ClassificationResult(
        sensitivity=level,
        confidence=round(confidence, 2),
        reasons=reasons,
        pii_findings=pii_findings,
        indicators=indicators,
        file_path=file_path,
    )


def classify_file(file_path: Path, min_pii_confidence: float = 0.7) -> ClassificationResult:
    """Classify a file by reading its content and path.

    Args:
        file_path: Path to the file to classify.
        min_pii_confidence: Minimum PII confidence threshold.

    Returns:
        ClassificationResult for the file.

    Raises:
        OSError: If the file cannot be read.
    """
    text = file_path.read_text(encoding="utf-8", errors="replace")
    return classify_text(text, file_path=str(file_path), min_pii_confidence=min_pii_confidence)
