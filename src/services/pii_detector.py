# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""PII Detection Engine — detects personally identifiable information in text.

Supports 15+ categories: email, phone, credit card, personnummer, API keys,
private keys, JWT, IBAN, IP addresses, passwords, URLs with credentials,
names, addresses, dates of birth, passport numbers, and SSN.

Each pattern uses regex + optional validators (Luhn for CC/personnummer,
checksum for IBAN). Confidence scoring: validated match 0.95, regex-only 0.7,
contextual 0.5.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ───────────────────────────────────────────────────────────────
#  Data classes
# ───────────────────────────────────────────────────────────────


@dataclass
class PIIFinding:
    """A single PII detection in text."""

    category: str
    value: str
    start: int
    end: int
    confidence: float
    context: str


@dataclass
class PIIReport:
    """Full PII scan report."""

    text_length: int
    findings: list[PIIFinding]
    categories_found: list[str]
    risk_level: str
    redacted_text: str
    summary: str

    def to_dict(self) -> dict[str, object]:
        """Serialize to JSON-safe dictionary."""
        return {
            "text_length": self.text_length,
            "findings_count": len(self.findings),
            "categories_found": self.categories_found,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "findings": [
                {
                    "category": f.category,
                    "value": f.value,
                    "start": f.start,
                    "end": f.end,
                    "confidence": f.confidence,
                    "context": f.context,
                }
                for f in self.findings
            ],
        }


# ───────────────────────────────────────────────────────────────
#  Validators
# ───────────────────────────────────────────────────────────────


def _luhn_check(digits: str) -> bool:
    """Validate a number string using the Luhn algorithm.

    Args:
        digits: String of digits to validate.

    Returns:
        True if the Luhn checksum is valid.
    """
    nums = [int(d) for d in digits if d.isdigit()]
    if len(nums) < 2:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _iban_checksum(iban: str) -> bool:
    """Validate IBAN using mod-97 check.

    Args:
        iban: IBAN string (with or without spaces).

    Returns:
        True if the IBAN checksum is valid.
    """
    clean = iban.replace(" ", "").replace("-", "").upper()
    if len(clean) < 5:
        return False
    # Move first 4 chars to end
    rearranged = clean[4:] + clean[:4]
    # Convert letters to numbers (A=10, B=11, ...)
    numeric = ""
    for ch in rearranged:
        if ch.isdigit():
            numeric += ch
        elif ch.isalpha():
            numeric += str(ord(ch) - ord("A") + 10)
        else:
            return False
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


def _validate_personnummer(pnr: str) -> bool:
    """Validate Swedish personnummer with Luhn on last 10 digits.

    Args:
        pnr: Personnummer string (YYMMDD-XXXX or YYYYMMDDXXXX).

    Returns:
        True if format and Luhn check pass.
    """
    digits_only = re.sub(r"[^0-9]", "", pnr)
    # Use last 10 digits for Luhn (YYMMDDXXXX)
    if len(digits_only) == 12:
        digits_only = digits_only[2:]
    if len(digits_only) != 10:
        return False
    # Basic date validation
    month = int(digits_only[2:4])
    day = int(digits_only[4:6])
    if month < 1 or month > 12 or day < 1 or day > 31:
        return False
    return _luhn_check(digits_only)


# ───────────────────────────────────────────────────────────────
#  Pattern definitions
# ───────────────────────────────────────────────────────────────

_CONTEXT_WINDOW = 20

# Risk levels per category (used for overall risk_level determination)
_CATEGORY_RISK: dict[str, str] = {
    "private_key": "critical",
    "password": "critical",
    "api_key": "critical",
    "credit_card": "critical",
    "personnummer": "high",
    "ssn": "high",
    "passport": "high",
    "jwt": "high",
    "email": "medium",
    "phone": "medium",
    "iban": "medium",
    "ip_address": "medium",
    "url_credentials": "critical",
    "name": "low",
    "address": "low",
    "date_of_birth": "low",
}

_RISK_ORDER = ["critical", "high", "medium", "low", "none"]


@dataclass
class _PIIPattern:
    """Internal pattern definition."""

    category: str
    regex: re.Pattern[str]
    validator: Any = None  # callable(str) -> bool, or None
    base_confidence: float = 0.7
    validated_confidence: float = 0.95
    contextual: bool = False


# ── Universal patterns ──

_EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
)

_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{2,4}(?!\d)",
)

_CREDIT_CARD_RE = re.compile(
    r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
    r"[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,4}\b",
)

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
)

_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b",
)

_API_KEY_RE = re.compile(
    r"\b(?:sk-[a-zA-Z0-9]{20,}|pk-[a-zA-Z0-9]{20,}"
    r"|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}"
    r"|github_pat_[a-zA-Z0-9_]{20,}"
    r"|xoxb-[a-zA-Z0-9\-]{20,}|xoxp-[a-zA-Z0-9\-]{20,}"
    r"|Bearer\s+[a-zA-Z0-9\-._~+/]{20,}=*"
    r"|AKIA[0-9A-Z]{16}"
    r"|sk_live_[a-zA-Z0-9]{20,}|pk_live_[a-zA-Z0-9]{20,}"
    r"|sk_test_[a-zA-Z0-9]{20,}|pk_test_[a-zA-Z0-9]{20,})\b",
)

_PASSWORD_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api_key|apikey|auth_token)"
    r"\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
    re.IGNORECASE,
)

_URL_CREDS_RE = re.compile(
    r"https?://[a-zA-Z0-9._\-]+:[^\s@]+@[a-zA-Z0-9.\-]+",
)

_JWT_RE = re.compile(
    r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b",
)

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|OPENSSH|DSA|ENCRYPTED)?\s*PRIVATE\s+KEY-----",
)

# ── Swedish/EU patterns ──

_PERSONNUMMER_RE = re.compile(
    r"\b(?:19|20)?\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[\-]?\d{4}\b",
)

_IBAN_RE = re.compile(
    r"\b[A-Z]{2}\d{2}\s?(?:\d{4}\s?){2,7}\d{1,4}\b",
)

_PASSPORT_RE = re.compile(
    r"\b(?:passport(?:\s*(?:nr|no|number))?|passnummer|pass\s*(?:nr|no|number))\s*[=:]\s*([A-Z0-9]{6,12})\b",
    re.IGNORECASE,
)

_SSN_RE = re.compile(
    r"\b\d{3}[\-]\d{2}[\-]\d{4}\b",
)

# ── Contextual patterns ──

_NAME_RE = re.compile(
    # Require word boundary (no className/userName prefix) and at least
    # two capitalized words (first + last name).  Removed "user" — too
    # many FP in code (user = await db...).
    r"(?<![A-Za-z])(?:name|patient|customer|contact|kund|namn|employee)"
    r"\s*[=:]\s*['\"]?"
    r"([A-Z\u00C0-\u024F][a-z\u00C0-\u024F]+(?:\s+[A-Z\u00C0-\u024F][a-z\u00C0-\u024F]+)+)"
    r"['\"]?",
)

_ADDRESS_RE = re.compile(
    r"(?:address|street|adress|gata|väg)\s*[=:]\s*['\"]?(.+?\d{3}\s?\d{2})['\"]?",
    re.IGNORECASE,
)

_DOB_RE = re.compile(
    r"(?:born|dob|birthday|birth_date|födelsedatum|födelsedag)\s*[=:]\s*['\"]?(\d{4}[\-/]\d{2}[\-/]\d{2}|\d{2}[\-/]\d{2}[\-/]\d{4})['\"]?",
    re.IGNORECASE,
)


def _build_patterns() -> list[_PIIPattern]:
    """Build the list of all PII detection patterns."""
    # Order matters: longer/more-specific patterns first to win dedup.
    # URL-with-creds before email, credit card before phone, etc.
    return [
        # ── High-specificity patterns first ──
        # 1. Private keys (very specific header)
        _PIIPattern(category="private_key", regex=_PRIVATE_KEY_RE, base_confidence=0.95),
        # 2. JWT tokens (long base64 with dots)
        _PIIPattern(category="jwt", regex=_JWT_RE, base_confidence=0.9),
        # 3. URLs with credentials (contains @ which email also matches)
        _PIIPattern(category="url_credentials", regex=_URL_CREDS_RE, base_confidence=0.9),
        # 4. API keys/tokens (prefix-based, specific)
        _PIIPattern(category="api_key", regex=_API_KEY_RE, base_confidence=0.9),
        # 5. Passwords in cleartext (keyword = "value")
        _PIIPattern(category="password", regex=_PASSWORD_RE, base_confidence=0.9),
        # 6. Credit card (long digit sequence — before phone which is shorter)
        _PIIPattern(
            category="credit_card", regex=_CREDIT_CARD_RE,
            validator=lambda m: _luhn_check(re.sub(r"[\s\-]", "", m)),
        ),
        # 7. IBAN (starts with 2 letters + 2 digits, validated)
        _PIIPattern(
            category="iban", regex=_IBAN_RE,
            validator=lambda m: _iban_checksum(m),
        ),
        # 8. Personnummer (Luhn-validated)
        _PIIPattern(
            category="personnummer", regex=_PERSONNUMMER_RE,
            validator=lambda m: _validate_personnummer(m),
        ),
        # 9. US SSN (3-2-4 dash format)
        _PIIPattern(category="ssn", regex=_SSN_RE),
        # 10. IPv4
        _PIIPattern(category="ip_address", regex=_IPV4_RE),
        # 11. IPv6
        _PIIPattern(category="ip_address", regex=_IPV6_RE),
        # 12. Email (after URL-with-creds to avoid overlap)
        _PIIPattern(category="email", regex=_EMAIL_RE),
        # 13. Passport (contextual — before phone to not lose digits)
        _PIIPattern(
            category="passport", regex=_PASSPORT_RE,
            contextual=True, base_confidence=0.5,
        ),
        # 14. Phone (last among digit-based — most greedy)
        _PIIPattern(category="phone", regex=_PHONE_RE, base_confidence=0.6),
        # ── Contextual patterns (lowest priority) ──
        # 15. Name
        _PIIPattern(
            category="name", regex=_NAME_RE,
            contextual=True, base_confidence=0.5,
        ),
        # 16. Address
        _PIIPattern(
            category="address", regex=_ADDRESS_RE,
            contextual=True, base_confidence=0.5,
        ),
        # 17. Date of birth
        _PIIPattern(
            category="date_of_birth", regex=_DOB_RE,
            contextual=True, base_confidence=0.5,
        ),
    ]


_ALL_PATTERNS = _build_patterns()


# ───────────────────────────────────────────────────────────────
#  Detection engine
# ───────────────────────────────────────────────────────────────


def _extract_context(text: str, start: int, end: int) -> str:
    """Extract surrounding context for a match."""
    ctx_start = max(0, start - _CONTEXT_WINDOW)
    ctx_end = min(len(text), end + _CONTEXT_WINDOW)
    return text[ctx_start:ctx_end]


def detect(text: str, min_confidence: float = 0.0) -> list[PIIFinding]:
    """Detect PII in text using all registered patterns.

    Args:
        text: Text to scan for PII.
        min_confidence: Minimum confidence threshold (0.0-1.0).

    Returns:
        List of PIIFinding instances, sorted by position.
    """
    findings: list[PIIFinding] = []
    seen_ranges: set[tuple[int, int]] = set()

    for pattern in _ALL_PATTERNS:
        for match in pattern.regex.finditer(text):
            start, end = match.start(), match.end()

            # Dedup overlapping matches (symmetric — also catches full containment)
            if any(start < e and end > s for s, e in seen_ranges):
                continue

            matched_text = match.group(1) if match.lastindex else match.group(0)

            # Determine confidence
            if pattern.validator is not None:
                try:
                    valid = pattern.validator(matched_text)
                except (ValueError, IndexError):
                    valid = False
                if valid:
                    confidence = pattern.validated_confidence
                else:
                    continue  # Validator failed → skip
            elif pattern.contextual:
                confidence = pattern.base_confidence
            else:
                confidence = pattern.base_confidence

            if confidence < min_confidence:
                continue

            context = _extract_context(text, start, end)
            findings.append(PIIFinding(
                category=pattern.category,
                value=matched_text,
                start=start,
                end=end,
                confidence=confidence,
                context=context,
            ))
            seen_ranges.add((start, end))

    findings.sort(key=lambda f: f.start)
    return findings


def redact(text: str, min_confidence: float = 0.0) -> str:
    """Replace all detected PII with [CATEGORY] placeholders.

    Args:
        text: Text to redact.
        min_confidence: Minimum confidence threshold.

    Returns:
        Redacted text with PII replaced by [CATEGORY] tags.
    """
    findings = detect(text, min_confidence=min_confidence)
    if not findings:
        return text

    # Process from end to start to preserve offsets
    result = text
    for finding in reversed(findings):
        tag = f"[{finding.category.upper()}]"
        result = result[:finding.start] + tag + result[finding.end:]
    return result


def _determine_risk_level(findings: list[PIIFinding]) -> str:
    """Determine overall risk level from findings.

    Args:
        findings: List of PII findings.

    Returns:
        Risk level string: "none", "low", "medium", "high", "critical".
    """
    if not findings:
        return "none"
    levels = {_CATEGORY_RISK.get(f.category, "low") for f in findings}
    for level in _RISK_ORDER:
        if level in levels:
            return level
    return "low"


def _build_summary(findings: list[PIIFinding]) -> str:
    """Build human-readable summary of findings.

    Args:
        findings: List of PII findings.

    Returns:
        Summary string like "3 PII items found: 1 email, 1 SSN, 1 API key".
    """
    if not findings:
        return "No PII detected."
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.category] = counts.get(f.category, 0) + 1
    parts = [f"{c} {cat}" for cat, c in sorted(counts.items())]
    total = len(findings)
    return f"{total} PII item{'s' if total != 1 else ''} found: {', '.join(parts)}"


def scan_text(text: str, min_confidence: float = 0.0) -> PIIReport:
    """Full PII scan — detect, assess risk, redact, summarize.

    Args:
        text: Text to scan.
        min_confidence: Minimum confidence threshold.

    Returns:
        PIIReport with findings, risk level, redacted text, and summary.
    """
    findings = detect(text, min_confidence=min_confidence)
    categories = sorted({f.category for f in findings})
    risk_level = _determine_risk_level(findings)
    redacted_text = redact(text, min_confidence=min_confidence)
    summary = _build_summary(findings)

    return PIIReport(
        text_length=len(text),
        findings=findings,
        categories_found=categories,
        risk_level=risk_level,
        redacted_text=redacted_text,
        summary=summary,
    )


# ───────────────────────────────────────────────────────────────
#  Policy
# ───────────────────────────────────────────────────────────────

_DEFAULT_POLICY: dict[str, Any] = {
    "enabled": True,
    "mode": "warn",
    "min_confidence": 0.7,
    "log_findings": True,
    "categories": {
        "api_key": "block",
        "private_key": "block",
        "password": "block",
        "credit_card": "block",
        "personnummer": "block",
        "url_credentials": "block",
        "jwt": "block",
        "email": "warn",
        "phone": "warn",
        "ssn": "block",
        "iban": "warn",
        "ip_address": "warn",
        "passport": "warn",
        "name": "off",
        "address": "off",
        "date_of_birth": "off",
    },
}

VALID_MODES = frozenset({"block", "warn", "redact", "off"})


def load_pii_policy(project_dir: Path | None = None) -> dict[str, Any]:
    """Load PII policy from .codetrust/pii-policy.toml.

    Args:
        project_dir: Project root directory. Defaults to CWD.

    Returns:
        Policy dict with enabled, mode, min_confidence, categories.
    """
    root = project_dir or Path.cwd()
    policy_path = root / ".codetrust" / "pii-policy.toml"

    if not policy_path.is_file():
        return dict(_DEFAULT_POLICY)

    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return dict(_DEFAULT_POLICY)

    try:
        raw = tomllib.loads(policy_path.read_text(encoding="utf-8"))
        pii = raw.get("pii", {})
        policy = dict(_DEFAULT_POLICY)
        for key in ("enabled", "mode", "min_confidence", "log_findings"):
            if key in pii:
                policy[key] = pii[key]
        if "categories" in pii:
            policy["categories"] = {**policy["categories"], **pii["categories"]}
        return policy
    except (OSError, ValueError, KeyError):
        return dict(_DEFAULT_POLICY)


def get_finding_mode(
    finding: PIIFinding,
    policy: dict[str, Any],
) -> str:
    """Determine the effective mode for a specific finding.

    Per-category override takes precedence over global mode.

    Args:
        finding: The PII finding.
        policy: The loaded PII policy.

    Returns:
        Mode string: "block", "warn", "redact", or "off".
    """
    categories = policy.get("categories", {})
    cat_mode = categories.get(finding.category)
    if cat_mode and cat_mode in VALID_MODES:
        return cat_mode
    return policy.get("mode", "warn")


def apply_policy(
    report: PIIReport,
    policy: dict[str, Any],
) -> dict[str, Any]:
    """Apply policy to a PII report — determine actions per finding.

    Args:
        report: The PII scan report.
        policy: The loaded PII policy.

    Returns:
        Dict with action per finding, overall_action, and messages.
    """
    if not policy.get("enabled", True):
        return {"overall_action": "off", "finding_actions": [], "messages": []}

    min_conf = policy.get("min_confidence", 0.7)
    finding_actions: list[dict[str, str]] = []
    messages: list[str] = []
    has_block = False
    has_warn = False

    for finding in report.findings:
        if finding.confidence < min_conf:
            continue

        mode = get_finding_mode(finding, policy)
        if mode == "off":
            continue

        finding_actions.append({
            "category": finding.category,
            "value": finding.value[:20] + "..." if len(finding.value) > 20 else finding.value,
            "mode": mode,
            "confidence": str(finding.confidence),
        })

        if mode == "block":
            has_block = True
            messages.append(
                f"BLOCK: {finding.category} detected (confidence {finding.confidence:.0%})"
            )
        elif mode == "warn":
            has_warn = True
            messages.append(
                f"WARN: {finding.category} detected (confidence {finding.confidence:.0%})"
            )

    if has_block:
        overall = "block"
    elif has_warn:
        overall = "warn"
    else:
        overall = "allow"

    return {
        "overall_action": overall,
        "finding_actions": finding_actions,
        "messages": messages,
    }
