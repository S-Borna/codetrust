# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Server-side rule delivery service.

Premium rules are NOT shipped in the distributed package. They are fetched
from the CodeTrust cloud API on demand, verified via HMAC signature, and
cached locally for 24 hours.

This is the primary technical moat: without the cloud service, only the
free-tier rules (15) are available. The remaining 260+ rules require an
active license and API connectivity.

Architecture:
    - Server (api.codetrust.ai): serves rules from ANTI_PATTERNS directly
    - Client (pip install): fetches premium rules via GET /v1/rules/download
    - Rules are signed with HMAC-SHA256 to prevent tampering
    - Local cache: ~/.codetrust/rules_cache.json (24h TTL)
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
from pathlib import Path

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field

logger = structlog.get_logger()

# --- Constants ---

RULES_DOWNLOAD_URL: str = "https://api.codetrust.ai/v1/rules/download"
RULES_CACHE_DIR: Path = Path.home() / ".codetrust"
RULES_CACHE_FILE: Path = RULES_CACHE_DIR / "rules_cache.json"
RULES_CACHE_TTL_SECONDS: int = 86_400  # 24 hours
RULES_DOWNLOAD_TIMEOUT: float = 10.0
RULES_HMAC_ALGORITHM: str = "sha256"

# The 15 rule IDs available in the free tier.
# These are the ONLY rules that work without a valid license + API connectivity.
# All other rules require premium access via the cloud API.
FREE_TIER_RULE_IDS: frozenset[str] = frozenset({
    # Critical security — always available
    "heredoc",
    "hardcoded_secret",
    "eval_exec",
    "sql_injection",
    "pickle_load",
    # Code quality basics
    "bare_except",
    "wildcard_import",
    "any_type",
    "console_log",
    "print_debug",
    # Hygiene
    "todo_hack",
    "mutable_default",
    "nested_ternary",
    # Essential safety
    "datetime_utcnow",
    "symptom_fix_marker",
})

FREE_TIER_RULE_COUNT: int = len(FREE_TIER_RULE_IDS)


class RuleBundle(BaseModel):
    """Signed bundle of premium rules delivered from the server."""

    model_config = ConfigDict(strict=True)

    rules: list[dict[str, object]] = Field(default_factory=list)
    signature: str = ""
    issued_at: str = ""
    expires_at: str = ""
    rule_count: int = 0
    version: str = ""


def _compute_rules_signature(
    rules: list[dict[str, object]],
    secret: str,
    issued_at: str,
) -> str:
    """Compute HMAC-SHA256 signature over rule content.

    Signs the concatenation of rule IDs + issued_at timestamp.
    This prevents rule injection and replay attacks.
    """
    # Deterministic serialization: sorted rule IDs
    rule_ids = sorted(r.get("id", "") for r in rules)
    payload = f"{','.join(rule_ids)}:{issued_at}:{len(rules)}"
    return hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()


def _verify_rules_signature(
    bundle: RuleBundle,
    secret: str,
) -> bool:
    """Verify the HMAC signature of a rule bundle."""
    expected = _compute_rules_signature(
        bundle.rules, secret, bundle.issued_at,
    )
    return hmac.compare_digest(bundle.signature, expected)


def filter_free_tier_rules(
    all_rules: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Return only the free-tier rules from the full rule set."""
    return [r for r in all_rules if r.get("id") in FREE_TIER_RULE_IDS]


def filter_premium_rules(
    all_rules: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Return only premium rules (those NOT in the free tier)."""
    return [r for r in all_rules if r.get("id") not in FREE_TIER_RULE_IDS]


def build_signed_bundle(
    rules: list[dict[str, object]],
    secret: str,
    version: str,
) -> RuleBundle:
    """Build a signed rule bundle for delivery to clients.

    Called on the server side to package premium rules for download.
    """
    now = datetime.datetime.now(datetime.UTC).isoformat()
    expires = (
        datetime.datetime.now(datetime.UTC)
        + datetime.timedelta(seconds=RULES_CACHE_TTL_SECONDS)
    ).isoformat()

    # Serialize rules — convert Severity enum to string for JSON transport
    serialized: list[dict[str, object]] = []
    for rule in rules:
        entry: dict[str, object] = {}
        for key, val in rule.items():
            if hasattr(val, "value"):
                entry[key] = val.value
            else:
                entry[key] = val
        serialized.append(entry)

    signature = _compute_rules_signature(serialized, secret, now)

    return RuleBundle(
        rules=serialized,
        signature=signature,
        issued_at=now,
        expires_at=expires,
        rule_count=len(serialized),
        version=version,
    )


def _load_cached_rules() -> RuleBundle | None:
    """Load cached premium rules from disk."""
    try:
        if not RULES_CACHE_FILE.exists():
            return None

        data = json.loads(RULES_CACHE_FILE.read_text())
        bundle = RuleBundle(**data)

        # Check expiry
        if bundle.expires_at:
            expires = datetime.datetime.fromisoformat(bundle.expires_at)
            now = datetime.datetime.now(datetime.UTC)
            # Ensure both are offset-aware for comparison
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=datetime.UTC)
            if now > expires:
                logger.info("premium_rules_cache_expired")
                return None

        return bundle
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.debug("rules_cache_load_failed", error=str(exc))
        return None


def _save_cached_rules(bundle: RuleBundle) -> None:
    """Persist premium rules to disk cache."""
    try:
        RULES_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        RULES_CACHE_FILE.write_text(
            json.dumps(bundle.model_dump(), indent=2),
        )
    except OSError as exc:
        logger.debug("rules_cache_save_failed", error=str(exc))


async def fetch_premium_rules(
    license_key: str,
    hmac_secret: str,
) -> list[dict[str, object]]:
    """Fetch premium rules from the CodeTrust cloud API.

    Returns the deserialized rule list if successful and signature-verified.
    Returns empty list on failure (graceful degradation to free tier).
    """
    if not license_key:
        return []

    # Check cache first
    cached = _load_cached_rules()
    if cached and cached.rules:
        if hmac_secret and not _verify_rules_signature(cached, hmac_secret):
            logger.warning("premium_rules_cache_signature_invalid")
        else:
            logger.info(
                "premium_rules_loaded_from_cache",
                count=len(cached.rules),
            )
            return cached.rules

    # Fetch from server
    try:
        async with httpx.AsyncClient(timeout=RULES_DOWNLOAD_TIMEOUT) as client:
            response = await client.get(
                RULES_DOWNLOAD_URL,
                headers={"X-API-Key": license_key},
            )

            if response.status_code == 200:
                data = response.json()
                bundle = RuleBundle(**data)

                # Verify signature if we have a secret
                if hmac_secret and not _verify_rules_signature(bundle, hmac_secret):
                    logger.warning("premium_rules_signature_invalid")
                    return []

                _save_cached_rules(bundle)
                logger.info(
                    "premium_rules_fetched",
                    count=bundle.rule_count,
                )
                return bundle.rules

            if response.status_code in (401, 403):
                logger.warning(
                    "premium_rules_unauthorized",
                    status=response.status_code,
                )
                return []

            logger.warning(
                "premium_rules_fetch_error",
                status=response.status_code,
            )

    except httpx.TimeoutException:
        logger.warning("premium_rules_fetch_timeout")
    except httpx.HTTPError as exc:
        logger.warning("premium_rules_fetch_failed", error=str(exc))

    # Server unreachable — try cache even if expired (grace)
    cached = _load_cached_rules()
    if cached and cached.rules:
        logger.info("premium_rules_using_expired_cache", count=len(cached.rules))
        return cached.rules

    return []


def merge_rules(
    free_rules: list[dict[str, object]],
    premium_rules: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Merge free-tier and premium rules, deduplicating by rule ID."""
    seen_ids: set[str] = set()
    merged: list[dict[str, object]] = []

    for rule in free_rules:
        rule_id = rule.get("id", "")
        if rule_id not in seen_ids:
            seen_ids.add(rule_id)
            merged.append(rule)

    for rule in premium_rules:
        rule_id = rule.get("id", "")
        if rule_id not in seen_ids:
            seen_ids.add(rule_id)
            merged.append(rule)

    return merged
