# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Runtime license validation and enforcement.

Ensures CodeTrust installations are authorized. Validates license keys against
the cloud API on startup and periodically during runtime.

Design:
- Startup validation: blocks API/MCP server if license is invalid
- Periodic re-validation: every 12 hours (configurable)
- Offline grace period: 7 days without connectivity before lockout
- CLI: warns but does not block (allows offline scanning)
- Degraded mode: limited rule set without valid license
"""

from __future__ import annotations

import datetime
import hashlib
import json
import platform
import time
import uuid
from importlib.metadata import version as _pkg_version
from pathlib import Path
from typing import Literal

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field

logger = structlog.get_logger()

# --- Constants ---

def _get_client_version() -> str:
    """Get installed package version dynamically."""
    try:
        return _pkg_version("codetrust")
    except Exception:
        return "0.0.0"

LICENSE_VALIDATION_URL: str = "https://api.codetrust.ai/v1/license/validate"
LICENSE_CHECK_INTERVAL_SECONDS: int = 43_200  # 12 hours
LICENSE_OFFLINE_GRACE_DAYS: int = 7
LICENSE_CACHE_DIR: Path = Path.home() / ".codetrust"
LICENSE_CACHE_FILE: Path = LICENSE_CACHE_DIR / "license_cache.json"
LICENSE_TIMEOUT_SECONDS: float = 5.0
MACHINE_ID_FILE: Path = LICENSE_CACHE_DIR / "machine_id"

# Reduced rule set for unlicensed/expired installations
UNLICENSED_MAX_RULES: int = 15
UNLICENSED_MAX_GATEWAY_RULES: int = 5


class MachineFingerprint(BaseModel):
    """Hardware fingerprint for license binding (hashed, not raw)."""

    model_config = ConfigDict(strict=True)

    fingerprint_hash: str = Field(
        ..., min_length=64, max_length=64,
        description="SHA-256 hash of machine identifiers",
    )
    platform: str = Field(..., max_length=64)
    python_version: str = Field(..., max_length=20)


class LicenseStatus(BaseModel):
    """Cached license validation result."""

    model_config = ConfigDict(strict=True)

    valid: bool = False
    license_key: str = ""
    plan: Literal["free", "pro", "enterprise", "expired", "unknown"] = "unknown"
    machine_bound: bool = False
    validated_at: str = ""
    expires_at: str = ""
    features: list[str] = Field(default_factory=list)
    max_rules: int = UNLICENSED_MAX_RULES
    max_gateway_rules: int = UNLICENSED_MAX_GATEWAY_RULES
    offline_since: str = ""


def _generate_machine_id() -> str:
    """Generate or retrieve a stable machine identifier.

    Uses a locally stored UUID that persists across sessions.
    This is NOT tied to hardware — it's a stable installation identifier.
    """
    MACHINE_ID_FILE.parent.mkdir(parents=True, exist_ok=True)

    if MACHINE_ID_FILE.exists():
        stored_id = MACHINE_ID_FILE.read_text().strip()
        if len(stored_id) >= 32:
            return stored_id

    new_id = uuid.uuid4().hex + uuid.uuid4().hex
    MACHINE_ID_FILE.write_text(new_id)
    return new_id


def compute_fingerprint() -> MachineFingerprint:
    """Compute a hashed machine fingerprint for license binding."""
    machine_id = _generate_machine_id()
    raw_data = f"{machine_id}:{platform.node()}:{platform.machine()}"
    fingerprint_hash = hashlib.sha256(raw_data.encode()).hexdigest()

    return MachineFingerprint(
        fingerprint_hash=fingerprint_hash,
        platform=platform.system()[:64],
        python_version=platform.python_version()[:20],
    )


def _load_cached_status() -> LicenseStatus | None:
    """Load cached license status from disk."""
    try:
        if LICENSE_CACHE_FILE.exists():
            data = json.loads(LICENSE_CACHE_FILE.read_text())
            return LicenseStatus(**data)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.debug("license_cache_load_failed", error=str(exc))
    return None


def _save_cached_status(status: LicenseStatus) -> None:
    """Persist license status to disk for offline grace period."""
    try:
        LICENSE_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        LICENSE_CACHE_FILE.write_text(
            json.dumps(status.model_dump(), indent=2),
        )
    except OSError as exc:
        logger.debug("license_cache_save_failed", error=str(exc))


def _is_within_grace_period(status: LicenseStatus) -> bool:
    """Check if we're within the offline grace period."""
    if not status.offline_since:
        return True

    try:
        offline_start = datetime.datetime.fromisoformat(status.offline_since)
        grace_deadline = offline_start + datetime.timedelta(
            days=LICENSE_OFFLINE_GRACE_DAYS,
        )
        now = datetime.datetime.now(datetime.UTC)
        return now < grace_deadline
    except (ValueError, TypeError):
        return False


def _needs_revalidation(status: LicenseStatus) -> bool:
    """Check if the cached status needs re-validation."""
    if not status.validated_at:
        return True

    try:
        last_check = datetime.datetime.fromisoformat(status.validated_at)
        elapsed = (
            datetime.datetime.now(datetime.UTC) - last_check
        ).total_seconds()
        return elapsed > LICENSE_CHECK_INTERVAL_SECONDS
    except (ValueError, TypeError):
        return True


async def _validate_with_server(
    license_key: str,
    fingerprint: MachineFingerprint,
) -> LicenseStatus:
    """Validate license key against the cloud API."""
    now_iso = datetime.datetime.now(datetime.UTC).isoformat()

    try:
        async with httpx.AsyncClient(timeout=LICENSE_TIMEOUT_SECONDS) as client:
            response = await client.post(
                LICENSE_VALIDATION_URL,
                json={
                    "license_key": license_key,
                    "fingerprint": fingerprint.fingerprint_hash,
                    "platform": fingerprint.platform,
                    "python_version": fingerprint.python_version,
                    "client_version": _get_client_version(),
                },
                headers={"X-API-Key": license_key},
            )

            if response.status_code == 200:
                data = response.json()
                status = LicenseStatus(
                    valid=bool(data.get("valid", False)),
                    license_key=license_key[:8] + "...",
                    plan=data.get("plan", "unknown"),
                    machine_bound=bool(data.get("machine_bound", False)),
                    validated_at=now_iso,
                    expires_at=data.get("expires_at", ""),
                    features=data.get("features", []),
                    max_rules=data.get("max_rules", UNLICENSED_MAX_RULES),
                    max_gateway_rules=data.get(
                        "max_gateway_rules", UNLICENSED_MAX_GATEWAY_RULES,
                    ),
                    offline_since="",
                )
                _save_cached_status(status)
                logger.info(
                    "license_validated",
                    plan=status.plan,
                    valid=status.valid,
                )
                return status

            if response.status_code == 401:
                logger.warning("license_invalid", key_prefix=license_key[:8])
                return LicenseStatus(
                    valid=False,
                    license_key=license_key[:8] + "...",
                    plan="expired",
                    validated_at=now_iso,
                )

            logger.warning(
                "license_server_error",
                status_code=response.status_code,
            )

    except httpx.TimeoutException:
        logger.warning("license_server_timeout")
    except httpx.HTTPError as exc:
        logger.warning("license_server_unreachable", error=str(exc))

    # Server unreachable — check offline grace period
    return _handle_offline_validation(license_key)


def _handle_offline_validation(license_key: str) -> LicenseStatus:
    """Handle license validation when the server is unreachable."""
    cached = _load_cached_status()
    now_iso = datetime.datetime.now(datetime.UTC).isoformat()

    if cached and cached.valid:
        if not cached.offline_since:
            cached.offline_since = now_iso
            _save_cached_status(cached)

        if _is_within_grace_period(cached):
            logger.info(
                "license_offline_grace",
                days_remaining=LICENSE_OFFLINE_GRACE_DAYS,
            )
            return cached

        logger.warning("license_offline_grace_expired")
        return LicenseStatus(
            valid=False,
            license_key=license_key[:8] + "..." if license_key else "",
            plan="expired",
            validated_at=now_iso,
            offline_since=cached.offline_since,
        )

    return LicenseStatus(
        valid=False,
        license_key=license_key[:8] + "..." if license_key else "",
        plan="unknown",
        validated_at=now_iso,
    )


async def validate_license(license_key: str) -> LicenseStatus:
    """Main license validation entry point.

    Called at startup by API server, MCP server, and CLI.
    Returns LicenseStatus with validity, plan, and feature gates.
    """
    if not license_key:
        logger.info("license_not_configured")
        cached = _load_cached_status()
        if cached and cached.valid and not _needs_revalidation(cached):
            return cached
        return LicenseStatus(valid=False, plan="free")

    # Check cache first
    cached = _load_cached_status()
    if cached and cached.valid and not _needs_revalidation(cached):
        return cached

    # Validate with server
    fingerprint = compute_fingerprint()
    return await _validate_with_server(license_key, fingerprint)


def validate_license_sync(license_key: str) -> LicenseStatus:
    """Synchronous license check for CLI startup (non-async context).

    Uses cached status only — does not make network calls.
    CLI emits a warning if license is missing but does not block.
    """
    if not license_key:
        cached = _load_cached_status()
        if cached and cached.valid and _is_within_grace_period(cached):
            return cached
        return LicenseStatus(valid=False, plan="free")

    cached = _load_cached_status()
    if cached and cached.valid:
        if _needs_revalidation(cached):
            logger.info("license_revalidation_needed")
        return cached

    return LicenseStatus(valid=False, plan="unknown")


def enforce_rule_limit(
    rules: list[dict[str, object]],
    status: LicenseStatus,
) -> list[dict[str, object]]:
    """Enforce rule limits based on license status.

    Licensed: all rules available.
    Unlicensed/expired: limited to UNLICENSED_MAX_RULES rules.
    """
    if status.valid:
        return rules

    if len(rules) <= status.max_rules:
        return rules

    logger.warning(
        "rules_limited_by_license",
        total_rules=len(rules),
        allowed_rules=status.max_rules,
        plan=status.plan,
    )
    return rules[:status.max_rules]


def enforce_gateway_rule_limit(
    rules: list[dict[str, object]],
    status: LicenseStatus,
) -> list[dict[str, object]]:
    """Enforce gateway rule limits based on license status."""
    if status.valid:
        return rules

    if len(rules) <= status.max_gateway_rules:
        return rules

    logger.warning(
        "gateway_rules_limited_by_license",
        total_rules=len(rules),
        allowed_rules=status.max_gateway_rules,
        plan=status.plan,
    )
    return rules[:status.max_gateway_rules]


# --- Periodic re-validation background task ---

_last_check_time: float = 0.0


async def periodic_license_check(license_key: str) -> LicenseStatus | None:
    """Called periodically (e.g. from a background task) to re-validate.

    Returns new status only if re-validation was needed and performed.
    """
    global _last_check_time  # noqa: PLW0603

    now = time.time()
    if now - _last_check_time < LICENSE_CHECK_INTERVAL_SECONDS:
        return None

    _last_check_time = now
    fingerprint = compute_fingerprint()
    return await _validate_with_server(license_key, fingerprint)
