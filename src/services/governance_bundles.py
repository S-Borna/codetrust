# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Governance policy bundles and signed snapshot generation."""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import uuid

BUNDLE_IDS: tuple[str, ...] = ("startup", "team", "enterprise")
COVERAGE_MODEL_VERSION: str = "coverage-v1"


def _utc_now_iso() -> str:
    """Return UTC ISO-8601 timestamp with Z suffix."""
    return datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z")


def _sign_payload(payload: dict[str, object], secret: str) -> str:
    """Return deterministic HMAC-SHA256 signature for payload."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _base_policy() -> dict[str, object]:
    """Return base governance policy shared by all bundles."""
    return {
        "mode": "enforce",
        "block_heredoc": True,
        "block_eval": True,
        "block_curl_pipe_sh": True,
        "block_rm_rf": True,
        "block_git_push": True,
        "block_chmod_777": True,
        "verify_before_install": True,
        "block_suspicious_packages": True,
        "scan_before_write": True,
        "protected_paths": ["LICENSE", ".env", ".env.production"],
        "disabled_rules": [],
    }


def _build_policy_bundle(bundle_id: str) -> dict[str, object]:
    """Return tenant-aware policy for a specific bundle."""
    policy = _base_policy()
    if bundle_id == "startup":
        policy["mode"] = "audit"
        policy["block_git_push"] = False
        policy["block_sudo"] = False
        return policy
    if bundle_id == "team":
        policy["mode"] = "enforce"
        policy["block_sudo"] = False
        policy["retention_days"] = 90
        return policy
    policy["mode"] = "enforce"
    policy["block_sudo"] = True
    policy["retention_days"] = 365
    policy["require_signed_snapshots"] = True
    policy["require_webhook_on_block"] = True
    return policy


def _bundle_meta(bundle_id: str) -> tuple[str, str]:
    """Return name and target tier for the bundle."""
    if bundle_id == "startup":
        return "Startup Baseline", "startup"
    if bundle_id == "team":
        return "Team Guardrails", "team"
    return "Enterprise Zero-Trust", "enterprise"


def list_signed_bundles(secret: str, version: str) -> list[dict[str, object]]:
    """Return all policy bundles with signatures."""
    issued_at = _utc_now_iso()
    bundles: list[dict[str, object]] = []
    for bundle_id in BUNDLE_IDS:
        policy = _build_policy_bundle(bundle_id)
        name, target_tier = _bundle_meta(bundle_id)
        payload = {
            "bundle_id": bundle_id,
            "name": name,
            "target_tier": target_tier,
            "description": f"Recommended governance defaults for {target_tier} teams.",
            "policy": policy,
            "issued_at": issued_at,
            "version": version,
            "coverage_model": COVERAGE_MODEL_VERSION,
        }
        payload["signature"] = _sign_payload(payload, secret)
        bundles.append(payload)
    return bundles


def build_signed_snapshot(
    *,
    bundle_id: str,
    overrides: dict[str, object],
    secret: str,
    version: str,
) -> dict[str, object]:
    """Create a signed snapshot from a bundle and override map."""
    policy = _build_policy_bundle(bundle_id)
    for key, value in overrides.items():
        if key in policy:
            policy[key] = value

    issued_at = _utc_now_iso()
    snapshot = {
        "snapshot_id": f"gps_{uuid.uuid4().hex[:16]}",
        "bundle_id": bundle_id,
        "policy": policy,
        "issued_at": issued_at,
        "version": version,
        "coverage_model": COVERAGE_MODEL_VERSION,
    }
    snapshot["signature"] = _sign_payload(snapshot, secret)
    return snapshot
