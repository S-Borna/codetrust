# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Policy integrity verification for gateway governance artifacts.

This module validates that policy files have not been tampered with by
comparing current SHA-256 hashes against a signed manifest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from pathlib import Path

POLICY_INTEGRITY_MANIFEST_REL: str = ".codetrust/policy-integrity.json"

POLICY_TARGET_FILES: tuple[str, ...] = (
    ".codetrust.toml",
    "CLAUDE.md",
    ".cursorrules",
    ".windsurfrules",
    ".cursor/rules/codetrust.mdc",
)


@dataclass(frozen=True)
class PolicyIntegrityResult:
    """Outcome of policy integrity verification."""

    verdict: str
    rule_id: str
    message: str
    suggestion: str
    metadata: dict[str, object]


def _sha256_file(path: Path) -> str:
    """Return SHA-256 hex digest for file content."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_payload(payload: dict[str, object]) -> str:
    """Return deterministic JSON payload string for signing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign_payload(payload: dict[str, object], sign_key: str) -> str:
    """Return HMAC-SHA256 signature for payload."""
    canonical = _canonical_payload(payload)
    return hmac.new(sign_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def _build_current_hashes(workspace: Path) -> dict[str, str]:
    """Build hash map for policy files that currently exist."""
    file_hashes: dict[str, str] = {}
    for rel_path in POLICY_TARGET_FILES:
        full_path = workspace / rel_path
        if full_path.is_file():
            file_hashes[rel_path] = _sha256_file(full_path)
    return file_hashes


def create_policy_integrity_manifest(
    workspace_path: str | Path,
    *,
    sign_key: str,
    version: str,
) -> dict[str, object]:
    """Create and persist signed policy integrity manifest in workspace."""
    workspace = Path(workspace_path)
    file_hashes = _build_current_hashes(workspace)
    payload: dict[str, object] = {
        "version": version,
        "issued_at": int(time.time()),
        "file_hashes": file_hashes,
    }
    signature = _sign_payload(payload, sign_key)
    manifest = {**payload, "signature": signature}

    manifest_path = workspace / POLICY_INTEGRITY_MANIFEST_REL
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")

    return manifest


def verify_policy_integrity(workspace_path: str | Path, *, sign_key: str) -> PolicyIntegrityResult:
    """Verify workspace policy files against signed integrity manifest."""
    workspace = Path(workspace_path)
    manifest_path = workspace / POLICY_INTEGRITY_MANIFEST_REL

    if not manifest_path.is_file():
        return PolicyIntegrityResult(
            verdict="WARN",
            rule_id="gateway_policy_integrity_missing",
            message="Policy integrity manifest is missing.",
            suggestion="Create a signed policy-integrity manifest before enforce-mode rollout.",
            metadata={"manifest_path": str(manifest_path)},
        )

    try:
        with open(manifest_path, encoding="utf-8") as f:
            manifest_raw = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        return PolicyIntegrityResult(
            verdict="BLOCK",
            rule_id="gateway_policy_integrity_invalid_manifest",
            message="Policy integrity manifest cannot be parsed.",
            suggestion="Regenerate the signed policy-integrity manifest.",
            metadata={"error": str(exc), "manifest_path": str(manifest_path)},
        )

    if not isinstance(manifest_raw, dict):
        return PolicyIntegrityResult(
            verdict="BLOCK",
            rule_id="gateway_policy_integrity_invalid_manifest",
            message="Policy integrity manifest has invalid format.",
            suggestion="Regenerate the signed policy-integrity manifest.",
            metadata={"manifest_path": str(manifest_path)},
        )

    signed_payload = {
        "version": manifest_raw.get("version", ""),
        "issued_at": manifest_raw.get("issued_at", 0),
        "file_hashes": manifest_raw.get("file_hashes", {}),
    }
    expected_signature = _sign_payload(signed_payload, sign_key)
    signature = str(manifest_raw.get("signature", ""))
    if not signature or not hmac.compare_digest(signature, expected_signature):
        return PolicyIntegrityResult(
            verdict="BLOCK",
            rule_id="gateway_policy_integrity_signature_mismatch",
            message="Policy integrity signature mismatch detected.",
            suggestion="Re-sign policy artifacts and verify signing key consistency.",
            metadata={"manifest_path": str(manifest_path)},
        )

    manifest_hashes = signed_payload["file_hashes"]
    if not isinstance(manifest_hashes, dict):
        return PolicyIntegrityResult(
            verdict="BLOCK",
            rule_id="gateway_policy_integrity_invalid_manifest",
            message="Policy integrity manifest file_hashes is invalid.",
            suggestion="Regenerate the signed policy-integrity manifest.",
            metadata={"manifest_path": str(manifest_path)},
        )

    current_hashes = _build_current_hashes(workspace)

    mismatches: list[dict[str, str]] = []
    for rel_path, expected_hash in manifest_hashes.items():
        rel = str(rel_path)
        current_hash = current_hashes.get(rel, "")
        if current_hash != str(expected_hash):
            mismatches.append(
                {
                    "path": rel,
                    "expected": str(expected_hash),
                    "actual": current_hash,
                },
            )

    if mismatches:
        return PolicyIntegrityResult(
            verdict="BLOCK",
            rule_id="gateway_policy_integrity_hash_mismatch",
            message="Policy file tampering detected (hash mismatch).",
            suggestion="Restore trusted policy files or regenerate signed manifest after approved changes.",
            metadata={"mismatches": mismatches, "manifest_path": str(manifest_path)},
        )

    return PolicyIntegrityResult(
        verdict="ALLOW",
        rule_id="gateway_policy_integrity_ok",
        message="Policy integrity verified.",
        suggestion="",
        metadata={
            "manifest_path": str(manifest_path),
            "tracked_files": sorted(current_hashes.keys()),
        },
    )
