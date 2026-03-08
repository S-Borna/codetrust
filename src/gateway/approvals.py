# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Approval requests and runtime exception lifecycle for governance."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from src.gateway.interceptor import ActionType, InterceptResult, Verdict

APPROVAL_DB_REL_PATH: str = ".codetrust/approvals.json"


def _to_float(value: object, default: float = 0.0) -> float:
    """Safely convert unknown JSON scalar to float."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default


def _parse_pending(item: dict[str, object]) -> PendingApproval:
    """Parse PendingApproval from raw JSON dict."""
    return PendingApproval(
        request_id=str(item.get("request_id", "")),
        rule_id=str(item.get("rule_id", "")),
        action_type=str(item.get("action_type", "")),
        original_action=str(item.get("original_action", "")),
        action_fingerprint=str(item.get("action_fingerprint", "")),
        requested_at=_to_float(item.get("requested_at", 0.0)),
        expires_at=_to_float(item.get("expires_at", 0.0)),
        session_id=str(item.get("session_id", "")),
        agent_id=str(item.get("agent_id", "")),
    )


def _parse_exception(item: dict[str, object]) -> GovernanceException:
    """Parse GovernanceException from raw JSON dict."""
    return GovernanceException(
        exception_id=str(item.get("exception_id", "")),
        rule_id=str(item.get("rule_id", "")),
        action_type=str(item.get("action_type", "")),
        action_fingerprint=str(item.get("action_fingerprint", "")),
        reason=str(item.get("reason", "")),
        approver=str(item.get("approver", "")),
        approver_role=str(item.get("approver_role", "owner")),
        created_at=_to_float(item.get("created_at", 0.0)),
        expires_at=_to_float(item.get("expires_at", 0.0)),
        revoked_at=_to_float(item.get("revoked_at", 0.0)),
        revoked_by=str(item.get("revoked_by", "")),
        session_id=str(item.get("session_id", "")),
        agent_id=str(item.get("agent_id", "")),
    )


@dataclass
class PendingApproval:
    """Pending user approval for a blocked governance action."""

    request_id: str
    rule_id: str
    action_type: str
    original_action: str
    action_fingerprint: str
    requested_at: float
    expires_at: float
    session_id: str
    agent_id: str


@dataclass
class GovernanceException:
    """Time-bound exception that can override a governance block."""

    exception_id: str
    rule_id: str
    action_type: str
    action_fingerprint: str
    reason: str
    approver: str
    approver_role: str
    created_at: float
    expires_at: float
    revoked_at: float = 0.0
    revoked_by: str = ""
    session_id: str = ""
    agent_id: str = ""


class ApprovalExceptionStore:
    """Persistent store for pending approvals and active exceptions."""

    def __init__(
        self,
        workspace_path: str,
        *,
        approval_ttl_minutes: int,
        exception_ttl_minutes: int,
    ) -> None:
        self._workspace = Path(workspace_path)
        self._db_path = self._workspace / APPROVAL_DB_REL_PATH
        self._approval_ttl_seconds = max(1, approval_ttl_minutes) * 60
        self._exception_ttl_seconds = max(1, exception_ttl_minutes) * 60

    def _read(self) -> dict[str, list[dict[str, object]]]:
        if not self._db_path.is_file():
            return {"pending": [], "exceptions": []}
        with open(self._db_path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"pending": [], "exceptions": []}
        pending = data.get("pending", [])
        exceptions = data.get("exceptions", [])
        return {
            "pending": pending if isinstance(pending, list) else [],
            "exceptions": exceptions if isinstance(exceptions, list) else [],
        }

    def _write(self, payload: dict[str, list[dict[str, object]]]) -> None:
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._db_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")

    @staticmethod
    def fingerprint(action_type: ActionType, original_action: str) -> str:
        """Build deterministic fingerprint for action matching."""
        payload = f"{action_type.value}:{original_action}".encode()
        return hashlib.sha256(payload).hexdigest()

    def _purge_expired(self, payload: dict[str, list[dict[str, object]]], now: float) -> None:
        payload["pending"] = [
            item for item in payload["pending"]
            if _to_float(item.get("expires_at", 0)) > now
        ]
        payload["exceptions"] = [
            item for item in payload["exceptions"]
            if _to_float(item.get("expires_at", 0)) > now and _to_float(item.get("revoked_at", 0)) <= 0
        ]

    def create_pending(
        self,
        result: InterceptResult,
        *,
        session_id: str,
        agent_id: str,
    ) -> PendingApproval:
        """Create a new pending approval request for an intercepted action."""
        now = time.time()
        payload = self._read()
        self._purge_expired(payload, now)

        pending = PendingApproval(
            request_id=f"apr_{uuid.uuid4().hex[:16]}",
            rule_id=result.rule_id,
            action_type=result.action_type.value,
            original_action=result.original_action,
            action_fingerprint=self.fingerprint(result.action_type, result.original_action),
            requested_at=now,
            expires_at=now + self._approval_ttl_seconds,
            session_id=session_id,
            agent_id=agent_id,
        )
        payload["pending"].append(asdict(pending))
        self._write(payload)
        return pending

    def approve(
        self,
        request_id: str,
        *,
        approver: str,
        approver_role: str,
        reason: str,
        ttl_minutes: int | None = None,
    ) -> GovernanceException | None:
        """Approve a pending request and create a time-bound exception."""
        now = time.time()
        payload = self._read()
        self._purge_expired(payload, now)

        pending_idx = -1
        pending_match: dict[str, object] | None = None
        for idx, item in enumerate(payload["pending"]):
            if str(item.get("request_id", "")) == request_id:
                pending_idx = idx
                pending_match = item
                break

        if pending_idx < 0 or pending_match is None:
            return None

        ttl_seconds = self._exception_ttl_seconds
        if ttl_minutes is not None:
            ttl_seconds = max(1, ttl_minutes) * 60

        created = GovernanceException(
            exception_id=f"gex_{uuid.uuid4().hex[:16]}",
            rule_id=str(pending_match.get("rule_id", "")),
            action_type=str(pending_match.get("action_type", "")),
            action_fingerprint=str(pending_match.get("action_fingerprint", "")),
            reason=reason,
            approver=approver,
            approver_role=approver_role,
            created_at=now,
            expires_at=now + ttl_seconds,
            session_id=str(pending_match.get("session_id", "")),
            agent_id=str(pending_match.get("agent_id", "")),
        )

        payload["pending"].pop(pending_idx)
        payload["exceptions"].append(asdict(created))
        self._write(payload)
        return created

    def revoke(self, exception_id: str, *, revoked_by: str) -> bool:
        """Revoke an existing exception by identifier."""
        now = time.time()
        payload = self._read()

        found = False
        for item in payload["exceptions"]:
            if str(item.get("exception_id", "")) == exception_id:
                item["revoked_at"] = now
                item["revoked_by"] = revoked_by
                found = True
                break

        if not found:
            return False

        self._write(payload)
        return True

    def list_pending(self) -> list[PendingApproval]:
        """Return non-expired pending approvals."""
        now = time.time()
        payload = self._read()
        self._purge_expired(payload, now)
        self._write(payload)
        return [_parse_pending(item) for item in payload["pending"]]

    def list_active_exceptions(self) -> list[GovernanceException]:
        """Return active exceptions only."""
        now = time.time()
        payload = self._read()
        self._purge_expired(payload, now)
        self._write(payload)
        return [_parse_exception(item) for item in payload["exceptions"]]

    def find_matching_exception(
        self,
        result: InterceptResult,
        *,
        session_id: str,
        agent_id: str,
    ) -> GovernanceException | None:
        """Find active exception that can override this blocked result."""
        fingerprint = self.fingerprint(result.action_type, result.original_action)
        for item in self.list_active_exceptions():
            if item.rule_id != result.rule_id:
                continue
            if item.action_type != result.action_type.value:
                continue
            if item.action_fingerprint != fingerprint:
                continue
            if item.session_id and item.session_id != session_id:
                continue
            if item.agent_id and item.agent_id != agent_id:
                continue
            return item
        return None


def apply_exception_override(
    result: InterceptResult,
    *,
    exception: GovernanceException,
) -> InterceptResult:
    """Return ALLOW result when an active exception applies."""
    result.verdict = Verdict.ALLOW
    result.message = "Action allowed via approved governance exception."
    result.suggestion = "Proceed with caution and track exception expiry."
    result.root_cause = ""
    result.safe_fix = ""
    result.metadata = {
        **result.metadata,
        "exception_id": exception.exception_id,
        "exception_reason": exception.reason,
        "exception_expires_at": exception.expires_at,
    }
    return result
