# Copyright (c) Said Borna. All rights reserved.
"""Multi-workspace governance registry — aggregated posture API.

Stores workspace registrations and computes aggregated governance
metrics across all registered workspaces. Each workspace reports
its posture via the register endpoint, and the aggregate endpoint
provides a bird's-eye view for organizational dashboards.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger()

WORKSPACE_STALE_SECONDS: float = 3600.0  # Consider workspace stale after 1 hour
DRIFT_GATE_COUNT: int = 7  # Number of governance gates checked for drift


@dataclass
class WorkspacePosture:
    """In-memory record of a workspace's governance posture."""

    workspace_id: str
    workspace_name: str
    agent_id: str = "unknown"
    enabled: bool = False
    mode: str = "audit"
    control_plane_ready: bool = False
    policy_hash: str = ""
    policy_verdict: str = "UNKNOWN"
    pending_approvals: int = 0
    active_exceptions: int = 0
    drift_count: int = 0
    last_seen_at: float = 0.0


@dataclass
class WorkspaceRegistry:
    """In-memory registry for multi-workspace governance aggregation.

    In production, this is backed by Redis or the database layer.
    For single-node deployments, in-memory is sufficient.
    """

    _workspaces: dict[str, WorkspacePosture] = field(default_factory=dict)

    def register(
        self,
        *,
        workspace_id: str,
        workspace_name: str,
        agent_id: str = "unknown",
        posture: dict[str, object] | None = None,
    ) -> WorkspacePosture:
        """Register or update a workspace's governance posture.

        Args:
            workspace_id: Unique identifier for the workspace.
            workspace_name: Human-readable name.
            agent_id: Agent reporting this posture.
            posture: Optional dict with posture fields to update.

        Returns:
            The updated WorkspacePosture record.
        """
        now = time.time()
        existing = self._workspaces.get(workspace_id)

        if existing is not None:
            record = existing
            record.workspace_name = workspace_name
            record.agent_id = agent_id
            record.last_seen_at = now
        else:
            record = WorkspacePosture(
                workspace_id=workspace_id,
                workspace_name=workspace_name,
                agent_id=agent_id,
                last_seen_at=now,
            )

        if posture:
            _apply_posture(record, posture)

        self._workspaces[workspace_id] = record
        logger.info(
            "workspace_registered",
            workspace_id=workspace_id,
            workspace_name=workspace_name,
            agent_id=agent_id,
        )
        return record

    def unregister(self, workspace_id: str) -> bool:
        """Remove a workspace from the registry.

        Args:
            workspace_id: The workspace to remove.

        Returns:
            True if found and removed, False otherwise.
        """
        removed = self._workspaces.pop(workspace_id, None)
        return removed is not None

    def get(self, workspace_id: str) -> WorkspacePosture | None:
        """Get a single workspace's posture.

        Args:
            workspace_id: The workspace to look up.

        Returns:
            WorkspacePosture if found, None otherwise.
        """
        return self._workspaces.get(workspace_id)

    def list_all(self) -> list[WorkspacePosture]:
        """List all registered workspaces.

        Returns:
            List of all WorkspacePosture records.
        """
        return list(self._workspaces.values())

    def aggregate(self) -> dict[str, object]:
        """Compute aggregated statistics across all workspaces.

        Returns:
            Dict with total_workspaces, healthy_count, drifted_count,
            disabled_count, and sum of pending/active items.
        """
        workspaces = self.list_all()
        total = len(workspaces)
        healthy = sum(1 for w in workspaces if w.enabled and w.drift_count == 0)
        drifted = sum(1 for w in workspaces if w.drift_count > 0)
        disabled = sum(1 for w in workspaces if not w.enabled)
        pending = sum(w.pending_approvals for w in workspaces)
        exceptions = sum(w.active_exceptions for w in workspaces)

        return {
            "total_workspaces": total,
            "healthy_count": healthy,
            "drifted_count": drifted,
            "disabled_count": disabled,
            "total_pending_approvals": pending,
            "total_active_exceptions": exceptions,
        }


def _apply_posture(record: WorkspacePosture, posture: dict[str, object]) -> None:
    """Apply posture dict fields to a WorkspacePosture record.

    Args:
        record: The workspace posture record to update.
        posture: Dict with optional posture fields.
    """
    if "enabled" in posture:
        record.enabled = bool(posture["enabled"])
    if "mode" in posture:
        record.mode = str(posture["mode"])
    if "control_plane_ready" in posture:
        record.control_plane_ready = bool(posture["control_plane_ready"])
    if "policy_hash" in posture:
        record.policy_hash = str(posture["policy_hash"])
    if "policy_verdict" in posture:
        record.policy_verdict = str(posture["policy_verdict"])
    if "pending_approvals" in posture:
        record.pending_approvals = int(posture["pending_approvals"])
    if "active_exceptions" in posture:
        record.active_exceptions = int(posture["active_exceptions"])
    if "drift_count" in posture:
        record.drift_count = int(posture["drift_count"])
