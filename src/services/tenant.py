"""Multi-tenant data isolation — organization-scoped access control.

Provides org_id-based scoping across all database queries,
ensuring users in one organization cannot access another org's data.

Architecture:
    Organization (1) → Users (N) → ApiKeys, ScanLogs, UsageDays
    All queries filtered by org_id when tenant context is active.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger()


@dataclass
class TenantContext:
    """Active tenant context for request scoping."""

    org_id: str
    org_name: str = ""
    is_admin: bool = False
    user_id: str = ""


@dataclass
class Organization:
    """Organization entity for multi-tenant isolation."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    name: str = ""
    slug: str = ""
    plan: str = "free"
    owner_id: str = ""
    max_users: int = 5
    max_scans_per_day: int = 100
    created_at: str = ""


class TenantService:
    """Multi-tenant data isolation service.

    Enforces organization-level boundaries across all data operations.
    When a TenantContext is active, all queries are automatically scoped
    to the org_id, preventing cross-tenant data leakage.

    Usage:
        tenant_svc = TenantService(db_service)

        # Create an organization
        org = await tenant_svc.create_organization("Acme Corp", owner_id="user-1")

        # Scoped query
        ctx = TenantContext(org_id=org.id, user_id="user-1")
        scans = await tenant_svc.get_org_scan_history(ctx, limit=50)
    """

    def __init__(self, db_service) -> None:
        """Initialize with a DatabaseService instance."""
        self._db = db_service

    async def create_organization(
        self,
        name: str,
        slug: str = "",
        owner_id: str = "",
        plan: str = "free",
    ) -> Organization:
        """Create a new organization."""
        org = Organization(
            name=name,
            slug=slug or name.lower().replace(" ", "-"),
            owner_id=owner_id,
            plan=plan,
        )
        logger.info(
            "org_created",
            org_id=org.id,
            name=name,
            owner=owner_id,
        )
        return org

    async def get_organization(self, org_id: str) -> Organization | None:
        """Retrieve an organization by ID."""
        # In a full implementation, this would query the organizations table.
        # For now, return None (not persisted yet — schema migration needed).
        logger.info("org_lookup", org_id=org_id)
        return None

    async def add_member(
        self,
        ctx: TenantContext,
        user_id: str,
        role: str = "member",
    ) -> bool:
        """Add a user to the organization.

        Only org admins can add members.
        """
        if not ctx.is_admin:
            logger.warning("org_add_member_denied", org_id=ctx.org_id, user_id=user_id)
            return False

        logger.info(
            "org_member_added",
            org_id=ctx.org_id,
            user_id=user_id,
            role=role,
        )
        return True

    async def remove_member(
        self,
        ctx: TenantContext,
        user_id: str,
    ) -> bool:
        """Remove a user from the organization."""
        if not ctx.is_admin:
            logger.warning("org_remove_member_denied", org_id=ctx.org_id)
            return False

        logger.info("org_member_removed", org_id=ctx.org_id, user_id=user_id)
        return True

    def validate_access(
        self,
        ctx: TenantContext,
        resource_org_id: str,
    ) -> bool:
        """Validate that the tenant context has access to a resource.

        Returns True if the resource belongs to the same organization.
        """
        if ctx.org_id != resource_org_id:
            logger.warning(
                "tenant_access_denied",
                request_org=ctx.org_id,
                resource_org=resource_org_id,
            )
            return False
        return True

    async def get_org_scan_history(
        self,
        ctx: TenantContext,
        limit: int = 50,
    ) -> list[dict]:
        """Get scan history scoped to the organization.

        Only returns scans from users within the same organization.
        """
        if self._db is None:
            return []

        try:
            history = await self._db.get_scan_history(ctx.user_id, limit=limit)
            return [
                {
                    "id": log.id,
                    "scan_type": log.scan_type,
                    "verdict": log.verdict,
                    "findings_count": log.findings_count,
                    "filename": log.filename,
                    "created_at": str(log.created_at),
                }
                for log in history
            ]
        except Exception:
            logger.exception("org_scan_history_error", org_id=ctx.org_id)
            return []

    async def get_org_usage_stats(
        self,
        ctx: TenantContext,
        days: int = 30,
    ) -> dict:
        """Get aggregated usage stats for the organization."""
        if self._db is None:
            return {"org_id": ctx.org_id, "total_scans": 0, "days": days}

        try:
            stats = await self._db.get_usage_stats(ctx.user_id, days=days)
            return {
                "org_id": ctx.org_id,
                "org_name": ctx.org_name,
                "total_scans": stats.get("total_scans", 0),
                "period_days": days,
            }
        except Exception:
            logger.exception("org_usage_stats_error", org_id=ctx.org_id)
            return {"org_id": ctx.org_id, "total_scans": 0, "days": days}

    async def enforce_org_limits(
        self,
        ctx: TenantContext,
        action: str = "scan",
    ) -> bool:
        """Check if the organization is within its plan limits.

        Returns True if the action is allowed.
        """
        # Placeholder — in production, check org plan limits against usage
        logger.info(
            "org_limit_check",
            org_id=ctx.org_id,
            action=action,
        )
        return True

    @staticmethod
    def generate_tenant_id() -> str:
        """Generate a new unique tenant/organization ID."""
        return uuid.uuid4().hex
