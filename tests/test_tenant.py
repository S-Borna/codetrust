"""Tests for multi-tenant data isolation (TenantService).

Validates that:
- Organizations can be created and looked up
- Members can be added/removed with admin checks
- Cross-tenant access is denied
- Org-scoped queries are properly filtered
"""

from __future__ import annotations

import pytest

from src.services.tenant import Organization, TenantContext, TenantService


@pytest.fixture()
def tenant_svc() -> TenantService:
    """TenantService with no DB (unit testing mode)."""
    return TenantService(db_service=None)


@pytest.fixture()
def admin_ctx() -> TenantContext:
    return TenantContext(org_id="org-1", org_name="Acme Corp", is_admin=True, user_id="user-1")


@pytest.fixture()
def member_ctx() -> TenantContext:
    return TenantContext(org_id="org-1", org_name="Acme Corp", is_admin=False, user_id="user-2")


@pytest.fixture()
def other_org_ctx() -> TenantContext:
    return TenantContext(org_id="org-2", org_name="Other Corp", is_admin=True, user_id="user-3")


# ---------------------------------------------------------------------------
# Organization creation
# ---------------------------------------------------------------------------


class TestCreateOrganization:
    @pytest.mark.asyncio()
    async def test_create_org(self, tenant_svc: TenantService) -> None:
        org = await tenant_svc.create_organization("Acme Corp", owner_id="user-1")
        assert org.name == "Acme Corp"
        assert org.slug == "acme-corp"
        assert org.owner_id == "user-1"
        assert org.plan == "free"
        assert len(org.id) == 32

    @pytest.mark.asyncio()
    async def test_create_org_custom_slug(self, tenant_svc: TenantService) -> None:
        org = await tenant_svc.create_organization("My Org", slug="custom-slug")
        assert org.slug == "custom-slug"

    @pytest.mark.asyncio()
    async def test_create_org_enterprise_plan(self, tenant_svc: TenantService) -> None:
        org = await tenant_svc.create_organization("BigCo", plan="enterprise")
        assert org.plan == "enterprise"


# ---------------------------------------------------------------------------
# Member management
# ---------------------------------------------------------------------------


class TestMemberManagement:
    @pytest.mark.asyncio()
    async def test_admin_can_add_member(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        result = await tenant_svc.add_member(admin_ctx, "new-user", role="member")
        assert result is True

    @pytest.mark.asyncio()
    async def test_non_admin_cannot_add_member(
        self, tenant_svc: TenantService, member_ctx: TenantContext,
    ) -> None:
        result = await tenant_svc.add_member(member_ctx, "new-user")
        assert result is False

    @pytest.mark.asyncio()
    async def test_admin_can_remove_member(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        result = await tenant_svc.remove_member(admin_ctx, "user-2")
        assert result is True

    @pytest.mark.asyncio()
    async def test_non_admin_cannot_remove_member(
        self, tenant_svc: TenantService, member_ctx: TenantContext,
    ) -> None:
        result = await tenant_svc.remove_member(member_ctx, "user-3")
        assert result is False


# ---------------------------------------------------------------------------
# Cross-tenant access control
# ---------------------------------------------------------------------------


class TestAccessControl:
    def test_same_org_access_allowed(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        assert tenant_svc.validate_access(admin_ctx, "org-1") is True

    def test_cross_org_access_denied(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        assert tenant_svc.validate_access(admin_ctx, "org-2") is False

    def test_member_cross_org_denied(
        self, tenant_svc: TenantService, member_ctx: TenantContext,
    ) -> None:
        assert tenant_svc.validate_access(member_ctx, "org-2") is False


# ---------------------------------------------------------------------------
# Org-scoped queries
# ---------------------------------------------------------------------------


class TestOrgScopedQueries:
    @pytest.mark.asyncio()
    async def test_get_org_scan_history_no_db(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        result = await tenant_svc.get_org_scan_history(admin_ctx, limit=10)
        assert result == []

    @pytest.mark.asyncio()
    async def test_get_org_usage_stats_no_db(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        result = await tenant_svc.get_org_usage_stats(admin_ctx, days=7)
        assert result["org_id"] == "org-1"
        assert result["total_scans"] == 0

    @pytest.mark.asyncio()
    async def test_enforce_org_limits(
        self, tenant_svc: TenantService, admin_ctx: TenantContext,
    ) -> None:
        allowed = await tenant_svc.enforce_org_limits(admin_ctx, action="scan")
        assert allowed is True


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


class TestTenantUtilities:
    def test_generate_tenant_id(self) -> None:
        id1 = TenantService.generate_tenant_id()
        id2 = TenantService.generate_tenant_id()
        assert len(id1) == 32
        assert id1 != id2

    def test_organization_defaults(self) -> None:
        org = Organization()
        assert org.plan == "free"
        assert org.max_users == 5
        assert org.max_scans_per_day == 100

    def test_tenant_context(self) -> None:
        ctx = TenantContext(org_id="x", user_id="u")
        assert ctx.org_id == "x"
        assert ctx.is_admin is False

    @pytest.mark.asyncio()
    async def test_get_organization_returns_none(
        self, tenant_svc: TenantService,
    ) -> None:
        result = await tenant_svc.get_organization("nonexistent")
        assert result is None
