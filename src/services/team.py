"""Team management and RBAC service.

Manages organizations, team memberships, and role-based access control.
Enforces org-level policies (license compliance, vulnerability gates).

This is a paid feature in Snyk Teams, SonarQube Enterprise, and Semgrep Teams —
CodeTrust provides it free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.models.database import Organization, TeamMember, User

logger = structlog.get_logger()


class TeamRole(str, Enum):
    """Supported team roles, ordered by privilege level."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


# Permissions by role (cumulative — each role inherits from roles below it).
ROLE_PERMISSIONS: dict[TeamRole, frozenset[str]] = {
    TeamRole.VIEWER: frozenset({
        "view_scans",
        "view_policies",
        "view_members",
    }),
    TeamRole.MEMBER: frozenset({
        "view_scans",
        "view_policies",
        "view_members",
        "run_scans",
        "create_api_keys",
    }),
    TeamRole.ADMIN: frozenset({
        "view_scans",
        "view_policies",
        "view_members",
        "run_scans",
        "create_api_keys",
        "manage_members",
        "edit_policies",
        "view_billing",
    }),
    TeamRole.OWNER: frozenset({
        "view_scans",
        "view_policies",
        "view_members",
        "run_scans",
        "create_api_keys",
        "manage_members",
        "edit_policies",
        "view_billing",
        "manage_billing",
        "delete_org",
        "transfer_ownership",
    }),
}


@dataclass(frozen=True)
class OrgInfo:
    """Organization information for API responses."""

    id: str
    name: str
    slug: str
    plan: str
    owner_id: str
    member_count: int
    created_at: str


@dataclass(frozen=True)
class MemberInfo:
    """Team member information for API responses."""

    id: str
    user_id: str
    email: str
    name: str
    role: str
    created_at: str


@dataclass(frozen=True)
class OrgPolicy:
    """Organization policy settings."""

    max_severity_allowed: str
    require_license_compliance: bool
    blocked_licenses: list[str]
    require_vuln_scan: bool
    max_critical_vulns: int
    max_high_vulns: int


@dataclass
class PolicyCheckResult:
    """Result of checking a scan against org policies."""

    passed: bool = True
    violations: list[str] = field(default_factory=list)


def _slugify(name: str) -> str:
    """Convert an organization name to a URL-safe slug."""
    import re
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    return slug.strip("-")[:100]


class TeamService:
    """Manages organizations, memberships, and RBAC.

    Follows the same async session pattern as DatabaseService.
    """

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        """Initialize with a SQLAlchemy async session factory."""
        self._session_factory = session_factory

    # --- Organization CRUD ---

    @staticmethod
    async def _persist_new_org(
        session: AsyncSession,
        name: str,
        slug: str,
        owner_id: str,
    ) -> OrgInfo:
        """Persist a new organization and its owner member record."""
        org = Organization(
            name=name.strip(),
            slug=slug,
            owner_id=owner_id,
        )
        session.add(org)
        await session.flush()

        member = TeamMember(
            organization_id=org.id,
            user_id=owner_id,
            role=TeamRole.OWNER.value,
            invited_by=owner_id,
        )
        session.add(member)
        await session.commit()

        logger.info("org_created", org_id=org.id, name=name, owner=owner_id)

        return OrgInfo(
            id=org.id,
            name=org.name,
            slug=org.slug,
            plan=org.plan,
            owner_id=org.owner_id,
            member_count=1,
            created_at=str(org.created_at),
        )

    async def create_org(
        self,
        name: str,
        owner_id: str,
    ) -> OrgInfo:
        """Create a new organization and add the creator as owner.

        Raises:
            ValueError: If name is empty or slug already exists.
        """
        if not name or not name.strip():
            raise ValueError("Organization name cannot be empty")

        slug = _slugify(name)
        if not slug:
            raise ValueError("Organization name produces an empty slug")

        async with self._session_factory() as session:
            existing = await session.execute(
                select(Organization).where(Organization.slug == slug)
            )
            if existing.scalar_one_or_none() is not None:
                raise ValueError(f"Organization slug '{slug}' already exists")

            return await self._persist_new_org(session, name, slug, owner_id)

    async def get_org(self, org_id: str) -> OrgInfo | None:
        """Get organization by ID."""
        async with self._session_factory() as session:
            org = await session.get(Organization, org_id)
            if org is None:
                return None

            # Count members.
            result = await session.execute(
                select(TeamMember).where(TeamMember.organization_id == org_id)
            )
            members = result.scalars().all()

            return OrgInfo(
                id=org.id,
                name=org.name,
                slug=org.slug,
                plan=org.plan,
                owner_id=org.owner_id,
                member_count=len(members),
                created_at=str(org.created_at),
            )

    async def get_org_by_slug(self, slug: str) -> OrgInfo | None:
        """Get organization by slug."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Organization).where(Organization.slug == slug)
            )
            org = result.scalar_one_or_none()
            if org is None:
                return None

            members_result = await session.execute(
                select(TeamMember).where(TeamMember.organization_id == org.id)
            )
            members = members_result.scalars().all()

            return OrgInfo(
                id=org.id,
                name=org.name,
                slug=org.slug,
                plan=org.plan,
                owner_id=org.owner_id,
                member_count=len(members),
                created_at=str(org.created_at),
            )

    async def list_user_orgs(self, user_id: str) -> list[OrgInfo]:
        """List all organizations a user belongs to."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(TeamMember).where(TeamMember.user_id == user_id)
            )
            memberships = result.scalars().all()

            orgs: list[OrgInfo] = []
            for membership in memberships:
                org = await session.get(Organization, membership.organization_id)
                if org is not None:
                    members_result = await session.execute(
                        select(TeamMember).where(
                            TeamMember.organization_id == org.id,
                        )
                    )
                    member_count = len(members_result.scalars().all())
                    orgs.append(OrgInfo(
                        id=org.id,
                        name=org.name,
                        slug=org.slug,
                        plan=org.plan,
                        owner_id=org.owner_id,
                        member_count=member_count,
                        created_at=str(org.created_at),
                    ))

            return orgs

    async def delete_org(self, org_id: str, requester_id: str) -> bool:
        """Delete an organization. Only the owner can delete.

        Args:
            org_id: Organization ID.
            requester_id: User ID of the requester.

        Returns:
            True if deleted, False if not found or not authorized.
        """
        async with self._session_factory() as session:
            org = await session.get(Organization, org_id)
            if org is None:
                return False
            if org.owner_id != requester_id:
                return False

            await session.delete(org)
            await session.commit()
            logger.info("org_deleted", org_id=org_id, by=requester_id)
            return True

    # --- Member Management ---

    @staticmethod
    async def _persist_new_member(
        session: AsyncSession,
        org_id: str,
        user_id: str,
        team_role: TeamRole,
        invited_by: str,
    ) -> MemberInfo | None:
        """Create and commit a new team member record."""
        user = await session.get(User, user_id)
        if user is None:
            return None

        member = TeamMember(
            organization_id=org_id,
            user_id=user_id,
            role=team_role.value,
            invited_by=invited_by,
        )
        session.add(member)
        await session.commit()

        logger.info("member_added", org_id=org_id, user_id=user_id, role=team_role.value)

        return MemberInfo(
            id=member.id,
            user_id=user_id,
            email=user.email,
            name=user.name,
            role=team_role.value,
            created_at=str(member.created_at),
        )

    async def add_member(
        self,
        org_id: str,
        user_id: str,
        role: str,
        invited_by: str,
    ) -> MemberInfo | None:
        """Add a user to an organization."""
        try:
            team_role = TeamRole(role)
        except ValueError:
            team_role = TeamRole.MEMBER

        async with self._session_factory() as session:
            result = await session.execute(
                select(TeamMember).where(
                    TeamMember.organization_id == org_id,
                    TeamMember.user_id == user_id,
                )
            )
            if result.scalar_one_or_none() is not None:
                return None

            return await self._persist_new_member(
                session, org_id, user_id, team_role, invited_by,
            )

    @staticmethod
    async def _delete_member_record(
        session: AsyncSession,
        org_id: str,
        user_id: str,
        requester_id: str,
    ) -> bool:
        """Delete a member record if found, preventing owner removal."""
        org = await session.get(Organization, org_id)
        if org is not None and org.owner_id == user_id:
            return False

        result = await session.execute(
            select(TeamMember).where(
                TeamMember.organization_id == org_id,
                TeamMember.user_id == user_id,
            )
        )
        member = result.scalar_one_or_none()
        if member is None:
            return False

        await session.delete(member)
        await session.commit()
        logger.info("member_removed", org_id=org_id, user_id=user_id, by=requester_id)
        return True

    async def remove_member(
        self,
        org_id: str,
        user_id: str,
        requester_id: str,
    ) -> bool:
        """Remove a user from an organization.

        Admin or owner can remove members. Owners cannot be removed.
        """
        requester_role = await self.get_user_role(org_id, requester_id)
        if requester_role not in (TeamRole.OWNER, TeamRole.ADMIN):
            return False

        async with self._session_factory() as session:
            return await self._delete_member_record(
                session, org_id, user_id, requester_id,
            )

    def _validate_role_change(
        self,
        requester_role: TeamRole | None,
        new_role: str,
    ) -> TeamRole | None:
        """Validate a role change request, returning the new TeamRole or None."""
        if requester_role not in (TeamRole.OWNER, TeamRole.ADMIN):
            return None
        try:
            team_role = TeamRole(new_role)
        except ValueError:
            return None
        if team_role in (TeamRole.ADMIN, TeamRole.OWNER) and requester_role != TeamRole.OWNER:
            return None
        return team_role

    async def update_member_role(
        self,
        org_id: str,
        user_id: str,
        new_role: str,
        requester_id: str,
    ) -> bool:
        """Update a member's role. Only admins/owners can do this."""
        requester_role = await self.get_user_role(org_id, requester_id)
        team_role = self._validate_role_change(requester_role, new_role)
        if team_role is None:
            return False

        async with self._session_factory() as session:
            result = await session.execute(
                select(TeamMember).where(
                    TeamMember.organization_id == org_id,
                    TeamMember.user_id == user_id,
                )
            )
            member = result.scalar_one_or_none()
            if member is None:
                return False

            member.role = team_role.value
            await session.commit()
            logger.info(
                "member_role_updated",
                org_id=org_id, user_id=user_id, new_role=new_role,
            )
            return True

    async def list_members(self, org_id: str) -> list[MemberInfo]:
        """List all members of an organization."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(TeamMember).where(TeamMember.organization_id == org_id)
            )
            members = result.scalars().all()

            infos: list[MemberInfo] = []
            for member in members:
                user = await session.get(User, member.user_id)
                infos.append(MemberInfo(
                    id=member.id,
                    user_id=member.user_id,
                    email=user.email if user else "",
                    name=user.name if user else "",
                    role=member.role,
                    created_at=str(member.created_at),
                ))

            return infos

    async def get_user_role(
        self, org_id: str, user_id: str,
    ) -> TeamRole | None:
        """Get a user's role in an organization.

        Returns:
            TeamRole if the user is a member, None otherwise.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(TeamMember).where(
                    TeamMember.organization_id == org_id,
                    TeamMember.user_id == user_id,
                )
            )
            member = result.scalar_one_or_none()
            if member is None:
                return None

            try:
                return TeamRole(member.role)
            except ValueError:
                return TeamRole.MEMBER

    def check_permission(
        self,
        role: TeamRole | None,
        permission: str,
    ) -> bool:
        """Check if a role has a specific permission.

        Args:
            role: The user's role (or None if not a member).
            permission: Permission string to check.

        Returns:
            True if the role has the permission.
        """
        if role is None:
            return False
        return permission in ROLE_PERMISSIONS.get(role, frozenset())

    # --- Policy Management ---

    async def get_org_policy(self, org_id: str) -> OrgPolicy | None:
        """Get the policy settings for an organization."""
        async with self._session_factory() as session:
            org = await session.get(Organization, org_id)
            if org is None:
                return None

            blocked = [
                s.strip() for s in org.blocked_licenses.split(",")
                if s.strip()
            ]

            return OrgPolicy(
                max_severity_allowed=org.max_severity_allowed,
                require_license_compliance=org.require_license_compliance,
                blocked_licenses=blocked,
                require_vuln_scan=org.require_vuln_scan,
                max_critical_vulns=org.max_critical_vulns,
                max_high_vulns=org.max_high_vulns,
            )

    @staticmethod
    def _apply_policy_fields(
        org: Organization,
        policy: dict[str, object],
    ) -> None:
        """Apply allowed policy field updates to an organization."""
        allowed_fields = {
            "max_severity_allowed",
            "require_license_compliance",
            "blocked_licenses",
            "require_vuln_scan",
            "max_critical_vulns",
            "max_high_vulns",
        }
        for key, value in policy.items():
            if key in allowed_fields:
                if key == "blocked_licenses" and isinstance(value, list):
                    value = ",".join(str(v) for v in value)
                setattr(org, key, value)

    async def update_org_policy(
        self,
        org_id: str,
        requester_id: str,
        policy: dict[str, object],
    ) -> bool:
        """Update organization policy settings.

        Only admins and owners can update policies.
        """
        role = await self.get_user_role(org_id, requester_id)
        if role not in (TeamRole.OWNER, TeamRole.ADMIN):
            return False

        async with self._session_factory() as session:
            org = await session.get(Organization, org_id)
            if org is None:
                return False

            self._apply_policy_fields(org, policy)
            await session.commit()
            logger.info("org_policy_updated", org_id=org_id, by=requester_id)
            return True

    @staticmethod
    def _check_severity_violation(
        policy: OrgPolicy,
        verdict: str,
    ) -> str | None:
        """Check if scan verdict exceeds policy maximum severity."""
        severity_order = {"INFO": 0, "WARN": 1, "BLOCK": 2}
        max_allowed = severity_order.get(policy.max_severity_allowed, 2)
        scan_severity = severity_order.get(verdict, 0)
        if scan_severity > max_allowed:
            return (
                f"Scan verdict '{verdict}' exceeds policy maximum "
                f"'{policy.max_severity_allowed}'"
            )
        return None

    @staticmethod
    def _check_vuln_violations(
        policy: OrgPolicy,
        critical_vulns: int,
        high_vulns: int,
    ) -> list[str]:
        """Check vulnerability counts against policy gates."""
        violations: list[str] = []
        if policy.max_critical_vulns > 0 and critical_vulns > policy.max_critical_vulns:
            violations.append(
                f"Found {critical_vulns} critical vulnerabilities "
                f"(maximum allowed: {policy.max_critical_vulns})"
            )
        if policy.max_high_vulns > 0 and high_vulns > policy.max_high_vulns:
            violations.append(
                f"Found {high_vulns} high vulnerabilities "
                f"(maximum allowed: {policy.max_high_vulns})"
            )
        return violations

    @staticmethod
    def _check_license_violations(
        policy: OrgPolicy,
        license_risks: list[str] | None,
    ) -> list[str]:
        """Check license risks against blocked licenses policy."""
        if not license_risks:
            return []
        violations: list[str] = []
        for risk in license_risks:
            for blocked in policy.blocked_licenses:
                if blocked.upper() in risk.upper():
                    violations.append(
                        f"License '{risk}' is blocked by organization policy"
                    )
        return violations

    def check_scan_against_policy(
        self,
        policy: OrgPolicy,
        verdict: str,
        critical_vulns: int = 0,
        high_vulns: int = 0,
        license_risks: list[str] | None = None,
    ) -> PolicyCheckResult:
        """Check if a scan result passes the organization's policies."""
        violations: list[str] = []

        severity_violation = self._check_severity_violation(policy, verdict)
        if severity_violation:
            violations.append(severity_violation)

        if policy.require_vuln_scan:
            violations.extend(
                self._check_vuln_violations(policy, critical_vulns, high_vulns)
            )

        if policy.require_license_compliance:
            violations.extend(
                self._check_license_violations(policy, license_risks)
            )

        return PolicyCheckResult(
            passed=len(violations) == 0,
            violations=violations,
        )
