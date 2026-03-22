# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""SQLAlchemy ORM models for users, API keys, scan logs, telemetry, and teams."""

import datetime
import uuid

from sqlalchemy import JSON, BigInteger, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.ext.asyncio import AsyncAttrs
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _new_id() -> str:
    """Generate a new UUID4 string."""
    return uuid.uuid4().hex


class Base(AsyncAttrs, DeclarativeBase):
    """SQLAlchemy declarative base for CodeTrust models."""


class User(Base):
    """A registered CodeTrust user (via GitHub OAuth)."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    github_id: Mapped[str] = mapped_column(
        String(50), unique=True, index=True,
    )
    email: Mapped[str] = mapped_column(String(255), default="")
    name: Mapped[str] = mapped_column(String(255), default="")
    avatar_url: Mapped[str] = mapped_column(String(512), default="")
    plan: Mapped[str] = mapped_column(String(20), default="free")
    stripe_customer_id: Mapped[str] = mapped_column(String(255), default="")
    stripe_subscription_id: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
    )

    api_keys: Mapped[list["ApiKeyRecord"]] = relationship(
        back_populates="user", cascade="all, delete-orphan",
    )
    scan_logs: Mapped[list["ScanLog"]] = relationship(
        back_populates="user", cascade="all, delete-orphan",
    )


class ApiKeyRecord(Base):
    """A hashed API key belonging to a user."""

    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True,
    )
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    prefix: Mapped[str] = mapped_column(String(12), default="")
    name: Mapped[str] = mapped_column(String(100), default="Default")
    is_revoked: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    revoked_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None,
    )
    last_used_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None,
    )

    user: Mapped["User"] = relationship(back_populates="api_keys")
    scan_logs: Mapped[list["ScanLog"]] = relationship(
        back_populates="api_key", cascade="all, delete-orphan",
    )


class ScanLog(Base):
    """A record of a single scan execution for history and billing."""

    __tablename__ = "scan_logs"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True,
    )
    api_key_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("api_keys.id", ondelete="SET NULL"),
        nullable=True, default=None,
    )
    scan_type: Mapped[str] = mapped_column(String(30), index=True)
    verdict: Mapped[str] = mapped_column(String(10), default="PASS")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    language: Mapped[str] = mapped_column(String(20), default="")
    filename: Mapped[str] = mapped_column(String(500), default="")
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    input_size: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True,
    )

    user: Mapped["User"] = relationship(back_populates="scan_logs")
    api_key: Mapped["ApiKeyRecord | None"] = relationship(back_populates="scan_logs")


class UsageDay(Base):
    """Aggregated daily usage for rate limiting and analytics."""

    __tablename__ = "usage_days"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True,
    )
    date: Mapped[datetime.date] = mapped_column(index=True)
    scan_count: Mapped[int] = mapped_column(Integer, default=0)
    findings_total: Mapped[int] = mapped_column(Integer, default=0)
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)


class TelemetryEvent(Base):
    """Anonymous telemetry event used for public aggregate statistics.

    This table must never store user PII, code, filenames, repo URLs, or paths.
    All numeric fields are deltas that can be safely summed.
    """

    __tablename__ = "telemetry_events"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    instance_id: Mapped[str] = mapped_column(
        String(64), index=True,
    )
    client: Mapped[str] = mapped_column(
        String(20), index=True,
    )
    client_version: Mapped[str] = mapped_column(
        String(32), default="",
    )
    schema_version: Mapped[int] = mapped_column(
        Integer, default=1,
    )
    event_type: Mapped[str] = mapped_column(
        String(64), index=True,
    )

    scan_type: Mapped[str] = mapped_column(String(30), default="", index=True)
    verdict: Mapped[str] = mapped_column(String(10), default="", index=True)
    language: Mapped[str] = mapped_column(String(20), default="", index=True)

    delta_scans: Mapped[int] = mapped_column(Integer, default=0)
    delta_findings_total: Mapped[int] = mapped_column(Integer, default=0)
    delta_hallucinated_packages_prevented: Mapped[int] = mapped_column(Integer, default=0)
    delta_destructive_commands_blocked: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True,
    )


class TelemetryEventRaw(Base):
    """Raw anonymous telemetry event storage (JSON payload).

    This is the canonical event log used for offline analysis and auditing.
    """

    __tablename__ = "telemetry_events_raw"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    source: Mapped[str] = mapped_column(String(20), index=True)
    installation_id: Mapped[str] = mapped_column(String(128), index=True, default="")
    version: Mapped[str] = mapped_column(String(32), default="")
    payload: Mapped[dict[str, object]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True,
    )


class MetricsCounter(Base):
    """Pre-aggregated metrics for fast reads and durability."""

    __tablename__ = "metrics_counters"

    metric_name: Mapped[str] = mapped_column(String(100), primary_key=True)
    metric_value: Mapped[int] = mapped_column(BigInteger, default=0)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
    )


class CounterSnapshot(Base):
    """Point-in-time snapshot of Redis counters for durability fallback."""

    __tablename__ = "counter_snapshots"

    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[int] = mapped_column(BigInteger, default=0)
    snapshot_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), primary_key=True, index=True,
    )


# --- Team Management / RBAC ---


class Organization(Base):
    """An organization that groups users and enforces shared policies."""

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    plan: Mapped[str] = mapped_column(String(20), default="free")
    owner_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True,
    )

    # Policy fields — org-wide defaults.
    max_severity_allowed: Mapped[str] = mapped_column(
        String(10), default="BLOCK",
        comment="Max severity before scan fails: BLOCK, WARN, INFO",
    )
    require_license_compliance: Mapped[bool] = mapped_column(default=False)
    blocked_licenses: Mapped[str] = mapped_column(
        String(500), default="",
        comment="Comma-separated license patterns to block, e.g. AGPL,GPL",
    )
    require_vuln_scan: Mapped[bool] = mapped_column(default=False)
    max_critical_vulns: Mapped[int] = mapped_column(
        Integer, default=0,
        comment="Max critical vulns before scan fails (0 = no limit)",
    )
    max_high_vulns: Mapped[int] = mapped_column(
        Integer, default=0,
        comment="Max high vulns before scan fails (0 = no limit)",
    )

    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
    )

    members: Mapped[list["TeamMember"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan",
    )


class TeamMember(Base):
    """A user's membership in an organization with an assigned role."""

    __tablename__ = "team_members"

    id: Mapped[str] = mapped_column(
        String(32), primary_key=True, default=_new_id,
    )
    organization_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("organizations.id", ondelete="CASCADE"), index=True,
    )
    user_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("users.id", ondelete="CASCADE"), index=True,
    )
    role: Mapped[str] = mapped_column(
        String(20), default="member",
        comment="Role: owner, admin, member, viewer",
    )
    invited_by: Mapped[str] = mapped_column(String(32), default="")
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(),
    )

    organization: Mapped["Organization"] = relationship(back_populates="members")
