"""SQLAlchemy ORM models for users, API keys, and scan logs."""

import datetime
import uuid

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, func
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
