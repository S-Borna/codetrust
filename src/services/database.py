# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Async database service for users, API keys, scan logs, usage, and telemetry."""

import datetime
import hashlib
import os
import secrets
import smtplib
import threading
from email.mime.text import MIMEText

import structlog
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.models.database import (
    ApiKeyRecord,
    Base,
    CounterSnapshot,
    MetricsCounter,
    ScanLog,
    TelemetryEvent,
    TelemetryEventRaw,
    UsageDay,
    User,
)
from src.services.impact_categories import IMPACT_CATEGORIES, get_rule_category

logger = structlog.get_logger()

API_KEY_PREFIX = "ct_live_"
API_KEY_BYTES = 32

USAGE_SNAPSHOT_KEY_MAP: dict[str, str] = {
    "total_scans": "ct:total_scans",
    "total_findings": "ct:total_findings",
    "blocks_found": "ct:total_blocks",
    "total_files_scanned": "ct:files_scanned",
    "src_cli": "ct:scans_by_source:cli",
    "src_vscode": "ct:scans_by_source:vscode",
    "src_mcp": "ct:scans_by_source:mcp",
    "src_github_action": "ct:scans_by_source:github_action",
    "src_cloud_api": "ct:scans_by_source:cloud_api",
    "hallucinated_packages_prevented": "ct:hallucinations_caught",
    "destructive_commands_blocked": "ct:gateway_blocks",
    "gateway_commands_allowed": "ct:gateway_allowed",
    "gateway_commands_warned": "ct:gateway_warned",
    "imports_verified": "ct:imports_verified",
    "impact_destructive_commands": "ct:impact:destructive_commands",
    "impact_hallucinations": "ct:impact:hallucinations",
    "impact_secrets_exposure": "ct:impact:secrets_exposure",
    "impact_injection_attacks": "ct:impact:injection_attacks",
    "impact_unsafe_config": "ct:impact:unsafe_config",
    "impact_supply_chain": "ct:impact:supply_chain",
    "impact_other": "ct:impact:other",
}

DISTRIBUTION_SNAPSHOT_KEY_MAP: dict[str, str] = {
    "pypi_downloads_total": "ct:ext:pepy_total_downloads",
    "marketplace_installs": "ct:ext:marketplace_installs",
    "marketplace_downloads": "ct:ext:marketplace_downloads",
    "marketplace_updates": "ct:ext:marketplace_updates",
    "openvsx_downloads": "ct:ext:openvsx_downloads",
}


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash an API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _generate_api_key() -> str:
    """Generate a new random API key with prefix."""
    token = secrets.token_hex(API_KEY_BYTES)
    return f"{API_KEY_PREFIX}{token}"


def _payload_int(value: object, *, default: int = 0) -> int:
    """Safely convert payload values to integers."""
    if not isinstance(value, (int, float, str, bytes, bytearray, bool)):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _payload_rule_ids(payload: dict[str, object]) -> list[str]:
    """Extract rule IDs from a scan telemetry payload's findings list."""
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return []

    rule_ids: list[str] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        rule_id_obj = finding.get("rule") or finding.get("rule_id")
        if isinstance(rule_id_obj, str) and rule_id_obj:
            rule_ids.append(rule_id_obj)
    return rule_ids


def _is_on_or_after(ts: object, threshold: datetime.datetime) -> bool:
    """Return whether a timestamp is on/after threshold, normalizing naive UTC."""
    if not isinstance(ts, datetime.datetime):
        return False
    candidate = ts
    if candidate.tzinfo is None:
        candidate = candidate.replace(tzinfo=datetime.UTC)
    return candidate >= threshold


POOL_TIMEOUT_SECS: int = 30
DASHBOARD_SESSION_KEY_NAME = "Dashboard Web Session"


def _build_db_engine(database_url: str, echo: bool) -> AsyncEngine:
    """Create an async engine with pool timeout for production databases."""
    if "sqlite" in database_url:
        # SQLite/StaticPool: pool_timeout not supported
        return create_async_engine(
            database_url, echo=echo, pool_pre_ping=True,
        )
    return create_async_engine(
        database_url, echo=echo, pool_pre_ping=True,
        pool_timeout=POOL_TIMEOUT_SECS,
    )


def _notify_new_user(name: str, email: str, github_id: str) -> None:
    """Send email notification when a new user registers. Non-blocking."""
    def _send() -> None:
        recipient = os.environ.get("CODETRUST_FEEDBACK_RECIPIENT_EMAIL", "")
        host = os.environ.get("CODETRUST_FEEDBACK_SMTP_HOST", "")
        username = os.environ.get("CODETRUST_FEEDBACK_SMTP_USERNAME", "")
        password = os.environ.get("CODETRUST_FEEDBACK_SMTP_PASSWORD", "")
        from_email = os.environ.get("CODETRUST_FEEDBACK_SMTP_FROM_EMAIL", "") or recipient
        port = int(os.environ.get("CODETRUST_FEEDBACK_SMTP_PORT", "587"))

        if not all([recipient, host, username, password]):
            return

        subject = f"CodeTrust: New user — {name or email or github_id}"
        body = (
            f"New CodeTrust user registered.\n\n"
            f"Name: {name or '(not provided)'}\n"
            f"Email: {email or '(not provided)'}\n"
            f"GitHub ID: {github_id}\n"
            f"Plan: free\n"
        )

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = from_email
        msg["To"] = recipient

        try:
            with smtplib.SMTP(host=host, port=port, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(username, password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            logger.warning("new_user_email_failed", error=str(exc))

    threading.Thread(target=_send, daemon=True).start()


class DatabaseService:
    """Async CRUD operations for CodeTrust database."""

    def __init__(self, database_url: str, echo: bool = False) -> None:
        """Initialize with database URL. Includes pool_timeout for non-SQLite."""
        self._engine = _build_db_engine(database_url, echo)
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False,
        )

    async def create_tables(self) -> None:
        """Create all tables if they don't exist, then verify critical schemas match the ORM."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("database_tables_created")
        await self._verify_counter_snapshots_schema()

    async def _verify_counter_snapshots_schema(self) -> None:
        """Roundtrip an ORM INSERT/SELECT/DELETE against counter_snapshots.

        Guards against a legacy schema (id + counter_key column) that create_all
        silently leaves in place. A mismatch here must crash startup so snapshot
        writes aren't swallowed by the background worker.
        """
        probe_key = "ct:probe:schema_verify"
        async with self._session_factory() as session:
            try:
                session.add(CounterSnapshot(key=probe_key, value=0))
                await session.flush()
                await session.execute(
                    CounterSnapshot.__table__.delete().where(
                        CounterSnapshot.key == probe_key,
                    ),
                )
                await session.commit()
            except Exception as exc:
                await session.rollback()
                raise RuntimeError(
                    "counter_snapshots schema does not match ORM model. "
                    "Run `alembic upgrade head` before starting the API. "
                    f"Underlying error: {type(exc).__name__}: {exc}",
                ) from exc

    async def close(self) -> None:
        """Dispose of the engine connection pool."""
        await self._engine.dispose()
        logger.info("database_closed")

    # --- User operations ---

    async def create_user(
        self,
        github_id: str,
        email: str = "",
        name: str = "",
        avatar_url: str = "",
    ) -> User:
        """Create a new user from GitHub OAuth data."""
        async with self._session_factory() as session:
            user = User(
                github_id=github_id,
                email=email,
                name=name,
                avatar_url=avatar_url,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            logger.info("user_created", user_id=user.id, github_id=github_id)
            _notify_new_user(name=name, email=email, github_id=github_id)
            return user

    async def get_user(self, user_id: str) -> User | None:
        """Get a user by ID."""
        async with self._session_factory() as session:
            return await session.get(User, user_id)

    async def get_user_by_github_id(self, github_id: str) -> User | None:
        """Get a user by GitHub ID."""
        async with self._session_factory() as session:
            stmt = select(User).where(User.github_id == github_id)
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def get_user_by_stripe_customer_id(
        self, stripe_customer_id: str,
    ) -> User | None:
        """Get a user by their Stripe customer ID."""
        async with self._session_factory() as session:
            stmt = select(User).where(
                User.stripe_customer_id == stripe_customer_id,
            )
            result = await session.execute(stmt)
            return result.scalar_one_or_none()

    async def get_or_create_user(
        self,
        github_id: str,
        email: str = "",
        name: str = "",
        avatar_url: str = "",
    ) -> User:
        """Get existing user or create new one from GitHub OAuth data."""
        existing = await self.get_user_by_github_id(github_id)
        if existing is not None:
            return existing
        return await self.create_user(github_id, email, name, avatar_url)

    async def update_user_plan(
        self,
        user_id: str,
        plan: str,
        stripe_customer_id: str = "",
        stripe_subscription_id: str = "",
    ) -> User | None:
        """Update a user's plan and Stripe IDs."""
        async with self._session_factory() as session:
            user = await session.get(User, user_id)
            if user is None:
                return None
            user.plan = plan
            if stripe_customer_id:
                user.stripe_customer_id = stripe_customer_id
            if stripe_subscription_id:
                user.stripe_subscription_id = stripe_subscription_id
            await session.commit()
            await session.refresh(user)
            logger.info("user_plan_updated", user_id=user_id, plan=plan)
            return user

    # --- API Key operations ---

    async def create_api_key(
        self, user_id: str, name: str = "Default",
    ) -> tuple[str, ApiKeyRecord]:
        """Create a new API key. Returns (raw_key, record)."""
        raw_key = _generate_api_key()
        key_hash = _hash_key(raw_key)
        prefix = raw_key[:16]

        async with self._session_factory() as session:
            record = ApiKeyRecord(
                user_id=user_id,
                key_hash=key_hash,
                prefix=prefix,
                name=name,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("api_key_created", user_id=user_id, key_id=record.id)
            return raw_key, record

    async def list_api_keys(self, user_id: str) -> list[ApiKeyRecord]:
        """List all API keys for a user (active and revoked)."""
        async with self._session_factory() as session:
            stmt = (
                select(ApiKeyRecord)
                .where(ApiKeyRecord.user_id == user_id)
                .order_by(ApiKeyRecord.created_at.desc())
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def revoke_api_key(
        self, key_id: str, user_id: str,
    ) -> bool:
        """Revoke an API key. Returns True if found and revoked."""
        async with self._session_factory() as session:
            stmt = select(ApiKeyRecord).where(
                ApiKeyRecord.id == key_id,
                ApiKeyRecord.user_id == user_id,
            )
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()
            if record is None:
                return False
            record.is_revoked = True
            record.revoked_at = datetime.datetime.now(datetime.UTC)
            await session.commit()
            logger.info("api_key_revoked", key_id=key_id, user_id=user_id)
            return True

    async def verify_api_key_hash(
        self, raw_key: str,
    ) -> ApiKeyRecord | None:
        """Look up an API key by its hash. Returns None if not found or revoked."""
        key_hash = _hash_key(raw_key)
        async with self._session_factory() as session:
            stmt = select(ApiKeyRecord).where(
                ApiKeyRecord.key_hash == key_hash,
                ApiKeyRecord.is_revoked.is_(False),
            )
            result = await session.execute(stmt)
            record = result.scalar_one_or_none()
            if record is not None:
                record.last_used_at = datetime.datetime.now(datetime.UTC)
                await session.commit()
            return record

    async def rotate_dashboard_api_key(
        self, user_id: str,
    ) -> tuple[str, ApiKeyRecord]:
        """Rotate a dashboard-scoped API key and return a fresh raw key."""
        raw_key = _generate_api_key()
        key_hash = _hash_key(raw_key)
        prefix = raw_key[:16]
        now = datetime.datetime.now(datetime.UTC)

        async with self._session_factory() as session:
            stmt = select(ApiKeyRecord).where(
                ApiKeyRecord.user_id == user_id,
                ApiKeyRecord.name == DASHBOARD_SESSION_KEY_NAME,
                ApiKeyRecord.is_revoked.is_(False),
            )
            rows = await session.execute(stmt)
            for existing in rows.scalars().all():
                existing.is_revoked = True
                existing.revoked_at = now

            record = ApiKeyRecord(
                user_id=user_id,
                key_hash=key_hash,
                prefix=prefix,
                name=DASHBOARD_SESSION_KEY_NAME,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            logger.info("dashboard_api_key_rotated", user_id=user_id, key_id=record.id)
            return raw_key, record

    async def get_adoption_overview(self) -> dict[str, int]:
        """Return aggregate adoption metrics for admin dashboards."""
        now = datetime.datetime.now(datetime.UTC)
        since = now - datetime.timedelta(days=30)

        async with self._session_factory() as session:
            total_users = int((await session.execute(select(func.count()).select_from(User))).scalar() or 0)

            plan_rows = await session.execute(
                select(User.plan, func.count()).group_by(User.plan),
            )
            plan_counts = {str(plan): int(count) for plan, count in plan_rows.all()}

            total_api_keys = int(
                (await session.execute(select(func.count()).select_from(ApiKeyRecord))).scalar() or 0,
            )
            active_api_keys = int(
                (
                    await session.execute(
                        select(func.count()).select_from(ApiKeyRecord).where(
                            ApiKeyRecord.is_revoked.is_(False),
                        ),
                    )
                ).scalar()
                or 0
            )
            active_users_30d = int(
                (
                    await session.execute(
                        select(func.count(func.distinct(ScanLog.user_id))).where(
                            ScanLog.created_at >= since,
                        ),
                    )
                ).scalar()
                or 0
            )
            total_scans_30d = int(
                (
                    await session.execute(
                        select(func.count()).select_from(ScanLog).where(
                            ScanLog.created_at >= since,
                        ),
                    )
                ).scalar()
                or 0
            )

            return {
                "total_users": total_users,
                "free_users": plan_counts.get("free", 0),
                "pro_users": plan_counts.get("pro", 0),
                "enterprise_users": plan_counts.get("enterprise", 0),
                "total_api_keys": total_api_keys,
                "active_api_keys": active_api_keys,
                "active_users_30d": active_users_30d,
                "total_scans_30d": total_scans_30d,
            }

    # --- Scan Log operations ---

    async def log_scan(
        self,
        user_id: str,
        scan_type: str,
        verdict: str,
        findings_count: int,
        latency_ms: int,
        language: str = "",
        filename: str = "",
        input_size: int = 0,
        api_key_id: str | None = None,
    ) -> ScanLog:
        """Record a scan execution."""
        async with self._session_factory() as session:
            log = ScanLog(
                user_id=user_id,
                api_key_id=api_key_id,
                scan_type=scan_type,
                verdict=verdict,
                findings_count=findings_count,
                latency_ms=latency_ms,
                language=language,
                filename=filename,
                input_size=input_size,
            )
            session.add(log)
            await session.commit()
            await session.refresh(log)
            return log

    async def get_scan_history(
        self,
        user_id: str,
        page: int = 1,
        per_page: int = 20,
        scan_type: str | None = None,
    ) -> list[ScanLog]:
        """Get paginated scan history for a user."""
        async with self._session_factory() as session:
            stmt = (
                select(ScanLog)
                .where(ScanLog.user_id == user_id)
                .order_by(ScanLog.created_at.desc())
            )
            if scan_type is not None:
                stmt = stmt.where(ScanLog.scan_type == scan_type)
            stmt = stmt.offset((page - 1) * per_page).limit(per_page)
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def count_scans(
        self, user_id: str, scan_type: str | None = None,
    ) -> int:
        """Count total scans for a user."""
        async with self._session_factory() as session:
            stmt = select(func.count()).select_from(ScanLog).where(
                ScanLog.user_id == user_id,
            )
            if scan_type is not None:
                stmt = stmt.where(ScanLog.scan_type == scan_type)
            result = await session.execute(stmt)
            return result.scalar_one()

    # --- Usage tracking ---

    async def increment_daily_usage(
        self,
        user_id: str,
        findings_count: int = 0,
        latency_ms: int = 0,
    ) -> UsageDay:
        """Increment today's usage counter for a user."""
        today = datetime.date.today()
        async with self._session_factory() as session:
            stmt = select(UsageDay).where(
                UsageDay.user_id == user_id,
                UsageDay.date == today,
            )
            result = await session.execute(stmt)
            usage = result.scalar_one_or_none()

            if usage is None:
                usage = UsageDay(
                    user_id=user_id,
                    date=today,
                    scan_count=1,
                    findings_total=findings_count,
                    avg_latency_ms=float(latency_ms),
                )
                session.add(usage)
            else:
                old_total = usage.avg_latency_ms * usage.scan_count
                usage.scan_count += 1
                usage.findings_total += findings_count
                usage.avg_latency_ms = (
                    (old_total + latency_ms) / usage.scan_count
                )

            await session.commit()
            await session.refresh(usage)
            return usage

    async def get_daily_usage(
        self, user_id: str, date: datetime.date | None = None,
    ) -> int:
        """Get scan count for a specific day (default: today)."""
        target = date or datetime.date.today()
        async with self._session_factory() as session:
            stmt = select(UsageDay).where(
                UsageDay.user_id == user_id,
                UsageDay.date == target,
            )
            result = await session.execute(stmt)
            usage = result.scalar_one_or_none()
            return usage.scan_count if usage is not None else 0

    async def get_usage_stats(
        self, user_id: str, days: int = 30,
    ) -> list[UsageDay]:
        """Get usage stats for the last N days."""
        since = datetime.date.today() - datetime.timedelta(days=days)
        async with self._session_factory() as session:
            stmt = (
                select(UsageDay)
                .where(
                    UsageDay.user_id == user_id,
                    UsageDay.date >= since,
                )
                .order_by(UsageDay.date.desc())
            )
            result = await session.execute(stmt)
            return list(result.scalars().all())

    async def get_public_stats(self) -> dict[str, int]:
        """Get aggregate public stats across all users (no auth required)."""
        async with self._session_factory() as session:
            # Total scans
            total_scans_stmt = select(func.count()).select_from(ScanLog)
            total_scans = (await session.execute(total_scans_stmt)).scalar_one()

            # Hallucinated packages prevented (imports scans with BLOCK verdict)
            hallucinated_stmt = (
                select(func.count())
                .select_from(ScanLog)
                .where(ScanLog.scan_type == "imports", ScanLog.verdict == "BLOCK")
            )
            hallucinated = (await session.execute(hallucinated_stmt)).scalar_one()

            # Destructive commands blocked (gateway blocks from audit)
            # Count all scans with BLOCK verdict across gateway-related types
            blocked_stmt = (
                select(func.count())
                .select_from(ScanLog)
                .where(
                    ScanLog.verdict == "BLOCK",
                    ScanLog.scan_type.notin_(["imports", "dockerfile"]),
                )
            )
            blocked = (await session.execute(blocked_stmt)).scalar_one()

            return {
                "total_scans": total_scans or 0,
                "hallucinated_packages_prevented": hallucinated or 0,
                "destructive_commands_blocked": blocked or 0,
            }

    async def get_public_usage_aggregates(self) -> dict[str, int]:
        """Return usage aggregates for public stats fallback when Redis is unavailable."""
        now_utc = datetime.datetime.now(datetime.UTC)
        today_start = datetime.datetime.combine(now_utc.date(), datetime.time.min, tzinfo=datetime.UTC)
        last_hour = now_utc - datetime.timedelta(hours=1)

        async with self._session_factory() as session:
            scanlog_total = int((await session.execute(select(func.count()).select_from(ScanLog))).scalar_one() or 0)
            raw_rows = (
                await session.execute(
                    select(
                        TelemetryEventRaw.payload,
                        TelemetryEventRaw.source,
                        TelemetryEventRaw.installation_id,
                        TelemetryEventRaw.created_at,
                    ).where(TelemetryEventRaw.event_type == "scan_completed")
                )
            ).all()
            raw_scan_total = len(raw_rows)
            total_scans = max(scanlog_total, raw_scan_total)
            scanlog_findings = int(
                (
                    await session.execute(
                        select(func.coalesce(func.sum(ScanLog.findings_count), 0)).select_from(ScanLog)
                    )
                ).scalar_one()
                or 0
            )
            scanlog_today = int(
                (
                    await session.execute(
                        select(func.count()).select_from(ScanLog).where(ScanLog.created_at >= today_start)
                    )
                ).scalar_one()
                or 0
            )
            scanlog_last_hour = int(
                (
                    await session.execute(
                        select(func.count()).select_from(ScanLog).where(ScanLog.created_at >= last_hour)
                    )
                ).scalar_one()
                or 0
            )
            scanlog_blocks = int(
                (
                    await session.execute(
                        select(func.count()).select_from(ScanLog).where(ScanLog.verdict == "BLOCK")
                    )
                ).scalar_one()
                or 0
            )
            raw_findings = 0
            raw_blocks = 0
            raw_files_scanned = 0
            raw_hallucinations = 0
            impact_counts: dict[str, int] = {category: 0 for category in IMPACT_CATEGORIES}
            raw_today = 0
            raw_last_hour = 0
            by_source: dict[str, int] = {"cli": 0, "vscode": 0, "mcp": 0, "github_action": 0, "cloud_api": 0}
            unique_ids: set[str] = set()
            unique_today_ids: set[str] = set()

            for payload, source, installation_id, created_at in raw_rows:
                payload_obj = payload if isinstance(payload, dict) else {}
                raw_findings += _payload_int(payload_obj.get("total_findings"))
                raw_blocks += _payload_int(
                    (payload_obj.get("findings_by_severity") or {}).get("BLOCK"),
                )
                raw_files_scanned += _payload_int(payload_obj.get("files_scanned"), default=1)
                raw_hallucinations += _payload_int(payload_obj.get("hallucinations_found"))

                for rule_id in _payload_rule_ids(payload_obj):
                    category = get_rule_category(rule_id)
                    impact_counts[category] = impact_counts.get(category, 0) + 1

                source_key = str(source or "")
                if source_key in by_source:
                    by_source[source_key] += 1

                if _is_on_or_after(created_at, today_start):
                    raw_today += 1
                if _is_on_or_after(created_at, last_hour):
                    raw_last_hour += 1

                installation = str(installation_id or "").strip()
                if installation:
                    unique_ids.add(installation)
                    if _is_on_or_after(created_at, today_start):
                        unique_today_ids.add(installation)

            total_findings = max(scanlog_findings, raw_findings)
            blocks_found = max(scanlog_blocks, raw_blocks)
            scans_today = max(scanlog_today, raw_today)
            scans_last_hour = max(scanlog_last_hour, raw_last_hour)
            total_files_scanned = max(total_scans, raw_files_scanned)
            hallucinations_caught = raw_hallucinations
            unique_total = len(unique_ids)
            unique_today = len(unique_today_ids)

            gateway_rows = (
                await session.execute(
                    select(TelemetryEventRaw.payload).where(
                        TelemetryEventRaw.event_type == "gateway_check",
                    )
                )
            ).all()
            gateway_blocks = 0
            gateway_allowed = 0
            gateway_warned = 0
            for (payload,) in gateway_rows:
                payload_obj = payload if isinstance(payload, dict) else {}
                action = str(payload_obj.get("action", "")).upper()
                if action == "BLOCKED":
                    gateway_blocks += 1
                elif action == "ALLOWED":
                    gateway_allowed += 1
                elif action == "WARNED":
                    gateway_warned += 1

            import_rows = (
                await session.execute(
                    select(TelemetryEventRaw.payload).where(
                        TelemetryEventRaw.event_type == "import_verified",
                    )
                )
            ).all()
            imports_verified = 0
            for (payload,) in import_rows:
                payload_obj = payload if isinstance(payload, dict) else {}
                imports_verified += _payload_int(payload_obj.get("total_imports_checked"))
                hallucinations_caught += _payload_int(payload_obj.get("hallucinations_caught"))

            snapshot_values = await self.get_latest_counter_snapshots(
                tuple(set(USAGE_SNAPSHOT_KEY_MAP.values()) | set(DISTRIBUTION_SNAPSHOT_KEY_MAP.values())),
            )
            total_scans = max(total_scans, _payload_int(snapshot_values.get("ct:total_scans")))
            total_findings = max(total_findings, _payload_int(snapshot_values.get("ct:total_findings")))
            blocks_found = max(blocks_found, _payload_int(snapshot_values.get("ct:total_blocks")))
            total_files_scanned = max(total_files_scanned, _payload_int(snapshot_values.get("ct:files_scanned")))

            by_source["cli"] = max(by_source["cli"], _payload_int(snapshot_values.get("ct:scans_by_source:cli")))
            by_source["vscode"] = max(by_source["vscode"], _payload_int(snapshot_values.get("ct:scans_by_source:vscode")))
            by_source["mcp"] = max(by_source["mcp"], _payload_int(snapshot_values.get("ct:scans_by_source:mcp")))
            by_source["github_action"] = max(
                by_source["github_action"],
                _payload_int(snapshot_values.get("ct:scans_by_source:github_action")),
            )
            by_source["cloud_api"] = max(
                by_source["cloud_api"],
                _payload_int(snapshot_values.get("ct:scans_by_source:cloud_api")),
            )
            hallucinations_caught = max(
                hallucinations_caught,
                _payload_int(snapshot_values.get("ct:hallucinations_caught")),
            )
            gateway_blocks = max(gateway_blocks, _payload_int(snapshot_values.get("ct:gateway_blocks")))
            gateway_allowed = max(gateway_allowed, _payload_int(snapshot_values.get("ct:gateway_allowed")))
            gateway_warned = max(gateway_warned, _payload_int(snapshot_values.get("ct:gateway_warned")))
            imports_verified = max(imports_verified, _payload_int(snapshot_values.get("ct:imports_verified")))

            impact_counts["destructive_commands"] = max(
                impact_counts["destructive_commands"],
                _payload_int(snapshot_values.get("ct:impact:destructive_commands")),
            )
            impact_counts["hallucinations"] = max(
                impact_counts["hallucinations"],
                _payload_int(snapshot_values.get("ct:impact:hallucinations")),
            )
            impact_counts["secrets_exposure"] = max(
                impact_counts["secrets_exposure"],
                _payload_int(snapshot_values.get("ct:impact:secrets_exposure")),
            )
            impact_counts["injection_attacks"] = max(
                impact_counts["injection_attacks"],
                _payload_int(snapshot_values.get("ct:impact:injection_attacks")),
            )
            impact_counts["unsafe_config"] = max(
                impact_counts["unsafe_config"],
                _payload_int(snapshot_values.get("ct:impact:unsafe_config")),
            )
            impact_counts["supply_chain"] = max(
                impact_counts["supply_chain"],
                _payload_int(snapshot_values.get("ct:impact:supply_chain")),
            )
            impact_counts["other"] = max(
                impact_counts["other"],
                _payload_int(snapshot_values.get("ct:impact:other")),
            )

            pypi_downloads_total = _payload_int(snapshot_values.get("ct:ext:pepy_total_downloads"))
            marketplace_installs = _payload_int(snapshot_values.get("ct:ext:marketplace_installs"))
            marketplace_downloads = _payload_int(snapshot_values.get("ct:ext:marketplace_downloads"))
            marketplace_updates = _payload_int(snapshot_values.get("ct:ext:marketplace_updates"))
            openvsx_downloads = _payload_int(snapshot_values.get("ct:ext:openvsx_downloads"))

            return {
                "total_scans": total_scans,
                "scans_today": scans_today,
                "scans_last_hour": scans_last_hour,
                "total_findings": total_findings,
                "blocks_found": blocks_found,
                "total_files_scanned": total_files_scanned,
                "unique_installations_total": unique_total,
                "unique_installations_today": unique_today,
                "src_cli": int(by_source.get("cli", 0)),
                "src_vscode": int(by_source.get("vscode", 0)),
                "src_mcp": int(by_source.get("mcp", 0)),
                "src_github_action": int(by_source.get("github_action", 0)),
                "src_cloud_api": int(by_source.get("cloud_api", 0)),
                "hallucinated_packages_prevented": hallucinations_caught,
                "destructive_commands_blocked": gateway_blocks,
                "gateway_commands_allowed": gateway_allowed,
                "gateway_commands_warned": gateway_warned,
                "imports_verified": imports_verified,
                "impact_destructive_commands": int(impact_counts["destructive_commands"]),
                "impact_hallucinations": int(impact_counts["hallucinations"]),
                "impact_secrets_exposure": int(impact_counts["secrets_exposure"]),
                "impact_injection_attacks": int(impact_counts["injection_attacks"]),
                "impact_unsafe_config": int(impact_counts["unsafe_config"]),
                "impact_supply_chain": int(impact_counts["supply_chain"]),
                "impact_other": int(impact_counts["other"]),
                "pypi_downloads_total": pypi_downloads_total,
                "marketplace_installs": marketplace_installs,
                "marketplace_downloads": marketplace_downloads,
                "marketplace_updates": marketplace_updates,
                "openvsx_downloads": openvsx_downloads,
            }

    async def insert_counter_snapshots(self, counters: dict[str, int]) -> None:
        """Persist a timestamped snapshot row for each Redis counter key."""
        if not counters:
            return

        async with self._session_factory() as session:
            rows: list[CounterSnapshot] = []
            for key, value in counters.items():
                rows.append(CounterSnapshot(key=str(key), value=int(value)))
            session.add_all(rows)
            await session.commit()

    async def get_latest_counter_snapshots(self, keys: tuple[str, ...]) -> dict[str, int]:
        """Return latest snapshot value per counter key for the requested keys."""
        if not keys:
            return {}

        async with self._session_factory() as session:
            stmt = (
                select(
                    CounterSnapshot.key,
                    CounterSnapshot.value,
                    CounterSnapshot.snapshot_at,
                )
                .where(CounterSnapshot.key.in_(keys))
                .order_by(CounterSnapshot.key.asc(), CounterSnapshot.snapshot_at.desc())
            )
            rows = (await session.execute(stmt)).all()

        latest: dict[str, int] = {}
        for key, value, _snapshot_at in rows:
            key_str = str(key)
            if key_str in latest:
                continue
            latest[key_str] = _payload_int(value)
        return latest

    async def get_redis_warmup_counters(self) -> dict[str, int]:
        """Return aggregate counters needed to warm up Redis after a restart.

        Queries the persisted telemetry rows so Redis counters are restored
        to their correct values rather than starting from zero.
        """
        today_utc = datetime.datetime.combine(
            datetime.date.today(), datetime.time.min, tzinfo=datetime.UTC,
        )
        async with self._session_factory() as session:
            scan_rows = (
                await session.execute(
                    select(
                        TelemetryEventRaw.payload,
                        TelemetryEventRaw.source,
                        TelemetryEventRaw.created_at,
                    ).where(TelemetryEventRaw.event_type == "scan_completed")
                )
            ).all()

            total_scans: int = len(scan_rows)
            scans_today = 0
            total_findings = 0
            total_blocks = 0
            hallucinations_caught = 0
            files_scanned = 0
            impact_counts: dict[str, int] = {category: 0 for category in IMPACT_CATEGORIES}
            top_rule_counts: dict[str, int] = {}
            sources = ("cli", "vscode", "mcp", "github_action", "cloud_api")
            by_source: dict[str, int] = {source: 0 for source in sources}
            for payload, source, created_at in scan_rows:
                payload_obj = payload if isinstance(payload, dict) else {}
                total_findings += _payload_int(payload_obj.get("total_findings"))
                total_blocks += _payload_int(
                    (payload_obj.get("findings_by_severity") or {}).get("BLOCK"),
                )
                hallucinations_caught += _payload_int(payload_obj.get("hallucinations_found"))
                files_scanned += _payload_int(payload_obj.get("files_scanned"), default=1)
                if _is_on_or_after(created_at, today_utc):
                    scans_today += 1

                source_key = str(source or "")
                if source_key in by_source:
                    by_source[source_key] += 1

                for rule_id in _payload_rule_ids(payload_obj):
                    category = get_rule_category(rule_id)
                    impact_counts[category] = impact_counts.get(category, 0) + 1
                    top_rule_counts[rule_id] = top_rule_counts.get(rule_id, 0) + 1

            gateway_rows = (
                await session.execute(
                    select(TelemetryEventRaw.payload).where(
                        TelemetryEventRaw.event_type == "gateway_check",
                    )
                )
            ).all()
            gateway_blocks = 0
            gateway_allowed = 0
            gateway_warned = 0
            for (payload,) in gateway_rows:
                payload_obj = payload if isinstance(payload, dict) else {}
                action = str(payload_obj.get("action", "")).upper()
                if action == "BLOCKED":
                    gateway_blocks += 1
                elif action == "ALLOWED":
                    gateway_allowed += 1
                elif action == "WARNED":
                    gateway_warned += 1

            import_rows = (
                await session.execute(
                    select(TelemetryEventRaw.payload).where(
                        TelemetryEventRaw.event_type == "import_verified",
                    )
                )
            ).all()
            imports_verified = 0
            for (payload,) in import_rows:
                payload_obj = payload if isinstance(payload, dict) else {}
                imports_verified += _payload_int(payload_obj.get("total_imports_checked"))
                hallucinations_caught += _payload_int(payload_obj.get("hallucinations_caught"))

        counters: dict[str, int] = {
            "ct:total_scans": total_scans,
            "ct:scans_today": scans_today,
            "ct:total_findings": total_findings,
            "ct:total_blocks": total_blocks,
            "ct:files_scanned": max(files_scanned, total_scans),
            "ct:hallucinations_caught": hallucinations_caught,
            "ct:gateway_blocks": gateway_blocks,
            "ct:gateway_allowed": gateway_allowed,
            "ct:gateway_warned": gateway_warned,
            "ct:imports_verified": imports_verified,
        }

        for category, count in impact_counts.items():
            counters[f"ct:impact:{category}"] = int(count)

        for rule_id, count in top_rule_counts.items():
            counters[f"ct:top_rules:{rule_id}"] = int(count)

        # Add per-source counts BEFORE snapshot merge so they also get a floor.
        counters.update({f"ct:scans_by_source:{src}": cnt for src, cnt in by_source.items()})

        # Read persisted counter snapshots and use max(aggregated, snapshot)
        # for each key.  This ensures Redis warmup recovers data even if
        # telemetry_events_raw is incomplete (e.g., after accidental table
        # drop + reseed).
        #
        # Only query keys that are actually snapshot-persisted to avoid
        # passing dynamic keys (ct:top_rules:*) into a large IN(...) query.
        snapshot_lookup_keys = sorted({
            *USAGE_SNAPSHOT_KEY_MAP.values(),
            *DISTRIBUTION_SNAPSHOT_KEY_MAP.values(),
            "ct:scans_today",
        })
        snapshot_values = await self.get_latest_counter_snapshots(tuple(snapshot_lookup_keys))
        for snap_key, snap_val in snapshot_values.items():
            current = counters.get(snap_key, 0)
            counters[snap_key] = max(current, snap_val)
        return counters

    # --- Anonymous telemetry (public aggregates) ---

    async def insert_telemetry_event(
        self,
        *,
        instance_id: str,
        client: str,
        client_version: str,
        schema_version: int,
        event_type: str,
        scan_type: str = "",
        verdict: str = "",
        language: str = "",
        delta_scans: int = 0,
        delta_findings_total: int = 0,
        delta_hallucinated_packages_prevented: int = 0,
        delta_destructive_commands_blocked: int = 0,
    ) -> None:
        """Insert a single anonymous telemetry event.

        Must never store code, filenames, repo URLs, or user identifiers.
        """

        async with self._session_factory() as session:
            event = TelemetryEvent(
                instance_id=instance_id,
                client=client,
                client_version=client_version,
                schema_version=schema_version,
                event_type=event_type,
                scan_type=scan_type,
                verdict=verdict,
                language=language,
                delta_scans=delta_scans,
                delta_findings_total=delta_findings_total,
                delta_hallucinated_packages_prevented=delta_hallucinated_packages_prevented,
                delta_destructive_commands_blocked=delta_destructive_commands_blocked,
            )
            session.add(event)
            await session.commit()

    @staticmethod
    async def _sum_telemetry_column(
        session: AsyncSession,
        column: object,
    ) -> int:
        """Execute a coalesce(sum(column), 0) query."""
        result = (
            await session.execute(
                select(func.coalesce(func.sum(column), 0))
            )
        ).scalar_one() or 0
        return _payload_int(result)

    @staticmethod
    async def _query_telemetry_aggregates(
        session: AsyncSession,
    ) -> dict[str, int]:
        """Execute telemetry aggregate queries within a session."""
        events_total = (
            await session.execute(select(func.count()).select_from(TelemetryEvent))
        ).scalar_one() or 0

        unique_instances = (
            await session.execute(
                select(func.count(func.distinct(TelemetryEvent.instance_id)))
            )
        ).scalar_one() or 0

        _sum = DatabaseService._sum_telemetry_column
        scans = await _sum(session, TelemetryEvent.delta_scans)
        findings = await _sum(session, TelemetryEvent.delta_findings_total)
        hallucinated = await _sum(session, TelemetryEvent.delta_hallucinated_packages_prevented)
        blocked = await _sum(session, TelemetryEvent.delta_destructive_commands_blocked)

        return {
            "telemetry_events_total": int(events_total),
            "telemetry_unique_instances": int(unique_instances),
            "telemetry_scans_total": scans,
            "telemetry_findings_total": findings,
            "telemetry_hallucinated_packages_prevented": hallucinated,
            "telemetry_destructive_commands_blocked": blocked,
        }

    async def get_public_telemetry_stats(self) -> dict[str, int]:
        """Return anonymous telemetry aggregates for public display.

        If the telemetry table doesn't exist (older deployments), callers should
        catch database errors and fall back to zeros.
        """
        async with self._session_factory() as session:
            return await self._query_telemetry_aggregates(session)

    async def insert_telemetry_raw_batch(self, events: list[dict[str, object]]) -> None:
        """Bulk insert raw telemetry events.

        Each dict must include: event_type, source, installation_id, version, payload.
        """

        if not events:
            return

        async with self._session_factory() as session:
            rows: list[TelemetryEventRaw] = []
            for e in events:
                event_type = str(e.get("event_type", ""))
                source = str(e.get("source", ""))
                installation_id = str(e.get("installation_id", "") or "")
                version = str(e.get("version", "") or "")
                payload = e.get("payload")
                payload_dict: dict[str, object] = payload if isinstance(payload, dict) else {}
                rows.append(
                    TelemetryEventRaw(
                        event_type=event_type,
                        source=source,
                        installation_id=installation_id,
                        version=version,
                        payload=payload_dict,
                    )
                )
            session.add_all(rows)
            await session.commit()

    async def upsert_metrics_counters(self, counters: dict[str, int]) -> None:
        """Upsert metric counters for durability.

        Uses PostgreSQL ON CONFLICT when available; falls back to per-row merge on other DBs.
        """

        if not counters:
            return

        async with self._session_factory() as session:
            try:
                stmt = pg_insert(MetricsCounter).values(
                    [
                        {"metric_name": name, "metric_value": int(value)}
                        for name, value in counters.items()
                    ]
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=[MetricsCounter.metric_name],
                    set_={
                        "metric_value": stmt.excluded.metric_value,
                        "updated_at": func.now(),
                    },
                )
                await session.execute(stmt)
                await session.commit()
            except Exception:
                # SQLite / non-Postgres fallback
                for name, value in counters.items():
                    existing = await session.get(MetricsCounter, name)
                    if existing is None:
                        session.add(MetricsCounter(metric_name=name, metric_value=int(value)))
                    else:
                        existing.metric_value = int(value)
                await session.commit()
