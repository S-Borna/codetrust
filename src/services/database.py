"""Async database service for users, API keys, scan logs, and usage tracking."""

import datetime
import hashlib
import secrets

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.models.database import ApiKeyRecord, Base, ScanLog, UsageDay, User

logger = structlog.get_logger()

API_KEY_PREFIX = "ct_live_"
API_KEY_BYTES = 32


def _hash_key(raw_key: str) -> str:
    """SHA-256 hash an API key for storage."""
    return hashlib.sha256(raw_key.encode()).hexdigest()


def _generate_api_key() -> str:
    """Generate a new random API key with prefix."""
    token = secrets.token_hex(API_KEY_BYTES)
    return f"{API_KEY_PREFIX}{token}"


class DatabaseService:
    """Async CRUD operations for CodeTrust database."""

    def __init__(self, database_url: str, echo: bool = False) -> None:
        """Initialize with database URL."""
        self._engine: AsyncEngine = create_async_engine(
            database_url, echo=echo, pool_pre_ping=True,
        )
        self._session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False,
        )

    async def create_tables(self) -> None:
        """Create all tables if they don't exist."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("database_tables_created")

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
