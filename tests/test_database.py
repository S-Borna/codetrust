"""Tests for database service — users, API keys, scan logs, and usage."""

import datetime

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from src.models.database import CounterSnapshot
from src.services.database import DatabaseService, _hash_key


@pytest.fixture()
async def db_service() -> DatabaseService:
    """Create an in-memory SQLite database for testing."""
    db = DatabaseService("sqlite+aiosqlite:///:memory:", echo=False)
    await db.create_tables()
    yield db  # type: ignore[misc]
    await db.close()


# --- User tests ---


class TestUserOperations:
    """Tests for user CRUD operations."""

    async def test_create_user(self, db_service: DatabaseService) -> None:
        """Create a user and verify fields."""
        user = await db_service.create_user(
            github_id="gh_12345",
            email="test@example.com",
            name="Test User",
            avatar_url="https://example.com/avatar.png",
        )
        assert user.id
        assert user.github_id == "gh_12345"
        assert user.email == "test@example.com"
        assert user.name == "Test User"
        assert user.plan == "free"

    async def test_get_user_by_id(self, db_service: DatabaseService) -> None:
        """Retrieve a user by their internal ID."""
        created = await db_service.create_user(github_id="gh_100")
        fetched = await db_service.get_user(created.id)
        assert fetched is not None
        assert fetched.id == created.id

    async def test_get_user_nonexistent(self, db_service: DatabaseService) -> None:
        """Return None for unknown user ID."""
        result = await db_service.get_user("nonexistent")
        assert result is None

    async def test_get_user_by_github_id(self, db_service: DatabaseService) -> None:
        """Retrieve a user by GitHub ID."""
        await db_service.create_user(github_id="gh_200", email="a@b.com")
        found = await db_service.get_user_by_github_id("gh_200")
        assert found is not None
        assert found.email == "a@b.com"

    async def test_get_user_by_github_id_not_found(
        self, db_service: DatabaseService,
    ) -> None:
        """Return None for unknown GitHub ID."""
        result = await db_service.get_user_by_github_id("unknown")
        assert result is None

    async def test_get_or_create_user_creates(
        self, db_service: DatabaseService,
    ) -> None:
        """Creates user when not found."""
        user = await db_service.get_or_create_user(
            github_id="gh_new", name="New",
        )
        assert user.github_id == "gh_new"
        assert user.name == "New"

    async def test_get_or_create_user_returns_existing(
        self, db_service: DatabaseService,
    ) -> None:
        """Returns existing user without creating duplicate."""
        first = await db_service.create_user(github_id="gh_dup")
        second = await db_service.get_or_create_user(github_id="gh_dup")
        assert first.id == second.id

    async def test_update_user_plan(self, db_service: DatabaseService) -> None:
        """Update user plan and Stripe IDs."""
        user = await db_service.create_user(github_id="gh_plan")
        updated = await db_service.update_user_plan(
            user.id, "pro", stripe_customer_id="cus_xxx",
        )
        assert updated is not None
        assert updated.plan == "pro"
        assert updated.stripe_customer_id == "cus_xxx"

    async def test_update_user_plan_not_found(
        self, db_service: DatabaseService,
    ) -> None:
        """Return None when updating nonexistent user."""
        result = await db_service.update_user_plan("fake_id", "pro")
        assert result is None


# --- API Key tests ---


class TestApiKeyOperations:
    """Tests for API key CRUD operations."""

    async def test_create_api_key(self, db_service: DatabaseService) -> None:
        """Create an API key and verify raw key format."""
        user = await db_service.create_user(github_id="gh_key1")
        raw_key, record = await db_service.create_api_key(user.id, "Test Key")

        assert raw_key.startswith("ct_live_")
        assert len(raw_key) > 20
        assert record.name == "Test Key"
        assert record.prefix == raw_key[:16]
        assert not record.is_revoked

    async def test_list_api_keys(self, db_service: DatabaseService) -> None:
        """List API keys for a user."""
        user = await db_service.create_user(github_id="gh_key2")
        await db_service.create_api_key(user.id, "Key A")
        await db_service.create_api_key(user.id, "Key B")

        keys = await db_service.list_api_keys(user.id)
        assert len(keys) == 2
        names = {k.name for k in keys}
        assert names == {"Key A", "Key B"}

    async def test_revoke_api_key(self, db_service: DatabaseService) -> None:
        """Revoke an API key."""
        user = await db_service.create_user(github_id="gh_key3")
        _, record = await db_service.create_api_key(user.id)

        success = await db_service.revoke_api_key(record.id, user.id)
        assert success

        keys = await db_service.list_api_keys(user.id)
        assert keys[0].is_revoked
        assert keys[0].revoked_at is not None

    async def test_revoke_api_key_wrong_user(
        self, db_service: DatabaseService,
    ) -> None:
        """Cannot revoke another user's key."""
        user = await db_service.create_user(github_id="gh_key4")
        _, record = await db_service.create_api_key(user.id)

        result = await db_service.revoke_api_key(record.id, "wrong_user")
        assert not result

    async def test_revoke_nonexistent_key(
        self, db_service: DatabaseService,
    ) -> None:
        """Return False for nonexistent key."""
        result = await db_service.revoke_api_key("fake", "fake")
        assert not result

    async def test_verify_api_key_hash(self, db_service: DatabaseService) -> None:
        """Verify a valid API key by its hash."""
        user = await db_service.create_user(github_id="gh_key5")
        raw_key, _ = await db_service.create_api_key(user.id)

        record = await db_service.verify_api_key_hash(raw_key)
        assert record is not None
        assert record.last_used_at is not None

    async def test_verify_api_key_hash_revoked(
        self, db_service: DatabaseService,
    ) -> None:
        """Revoked keys return None on verification."""
        user = await db_service.create_user(github_id="gh_key6")
        raw_key, record = await db_service.create_api_key(user.id)
        await db_service.revoke_api_key(record.id, user.id)

        result = await db_service.verify_api_key_hash(raw_key)
        assert result is None

    async def test_verify_api_key_hash_invalid(
        self, db_service: DatabaseService,
    ) -> None:
        """Invalid key returns None."""
        result = await db_service.verify_api_key_hash("ct_live_fakefake")
        assert result is None


# --- Scan Log tests ---


class TestScanLogOperations:
    """Tests for scan log operations."""

    async def test_log_scan(self, db_service: DatabaseService) -> None:
        """Log a scan and verify fields."""
        user = await db_service.create_user(github_id="gh_log1")
        log = await db_service.log_scan(
            user_id=user.id,
            scan_type="static",
            verdict="PASS",
            findings_count=3,
            latency_ms=42,
            language="python",
            filename="test.py",
        )
        assert log.id
        assert log.scan_type == "static"
        assert log.verdict == "PASS"
        assert log.findings_count == 3

    async def test_get_scan_history(self, db_service: DatabaseService) -> None:
        """Get paginated scan history."""
        user = await db_service.create_user(github_id="gh_log2")
        for i in range(5):
            await db_service.log_scan(
                user_id=user.id,
                scan_type="deep" if i % 2 == 0 else "static",
                verdict="PASS",
                findings_count=i,
                latency_ms=10,
            )

        history = await db_service.get_scan_history(user.id, page=1, per_page=3)
        assert len(history) == 3

        page2 = await db_service.get_scan_history(user.id, page=2, per_page=3)
        assert len(page2) == 2

    async def test_get_scan_history_filtered(
        self, db_service: DatabaseService,
    ) -> None:
        """Filter scan history by type."""
        user = await db_service.create_user(github_id="gh_log3")
        await db_service.log_scan(
            user_id=user.id, scan_type="static", verdict="PASS",
            findings_count=0, latency_ms=10,
        )
        await db_service.log_scan(
            user_id=user.id, scan_type="deep", verdict="WARN",
            findings_count=2, latency_ms=20,
        )

        static_only = await db_service.get_scan_history(
            user.id, scan_type="static",
        )
        assert len(static_only) == 1
        assert static_only[0].scan_type == "static"

    async def test_count_scans(self, db_service: DatabaseService) -> None:
        """Count total scans for a user."""
        user = await db_service.create_user(github_id="gh_log4")
        for _ in range(3):
            await db_service.log_scan(
                user_id=user.id, scan_type="static", verdict="PASS",
                findings_count=0, latency_ms=5,
            )

        count = await db_service.count_scans(user.id)
        assert count == 3


# --- Usage tests ---


class TestUsageTracking:
    """Tests for daily usage tracking."""

    async def test_increment_daily_usage(
        self, db_service: DatabaseService,
    ) -> None:
        """Increment usage creates a new entry."""
        user = await db_service.create_user(github_id="gh_usage1")
        usage = await db_service.increment_daily_usage(
            user.id, findings_count=5, latency_ms=100,
        )
        assert usage.scan_count == 1
        assert usage.findings_total == 5

    async def test_increment_daily_usage_accumulates(
        self, db_service: DatabaseService,
    ) -> None:
        """Multiple increments accumulate on the same day."""
        user = await db_service.create_user(github_id="gh_usage2")
        await db_service.increment_daily_usage(user.id, 3, 100)
        usage = await db_service.increment_daily_usage(user.id, 7, 200)  # noqa: magic_number

        assert usage.scan_count == 2
        assert usage.findings_total == 10

    async def test_get_daily_usage(self, db_service: DatabaseService) -> None:
        """Get scan count for today."""
        user = await db_service.create_user(github_id="gh_usage3")
        await db_service.increment_daily_usage(user.id)
        await db_service.increment_daily_usage(user.id)

        count = await db_service.get_daily_usage(user.id)
        assert count == 2

    async def test_get_daily_usage_no_data(
        self, db_service: DatabaseService,
    ) -> None:
        """Return 0 when no usage data."""
        user = await db_service.create_user(github_id="gh_usage4")
        count = await db_service.get_daily_usage(user.id)
        assert count == 0

    async def test_get_usage_stats(self, db_service: DatabaseService) -> None:
        """Get usage stats for the last N days."""
        user = await db_service.create_user(github_id="gh_usage5")
        await db_service.increment_daily_usage(user.id, 10, 50)

        stats = await db_service.get_usage_stats(user.id, days=30)
        assert len(stats) >= 1
        assert stats[0].date == datetime.date.today()


# --- Hash function test ---


class TestHashKey:
    """Tests for the key hashing utility."""

    def test_hash_deterministic(self) -> None:
        """Same key produces same hash."""
        assert _hash_key("test_key") == _hash_key("test_key")

    def test_hash_different_keys(self) -> None:
        """Different keys produce different hashes."""
        assert _hash_key("key_a") != _hash_key("key_b")

    def test_hash_length(self) -> None:
        """SHA-256 hash is 64 hex characters."""
        h = _hash_key("any_key")
        assert len(h) == 64


class TestCounterSnapshotSchema:
    """Guardrails for counter_snapshots schema — the bug that lost our telemetry."""

    async def test_orm_roundtrip_on_fresh_schema(self, db_service: DatabaseService) -> None:
        """Create a snapshot via ORM, read it back — baseline that schema matches."""
        async with db_service._session_factory() as session:
            session.add(CounterSnapshot(key="ct:test:roundtrip", value=42))
            await session.commit()

        latest = await db_service.get_latest_counter_snapshots(("ct:test:roundtrip",))
        assert latest == {"ct:test:roundtrip": 42}

    async def test_create_tables_rejects_legacy_schema(self, tmp_path) -> None:
        """A pre-existing counter_snapshots table with the legacy (id, counter_key)
        shape must cause create_tables to raise — not silently continue. This is
        the exact condition that masked a 19-day snapshot-write outage in prod.
        """
        db_path = tmp_path / "legacy.db"
        url = f"sqlite+aiosqlite:///{db_path}"

        # Seed a legacy counter_snapshots table before ORM create_all runs.
        engine = create_async_engine(url)
        async with engine.begin() as conn:
            await conn.execute(text(
                "CREATE TABLE counter_snapshots ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " counter_key TEXT NOT NULL,"
                " value BIGINT NOT NULL DEFAULT 0,"
                " snapshot_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
                ")"
            ))
        await engine.dispose()

        db = DatabaseService(url)
        with pytest.raises(RuntimeError, match="counter_snapshots schema does not match"):
            await db.create_tables()
        await db.close()
