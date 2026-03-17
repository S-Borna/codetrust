"""Tests for CacheService — connect, get/set, JSON ops, disconnect, is_connected."""

from __future__ import annotations

from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

from src.services.cache import CacheService
from src.services.telemetry import (
    BASELINE_DB_SNAPSHOT,
    BASELINES,
    IMPACT_BASELINES,
    SCANS_TODAY_KEY,
    STATS_CACHE_KEY,
    sync_redis_counters_to_snapshots,
    warm_up_redis_counters,
)


@pytest.fixture()
def cache() -> CacheService:
    """CacheService with a FakeRedis backend."""
    svc = CacheService("redis://localhost:6379")
    svc._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return svc


@pytest.fixture()
def disconnected_cache() -> CacheService:
    """CacheService with no connection (client=None)."""
    svc = CacheService("redis://localhost:6379")
    svc._client = None
    return svc


# ---------------------------------------------------------------------------
# Basic get/set
# ---------------------------------------------------------------------------


class TestCacheGetSet:
    @pytest.mark.asyncio()
    async def test_set_and_get(self, cache: CacheService) -> None:
        await cache.set("foo", "bar", ttl=60)
        assert await cache.get("foo") == "bar"

    @pytest.mark.asyncio()
    async def test_get_missing_key(self, cache: CacheService) -> None:
        assert await cache.get("nonexistent") is None

    @pytest.mark.asyncio()
    async def test_get_disconnected_returns_none(self, disconnected_cache: CacheService) -> None:
        assert await disconnected_cache.get("key") is None

    @pytest.mark.asyncio()
    async def test_set_disconnected_is_silent(self, disconnected_cache: CacheService) -> None:
        await disconnected_cache.set("key", "val", ttl=10)  # Should not raise


# ---------------------------------------------------------------------------
# JSON operations
# ---------------------------------------------------------------------------


class TestCacheJSON:
    @pytest.mark.asyncio()
    async def test_set_and_get_json(self, cache: CacheService) -> None:
        data = {"name": "test", "count": 42, "active": True}
        await cache.set_json("json-key", data, ttl=120)
        result = await cache.get_json("json-key")
        assert result == data

    @pytest.mark.asyncio()
    async def test_get_json_missing(self, cache: CacheService) -> None:
        assert await cache.get_json("no-key") is None

    @pytest.mark.asyncio()
    async def test_get_json_invalid(self, cache: CacheService) -> None:
        await cache.set("bad-json", "not-json{{{", ttl=60)
        assert await cache.get_json("bad-json") is None

    @pytest.mark.asyncio()
    async def test_get_json_disconnected(self, disconnected_cache: CacheService) -> None:
        assert await disconnected_cache.get_json("key") is None

    @pytest.mark.asyncio()
    async def test_set_json_disconnected(self, disconnected_cache: CacheService) -> None:
        await disconnected_cache.set_json("key", {"a": 1}, ttl=60)  # Silent


# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------


class TestCacheConnection:
    @pytest.mark.asyncio()
    async def test_is_connected_true(self, cache: CacheService) -> None:
        assert await cache.is_connected() is True

    @pytest.mark.asyncio()
    async def test_is_connected_false(self, disconnected_cache: CacheService) -> None:
        assert await disconnected_cache.is_connected() is False

    @pytest.mark.asyncio()
    async def test_disconnect(self, cache: CacheService) -> None:
        await cache.disconnect()
        assert cache._client is None

    @pytest.mark.asyncio()
    async def test_disconnect_when_already_none(self, disconnected_cache: CacheService) -> None:
        await disconnected_cache.disconnect()  # Should not raise

    @pytest.mark.asyncio()
    async def test_make_key(self, cache: CacheService) -> None:
        key = cache._make_key("scan", "abc123")
        assert key == "codetrust:scan:abc123"


# ---------------------------------------------------------------------------
# warm_up_redis_counters
# ---------------------------------------------------------------------------


class TestWarmUpRedisCounters:
    """Unit tests for the Redis counter warm-up function."""

    @pytest.fixture()
    def fake_redis(self) -> fakeredis.aioredis.FakeRedis:
        return fakeredis.aioredis.FakeRedis(decode_responses=True)

    def _make_db(self, counters: dict[str, int]) -> AsyncMock:
        db = AsyncMock()
        db.get_redis_warmup_counters = AsyncMock(return_value=counters)
        return db

    @pytest.mark.asyncio()
    async def test_seeds_empty_redis_from_db(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """When Redis has no counters, DB values are written."""
        db = self._make_db({"ct:total_scans": 500, SCANS_TODAY_KEY: 42})  # noqa: magic_number
        await warm_up_redis_counters(r=fake_redis, db=db)
        expected = BASELINES["ct:total_scans"] + max(500 - BASELINE_DB_SNAPSHOT["ct:total_scans"], 0)
        assert int(await fake_redis.get("ct:total_scans")) == expected
        assert int(await fake_redis.get(SCANS_TODAY_KEY)) == 42

    @pytest.mark.asyncio()
    async def test_applies_baseline_floor_for_required_keys(
        self, fake_redis: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """Required counters are forced to at least baseline when DB is below floors."""
        db = self._make_db({"ct:total_scans": 1, "ct:total_findings": 2})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert int(await fake_redis.get("ct:total_scans")) == BASELINES["ct:total_scans"]
        assert int(await fake_redis.get("ct:total_findings")) == BASELINES["ct:total_findings"]

    @pytest.mark.asyncio()
    async def test_invalidates_stats_cache_when_restored(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """After restoring at least one counter, stale stats cache is deleted."""
        await fake_redis.set(STATS_CACHE_KEY, '{"stale":"true"}')
        db = self._make_db({"ct:total_scans": 100})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert await fake_redis.get(STATS_CACHE_KEY) is None

    @pytest.mark.asyncio()
    async def test_handles_db_error_gracefully(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """If the DB raises, warm-up exits silently without touching Redis."""
        db = AsyncMock()
        db.get_redis_warmup_counters = AsyncMock(side_effect=RuntimeError("db down"))
        await warm_up_redis_counters(r=fake_redis, db=db)  # must not raise
        assert await fake_redis.get("ct:total_scans") is None

    @pytest.mark.asyncio()
    async def test_sets_baselines_even_when_db_zero(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """Baseline floors are applied even when DB returns zero values."""
        db = self._make_db({"ct:total_scans": 0, SCANS_TODAY_KEY: 0})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert int(await fake_redis.get("ct:total_scans")) == BASELINES["ct:total_scans"]

    @pytest.mark.asyncio()
    async def test_applies_additive_baseline_when_db_exceeds_snapshot(
        self, fake_redis: fakeredis.aioredis.FakeRedis,
    ) -> None:
        """When DB is above baseline snapshot, final value is baseline plus delta."""
        snapshot_total_scans = int(BASELINE_DB_SNAPSHOT["ct:total_scans"])
        db = self._make_db({"ct:total_scans": snapshot_total_scans + 3})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert int(await fake_redis.get("ct:total_scans")) == BASELINES["ct:total_scans"] + 3

    @pytest.mark.asyncio()
    async def test_warmup_restores_impact_counters(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """Impact counters are included in Redis warmup coverage."""
        db = self._make_db({"ct:impact:injection_attacks": 7})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert int(await fake_redis.get("ct:impact:injection_attacks")) == 7
        assert int(await fake_redis.get("ct:impact:other")) == IMPACT_BASELINES["ct:impact:other"]


class TestCounterSnapshots:
    """Unit tests for snapshot sync coverage."""

    @pytest.mark.asyncio()
    async def test_snapshot_sync_includes_impact_counters(self) -> None:
        fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
        await fake_redis.set("ct:impact:secrets_exposure", "9")
        db = AsyncMock()
        db.get_redis_warmup_counters = AsyncMock(return_value={})
        db.insert_counter_snapshots = AsyncMock(return_value=None)

        await sync_redis_counters_to_snapshots(r=fake_redis, db=db)

        assert db.insert_counter_snapshots.await_count == 1
        counters = db.insert_counter_snapshots.await_args.args[0]
        assert counters["ct:impact:secrets_exposure"] == 9
