"""Tests for CacheService — connect, get/set, JSON ops, disconnect, is_connected."""

from __future__ import annotations

from unittest.mock import AsyncMock

import fakeredis.aioredis
import pytest

from src.services.cache import CacheService
from src.services.telemetry import SCANS_TODAY_KEY, STATS_CACHE_KEY, warm_up_redis_counters


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
        db = self._make_db({"ct:total_scans": 500, SCANS_TODAY_KEY: 42})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert int(await fake_redis.get("ct:total_scans")) == 500
        assert int(await fake_redis.get(SCANS_TODAY_KEY)) == 42

    @pytest.mark.asyncio()
    async def test_does_not_decrement_live_counter(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """When Redis already has a higher value, it is not overwritten."""
        await fake_redis.set("ct:total_scans", 1000)
        db = self._make_db({"ct:total_scans": 500})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert int(await fake_redis.get("ct:total_scans")) == 1000

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
    async def test_skips_zero_counters(self, fake_redis: fakeredis.aioredis.FakeRedis) -> None:
        """Zero values from the DB are not written to Redis."""
        db = self._make_db({"ct:total_scans": 0, SCANS_TODAY_KEY: 0})
        await warm_up_redis_counters(r=fake_redis, db=db)
        assert await fake_redis.get("ct:total_scans") is None
