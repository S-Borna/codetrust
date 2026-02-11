"""Tests for CacheService — uses fakeredis, never hits real Redis."""


import fakeredis.aioredis
import pytest

from src.services.cache import CacheService


@pytest.fixture()
async def cache() -> CacheService:
    """Create a CacheService backed by fakeredis."""
    svc = CacheService("redis://localhost:6379")
    svc._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return svc


@pytest.mark.asyncio()
async def test_get_returns_none_on_miss(cache: CacheService) -> None:
    """Cache miss returns None."""
    result = await cache.get("nonexistent_key")
    assert result is None


@pytest.mark.asyncio()
async def test_set_and_get_roundtrip(cache: CacheService) -> None:
    """Set a value and retrieve it."""
    await cache.set("test_key", "test_value", ttl=300)
    result = await cache.get("test_key")
    assert result == "test_value"


@pytest.mark.asyncio()
async def test_set_json_and_get_json_roundtrip(cache: CacheService) -> None:
    """Set JSON and retrieve parsed dict."""
    data = {"exists": True, "latest": "1.0.0", "deprecated": False}
    await cache.set_json("pkg:requests", data, ttl=300)
    result = await cache.get_json("pkg:requests")
    assert result is not None
    assert result["exists"] is True
    assert result["latest"] == "1.0.0"


@pytest.mark.asyncio()
async def test_get_json_returns_none_on_miss(cache: CacheService) -> None:
    """JSON cache miss returns None."""
    result = await cache.get_json("no_such_key")
    assert result is None


@pytest.mark.asyncio()
async def test_get_json_returns_none_on_invalid_json(cache: CacheService) -> None:
    """Malformed JSON returns None gracefully."""
    await cache.set("bad_json", "not-valid-json{{{", ttl=300)
    result = await cache.get_json("bad_json")
    assert result is None


@pytest.mark.asyncio()
async def test_make_key(cache: CacheService) -> None:
    """_make_key builds correct namespaced keys."""
    key = cache._make_key("pypi", "requests")
    assert key == "codetrust:pypi:requests"


@pytest.mark.asyncio()
async def test_is_connected_true(cache: CacheService) -> None:
    """is_connected returns True when fakeredis is connected."""
    result = await cache.is_connected()
    assert result is True


@pytest.mark.asyncio()
async def test_is_connected_false_when_no_client() -> None:
    """is_connected returns False when client is None."""
    svc = CacheService("redis://localhost:6379")
    svc._client = None
    result = await svc.is_connected()
    assert result is False


@pytest.mark.asyncio()
async def test_get_returns_none_when_no_client() -> None:
    """Graceful degradation: get returns None when Redis unavailable."""
    svc = CacheService("redis://localhost:6379")
    svc._client = None
    result = await svc.get("any_key")
    assert result is None


@pytest.mark.asyncio()
async def test_set_silently_fails_when_no_client() -> None:
    """Graceful degradation: set does nothing when Redis unavailable."""
    svc = CacheService("redis://localhost:6379")
    svc._client = None
    await svc.set("key", "val", ttl=300)  # Should not raise
