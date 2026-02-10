"""Shared test fixtures for CodeTrust tests."""

import fakeredis.aioredis
import httpx
import pytest

from src.services.cache import CacheService
from src.services.registry import RegistryService


@pytest.fixture()
async def fake_cache() -> CacheService:
    """Create a CacheService backed by fakeredis."""
    cache = CacheService("redis://localhost:6379")
    # Replace the internal client with fakeredis
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return cache


@pytest.fixture()
async def disconnected_cache() -> CacheService:
    """Create a CacheService with no Redis connection (graceful degradation)."""
    cache = CacheService("redis://localhost:6379")
    cache._client = None
    return cache


@pytest.fixture()
def mock_http_client() -> httpx.AsyncClient:
    """Create an httpx.AsyncClient for testing (will be mocked by pytest-httpx)."""
    return httpx.AsyncClient()


@pytest.fixture()
async def registry_service(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
) -> RegistryService:
    """Create a RegistryService with fake cache and mock HTTP client."""
    return RegistryService(fake_cache, mock_http_client)
