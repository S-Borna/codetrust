"""Shared test fixtures for CodeTrust tests."""

import fakeredis.aioredis
import httpx
import pytest

from src.middleware.ip_rate_limit import IPRateLimitMiddleware
from src.services.cache import CacheService
from src.services.registry import RegistryService


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force unauthenticated mode in tests.

    Some developer environments may have CODETRUST_API_KEY set, which would
    make many endpoint tests fail with unauthorized responses. Individual tests can still
    override settings.api_key explicitly when exercising auth.
    """

    monkeypatch.delenv("CODETRUST_API_KEY", raising=False)
    # Prevent any test from performing outbound anonymous telemetry.
    monkeypatch.setenv("CODETRUST_TELEMETRY", "0")
    from src.config import settings

    settings.api_key = ""


@pytest.fixture(autouse=True)
def _sanitize_governance_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep governance tests deterministic regardless of shell exports.

    Local developer shells may export governance toggles (for manual runtime tests),
    but unit tests should rely on per-test fixtures and config files instead.
    """

    monkeypatch.delenv("CODETRUST_GOVERNANCE_MODE", raising=False)
    monkeypatch.delenv("CODETRUST_GOVERNANCE_ENABLED", raising=False)


@pytest.fixture(autouse=True)
def _reset_ip_rate_limiter() -> None:
    """Clear IP rate limiter buckets before every test.

    The IPRateLimitMiddleware lives on the app singleton and its in-memory
    buckets persist across tests.  All TestClient requests arrive from IP
    'testclient', so without this reset the burst/window counters carry
    over and cause spurious 429s.
    """
    from src.api import app

    stack = app.middleware_stack
    while stack is not None:
        if isinstance(stack, IPRateLimitMiddleware):
            stack._buckets.clear()
            break
        stack = getattr(stack, "app", None)


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
