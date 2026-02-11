"""Tests for IP-based rate limiting middleware."""

from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.middleware.ip_rate_limit import (
    IP_BURST_LIMIT,
    IP_RATE_LIMIT,
    MAX_BODY_SIZE,
    IPRateLimitMiddleware,
    _IPBucket,
)
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer

# --- Unit tests for _IPBucket ---


class TestIPBucket:
    """Test the sliding window counter logic."""

    def test_allows_normal_traffic(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        for _ in range(10):
            assert bucket.check(now) is True

    def test_blocks_burst_over_limit(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        for _ in range(IP_BURST_LIMIT):
            assert bucket.check(now) is True
        # Next request in same burst window should be blocked
        assert bucket.check(now) is False

    def test_burst_resets_after_window(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        for _ in range(IP_BURST_LIMIT):
            bucket.check(now)
        assert bucket.check(now) is False
        # After burst window expires, should allow again
        assert bucket.check(now + 6.0) is True

    def test_blocks_after_rate_limit(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        # Send requests spread across burst windows to avoid burst limit
        for i in range(IP_RATE_LIMIT):
            t = now + (i * 0.3)  # spread out to avoid burst
            bucket.check(t)
        # Should be blocked (over window limit)
        last_t = now + (IP_RATE_LIMIT * 0.3)
        assert bucket.check(last_t) is False

    def test_window_resets_after_expiry(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        for i in range(IP_RATE_LIMIT):
            bucket.check(now + (i * 0.3))
        # After window expires, should allow again
        assert bucket.check(now + 61.0) is True

    def test_ban_after_repeated_violations(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        # Trigger multiple violations by repeatedly exceeding burst limit
        for violation in range(6):
            t = now + (violation * 6.0)  # new burst window each time
            for _ in range(IP_BURST_LIMIT + 1):
                bucket.check(t)
        # Should be banned now
        ban_time = now + 36.0
        assert bucket.check(ban_time) is False

    def test_ban_expires(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        # Trigger ban
        for violation in range(6):
            t = now + (violation * 6.0)
            for _ in range(IP_BURST_LIMIT + 1):
                bucket.check(t)
        # After ban duration, should allow again
        assert bucket.check(now + 400.0) is True


# --- Integration tests with FastAPI ---


def _clear_ip_buckets() -> None:
    """Clear all IP rate limiter buckets in the app middleware stack."""
    # The middleware is stored in app.middleware_stack after first request
    # We need to access the actual middleware instance
    stack = app.middleware_stack
    while stack is not None:
        if isinstance(stack, IPRateLimitMiddleware):
            stack._buckets.clear()
            return
        stack = getattr(stack, "app", None)


@pytest.fixture()
def rate_limit_client() -> TestClient:
    """Create a TestClient with mocked app state for rate limit tests."""
    cache = CacheService("redis://localhost:6379")
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)

    http_client = httpx.AsyncClient()
    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.ast_analyzer = AstAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = None
    app.state.billing = MagicMock(spec=BillingService)
    app.state.auth = AuthService(http_client)
    app.state.rate_limiter = None

    client = TestClient(app, raise_server_exceptions=False)
    _clear_ip_buckets()
    return client


class TestIPRateLimitIntegration:
    """Integration tests for IP rate limiting via TestClient."""

    def test_status_endpoint_exempt_from_ip_limit(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Health check should never be rate limited (never returns 429)."""
        for _ in range(30):
            resp = rate_limit_client.get("/v1/status")
            # Status may return 200 or 500 (depending on app state setup)
            # but should NEVER return 429
            assert resp.status_code != 429

    def test_scan_endpoint_returns_429_on_flood(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Scan endpoints should return 429 when flooded from same IP."""
        blocked = False
        for _ in range(IP_BURST_LIMIT + 5):
            resp = rate_limit_client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
            )
            if resp.status_code == 429:
                blocked = True
                data = resp.json()
                assert data["error"] == "too_many_requests"
                assert "retry_after" in data
                break
        assert blocked, "Expected 429 after burst limit exceeded"

    def test_429_includes_retry_after_header(
        self, rate_limit_client: TestClient,
    ) -> None:
        """429 response should include Retry-After header."""
        for _ in range(IP_BURST_LIMIT + 5):
            resp = rate_limit_client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
            )
            if resp.status_code == 429:
                assert "retry-after" in resp.headers
                assert int(resp.headers["retry-after"]) > 0
                return
        pytest.fail("Expected 429 response")

    def test_oversized_payload_returns_413(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Requests with body > MAX_BODY_SIZE should be rejected."""
        huge_code = "x = 1\n" * (MAX_BODY_SIZE // 5)  # well over 1MB
        resp = rate_limit_client.post(
            "/v1/scan/static",
            json={"code": huge_code, "filename": "huge.py"},
        )
        assert resp.status_code == 413
        assert resp.json()["error"] == "payload_too_large"

    def test_normal_payload_accepted(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Normal-sized requests should pass through."""
        resp = rate_limit_client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "small.py"},
        )
        # Should get 200 or 401 (auth), but NOT 413 or 429
        assert resp.status_code not in (413, 429)
