"""Tests for IP-based rate limiting middleware."""

import time
import unittest.mock
from http import HTTPStatus
from unittest.mock import MagicMock

import fakeredis.aioredis
import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.middleware.ip_rate_limit import (
    IP_BURST_LIMIT,
    IP_BURST_WINDOW,
    IP_RATE_LIMIT,
    IP_RATE_WINDOW,
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
        assert bucket.check(now + IP_BURST_WINDOW + 0.1) is True

    def test_blocks_after_rate_limit(self) -> None:
        bucket = _IPBucket()
        now = bucket.window_start
        # Generate traffic that exceeds the per-minute limit while staying under the burst limit.
        #
        # Constraints (must satisfy both):
        # - Burst: <= IP_BURST_LIMIT requests per IP_BURST_WINDOW seconds
        # - Rate:  <= IP_RATE_LIMIT requests per IP_RATE_WINDOW seconds
        #
        # Use a dt that is:
        # - small enough to exceed the overall rate window (dt < IP_RATE_WINDOW / IP_RATE_LIMIT)
        # - large enough to stay within burst (dt >= IP_BURST_WINDOW / IP_BURST_LIMIT)
        rate_dt = (IP_RATE_WINDOW / IP_RATE_LIMIT) * 0.9
        burst_dt = IP_BURST_WINDOW / IP_BURST_LIMIT
        dt = max(rate_dt, burst_dt)

        for i in range(IP_RATE_LIMIT):
            bucket.check(now + (i * dt))

        # Next request within the same rate window should be blocked.
        assert bucket.check(now + (IP_RATE_LIMIT * dt)) is False

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
        assert bucket.check(now + (40 * 10.0)) is True


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
        """Health check should never be rate limited."""
        for _ in range(30):
            resp = rate_limit_client.get("/v1/status")
            # Status may return success or server error depending on app state,
            # but should never return too-many-requests.
            assert resp.status_code != HTTPStatus.TOO_MANY_REQUESTS

    def test_scan_endpoint_returns_429_on_flood(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Scan endpoints should return too-many-requests when flooded from same IP."""
        # Freeze time.monotonic so burst window doesn't reset during slow requests
        frozen_time = time.monotonic()
        blocked = False
        with unittest.mock.patch("src.middleware.ip_rate_limit.time") as mock_time:
            mock_time.monotonic.return_value = frozen_time
            for _ in range(IP_BURST_LIMIT + 5):
                resp = rate_limit_client.post(
                    "/v1/scan/static",
                    json={"code": "x = 1", "filename": "test.py"},
                    headers={"X-API-Key": "ct_pro_test"},
                )
                if resp.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    blocked = True
                    data = resp.json()
                    assert data["error"] == "too_many_requests"
                    assert "retry_after" in data
                    break
        assert blocked, "Expected too-many-requests after burst limit exceeded"

    def test_429_includes_retry_after_header(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Too-many-requests response should include Retry-After header."""
        frozen_time = time.monotonic()
        with unittest.mock.patch("src.middleware.ip_rate_limit.time") as mock_time:
            mock_time.monotonic.return_value = frozen_time
            for _ in range(IP_BURST_LIMIT + 5):
                resp = rate_limit_client.post(
                    "/v1/scan/static",
                    json={"code": "x = 1", "filename": "test.py"},
                    headers={"X-API-Key": "ct_pro_test"},
                )
                if resp.status_code == HTTPStatus.TOO_MANY_REQUESTS:
                    assert "retry-after" in resp.headers
                    assert int(resp.headers["retry-after"]) > 0
                    return
        pytest.fail("Expected too-many-requests response")

    def test_oversized_payload_returns_413(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Requests with body > MAX_BODY_SIZE should be rejected."""
        huge_code = "x = 1\n" * (MAX_BODY_SIZE // 5)  # well over 1MB
        resp = rate_limit_client.post(
            "/v1/scan/static",
            json={"code": huge_code, "filename": "huge.py"},
        )
        assert resp.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        assert resp.json()["error"] == "payload_too_large"

    def test_normal_payload_accepted(
        self, rate_limit_client: TestClient,
    ) -> None:
        """Normal-sized requests should pass through."""
        resp = rate_limit_client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "small.py"},
            headers={"X-API-Key": "ct_pro_test"},
        )
        # Should get success or auth failure, but not payload-too-large or rate-limit.
        assert resp.status_code not in (HTTPStatus.REQUEST_ENTITY_TOO_LARGE, HTTPStatus.TOO_MANY_REQUESTS)
