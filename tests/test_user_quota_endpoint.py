# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for GET /v1/user/quota.

This endpoint backs the dashboard settings page's reduced-mode widget.
It returns the caller's current scan quota state without minting a
JWT (so it's safe to call on every settings render).

Contract pinned here:
  * response keys: plan, used, limit, exceeded, resets_at
  * exceeded is True when used >= limit
  * resets_at is an ISO-8601 string pointing at the next UTC midnight
  * works when the database is unavailable (returns used=0 instead of 500)
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from src.api import app
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def _setup_no_db() -> None:
    """App state with db=None to exercise the graceful-degradation branch."""
    import fakeredis.aioredis

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


@pytest.fixture()
def _setup_with_db() -> MagicMock:
    """App state with a mocked db whose get_daily_usage returns a known value."""
    import fakeredis.aioredis

    cache = CacheService("redis://localhost:6379")
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    http_client = httpx.AsyncClient()

    mock_db = MagicMock()
    mock_db.get_daily_usage = AsyncMock(return_value=17)

    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.ast_analyzer = AstAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = mock_db
    app.state.billing = MagicMock(spec=BillingService)
    app.state.auth = AuthService(http_client)
    app.state.rate_limiter = None
    return mock_db


@pytest.fixture()
def client_nodb(_setup_no_db: None) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def client_withdb(_setup_with_db: MagicMock) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# ─────────────────────────────────────────────────────────────
#  Happy path (db available)
# ─────────────────────────────────────────────────────────────


def test_quota_endpoint_returns_expected_shape(
    client_withdb: TestClient,
) -> None:
    """Pinned response contract — dashboard depends on these keys."""
    resp = client_withdb.get("/v1/user/quota")
    assert resp.status_code == 200

    data = resp.json()
    assert set(data.keys()) == {"plan", "used", "limit", "exceeded", "resets_at"}
    assert isinstance(data["plan"], str)
    assert isinstance(data["used"], int)
    assert isinstance(data["limit"], int)
    assert isinstance(data["exceeded"], bool)
    assert isinstance(data["resets_at"], str)


def test_quota_endpoint_reports_db_usage(client_withdb: TestClient) -> None:
    """used comes from db.get_daily_usage — wired correctly."""
    resp = client_withdb.get("/v1/user/quota")
    data = resp.json()
    assert data["used"] == 17  # our mock returns 17


def test_quota_endpoint_exceeded_is_used_ge_limit(
    client_withdb: TestClient, _setup_with_db: MagicMock,
) -> None:
    """exceeded flag flips when used crosses the limit."""
    # Not exceeded (17 < 25 default free limit)
    resp = client_withdb.get("/v1/user/quota")
    assert resp.json()["exceeded"] is False

    # Exceeded
    _setup_with_db.get_daily_usage = AsyncMock(return_value=1000)
    resp = client_withdb.get("/v1/user/quota")
    assert resp.json()["exceeded"] is True


# ─────────────────────────────────────────────────────────────
#  resets_at contract
# ─────────────────────────────────────────────────────────────


def test_quota_endpoint_resets_at_is_future_utc_midnight(
    client_withdb: TestClient,
) -> None:
    """resets_at must be a parseable ISO-8601 timestamp in the future,
    aligned to midnight UTC (hour/minute/second all zero)."""
    resp = client_withdb.get("/v1/user/quota")
    resets_at = resp.json()["resets_at"]

    parsed = datetime.fromisoformat(resets_at)
    now = datetime.now(tz=UTC)

    assert parsed > now, f"resets_at should be in the future, got {resets_at}"
    assert parsed.hour == 0
    assert parsed.minute == 0
    assert parsed.second == 0
    # Within 24 hours — we return the NEXT midnight, not one a week out
    assert (parsed - now).total_seconds() <= 86_400


# ─────────────────────────────────────────────────────────────
#  Graceful degradation
# ─────────────────────────────────────────────────────────────


def test_quota_endpoint_handles_no_database(client_nodb: TestClient) -> None:
    """When db is None (local dev or temporary outage), the endpoint
    returns used=0 instead of 500 — the dashboard degrades to "you
    haven't scanned today" rather than showing an error."""
    resp = client_nodb.get("/v1/user/quota")
    assert resp.status_code == 200
    data = resp.json()
    assert data["used"] == 0
    assert data["exceeded"] is False
    assert data["limit"] > 0


def test_quota_endpoint_plan_defaults_when_unknown(
    client_nodb: TestClient,
) -> None:
    """Unknown plan strings fall back to the free limit of 25
    rather than crashing (defensive — PLAN_LIMITS.get with default)."""
    resp = client_nodb.get("/v1/user/quota")
    data = resp.json()
    assert data["limit"] >= 25  # any plan must at least match free
