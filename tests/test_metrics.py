"""Tests for Prometheus metrics middleware and metrics store.

Covers: MetricsMiddleware, _MetricsStore, _normalize_path, metrics_endpoint.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse

if TYPE_CHECKING:
    from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from src.middleware.metrics import (
    MetricsMiddleware,
    _MetricsStore,
    _normalize_path,
    get_metrics_store,
    metrics_endpoint,
)

# ---------------------------------------------------------------------------
# _MetricsStore unit tests
# ---------------------------------------------------------------------------


class TestMetricsStore:
    def test_record_increments_counter(self) -> None:
        store = _MetricsStore()
        store.record("GET", "/test", HTTPStatus.OK, 0.05)
        store.record("GET", "/test", HTTPStatus.OK, 0.03)
        assert store._request_count[("GET", "/test", HTTPStatus.OK)] == 2

    def test_record_tracks_duration(self) -> None:
        store = _MetricsStore()
        store.record("POST", "/scan", HTTPStatus.OK, 0.1)
        store.record("POST", "/scan", HTTPStatus.OK, 0.2)
        assert store._request_duration_sum[("POST", "/scan")] == pytest.approx(0.3)
        assert store._request_duration_count[("POST", "/scan")] == 2

    def test_inc_dec_active(self) -> None:
        store = _MetricsStore()
        assert store._active_requests == 0
        store.inc_active()
        store.inc_active()
        assert store._active_requests == 2
        store.dec_active()
        assert store._active_requests == 1

    def test_render_prometheus_format(self) -> None:
        store = _MetricsStore()
        store.record("GET", "/v1/status", HTTPStatus.OK, 0.01)
        output = store.render()
        assert "codetrust_http_requests_total" in output
        assert 'method="GET"' in output
        assert 'path="/v1/status"' in output
        assert 'status="200"' in output
        assert "codetrust_http_request_duration_seconds_sum" in output
        assert "codetrust_http_request_duration_seconds_count" in output
        assert "codetrust_active_requests" in output
        assert "codetrust_uptime_seconds" in output

    def test_render_empty_store(self) -> None:
        store = _MetricsStore()
        output = store.render()
        assert "codetrust_active_requests 0" in output
        assert "codetrust_uptime_seconds" in output

    def test_render_multiple_paths(self) -> None:
        store = _MetricsStore()
        store.record("GET", "/a", HTTPStatus.OK, 0.01)
        store.record("POST", "/b", HTTPStatus.CREATED, 0.02)
        store.record("GET", "/a", HTTPStatus.NOT_FOUND, 0.03)
        output = store.render()
        lines = [line for line in output.split("\n") if line.startswith("codetrust_http_requests_total")]
        assert len(lines) == 3  # 3 distinct (method, path, status) combos

    def test_render_with_500_errors(self) -> None:
        store = _MetricsStore()
        store.record("GET", "/fail", HTTPStatus.INTERNAL_SERVER_ERROR, 1.5)
        output = store.render()
        assert 'status="500"' in output


# ---------------------------------------------------------------------------
# _normalize_path tests
# ---------------------------------------------------------------------------


class TestNormalizePath:
    def test_short_paths_unchanged(self) -> None:
        assert _normalize_path("/v1/status") == "/v1/status"
        assert _normalize_path("/metrics") == "/metrics"

    def test_uuid_collapsed(self) -> None:
        result = _normalize_path("/v1/api-keys/abc123def456ghi789jklmnop")
        assert "{id}" in result

    def test_long_id_collapsed(self) -> None:
        result = _normalize_path("/v1/scan/a1b2c3d4e5f6g7h8i9j0k1l2")
        assert "{id}" in result

    def test_empty_path(self) -> None:
        result = _normalize_path("/")
        assert result == "/"


# ---------------------------------------------------------------------------
# MetricsMiddleware integration tests
# ---------------------------------------------------------------------------


def _test_app():
    async def home(request: Request):
        return JSONResponse({"ok": True})

    async def error(request: Request):
        raise ValueError("boom")

    app = Starlette(
        routes=[
            Route("/", home),
            Route("/error", error),
            Route("/metrics", metrics_endpoint),
        ],
    )
    app.add_middleware(MetricsMiddleware)
    return app


class TestMetricsMiddleware:
    def test_middleware_records_request(self) -> None:
        client = TestClient(_test_app(), raise_server_exceptions=False)
        client.get("/")
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "codetrust_http_requests_total" in resp.text

    def test_middleware_records_500_on_error(self) -> None:
        client = TestClient(_test_app(), raise_server_exceptions=False)
        resp = client.get("/error")
        assert resp.status_code == 500

    def test_metrics_content_type(self) -> None:
        client = TestClient(_test_app(), raise_server_exceptions=False)
        resp = client.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]


# ---------------------------------------------------------------------------
# get_metrics_store accessor
# ---------------------------------------------------------------------------


class TestGetMetricsStore:
    def test_returns_singleton(self) -> None:
        store = get_metrics_store()
        assert isinstance(store, _MetricsStore)
        assert get_metrics_store() is store
