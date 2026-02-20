# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Prometheus metrics middleware and /metrics endpoint.

Tracks request counts, latencies, and active connections for
monitoring via Prometheus scraping or any compatible backend.

Usage:
    from src.middleware.metrics import MetricsMiddleware, metrics_endpoint

    app.add_middleware(MetricsMiddleware)
    app.add_route("/metrics", metrics_endpoint)
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse, Response

if TYPE_CHECKING:
    from starlette.requests import Request


class _MetricsStore:
    """Thread-safe in-process metrics accumulator.

    No external dependencies — generates Prometheus exposition format.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._request_count: dict[tuple[str, str, int], int] = defaultdict(int)
        self._request_duration_sum: dict[tuple[str, str], float] = defaultdict(float)
        self._request_duration_count: dict[tuple[str, str], int] = defaultdict(int)
        self._active_requests = 0
        self._startup_time = time.time()

    def record(self, method: str, path: str, status: int, duration: float) -> None:
        with self._lock:
            key = (method, path, status)
            self._request_count[key] += 1
            dur_key = (method, path)
            self._request_duration_sum[dur_key] += duration
            self._request_duration_count[dur_key] += 1

    def inc_active(self) -> None:
        with self._lock:
            self._active_requests += 1

    def dec_active(self) -> None:
        with self._lock:
            self._active_requests -= 1

    def _render_requests_total(self, lines: list[str]) -> None:
        """Append codetrust_http_requests_total counter lines."""
        lines.append("# HELP codetrust_http_requests_total Total HTTP requests.")
        lines.append("# TYPE codetrust_http_requests_total counter")
        for (method, path, status), count in sorted(self._request_count.items()):
            lines.append(
                f'codetrust_http_requests_total{{method="{method}",'
                f'path="{path}",status="{status}"}} {count}'
            )

    def _render_duration(self, lines: list[str]) -> None:
        """Append codetrust_http_request_duration_seconds summary lines."""
        lines.append("")
        lines.append(
            "# HELP codetrust_http_request_duration_seconds "
            "Request duration in seconds."
        )
        lines.append("# TYPE codetrust_http_request_duration_seconds summary")
        for (method, path), total in sorted(self._request_duration_sum.items()):
            count = self._request_duration_count[(method, path)]
            lines.append(
                f'codetrust_http_request_duration_seconds_sum'
                f'{{method="{method}",path="{path}"}} {total:.6f}'
            )
            lines.append(
                f'codetrust_http_request_duration_seconds_count'
                f'{{method="{method}",path="{path}"}} {count}'
            )

    def _render_gauges(self, lines: list[str]) -> None:
        """Append active-requests and uptime gauge lines."""
        lines.append("")
        lines.append("# HELP codetrust_active_requests Currently active requests.")
        lines.append("# TYPE codetrust_active_requests gauge")
        lines.append(f"codetrust_active_requests {self._active_requests}")

        lines.append("")
        lines.append("# HELP codetrust_uptime_seconds Seconds since server start.")
        lines.append("# TYPE codetrust_uptime_seconds gauge")
        uptime = time.time() - self._startup_time
        lines.append(f"codetrust_uptime_seconds {uptime:.1f}")

    def render(self) -> str:
        """Generate Prometheus exposition format text."""
        lines: list[str] = []

        with self._lock:
            self._render_requests_total(lines)
            self._render_duration(lines)
            self._render_gauges(lines)

        lines.append("")
        return "\n".join(lines)


# Singleton store
_store = _MetricsStore()


def get_metrics_store() -> _MetricsStore:
    """Access the global metrics store (for testing)."""
    return _store


HTTP_INTERNAL_SERVER_ERROR: int = 500


class MetricsMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that records request metrics."""

    async def dispatch(self, request: Request, call_next: object) -> Response:
        # Normalize path to avoid cardinality explosion
        path = _normalize_path(request.url.path)
        method = request.method

        _store.inc_active()
        start = time.monotonic()

        try:
            response = await call_next(request)
            duration = time.monotonic() - start
            _store.record(method, path, response.status_code, duration)
            return response
        except Exception:
            duration = time.monotonic() - start
            _store.record(method, path, HTTP_INTERNAL_SERVER_ERROR, duration)
            raise
        finally:
            _store.dec_active()


async def metrics_endpoint(request: Request) -> PlainTextResponse:
    """Serve Prometheus metrics at /metrics."""
    return PlainTextResponse(
        content=_store.render(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


def _normalize_path(path: str) -> str:
    """Collapse dynamic path segments to reduce metric cardinality.

    /v1/scan/abc123 → /v1/scan/{id}
    /v1/api-keys/some-key → /v1/api-keys/{id}
    """
    parts = path.strip("/").split("/")
    normalized: list[str] = []
    for part in parts:
        # If it looks like an ID (UUID, hex, long alphanumeric), collapse
        if len(part) > 20 or (len(part) > 8 and not part.replace("-", "").isalpha()):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)
