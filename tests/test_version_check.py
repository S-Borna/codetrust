# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for client version enforcement middleware."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.middleware.version_check import (
    CLIENT_VERSION_HEADER,
    HTTP_UPGRADE_REQUIRED,
    VersionEnforcementMiddleware,
    _is_version_below,
    _parse_version,
)

# --- Unit tests for version parsing ---


class TestParseVersion:
    """Tests for _parse_version helper."""

    def test_standard_semver(self) -> None:
        """Parse standard 3-part version."""
        assert _parse_version("2.6.1") == (2, 6, 1)

    def test_two_part(self) -> None:
        """Parse 2-part version."""
        assert _parse_version("2.6") == (2, 6)

    def test_single_part(self) -> None:
        """Parse single number version."""
        assert _parse_version("3") == (3,)

    def test_prerelease_stripped(self) -> None:
        """Pre-release suffix should be stripped."""
        assert _parse_version("2.6.1-beta.1") == (2, 6, 1)

    def test_build_metadata_stripped(self) -> None:
        """Build metadata should be stripped."""
        assert _parse_version("2.6.1+build123") == (2, 6, 1)

    def test_empty_string(self) -> None:
        """Empty string returns default."""
        assert _parse_version("") == (0, 0, 0)

    def test_nonsense(self) -> None:
        """Non-numeric input returns default."""
        assert _parse_version("abc") == (0, 0, 0)


class TestIsVersionBelow:
    """Tests for _is_version_below comparator."""

    def test_below(self) -> None:
        """2.6.0 is below 2.6.1."""
        assert _is_version_below("2.6.0", "2.6.1") is True

    def test_equal(self) -> None:
        """Equal versions are not below."""
        assert _is_version_below("2.6.1", "2.6.1") is False

    def test_above(self) -> None:
        """2.7.0 is not below 2.6.1."""
        assert _is_version_below("2.7.0", "2.6.1") is False

    def test_major_below(self) -> None:
        """1.9.9 is below 2.0.0."""
        assert _is_version_below("1.9.9", "2.0.0") is True

    def test_major_above(self) -> None:
        """3.0.0 is not below 2.6.1."""
        assert _is_version_below("3.0.0", "2.6.1") is False


# --- Integration tests with Starlette test client ---


def _make_app(min_version: str = "2.6.1") -> Starlette:
    """Create a test app with the version enforcement middleware."""

    async def ok_endpoint(request: object) -> JSONResponse:
        """Simple OK endpoint."""
        return JSONResponse({"status": "ok"})

    async def health_endpoint(request: object) -> JSONResponse:
        """Health check endpoint."""
        return JSONResponse({"status": "healthy"})

    app = Starlette(
        routes=[
            Route("/v1/scan", ok_endpoint),
            Route("/health", health_endpoint),
        ],
    )
    app.add_middleware(VersionEnforcementMiddleware, min_version=min_version)
    return app


class TestVersionEnforcementMiddleware:
    """Integration tests for the middleware."""

    def test_no_header_allowed(self) -> None:
        """Requests without X-Client-Version should pass (browser, curl)."""
        client = TestClient(_make_app())
        resp = client.get("/v1/scan")
        assert resp.status_code == 200

    def test_current_version_allowed(self) -> None:
        """Requests with current version should pass."""
        client = TestClient(_make_app())
        resp = client.get("/v1/scan", headers={CLIENT_VERSION_HEADER: "2.6.1"})
        assert resp.status_code == 200

    def test_newer_version_allowed(self) -> None:
        """Requests with newer version should pass."""
        client = TestClient(_make_app())
        resp = client.get("/v1/scan", headers={CLIENT_VERSION_HEADER: "3.0.0"})
        assert resp.status_code == 200

    def test_old_version_rejected(self) -> None:
        """Requests with old version should get 426."""
        client = TestClient(_make_app())
        resp = client.get("/v1/scan", headers={CLIENT_VERSION_HEADER: "2.5.2"})
        assert resp.status_code == HTTP_UPGRADE_REQUIRED
        body = resp.json()
        assert body["error"] == "upgrade_required"
        assert "2.5.2" in body["message"]
        assert body["min_version"] == "2.6.1"

    def test_v260_rejected(self) -> None:
        """The broken v2.6.0 should also be rejected."""
        client = TestClient(_make_app())
        resp = client.get("/v1/scan", headers={CLIENT_VERSION_HEADER: "2.6.0"})
        assert resp.status_code == HTTP_UPGRADE_REQUIRED

    def test_exempt_path_passes(self) -> None:
        """Health endpoint should pass regardless of version."""
        client = TestClient(_make_app())
        resp = client.get("/health", headers={CLIENT_VERSION_HEADER: "1.0.0"})
        assert resp.status_code == 200

    def test_upgrade_response_has_command(self) -> None:
        """426 response should include upgrade command."""
        client = TestClient(_make_app())
        resp = client.get("/v1/scan", headers={CLIENT_VERSION_HEADER: "2.5.0"})
        body = resp.json()
        assert body["upgrade_command"] == "pip install --upgrade codetrust"

    def test_custom_min_version(self) -> None:
        """Middleware respects custom min_version."""
        client = TestClient(_make_app(min_version="3.0.0"))
        resp = client.get("/v1/scan", headers={CLIENT_VERSION_HEADER: "2.6.1"})
        assert resp.status_code == HTTP_UPGRADE_REQUIRED
