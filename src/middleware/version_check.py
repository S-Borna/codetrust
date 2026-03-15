# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Client version advisory middleware.

Never blocks requests. It logs warnings for missing/outdated client versions
and adds a response header when an upgrade is recommended.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from starlette.middleware.base import BaseHTTPMiddleware

if TYPE_CHECKING:
    from starlette.requests import Request
    from starlette.responses import Response

logger = structlog.get_logger()

# Header name clients must send
CLIENT_VERSION_HEADER: str = "X-Client-Version"

# Paths exempt from version check (health, public info, upgrade endpoint)
VERSION_CHECK_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/",
    "/health",
    "/v1/health",
    "/v1/stats/public",
    "/v1/license/validate",
    "/docs",
    "/openapi.json",
    "/metrics",
})

API_KEY_HEADER: str = "X-API-Key"
UPGRADE_AVAILABLE_HEADER: str = "X-CodeTrust-Upgrade-Available"


def _parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a semver string into a comparable tuple.

    Handles formats like '2.6.1', '2.6.1-beta', etc.
    Non-numeric segments are stripped.
    """
    clean = version_str.split("-")[0].split("+")[0]
    parts: list[int] = []
    for segment in clean.split("."):
        try:
            parts.append(int(segment))
        except ValueError:
            break
    return tuple(parts) if parts else (0, 0, 0)


def _is_version_below(
    client_version: str,
    min_version: str,
) -> bool:
    """Check if client_version is strictly below min_version."""
    return _parse_version(client_version) < _parse_version(min_version)


class VersionEnforcementMiddleware(BaseHTTPMiddleware):
    """Advise on minimum client version for authenticated requests only."""

    def __init__(self, app: object, min_version: str = "2.6.1") -> None:
        """Initialize with minimum required version."""
        super().__init__(app)
        self.min_version = min_version

    async def dispatch(
        self,
        request: Request,
        call_next: object,
    ) -> Response:
        """Log advisory warnings and annotate response if upgrade is needed."""
        path = request.url.path

        # Exempt paths always pass
        if path in VERSION_CHECK_EXEMPT_PATHS:
            return await call_next(request)

        api_key = request.headers.get(API_KEY_HEADER, "").strip()
        if not api_key:
            return await call_next(request)

        client_version = request.headers.get(CLIENT_VERSION_HEADER)
        if not client_version:
            logger.warning(
                "client_version_missing",
                path=path,
                min_version=self.min_version,
            )
            return await call_next(request)

        response = await call_next(request)
        if _is_version_below(client_version, self.min_version):
            logger.warning(
                "client_version_outdated",
                client_version=client_version,
                min_version=self.min_version,
                path=path,
            )
            response.headers[UPGRADE_AVAILABLE_HEADER] = "true"

        return response
