# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Client version enforcement middleware.

Rejects API requests from clients below the minimum supported version.
This forces old installations to upgrade, addressing security and IP concerns.

Returns HTTP 426 Upgrade Required with upgrade instructions.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from starlette.requests import Request

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

# HTTP status for upgrade required
HTTP_UPGRADE_REQUIRED: int = 426


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
    """Enforce minimum client version on API requests.

    Clients must send X-Client-Version header. Requests from clients
    below min_client_version get HTTP 426 Upgrade Required.

    Exempt paths (health, docs, etc.) are always allowed.
    Requests without the header are allowed (browser, curl, etc.).
    """

    def __init__(self, app: object, min_version: str = "2.6.1") -> None:
        """Initialize with minimum required version."""
        super().__init__(app)
        self.min_version = min_version

    async def dispatch(
        self,
        request: Request,
        call_next: object,
    ) -> Response:
        """Check client version before processing request."""
        path = request.url.path

        # Exempt paths always pass
        if path in VERSION_CHECK_EXEMPT_PATHS:
            return await call_next(request)

        # No version header = non-CLI client (browser, curl) — allow
        client_version = request.headers.get(CLIENT_VERSION_HEADER)
        if not client_version:
            return await call_next(request)

        # Check version
        if _is_version_below(client_version, self.min_version):
            logger.warning(
                "client_version_rejected",
                client_version=client_version,
                min_version=self.min_version,
                path=path,
            )
            return JSONResponse(
                status_code=HTTP_UPGRADE_REQUIRED,
                content={
                    "error": "upgrade_required",
                    "message": (
                        f"Client version {client_version} is no longer supported. "
                        f"Minimum required: {self.min_version}. "
                        f"Run: pip install --upgrade codetrust"
                    ),
                    "min_version": self.min_version,
                    "upgrade_command": "pip install --upgrade codetrust",
                },
            )

        return await call_next(request)
