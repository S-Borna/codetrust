"""Public-facing stats aggregation for the website.

Combines:
- Cloud API telemetry (from the database ScanLog table, if configured)
- Distribution signals (PyPI downloads, VS Code Marketplace installs/downloads, Open VSX downloads)

All external calls are cached (Redis when available) to avoid rate limits.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

import httpx
import structlog

from src.config import settings

if TYPE_CHECKING:
    from src.services.cache import CacheService

logger = structlog.get_logger()

JsonScalar = str | bool | int | float

PYPISTATS_RECENT_URL: str = "https://pypistats.org/api/packages/codetrust/recent"
MARKETPLACE_EXTENSION_QUERY_URL: str = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
OPEN_VSX_EXTENSION_URL_TEMPLATE: str = "https://open-vsx.org/api/{namespace}/{name}"

PEPY_PROJECT_URL_TEMPLATE: str = "https://pepy.tech/projects/{project}"
PEPY_PROJECT: str = "codetrust"

MARKETPLACE_EXTENSION_ID: str = "SaidBorna.codetrust"
MARKETPLACE_FLAGS: int = 914

OPEN_VSX_NAMESPACE: str = "SaidBorna"
OPEN_VSX_EXTENSION_NAME: str = "codetrust"

CACHE_TTL_SECONDS: int = 900  # 15 minutes
CACHE_KEY_PREFIX: str = "codetrust:public_stats:"

_PEPY_TOTAL_DOWNLOADS_RE: re.Pattern[str] = re.compile(r'\\?"totalDownloads\\?"\s*:\s*(\d+)')


def _cache_key(name: str) -> str:
    """Return the Redis cache key for a public-stats subpayload."""

    return f"{CACHE_KEY_PREFIX}{name}"


async def _fetch_pypi_from_api(
    http_client: httpx.AsyncClient,
) -> dict[str, int]:
    """Fetch and parse PyPI download data from the API."""
    res = await http_client.get(PYPISTATS_RECENT_URL)
    res.raise_for_status()
    payload = res.json()
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    return {
        "pypi_downloads_last_day": int(data.get("last_day", 0) or 0),
        "pypi_downloads_last_week": int(data.get("last_week", 0) or 0),
        "pypi_downloads_last_month": int(data.get("last_month", 0) or 0),
    }


_PYPI_ZERO_RESULT: dict[str, int] = {
    "pypi_downloads_last_day": 0,
    "pypi_downloads_last_week": 0,
    "pypi_downloads_last_month": 0,
}


async def get_pypi_download_stats(
    http_client: httpx.AsyncClient,
    cache: CacheService,
) -> dict[str, int]:
    """Fetch PyPI download stats from pypistats.org.

    Returns dict with keys:
      - pypi_downloads_last_day
      - pypi_downloads_last_week
      - pypi_downloads_last_month

    Falls back to zeros on any failure.
    """
    cached = await cache.get_json(_cache_key("pypi"))
    if cached is not None:
        return {
            k: int(cached.get(k, 0)) for k in _PYPI_ZERO_RESULT
        }

    try:
        result = await _fetch_pypi_from_api(http_client)
        cache_payload: dict[str, JsonScalar] = {k: v for k, v in result.items()}
        await cache.set_json(_cache_key("pypi"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError):
        return dict(_PYPI_ZERO_RESULT)


_MARKETPLACE_ZERO_RESULT: dict[str, int] = {
    "marketplace_installs": 0,
    "marketplace_downloads": 0,
    "marketplace_updates": 0,
}


def _parse_marketplace_statistics(
    payload: dict[str, object],
) -> dict[str, int]:
    """Parse VS Code Marketplace extension query response into stats."""
    results = payload.get("results", []) if isinstance(payload, dict) else []
    extensions = results[0].get("extensions", []) if results else []
    ext = extensions[0] if extensions else {}

    stats_list = ext.get("statistics", []) if isinstance(ext, dict) else []
    stats_map: dict[str, int] = {}
    for item in stats_list:
        if not isinstance(item, dict):
            continue
        name = item.get("statisticName")
        value = item.get("value")
        if isinstance(name, str) and value is not None:
            try:
                stats_map[name] = int(float(value))
            except (TypeError, ValueError) as exc:
                logger.debug(
                    "marketplace_stat_parse_failed",
                    statistic_name=name,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
    return {
        "marketplace_installs": int(stats_map.get("install", 0)),
        "marketplace_downloads": int(stats_map.get("downloadCount", 0)),
        "marketplace_updates": int(stats_map.get("updateCount", 0)),
    }


async def get_marketplace_stats(
    http_client: httpx.AsyncClient,
    cache: CacheService,
) -> dict[str, int]:
    """Fetch VS Code Marketplace install/download statistics."""
    cached = await cache.get_json(_cache_key("marketplace"))
    if cached is not None:
        return {k: int(cached.get(k, 0)) for k in _MARKETPLACE_ZERO_RESULT}

    body = {
        "filters": [
            {"criteria": [{"filterType": 7, "value": MARKETPLACE_EXTENSION_ID}]}
        ],
        "flags": MARKETPLACE_FLAGS,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json;api-version=3.0-preview.1",
    }

    try:
        res = await http_client.post(
            MARKETPLACE_EXTENSION_QUERY_URL, json=body, headers=headers,
        )
        res.raise_for_status()
        result = _parse_marketplace_statistics(res.json())
        cache_payload: dict[str, JsonScalar] = {k: v for k, v in result.items()}
        await cache.set_json(
            _cache_key("marketplace"), cache_payload, ttl=CACHE_TTL_SECONDS,
        )
        return result
    except (httpx.HTTPError, ValueError, TypeError, IndexError, KeyError):
        return dict(_MARKETPLACE_ZERO_RESULT)


def _parse_openvsx_download_count(payload: dict[str, object]) -> int:
    """Parse download count from Open VSX API response."""
    download_count = payload.get("downloadCount") if isinstance(payload, dict) else None
    if download_count is None:
        return 0
    try:
        return int(float(download_count))
    except (TypeError, ValueError) as exc:
        logger.debug(
            "openvsx_download_count_parse_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return 0


async def get_open_vsx_stats(
    http_client: httpx.AsyncClient,
    cache: CacheService,
) -> dict[str, int]:
    """Fetch Open VSX statistics for the CodeTrust extension.

    Returns dict with keys:
      - openvsx_downloads

    Falls back to zeros on any failure.
    """
    cached = await cache.get_json(_cache_key("openvsx"))
    if cached is not None:
        return {"openvsx_downloads": int(cached.get("openvsx_downloads", 0))}

    url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(
        namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME,
    )
    try:
        res = await http_client.get(url)
        res.raise_for_status()
        downloads_int = _parse_openvsx_download_count(res.json())

        result: dict[str, int] = {"openvsx_downloads": downloads_int}
        cache_payload: dict[str, JsonScalar] = {"openvsx_downloads": downloads_int}
        await cache.set_json(_cache_key("openvsx"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError):
        return {"openvsx_downloads": 0}


async def _fetch_pepy_downloads(
    http_client: httpx.AsyncClient,
) -> int:
    """Fetch total downloads from pepy.tech page."""
    url = PEPY_PROJECT_URL_TEMPLATE.format(project=PEPY_PROJECT)
    params = {
        "timeRange": "threeMonths",
        "category": "version",
        "includeCIDownloads": "true",
        "granularity": "daily",
        "viewType": "line",
        "versions": settings.version,
    }
    res = await http_client.get(url, params=params, follow_redirects=True)
    res.raise_for_status()
    match = _PEPY_TOTAL_DOWNLOADS_RE.search(res.text)
    return int(match.group(1)) if match else 0


async def get_pepy_download_stats(
    http_client: httpx.AsyncClient,
    cache: CacheService,
) -> dict[str, int]:
    """Fetch Pepy download stats for the CodeTrust PyPI package.

    Returns dict with keys:
      - pypi_downloads_last_3_months_ci

    Falls back to zeros on any failure.
    """
    cached = await cache.get_json(_cache_key("pepy"))
    if cached is not None:
        return {
            "pypi_downloads_last_3_months_ci": int(
                cached.get("pypi_downloads_last_3_months_ci", 0)
            ),
        }

    try:
        downloads = await _fetch_pepy_downloads(http_client)
        result: dict[str, int] = {"pypi_downloads_last_3_months_ci": downloads}
        cache_payload: dict[str, JsonScalar] = {
            "pypi_downloads_last_3_months_ci": downloads,
        }
        await cache.set_json(_cache_key("pepy"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.debug("pepy_stats_fetch_failed", error=str(exc), error_type=type(exc).__name__)
        return {"pypi_downloads_last_3_months_ci": 0}
