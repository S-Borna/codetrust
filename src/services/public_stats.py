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
            "pypi_downloads_last_day": int(cached.get("pypi_downloads_last_day", 0)),
            "pypi_downloads_last_week": int(cached.get("pypi_downloads_last_week", 0)),
            "pypi_downloads_last_month": int(cached.get("pypi_downloads_last_month", 0)),
        }

    try:
        res = await http_client.get(PYPISTATS_RECENT_URL)
        res.raise_for_status()
        payload = res.json()
        data = payload.get("data", {}) if isinstance(payload, dict) else {}

        result: dict[str, int] = {
            "pypi_downloads_last_day": int(data.get("last_day", 0) or 0),
            "pypi_downloads_last_week": int(data.get("last_week", 0) or 0),
            "pypi_downloads_last_month": int(data.get("last_month", 0) or 0),
        }

        cache_payload: dict[str, JsonScalar] = {
            "pypi_downloads_last_day": result["pypi_downloads_last_day"],
            "pypi_downloads_last_week": result["pypi_downloads_last_week"],
            "pypi_downloads_last_month": result["pypi_downloads_last_month"],
        }
        await cache.set_json(_cache_key("pypi"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError):
        return {
            "pypi_downloads_last_day": 0,
            "pypi_downloads_last_week": 0,
            "pypi_downloads_last_month": 0,
        }


async def get_marketplace_stats(
    http_client: httpx.AsyncClient,
    cache: CacheService,
) -> dict[str, int]:
    """Fetch VS Code Marketplace statistics for the CodeTrust extension.

    Uses the public extension query API.

    Returns dict with keys:
      - marketplace_installs
      - marketplace_downloads
      - marketplace_updates

    Falls back to zeros on any failure.
    """

    cached = await cache.get_json(_cache_key("marketplace"))
    if cached is not None:
        return {
            "marketplace_installs": int(cached.get("marketplace_installs", 0)),
            "marketplace_downloads": int(cached.get("marketplace_downloads", 0)),
            "marketplace_updates": int(cached.get("marketplace_updates", 0)),
        }

    body = {
        "filters": [
            {
                "criteria": [
                    {
                        "filterType": 7,
                        "value": MARKETPLACE_EXTENSION_ID,
                    }
                ]
            }
        ],
        "flags": MARKETPLACE_FLAGS,
    }

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json;api-version=3.0-preview.1",
    }

    try:
        res = await http_client.post(MARKETPLACE_EXTENSION_QUERY_URL, json=body, headers=headers)
        res.raise_for_status()
        payload = res.json()

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
            if isinstance(name, str):
                if value is None:
                    continue
                try:
                    stats_map[name] = int(float(value))
                except (TypeError, ValueError) as exc:
                    logger.debug(
                        "marketplace_stat_parse_failed",
                        statistic_name=name,
                        error=str(exc),
                        error_type=type(exc).__name__,
                    )
                    continue

        result: dict[str, int] = {
            "marketplace_installs": int(stats_map.get("install", 0)),
            "marketplace_downloads": int(stats_map.get("downloadCount", 0)),
            "marketplace_updates": int(stats_map.get("updateCount", 0)),
        }

        cache_payload: dict[str, JsonScalar] = {
            "marketplace_installs": result["marketplace_installs"],
            "marketplace_downloads": result["marketplace_downloads"],
            "marketplace_updates": result["marketplace_updates"],
        }
        await cache.set_json(_cache_key("marketplace"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError, IndexError, KeyError):
        return {
            "marketplace_installs": 0,
            "marketplace_downloads": 0,
            "marketplace_updates": 0,
        }


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
        return {
            "openvsx_downloads": int(cached.get("openvsx_downloads", 0)),
        }

    url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME)
    try:
        res = await http_client.get(url)
        res.raise_for_status()
        payload = res.json()
        download_count = payload.get("downloadCount") if isinstance(payload, dict) else None
        if download_count is None:
            downloads_int = 0
        else:
            try:
                downloads_int = int(float(download_count))
            except (TypeError, ValueError) as exc:
                logger.debug(
                    "openvsx_download_count_parse_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                downloads_int = 0

        result: dict[str, int] = {
            "openvsx_downloads": downloads_int,
        }

        cache_payload: dict[str, JsonScalar] = {
            "openvsx_downloads": downloads_int,
        }
        await cache.set_json(_cache_key("openvsx"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError):
        return {
            "openvsx_downloads": 0,
        }


async def get_pepy_download_stats(
    http_client: httpx.AsyncClient,
    cache: CacheService,
) -> dict[str, int]:
    """Fetch Pepy download stats for the CodeTrust PyPI package.

    Pepy powers the "2.71k" style numbers you see on pepy.tech for a given
    time range (e.g., last 3 months) and can optionally include CI downloads.

    Returns dict with keys:
      - pypi_downloads_last_3_months_ci

    Falls back to zeros on any failure.
    """

    cached = await cache.get_json(_cache_key("pepy"))
    if cached is not None:
        return {
            "pypi_downloads_last_3_months_ci": int(cached.get("pypi_downloads_last_3_months_ci", 0)),
        }

    url = PEPY_PROJECT_URL_TEMPLATE.format(project=PEPY_PROJECT)
    params = {
        "timeRange": "threeMonths",
        "category": "version",
        "includeCIDownloads": "true",
        "granularity": "daily",
        "viewType": "line",
        "versions": settings.version,
    }

    try:
        res = await http_client.get(url, params=params, follow_redirects=True)
        res.raise_for_status()
        html = res.text

        match = _PEPY_TOTAL_DOWNLOADS_RE.search(html)
        downloads = int(match.group(1)) if match else 0

        result: dict[str, int] = {
            "pypi_downloads_last_3_months_ci": downloads,
        }

        cache_payload: dict[str, JsonScalar] = {
            "pypi_downloads_last_3_months_ci": downloads,
        }
        await cache.set_json(_cache_key("pepy"), cache_payload, ttl=CACHE_TTL_SECONDS)
        return result
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.debug("pepy_stats_fetch_failed", error=str(exc), error_type=type(exc).__name__)
        return {
            "pypi_downloads_last_3_months_ci": 0,
        }
