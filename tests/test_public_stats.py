import httpx
import pytest

from src.config import settings
from src.services.cache import CacheService
from src.services.public_stats import (
    MARKETPLACE_EXTENSION_QUERY_URL,
    OPEN_VSX_EXTENSION_NAME,
    OPEN_VSX_EXTENSION_URL_TEMPLATE,
    OPEN_VSX_NAMESPACE,
    PEPY_PROJECT,
    PEPY_PROJECT_URL_TEMPLATE,
    PYPISTATS_RECENT_URL,
    get_marketplace_stats,
    get_open_vsx_stats,
    get_pepy_download_stats,
    get_pypi_download_stats,
)


@pytest.mark.asyncio
async def test_get_pypi_download_stats_parses_and_caches(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
    httpx_mock,
) -> None:
    httpx_mock.add_response(
        method="GET",
        url=PYPISTATS_RECENT_URL,
        json={"data": {"last_day": 1, "last_week": 7, "last_month": 30}},
    )

    first = await get_pypi_download_stats(http_client=mock_http_client, cache=fake_cache)
    assert first == {
        "pypi_downloads_last_day": 1,
        "pypi_downloads_last_week": 7,
        "pypi_downloads_last_month": 30,
    }

    # Cached path (no second HTTP response registered)
    second = await get_pypi_download_stats(http_client=mock_http_client, cache=fake_cache)
    assert second == first


@pytest.mark.asyncio
async def test_get_marketplace_stats_parses_statistics(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
    httpx_mock,
) -> None:
    httpx_mock.add_response(
        method="POST",
        url=MARKETPLACE_EXTENSION_QUERY_URL,
        json={
            "results": [
                {
                    "extensions": [
                        {
                            "statistics": [
                                {"statisticName": "install", "value": 4.0},
                                {"statisticName": "downloadCount", "value": 89.0},
                                {"statisticName": "updateCount", "value": 8.0},
                            ]
                        }
                    ]
                }
            ]
        },
    )

    stats = await get_marketplace_stats(http_client=mock_http_client, cache=fake_cache)
    assert stats == {
        "marketplace_installs": 4,
        "marketplace_downloads": 89,
        "marketplace_updates": 8,
    }


@pytest.mark.asyncio
async def test_get_open_vsx_stats_parses_download_count(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
    httpx_mock,
) -> None:
    url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME)
    httpx_mock.add_response(method="GET", url=url, json={"downloadCount": 2710})

    stats = await get_open_vsx_stats(http_client=mock_http_client, cache=fake_cache)
    assert stats == {"openvsx_downloads": 2710}


@pytest.mark.asyncio
async def test_get_open_vsx_stats_404_falls_back_to_zero(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
    httpx_mock,
) -> None:
    url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME)
    httpx_mock.add_response(method="GET", url=url, status_code=404, json={"error": "not found"})

    stats = await get_open_vsx_stats(http_client=mock_http_client, cache=fake_cache)
    assert stats == {"openvsx_downloads": 0}


@pytest.mark.asyncio
async def test_get_pepy_download_stats_parses_total_downloads(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
    httpx_mock,
) -> None:
    base_url = PEPY_PROJECT_URL_TEMPLATE.format(project=PEPY_PROJECT)
    url = str(
        httpx.URL(base_url).copy_merge_params(
            {
                "timeRange": "threeMonths",
                "category": "version",
                "includeCIDownloads": "true",
                "granularity": "daily",
                "viewType": "line",
                "versions": settings.version,
            }
        )
    )
    httpx_mock.add_response(
        method="GET",
        url=url,
        text='<!doctype html><script>self.__next_f.push([1,"{\\"totalDownloads\\":2712}"])</script>',
    )

    stats = await get_pepy_download_stats(http_client=mock_http_client, cache=fake_cache)
    assert stats == {"pypi_downloads_last_3_months_ci": 2712}

