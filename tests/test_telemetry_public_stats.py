import httpx
import pytest

from src.config import settings
from src.services.cache import CacheService
from src.services.telemetry import (
    MARKETPLACE_EXTENSION_QUERY_URL,
    OPEN_VSX_EXTENSION_NAME,
    OPEN_VSX_EXTENSION_URL_TEMPLATE,
    OPEN_VSX_NAMESPACE,
    PEPY_PROJECT,
    PEPY_PROJECT_URL_TEMPLATE,
    PYPI_RECENT_URL,
    build_public_stats,
    fetch_external_stats,
)


@pytest.mark.asyncio
async def test_fetch_external_stats_populates_distribution_keys(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
    httpx_mock,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    httpx_mock.add_response(
        method="GET",
        url=PYPI_RECENT_URL,
        json={"data": {"last_day": 11, "last_week": 881, "last_month": 881}},
    )

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

    open_vsx_url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(
        namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME
    )
    httpx_mock.add_response(method="GET", url=open_vsx_url, json={"downloadCount": 2710})

    pepy_base_url = PEPY_PROJECT_URL_TEMPLATE.format(project=PEPY_PROJECT)
    pepy_url = str(
        httpx.URL(pepy_base_url).copy_merge_params(
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
        url=pepy_url,
        text='<!doctype html><script>self.__next_f.push([1,"{\\"totalDownloads\\":2712}"])</script>',
    )

    await fetch_external_stats(r, mock_http_client)

    assert await r.get("ct:ext:pypi_last_day") == "11"
    assert await r.get("ct:ext:pypi_last_week") == "881"
    assert await r.get("ct:ext:pypi_last_month") == "881"

    assert await r.get("ct:ext:marketplace_installs") == "4"
    assert await r.get("ct:ext:marketplace_downloads") == "89"
    assert await r.get("ct:ext:marketplace_updates") == "8"

    assert await r.get("ct:ext:openvsx_downloads") == "2710"

    assert await r.get("ct:ext:pepy_3m_ci_downloads") == "2712"


@pytest.mark.asyncio
async def test_build_public_stats_includes_open_vsx_distribution(
    fake_cache: CacheService,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    # Seed minimal counters and external distribution stats.
    await r.set("ct:total_scans", "3")
    await r.set("ct:hallucinations_caught", "2")
    await r.set("ct:gateway_blocks", "1")

    await r.set("ct:ext:pypi_last_week", "881")
    await r.set("ct:ext:marketplace_installs", "4")
    await r.set("ct:ext:marketplace_downloads", "89")
    await r.set("ct:ext:openvsx_downloads", "2710")
    await r.set("ct:ext:pepy_3m_ci_downloads", "2712")

    stats = await build_public_stats(r=r, use_cache=False)

    distribution = stats.get("distribution")
    assert isinstance(distribution, dict)
    assert (distribution.get("open_vsx") or {}).get("downloads") == 2710

    pypi = distribution.get("pypi") or {}
    assert isinstance(pypi, dict)
    assert pypi.get("downloads_last_3_months_ci") == 2712

    impact = stats.get("impact")
    assert isinstance(impact, dict)
    assert impact.get("hallucinations_caught") == 2
    assert impact.get("gateway_commands_blocked") == 1
