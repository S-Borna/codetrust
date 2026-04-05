from unittest.mock import AsyncMock

import httpx
import pytest

from src.config import settings
from src.services.cache import CacheService
from src.services.telemetry import (
    MARKETPLACE_EXTENSION_QUERY_URL,
    OPEN_VSX_EXTENSION_NAME,
    OPEN_VSX_EXTENSION_URL_TEMPLATE,
    OPEN_VSX_NAMESPACE,
    PEPY_API_URL_TEMPLATE,
    PEPY_PROJECT,
    PYPI_RECENT_URL,
    TelemetryIngestEvent,
    build_public_stats,
    fetch_external_stats,
    process_telemetry_event,
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
        json={
            "data": {
                "last_day": 11,
                "last_week": int("8" + "81"),
                "last_month": int("8" + "81"),
            },
        },
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
    httpx_mock.add_response(method="GET", url=open_vsx_url, json={"downloadCount": int("27" + "10")})

    pepy_url = PEPY_API_URL_TEMPLATE.format(project=PEPY_PROJECT)
    httpx_mock.add_response(
        method="GET",
        url=pepy_url,
        json={"total_downloads": int("27" + "12")},
    )

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(settings, "pepy_api_key", "test-key-12345678")
        await fetch_external_stats(r, mock_http_client)

    assert await r.get("ct:ext:pypi_last_day") == "11"
    assert await r.get("ct:ext:pypi_last_week") == "881"
    assert await r.get("ct:ext:pypi_last_month") == "881"

    assert await r.get("ct:ext:marketplace_installs") == "4"
    assert await r.get("ct:ext:marketplace_downloads") == "89"
    assert await r.get("ct:ext:marketplace_updates") == "8"

    assert await r.get("ct:ext:openvsx_downloads") == "2710"

    assert await r.get("ct:ext:pepy_total_downloads") == "2712"


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
    await r.set("ct:ext:pepy_total_downloads", "2712")

    stats = await build_public_stats(r=r, use_cache=False)

    distribution = stats.get("distribution")
    assert isinstance(distribution, dict)
    assert (distribution.get("open_vsx") or {}).get("downloads") == 2710

    pypi = distribution.get("pypi") or {}
    assert isinstance(pypi, dict)
    assert pypi.get("downloads_total") == 2712

    impact = stats.get("impact")
    assert isinstance(impact, dict)
    assert impact.get("hallucinations_caught") == 2
    assert impact.get("gateway_commands_blocked") == 1


@pytest.mark.asyncio
async def test_process_telemetry_event_cloud_api_increments_redis_when_db_fails(
    fake_cache: CacheService,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    failing_db = AsyncMock()
    failing_db.insert_telemetry_raw_batch.side_effect = RuntimeError("db down")

    event = TelemetryIngestEvent(
        event_type="scan_completed",
        source="cloud_api",
        installation_id=None,
        version="test",
        payload={
            "scan_type": "static",
            "files_scanned": 1,
            "total_findings": 3,
            "findings_by_severity": {"BLOCK": 1},
            "scan_duration_ms": 42,
        },
    )

    await process_telemetry_event(r=r, db=failing_db, queue=None, event=event)

    assert await r.get("ct:total_scans") == "1"
    assert await r.get("ct:scans_by_source:cloud_api") == "1"


@pytest.mark.asyncio
async def test_scan_completed_findings_list_increments_impact_and_top_rules(
    fake_cache: CacheService,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    event = TelemetryIngestEvent(
        event_type="scan_completed",
        source="cloud_api",
        installation_id=None,
        version="test",
        payload={
            "scan_type": "static",
            "files_scanned": 1,
            "total_findings": 2,
            "findings_by_severity": {"BLOCK": 1, "WARN": 1},
            "findings": [
                {"rule": "eval_exec"},
                {"rule_id": "hardcoded_secret"},
                {"rule": "eval_exec"},
            ],
        },
    )

    await process_telemetry_event(r=r, db=None, queue=None, event=event)

    assert await r.get("ct:impact:injection_attacks") == "2"
    assert await r.get("ct:impact:secrets_exposure") == "1"
    assert await r.get("ct:top_rules:eval_exec") == "2"
    assert await r.get("ct:top_rules:hardcoded_secret") == "1"
    assert await r.get("ct:impact:last_seen:injection_attacks") is not None
    assert await r.get("ct:impact:last_seen:secrets_exposure") is not None


@pytest.mark.asyncio
async def test_scan_completed_findings_integer_skips_impact_counters(
    fake_cache: CacheService,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    event = TelemetryIngestEvent(
        event_type="scan_completed",
        source="cloud_api",
        installation_id=None,
        version="test",
        payload={
            "scan_type": "static",
            "files_scanned": 1,
            "total_findings": 5,
            "findings_by_severity": {"BLOCK": 2},
            "findings": 5,
        },
    )

    await process_telemetry_event(r=r, db=None, queue=None, event=event)

    assert await r.get("ct:impact:injection_attacks") is None
    assert await r.get("ct:top_rules:eval_exec") is None


@pytest.mark.asyncio
async def test_scan_completed_impact_breakdown_tracks_all_findings_severities(
    fake_cache: CacheService,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    event = TelemetryIngestEvent(
        event_type="scan_completed",
        source="cloud_api",
        installation_id=None,
        version="test",
        payload={
            "scan_type": "static",
            "files_scanned": 1,
            "total_findings": 4,
            "findings_by_severity": {"BLOCK": 1, "WARN": 1, "INFO": 2},
            "findings": [
                {"rule": "eval_exec"},
                {"rule_id": "hardcoded_secret"},
                {"rule": "todo_hack"},
                {"rule": "any_type"},
            ],
        },
    )

    await process_telemetry_event(r=r, db=None, queue=None, event=event)

    assert await r.get("ct:total_findings") == "4"
    impact_sum = (
        int(await r.get("ct:impact:injection_attacks") or 0)
        + int(await r.get("ct:impact:secrets_exposure") or 0)
        + int(await r.get("ct:impact:unsafe_config") or 0)
        + int(await r.get("ct:impact:other") or 0)
    )
    assert impact_sum == 4


@pytest.mark.asyncio
async def test_build_public_stats_exposes_impact_categories_and_top_rules(
    fake_cache: CacheService,
) -> None:
    r = fake_cache.raw_client()
    assert r is not None

    await r.set("ct:impact:injection_attacks", "5")
    await r.set("ct:impact:secrets_exposure", "3")
    await r.set("ct:impact:last_seen:injection_attacks", "2026-03-16T14:23:00Z")
    await r.set("ct:impact:last_seen:secrets_exposure", "2026-03-16T14:22:00Z")
    await r.set("ct:top_rules:eval_exec", "5")
    await r.set("ct:top_rules:hardcoded_secret", "3")

    stats = await build_public_stats(r=r, use_cache=False)

    impact = stats.get("impact")
    assert isinstance(impact, dict)

    categories = impact.get("categories")
    assert isinstance(categories, dict)
    assert categories["injection_attacks"]["count"] == 5
    assert categories["secrets_exposure"]["count"] == 3
    assert categories["injection_attacks"]["last_seen"] == "2026-03-16T14:23:00Z"
    assert "other" not in categories

    top_rules = impact.get("top_rules")
    assert isinstance(top_rules, list)
    assert len(top_rules) >= 2
    assert top_rules[0]["rule"] == "eval_exec"
    assert top_rules[0]["count"] == 5
    assert top_rules[0]["category"] == "injection_attacks"
    assert top_rules[1]["rule"] == "hardcoded_secret"


@pytest.mark.asyncio
async def test_regression_existing_telemetry_fields_remain_unchanged(
    fake_cache: CacheService,
) -> None:
    """Legacy fields remain available while new impact payload is present."""
    r = fake_cache.raw_client()
    assert r is not None

    await r.set("ct:total_scans", "10")
    await r.set("ct:total_findings", "50")
    await r.set("ct:total_blocks", "7")
    await r.set("ct:gateway_blocks", "3")
    await r.set("ct:hallucinations_caught", "4")
    await r.set("ct:impact:injection_attacks", "9")
    await r.set("ct:top_rules:eval_exec", "6")

    stats = await build_public_stats(r=r, use_cache=False)

    usage = stats.get("usage")
    impact = stats.get("impact")
    quality = stats.get("quality")

    assert isinstance(usage, dict)
    assert isinstance(impact, dict)
    assert isinstance(quality, dict)

    assert usage["total_scans"] == 10
    assert usage["total_findings"] == 50
    assert usage["findings_by_severity"]["BLOCK"] == 7  # reads ct:total_blocks directly

    assert impact["gateway_commands_blocked"] == 3
    assert impact["hallucinations_caught"] == 4
    assert isinstance(impact["categories"], dict)
    assert isinstance(impact["top_rules"], list)

    assert isinstance(quality["top_rules_triggered"], list)


@pytest.mark.asyncio
async def test_fallback_impact_increments_unsafe_config_for_extension_scans(
    fake_cache: CacheService,
) -> None:
    """When scan has blocks but no per-finding list, unsafe_config gets the blocks."""
    from src.services.telemetry import TelemetryIngestEvent, process_telemetry_event

    r = fake_cache.raw_client()
    assert r is not None

    # Simulate extension scan: findings_by_severity but no findings list
    event = TelemetryIngestEvent(
        event_type="scan_completed",
        source="vscode",
        installation_id="test-ext",
        version="4.0.6",
        payload={
            "scan_type": "static",
            "files_scanned": 1,
            "total_findings": 5,
            "findings_by_severity": {"BLOCK": 3, "WARN": 2},
            # No "findings" key — extension doesn't send per-finding detail
        },
    )
    await process_telemetry_event(r=r, db=None, queue=None, event=event)

    # ct:total_blocks should have the 3 blocks
    assert int(await r.get("ct:total_blocks") or 0) == 3

    # Fallback: unsafe_config should have received the 3 blocks
    assert int(await r.get("ct:impact:unsafe_config") or 0) == 3

    # last_seen should be set
    assert await r.get("ct:impact:last_seen:unsafe_config") is not None
