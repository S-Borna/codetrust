# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for database-backed impact aggregate calculations."""

import pytest

from src.services.database import DatabaseService


@pytest.mark.asyncio()
async def test_redis_warmup_counters_include_impact_and_top_rules() -> None:
    """Warmup aggregate includes impact categories and top rule counters."""
    db = DatabaseService("sqlite+aiosqlite:///:memory:")
    await db.create_tables()

    await db.insert_telemetry_raw_batch(
        [
            {
                "event_type": "scan_completed",
                "source": "cloud_api",
                "installation_id": "install-a",
                "version": "test",
                "payload": {
                    "total_findings": 3,
                    "files_scanned": 1,
                    "findings_by_severity": {"BLOCK": 2},
                    "findings": [
                        {"rule": "eval_exec"},
                        {"rule_id": "hardcoded_secret"},
                        {"rule": "eval_exec"},
                    ],
                },
            }
        ]
    )

    counters = await db.get_redis_warmup_counters()

    assert counters["ct:impact:injection_attacks"] == 2
    assert counters["ct:impact:secrets_exposure"] == 1
    assert counters["ct:top_rules:eval_exec"] == 2
    assert counters["ct:top_rules:hardcoded_secret"] == 1

    await db.close()


@pytest.mark.asyncio()
async def test_public_usage_aggregates_include_impact_category_counts() -> None:
    """Fallback aggregate includes impact category counters from raw telemetry."""
    db = DatabaseService("sqlite+aiosqlite:///:memory:")
    await db.create_tables()

    await db.insert_telemetry_raw_batch(
        [
            {
                "event_type": "scan_completed",
                "source": "cloud_api",
                "installation_id": "install-b",
                "version": "test",
                "payload": {
                    "total_findings": 2,
                    "files_scanned": 1,
                    "findings_by_severity": {"BLOCK": 1},
                    "findings": [
                        {"rule": "eval_exec"},
                        {"rule": "import_not_found"},
                    ],
                },
            }
        ]
    )

    aggregates = await db.get_public_usage_aggregates()

    assert aggregates["impact_injection_attacks"] == 1
    assert aggregates["impact_hallucinations"] == 1
    assert aggregates["impact_other"] == 0

    await db.close()


@pytest.mark.asyncio()
async def test_warmup_snapshot_floor_applies_to_all_counters() -> None:
    """Snapshot floor via max(aggregated, snapshot) applies to every counter
    including per-source counts.  Verifies fix for Copilot finding where
    ct:scans_by_source:* was added after the snapshot merge."""
    db = DatabaseService("sqlite+aiosqlite:///:memory:")
    await db.create_tables()

    # Insert one scan event so aggregated counters are low.
    await db.insert_telemetry_raw_batch(
        [
            {
                "event_type": "scan_completed",
                "source": "cli",
                "installation_id": "snap-test",
                "version": "test",
                "payload": {
                    "total_findings": 1,
                    "files_scanned": 1,
                    "findings_by_severity": {"BLOCK": 1},
                    "findings": [{"rule": "eval_exec"}],
                },
            }
        ]
    )

    # Insert snapshot values HIGHER than aggregated — simulating a Redis
    # restart where telemetry_events_raw lost rows but snapshots persist.
    await db.insert_counter_snapshots(
        {
            "ct:total_scans": 500,
            "ct:total_findings": 9000,
            "ct:total_blocks": 3000,
            "ct:scans_by_source:cli": 200,
            "ct:scans_by_source:vscode": 150,
            "ct:ext:pepy_total_downloads": 8000,
        }
    )

    counters = await db.get_redis_warmup_counters()

    # Snapshot floors must win over the low aggregated values.
    assert counters["ct:total_scans"] == 500
    assert counters["ct:total_findings"] == 9000
    assert counters["ct:total_blocks"] == 3000
    assert counters["ct:scans_by_source:cli"] == 200
    assert counters["ct:scans_by_source:vscode"] == 150
    assert counters["ct:ext:pepy_total_downloads"] == 8000

    # Aggregated value should survive when higher than snapshot.
    assert counters["ct:impact:injection_attacks"] == 1

    await db.close()
