"""Real-time telemetry ingestion and public stats aggregation.

This module is intentionally privacy-preserving:
- No code, filenames, repo URLs, paths, IPs, user identifiers, or API keys.
- Only anonymous installation IDs and aggregate numeric counters.
"""

from __future__ import annotations

import asyncio
import datetime
import json
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
import redis.asyncio as redis
import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.config import settings

if TYPE_CHECKING:
    from collections.abc import Awaitable as _Awaitable
    from collections.abc import Callable as _Callable

    from src.services.database import DatabaseService

logger = structlog.get_logger()

SECONDS_PER_HOUR: int = 3_600
TELEMETRY_QUEUE_MAXSIZE: int = 10_000
TELEMETRY_BATCH_SIZE: int = 50
TELEMETRY_FLUSH_INTERVAL_SECONDS: float = 5.0

STATS_CACHE_KEY: str = "ct:stats_cache"
STATS_CACHE_TTL_SECONDS: int = 60

EXT_STATS_TTL_SECONDS: int = 300
EXT_STATS_POLL_SECONDS: float = 300.0

ACTIVE_SESSIONS_KEY: str = "ct:active_sessions"
ACTIVE_SESSIONS_TODAY_KEY: str = "ct:active_sessions_today"

SCANS_LAST_HOUR_KEY: str = "ct:scans_last_hour"
SCANS_LAST_HOUR_WINDOW_SECONDS: int = 3600

SCANS_TODAY_KEY: str = "ct:scans_today"
SCANS_TODAY_TTL_SECONDS: int = 60 * 60 * 48

PYPI_RECENT_URL: str = "https://pypistats.org/api/packages/codetrust/recent"
MARKETPLACE_EXTENSION_QUERY_URL: str = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
MARKETPLACE_EXTENSION_ID: str = "SaidBorna.codetrust"
MARKETPLACE_FLAGS: int = 914

OPEN_VSX_EXTENSION_URL_TEMPLATE: str = "https://open-vsx.org/api/{namespace}/{name}"
OPEN_VSX_NAMESPACE: str = "SaidBorna"
OPEN_VSX_EXTENSION_NAME: str = "codetrust"

PEPY_API_URL_TEMPLATE: str = "https://api.pepy.tech/api/v2/projects/{project}"
PEPY_PROJECT: str = "codetrust"


class TelemetryIngestEvent(BaseModel):
    """Anonymous telemetry event payload.

    Compatible with the published spec in this repo.
    """

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    event_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9_.:-]+$",
    )
    source: str = Field(
        ...,
        pattern=r"^(cli|vscode|mcp|github_action|cloud_api)$",
    )
    installation_id: str | None = Field(
        default=None,
        min_length=8,
        max_length=128,
        description="Anonymous installation/session identifier",
    )
    version: str | None = Field(default=None, max_length=32)
    payload: dict[str, object] = Field(default_factory=dict)


@dataclass(frozen=True)
class TelemetryWriteItem:
    """Normalized write item for DB persistence."""

    event_type: str
    source: str
    installation_id: str | None
    version: str | None
    payload: dict[str, object]


def _now_unix() -> float:
    return time.time()


def _end_of_day_ttl_seconds(now: datetime.datetime | None = None) -> int:
    """Return seconds until end-of-day UTC (min 1, max 48h)."""

    current = now or datetime.datetime.now(datetime.UTC)
    tomorrow = (current + datetime.timedelta(days=1)).date()
    end = datetime.datetime.combine(tomorrow, datetime.time(0, 0, 0), tzinfo=datetime.UTC)
    ttl = int((end - current).total_seconds())
    return max(1, min(SCANS_TODAY_TTL_SECONDS, ttl))


def _safe_int(value: object, *, default: int = 0, min_value: int = 0, max_value: int = 10_000_000) -> int:
    try:
        num = int(value)
    except (TypeError, ValueError):
        return default
    if num < min_value:
        return min_value
    if num > max_value:
        return max_value
    return num


def _safe_str(value: object, *, default: str = "", max_length: int = 128) -> str:
    if not isinstance(value, str):
        return default
    return value[:max_length]


async def _increment_active_sessions(
    r: redis.Redis,
    installation_id: str | None,
) -> None:
    if not installation_id:
        return
    try:
        ttl = _end_of_day_ttl_seconds()
        pipe = r.pipeline()
        pipe.pfadd(ACTIVE_SESSIONS_KEY, installation_id)
        pipe.pfadd(ACTIVE_SESSIONS_TODAY_KEY, installation_id)
        pipe.expire(ACTIVE_SESSIONS_TODAY_KEY, ttl)
        await pipe.execute()
    except redis.RedisError as exc:
        logger.warning("telemetry_active_sessions_failed", error=str(exc))


def _parse_scan_payload(
    payload: dict[str, object],
) -> tuple[dict[str, int], list[int], list[str], int | None, str]:
    """Parse scan payload into language, layer, rule, trust and trend data."""
    raw_langs = payload.get("languages") if isinstance(payload.get("languages"), dict) else {}
    languages: dict[str, int] = {}
    for lang, count in list(raw_langs.items())[:32]:
        languages[_safe_str(lang, max_length=32)] = _safe_int(count, max_value=10_000_000)

    raw_layers = payload.get("layers_hit") if isinstance(payload.get("layers_hit"), list) else []
    layers = [_safe_int(layer, min_value=1, max_value=10) for layer in raw_layers[:20]]

    raw_rules = payload.get("rules_triggered") if isinstance(payload.get("rules_triggered"), list) else []
    rules = [_safe_str(rule, max_length=80) for rule in raw_rules[:50] if _safe_str(rule, max_length=80)]

    trust_raw = payload.get("trust_score")
    trust_score: int | None = _safe_int(trust_raw, max_value=1000) if trust_raw is not None else None

    trend = _safe_str(payload.get("trend"), max_length=16)
    return languages, layers, rules, trust_score, trend


async def _handle_scan_completed(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    """Handle scan_completed event by updating Redis counters."""
    p = event.payload
    files_scanned = _safe_int(p.get("files_scanned"), max_value=1_000_000)
    total_findings = _safe_int(p.get("total_findings"), max_value=10_000_000)
    hallucinations = _safe_int(p.get("hallucinations_found"), max_value=1_000_000)
    severity = p.get("findings_by_severity") if isinstance(p.get("findings_by_severity"), dict) else {}
    blocks = _safe_int(getattr(severity, "get", lambda _k, _d=0: 0)("BLOCK", 0), max_value=10_000_000)
    scan_type = _safe_str(p.get("scan_type"), max_length=32)
    languages, layers, rules, trust_score, trend = _parse_scan_payload(p)

    pipe = r.pipeline()
    pipe.incr("ct:total_scans")
    pipe.incr(f"ct:scans_by_source:{event.source}")
    pipe.incrby("ct:files_scanned", files_scanned)
    pipe.incrby("ct:total_findings", total_findings)
    pipe.incrby("ct:total_blocks", blocks)
    pipe.incrby("ct:hallucinations_caught", hallucinations)
    pipe.incr(SCANS_TODAY_KEY)
    pipe.expire(SCANS_TODAY_KEY, _end_of_day_ttl_seconds())
    pipe.zadd(SCANS_LAST_HOUR_KEY, {uuid.uuid4().hex: _now_unix()})
    if scan_type:
        pipe.incr(f"ct:scan_type:{scan_type}")
    for lang, count in languages.items():
        pipe.incrby(f"ct:lang:{lang}", count)
    for layer_num in layers:
        pipe.incr(f"ct:layer:{layer_num}")
    for rule_name in rules:
        pipe.incr(f"ct:rule:{rule_name}")
    if trust_score is not None:
        pipe.incrby("ct:trust_score_sum", trust_score)
        pipe.incr("ct:trust_score_count")
    if trend in {"improving", "stable", "degrading"}:
        pipe.incr(f"ct:trend:{trend}")
    await pipe.execute()


async def _handle_gateway_check(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    p = event.payload
    action = _safe_str(p.get("action"), max_length=16)
    rule = _safe_str(p.get("rule_triggered"), max_length=80)
    pipe = r.pipeline()
    if action == "BLOCKED":
        pipe.incr("ct:gateway_blocks")
    elif action == "ALLOWED":
        pipe.incr("ct:gateway_allowed")
    elif action == "WARNED":
        pipe.incr("ct:gateway_warned")
    if rule:
        pipe.incr(f"ct:rule:{rule}")
    await pipe.execute()


async def _handle_import_verified(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    p = event.payload
    pipe = r.pipeline()
    pipe.incrby("ct:imports_verified", _safe_int(p.get("total_imports_checked"), max_value=10_000_000))
    pipe.incrby("ct:hallucinations_caught", _safe_int(p.get("hallucinations_caught"), max_value=10_000_000))
    await pipe.execute()


async def _handle_docker_verified(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    p = event.payload
    pipe = r.pipeline()
    pipe.incrby("ct:docker_verified", _safe_int(p.get("images_checked"), max_value=10_000_000))
    await pipe.execute()


async def _handle_fix_applied(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    p = event.payload
    pipe = r.pipeline()
    pipe.incrby("ct:fixes_applied", _safe_int(p.get("fixes_applied"), max_value=10_000_000))
    pipe.incrby("ct:fix_files_changed", _safe_int(p.get("files_changed"), max_value=10_000_000))
    pipe.incrby("ct:fix_lines_changed", _safe_int(p.get("lines_changed"), max_value=10_000_000))
    await pipe.execute()


async def _handle_ci_run_completed(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    """Handle GitHub Action / CI pipeline telemetry.

    Increments CI-specific counters AND overall scan counters so that
    CI-driven scans contribute to the global totals.
    """
    p = event.payload
    files_scanned = _safe_int(p.get("files_scanned"), max_value=1_000_000)
    total_findings = _safe_int(p.get("total_findings"), max_value=10_000_000)
    gate = _safe_str(p.get("gate_result"), max_length=8)
    duration_ms = _safe_int(p.get("duration_ms"), max_value=600_000)

    pipe = r.pipeline()
    pipe.incr("ct:ci_runs_total")
    pipe.incr("ct:total_scans")
    pipe.incr(f"ct:scans_by_source:{event.source}")
    pipe.incrby("ct:files_scanned", files_scanned)
    pipe.incrby("ct:total_findings", total_findings)
    pipe.incr(SCANS_TODAY_KEY)
    pipe.expire(SCANS_TODAY_KEY, _end_of_day_ttl_seconds())
    pipe.zadd(SCANS_LAST_HOUR_KEY, {uuid.uuid4().hex: _now_unix()})
    if gate == "PASS":
        pipe.incr("ct:ci_gates_passed")
    elif gate == "FAIL":
        pipe.incr("ct:ci_gates_failed")
    if duration_ms > 0:
        pipe.incrby("ct:ci_total_duration_ms", duration_ms)
    await pipe.execute()


async def _handle_pr_risk_assessed(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    p = event.payload
    gate = _safe_str(p.get("gate_result"), max_length=8)
    pipe = r.pipeline()
    if gate == "PASS":
        pipe.incr("ct:pr_gates_passed")
    elif gate == "FAIL":
        pipe.incr("ct:pr_gates_failed")
    await pipe.execute()


async def _handle_generic(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    try:
        await r.incr(f"ct:event:{event.event_type}")
    except redis.RedisError as exc:
        logger.warning("telemetry_generic_failed", error=str(exc), event_type=event.event_type)


EVENT_HANDLERS: dict[str, _Callable[[redis.Redis, TelemetryIngestEvent], _Awaitable[None]]] = {
    "scan_completed": _handle_scan_completed,
    "gateway_check": _handle_gateway_check,
    "import_verified": _handle_import_verified,
    "docker_verified": _handle_docker_verified,
    "fix_applied": _handle_fix_applied,
    "ci_run_completed": _handle_ci_run_completed,
    "pr_risk_assessed": _handle_pr_risk_assessed,
}


async def process_telemetry_event(
    *,
    r: redis.Redis | None,
    queue: asyncio.Queue[TelemetryWriteItem] | None,
    event: TelemetryIngestEvent,
) -> None:
    """Update real-time counters and enqueue DB write (best-effort)."""

    if r is not None:
        await _increment_active_sessions(r, event.installation_id)
        handler = EVENT_HANDLERS.get(event.event_type)
        try:
            if handler is None:
                await _handle_generic(r, event)
            else:
                await handler(r, event)
        except redis.RedisError as exc:
            logger.warning("telemetry_redis_failed", error=str(exc), event_type=event.event_type)

    if queue is None:
        return

    item = TelemetryWriteItem(
        event_type=event.event_type,
        source=event.source,
        installation_id=event.installation_id,
        version=event.version,
        payload=event.payload,
    )

    try:
        queue.put_nowait(item)
    except asyncio.QueueFull:
        # Drop rather than block.
        logger.info("telemetry_queue_full_drop", event_type=event.event_type, source=event.source)


async def prune_last_hour(r: redis.Redis) -> None:
    """Remove scans older than 1 hour from last-hour zset."""

    cutoff = _now_unix() - float(SCANS_LAST_HOUR_WINDOW_SECONDS)
    try:
        await r.zremrangebyscore(SCANS_LAST_HOUR_KEY, 0, cutoff)
    except redis.RedisError as exc:
        logger.warning("telemetry_prune_failed", error=str(exc))


async def _fetch_pypi_external(
    r: redis.Redis, http_client: httpx.AsyncClient,
) -> None:
    """Fetch PyPI download stats and cache in Redis."""
    try:
        res = await http_client.get(PYPI_RECENT_URL)
        res.raise_for_status()
        payload = res.json()
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        await r.set("ct:ext:pypi_last_day", str(_safe_int(data.get("last_day"))), ex=EXT_STATS_TTL_SECONDS)
        await r.set("ct:ext:pypi_last_week", str(_safe_int(data.get("last_week"))), ex=EXT_STATS_TTL_SECONDS)
        await r.set("ct:ext:pypi_last_month", str(_safe_int(data.get("last_month"))), ex=EXT_STATS_TTL_SECONDS)
    except (httpx.HTTPError, ValueError, TypeError, redis.RedisError) as exc:
        logger.warning("ext_stats_pypi_failed", error=str(exc))


async def _fetch_pepy_external(
    r: redis.Redis, http_client: httpx.AsyncClient,
) -> None:
    """Fetch Pepy total PyPI downloads via authenticated API."""
    if not settings.pepy_api_key:
        return
    try:
        url = PEPY_API_URL_TEMPLATE.format(project=PEPY_PROJECT)
        headers = {"X-Api-Key": settings.pepy_api_key}
        res = await http_client.get(url, headers=headers)
        res.raise_for_status()
        payload = res.json()
        total_downloads = _safe_int(
            payload.get("total_downloads") if isinstance(payload, dict) else 0,
            max_value=100_000_000,
        )
        await r.set("ct:ext:pepy_3m_ci_downloads", str(total_downloads), ex=EXT_STATS_TTL_SECONDS)
    except (httpx.HTTPError, ValueError, TypeError, redis.RedisError) as exc:
        logger.warning("ext_stats_pepy_failed", error=str(exc))


def _parse_marketplace_response(payload: object) -> dict[str, int]:
    """Extract statistics map from marketplace API JSON response."""
    results = payload.get("results", []) if isinstance(payload, dict) else []
    extensions = results[0].get("extensions", []) if results else []
    ext = extensions[0] if extensions else {}
    stats_list = ext.get("statistics", []) if isinstance(ext, dict) else []
    stats_map: dict[str, int] = {}
    for item in stats_list:
        if not isinstance(item, dict):
            continue
        name = item.get("statisticName")
        val = item.get("value")
        if isinstance(name, str):
            stats_map[name] = _safe_int(val)
    return stats_map


async def _fetch_marketplace_external(
    r: redis.Redis, http_client: httpx.AsyncClient,
) -> None:
    """Fetch VS Code Marketplace stats and cache in Redis."""
    body = {
        "filters": [{"criteria": [{"filterType": 7, "value": MARKETPLACE_EXTENSION_ID}]}],
        "flags": MARKETPLACE_FLAGS,
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json;api-version=3.0-preview.1",
    }
    try:
        res = await http_client.post(MARKETPLACE_EXTENSION_QUERY_URL, json=body, headers=headers)
        res.raise_for_status()
        stats_map = _parse_marketplace_response(res.json())
        await r.set("ct:ext:marketplace_installs", str(_safe_int(stats_map.get("install"))), ex=EXT_STATS_TTL_SECONDS)
        await r.set("ct:ext:marketplace_downloads", str(_safe_int(stats_map.get("downloadCount"))), ex=EXT_STATS_TTL_SECONDS)
        await r.set("ct:ext:marketplace_updates", str(_safe_int(stats_map.get("updateCount"))), ex=EXT_STATS_TTL_SECONDS)
    except (httpx.HTTPError, ValueError, TypeError, IndexError, KeyError, redis.RedisError) as exc:
        logger.warning("ext_stats_marketplace_failed", error=str(exc))


async def _fetch_openvsx_external(
    r: redis.Redis, http_client: httpx.AsyncClient,
) -> None:
    """Fetch Open VSX download stats and cache in Redis."""
    try:
        url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(
            namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME,
        )
        res = await http_client.get(url)
        res.raise_for_status()
        payload = res.json()
        download_count = payload.get("downloadCount") if isinstance(payload, dict) else None
        await r.set("ct:ext:openvsx_downloads", str(_safe_int(download_count)), ex=EXT_STATS_TTL_SECONDS)
    except httpx.HTTPStatusError as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status == 404:
            logger.debug("ext_stats_openvsx_not_found")
        else:
            logger.warning("ext_stats_openvsx_failed", error=str(exc), status_code=status)
    except (httpx.HTTPError, ValueError, TypeError, redis.RedisError) as exc:
        logger.warning("ext_stats_openvsx_failed", error=str(exc))


async def warm_up_redis_counters(r: redis.Redis, db: DatabaseService) -> None:
    """Seed Redis counters from the database after a server restart.

    Only sets a counter when the persisted DB value exceeds the current Redis
    value, so this is always monotonic and safe to call concurrently.
    """
    try:
        db_counters: dict[str, int] = await db.get_redis_warmup_counters()
    except Exception as exc:
        logger.warning("redis_warmup_db_failed", error=str(exc), error_type=type(exc).__name__)
        return

    if not db_counters:
        return

    try:
        keys = list(db_counters.keys())
        fetch_pipe = r.pipeline()
        for key in keys:
            fetch_pipe.get(key)
        current_raws = await fetch_pipe.execute()
        current: dict[str, int] = {
            key: int(raw) if raw else 0
            for key, raw in zip(keys, current_raws, strict=True)
        }

        set_pipe = r.pipeline()
        restored = 0
        for key in keys:
            db_val = db_counters[key]
            if db_val > current.get(key, 0):
                set_pipe.set(key, db_val)
                if key == SCANS_TODAY_KEY:
                    set_pipe.expire(key, _end_of_day_ttl_seconds())
                restored += 1

        if restored:
            await set_pipe.execute()
            await r.delete(STATS_CACHE_KEY)  # force fresh build on next request

        logger.info(
            "redis_warmup_complete",
            counters_restored=restored,
            total_db_scans=db_counters.get("ct:total_scans", 0),
        )
    except redis.RedisError as exc:
        logger.warning("redis_warmup_set_failed", error=str(exc), error_type=type(exc).__name__)


async def fetch_external_stats(r: redis.Redis, http_client: httpx.AsyncClient) -> None:
    """Fetch external distribution stats and cache in Redis."""
    await _fetch_pypi_external(r, http_client)
    await _fetch_pepy_external(r, http_client)
    await _fetch_marketplace_external(r, http_client)
    await _fetch_openvsx_external(r, http_client)


async def stats_worker(*, r: redis.Redis, http_client: httpx.AsyncClient, stop: asyncio.Event) -> None:
    """Background loop updating external stats and pruning time windows."""

    while not stop.is_set():
        try:
            await fetch_external_stats(r, http_client)
            await prune_last_hour(r)
        except Exception as exc:
            logger.warning("stats_worker_failed", error=str(exc), error_type=type(exc).__name__)
        try:
            await asyncio.wait_for(stop.wait(), timeout=EXT_STATS_POLL_SECONDS)
        except TimeoutError as exc:
            logger.debug(
                "stats_worker_tick",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            continue


_COUNTER_KEYS: tuple[str, ...] = (
    "ct:total_scans",
    "ct:total_findings",
    "ct:total_blocks",
    "ct:hallucinations_caught",
    "ct:gateway_blocks",
    "ct:gateway_allowed",
    "ct:gateway_warned",
    "ct:imports_verified",
    "ct:docker_verified",
    "ct:fixes_applied",
    "ct:fix_files_changed",
    "ct:fix_lines_changed",
    "ct:pr_gates_passed",
    "ct:pr_gates_failed",
    "ct:files_scanned",
    "ct:trust_score_sum",
    "ct:trust_score_count",
    "ct:trend:improving",
    "ct:trend:stable",
    "ct:trend:degrading",
    SCANS_TODAY_KEY,
    "ct:scans_by_source:cli",
    "ct:scans_by_source:vscode",
    "ct:scans_by_source:mcp",
    "ct:scans_by_source:github_action",
    "ct:scans_by_source:cloud_api",
    "ct:ci_runs_total",
    "ct:ci_gates_passed",
    "ct:ci_gates_failed",
    "ct:ext:pypi_last_day",
    "ct:ext:pypi_last_week",
    "ct:ext:pypi_last_month",
    "ct:ext:pepy_3m_ci_downloads",
    "ct:ext:marketplace_installs",
    "ct:ext:marketplace_downloads",
    "ct:ext:marketplace_updates",
    "ct:ext:openvsx_downloads",
)

_LANG_KEYS: tuple[str, ...] = (
    "python", "javascript", "typescript", "go",
    "rust", "dockerfile", "sql", "yaml",
)
_LAYER_RANGE: range = range(1, 11)
_MAX_RULE_KEYS: int = 500
_TOP_RULES_LIMIT: int = 15


async def _fetch_redis_counters(
    r: redis.Redis,
) -> tuple[dict[str, int], int, int, int]:
    """Fetch all primary counters, HLL counts, and last-hour scans."""
    pipe = r.pipeline()
    for k in _COUNTER_KEYS:
        pipe.get(k)
    values = await pipe.execute()
    kv: dict[str, int] = {k: _safe_int(v) for k, v in zip(_COUNTER_KEYS, values, strict=True)}
    active_total = _safe_int(await r.pfcount(ACTIVE_SESSIONS_KEY))
    active_today = _safe_int(await r.pfcount(ACTIVE_SESSIONS_TODAY_KEY))
    scans_last_hour = _safe_int(
        await r.zcount(SCANS_LAST_HOUR_KEY, _now_unix() - SECONDS_PER_HOUR, float("inf")),
    )
    return kv, active_total, active_today, scans_last_hour


async def _fetch_language_distribution(r: redis.Redis) -> dict[str, int]:
    """Fetch language scan counts from Redis."""
    pipe = r.pipeline()
    for lang in _LANG_KEYS:
        pipe.get(f"ct:lang:{lang}")
    values = await pipe.execute()
    return {lang: _safe_int(val) for lang, val in zip(_LANG_KEYS, values, strict=True)}


async def _fetch_layer_distribution(r: redis.Redis) -> dict[str, int]:
    """Fetch layer scan counts from Redis."""
    pipe = r.pipeline()
    for i in _LAYER_RANGE:
        pipe.get(f"ct:layer:{i}")
    values = await pipe.execute()
    return {f"layer_{i}": _safe_int(val) for i, val in zip(_LAYER_RANGE, values, strict=True)}


async def _fetch_top_rules(r: redis.Redis) -> list[dict[str, object]]:
    """Scan for triggered rules and return sorted top rules."""
    try:
        rule_keys: list[str] = []
        async for key in r.scan_iter(match="ct:rule:*"):
            if isinstance(key, str):
                rule_keys.append(key)
            if len(rule_keys) >= _MAX_RULE_KEYS:
                break
        if not rule_keys:
            return []
        pipe = r.pipeline()
        for rk in rule_keys:
            pipe.get(rk)
        rule_vals = await pipe.execute()
        rule_counts = [
            (rk.replace("ct:rule:", "", 1), _safe_int(rv))
            for rk, rv in zip(rule_keys, rule_vals, strict=True)
        ]
        rule_counts.sort(key=lambda x: x[1], reverse=True)
        return [{"rule": name, "count": count} for name, count in rule_counts[:_TOP_RULES_LIMIT]]
    except (redis.RedisError, TypeError):
        return []


def _build_distribution_stats(kv: dict[str, int]) -> dict[str, object]:
    """Build distribution section of stats payload."""
    return {
        "pypi": {
            "downloads_today": kv.get("ct:ext:pypi_last_day", 0),
            "downloads_this_week": kv.get("ct:ext:pypi_last_week", 0),
            "downloads_this_month": kv.get("ct:ext:pypi_last_month", 0),
            "downloads_last_3_months_ci": kv.get("ct:ext:pepy_3m_ci_downloads", 0),
        },
        "marketplace": {
            "installs": kv.get("ct:ext:marketplace_installs", 0),
            "downloads": kv.get("ct:ext:marketplace_downloads", 0),
            "updates": kv.get("ct:ext:marketplace_updates", 0),
        },
        "open_vsx": {
            "downloads": kv.get("ct:ext:openvsx_downloads", 0),
        },
    }


def _build_usage_stats(
    kv: dict[str, int],
    active_total: int,
    active_today: int,
    scans_last_hour: int,
) -> dict[str, object]:
    """Build usage section of stats payload."""
    total_findings = kv.get("ct:total_findings", 0)
    total_blocks = kv.get("ct:total_blocks", 0)
    return {
        "total_scans": kv.get("ct:total_scans", 0),
        "scans_today": kv.get(SCANS_TODAY_KEY, 0),
        "scans_last_hour": scans_last_hour,
        "scans_by_source": {
            "cli": kv.get("ct:scans_by_source:cli", 0),
            "vscode": kv.get("ct:scans_by_source:vscode", 0),
            "mcp": kv.get("ct:scans_by_source:mcp", 0),
            "github_action": kv.get("ct:scans_by_source:github_action", 0),
            "cloud_api": kv.get("ct:scans_by_source:cloud_api", 0),
        },
        "total_files_scanned": kv.get("ct:files_scanned", 0),
        "total_findings": total_findings,
        "findings_by_severity": {
            "BLOCK": total_blocks,
            "WARN": max(0, total_findings - total_blocks),
            "INFO": 0,
        },
        "unique_installations_total": active_total,
        "unique_installations_today": active_today,
    }


def _build_impact_stats(kv: dict[str, int]) -> dict[str, object]:
    """Build impact section of stats payload."""
    return {
        "hallucinations_caught": kv.get("ct:hallucinations_caught", 0),
        "gateway_commands_blocked": kv.get("ct:gateway_blocks", 0),
        "gateway_commands_allowed": kv.get("ct:gateway_allowed", 0),
        "gateway_commands_warned": kv.get("ct:gateway_warned", 0),
        "imports_verified": kv.get("ct:imports_verified", 0),
        "docker_images_verified": kv.get("ct:docker_verified", 0),
        "fixes_applied": kv.get("ct:fixes_applied", 0),
        "fix_files_changed": kv.get("ct:fix_files_changed", 0),
        "fix_lines_changed": kv.get("ct:fix_lines_changed", 0),
        "pr_gates_passed": kv.get("ct:pr_gates_passed", 0),
        "pr_gates_failed": kv.get("ct:pr_gates_failed", 0),
        "ci_runs_total": kv.get("ct:ci_runs_total", 0),
        "ci_gates_passed": kv.get("ct:ci_gates_passed", 0),
        "ci_gates_failed": kv.get("ct:ci_gates_failed", 0),
    }


def _build_quality_stats(
    kv: dict[str, int],
    top_rules: list[dict[str, object]],
) -> dict[str, object]:
    """Build quality section of stats payload."""
    ts_sum = kv.get("ct:trust_score_sum", 0)
    ts_count = kv.get("ct:trust_score_count", 0)
    avg_score = round(ts_sum / ts_count) if ts_count > 0 else 0
    return {
        "average_trust_score": avg_score,
        "trend_distribution": {
            "improving": kv.get("ct:trend:improving", 0),
            "stable": kv.get("ct:trend:stable", 0),
            "degrading": kv.get("ct:trend:degrading", 0),
        },
        "top_rules_triggered": top_rules,
    }


async def build_public_stats(
    *,
    r: redis.Redis,
    use_cache: bool,
) -> dict[str, object]:
    """Build full public stats payload from Redis counters."""
    if use_cache:
        cached = await r.get(STATS_CACHE_KEY)
        if cached:
            try:
                return json.loads(cached)
            except (json.JSONDecodeError, TypeError) as exc:
                logger.debug("stats_cache_decode_failed", error=str(exc), error_type=type(exc).__name__)

    kv, active_total, active_today, scans_last_hour = await _fetch_redis_counters(r)
    languages = await _fetch_language_distribution(r)
    layers = await _fetch_layer_distribution(r)
    top_rules = await _fetch_top_rules(r)

    stats: dict[str, object] = {
        "updated_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "distribution": _build_distribution_stats(kv),
        "usage": _build_usage_stats(kv, active_total, active_today, scans_last_hour),
        "impact": _build_impact_stats(kv),
        "quality": _build_quality_stats(kv, top_rules),
        "languages": languages,
        "layers": layers,
    }

    await r.set(STATS_CACHE_KEY, json.dumps(stats), ex=STATS_CACHE_TTL_SECONDS)
    return stats
