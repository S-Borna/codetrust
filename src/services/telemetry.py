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

if TYPE_CHECKING:
    from collections.abc import Awaitable as _Awaitable
    from collections.abc import Callable as _Callable

logger = structlog.get_logger()

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


async def _handle_scan_completed(r: redis.Redis, event: TelemetryIngestEvent) -> None:
    p = event.payload
    files_scanned = _safe_int(p.get("files_scanned"), max_value=1_000_000)
    total_findings = _safe_int(p.get("total_findings"), max_value=10_000_000)
    hallucinations = _safe_int(p.get("hallucinations_found"), max_value=1_000_000)
    severity = p.get("findings_by_severity") if isinstance(p.get("findings_by_severity"), dict) else {}
    blocks = _safe_int(getattr(severity, "get", lambda _k, _d=0: 0)("BLOCK", 0), max_value=10_000_000)

    scan_type = _safe_str(p.get("scan_type"), max_length=32)

    pipe = r.pipeline()
    pipe.incr("ct:total_scans")
    pipe.incr(f"ct:scans_by_source:{event.source}")
    pipe.incrby("ct:files_scanned", files_scanned)
    pipe.incrby("ct:total_findings", total_findings)
    pipe.incrby("ct:total_blocks", blocks)
    pipe.incrby("ct:hallucinations_caught", hallucinations)
    pipe.incr(SCANS_TODAY_KEY)
    pipe.expire(SCANS_TODAY_KEY, _end_of_day_ttl_seconds())

    # Last-hour activity
    pipe.zadd(SCANS_LAST_HOUR_KEY, {uuid.uuid4().hex: _now_unix()})

    if scan_type:
        pipe.incr(f"ct:scan_type:{scan_type}")

    languages = p.get("languages") if isinstance(p.get("languages"), dict) else {}
    for lang, count in list(languages.items())[:32]:
        pipe.incrby(f"ct:lang:{_safe_str(lang, max_length=32)}", _safe_int(count, max_value=10_000_000))

    layers_hit = p.get("layers_hit") if isinstance(p.get("layers_hit"), list) else []
    for layer in layers_hit[:20]:
        layer_num = _safe_int(layer, min_value=1, max_value=10)
        pipe.incr(f"ct:layer:{layer_num}")

    rules_triggered = p.get("rules_triggered") if isinstance(p.get("rules_triggered"), list) else []
    for rule in rules_triggered[:50]:
        rule_name = _safe_str(rule, max_length=80)
        if rule_name:
            pipe.incr(f"ct:rule:{rule_name}")

    trust_score = p.get("trust_score")
    if trust_score is not None:
        pipe.incrby("ct:trust_score_sum", _safe_int(trust_score, max_value=1000))
        pipe.incr("ct:trust_score_count")

    trend = _safe_str(p.get("trend"), max_length=16)
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


async def fetch_external_stats(r: redis.Redis, http_client: httpx.AsyncClient) -> None:
    """Fetch external distribution stats and cache in Redis."""

    # PyPI downloads
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

    # VS Code Marketplace
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
            val = item.get("value")
            if isinstance(name, str):
                stats_map[name] = _safe_int(val)
        await r.set("ct:ext:marketplace_installs", str(_safe_int(stats_map.get("install"))), ex=EXT_STATS_TTL_SECONDS)
        await r.set(
            "ct:ext:marketplace_downloads",
            str(_safe_int(stats_map.get("downloadCount"))),
            ex=EXT_STATS_TTL_SECONDS,
        )
        await r.set(
            "ct:ext:marketplace_updates",
            str(_safe_int(stats_map.get("updateCount"))),
            ex=EXT_STATS_TTL_SECONDS,
        )
    except (httpx.HTTPError, ValueError, TypeError, IndexError, KeyError, redis.RedisError) as exc:
        logger.warning("ext_stats_marketplace_failed", error=str(exc))

    # Open VSX (for VSCodium/Cursor distributions)
    try:
        url = OPEN_VSX_EXTENSION_URL_TEMPLATE.format(namespace=OPEN_VSX_NAMESPACE, name=OPEN_VSX_EXTENSION_NAME)
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
                logger.debug(
                    "stats_cache_decode_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

    keys = [
        "ct:total_scans",
        "ct:total_findings",
        "ct:total_blocks",
        "ct:hallucinations_caught",
        "ct:gateway_blocks",
        "ct:gateway_allowed",
        "ct:imports_verified",
        "ct:docker_verified",
        "ct:fixes_applied",
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
        "ct:ext:pypi_last_day",
        "ct:ext:pypi_last_week",
        "ct:ext:pypi_last_month",
        "ct:ext:marketplace_installs",
        "ct:ext:marketplace_downloads",
        "ct:ext:marketplace_updates",
        "ct:ext:openvsx_downloads",
    ]
    pipe = r.pipeline()
    for k in keys:
        pipe.get(k)
    values = await pipe.execute()
    kv: dict[str, int] = {k: _safe_int(v) for k, v in zip(keys, values, strict=True)}

    active_total = _safe_int(await r.pfcount(ACTIVE_SESSIONS_KEY))
    active_today = _safe_int(await r.pfcount(ACTIVE_SESSIONS_TODAY_KEY))
    scans_last_hour = _safe_int(
        await r.zcount(SCANS_LAST_HOUR_KEY, _now_unix() - 3600, float("inf"))
    )

    ts_sum = kv.get("ct:trust_score_sum", 0)
    ts_count = kv.get("ct:trust_score_count", 0)
    avg_score = round(ts_sum / ts_count) if ts_count > 0 else 0

    total_findings = kv.get("ct:total_findings", 0)
    total_blocks = kv.get("ct:total_blocks", 0)
    total_warn = max(0, total_findings - total_blocks)

    # Language distribution (bounded key list)
    lang_keys = [
        "python",
        "javascript",
        "typescript",
        "go",
        "rust",
        "dockerfile",
        "sql",
        "yaml",
    ]
    lang_pipe = r.pipeline()
    for lang in lang_keys:
        lang_pipe.get(f"ct:lang:{lang}")
    lang_values = await lang_pipe.execute()
    languages: dict[str, int] = {
        lang: _safe_int(val) for lang, val in zip(lang_keys, lang_values, strict=True)
    }

    # Layers distribution (1..10)
    layer_pipe = r.pipeline()
    for i in range(1, 11):
        layer_pipe.get(f"ct:layer:{i}")
    layer_values = await layer_pipe.execute()
    layers: dict[str, int] = {
        f"layer_{i}": _safe_int(val) for i, val in zip(range(1, 11), layer_values, strict=True)
    }

    # Top rules triggered
    top_rules: list[dict[str, object]] = []
    try:
        rule_keys: list[str] = []
        async for key in r.scan_iter(match="ct:rule:*"):
            if isinstance(key, str):
                rule_keys.append(key)
            if len(rule_keys) >= 500:
                break

        if rule_keys:
            rule_pipe = r.pipeline()
            for rk in rule_keys:
                rule_pipe.get(rk)
            rule_vals = await rule_pipe.execute()
            rule_counts: list[tuple[str, int]] = []
            for rk, rv in zip(rule_keys, rule_vals, strict=True):
                rule_name = rk.replace("ct:rule:", "", 1)
                rule_counts.append((rule_name, _safe_int(rv)))
            rule_counts.sort(key=lambda x: x[1], reverse=True)
            top_rules = [{"rule": name, "count": count} for name, count in rule_counts[:15]]
    except (redis.RedisError, TypeError):
        top_rules = []

    stats: dict[str, object] = {
        "updated_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "distribution": {
            "pypi": {
                "downloads_today": kv.get("ct:ext:pypi_last_day", 0),
                "downloads_this_week": kv.get("ct:ext:pypi_last_week", 0),
                "downloads_this_month": kv.get("ct:ext:pypi_last_month", 0),
            },
            "marketplace": {
                "installs": kv.get("ct:ext:marketplace_installs", 0),
                "downloads": kv.get("ct:ext:marketplace_downloads", 0),
                "updates": kv.get("ct:ext:marketplace_updates", 0),
            },
            "open_vsx": {
                "downloads": kv.get("ct:ext:openvsx_downloads", 0),
            },
        },
        "usage": {
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
                "WARN": total_warn,
                "INFO": 0,
            },
            "unique_installations_total": active_total,
            "unique_installations_today": active_today,
        },
        "impact": {
            "hallucinations_caught": kv.get("ct:hallucinations_caught", 0),
            "gateway_commands_blocked": kv.get("ct:gateway_blocks", 0),
            "gateway_commands_allowed": kv.get("ct:gateway_allowed", 0),
            "imports_verified": kv.get("ct:imports_verified", 0),
            "docker_images_verified": kv.get("ct:docker_verified", 0),
            "fixes_applied": kv.get("ct:fixes_applied", 0),
            "pr_gates_passed": kv.get("ct:pr_gates_passed", 0),
            "pr_gates_failed": kv.get("ct:pr_gates_failed", 0),
        },
        "quality": {
            "average_trust_score": avg_score,
            "trend_distribution": {
                "improving": kv.get("ct:trend:improving", 0),
                "stable": kv.get("ct:trend:stable", 0),
                "degrading": kv.get("ct:trend:degrading", 0),
            },
            "top_rules_triggered": top_rules,
        },
        "languages": languages,
        "layers": layers,
    }

    await r.set(STATS_CACHE_KEY, json.dumps(stats), ex=STATS_CACHE_TTL_SECONDS)
    return stats
