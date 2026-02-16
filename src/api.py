"""FastAPI application — CodeTrust HTTP API with auth and lifespan management."""

import asyncio
import os
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import structlog
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Security,
    WebSocket,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from starlette.responses import Response
from starlette.websockets import WebSocketDisconnect

from src.config import settings
from src.formatters.sarif import deep_scan_to_sarif, static_scan_to_sarif
from src.middleware.ip_rate_limit import IPRateLimitMiddleware
from src.middleware.metrics import MetricsMiddleware, metrics_endpoint
from src.models.enums import Language, Severity, VerifyStatus
from src.models.requests import (
    AstScanRequest,
    CheckoutRequest,
    CreateApiKeyRequest,
    DeepScanRequest,
    GithubAuthRequest,
    OIDCCallbackRequest,
    RefreshRequest,
    SandboxRequest,
    StaticScanRequest,
    VerifyDockerRequest,
    VerifyImportsRequest,
)
from src.models.responses import (
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    AstScanResponse,
    DeepScanResponse,
    Finding,
    HealthResponse,
    RevokeResponse,
    SandboxResponse,
    ScanHistoryResponse,
    ScanLogResponse,
    StaticScanResponse,
    StatusResponse,
    TokenResponse,
    UrlResponse,
    UsageDayResponse,
    UsageStatsResponse,
    UserProfileResponse,
    VerifyDockerResponse,
    VerifyImportsResponse,
)
from src.services.ast_analyzer import SUPPORTED_LANGUAGES as AST_LANGUAGES
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.billing import PLAN_LIMITS, BillingService
from src.services.cache import CacheService
from src.services.database import DatabaseService
from src.services.docker_verify import DockerVerifyService
from src.services.rate_limiter import RateLimiter
from src.services.registry import RegistryService
from src.services.sandbox import SUPPORTED_SANDBOX_LANGUAGES, SandboxService
from src.services.static_analyzer import StaticAnalyzer
from src.services.telemetry import TelemetryIngestEvent, process_telemetry_event
from src.utils.parsers import (
    extract_go_imports,
    extract_js_imports,
    extract_python_imports,
    extract_rust_imports,
    parse_dockerfile_from,
)

logger = structlog.get_logger()

# --- Auth Context ---


@dataclass
class AuthContext:
    """Resolved authentication context for a request."""

    user_id: str = "local"
    plan: str = "free"
    is_admin: bool = False
    api_key_id: str | None = field(default=None)


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _resolve_auth_from_key(
    key: str, db: DatabaseService | None,
) -> AuthContext:
    """Resolve auth from an API key (master or database-backed)."""
    if key == settings.api_key:
        return AuthContext(
            user_id="admin", plan="enterprise", is_admin=True,
        )
    if db is not None and key.startswith("ct_live_"):
        record = await db.verify_api_key_hash(key)
        if record is not None:
            user = await db.get_user(record.user_id)
            plan = user.plan if user else "free"
            return AuthContext(
                user_id=record.user_id,
                plan=plan,
                api_key_id=record.id,
            )
    return AuthContext()


async def _resolve_auth_from_bearer(
    token: str, auth_svc: AuthService | None,
) -> AuthContext | None:
    """Resolve auth from a Bearer JWT token."""
    if auth_svc is None or not auth_svc.jwt_configured():
        return None
    decoded = auth_svc.decode_jwt(token)
    if decoded is None:
        return None
    return AuthContext(
        user_id=decoded["user_id"],
        plan=decoded["plan"],
    )


async def get_auth_context(
    request: Request,
    key: str | None = Security(api_key_header),
) -> AuthContext:
    """Resolve authentication from API key, JWT bearer, or local dev mode.

    Priority: X-API-Key header > Authorization Bearer > local dev mode.
    """
    db = getattr(request.app.state, "db", None)
    auth_svc = getattr(request.app.state, "auth", None)

    auth_is_configured = (
        bool(settings.api_key)
        or (db is not None)
        or (auth_svc is not None and auth_svc.jwt_configured())
    )

    if key:
        if not auth_is_configured:
            # Unauthenticated mode: ignore any provided API key to avoid surprising 401s.
            return AuthContext()
        ctx = await _resolve_auth_from_key(key, db)
        if ctx.user_id != "local":
            return ctx
        raise HTTPException(
            status_code=401,
            detail="Invalid API key. Omit X-API-Key to use unauthenticated mode.",
        )

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if not auth_is_configured:
            # Unauthenticated mode: ignore bearer tokens.
            return AuthContext()
        ctx = await _resolve_auth_from_bearer(token, auth_svc)
        if ctx is not None:
            return ctx
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if not settings.api_key:
        return AuthContext()

    raise HTTPException(status_code=401, detail="Authentication required")





async def _startup(app: FastAPI) -> None:
    """Create and attach shared resources to app state."""
    cache = CacheService(settings.redis_url)
    await cache.connect()

    http_client = httpx.AsyncClient(
        timeout=settings.http_timeout,
        limits=httpx.Limits(
            max_connections=settings.http_max_connections,
            max_keepalive_connections=settings.http_max_keepalive,
        ),
    )

    db: DatabaseService | None
    try:
        db = DatabaseService(settings.database_url, echo=settings.database_echo)
        await db.create_tables()
    except Exception as exc:
        logger.warning(
            "database_init_skipped",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        db = None

    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.ast_analyzer = AstAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = db
    app.state.billing = BillingService()
    app.state.auth = AuthService(http_client)
    app.state.rate_limiter = RateLimiter(db) if db is not None else None

    # --- Telemetry background services (best-effort) ---
    app.state.telemetry_stop = asyncio.Event()
    app.state.telemetry_queue = asyncio.Queue(maxsize=10_000)
    app.state.ws_clients = set()
    app.state.telemetry_bg_tasks = set()

    redis_client = cache.raw_client()
    if redis_client is not None:
        from src.services.telemetry import stats_worker

        app.state.stats_worker_task = asyncio.create_task(
            stats_worker(r=redis_client, http_client=http_client, stop=app.state.telemetry_stop),
        )
    else:
        app.state.stats_worker_task = None

    app.state.telemetry_writer_task = None
    if db is not None:
        app.state.telemetry_writer_task = asyncio.create_task(_telemetry_batch_writer(app))


async def _shutdown(app: FastAPI) -> None:
    """Close all connections and dispose of resources."""
    logger.info("api_shutdown")

    stop = getattr(app.state, "telemetry_stop", None)
    if isinstance(stop, asyncio.Event):
        stop.set()

    for task_name in ("telemetry_writer_task", "stats_worker_task"):
        task = getattr(app.state, task_name, None)
        if task is not None:
            task.cancel()

    await app.state.http_client.aclose()
    await app.state.cache.disconnect()
    if app.state.db is not None:
        await app.state.db.close()


# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize and teardown shared resources."""
    logger.info("api_startup", version=settings.version)
    await _startup(app)
    yield
    await _shutdown(app)


# --- Application ---
app = FastAPI(
    title="CodeTrust API",
    version=settings.version,
    description="AI code verification platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.dashboard_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# IP-based rate limiting - runs before auth, catches unauthenticated floods
app.add_middleware(IPRateLimitMiddleware)

# Prometheus metrics — request counts, latency, active connections
app.add_middleware(MetricsMiddleware)
app.add_route("/metrics", metrics_endpoint, methods=["GET"])

API_TELEMETRY_SKIP_PATHS: set[str] = {
    "/metrics",
    "/v1/telemetry",
    "/v1/stats/public",
    "/v1/status",
}


@app.middleware("http")
async def api_request_telemetry(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Emit anonymous request telemetry (best-effort).

    Never blocks the request path; skips endpoints that would cause recursion or noise.
    """

    path = request.url.path
    if request.method == "OPTIONS" or path in API_TELEMETRY_SKIP_PATHS:
        return await call_next(request)

    started = time.monotonic()
    status_code: int = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        return response
    finally:
        duration_ms = int((time.monotonic() - started) * 1000)

        cache: CacheService | None = getattr(request.app.state, "cache", None)
        redis_client = cache.raw_client() if cache is not None else None
        queue = getattr(request.app.state, "telemetry_queue", None)

        try:
            event = TelemetryIngestEvent(
                event_type="api_request_completed",
                source="cloud_api",
                installation_id=None,
                version=settings.version,
                payload={
                    "method": request.method,
                    "path": path,
                    "status_code": int(status_code),
                    "duration_ms": int(duration_ms),
                },
            )
        except Exception:
            return

        async def _emit() -> None:
            try:
                await process_telemetry_event(r=redis_client, queue=queue, event=event)
            except Exception:
                return

        try:
            task = asyncio.create_task(_emit())
            tasks: set[asyncio.Task[None]] = getattr(request.app.state, "telemetry_bg_tasks", set())
            tasks.add(task)
            request.app.state.telemetry_bg_tasks = tasks

            def _cleanup(done: asyncio.Task[None]) -> None:
                tasks.discard(done)

            task.add_done_callback(_cleanup)
        except Exception:
            return


def _get_registry(request: Request) -> RegistryService:
    """Dependency: get RegistryService from app state."""
    return request.app.state.registry


def _get_docker(request: Request) -> DockerVerifyService:
    """Dependency: get DockerVerifyService from app state."""
    return request.app.state.docker


def _get_analyzer(request: Request) -> StaticAnalyzer:
    """Dependency: get StaticAnalyzer from app state."""
    return request.app.state.analyzer


def _get_ast_analyzer(request: Request) -> AstAnalyzer:
    """Dependency: get AstAnalyzer from app state."""
    return request.app.state.ast_analyzer


def _get_cache(request: Request) -> CacheService:
    """Dependency: get CacheService from app state."""
    return request.app.state.cache


def _get_sandbox(request: Request) -> SandboxService:
    """Dependency: get SandboxService from app state."""
    return request.app.state.sandbox


def _get_db(request: Request) -> DatabaseService:
    """Dependency: get DatabaseService from app state."""
    db = request.app.state.db
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    return db


def _get_billing(request: Request) -> BillingService:
    """Dependency: get BillingService from app state."""
    return request.app.state.billing


def _get_auth(request: Request) -> AuthService:
    """Dependency: get AuthService from app state."""
    return request.app.state.auth


def _get_rate_limiter(request: Request) -> RateLimiter | None:
    """Dependency: get RateLimiter from app state (None if DB unavailable)."""
    return request.app.state.rate_limiter


async def _enforce_rate_limit(
    auth: AuthContext, rate_limiter: RateLimiter | None,
) -> None:
    """Check rate limit for a user. Raises 429 if exceeded."""
    if auth.is_admin or rate_limiter is None:
        return
    allowed, current, limit = await rate_limiter.check_limit(
        auth.user_id, auth.plan,
    )
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "current_usage": current,
                "daily_limit": limit,
                "plan": auth.plan,
                "message": f"Daily limit of {limit} scans exceeded. "
                f"Upgrade your plan for higher limits.",
            },
        )


async def _log_scan(
    request: Request,
    auth: AuthContext,
    scan_type: str,
    verdict: str,
    findings_count: int,
    latency_ms: int,
    language: str = "",
    filename: str = "",
) -> None:
    """Log a scan execution and increment usage counters."""
    db = getattr(request.app.state, "db", None)
    rate_limiter = getattr(request.app.state, "rate_limiter", None)
    if db is None:
        return
    try:
        await db.log_scan(
            user_id=auth.user_id,
            scan_type=scan_type,
            verdict=verdict,
            findings_count=findings_count,
            latency_ms=latency_ms,
            language=language,
            filename=filename,
            api_key_id=auth.api_key_id,
        )
        if rate_limiter is not None:
            await rate_limiter.increment(
                auth.user_id, findings_count, latency_ms,
            )
    except Exception as exc:
        logger.warning("scan_logging_failed", error=str(exc))


# --- Endpoints ---


@app.get("/v1/status", response_model=HealthResponse)
async def health_check(
    cache: CacheService = Depends(_get_cache),
) -> HealthResponse:
    """Health check endpoint."""
    connected = await cache.is_connected()
    return HealthResponse(
        status="ok",
        version=settings.version,
        cache_connected=connected,
    )


@app.get("/v1/stats/public")
async def public_stats(request: Request) -> dict:
    """Public aggregate stats for landing page — no auth required."""
    db = getattr(request.app.state, "db", None)
    cache = getattr(request.app.state, "cache", None)
    http_client = getattr(request.app.state, "http_client", None)

    redis_client = cache.raw_client() if cache is not None else None
    if redis_client is not None:
        from src.services.telemetry import build_public_stats

        stats = await build_public_stats(r=redis_client, use_cache=True)

        # Backwards-compatible flat keys for existing website counters.
        legacy: dict[str, int] = {
            "total_scans": int(stats.get("usage", {}).get("total_scans", 0)),
            "hallucinated_packages_prevented": int(stats.get("impact", {}).get("hallucinations_caught", 0)),
            "destructive_commands_blocked": int(stats.get("impact", {}).get("gateway_commands_blocked", 0)),
            "pypi_downloads_last_week": int(
                stats.get("distribution", {}).get("pypi", {}).get("downloads_this_week", 0)
            ),
            "marketplace_installs": int(
                stats.get("distribution", {}).get("marketplace", {}).get("installs", 0)
            ),
            "marketplace_downloads": int(
                stats.get("distribution", {}).get("marketplace", {}).get("downloads", 0)
            ),
            "openvsx_downloads": int(
                stats.get("distribution", {}).get("open_vsx", {}).get("downloads", 0)
            ),
        }
        return {**legacy, "stats": stats}

    # Fallback for deployments without Redis.
    from src.services.public_stats import get_marketplace_stats, get_open_vsx_stats, get_pypi_download_stats

    base: dict[str, int] = {
        "total_scans": 0,
        "hallucinated_packages_prevented": 0,
        "destructive_commands_blocked": 0,
        "pypi_downloads_last_day": 0,
        "pypi_downloads_last_week": 0,
        "pypi_downloads_last_month": 0,
        "marketplace_installs": 0,
        "marketplace_downloads": 0,
        "marketplace_updates": 0,
        "openvsx_downloads": 0,
    }

    if db is not None:
        try:
            base.update(await db.get_public_stats())
        except Exception as exc:
            logger.warning("public_stats_failed", error=str(exc))

    if cache is None or http_client is None:
        return base

    if cache is None or http_client is None:
        return base

    pypi = await get_pypi_download_stats(http_client=http_client, cache=cache)
    marketplace = await get_marketplace_stats(http_client=http_client, cache=cache)
    openvsx = await get_open_vsx_stats(http_client=http_client, cache=cache)
    return {**base, **pypi, **marketplace, **openvsx}


async def _telemetry_batch_writer(app: FastAPI) -> None:
    """Flush telemetry write queue into the database in batches."""

    from src.services.telemetry import (
        TELEMETRY_BATCH_SIZE,
        TELEMETRY_FLUSH_INTERVAL_SECONDS,
        TelemetryWriteItem,
    )

    queue: asyncio.Queue[TelemetryWriteItem] | None = getattr(app.state, "telemetry_queue", None)
    stop: asyncio.Event | None = getattr(app.state, "telemetry_stop", None)
    db: DatabaseService | None = getattr(app.state, "db", None)

    if queue is None or stop is None or db is None:
        return

    while not stop.is_set():
        batch: list[TelemetryWriteItem] = []
        try:
            while len(batch) < TELEMETRY_BATCH_SIZE:
                item = await asyncio.wait_for(queue.get(), timeout=TELEMETRY_FLUSH_INTERVAL_SECONDS)
                batch.append(item)
        except TimeoutError:
            if not batch:
                continue
        except Exception as exc:
            logger.warning("telemetry_queue_read_failed", error=str(exc), error_type=type(exc).__name__)

        if not batch:
            continue

        try:
            await db.insert_telemetry_raw_batch(
                [
                    {
                        "event_type": b.event_type,
                        "source": b.source,
                        "installation_id": b.installation_id or "",
                        "version": b.version or "",
                        "payload": b.payload,
                    }
                    for b in batch
                ]
            )
        except Exception as exc:
            logger.warning("telemetry_db_batch_failed", error=str(exc), error_type=type(exc).__name__)


@app.post("/v1/telemetry", status_code=202, response_model=StatusResponse)
async def ingest_telemetry(
    event: dict[str, object],
    request: Request,
    background_tasks: BackgroundTasks,
) -> StatusResponse:
    """Accept anonymous telemetry.

    Returns immediately (202). Processing is best-effort and must never block.
    """

    from src.services.telemetry import TelemetryIngestEvent, process_telemetry_event

    try:
        parsed = TelemetryIngestEvent.model_validate(event)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid telemetry payload") from exc

    cache = getattr(request.app.state, "cache", None)
    redis_client = cache.raw_client() if cache is not None else None
    queue = getattr(request.app.state, "telemetry_queue", None)

    background_tasks.add_task(
        process_telemetry_event,
        r=redis_client,
        queue=queue,
        event=parsed,
    )
    background_tasks.add_task(_notify_ws_clients, request, parsed.event_type)
    return StatusResponse(status="accepted")


async def _notify_ws_clients(request: Request, event_type: str) -> None:
    cache = getattr(request.app.state, "cache", None)
    redis_client = cache.raw_client() if cache is not None else None
    ws_clients: set[WebSocket] = getattr(request.app.state, "ws_clients", set())
    if redis_client is None or not ws_clients:
        return

    from src.services.telemetry import build_public_stats

    try:
        stats = await build_public_stats(r=redis_client, use_cache=False)
    except Exception as exc:
        logger.warning("ws_stats_build_failed", error=str(exc), error_type=type(exc).__name__)
        return

    dead: set[WebSocket] = set()
    for ws in ws_clients:
        try:
            await ws.send_json({"event": event_type, "stats": stats})
        except Exception:
            dead.add(ws)
    for ws in dead:
        ws_clients.discard(ws)


@app.websocket("/v1/stats/live")
async def stats_websocket(websocket: WebSocket) -> None:
    """Push live stats updates to connected clients."""

    await websocket.accept()
    ws_clients: set[WebSocket] = getattr(app.state, "ws_clients", set())
    ws_clients.add(websocket)
    app.state.ws_clients = ws_clients
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_clients.discard(websocket)


@app.get("/v1/governance/audit")
async def governance_audit(
    hours: int = 24,
    verdict: str | None = None,
    limit: int = 100,
) -> dict:
    """Query the governance audit log.

    Returns recent audit entries and aggregate statistics.
    Reads from .codetrust/audit.jsonl in the workspace.

    Args:
        hours: How many hours back to search (default: 24).
        verdict: Filter by verdict: ALLOW, WARN, BLOCK.
        limit: Maximum entries to return (default: 100).

    Returns:
        Dict with entries list and stats summary.
    """
    from src.gateway.audit import AuditLogger

    audit_path = os.path.join(os.getcwd(), ".codetrust", "audit.jsonl")
    logger_instance = AuditLogger(audit_path)

    since = time.time() - (hours * 3600)
    entries = logger_instance.get_entries(
        since=since,
        verdict=verdict,
        limit=limit,
    )
    stats = logger_instance.get_stats()

    return {
        "entries": [
            {
                "timestamp": e.timestamp,
                "action_type": e.action_type,
                "verdict": e.verdict,
                "rule_id": e.rule_id,
                "original_action": e.original_action,
                "message": e.message,
                "agent_id": e.agent_id,
                "session_id": e.session_id,
            }
            for e in entries
        ],
        "stats": stats,
    }


@app.post("/v1/verify/imports", response_model=VerifyImportsResponse)
async def verify_imports(
    request: Request,
    req: VerifyImportsRequest,
    registry: RegistryService = Depends(_get_registry),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> VerifyImportsResponse:
    """Verify package imports exist in registries."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_verify_imports", language=req.language, count=len(req.imports))
    start = time.monotonic()

    results = await registry.verify_packages(req.language, req.imports, req.requirements)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    response = _build_imports_response(results, elapsed_ms)

    await _log_scan(
        request, auth, "imports", "PASS" if response.failed == 0 else "BLOCK",
        len(response.results), elapsed_ms, str(req.language),
    )
    return response


@app.post("/v1/verify/dockerfile", response_model=VerifyDockerResponse)
async def verify_dockerfile(
    request: Request,
    req: VerifyDockerRequest,
    docker: DockerVerifyService = Depends(_get_docker),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> VerifyDockerResponse:
    """Verify Docker images and tags exist on Docker Hub."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_verify_dockerfile", count=len(req.images))
    start = time.monotonic()

    results = await docker.verify_images(req.images)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    verified = sum(1 for r in results if r.status == VerifyStatus.VERIFIED)
    failed = len(results) - verified
    response = VerifyDockerResponse(
        verified=verified, failed=failed, results=results, latency_ms=elapsed_ms,
    )
    await _log_scan(
        request, auth, "dockerfile",
        "PASS" if failed == 0 else "BLOCK", len(results), elapsed_ms,
    )
    return response


@app.post("/v1/scan/static", response_model=StaticScanResponse)
async def static_scan(
    request: Request,
    req: StaticScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> StaticScanResponse:
    """Run static anti-pattern analysis on code."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_static_scan", filename=req.filename)
    start = time.monotonic()
    findings = analyzer.scan_code(req.code, req.filename)
    response = analyzer.build_scan_response(findings)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    await _log_scan(
        request, auth, "static", response.verdict,
        response.total_findings, elapsed_ms, filename=req.filename,
    )
    return response


@app.post("/v1/scan/ast", response_model=AstScanResponse)
async def ast_scan(
    request: Request,
    req: AstScanRequest,
    ast_anal: AstAnalyzer = Depends(_get_ast_analyzer),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> AstScanResponse:
    """Run AST-based code analysis using tree-sitter."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_ast_scan", filename=req.filename, language=req.language)
    start = time.monotonic()

    if req.language not in AST_LANGUAGES:
        return AstScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )

    findings = ast_anal.analyze(
        req.code, req.language, req.filename,
        req.max_nesting, req.complexity_threshold,
    )
    response = _build_ast_response(findings)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    await _log_scan(
        request, auth, "ast", response.verdict,
        response.total_findings, elapsed_ms, str(req.language), req.filename,
    )
    return response


@app.post("/v1/sandbox/run", response_model=SandboxResponse)
async def sandbox_run(
    request: Request,
    req: SandboxRequest,
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> SandboxResponse:
    """Execute code in an isolated Docker sandbox."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_sandbox_run", language=req.language, timeout=req.timeout)

    if req.language not in SUPPORTED_SANDBOX_LANGUAGES:
        return SandboxResponse(
            exit_code=-1, stdout="", stderr="", timed_out=False,
            error=f"Unsupported sandbox language: {req.language}", latency_ms=0,
        )

    result = await sandbox_svc.execute_code(req.code, req.language, req.timeout)
    verdict = "PASS" if result.exit_code == 0 and not result.timed_out else "BLOCK"
    await _log_scan(
        request, auth, "sandbox", verdict, 0,
        result.latency_ms, str(req.language), req.filename,
    )
    return result


@app.post("/v1/scan/static/sarif", response_model=dict[str, object])
async def static_scan_sarif(
    request: Request,
    req: StaticScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> dict[str, object]:
    """Run static analysis and return results in SARIF format."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_static_sarif", filename=req.filename)
    start = time.monotonic()
    findings = analyzer.scan_code(req.code, req.filename)
    response = analyzer.build_scan_response(findings)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    await _log_scan(
        request, auth, "static_sarif", response.verdict,
        response.total_findings, elapsed_ms,
        str(req.language) if req.language else "", req.filename,
    )
    return static_scan_to_sarif(response)


@app.post("/v1/scan/deep/sarif", response_model=dict[str, object])
async def deep_scan_sarif(
    request: Request,
    req: DeepScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    ast_anal: AstAnalyzer = Depends(_get_ast_analyzer),
    registry: RegistryService = Depends(_get_registry),
    docker: DockerVerifyService = Depends(_get_docker),
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> dict[str, object]:
    """Run deep scan and return results in SARIF format."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_deep_sarif", filename=req.filename)
    start = time.monotonic()
    deep_result = await _run_deep_scan_core(
        req, analyzer, ast_anal, registry, docker, sandbox_svc,
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)
    await _log_scan(
        request, auth, "deep_sarif", deep_result.overall_verdict,
        deep_result.total_findings, elapsed_ms,
        str(req.language) if req.language else "", req.filename,
    )
    return deep_scan_to_sarif(deep_result)


@app.post("/v1/scan/deep", response_model=DeepScanResponse)
async def deep_scan(
    request: Request,
    req: DeepScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    ast_anal: AstAnalyzer = Depends(_get_ast_analyzer),
    registry: RegistryService = Depends(_get_registry),
    docker: DockerVerifyService = Depends(_get_docker),
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> DeepScanResponse:
    """Run full deep scan combining all layers."""
    await _enforce_rate_limit(auth, rate_limiter)
    logger.info("api_deep_scan", filename=req.filename)
    start = time.monotonic()

    result = await _run_deep_scan_core(
        req, analyzer, ast_anal, registry, docker, sandbox_svc,
    )
    elapsed_ms = int((time.monotonic() - start) * 1000)
    result.latency_ms = elapsed_ms

    await _log_scan(
        request, auth, "deep", result.overall_verdict,
        result.total_findings, elapsed_ms,
        str(req.language) if req.language else "", req.filename,
    )
    return result


async def _run_deep_scan_core(
    req: DeepScanRequest,
    analyzer: StaticAnalyzer,
    ast_anal: AstAnalyzer,
    registry: RegistryService,
    docker: DockerVerifyService,
    sandbox_svc: SandboxService,
) -> DeepScanResponse:
    """Core deep scan logic shared between JSON and SARIF endpoints."""
    start = time.monotonic()
    static_result = analyzer.build_scan_response(
        analyzer.scan_code(req.code, req.filename),
    )
    ast_result = _run_ast_layer(req, ast_anal)
    import_result = await _run_import_layer(req, registry)
    docker_result = await _run_docker_layer(req, docker)
    sandbox_result = await _run_sandbox_layer(req, sandbox_svc)

    return _assemble_deep_response(
        static_result, ast_result, import_result,
        docker_result, sandbox_result, start,
    )


def _run_ast_layer(
    req: DeepScanRequest, ast_anal: AstAnalyzer,
) -> AstScanResponse | None:
    """Run AST analysis layer if language supports it."""
    if req.language and req.language in AST_LANGUAGES:
        findings = ast_anal.analyze(req.code, req.language, req.filename)
        return _build_ast_response(findings)
    return None


async def _run_import_layer(
    req: DeepScanRequest, registry: RegistryService,
) -> VerifyImportsResponse | None:
    """Run import verification layer if requested."""
    if req.verify_imports and req.language:
        return await _verify_imports_from_code(
            req.code, req.language, req.requirements_content, registry,
        )
    return None


async def _run_docker_layer(
    req: DeepScanRequest, docker: DockerVerifyService,
) -> VerifyDockerResponse | None:
    """Run Docker verification layer if requested."""
    if req.verify_docker and req.dockerfile_content:
        return await _verify_docker_from_content(req.dockerfile_content, docker)
    return None


async def _run_sandbox_layer(
    req: DeepScanRequest, sandbox_svc: SandboxService,
) -> SandboxResponse | None:
    """Run sandbox execution layer if requested."""
    if req.sandbox_run and req.language in SUPPORTED_SANDBOX_LANGUAGES:
        return await sandbox_svc.execute_code(req.code, req.language)
    return None


def _assemble_deep_response(
    static_result: StaticScanResponse,
    ast_result: AstScanResponse | None,
    import_result: VerifyImportsResponse | None,
    docker_result: VerifyDockerResponse | None,
    sandbox_result: SandboxResponse | None,
    start: float,
) -> DeepScanResponse:
    """Assemble the final DeepScanResponse from layer results."""
    elapsed_ms = int((time.monotonic() - start) * 1000)
    overall = _compute_overall_verdict(
        static_result, ast_result, import_result, docker_result, sandbox_result,
    )
    total = _compute_total_findings(
        static_result, ast_result, import_result, docker_result,
    )
    return DeepScanResponse(
        static_scan=static_result,
        ast_scan=ast_result,
        import_verification=import_result,
        docker_verification=docker_result,
        sandbox_result=sandbox_result,
        overall_verdict=overall,
        total_findings=total,
        latency_ms=elapsed_ms,
    )


# --- Internal helpers ---


async def _verify_imports_from_code(
    code: str,
    language: Language,
    requirements: str,
    registry: RegistryService,
) -> VerifyImportsResponse:
    """Extract imports from code and verify against registries."""
    start = time.monotonic()

    if language == Language.PYTHON:
        imports = extract_python_imports(code)
    elif language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
        imports = extract_js_imports(code)
    elif language == Language.GO:
        imports = extract_go_imports(code)
    elif language == Language.RUST:
        imports = extract_rust_imports(code)
    else:
        imports = []

    if not imports:
        return VerifyImportsResponse(
            verified=0, failed=0, warnings=0,
            results=[], latency_ms=0, cached_ratio=0.0,
        )

    results = await registry.verify_packages(language, imports, requirements)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    return _build_imports_response(results, elapsed_ms)


async def _verify_docker_from_content(
    dockerfile_content: str,
    docker: DockerVerifyService,
) -> VerifyDockerResponse:
    """Parse Dockerfile and verify images."""
    from src.models.requests import DockerImageInput

    start = time.monotonic()
    parsed = parse_dockerfile_from(dockerfile_content)

    if not parsed:
        return VerifyDockerResponse(
            verified=0, failed=0, results=[], latency_ms=0,
        )

    inputs = [DockerImageInput(image=img, tag=tag) for img, tag in parsed]
    results = await docker.verify_images(inputs)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    verified = sum(1 for r in results if r.status == VerifyStatus.VERIFIED)
    failed = len(results) - verified
    return VerifyDockerResponse(
        verified=verified,
        failed=failed,
        results=results,
        latency_ms=elapsed_ms,
    )


def _build_imports_response(
    results: list[object],
    elapsed_ms: int,
) -> VerifyImportsResponse:
    """Build a VerifyImportsResponse from a list of PackageResults."""
    from src.models.responses import PackageResult

    typed_results: list[PackageResult] = []
    for r in results:
        if isinstance(r, PackageResult):
            typed_results.append(r)

    verified = sum(1 for r in typed_results if r.status == VerifyStatus.VERIFIED)
    failed = sum(
        1 for r in typed_results
        if r.status in (VerifyStatus.NOT_FOUND, VerifyStatus.VERSION_MISMATCH)
    )
    warnings = sum(
        1 for r in typed_results
        if r.status in (VerifyStatus.DEPRECATED, VerifyStatus.TIMEOUT, VerifyStatus.ERROR)
    )
    cached_count = sum(1 for r in typed_results if r.cached)
    total = len(typed_results)
    cached_ratio = cached_count / total if total > 0 else 0.0

    return VerifyImportsResponse(
        verified=verified,
        failed=failed,
        warnings=warnings,
        results=typed_results,
        latency_ms=elapsed_ms,
        cached_ratio=cached_ratio,
    )


def _build_ast_response(findings: list[Finding]) -> AstScanResponse:
    """Build an AstScanResponse from a list of findings."""
    blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
    warns = sum(1 for f in findings if f.severity == Severity.WARN)
    infos = sum(1 for f in findings if f.severity == Severity.INFO)

    verdict = "PASS"
    if blocks > 0:
        verdict = "BLOCK"
    elif warns > 0:
        verdict = "WARN"

    return AstScanResponse(
        total_findings=len(findings),
        blocks=blocks,
        warnings=warns,
        infos=infos,
        findings=findings,
        verdict=verdict,
    )


def _compute_overall_verdict(
    static: StaticScanResponse,
    ast: AstScanResponse | None,
    imports: VerifyImportsResponse | None,
    docker: VerifyDockerResponse | None,
    sandbox: SandboxResponse | None = None,
) -> str:
    """Compute overall verdict from sub-results."""
    if static.verdict == "BLOCK":
        return "BLOCK"

    if ast is not None and ast.verdict == "BLOCK":
        return "BLOCK"

    if imports is not None and imports.failed > 0:
        return "BLOCK"

    if docker is not None and docker.failed > 0:
        return "BLOCK"

    if sandbox is not None and sandbox.exit_code != 0:
        return "BLOCK"

    if sandbox is not None and sandbox.timed_out:
        return "BLOCK"

    if static.verdict == "WARN":
        return "WARN"

    if ast is not None and ast.verdict == "WARN":
        return "WARN"

    if imports is not None and imports.warnings > 0:
        return "WARN"

    if sandbox is not None and sandbox.error:
        return "WARN"

    return "PASS"


def _compute_total_findings(
    static: StaticScanResponse,
    ast: AstScanResponse | None,
    imports: VerifyImportsResponse | None,
    docker: VerifyDockerResponse | None,
) -> int:
    """Count total findings across all layers."""
    total = static.total_findings

    if ast is not None:
        total += ast.total_findings

    if imports is not None:
        total += len(imports.results)

    if docker is not None:
        total += len(docker.results)

    return total


def run() -> None:
    """Run the API server with uvicorn."""
    import uvicorn

    uvicorn.run(
        "src.api:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )


# --- Dashboard: API Key management ---


@app.post("/v1/api-keys", response_model=ApiKeyCreatedResponse)
async def create_api_key(
    req: CreateApiKeyRequest,
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> ApiKeyCreatedResponse:
    """Create a new API key for the authenticated user."""
    raw_key, record = await db.create_api_key(auth.user_id, req.name)
    return ApiKeyCreatedResponse(
        key=raw_key, id=record.id, name=record.name, prefix=record.prefix,
    )


@app.get("/v1/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> list[ApiKeyResponse]:
    """List all API keys for the authenticated user."""
    records = await db.list_api_keys(auth.user_id)
    return [
        ApiKeyResponse(
            id=r.id, name=r.name, prefix=r.prefix,
            is_revoked=r.is_revoked,
            created_at=r.created_at.isoformat() if r.created_at else "",
            last_used_at=r.last_used_at.isoformat() if r.last_used_at else "",
        )
        for r in records
    ]


@app.delete("/v1/api-keys/{key_id}", response_model=RevokeResponse)
async def revoke_api_key(
    key_id: str,
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> RevokeResponse:
    """Revoke an API key."""
    success = await db.revoke_api_key(key_id, auth.user_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    return RevokeResponse(revoked=True)


# --- Dashboard: Scan history ---


@app.get("/v1/scans/history", response_model=ScanHistoryResponse)
async def scan_history(
    page: int = Query(default=1, ge=1, le=1000),
    per_page: int = Query(default=20, ge=1, le=100),
    scan_type: str | None = None,
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> ScanHistoryResponse:
    """Get paginated scan history for the authenticated user."""
    logs = await db.get_scan_history(auth.user_id, page, per_page, scan_type)
    total = await db.count_scans(auth.user_id, scan_type)
    return ScanHistoryResponse(
        scans=[
            ScanLogResponse(
                id=log.id,
                scan_type=log.scan_type,
                verdict=log.verdict,
                findings_count=log.findings_count,
                language=log.language,
                filename=log.filename,
                latency_ms=log.latency_ms,
                created_at=log.created_at.isoformat() if log.created_at else "",
            )
            for log in logs
        ],
        page=page,
        per_page=per_page,
        total=total,
    )


# --- Dashboard: Usage stats ---


@app.get("/v1/usage", response_model=UsageStatsResponse)
async def usage_stats(
    days: int = Query(default=30, ge=1, le=365),
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> UsageStatsResponse:
    """Get daily usage statistics for the authenticated user."""
    usage_days = await db.get_usage_stats(auth.user_id, days)
    total_scans = sum(d.scan_count for d in usage_days)
    return UsageStatsResponse(
        days=[
            UsageDayResponse(
                date=d.date.isoformat(),
                scan_count=d.scan_count,
                findings_total=d.findings_total,
                avg_latency_ms=d.avg_latency_ms,
            )
            for d in usage_days
        ],
        total_scans=total_scans,
        period_days=days,
    )


# --- Dashboard: Billing ---


@app.post("/v1/billing/checkout", response_model=UrlResponse)
async def billing_checkout(
    request: Request,
    req: CheckoutRequest,
    billing: BillingService = Depends(_get_billing),
    auth: AuthContext = Depends(get_auth_context),
) -> UrlResponse:
    """Create a Stripe checkout session for upgrading plans."""
    if not billing.is_configured():
        raise HTTPException(status_code=503, detail="Billing not configured")

    customer_id = ""
    db = getattr(request.app.state, "db", None)
    if db is not None:
        user = await db.get_user(auth.user_id)
        if user is not None:
            customer_id = user.stripe_customer_id or ""
    url = await billing.create_checkout_session(
        customer_id=customer_id,
        plan=req.plan,
    )
    if not url:
        raise HTTPException(status_code=500, detail="Failed to create checkout")
    return UrlResponse(url=url)


@app.post("/v1/billing/portal", response_model=UrlResponse)
async def billing_portal(
    request: Request,
    billing: BillingService = Depends(_get_billing),
    auth: AuthContext = Depends(get_auth_context),
) -> UrlResponse:
    """Create a Stripe customer portal session."""
    if not billing.is_configured():
        raise HTTPException(status_code=503, detail="Billing not configured")

    customer_id = ""
    db = getattr(request.app.state, "db", None)
    if db is not None:
        user = await db.get_user(auth.user_id)
        if user is not None:
            customer_id = user.stripe_customer_id or ""
    url = await billing.create_portal_session(customer_id=customer_id)
    if not url:
        raise HTTPException(status_code=500, detail="Failed to create portal session")
    return UrlResponse(url=url)


@app.post("/v1/webhooks/stripe", response_model=StatusResponse)
async def stripe_webhook(
    request: Request,
    billing: BillingService = Depends(_get_billing),
    db: DatabaseService = Depends(_get_db),
) -> StatusResponse:
    """Handle Stripe webhook events for subscription changes."""
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    event = billing.construct_webhook_event(payload, sig)
    if event is None:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    await _handle_stripe_event(event, db)
    return StatusResponse(status="ok")


async def _handle_stripe_event(
    event: object, db: DatabaseService,
) -> None:
    """Process a Stripe webhook event."""
    import stripe as stripe_lib

    if not isinstance(event, stripe_lib.Event):
        return

    if event.type == "checkout.session.completed":
        session = event.data.object
        customer_id = getattr(session, "customer", "")
        sub_id = getattr(session, "subscription", "")
        plan = getattr(session, "metadata", {}).get("plan", "pro")
        logger.info(
            "stripe_checkout_completed",
            customer_id=customer_id,
            sub_id=sub_id,
            plan=plan,
        )
        if customer_id and db is not None:
            user = await db.get_user_by_stripe_customer_id(customer_id)
            if user is not None:
                await db.update_user_plan(
                    user.id, plan,
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=sub_id,
                )

    elif event.type == "customer.subscription.deleted":
        sub = event.data.object
        customer_id = getattr(sub, "customer", "")
        logger.info("stripe_sub_deleted", customer_id=customer_id)
        if customer_id and db is not None:
            user = await db.get_user_by_stripe_customer_id(customer_id)
            if user is not None:
                await db.update_user_plan(user.id, "free")


# --- Auth: GitHub OAuth + JWT ---


@app.post("/v1/auth/github", response_model=TokenResponse)
async def github_auth(
    req: GithubAuthRequest,
    auth_svc: AuthService = Depends(_get_auth),
    db: DatabaseService = Depends(_get_db),
) -> TokenResponse:
    """Exchange a GitHub OAuth code for a JWT token."""
    if not auth_svc.is_configured():
        raise HTTPException(status_code=503, detail="OAuth not configured")

    user_info = await auth_svc.exchange_github_code(req.code)
    if not user_info or not user_info.get("github_id"):
        raise HTTPException(status_code=401, detail="GitHub auth failed")

    user = await db.get_or_create_user(
        github_id=user_info["github_id"],
        email=user_info.get("email", ""),
        name=user_info.get("name", ""),
        avatar_url=user_info.get("avatar_url", ""),
    )

    token = auth_svc.create_jwt(user.id, user.plan)
    return TokenResponse(
        token=token,
        user_id=user.id,
        plan=user.plan,
        expires_in_minutes=settings.jwt_expire_minutes,
    )


@app.post("/v1/auth/refresh", response_model=TokenResponse)
async def refresh_token(
    req: RefreshRequest,
    auth_svc: AuthService = Depends(_get_auth),
    db: DatabaseService = Depends(_get_db),
) -> TokenResponse:
    """Refresh an expiring JWT token."""
    decoded = auth_svc.decode_jwt(req.token)
    if decoded is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await db.get_user(decoded["user_id"])
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    new_token = auth_svc.create_jwt(user.id, user.plan)
    return TokenResponse(
        token=new_token,
        user_id=user.id,
        plan=user.plan,
        expires_in_minutes=settings.jwt_expire_minutes,
    )


# --- Dashboard: User Profile ---


@app.get("/v1/profile", response_model=UserProfileResponse)
async def user_profile(
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> UserProfileResponse:
    """Get the authenticated user's profile and usage stats."""
    user = await db.get_user(auth.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    daily_usage = await db.get_daily_usage(auth.user_id)
    limit = PLAN_LIMITS.get(user.plan, PLAN_LIMITS.get("free", 100))

    return UserProfileResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        avatar_url=user.avatar_url,
        plan=user.plan,
        created_at=user.created_at.isoformat() if user.created_at else "",
        daily_limit=limit,
        daily_usage=daily_usage,
    )


if __name__ == "__main__":
    run()


# --- SSO / OIDC ---


@app.get("/v1/auth/oidc/login")
async def oidc_login(
    request: Request,
    state: str = Query(default=""),
) -> dict:
    """Redirect URL for OIDC/SSO login.

    Returns the authorization URL to redirect the browser to the IdP.
    Requires OIDC to be configured via CODETRUST_OIDC_* env vars.
    """
    from src.services.sso import OIDCConfig, OIDCService

    if not settings.oidc_enabled:
        raise HTTPException(status_code=503, detail="OIDC not configured")

    http_client = request.app.state.http_client
    config = OIDCConfig(
        enabled=True,
        issuer=settings.oidc_issuer,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        redirect_uri=settings.oidc_redirect_uri,
        scopes=settings.oidc_scopes.split(","),
        allowed_domains=(
            settings.oidc_allowed_domains.split(",")
            if settings.oidc_allowed_domains
            else []
        ),
        role_claim=settings.oidc_role_claim,
    )
    svc = OIDCService(config, http_client)
    discovered = await svc.discover()
    if not discovered:
        raise HTTPException(status_code=502, detail="OIDC discovery failed")

    import secrets as _secrets

    actual_state = state or _secrets.token_urlsafe(32)
    url = svc.build_auth_url(state=actual_state)
    return {"auth_url": url, "state": actual_state}


@app.post("/v1/auth/oidc/callback", response_model=TokenResponse)
async def oidc_callback(
    request: Request,
    req: OIDCCallbackRequest,
    db: DatabaseService = Depends(_get_db),
) -> TokenResponse:
    """Exchange an OIDC authorization code for a CodeTrust JWT.

    The OIDC IdP redirects back with a code; this endpoint:
    1. Exchanges the code for tokens at the IdP
    2. Extracts user info from the ID token
    3. Creates or updates the user in the database
    4. Returns a CodeTrust JWT for dashboard sessions
    """
    from src.services.sso import OIDCConfig, OIDCService

    if not settings.oidc_enabled:
        raise HTTPException(status_code=503, detail="OIDC not configured")

    http_client = request.app.state.http_client
    config = OIDCConfig(
        enabled=True,
        issuer=settings.oidc_issuer,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret,
        redirect_uri=settings.oidc_redirect_uri,
        scopes=settings.oidc_scopes.split(","),
        allowed_domains=(
            settings.oidc_allowed_domains.split(",")
            if settings.oidc_allowed_domains
            else []
        ),
        role_claim=settings.oidc_role_claim,
    )
    svc = OIDCService(config, http_client)
    discovered = await svc.discover()
    if not discovered:
        raise HTTPException(status_code=502, detail="OIDC discovery failed")

    user_info = await svc.exchange_code(req.code)
    if user_info is None:
        raise HTTPException(status_code=401, detail="OIDC authentication failed")

    if not svc.validate_domain(user_info.email):
        raise HTTPException(
            status_code=403,
            detail=f"Email domain not allowed: {user_info.email}",
        )

    # Use OIDC sub as github_id placeholder for OIDC users
    oidc_id = f"oidc:{user_info.provider}:{user_info.sub}"
    user = await db.get_or_create_user(
        github_id=oidc_id,
        email=user_info.email,
        name=user_info.name,
        avatar_url=user_info.picture,
    )

    auth_svc = request.app.state.auth
    token = auth_svc.create_jwt(user.id, user.plan)
    return TokenResponse(
        token=token,
        user_id=user.id,
        plan=user.plan,
        expires_in_minutes=settings.jwt_expire_minutes,
    )


# --- GDPR Data Export / Delete ---


@app.get("/v1/user/export")
async def gdpr_export(
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """Export all personal data for the authenticated user (GDPR Art. 15).

    Returns a JSON object with all user data including profile,
    API keys, scan history, and usage statistics.
    """
    from src.services.gdpr import GDPRService

    gdpr = GDPRService(db)
    data = await gdpr.export_user_data(auth.user_id)
    if not data:
        raise HTTPException(status_code=404, detail="User not found")
    return data


@app.delete("/v1/user/delete")
async def gdpr_delete(
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """Delete all personal data for the authenticated user (GDPR Art. 17).

    WARNING: This action is irreversible. All user data will be permanently deleted.
    """
    from src.services.gdpr import GDPRService

    gdpr = GDPRService(db)
    result = await gdpr.delete_user_data(auth.user_id)
    if not result.get("deleted"):
        raise HTTPException(status_code=404, detail="User not found")
    return result
