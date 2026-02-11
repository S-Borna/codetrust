"""FastAPI application — CodeTrust HTTP API with auth and lifespan management."""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from src.config import settings
from src.formatters.sarif import deep_scan_to_sarif, static_scan_to_sarif
from src.middleware.ip_rate_limit import IPRateLimitMiddleware
from src.models.enums import Language, Severity, VerifyStatus
from src.models.requests import (
    AstScanRequest,
    CheckoutRequest,
    CreateApiKeyRequest,
    DeepScanRequest,
    GithubAuthRequest,
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

    if key:
        ctx = await _resolve_auth_from_key(key, db)
        if ctx.user_id != "local":
            return ctx
        raise HTTPException(status_code=401, detail="Invalid API key")

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
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

    try:
        db = DatabaseService(settings.database_url, echo=settings.database_echo)
        await db.create_tables()
    except Exception as exc:
        logger.warning("database_init_skipped", error=str(exc))
        db = None  # type: ignore[assignment]

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


async def _shutdown(app: FastAPI) -> None:
    """Close all connections and dispose of resources."""
    logger.info("api_shutdown")
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
