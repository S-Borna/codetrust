"""FastAPI application — CodeTrust HTTP API with auth and lifespan management."""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader

from src.config import settings
from src.formatters.sarif import deep_scan_to_sarif, static_scan_to_sarif
from src.models.enums import Language, Severity, VerifyStatus
from src.models.requests import (
    AstScanRequest,
    CheckoutRequest,
    CreateApiKeyRequest,
    DeepScanRequest,
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
    SandboxResponse,
    ScanHistoryResponse,
    ScanLogResponse,
    StaticScanResponse,
    UsageDayResponse,
    UsageStatsResponse,
    VerifyDockerResponse,
    VerifyImportsResponse,
)
from src.services.ast_analyzer import SUPPORTED_LANGUAGES as AST_LANGUAGES
from src.services.ast_analyzer import AstAnalyzer
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.database import DatabaseService
from src.services.docker_verify import DockerVerifyService
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

# --- Auth ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(
    key: str | None = Security(api_key_header),
) -> str:
    """Validate API key. Skip if CODETRUST_API_KEY is empty (local dev)."""
    if not settings.api_key:
        return ""
    if key is None or key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key


# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Initialize and teardown shared resources."""
    logger.info("api_startup", version=settings.version)

    # Startup: create shared resources
    cache = CacheService(settings.redis_url)
    await cache.connect()

    http_client = httpx.AsyncClient(
        timeout=settings.http_timeout,
        limits=httpx.Limits(
            max_connections=settings.http_max_connections,
            max_keepalive_connections=settings.http_max_keepalive,
        ),
    )

    db = DatabaseService(settings.database_url, echo=settings.database_echo)
    try:
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

    yield

    # Shutdown: close all connections
    logger.info("api_shutdown")
    await http_client.aclose()
    await cache.disconnect()
    if db is not None:
        await db.close()


# --- Application ---
app = FastAPI(
    title="CodeTrust API",
    version=settings.version,
    description="AI code verification platform",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.dashboard_url, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    req: VerifyImportsRequest,
    registry: RegistryService = Depends(_get_registry),
    _api_key: str = Depends(verify_api_key),
) -> VerifyImportsResponse:
    """Verify package imports exist in registries."""
    logger.info("api_verify_imports", language=req.language, count=len(req.imports))
    start = time.monotonic()

    requirements = req.requirements
    results = await registry.verify_packages(req.language, req.imports, requirements)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    return _build_imports_response(results, elapsed_ms)


@app.post("/v1/verify/dockerfile", response_model=VerifyDockerResponse)
async def verify_dockerfile(
    req: VerifyDockerRequest,
    docker: DockerVerifyService = Depends(_get_docker),
    _api_key: str = Depends(verify_api_key),
) -> VerifyDockerResponse:
    """Verify Docker images and tags exist on Docker Hub."""
    logger.info("api_verify_dockerfile", count=len(req.images))
    start = time.monotonic()

    results = await docker.verify_images(req.images)

    elapsed_ms = int((time.monotonic() - start) * 1000)
    verified = sum(1 for r in results if r.status == VerifyStatus.VERIFIED)
    failed = len(results) - verified
    return VerifyDockerResponse(
        verified=verified,
        failed=failed,
        results=results,
        latency_ms=elapsed_ms,
    )


@app.post("/v1/scan/static", response_model=StaticScanResponse)
async def static_scan(
    req: StaticScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    _api_key: str = Depends(verify_api_key),
) -> StaticScanResponse:
    """Run static anti-pattern analysis on code."""
    logger.info("api_static_scan", filename=req.filename)
    findings = analyzer.scan_code(req.code, req.filename)
    return analyzer.build_scan_response(findings)


@app.post("/v1/scan/ast", response_model=AstScanResponse)
async def ast_scan(
    req: AstScanRequest,
    ast_anal: AstAnalyzer = Depends(_get_ast_analyzer),
    _api_key: str = Depends(verify_api_key),
) -> AstScanResponse:
    """Run AST-based code analysis using tree-sitter."""
    logger.info("api_ast_scan", filename=req.filename, language=req.language)

    if req.language not in AST_LANGUAGES:
        return AstScanResponse(
            total_findings=0, blocks=0, warnings=0,
            infos=0, findings=[], verdict="PASS",
        )

    findings = ast_anal.analyze(
        req.code, req.language, req.filename,
        req.max_nesting, req.complexity_threshold,
    )
    return _build_ast_response(findings)


@app.post("/v1/sandbox/run", response_model=SandboxResponse)
async def sandbox_run(
    req: SandboxRequest,
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    _api_key: str = Depends(verify_api_key),
) -> SandboxResponse:
    """Execute code in an isolated Docker sandbox."""
    logger.info("api_sandbox_run", language=req.language, timeout=req.timeout)

    if req.language not in SUPPORTED_SANDBOX_LANGUAGES:
        return SandboxResponse(
            exit_code=-1,
            stdout="",
            stderr="",
            timed_out=False,
            error=f"Unsupported sandbox language: {req.language}",
            latency_ms=0,
        )

    return await sandbox_svc.execute_code(
        req.code, req.language, req.timeout,
    )


@app.post("/v1/scan/static/sarif")
async def static_scan_sarif(
    req: StaticScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    _api_key: str = Depends(verify_api_key),
) -> dict[str, object]:
    """Run static analysis and return results in SARIF format."""
    logger.info("api_static_sarif", filename=req.filename)
    findings = analyzer.scan_code(req.code, req.filename)
    response = analyzer.build_scan_response(findings)
    return static_scan_to_sarif(response)


@app.post("/v1/scan/deep/sarif")
async def deep_scan_sarif(
    req: DeepScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    ast_anal: AstAnalyzer = Depends(_get_ast_analyzer),
    registry: RegistryService = Depends(_get_registry),
    docker: DockerVerifyService = Depends(_get_docker),
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    _api_key: str = Depends(verify_api_key),
) -> dict[str, object]:
    """Run deep scan and return results in SARIF format."""
    logger.info("api_deep_sarif", filename=req.filename)
    deep_result = await deep_scan(
        req, analyzer, ast_anal, registry, docker, sandbox_svc, _api_key,
    )
    return deep_scan_to_sarif(deep_result)


@app.post("/v1/scan/deep", response_model=DeepScanResponse)
async def deep_scan(
    req: DeepScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    ast_anal: AstAnalyzer = Depends(_get_ast_analyzer),
    registry: RegistryService = Depends(_get_registry),
    docker: DockerVerifyService = Depends(_get_docker),
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    _api_key: str = Depends(verify_api_key),
) -> DeepScanResponse:
    """Run full deep scan combining all layers."""
    logger.info("api_deep_scan", filename=req.filename)
    start = time.monotonic()

    # Layer 1: Static analysis
    findings = analyzer.scan_code(req.code, req.filename)
    static_result = analyzer.build_scan_response(findings)

    # Layer 3: AST analysis (if language supports it)
    ast_result = None
    if req.language and req.language in AST_LANGUAGES:
        ast_findings = ast_anal.analyze(req.code, req.language, req.filename)
        ast_result = _build_ast_response(ast_findings)

    # Layer 2a: Import verification (optional)
    import_result = None
    if req.verify_imports and req.language:
        import_result = await _verify_imports_from_code(
            req.code, req.language, req.requirements_content, registry
        )

    # Layer 2b: Docker verification (optional)
    docker_result = None
    if req.verify_docker and req.dockerfile_content:
        docker_result = await _verify_docker_from_content(
            req.dockerfile_content, docker
        )

    # Layer 4: Sandbox execution (optional)
    sandbox_result: SandboxResponse | None = None
    if req.sandbox_run and req.language in SUPPORTED_SANDBOX_LANGUAGES:
        sandbox_result = await sandbox_svc.execute_code(
            req.code, req.language,
        )

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
    _api_key: str = Depends(verify_api_key),
) -> ApiKeyCreatedResponse:
    """Create a new API key for the authenticated user."""
    # For now use a placeholder user_id derived from API key auth
    user_id = _api_key or "local"
    raw_key, record = await db.create_api_key(user_id, req.name)
    return ApiKeyCreatedResponse(
        key=raw_key,
        id=record.id,
        name=record.name,
        prefix=record.prefix,
    )


@app.get("/v1/api-keys", response_model=list[ApiKeyResponse])
async def list_api_keys(
    db: DatabaseService = Depends(_get_db),
    _api_key: str = Depends(verify_api_key),
) -> list[ApiKeyResponse]:
    """List all API keys for the authenticated user."""
    user_id = _api_key or "local"
    records = await db.list_api_keys(user_id)
    return [
        ApiKeyResponse(
            id=r.id,
            name=r.name,
            prefix=r.prefix,
            is_revoked=r.is_revoked,
            created_at=r.created_at.isoformat() if r.created_at else "",
            last_used_at=r.last_used_at.isoformat() if r.last_used_at else "",
        )
        for r in records
    ]


@app.delete("/v1/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    db: DatabaseService = Depends(_get_db),
    _api_key: str = Depends(verify_api_key),
) -> dict[str, bool]:
    """Revoke an API key."""
    user_id = _api_key or "local"
    success = await db.revoke_api_key(key_id, user_id)
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"revoked": True}


# --- Dashboard: Scan history ---


@app.get("/v1/scans/history", response_model=ScanHistoryResponse)
async def scan_history(
    page: int = 1,
    per_page: int = 20,
    scan_type: str | None = None,
    db: DatabaseService = Depends(_get_db),
    _api_key: str = Depends(verify_api_key),
) -> ScanHistoryResponse:
    """Get paginated scan history for the authenticated user."""
    user_id = _api_key or "local"
    logs = await db.get_scan_history(user_id, page, per_page, scan_type)
    total = await db.count_scans(user_id, scan_type)
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
    days: int = 30,
    db: DatabaseService = Depends(_get_db),
    _api_key: str = Depends(verify_api_key),
) -> UsageStatsResponse:
    """Get daily usage statistics for the authenticated user."""
    user_id = _api_key or "local"
    usage_days = await db.get_usage_stats(user_id, days)
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


@app.post("/v1/billing/checkout")
async def billing_checkout(
    req: CheckoutRequest,
    billing: BillingService = Depends(_get_billing),
    _api_key: str = Depends(verify_api_key),
) -> dict[str, str]:
    """Create a Stripe checkout session for upgrading plans."""
    if not billing.is_configured():
        raise HTTPException(status_code=503, detail="Billing not configured")

    url = await billing.create_checkout_session(
        customer_id="",  # Will be set from user record in production
        plan=req.plan,
    )
    if not url:
        raise HTTPException(status_code=500, detail="Failed to create checkout")
    return {"url": url}


@app.post("/v1/billing/portal")
async def billing_portal(
    billing: BillingService = Depends(_get_billing),
    _api_key: str = Depends(verify_api_key),
) -> dict[str, str]:
    """Create a Stripe customer portal session."""
    if not billing.is_configured():
        raise HTTPException(status_code=503, detail="Billing not configured")

    url = await billing.create_portal_session(customer_id="")
    if not url:
        raise HTTPException(status_code=500, detail="Failed to create portal session")
    return {"url": url}


@app.post("/v1/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    billing: BillingService = Depends(_get_billing),
    db: DatabaseService = Depends(_get_db),
) -> dict[str, str]:
    """Handle Stripe webhook events for subscription changes."""
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    event = billing.construct_webhook_event(payload, sig)
    if event is None:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    await _handle_stripe_event(event, db)
    return {"status": "ok"}


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
        # In production, look up user by stripe_customer_id and update plan
        _ = (customer_id, sub_id, plan, db)

    elif event.type == "customer.subscription.deleted":
        sub = event.data.object
        customer_id = getattr(sub, "customer", "")
        logger.info("stripe_sub_deleted", customer_id=customer_id)
        # In production, downgrade user to free tier
        _ = (customer_id, db)


if __name__ == "__main__":
    run()
