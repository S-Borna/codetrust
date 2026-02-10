"""FastAPI application — CodeTrust HTTP API with auth and lifespan management."""

import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import Depends, FastAPI, HTTPException, Request, Security
from fastapi.security import APIKeyHeader

from src.config import settings
from src.models.enums import Language, VerifyStatus
from src.models.requests import (
    DeepScanRequest,
    StaticScanRequest,
    VerifyDockerRequest,
    VerifyImportsRequest,
)
from src.models.responses import (
    DeepScanResponse,
    HealthResponse,
    StaticScanResponse,
    VerifyDockerResponse,
    VerifyImportsResponse,
)
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.static_analyzer import StaticAnalyzer
from src.utils.parsers import (
    extract_js_imports,
    extract_python_imports,
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

    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()

    yield

    # Shutdown: close all connections
    logger.info("api_shutdown")
    await http_client.aclose()
    await cache.disconnect()


# --- Application ---
app = FastAPI(
    title="CodeTrust API",
    version=settings.version,
    description="AI code verification platform",
    lifespan=lifespan,
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


def _get_cache(request: Request) -> CacheService:
    """Dependency: get CacheService from app state."""
    return request.app.state.cache


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


@app.post("/v1/scan/deep", response_model=DeepScanResponse)
async def deep_scan(
    req: DeepScanRequest,
    analyzer: StaticAnalyzer = Depends(_get_analyzer),
    registry: RegistryService = Depends(_get_registry),
    docker: DockerVerifyService = Depends(_get_docker),
    _api_key: str = Depends(verify_api_key),
) -> DeepScanResponse:
    """Run full deep scan combining all layers."""
    logger.info("api_deep_scan", filename=req.filename)
    start = time.monotonic()

    # Layer 1: Static analysis
    findings = analyzer.scan_code(req.code, req.filename)
    static_result = analyzer.build_scan_response(findings)

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

    elapsed_ms = int((time.monotonic() - start) * 1000)
    overall = _compute_overall_verdict(static_result, import_result, docker_result)
    total = _compute_total_findings(static_result, import_result, docker_result)

    return DeepScanResponse(
        static_scan=static_result,
        import_verification=import_result,
        docker_verification=docker_result,
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


def _compute_overall_verdict(
    static: StaticScanResponse,
    imports: VerifyImportsResponse | None,
    docker: VerifyDockerResponse | None,
) -> str:
    """Compute overall verdict from sub-results."""
    if static.verdict == "BLOCK":
        return "BLOCK"

    if imports is not None and imports.failed > 0:
        return "BLOCK"

    if docker is not None and docker.failed > 0:
        return "BLOCK"

    if static.verdict == "WARN":
        return "WARN"

    if imports is not None and imports.warnings > 0:
        return "WARN"

    return "PASS"


def _compute_total_findings(
    static: StaticScanResponse,
    imports: VerifyImportsResponse | None,
    docker: VerifyDockerResponse | None,
) -> int:
    """Count total findings across all layers."""
    total = static.total_findings

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


if __name__ == "__main__":
    run()
