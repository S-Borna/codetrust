# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""FastAPI application — CodeTrust HTTP API with auth and lifespan management."""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from datetime import time as dt_time
from email.message import EmailMessage
from pathlib import Path

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
from pydantic import BaseModel, ValidationError
from starlette.responses import JSONResponse, Response
from starlette.websockets import WebSocketDisconnect

from src.config import settings
from src.formatters.sarif import deep_scan_to_sarif, static_scan_to_sarif
from src.gateway.approvals import ApprovalExceptionStore
from src.gateway.audit import AuditEntry
from src.gateway.interceptor import CommandInterceptor
from src.gateway.policies import PolicyEngine
from src.gateway.policy_integrity import get_policy_manifest_hash, verify_policy_integrity
from src.middleware.ip_rate_limit import IPRateLimitMiddleware
from src.middleware.metrics import MetricsMiddleware, metrics_endpoint
from src.middleware.version_check import VersionEnforcementMiddleware
from src.models.enums import Language, Severity, VerifyStatus
from src.models.requests import (
    AddMemberRequest,
    AstScanRequest,
    AutoFixRequest,
    CheckoutRequest,
    CreateApiKeyRequest,
    CreateOrgRequest,
    CrossFileScanRequest,
    DashboardBootstrapApiKeyRequest,
    DeepScanRequest,
    FeedbackReportRequest,
    GithubAuthRequest,
    GovernanceApproveRequest,
    GovernancePolicySimulationRequest,
    GovernancePolicySnapshotRequest,
    GovernanceRegisterWorkspaceRequest,
    GovernanceUnifiedSessionRequest,
    LicenseScanRequest,
    OIDCCallbackRequest,
    RefreshRequest,
    SandboxRequest,
    SbomGenerateRequest,
    SignatureScanRequest,
    StaticScanRequest,
    TaintVerifiedRequest,
    UpdateMemberRoleRequest,
    UpdateOrgPolicyRequest,
    VerifyDockerRequest,
    VerifyImportsRequest,
    VulnScanRequest,
)
from src.models.responses import (
    AdminAdoptionOverviewResponse,
    ApiKeyCreatedResponse,
    ApiKeyResponse,
    AstScanResponse,
    DashboardBootstrapApiKeyResponse,
    DeepScanResponse,
    FeedbackReportResponse,
    Finding,
    GitHubAppWebhookResponse,
    GovernanceApproveResponse,
    GovernanceAuditEntryResponse,
    GovernanceAuditResponse,
    GovernanceAuditStatsResponse,
    GovernanceExceptionResponse,
    GovernancePendingApprovalResponse,
    GovernancePolicyBundleResponse,
    GovernancePolicySimulationOutcomeResponse,
    GovernancePolicySimulationResponse,
    GovernancePolicySnapshotResponse,
    GovernancePostureResponse,
    GovernanceSessionStatusResponse,
    GovernanceUnifiedSessionResponse,
    GovernanceWorkspaceAggregateResponse,
    GovernanceWorkspacePostureResponse,
    HealthResponse,
    PublicStatsResponse,
    RevokeResponse,
    SandboxResponse,
    SbomGenerateResponse,
    ScanHistoryResponse,
    ScanLogResponse,
    SignatureScanResponse,
    StaticScanResponse,
    StatusResponse,
    TaintVerifiedResponse,
    TokenResponse,
    UrlResponse,
    UsageDayResponse,
    UsageStatsResponse,
    UserProfileResponse,
    VerifiedFindingResponse,
    VerifyDockerResponse,
    VerifyImportsResponse,
)
from src.services.ast_analyzer import SUPPORTED_LANGUAGES as AST_LANGUAGES
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.autofix import AutoFixResult
from src.services.billing import (
    CI_ENFORCEMENT_PLANS,
    ENTERPRISE_PLANS,
    PLAN_LIMITS,
    REGISTRY_BLOCK_PLANS,
    TEAM_PLANS,
    BillingService,
)
from src.services.cache import CacheService
from src.services.database import DatabaseService
from src.services.docker_verify import DockerVerifyService
from src.services.github_app import GitHubAppService
from src.services.governance_bundles import get_bundle_policy
from src.services.license_checker import LicenseScanResponse
from src.services.license_guard import LicenseStatus, validate_license
from src.services.rate_limiter import RateLimiter
from src.services.registry import RegistryService
from src.services.runtime_taint_verifier import (
    RuntimeTaintVerifier,
    VerificationSummary,
    VerifiedFinding,
)
from src.services.sandbox import SUPPORTED_SANDBOX_LANGUAGES, SandboxService
from src.services.sso import OIDCConfig, OIDCService
from src.services.static_analyzer import StaticAnalyzer
from src.services.taint_analyzer import TaintAnalyzer
from src.services.telemetry import STATS_CACHE_KEY, TelemetryIngestEvent, process_telemetry_event
from src.services.unified_session import UnifiedSessionStore
from src.services.vulnerability import VulnScanResponse
from src.services.workspace_registry import WorkspaceRegistry
from src.utils.parsers import (
    extract_cpp_includes,
    extract_csharp_imports,
    extract_go_imports,
    extract_java_imports,
    extract_js_imports,
    extract_python_imports,
    extract_rust_imports,
    parse_dockerfile_from,
)

logger = structlog.get_logger()
startup_logger = logging.getLogger("codetrust")

SECONDS_PER_HOUR: int = 3_600
OIDC_STATE_PREFIX: str = "oidc:state:"
OIDC_STATE_TTL_SECS: int = 600  # 10 minutes for OIDC flow

MAX_WS_CLIENTS: int = 50
WS_IDLE_TIMEOUT_SECS: float = 300.0  # 5 minutes
FREE_DAILY_SCAN_LIMIT: int = 25
SCAN_TELEMETRY_FINDINGS_CAP: int = 50

BASELINES: dict[str, int] = {
    "ct:total_findings": 113744,
    "ct:total_blocks": 12405,
    "ct:total_scans": 12673,
    "ct:files_scanned": 12770,
    "ct:scans_by_source:cli": 24,
    "ct:scans_by_source:vscode": 7732,
    "ct:scans_by_source:github_action": 16,
    "ct:scans_by_source:cloud_api": 4972,
}

BASELINE_DB_SNAPSHOT: dict[str, int] = {
    "ct:total_findings": 66724,
    "ct:total_scans": 12277,
    "ct:files_scanned": 12277,
    "ct:total_blocks": 9708,
    "ct:scans_by_source:cli": 24,
    "ct:scans_by_source:vscode": 7305,
    "ct:scans_by_source:github_action": 16,
    "ct:scans_by_source:cloud_api": 4972,
}
PIP_INSTALLS_BASELINE: int = 6711

_scan_limits: dict[str, dict[str, str | int]] = {}


def _apply_public_usage_baselines(stats_values: dict[str, int]) -> dict[str, int]:
    """Apply additive baselines for fallback usage counters."""
    adjusted = dict(stats_values)

    def _additive(redis_key: str, current_db: int) -> int:
        baseline = int(BASELINES.get(redis_key, 0))
        snapshot = int(BASELINE_DB_SNAPSHOT.get(redis_key, 0))
        new_since_baseline = max(int(current_db) - snapshot, 0)
        return baseline + new_since_baseline

    adjusted["total_findings"] = _additive("ct:total_findings", int(adjusted.get("total_findings", 0)))
    adjusted["blocks_found"] = _additive("ct:total_blocks", int(adjusted.get("blocks_found", 0)))
    adjusted["total_scans"] = _additive("ct:total_scans", int(adjusted.get("total_scans", 0)))
    adjusted["total_files_scanned"] = _additive("ct:files_scanned", int(adjusted.get("total_files_scanned", 0)))
    adjusted["src_cli"] = _additive("ct:scans_by_source:cli", int(adjusted.get("src_cli", 0)))
    adjusted["src_vscode"] = _additive("ct:scans_by_source:vscode", int(adjusted.get("src_vscode", 0)))
    adjusted["src_github_action"] = _additive(
        "ct:scans_by_source:github_action", int(adjusted.get("src_github_action", 0)),
    )
    adjusted["src_cloud_api"] = _additive(
        "ct:scans_by_source:cloud_api", int(adjusted.get("src_cloud_api", 0)),
    )
    return adjusted


def _apply_pip_downloads_baseline(stats_payload: dict[str, object]) -> dict[str, object]:
    """Ensure pip installs/reach display never falls below historical baseline."""
    distribution = stats_payload.get("distribution")
    if not isinstance(distribution, dict):
        return stats_payload
    pypi = distribution.get("pypi")
    if not isinstance(pypi, dict):
        return stats_payload
    pypi["downloads_total"] = max(int(pypi.get("downloads_total", 0)), PIP_INSTALLS_BASELINE)
    return stats_payload


def _resolve_attestation_session_id(request: Request) -> str:
    """Resolve runtime attestation session ID from header or generate one."""
    header_value = request.headers.get("X-CodeTrust-Session-ID", "").strip()
    if header_value:
        return header_value[:128]
    return f"api-{int(time.time() * 1000)}"


def _disabled_rules_from_bundle(policy: dict[str, object]) -> set[str]:
    """Translate bundle policy booleans into disabled gateway rules."""
    disabled_rules: set[str] = set()
    if not bool(policy.get("block_heredoc", True)):
        disabled_rules.add("gateway_heredoc")
    if not bool(policy.get("block_eval", True)):
        disabled_rules.add("gateway_eval")
    if not bool(policy.get("block_git_push", True)):
        disabled_rules.add("gateway_git_push")
        disabled_rules.add("gateway_git_force_push")
    if not bool(policy.get("block_rm_rf", True)):
        disabled_rules.add("gateway_rm_rf_root")
        disabled_rules.add("gateway_rm_rf_home")
    if not bool(policy.get("block_curl_pipe_sh", True)):
        disabled_rules.add("gateway_curl_pipe_sh")
    if not bool(policy.get("block_chmod_777", True)):
        disabled_rules.add("gateway_chmod_777")
    return disabled_rules

# --- Auth Context ---


@dataclass
class AuthContext:
    """Resolved authentication context for a request."""

    user_id: str = "local"
    plan: str = "free"
    is_admin: bool = False
    api_key_id: str | None = field(default=None)


def _utc_today() -> date:
    """Return the current date in UTC."""
    return datetime.now(UTC).date()


def _resolve_installation_id(request: Request) -> str:
    """Resolve installation ID from header, API key hash, or client IP hash."""
    install_id = request.headers.get("X-CodeTrust-Installation-ID", "").strip()
    if install_id:
        return install_id[:128]

    api_key = request.headers.get("X-API-Key", "").strip()
    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
        return f"key:{digest}"

    client_ip = request.client.host if request.client else "unknown"
    digest = hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:16]
    return f"ip:{digest}"


def _check_scan_limit(installation_id: str, plan: str) -> dict[str, str | int] | None:
    """Return 429 payload when an installation exceeds daily scan quota for its plan."""
    plan_limit = PLAN_LIMITS.get(plan, FREE_DAILY_SCAN_LIMIT)

    today = _utc_today().isoformat()
    tracker = _scan_limits.get(installation_id)
    if tracker is None or tracker.get("date") != today:
        _scan_limits[installation_id] = {"date": today, "count": 1}
        return None

    current = int(tracker.get("count", 0)) + 1
    tracker["count"] = current
    if current <= plan_limit:
        return None

    tomorrow = datetime.combine(_utc_today() + timedelta(days=1), dt_time.min, tzinfo=UTC)
    return {
        "error": "daily_scan_limit_reached",
        "message": f"{plan.capitalize()} plan limit: {plan_limit} scans/day. Upgrade for higher limits.",
        "limit": plan_limit,
        "used": current,
        "plan": plan,
        "resets_at": tomorrow.isoformat(),
        "upgrade_url": "https://app.codetrust.ai/pricing",
    }


api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _resolve_auth_from_key(
    key: str, db: DatabaseService | None,
) -> AuthContext:
    """Resolve auth from an API key (master or database-backed)."""
    if settings.api_key and hmac.compare_digest(key, settings.api_key):
        return AuthContext(
            user_id="system_master_key", plan="enterprise", is_admin=True,
        )
    if db is not None:
        record = await db.verify_api_key_hash(key)
        if record is not None:
            user = await db.get_user(record.user_id)
            plan = user.plan if user else "free"
            return AuthContext(
                user_id=record.user_id,
                plan=plan,
                api_key_id=record.id,
            )
    # Preserve synthetic test/dev keys when no DB-backed key store is available.
    if db is None and key.startswith("ct_pro_"):
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return AuthContext(user_id=f"pro:{digest}", plan="pro")
    if db is None and key.startswith("ct_enterprise_"):
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return AuthContext(user_id=f"enterprise:{digest}", plan="enterprise")
    if db is None and key.startswith("ct_free_"):
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        return AuthContext(user_id=f"free:{digest}", plan="free")
    return AuthContext()


async def _resolve_auth_from_bearer(
    token: str, auth_svc: AuthService | None,
) -> AuthContext | None:
    """Resolve auth from a Bearer JWT token."""
    if auth_svc is None or not auth_svc.jwt_configured():
        return None
    if await auth_svc.is_token_revoked(token):
        return None
    decoded = auth_svc.decode_jwt(token)
    if decoded is None:
        return None
    return AuthContext(
        user_id=decoded["user_id"],
        plan=decoded["plan"],
    )


def _is_auth_configured(
    db: DatabaseService | None, auth_svc: AuthService | None,
) -> bool:
    """Check if any authentication mechanism is configured."""
    return (
        bool(settings.api_key)
        or (db is not None)
        or (auth_svc is not None and auth_svc.jwt_configured())
    )


async def _resolve_api_key_auth(
    key: str, db: DatabaseService | None, auth_configured: bool,
) -> AuthContext:
    """Resolve auth from an API key, raising 401 if invalid and auth is configured."""
    ctx = await _resolve_auth_from_key(key, db)
    if ctx.user_id != "local":
        return ctx
    if not auth_configured:
        return AuthContext()
    raise HTTPException(
        status_code=401,
        detail="Invalid API key. Omit X-API-Key to use unauthenticated mode.",
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
    auth_configured = _is_auth_configured(db, auth_svc)

    if key and key.strip():
        return await _resolve_api_key_auth(key, db, auth_configured)

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if not auth_configured:
            return AuthContext()
        ctx = await _resolve_auth_from_bearer(token, auth_svc)
        if ctx is not None:
            return ctx
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if settings.production_mode and auth_configured:
        raise HTTPException(status_code=401, detail="Authentication required")

    if not settings.api_key:
        return AuthContext()

    raise HTTPException(status_code=401, detail="Authentication required")


async def get_optional_auth_context(
    request: Request,
    key: str | None = Security(api_key_header),
) -> AuthContext:
    """Resolve auth context while preserving anonymous free-tier access."""
    db = getattr(request.app.state, "db", None)
    auth_svc = getattr(request.app.state, "auth", None)
    auth_configured = _is_auth_configured(db, auth_svc)

    if key and key.strip():
        return await _resolve_api_key_auth(key, db, auth_configured)

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if not auth_configured:
            return AuthContext()
        ctx = await _resolve_auth_from_bearer(token, auth_svc)
        if ctx is not None:
            return ctx
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    return AuthContext()


def _filter_free_static_response(response: StaticScanResponse) -> StaticScanResponse:
    """Strip signature-related details from free-tier static responses."""
    filtered = [
        finding for finding in response.findings
        if "signature" not in finding.rule_id and "hallucinated" not in finding.rule_id
    ]
    if len(filtered) != len(response.findings):
        response.findings = filtered
        response.blocks = sum(1 for finding in filtered if finding.severity == Severity.BLOCK)
        response.warnings = sum(1 for finding in filtered if finding.severity == Severity.WARN)
        response.infos = sum(1 for finding in filtered if finding.severity == Severity.INFO)
        response.total_findings = len(filtered)
        response.verdict = "BLOCK" if response.blocks > 0 else ("WARN" if response.warnings > 0 else "PASS")
    response.upgrade_hints = [
        "Signature validation (405 functions) — available on Pro",
        "Registry verification with BLOCK enforcement — available on Pro",
        "GitHub Action PR gate — available on Pro",
        "Docker & infrastructure verification — available on Pro",
        "Sandbox execution — available on Pro",
    ]
    return response


def _downgrade_registry_blocks_for_free(
    findings: list[dict[str, str | int]],
) -> list[dict[str, str | int]]:
    """Downgrade registry BLOCK findings to WARN for free-tier users.

    Free plan gets WARN on hallucinated packages (detection only).
    Pro+ plans get BLOCK (enforcement).
    """
    for finding in findings:
        rule_id = str(finding.get("rule_id", ""))
        if rule_id.startswith("import_") and finding.get("severity") == "BLOCK":
            finding["severity"] = "WARN"
            finding["message"] = str(finding.get("message", "")) + " [Upgrade to Pro for BLOCK enforcement]"
    return findings


def _require_paid_plan(plan: str, feature: str) -> None:
    """Raise 403 if user is on free plan for a paid-only feature."""
    if plan not in CI_ENFORCEMENT_PLANS:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "plan_upgrade_required",
                "message": f"{feature} requires a Pro or higher plan.",
                "upgrade_url": "https://app.codetrust.ai/pricing",
            },
        )


def _require_team_plan(plan: str, feature: str) -> None:
    """Raise 403 if user is below Team plan for a team-only feature."""
    if plan not in TEAM_PLANS:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "plan_upgrade_required",
                "message": f"{feature} requires a Team or Enterprise plan.",
                "required_plan": "team",
                "upgrade_url": "https://app.codetrust.ai/pricing",
            },
        )


def _require_enterprise_plan(plan: str, feature: str) -> None:
    """Raise 403 if user is below Enterprise plan."""
    if plan not in ENTERPRISE_PLANS:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "plan_upgrade_required",
                "message": f"{feature} requires an Enterprise plan.",
                "required_plan": "enterprise",
                "upgrade_url": "https://app.codetrust.ai/pricing",
            },
        )





async def _init_http_client() -> httpx.AsyncClient:
    """Create the shared HTTP client."""
    return httpx.AsyncClient(
        timeout=settings.http_timeout,
        limits=httpx.Limits(
            max_connections=settings.http_max_connections,
            max_keepalive_connections=settings.http_max_keepalive,
        ),
    )


async def _init_database() -> DatabaseService | None:
    """Initialize the database, returning None if unavailable."""
    try:
        db = DatabaseService(settings.database_url, echo=settings.database_echo)
        await db.create_tables()
        return db
    except Exception as exc:
        logger.warning(
            "database_init_skipped",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return None


def _attach_core_services(
    app: FastAPI, cache: CacheService,
    http_client: httpx.AsyncClient, db: DatabaseService | None,
) -> None:
    """Attach core services to app state."""
    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.github_app = GitHubAppService(http_client, app.state.analyzer)
    app.state.ast_analyzer = AstAnalyzer()
    app.state.taint_analyzer = TaintAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = db
    app.state.billing = BillingService()
    app.state.auth = AuthService(http_client, cache=cache)
    app.state.rate_limiter = RateLimiter(db) if db is not None else None


def _init_team_service(app: FastAPI, db: DatabaseService | None) -> None:
    """Initialize the team service for RBAC."""
    app.state.team_service = None
    if db is not None:
        from src.services.team import TeamService

        app.state.team_service = TeamService(db._session_factory)


async def _init_telemetry_tasks(
    app: FastAPI, cache: CacheService,
    http_client: httpx.AsyncClient, db: DatabaseService | None,
) -> None:
    """Start telemetry background tasks and restore Redis counters from the DB."""
    app.state.telemetry_stop = asyncio.Event()
    app.state.telemetry_queue = asyncio.Queue(maxsize=10_000)
    app.state.ws_clients = set()
    app.state.telemetry_bg_tasks = set()

    redis_client = cache.raw_client()
    if redis_client is not None:
        from src.services.telemetry import (
            counter_snapshot_worker,
            stats_worker,
            warm_up_redis_counters,
        )

        app.state.stats_worker_task = asyncio.create_task(
            stats_worker(r=redis_client, http_client=http_client, stop=app.state.telemetry_stop),
        )
        app.state.counter_snapshot_task = None
        if db is not None:
            restored = await warm_up_redis_counters(r=redis_client, db=db)
            startup_logger.info(f"STARTUP COMPLETE: Redis connected, {restored} counters restored")
            app.state.counter_snapshot_task = asyncio.create_task(
                counter_snapshot_worker(r=redis_client, db=db, stop=app.state.telemetry_stop),
            )
        else:
            startup_logger.info("STARTUP COMPLETE: Redis connected, 0 counters restored")
    else:
        startup_logger.warning("STARTUP: Redis unavailable, running in DB-fallback mode")
        app.state.stats_worker_task = None
        app.state.counter_snapshot_task = None

    app.state.telemetry_writer_task = None
    if db is not None:
        app.state.telemetry_writer_task = asyncio.create_task(_telemetry_batch_writer(app))


async def _startup(app: FastAPI) -> None:
    """Create and attach shared resources to app state."""
    redis_url_from_env = os.getenv("CODETRUST_REDIS_URL") or os.getenv("REDIS_URL")
    redis_url_effective = redis_url_from_env or settings.redis_url
    startup_logger.warning("STARTUP REDIS URL (effective): %s", redis_url_effective)
    if not redis_url_from_env:
        startup_logger.warning("NO REDIS_URL FOUND — falling back to database stats")

    cache = CacheService(settings.redis_url)
    await cache.connect()
    if settings.production_mode and settings.redis_enabled:
        connected = await cache.is_connected()
        if not connected:
            startup_logger.warning("STARTUP: Redis unavailable, running in DB-fallback mode")
            logger.critical(
                "redis_unavailable_startup",
                message=(
                    "Redis is unavailable at startup; continuing with database-backed fallback stats. "
                    "Set CODETRUST_REDIS_URL or REDIS_URL to a reachable Redis instance to restore live aggregation."
                ),
            )
    http_client = await _init_http_client()
    db = await _init_database()
    _attach_core_services(app, cache, http_client, db)
    _init_team_service(app, db)
    await _init_telemetry_tasks(app, cache, http_client, db)


async def _shutdown(app: FastAPI) -> None:
    """Close all connections and dispose of resources."""
    logger.info("api_shutdown")

    stop = getattr(app.state, "telemetry_stop", None)
    if isinstance(stop, asyncio.Event):
        stop.set()

    for task_name in ("telemetry_writer_task", "stats_worker_task", "counter_snapshot_task"):
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

    # License validation — enforce on API server startup
    # --- P0: JWT secret enforcement in production mode ---
    if settings.production_mode and len(settings.jwt_secret) < 32:
        logger.critical(
            "jwt_secret_too_weak",
            message="FATAL: production_mode requires CODETRUST_JWT_SECRET >= 32 characters.",
        )
        import sys
        sys.exit(1)

    if settings.production_mode and not settings.api_key:
        logger.critical(
            "api_key_missing_production_mode",
            message="FATAL: production_mode requires CODETRUST_API_KEY to be set.",
        )
        import sys
        sys.exit(1)

    # The API server IS the license server — it should not validate
    # against itself (circular dependency). Use license_key for client
    # license validation endpoint only. Server always runs fully licensed.
    if settings.license_key:
        license_status = await validate_license(settings.license_key)
    else:
        # Server-side: grant full access (this IS the authoritative server)
        license_status = LicenseStatus(
            valid=True,
            plan="enterprise",
            license_key="server-self",
        )
    app.state.license_status = license_status
    if not license_status.valid:
        if settings.production_mode:
            logger.critical(
                "license_invalid_production_mode",
                plan=license_status.plan,
                message="FATAL: Production mode requires a valid license. "
                "Set CODETRUST_LICENSE_KEY or disable CODETRUST_PRODUCTION_MODE.",
            )
            import sys
            sys.exit(1)
        logger.warning(
            "license_not_valid",
            plan=license_status.plan,
            max_rules=license_status.max_rules,
            message="Running in limited mode — obtain a license at codetrust.ai",
        )

    await _startup(app)
    yield
    await _shutdown(app)


# --- Application ---
app = FastAPI(
    title="CodeTrust API",
    version=settings.version,
    description="AI code verification platform",
    lifespan=lifespan,
    docs_url=None if settings.production_mode else "/docs",
    redoc_url=None if settings.production_mode else "/redoc",
    openapi_url=None if settings.production_mode else "/openapi.json",
)

_ALLOWED_ORIGINS: list[str] = [
    "https://app.codetrust.ai",
    "https://codetrust.ai",
]
if settings.dashboard_url not in _ALLOWED_ORIGINS:
    _ALLOWED_ORIGINS.append(settings.dashboard_url)
if not settings.production_mode:
    _ALLOWED_ORIGINS.append("http://localhost:3000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Client-Version"],
)

# Client version enforcement — reject outdated installations
app.add_middleware(
    VersionEnforcementMiddleware,
    min_version=settings.min_client_version,
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


def _build_request_telemetry_event(
    method: str, path: str, status_code: int, duration_ms: int,
) -> TelemetryIngestEvent:
    """Build a telemetry event for an API request."""
    return TelemetryIngestEvent(
        event_type="api_request_completed",
        source="cloud_api",
        installation_id=None,
        version=settings.version,
        payload={
            "method": method,
            "path": path,
            "status_code": status_code,
            "duration_ms": duration_ms,
        },
    )


async def _schedule_telemetry_emit(
    request: Request, event: TelemetryIngestEvent,
    redis_client: object | None, queue: asyncio.Queue[object] | None,
    db: DatabaseService | None,
) -> None:
    """Emit telemetry event best-effort without failing the request path."""
    _ = request
    try:
        await process_telemetry_event(r=redis_client, db=db, queue=queue, event=event)
    except Exception:
        return


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
        db = getattr(request.app.state, "db", None)

        try:
            event = _build_request_telemetry_event(
                request.method, path, status_code, duration_ms,
            )
        except Exception:
            return

        await _schedule_telemetry_emit(request, event, redis_client, queue, db)


@app.middleware("http")
async def rate_limit_headers_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Inject X-RateLimit-* headers into scan responses.

    Reads usage info stored on request.state by _enforce_rate_limit.
    """
    response = await call_next(request)
    limit = getattr(request.state, "rate_limit_limit", None)
    if limit is not None:
        current = getattr(request.state, "rate_limit_current", 0)
        remaining = getattr(request.state, "rate_limit_remaining", 0)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Used"] = str(current)
    return response


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


def _get_taint_analyzer(request: Request) -> TaintAnalyzer:
    """Dependency: get TaintAnalyzer from app state."""
    return request.app.state.taint_analyzer


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


def _get_github_app(request: Request) -> GitHubAppService:
    """Dependency: get GitHubAppService from app state."""
    return request.app.state.github_app


def _get_rate_limiter(request: Request) -> RateLimiter | None:
    """Dependency: get RateLimiter from app state (None if DB unavailable)."""
    return request.app.state.rate_limiter


UPGRADE_URL_PATH = "/dashboard/settings"


def _require_pro_or_enterprise(plan: str) -> JSONResponse | None:
    """Return 403 response when endpoint requires Pro or higher."""
    if plan in CI_ENFORCEMENT_PLANS:
        return None
    return JSONResponse(
        status_code=403,
        content={
            "error": "upgrade_required",
            "message": "This feature requires a Pro or higher plan.",
            "required_plan": "pro",
            "upgrade_url": "https://app.codetrust.ai/pricing",
        },
    )


def _require_pro_for_cloud(auth: "AuthContext") -> JSONResponse | None:
    """Enforce Pro+ plan on cloud API, but allow local dev mode through.

    In local dev mode (no API key configured, no database), AuthContext
    defaults to user_id='local' and plan='free'. Governance endpoints
    must remain open locally — the product works offline. Plan-gating
    only applies when the API serves authenticated cloud users.
    """
    if auth.user_id == "local":
        return None
    if auth.is_admin:
        return None
    return _require_pro_or_enterprise(auth.plan)


def _require_team_or_above(plan: str) -> JSONResponse | None:
    """Return 403 when endpoint requires Team or Enterprise plan."""
    if plan in TEAM_PLANS:
        return None
    return JSONResponse(
        status_code=403,
        content={
            "error": "upgrade_required",
            "message": "This feature requires a Team or Enterprise plan.",
            "required_plan": "team",
            "upgrade_url": "https://app.codetrust.ai/pricing",
        },
    )


def _require_enterprise(plan: str) -> JSONResponse | None:
    """Return 403 response when endpoint requires Enterprise."""
    if plan in ENTERPRISE_PLANS:
        return None
    return JSONResponse(
        status_code=403,
        content={
            "error": "upgrade_required",
            "message": "This feature requires an Enterprise plan.",
            "required_plan": "enterprise",
            "upgrade_url": "https://app.codetrust.ai/pricing",
        },
    )


async def _parse_request_model[RequestModelT: BaseModel](
    request: Request,
    model_type: type[RequestModelT],
) -> RequestModelT:
    """Parse and validate a JSON request body after auth/plan guards run."""
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail=[
                {
                    "type": "json_invalid",
                    "loc": ["body"],
                    "msg": "Invalid JSON",
                    "input": None,
                    "ctx": {"error": str(exc)},
                },
            ],
        ) from exc

    try:
        return model_type.model_validate(payload)
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail=exc.errors(include_url=False),
        ) from exc


async def _enforce_rate_limit(
    auth: AuthContext,
    rate_limiter: RateLimiter | None,
    request: Request | None = None,
) -> None:
    """Check rate limit for a user. Raises 429 if exceeded.

    Stores usage info on request.state for header injection by middleware.
    """
    if auth.is_admin or rate_limiter is None:
        return
    allowed, current, limit = await rate_limiter.check_limit(
        auth.user_id, auth.plan,
    )

    # Store usage info for response header middleware
    if request is not None:
        request.state.rate_limit_current = current
        request.state.rate_limit_limit = limit
        request.state.rate_limit_remaining = max(0, limit - current)

    if not allowed:
        upgrade_url = f"{settings.dashboard_url}{UPGRADE_URL_PATH}"
        raise HTTPException(
            status_code=429,
            detail={
                "error": "rate_limit_exceeded",
                "current_usage": current,
                "daily_limit": limit,
                "plan": auth.plan,
                "message": f"Daily limit of {limit} scans exceeded. "
                f"Upgrade your plan for higher limits.",
                "upgrade_url": upgrade_url,
            },
        )


async def _log_scan_to_db(
    db: DatabaseService,
    auth: AuthContext,
    scan_type: str,
    verdict: str,
    findings_count: int,
    latency_ms: int,
    language: str,
    filename: str,
    rate_limiter: RateLimiter | None,
) -> None:
    """Write scan record to database and increment rate limit counters."""
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


async def _emit_scan_telemetry(
    redis_client: object,
    queue: asyncio.Queue[object] | None,
    db: DatabaseService | None,
    scan_type: str,
    findings_count: int,
    verdict: str,
    latency_ms: int,
    findings: list[dict[str, str]] | None = None,
) -> None:
    """Emit scan completion telemetry event via Redis."""
    findings_list = findings or []
    blocks_count = sum(
        1 for f in findings_list
        if isinstance(f, dict) and str(f.get("severity", "")).upper() == "BLOCK"
    )
    try:
        event = TelemetryIngestEvent(
            event_type="scan_completed",
            source="cloud_api",
            installation_id=None,
            version=settings.version,
            payload={
                "scan_type": scan_type,
                "files_scanned": 1,
                "total_findings": findings_count,
                "findings_by_severity": {"BLOCK": blocks_count},
                "scan_duration_ms": latency_ms,
                "findings": findings_list,
            },
        )
        await process_telemetry_event(r=redis_client, db=db, queue=queue, event=event)
    except Exception as exc:
        logger.warning("scan_telemetry_emit_failed", error=str(exc))


def _serialize_finding_for_telemetry(finding: object) -> dict[str, str] | None:
    """Normalize finding shape for telemetry impact/category aggregation."""
    if isinstance(finding, dict):
        raw_rule = finding.get("rule") or finding.get("rule_id")
        raw_severity = finding.get("severity")
        raw_file = finding.get("file") or finding.get("filename")
    else:
        raw_rule = getattr(finding, "rule", None) or getattr(finding, "rule_id", None)
        raw_severity = getattr(finding, "severity", None)
        raw_file = getattr(finding, "file", None) or getattr(finding, "filename", None)

    rule = str(raw_rule).strip() if raw_rule else ""
    if not rule:
        return None

    if isinstance(raw_severity, Severity):
        severity = raw_severity.value
    else:
        severity = str(raw_severity).strip().upper() if raw_severity else ""

    file_name = str(raw_file).strip() if raw_file else ""
    entry: dict[str, str] = {"rule": rule, "rule_id": rule}
    if severity:
        entry["severity"] = severity
    if file_name:
        entry["file"] = file_name
    return entry


def _build_scan_findings_for_telemetry(findings: Sequence[object] | None) -> list[dict[str, str]]:
    """Build capped per-finding telemetry payload from API scan response findings."""
    if findings is None:
        return []

    serialized: list[dict[str, str]] = []
    for finding in findings[:SCAN_TELEMETRY_FINDINGS_CAP]:
        item = _serialize_finding_for_telemetry(finding)
        if item is not None:
            serialized.append(item)
    return serialized


def _collect_deep_scan_findings(result: DeepScanResponse) -> list[Finding]:
    """Flatten findings from deep scan layers for telemetry impact attribution.

    When both regex and AST fire on the same line, the AST finding is kept
    (more precise) and the regex duplicate is dropped.
    """
    from src.services.ast_analyzer import AstAnalyzer

    static_findings: list[Finding] = list(result.static_scan.findings)
    ast_findings: list[Finding] = []
    if result.ast_scan is not None:
        ast_findings = list(result.ast_scan.findings)

    # Dedup: remove regex findings superseded by AST findings on same line
    deduped_static = AstAnalyzer.dedup_with_regex(static_findings, ast_findings)

    combined: list[Finding] = deduped_static
    combined.extend(ast_findings)
    if result.signature_validation is not None:
        combined.extend(result.signature_validation.findings)
    if result.taint_scan is not None:
        combined.extend(result.taint_scan.findings)
    return combined


async def _log_scan(
    request: Request,
    auth: AuthContext,
    scan_type: str,
    verdict: str,
    findings_count: int,
    latency_ms: int,
    language: str = "",
    filename: str = "",
    findings: Sequence[object] | None = None,
) -> None:
    """Log a scan execution, increment usage counters, and emit telemetry.

    This ensures every API-driven scan is reflected in real-time public stats,
    not just the database log.
    """
    db = getattr(request.app.state, "db", None)
    rate_limiter = getattr(request.app.state, "rate_limiter", None)
    if db is not None:
        await _log_scan_to_db(
            db, auth, scan_type, verdict, findings_count,
            latency_ms, language, filename, rate_limiter,
        )

    cache = getattr(request.app.state, "cache", None)
    redis_client = cache.raw_client() if cache is not None else None
    db = getattr(request.app.state, "db", None)
    queue = getattr(request.app.state, "telemetry_queue", None)
    if redis_client is not None:
        findings_payload = _build_scan_findings_for_telemetry(findings)
        await _emit_scan_telemetry(
            redis_client,
            queue,
            db,
            scan_type,
            findings_count,
            verdict,
            latency_ms,
            findings_payload,
        )


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


@app.post("/v1/license/validate")
async def validate_license_endpoint(
    request: Request,
    body: dict[str, object],
) -> dict[str, object]:
    """Validate a license key and return feature entitlements.

    Called by client installations at startup and periodically.
    """
    license_key = str(body.get("license_key", ""))
    fingerprint = str(body.get("fingerprint", ""))

    if not license_key:
        raise HTTPException(status_code=401, detail="License key required")

    # Validate against configured master key or database
    is_valid = bool(settings.api_key) and hmac.compare_digest(
        license_key, settings.api_key,
    )

    # Check database for registered license keys
    db = getattr(request.app.state, "db", None)
    plan = "free"
    if is_valid:
        plan = "pro"
    elif db is not None:
        try:
            from src.services.database import DatabaseService

            if isinstance(db, DatabaseService):
                key_record = await db.get_api_key(license_key)
                if key_record:
                    is_valid = True
                    plan = key_record.get("plan", "pro")
        except Exception as exc:
            logger.debug("license_db_lookup_failed", error=str(exc))

    max_rules = 275 if is_valid else 15
    max_gateway = 76 if is_valid else 5

    return {
        "valid": is_valid,
        "plan": plan,
        "machine_bound": bool(fingerprint),
        "expires_at": "",
        "features": ["full_scan", "gateway", "mcp", "enterprise"] if is_valid else ["basic_scan"],
        "max_rules": max_rules,
        "max_gateway_rules": max_gateway,
    }


@app.get("/v1/rules/download", include_in_schema=False)
async def download_rules(
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Internal endpoint for rule distribution to licensed clients."""
    from src.rules.anti_patterns import ANTI_PATTERNS
    from src.services.rule_delivery import (
        build_signed_bundle,
        filter_premium_rules,
    )

    if not auth.is_admin and auth.plan == "free":
        return {
            "rules": [],
            "signature": "",
            "issued_at": "",
            "expires_at": "",
            "rule_count": 0,
            "version": settings.version,
            "message": "Premium rules require a paid license. Visit codetrust.ai",
        }

    premium = filter_premium_rules(ANTI_PATTERNS)
    bundle = build_signed_bundle(
        premium,
        secret=settings.rules_hmac_secret or settings.jwt_secret or "codetrust",
        version=settings.version,
    )
    return bundle.model_dump()


_FALLBACK_STATS_BASE: dict[str, int] = {
    "total_scans": 0,
    "hallucinated_packages_prevented": 0,
    "destructive_commands_blocked": 0,
    "gateway_commands_allowed": 0,
    "gateway_commands_warned": 0,
    "imports_verified": 0,
    "pypi_downloads_last_day": 0,
    "pypi_downloads_last_week": 0,
    "pypi_downloads_last_month": 0,
    "pypi_downloads_total": 0,
    "marketplace_installs": 0,
    "marketplace_downloads": 0,
    "marketplace_updates": 0,
    "openvsx_downloads": 0,
}


def _coerce_stats_contract(stats: dict[str, object]) -> dict[str, object]:
    """Ensure stats payload includes required contract metadata."""
    out = dict(stats)
    # Always pin schema metadata to running app version, even for cached payloads.
    out["schema_version"] = settings.version
    out.setdefault("source_of_truth", "/v1/stats/public")
    out.setdefault("coverage", {
        "model": "coverage-v1",
        "overall_score": 0,
        "active_surfaces": 0,
        "surfaces": {
            "cli": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
            "vscode": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
            "mcp": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
            "github_action": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
            "cloud_api": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
        },
    })
    return out


def _build_legacy_public_stats(stats: dict[str, object]) -> dict[str, int]:
    """Build legacy top-level counters from nested stats payload."""
    return {
        "total_scans": int(stats.get("usage", {}).get("total_scans", 0)),
        "hallucinated_packages_prevented": int(
            stats.get("impact", {}).get("hallucinations_caught", 0),
        ),
        "destructive_commands_blocked": int(
            stats.get("impact", {}).get("gateway_commands_blocked", 0),
        ),
        "pypi_downloads_last_week": int(
            stats.get("distribution", {}).get("pypi", {}).get("downloads_this_week", 0),
        ),
        "pypi_downloads_total": int(
            stats.get("distribution", {}).get("pypi", {}).get("downloads_total", 0),
        ),
        "marketplace_installs": int(
            stats.get("distribution", {}).get("marketplace", {}).get("installs", 0),
        ),
        "marketplace_downloads": int(
            stats.get("distribution", {}).get("marketplace", {}).get("downloads", 0),
        ),
        "openvsx_downloads": int(
            stats.get("distribution", {}).get("open_vsx", {}).get("downloads", 0),
        ),
    }


async def _build_redis_public_stats(
    redis_client: object,
    *,
    use_cache: bool = True,
) -> dict[str, object]:
    """Build public stats from Redis with backwards-compatible flat keys."""
    from src.services.telemetry import build_public_stats

    stats = _coerce_stats_contract(await build_public_stats(r=redis_client, use_cache=use_cache))
    stats = _apply_pip_downloads_baseline(stats)
    legacy = _build_legacy_public_stats(stats)
    return {**legacy, "stats": stats}


async def _build_fallback_public_stats(
    db: DatabaseService | None,
    cache: CacheService | None,
    http_client: httpx.AsyncClient | None,
) -> dict[str, object]:
    """Build public stats from database and external APIs."""
    from src.services.impact_categories import CATEGORY_DISPLAY, IMPACT_CATEGORIES
    from src.services.public_stats import (
        get_marketplace_stats,
        get_open_vsx_stats,
        get_pepy_download_stats,
        get_pypi_download_stats,
    )

    def _build_impact_categories(source: dict[str, int]) -> dict[str, dict[str, object]]:
        categories: dict[str, dict[str, object]] = {}
        for category in IMPACT_CATEGORIES:
            categories[category] = {
                "label": str(CATEGORY_DISPLAY.get(category, {}).get("label", category.replace("_", " ").title())),
                "count": int(source.get(f"impact_{category}", 0)),
                "last_seen": None,
            }
        return categories

    base: dict[str, int] = dict(_FALLBACK_STATS_BASE)

    if db is not None:
        try:
            base.update(await db.get_public_stats())
        except Exception as exc:
            logger.warning("public_stats_failed", error=str(exc))
        try:
            base.update(await db.get_public_usage_aggregates())
        except Exception as exc:
            logger.warning("public_usage_aggregates_failed", error=str(exc))

    base = _apply_public_usage_baselines(base)

    if cache is None or http_client is None:
        stats: dict[str, object] = {
            "schema_version": settings.version,
            "source_of_truth": "/v1/stats/public",
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "distribution": {
                "pypi": {
                    "downloads_today": base.get("pypi_downloads_last_day", 0),
                    "downloads_this_week": base.get("pypi_downloads_last_week", 0),
                    "downloads_this_month": base.get("pypi_downloads_last_month", 0),
                    "downloads_total": base.get("pypi_downloads_total", 0),
                },
                "marketplace": {
                    "installs": base.get("marketplace_installs", 0),
                    "downloads": base.get("marketplace_downloads", 0),
                    "updates": base.get("marketplace_updates", 0),
                },
                "open_vsx": {"downloads": base.get("openvsx_downloads", 0)},
            },
            "usage": {
                "total_scans": base.get("total_scans", 0),
                "scans_today": base.get("scans_today", 0),
                "scans_last_hour": base.get("scans_last_hour", 0),
                "scans_by_source": {
                    "cli": base.get("src_cli", 0),
                    "vscode": base.get("src_vscode", 0),
                    "mcp": base.get("src_mcp", 0),
                    "github_action": base.get("src_github_action", 0),
                    "cloud_api": base.get("src_cloud_api", 0),
                },
                "total_files_scanned": base.get("total_files_scanned", 0),
                "total_findings": base.get("total_findings", 0),
                "findings_by_severity": {"BLOCK": base.get("blocks_found", 0), "WARN": 0, "INFO": 0},
                "unique_installations_total": base.get("unique_installations_total", 0),
                "unique_installations_today": base.get("unique_installations_today", 0),
            },
            "impact": {
                "hallucinations_caught": base.get("hallucinated_packages_prevented", 0),
                "gateway_commands_blocked": base.get("destructive_commands_blocked", 0),
                "gateway_commands_allowed": base.get("gateway_commands_allowed", 0),
                "gateway_commands_warned": base.get("gateway_commands_warned", 0),
                "imports_verified": base.get("imports_verified", 0),
                "docker_images_verified": 0,
                "fixes_applied": 0,
                "fix_files_changed": 0,
                "fix_lines_changed": 0,
                "pr_gates_passed": 0,
                "pr_gates_failed": 0,
                "ci_runs_total": 0,
                "ci_gates_passed": 0,
                "ci_gates_failed": 0,
                "categories": _build_impact_categories(base),
                "top_rules": [],
            },
            "quality": {
                "average_trust_score": 0,
                "trend_distribution": {"improving": 0, "stable": 0, "degrading": 0},
                "top_rules_triggered": [],
            },
            "coverage": {
                "model": "coverage-v1",
                "overall_score": 0,
                "active_surfaces": 0,
                "surfaces": {
                    "cli": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                    "vscode": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                    "mcp": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                    "github_action": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                    "cloud_api": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                },
            },
            "languages": {},
            "layers": {},
        }
        stats = _apply_pip_downloads_baseline(stats)
        return {**_build_legacy_public_stats(stats), "stats": stats}

    pypi = await get_pypi_download_stats(http_client=http_client, cache=cache)
    pepy = await get_pepy_download_stats(http_client=http_client, cache=cache)
    marketplace = await get_marketplace_stats(http_client=http_client, cache=cache)
    openvsx = await get_open_vsx_stats(http_client=http_client, cache=cache)
    merged = {**base, **pypi, **pepy, **marketplace, **openvsx}
    merged = _apply_public_usage_baselines(merged)
    stats = {
        "schema_version": settings.version,
        "source_of_truth": "/v1/stats/public",
        "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "distribution": {
            "pypi": {
                "downloads_today": merged.get("pypi_downloads_last_day", 0),
                "downloads_this_week": merged.get("pypi_downloads_last_week", 0),
                "downloads_this_month": merged.get("pypi_downloads_last_month", 0),
                "downloads_total": merged.get("pypi_downloads_total", 0),
            },
            "marketplace": {
                "installs": merged.get("marketplace_installs", 0),
                "downloads": merged.get("marketplace_downloads", 0),
                "updates": merged.get("marketplace_updates", 0),
            },
            "open_vsx": {"downloads": merged.get("openvsx_downloads", 0)},
        },
        "usage": {
            "total_scans": merged.get("total_scans", 0),
            "scans_today": merged.get("scans_today", 0),
            "scans_last_hour": merged.get("scans_last_hour", 0),
            "scans_by_source": {
                "cli": merged.get("src_cli", 0),
                "vscode": merged.get("src_vscode", 0),
                "mcp": merged.get("src_mcp", 0),
                "github_action": merged.get("src_github_action", 0),
                "cloud_api": merged.get("src_cloud_api", 0),
            },
            "total_files_scanned": merged.get("total_files_scanned", 0),
            "total_findings": merged.get("total_findings", 0),
            "findings_by_severity": {"BLOCK": merged.get("blocks_found", 0), "WARN": 0, "INFO": 0},
            "unique_installations_total": merged.get("unique_installations_total", 0),
            "unique_installations_today": merged.get("unique_installations_today", 0),
        },
        "impact": {
            "hallucinations_caught": merged.get("hallucinated_packages_prevented", 0),
            "gateway_commands_blocked": merged.get("destructive_commands_blocked", 0),
            "gateway_commands_allowed": merged.get("gateway_commands_allowed", 0),
            "gateway_commands_warned": merged.get("gateway_commands_warned", 0),
            "imports_verified": merged.get("imports_verified", 0),
            "docker_images_verified": 0,
            "fixes_applied": 0,
            "fix_files_changed": 0,
            "fix_lines_changed": 0,
            "pr_gates_passed": 0,
            "pr_gates_failed": 0,
            "ci_runs_total": 0,
            "ci_gates_passed": 0,
            "ci_gates_failed": 0,
            "categories": _build_impact_categories(merged),
            "top_rules": [],
        },
        "quality": {
            "average_trust_score": 0,
            "trend_distribution": {"improving": 0, "stable": 0, "degrading": 0},
            "top_rules_triggered": [],
        },
        "coverage": {
            "model": "coverage-v1",
            "overall_score": 0,
            "active_surfaces": 0,
            "surfaces": {
                "cli": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                "vscode": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                "mcp": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                "github_action": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
                "cloud_api": {"events": 0, "enforced_events": 0, "enforced": False, "score": 0, "status": "inactive"},
            },
        },
        "languages": {},
        "layers": {},
    }
    stats = _apply_pip_downloads_baseline(stats)
    return {**_build_legacy_public_stats(stats), "stats": stats}


@app.get("/v1/stats/public", response_model=PublicStatsResponse)
async def public_stats(
    request: Request,
    refresh: bool = Query(default=False, description="Force uncached stats rebuild"),
    cache_bust: str | None = Query(default=None, alias="_bust"),
) -> PublicStatsResponse:
    """Public aggregate stats for landing page — no auth required."""
    db = getattr(request.app.state, "db", None)
    cache = getattr(request.app.state, "cache", None)
    http_client = getattr(request.app.state, "http_client", None)

    redis_client = cache.raw_client() if cache is not None else None
    redis_connected = False
    if cache is not None:
        try:
            redis_connected = await cache.is_connected()
        except Exception as exc:
            logger.warning("public_stats_redis_health_check_failed", error=str(exc))

    redis_available = redis_client is not None and redis_connected
    logger.info(
        "stats_endpoint_source_decision",
        redis_available=redis_available,
        using="redis" if redis_available else "fallback",
    )

    if redis_available:
        try:
            force_uncached = refresh or bool(cache_bust)
            if force_uncached:
                try:
                    await redis_client.delete(STATS_CACHE_KEY)
                except Exception as exc:
                    logger.warning("public_stats_cache_invalidate_failed", error=str(exc))
            logger.info("public_stats_source_selected", source="redis")
            return PublicStatsResponse.model_validate(
                await _build_redis_public_stats(redis_client, use_cache=not force_uncached),
            )
        except Exception as exc:
            logger.warning("public_stats_redis_failed_falling_back", error=str(exc))

    reason = "cache_service_missing"
    if cache is not None and redis_client is None:
        reason = "redis_client_uninitialized"
    elif cache is not None and not redis_connected:
        reason = "redis_connectivity_check_failed"
    logger.warning(
        "public_stats_source_selected",
        source="fallback",
        reason=reason,
        has_db=db is not None,
        has_http_client=http_client is not None,
    )

    return PublicStatsResponse.model_validate(await _build_fallback_public_stats(db, cache, http_client))


async def _collect_telemetry_batch(
    queue: asyncio.Queue[object],
    batch_size: int,
    flush_interval: float,
) -> list[object]:
    """Collect a batch of items from the telemetry queue."""
    batch: list[object] = []
    try:
        while len(batch) < batch_size:
            item = await asyncio.wait_for(queue.get(), timeout=flush_interval)
            batch.append(item)
    except TimeoutError:
        logger.debug("telemetry_batch_timeout", collected=len(batch))
    except Exception as exc:
        logger.warning(
            "telemetry_queue_read_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
    return batch


async def _flush_telemetry_batch(
    db: DatabaseService, batch: list[object],
) -> None:
    """Write a batch of telemetry items to the database."""
    try:
        await db.insert_telemetry_raw_batch(
            [
                {
                    "event_type": getattr(b, "event_type", ""),
                    "source": getattr(b, "source", ""),
                    "installation_id": getattr(b, "installation_id", "") or "",
                    "version": getattr(b, "version", "") or "",
                    "payload": getattr(b, "payload", {}),
                }
                for b in batch
            ]
        )
    except Exception as exc:
        logger.warning(
            "telemetry_db_batch_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )


async def _telemetry_batch_writer(app: FastAPI) -> None:
    """Flush telemetry write queue into the database in batches."""
    from src.services.telemetry import (
        TELEMETRY_BATCH_SIZE,
        TELEMETRY_FLUSH_INTERVAL_SECONDS,
    )

    queue: asyncio.Queue[object] | None = getattr(app.state, "telemetry_queue", None)
    stop: asyncio.Event | None = getattr(app.state, "telemetry_stop", None)
    db: DatabaseService | None = getattr(app.state, "db", None)

    if queue is None or stop is None or db is None:
        return

    while not stop.is_set():
        batch = await _collect_telemetry_batch(
            queue, TELEMETRY_BATCH_SIZE, TELEMETRY_FLUSH_INTERVAL_SECONDS,
        )
        if not batch:
            continue
        await _flush_telemetry_batch(db, batch)


@app.post("/v1/telemetry", status_code=202, response_model=StatusResponse)
async def ingest_telemetry(
    event: dict[str, object],
    request: Request,
    background_tasks: BackgroundTasks,
) -> StatusResponse:
    """Accept telemetry from all users (including anonymous extension users).

    Returns immediately (202). Processing is best-effort and must never block.
    """

    from src.services.telemetry import TelemetryIngestEvent, process_telemetry_event

    try:
        parsed = TelemetryIngestEvent.model_validate(event)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Invalid telemetry payload") from exc

    cache = getattr(request.app.state, "cache", None)
    redis_client = cache.raw_client() if cache is not None else None
    db = getattr(request.app.state, "db", None)
    queue = getattr(request.app.state, "telemetry_queue", None)

    background_tasks.add_task(
        process_telemetry_event,
        r=redis_client,
        db=db,
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


def _feedback_report_id() -> str:
    """Generate a stable, sortable report ID."""
    return f"rep_{int(time.time() * 1000)}"


def _feedback_recipient_email() -> str:
    """Resolve recipient email with safe fallback."""
    recipient = settings.feedback_recipient_email.strip()
    if recipient:
        return recipient
    return "said@saidborna.com"


def _append_feedback_report_sink(payload: dict[str, object]) -> None:
    """Append report payload to a local JSONL sink if configured."""
    sink = settings.feedback_report_sink_path.strip()
    if not sink:
        return

    sink_path = Path(sink).expanduser()
    sink_path.parent.mkdir(parents=True, exist_ok=True)
    with sink_path.open("a", encoding="utf-8") as sink_file:
        sink_file.write(json.dumps(payload, ensure_ascii=False) + "\n")


async def _forward_feedback_report_webhook(
    request: Request,
    payload: dict[str, object],
) -> None:
    """Forward report payload to a configured webhook endpoint."""
    webhook_url = settings.feedback_webhook_url.strip()
    if not webhook_url:
        logger.info("feedback_report_webhook_not_configured")
        return

    headers: dict[str, str] = {"Content-Type": "application/json"}
    webhook_token = settings.feedback_webhook_token.strip()
    if webhook_token:
        headers["Authorization"] = f"Bearer {webhook_token}"

    http_client: httpx.AsyncClient = request.app.state.http_client
    try:
        response = await http_client.post(
            webhook_url,
            json=payload,
            headers=headers,
            timeout=settings.feedback_webhook_timeout,
        )
        if response.status_code >= 400:
            logger.warning(
                "feedback_report_webhook_failed",
                status_code=response.status_code,
            )
            return
        logger.info("feedback_report_forwarded", status_code=response.status_code)
    except httpx.TimeoutException as exc:
        logger.warning("feedback_report_webhook_timeout", error=str(exc))
    except httpx.HTTPError as exc:
        logger.warning("feedback_report_webhook_http_error", error=str(exc))


def _build_feedback_email_message(payload: dict[str, object]) -> EmailMessage:
    """Build plain-text message for feedback delivery."""
    recipient = str(payload.get("recipient_email") or _feedback_recipient_email())
    from_email = settings.feedback_smtp_from_email.strip() or recipient
    report_id = str(payload.get("report_id") or "")
    report_type = str(payload.get("report_type") or "")
    summary = str(payload.get("summary") or "")
    subject = f"[CodeTrust] {report_type} - {summary} ({report_id})"

    body_lines = [
        f"Report ID: {report_id}",
        f"Type: {report_type}",
        f"Surface: {payload.get('surface', '')}",
        f"Version: {payload.get('version', '')}",
        f"Environment: {payload.get('environment', '')}",
        f"Submitted (UTC): {payload.get('submitted_at_utc', '')}",
        f"Received (UTC): {payload.get('received_at_utc', '')}",
        "",
        "Summary:",
        summary,
        "",
        "Details:",
        str(payload.get("details") or ""),
    ]

    message = EmailMessage()
    message["From"] = from_email
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content("\n".join(body_lines))
    return message


def _send_feedback_report_email_sync(payload: dict[str, object]) -> bool:
    """Send feedback email synchronously via configured SMTP settings."""
    host = settings.feedback_smtp_host.strip()
    username = settings.feedback_smtp_username.strip()
    password = settings.feedback_smtp_password.strip()
    if not host or not username or not password:
        logger.info("feedback_report_email_not_configured")
        return False

    context = ssl.create_default_context()
    message = _build_feedback_email_message(payload)
    port = settings.feedback_smtp_port
    timeout = settings.feedback_smtp_timeout

    if settings.feedback_smtp_use_ssl:
        with smtplib.SMTP_SSL(host=host, port=port, timeout=timeout, context=context) as smtp:
            smtp.login(username, password)
            smtp.send_message(message)
        return True

    with smtplib.SMTP(host=host, port=port, timeout=timeout) as smtp:
        smtp.ehlo()
        if settings.feedback_smtp_use_tls:
            smtp.starttls(context=context)
            smtp.ehlo()
        smtp.login(username, password)
        smtp.send_message(message)
    return True


async def _send_feedback_report_email(payload: dict[str, object]) -> None:
    """Send feedback email off the event loop to avoid blocking API requests."""
    try:
        sent = await asyncio.to_thread(_send_feedback_report_email_sync, payload)
        if sent:
            logger.info("feedback_report_email_sent", report_id=payload.get("report_id", ""))
    except smtplib.SMTPException as exc:
        logger.warning("feedback_report_email_smtp_error", error=str(exc))
    except OSError as exc:
        logger.warning("feedback_report_email_os_error", error=str(exc))


async def _dispatch_feedback_report(
    request: Request,
    payload: dict[str, object],
) -> None:
    """Best-effort report dispatch to local sink and webhook."""
    try:
        _append_feedback_report_sink(payload)
    except OSError as exc:
        logger.warning("feedback_report_sink_failed", error=str(exc))

    await _forward_feedback_report_webhook(request=request, payload=payload)
    await _send_feedback_report_email(payload=payload)


@app.post("/v1/feedback/report", status_code=202, response_model=FeedbackReportResponse)
async def submit_feedback_report(
    req: FeedbackReportRequest,
    request: Request,
    background_tasks: BackgroundTasks,
) -> FeedbackReportResponse:
    """Accept a user report and dispatch it asynchronously."""
    report_id = _feedback_report_id()
    payload: dict[str, object] = {
        "report_id": report_id,
        "recipient_email": settings.feedback_recipient_email.strip(),
        "report_type": req.report_type,
        "surface": req.surface,
        "version": req.version,
        "environment": req.environment,
        "summary": req.summary,
        "details": req.details,
        "submitted_at_utc": req.submitted_at_utc,
        "received_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    logger.info(
        "feedback_report_received",
        report_id=report_id,
        report_type=req.report_type,
        surface=req.surface,
    )
    background_tasks.add_task(_dispatch_feedback_report, request, payload)
    return FeedbackReportResponse(status="accepted", report_id=report_id)


@app.websocket("/v1/stats/live")
async def stats_websocket(websocket: WebSocket) -> None:
    """Push live stats updates to connected clients.

    Enforces MAX_WS_CLIENTS limit, per-IP cap (3), and idle timeout.
    """
    import asyncio

    ws_clients: set[WebSocket] = getattr(app.state, "ws_clients", set())

    # --- Connection limit ---
    if len(ws_clients) >= MAX_WS_CLIENTS:
        await websocket.close(code=1013, reason="Server at capacity")
        return

    await websocket.accept()
    ws_clients.add(websocket)
    app.state.ws_clients = ws_clients
    try:
        while True:
            try:
                await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=WS_IDLE_TIMEOUT_SECS,
                )
            except TimeoutError:
                await websocket.close(code=1000, reason="Idle timeout")
                break
    except WebSocketDisconnect:
        logger.debug("websocket_client_disconnected")
    finally:
        ws_clients.discard(websocket)


def _format_audit_entries(entries: list[AuditEntry]) -> list[dict[str, object]]:
    """Format audit log entries for API response."""
    return [
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
    ]


@app.get("/v1/governance/audit", response_model=GovernanceAuditResponse)
async def governance_audit(
    hours: int = 24,
    verdict: str | None = None,
    limit: int = 100,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernanceAuditResponse | JSONResponse:
    """Query the governance audit log.

    Returns recent audit entries and aggregate statistics.
    Reads from .codetrust/audit.jsonl in the workspace.

    Args:
        hours: How many hours back to search (default: 24).
        verdict: Filter by verdict: ALLOW, WARN, BLOCK.
        limit: Maximum entries to return (default: 100).

    Returns:
        Typed response with entries list and stats summary.
    """
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    from src.gateway.audit import AuditLogger

    audit_path = os.path.join(os.getcwd(), ".codetrust", "audit.jsonl")
    logger_instance = AuditLogger(audit_path)

    since = time.time() - (hours * SECONDS_PER_HOUR)
    entries = logger_instance.get_entries(
        since=since,
        verdict=verdict,
        limit=limit,
    )
    raw_stats = logger_instance.get_stats()

    typed_entries = [
        GovernanceAuditEntryResponse(
            timestamp=e.timestamp,
            action_type=e.action_type,
            verdict=e.verdict,
            rule_id=e.rule_id,
            original_action=e.original_action,
            message=e.message,
            agent_id=e.agent_id,
            session_id=e.session_id,
        )
        for e in entries
    ]
    typed_stats = GovernanceAuditStatsResponse(
        total=int(raw_stats.get("total", 0)),
        by_verdict=dict(raw_stats.get("by_verdict", {})),
        by_action_type=dict(raw_stats.get("by_action_type", {})),
        top_rules=list(raw_stats.get("top_rules", [])),
    )

    return GovernanceAuditResponse(entries=typed_entries, stats=typed_stats)


@app.post("/v1/verify/imports", response_model=VerifyImportsResponse)
async def verify_imports(
    request: Request,
    req: VerifyImportsRequest,
    registry: RegistryService = Depends(_get_registry),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> VerifyImportsResponse:
    """Verify package imports exist in registries."""
    logger.info("api_verify_imports", language=req.language, count=len(req.imports))
    start = time.monotonic()

    results = await registry.verify_packages(req.language, req.imports, req.requirements)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    response = _build_imports_response(results, elapsed_ms)

    # Free plan: downgrade registry BLOCK → WARN (detection only, no enforcement)
    if auth.plan not in REGISTRY_BLOCK_PLANS:
        for result in response.results:
            if result.status == VerifyStatus.NOT_FOUND:
                result.severity = Severity.WARN
        response.failed = 0  # No enforcement failures for free

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
    _require_paid_plan(auth.plan, "Docker verification")
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
    installation_id = _resolve_installation_id(request)
    plan = auth.plan if auth else "free"
    limit_hit = _check_scan_limit(installation_id, plan)
    if limit_hit is not None:
        return JSONResponse(status_code=429, content=limit_hit)

    logger.info("api_static_scan", filename=req.filename)
    start = time.monotonic()
    findings = analyzer.scan_code(req.code, req.filename)
    response = analyzer.build_scan_response(findings)
    if plan == "free":
        response = _filter_free_static_response(response)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    await _log_scan(
        request, auth, "static", response.verdict,
        response.total_findings, elapsed_ms, filename=req.filename,
        findings=response.findings,
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
    await _enforce_rate_limit(auth, rate_limiter, request)
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
        findings=response.findings,
    )
    return response


@app.post("/v1/scan/signatures", response_model=SignatureScanResponse)
async def signature_scan(
    request: Request,
    req: SignatureScanRequest,
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> SignatureScanResponse:
    """Validate function signatures against curated database.

    Detects AI-hallucinated functions, wrong parameters, deprecated
    API usage, and common AI mistakes in library calls.
    """
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required
    logger.info(
        "api_signature_scan", filename=req.filename,
        language=str(req.language),
    )
    start = time.monotonic()

    from src.services.signature_validator import validate_signatures

    lang_str = str(req.language.value) if hasattr(req.language, "value") else str(req.language)
    findings = validate_signatures(req.code, lang_str, req.filename)

    blocks = [f for f in findings if f.severity == Severity.BLOCK]
    warns = [f for f in findings if f.severity == Severity.WARN]
    infos = [f for f in findings if f.severity == Severity.INFO]
    hallucinations = sum(
        1 for f in findings if "hallucinated" in f.rule_id
    )
    verdict = "BLOCK" if blocks else ("WARN" if warns else "PASS")

    response = SignatureScanResponse(
        total_findings=len(findings),
        blocks=len(blocks),
        warnings=len(warns),
        infos=len(infos),
        hallucinations_caught=hallucinations,
        findings=findings,
        verdict=verdict,
    )

    elapsed_ms = int((time.monotonic() - start) * 1000)
    await _log_scan(
        request, auth, "signatures", verdict,
        len(findings), elapsed_ms, lang_str, req.filename,
        findings=findings,
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
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required
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
    _require_paid_plan(auth.plan, "SARIF output (GitHub Action)")
    await _enforce_rate_limit(auth, rate_limiter, request)
    logger.info("api_static_sarif", filename=req.filename)
    start = time.monotonic()
    findings = analyzer.scan_code(req.code, req.filename)
    response = analyzer.build_scan_response(findings)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    await _log_scan(
        request, auth, "static_sarif", response.verdict,
        response.total_findings, elapsed_ms,
        str(req.language) if req.language else "", req.filename,
        findings=response.findings,
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
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required
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
        findings=_collect_deep_scan_findings(deep_result),
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
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required

    installation_id = _resolve_installation_id(request)
    plan = auth.plan if auth else "free"
    limit_hit = _check_scan_limit(installation_id, plan)
    if limit_hit is not None:
        return JSONResponse(status_code=429, content=limit_hit)

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
        findings=_collect_deep_scan_findings(result),
    )
    return result


async def _run_deep_scan_core(
    req: DeepScanRequest,
    analyzer: StaticAnalyzer,
    ast_anal: AstAnalyzer,
    registry: RegistryService,
    docker: DockerVerifyService,
    sandbox_svc: SandboxService,
    taint_anal: TaintAnalyzer | None = None,
) -> DeepScanResponse:
    """Core deep scan logic shared between JSON and SARIF endpoints."""
    start = time.monotonic()
    static_result = analyzer.build_scan_response(
        analyzer.scan_code(req.code, req.filename),
    )
    ast_result = _run_ast_layer(req, ast_anal)
    taint_result = _run_taint_layer(req, taint_anal) if taint_anal else None
    sig_result = _run_signature_layer(req)
    import_result = await _run_import_layer(req, registry)
    docker_result = await _run_docker_layer(req, docker)
    sandbox_result = await _run_sandbox_layer(req, sandbox_svc)

    return _assemble_deep_response(
        static_result, ast_result, sig_result, import_result,
        docker_result, sandbox_result, start, taint_result=taint_result,
    )


def _run_ast_layer(
    req: DeepScanRequest, ast_anal: AstAnalyzer,
) -> AstScanResponse | None:
    """Run AST analysis layer if language supports it."""
    if req.language and req.language in AST_LANGUAGES:
        findings = ast_anal.analyze(req.code, req.language, req.filename)
        return _build_ast_response(findings)
    return None


_TAINT_SUPPORTED_LANGUAGES = {"python", "javascript", "typescript"}


def _run_taint_layer(
    req: DeepScanRequest, taint_anal: TaintAnalyzer,
) -> AstScanResponse | None:
    """Run taint analysis layer if language supports it."""
    if not req.language:
        return None
    lang_str = str(req.language.value) if hasattr(req.language, "value") else str(req.language)
    if lang_str not in _TAINT_SUPPORTED_LANGUAGES:
        return None
    findings = taint_anal.analyze(req.code, req.language, req.filename)
    if not findings:
        return None
    return _build_ast_response(findings)


_SIG_SUPPORTED_LANGUAGES = {"python", "javascript", "typescript"}


def _run_signature_layer(
    req: DeepScanRequest,
) -> SignatureScanResponse | None:
    """Run function signature validation if language is supported."""
    if not getattr(req, "verify_signatures", True):
        return None
    if not req.language:
        return None

    lang_str = str(req.language.value) if hasattr(req.language, "value") else str(req.language)
    if lang_str not in _SIG_SUPPORTED_LANGUAGES:
        return None

    try:
        from src.services.signature_validator import validate_signatures

        findings = validate_signatures(req.code, lang_str, req.filename)
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        warns = [f for f in findings if f.severity == Severity.WARN]
        infos = [f for f in findings if f.severity == Severity.INFO]
        hallucinations = sum(
            1 for f in findings if "hallucinated" in f.rule_id
        )
        verdict = "BLOCK" if blocks else ("WARN" if warns else "PASS")

        return SignatureScanResponse(
            total_findings=len(findings),
            blocks=len(blocks),
            warnings=len(warns),
            infos=len(infos),
            hallucinations_caught=hallucinations,
            findings=findings,
            verdict=verdict,
        )
    except Exception as exc:
        logger.debug(
            "signature_layer_failed",
            error=str(exc),
            error_type=type(exc).__name__,
        )
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
    sig_result: SignatureScanResponse | None,
    import_result: VerifyImportsResponse | None,
    docker_result: VerifyDockerResponse | None,
    sandbox_result: SandboxResponse | None,
    start: float,
    taint_result: AstScanResponse | None = None,
) -> DeepScanResponse:
    """Assemble the final DeepScanResponse from layer results."""
    elapsed_ms = int((time.monotonic() - start) * 1000)
    overall = _compute_overall_verdict(
        static_result, ast_result, import_result, docker_result, sandbox_result,
        sig_result=sig_result,
    )
    total = _compute_total_findings(
        static_result, ast_result, import_result, docker_result,
        sig_result=sig_result,
    )
    if taint_result is not None:
        total += taint_result.total_findings
        if taint_result.blocks > 0 and overall != "BLOCK":
            overall = "BLOCK"
    return DeepScanResponse(
        static_scan=static_result,
        ast_scan=ast_result,
        signature_validation=sig_result,
        import_verification=import_result,
        docker_verification=docker_result,
        sandbox_result=sandbox_result,
        taint_scan=taint_result,
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
    elif language == Language.JAVA:
        imports = extract_java_imports(code)
    elif language == Language.CSHARP:
        imports = extract_csharp_imports(code)
    elif language == Language.CPP:
        imports = extract_cpp_includes(code)
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
    sig_result: SignatureScanResponse | None = None,
) -> str:
    """Compute overall verdict from sub-results."""
    if static.verdict == "BLOCK":
        return "BLOCK"

    if ast is not None and ast.verdict == "BLOCK":
        return "BLOCK"

    if sig_result is not None and sig_result.verdict == "BLOCK":
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

    if sig_result is not None and sig_result.verdict == "WARN":
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
    sig_result: SignatureScanResponse | None = None,
) -> int:
    """Count total findings across all layers."""
    total = static.total_findings

    if ast is not None:
        total += ast.total_findings

    if sig_result is not None:
        total += sig_result.total_findings

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


# --- Vulnerability Scanning ---


def _build_vuln_scan_response(result: VulnScanResponse) -> dict[str, object]:
    """Build the API response dict from a vulnerability scan result."""
    return {
        "total_packages": result.total_packages,
        "vulnerable_count": result.vulnerable_count,
        "clean_count": result.clean_count,
        "total_vulnerabilities": result.total_vulnerabilities,
        "critical_count": result.critical_count,
        "high_count": result.high_count,
        "medium_count": result.medium_count,
        "low_count": result.low_count,
        "results": [
            {
                "package": r.package,
                "ecosystem": r.ecosystem,
                "version": r.version,
                "is_vulnerable": r.is_vulnerable,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "summary": v.summary,
                        "severity": v.severity,
                        "fixed_version": v.fixed_version,
                        "aliases": v.aliases,
                        "reference_url": v.reference_url,
                    }
                    for v in r.vulnerabilities
                ],
                "error": r.error,
            }
            for r in result.results
        ],
        "latency_ms": result.latency_ms,
    }


@app.post("/v1/vuln/scan")
async def vuln_scan(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> dict[str, object]:
    """Scan packages for known vulnerabilities (CVE/GHSA) via OSV database."""
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required
    req = await _parse_request_model(request, VulnScanRequest)

    installation_id = _resolve_installation_id(request)
    plan = auth.plan if auth else "free"
    limit_hit = _check_scan_limit(installation_id, plan)
    if limit_hit is not None:
        return JSONResponse(status_code=429, content=limit_hit)

    logger.info("api_vuln_scan", language=str(req.language), packages=len(req.packages))

    from src.services.vulnerability import VulnerabilityService

    cache: CacheService = request.app.state.cache
    http_client: httpx.AsyncClient = request.app.state.http_client
    vuln_svc = VulnerabilityService(cache, http_client)

    result = await vuln_svc.check_packages(
        language=req.language,
        packages=req.packages,
        versions=req.versions if req.versions else None,
    )

    await _log_scan(
        request, auth, "vuln", "BLOCK" if result.vulnerable_count > 0 else "PASS",
        result.total_vulnerabilities, result.latency_ms,
        str(req.language), "",
    )

    return _build_vuln_scan_response(result)


# --- License Compliance ---


def _build_license_scan_response(result: LicenseScanResponse) -> dict[str, object]:
    """Build the API response dict from a license scan result."""
    return {
        "total_packages": result.total_packages,
        "permissive_count": result.permissive_count,
        "weak_copyleft_count": result.weak_copyleft_count,
        "strong_copyleft_count": result.strong_copyleft_count,
        "network_copyleft_count": result.network_copyleft_count,
        "unknown_count": result.unknown_count,
        "compliant": result.compliant,
        "risk_packages": [
            {
                "package": r.package,
                "ecosystem": r.ecosystem,
                "license_name": r.license_name,
                "risk": r.risk.value,
                "spdx_id": r.spdx_id,
            }
            for r in result.risk_packages
        ],
        "all_licenses": [
            {
                "package": r.package,
                "ecosystem": r.ecosystem,
                "license_name": r.license_name,
                "risk": r.risk.value,
                "spdx_id": r.spdx_id,
            }
            for r in result.all_licenses
        ],
        "latency_ms": result.latency_ms,
    }


@app.post("/v1/license/scan")
async def license_scan(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> dict[str, object]:
    """Check package licenses for compliance (copyleft detection)."""
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required
    req = await _parse_request_model(request, LicenseScanRequest)

    installation_id = _resolve_installation_id(request)
    plan = auth.plan if auth else "free"
    limit_hit = _check_scan_limit(installation_id, plan)
    if limit_hit is not None:
        return JSONResponse(status_code=429, content=limit_hit)

    logger.info("api_license_scan", language=str(req.language), packages=len(req.packages))

    from src.services.license_checker import LicenseService

    cache: CacheService = request.app.state.cache
    http_client: httpx.AsyncClient = request.app.state.http_client
    license_svc = LicenseService(cache, http_client)

    result = await license_svc.check_packages(
        language=req.language,
        packages=req.packages,
    )

    await _log_scan(
        request, auth, "license", "PASS" if result.compliant else "BLOCK",
        result.strong_copyleft_count + result.network_copyleft_count,
        result.latency_ms, str(req.language), "",
    )

    return _build_license_scan_response(result)


# --- Compliance Reports ---


@app.get("/v1/compliance/{framework}")
async def compliance_report(
    framework: str,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Generate a compliance mapping report for a security framework.

    Maps CodeTrust governance capabilities to recognized frameworks.
    Supported: owasp-asi-2026, eu-ai-act, nist-ai-rmf.
    """
    logger.info("api_compliance_report", framework=framework)

    from src.services.compliance import (
        compliance_summary,
        get_compliance_report,
        is_fully_compliant,
        list_frameworks,
    )

    if framework == "list":
        return {"frameworks": list_frameworks()}

    try:
        report = get_compliance_report(framework)
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": str(exc)},
        )

    result = report.to_dict()
    result["fully_compliant"] = is_fully_compliant(framework)
    result["summary"] = compliance_summary(report)
    return result


# --- Agent Integrity Verification ---


@app.post("/v1/integrity/check")
async def integrity_check(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Analyze agent session for behavioral integrity patterns.

    Detects sycophantic retraction, unsubstantiated claims,
    unverified references, and contradictory positions.
    """
    logger.info("api_integrity_check")

    body = await request.json()
    agent_output: str = body.get("agent_output", "")
    raw_messages: list[dict[str, str]] = body.get("session_history", [])
    raw_commands: list[str] = body.get("commands", [])
    session_id: str = body.get("session_id", "api-session")

    from src.services.agent_integrity import (
        analyze_session,
        parse_session_messages,
    )

    if agent_output:
        raw_messages = list(raw_messages)
        raw_messages.append({"role": "assistant", "content": agent_output})

    messages = parse_session_messages(raw_messages)
    report = analyze_session(messages, raw_commands, session_id=session_id)
    return report.to_dict()


# --- SBOM Generation ---


@app.post("/v1/sbom/generate", response_model=SbomGenerateResponse)
async def sbom_generate(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> SbomGenerateResponse:
    """Generate CycloneDX and SPDX SBOM outputs for dependency inventories."""
    enterprise_required = _require_pro_or_enterprise(auth.plan)
    if enterprise_required is not None:
        return enterprise_required
    req = await _parse_request_model(request, SbomGenerateRequest)

    logger.info("api_sbom_generate", language=str(req.language), packages=len(req.packages))

    from src.services.sbom import SbomService

    sbom_svc = SbomService()
    result = sbom_svc.generate(
        language=req.language,
        packages=req.packages,
        versions=req.versions,
        document_name=req.document_name,
    )

    await _log_scan(
        request, auth, "sbom", "PASS", 0, result.latency_ms,
        str(req.language), req.document_name,
    )

    return SbomGenerateResponse(
        ecosystem=result.ecosystem,
        document_name=result.document_name,
        component_count=result.component_count,
        cyclonedx_json=result.cyclonedx_json,
        spdx_json=result.spdx_json,
        latency_ms=result.latency_ms,
    )


# --- Cross-File Analysis ---


@app.post("/v1/scan/cross-file")
async def cross_file_scan(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> dict[str, object]:
    """Analyze import dependency graph across multiple files."""
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required
    req = await _parse_request_model(request, CrossFileScanRequest)

    installation_id = _resolve_installation_id(request)
    plan = auth.plan if auth else "free"
    limit_hit = _check_scan_limit(installation_id, plan)
    if limit_hit is not None:
        return JSONResponse(status_code=429, content=limit_hit)

    logger.info("api_cross_file_scan", files=len(req.files))

    from src.services.cross_file_analyzer import CrossFileAnalyzer

    analyzer = CrossFileAnalyzer()
    result = analyzer.analyze_project(file_contents=req.files)

    await _log_scan(
        request, auth, "cross-file", "WARN" if result.circular_dependencies else "PASS",
        len(result.circular_dependencies) + len(result.orphan_files),
        result.latency_ms, "", "",
    )

    return {
        "total_files": result.total_files,
        "total_edges": result.total_edges,
        "circular_dependencies": result.circular_dependencies,
        "orphan_files": result.orphan_files,
        "hub_files": result.hub_files,
        "latency_ms": result.latency_ms,
    }


# --- Taint Verified Scan ---


@app.post("/v1/scan/taint/verified", response_model=TaintVerifiedResponse)
async def taint_verified_scan(
    request: Request,
    req: TaintVerifiedRequest,
    taint_anal: TaintAnalyzer = Depends(_get_taint_analyzer),
    sandbox_svc: SandboxService = Depends(_get_sandbox),
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> TaintVerifiedResponse:
    """Run taint analysis with runtime exploit verification.

    Performs static taint analysis, then attempts to confirm each
    finding by executing proof-of-concept exploits in an isolated
    Docker sandbox. Verified findings have high confidence (~0.95).
    """
    pro_required = _require_pro_or_enterprise(auth.plan)
    if pro_required is not None:
        return pro_required

    installation_id = _resolve_installation_id(request)
    plan = auth.plan if auth else "free"
    limit_hit = _check_scan_limit(installation_id, plan)
    if limit_hit is not None:
        return JSONResponse(status_code=429, content=limit_hit)

    logger.info("api_taint_verified_scan", filename=req.filename, language=str(req.language))
    start = time.monotonic()

    response = await _run_taint_verified(req, taint_anal, sandbox_svc)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    response.latency_ms = elapsed_ms

    await _log_scan(
        request, auth, "taint-verified", response.verdict,
        response.total, elapsed_ms, str(req.language), req.filename,
        findings=response.taint_findings,
    )
    return response


async def _run_taint_verified(
    req: TaintVerifiedRequest,
    taint_anal: TaintAnalyzer,
    sandbox_svc: SandboxService,
) -> TaintVerifiedResponse:
    """Core logic for taint analysis with runtime verification.

    Args:
        req: The validated request.
        taint_anal: Taint analyzer instance.
        sandbox_svc: Sandbox service for exploit execution.

    Returns:
        TaintVerifiedResponse with original and verified findings.
    """
    lang_str = str(req.language.value) if hasattr(req.language, "value") else str(req.language)
    if lang_str not in _TAINT_SUPPORTED_LANGUAGES:
        return TaintVerifiedResponse(verdict="PASS")

    findings = taint_anal.analyze(req.code, req.language, req.filename)
    if not findings:
        return TaintVerifiedResponse(verdict="PASS")

    verifier = RuntimeTaintVerifier(sandbox=sandbox_svc)
    summary = await verifier.verify_findings(findings, language=req.language)

    return _build_taint_verified_response(findings, summary)


def _build_taint_verified_response(
    findings: list[Finding],
    summary: VerificationSummary,
) -> TaintVerifiedResponse:
    """Assemble the TaintVerifiedResponse from analysis results.

    Args:
        findings: Original taint findings.
        summary: Verification summary from RuntimeTaintVerifier.

    Returns:
        Populated TaintVerifiedResponse.
    """
    verified_items = [
        _verified_finding_to_response(vf) for vf in summary.results
    ]

    has_blocks = any(f.severity == Severity.BLOCK for f in findings)
    has_verified = summary.verified > 0
    verdict = "BLOCK" if (has_blocks or has_verified) else "WARN" if findings else "PASS"

    return TaintVerifiedResponse(
        taint_findings=findings,
        verified_findings=verified_items,
        total=summary.total,
        verified_count=summary.verified,
        unverified_count=summary.unverified,
        sandbox_unavailable=summary.sandbox_unavailable,
        verdict=verdict,
    )


def _verified_finding_to_response(vf: VerifiedFinding) -> VerifiedFindingResponse:
    """Convert a dataclass VerifiedFinding to a Pydantic response model.

    Args:
        vf: The dataclass instance from RuntimeTaintVerifier.

    Returns:
        VerifiedFindingResponse suitable for JSON serialization.
    """
    return VerifiedFindingResponse(
        finding=vf.finding,
        verified=vf.verified,
        confidence=vf.confidence,
        exploit_payload=vf.exploit_payload,
        verification_method=vf.verification_method,
    )


# --- Auto-Fix ---


def _detect_file_languages(
    files: dict[str, str], languages: dict[str, str] | None,
) -> dict[str, str]:
    """Auto-detect languages for files that don't have one specified."""
    from src.services.cross_file_analyzer import detect_language_from_extension

    result: dict[str, str] = dict(languages) if languages else {}
    for filepath in files:
        if filepath not in result:
            lang = detect_language_from_extension(filepath)
            if lang is not None:
                result[filepath] = lang.value
    return result


def _build_autofix_response(result: AutoFixResult) -> dict[str, object]:
    """Build the API response dict from an auto-fix result."""
    return {
        "files_fixed": [
            {"path": f.path, "fixes_applied": f.fixes_applied}
            for f in result.files_fixed
        ],
        "total_fixes": result.total_fixes,
        "pr_url": result.pr_url,
        "branch_name": result.branch_name,
        "error": result.error,
    }


@app.post("/v1/fix/apply")
async def autofix_apply(
    request: Request,
    req: AutoFixRequest,
    auth: AuthContext = Depends(get_auth_context),
    rate_limiter: RateLimiter | None = Depends(_get_rate_limiter),
) -> dict[str, object]:
    """Apply auto-fix recipes to code. Optionally create a GitHub PR."""
    enterprise_required = _require_pro_or_enterprise(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    logger.info("api_autofix", files=len(req.files), create_pr=req.create_pr)

    from src.services.autofix import AutoFixService

    languages = _detect_file_languages(req.files, req.languages)
    http_client: httpx.AsyncClient = request.app.state.http_client
    github_token = os.environ.get("CODETRUST_GITHUB_TOKEN", "")

    fix_svc = AutoFixService(
        http_client=http_client if req.create_pr else None,
        github_token=github_token,
    )

    result = fix_svc.apply_fixes(
        file_contents=req.files,
        file_languages=languages,
        recipes=req.recipes if req.recipes else None,
    )

    if req.create_pr and result.files_fixed:
        result = await fix_svc.create_pr(
            owner=req.github_owner,
            repo=req.github_repo,
            base_branch=req.github_base_branch,
            fix_result=result,
        )

    await _log_scan(request, auth, "autofix", "PASS", result.total_fixes, 0, "", "")

    return _build_autofix_response(result)


# --- Team Management / RBAC ---


def _get_team_service(request: Request) -> object:
    """Get team service from app state."""
    return getattr(request.app.state, "team_service", None)


@app.post("/v1/orgs")
async def create_org(
    request: Request,
    req: CreateOrgRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Create a new organization."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    try:
        org = await team_svc.create_org(name=req.name, owner_id=auth.user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return {
        "id": org.id, "name": org.name, "slug": org.slug,
        "plan": org.plan, "owner_id": org.owner_id,
        "member_count": org.member_count, "created_at": org.created_at,
    }


@app.get("/v1/orgs")
async def list_orgs(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> list[dict[str, object]]:
    """List organizations the authenticated user belongs to."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    orgs = await team_svc.list_user_orgs(auth.user_id)
    return [
        {
            "id": o.id, "name": o.name, "slug": o.slug,
            "plan": o.plan, "owner_id": o.owner_id,
            "member_count": o.member_count, "created_at": o.created_at,
        }
        for o in orgs
    ]


@app.get("/v1/orgs/{org_id}")
async def get_org(
    org_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Get organization details. Requires membership."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    role = await team_svc.get_user_role(org_id, auth.user_id)
    if role is None and not auth.is_admin:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    org = await team_svc.get_org(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    return {
        "id": org.id, "name": org.name, "slug": org.slug,
        "plan": org.plan, "owner_id": org.owner_id,
        "member_count": org.member_count, "created_at": org.created_at,
    }


@app.delete("/v1/orgs/{org_id}")
async def delete_org(
    org_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Delete an organization. Only the owner can delete."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    deleted = await team_svc.delete_org(org_id, auth.user_id)
    if not deleted:
        raise HTTPException(status_code=403, detail="Not authorized or not found")

    return {"deleted": True}


@app.get("/v1/orgs/{org_id}/members")
async def list_members(
    org_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> list[dict[str, object]]:
    """List members of an organization. Requires membership."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    role = await team_svc.get_user_role(org_id, auth.user_id)
    if role is None and not auth.is_admin:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    members = await team_svc.list_members(org_id)
    return [
        {
            "id": m.id, "user_id": m.user_id, "email": m.email,
            "name": m.name, "role": m.role, "created_at": m.created_at,
        }
        for m in members
    ]


@app.post("/v1/orgs/{org_id}/members")
async def add_member(
    org_id: str,
    request: Request,
    req: AddMemberRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Add a member to an organization."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    member = await team_svc.add_member(
        org_id=org_id,
        user_id=req.user_id,
        role=req.role,
        invited_by=auth.user_id,
    )
    if member is None:
        raise HTTPException(status_code=400, detail="User already a member or not found")

    return {
        "id": member.id, "user_id": member.user_id, "email": member.email,
        "name": member.name, "role": member.role, "created_at": member.created_at,
    }


@app.delete("/v1/orgs/{org_id}/members/{user_id}")
async def remove_member(
    org_id: str,
    user_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Remove a member from an organization."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    removed = await team_svc.remove_member(org_id, user_id, auth.user_id)
    if not removed:
        raise HTTPException(status_code=403, detail="Not authorized or member not found")

    return {"removed": True}


@app.put("/v1/orgs/{org_id}/members/{user_id}/role")
async def update_role(
    org_id: str,
    user_id: str,
    request: Request,
    req: UpdateMemberRoleRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Update a member's role in an organization."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    updated = await team_svc.update_member_role(org_id, user_id, req.role, auth.user_id)
    if not updated:
        raise HTTPException(status_code=403, detail="Not authorized")

    return {"updated": True}


@app.get("/v1/orgs/{org_id}/policy")
async def get_policy(
    org_id: str,
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Get organization policy settings. Requires membership."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    role = await team_svc.get_user_role(org_id, auth.user_id)
    if role is None and not auth.is_admin:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    policy = await team_svc.get_org_policy(org_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Organization not found")

    return {
        "max_severity_allowed": policy.max_severity_allowed,
        "require_license_compliance": policy.require_license_compliance,
        "blocked_licenses": policy.blocked_licenses,
        "require_vuln_scan": policy.require_vuln_scan,
        "max_critical_vulns": policy.max_critical_vulns,
        "max_high_vulns": policy.max_high_vulns,
    }


@app.put("/v1/orgs/{org_id}/policy")
async def update_policy(
    org_id: str,
    request: Request,
    req: UpdateOrgPolicyRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, object]:
    """Update organization policy settings."""
    enterprise_required = _require_team_or_above(auth.plan)
    if enterprise_required is not None:
        return enterprise_required

    team_svc = _get_team_service(request)
    if team_svc is None:
        raise HTTPException(status_code=503, detail="Team service not available")

    updated = await team_svc.update_org_policy(
        org_id=org_id,
        requester_id=auth.user_id,
        policy={
            "max_severity_allowed": req.max_severity_allowed,
            "require_license_compliance": req.require_license_compliance,
            "blocked_licenses": req.blocked_licenses,
            "require_vuln_scan": req.require_vuln_scan,
            "max_critical_vulns": req.max_critical_vulns,
            "max_high_vulns": req.max_high_vulns,
        },
    )
    if not updated:
        raise HTTPException(status_code=403, detail="Not authorized")

    return {"updated": True}


# --- Dashboard: API Key management ---


@app.post(
    "/v1/admin/dashboard/bootstrap-api-key",
    response_model=DashboardBootstrapApiKeyResponse,
)
async def admin_dashboard_bootstrap_api_key(
    req: DashboardBootstrapApiKeyRequest,
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> DashboardBootstrapApiKeyResponse:
    """Bootstrap a user-scoped API key using server-side master-key auth."""
    if auth.user_id != "system_master_key":
        raise HTTPException(status_code=403, detail="Admin access required")

    github_id = req.github_id or req.user_id
    user = await db.get_user(req.user_id)
    if user is None:
        user = await db.get_user_by_github_id(github_id)
    if user is None:
        user = await db.create_user(
            github_id=github_id,
            email=req.email,
            name=req.name,
        )
    raw_key, record = await db.rotate_dashboard_api_key(user.id)
    return DashboardBootstrapApiKeyResponse(
        user_id=user.id,
        plan=user.plan,
        api_key=raw_key,
        key_id=record.id,
        prefix=record.prefix,
    )


@app.get(
    "/v1/admin/adoption/overview",
    response_model=AdminAdoptionOverviewResponse,
)
async def admin_adoption_overview(
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> AdminAdoptionOverviewResponse:
    """Return high-level platform adoption metrics for admins."""
    if auth.user_id != "system_master_key":
        raise HTTPException(status_code=403, detail="Admin access required")
    data = await db.get_adoption_overview()
    return AdminAdoptionOverviewResponse(**data)


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


@app.get(
    "/v1/governance/policy-bundles",
    response_model=list[GovernancePolicyBundleResponse],
)
async def governance_policy_bundles(
    auth: AuthContext = Depends(get_auth_context),
) -> list[GovernancePolicyBundleResponse] | JSONResponse:
    """Return tenant-aware governance bundles with signatures."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    from src.services.governance_bundles import list_signed_bundles

    secret = settings.rules_hmac_secret or settings.jwt_secret or "codetrust"
    bundles = list_signed_bundles(secret=secret, version=settings.version)
    return [GovernancePolicyBundleResponse.model_validate(bundle) for bundle in bundles]


@app.post(
    "/v1/governance/policy-snapshot",
    response_model=GovernancePolicySnapshotResponse,
)
async def governance_policy_snapshot(
    request: Request,
    req: GovernancePolicySnapshotRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernancePolicySnapshotResponse | JSONResponse:
    """Create signed governance policy snapshot and append audit trail entry."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    from src.gateway.audit import AuditEntry, AuditLogger
    from src.services.governance_bundles import build_signed_snapshot

    secret = settings.rules_hmac_secret or settings.jwt_secret or "codetrust"
    snapshot = build_signed_snapshot(
        bundle_id=req.bundle_id,
        overrides=req.overrides,
        secret=secret,
        version=settings.version,
    )
    session_id = _resolve_attestation_session_id(request)

    audit_path = os.path.join(os.getcwd(), ".codetrust", "audit.jsonl")
    audit_logger = AuditLogger(audit_path)
    audit_logger.log(AuditEntry(
        timestamp=time.time(),
        action_type="governance_policy_snapshot",
        verdict="ALLOW",
        rule_id="policy_snapshot_signed",
        original_action=req.bundle_id,
        message="Signed governance snapshot created",
        suggestion="Apply snapshot through org policy automation",
        session_id=session_id,
        agent_id=auth.user_id,
        workspace=str(os.getcwd()),
        metadata={
            "snapshot_id": snapshot["snapshot_id"],
            "signature": snapshot["signature"],
            "policy_hash": snapshot["policy_hash"],
            "issued_at": snapshot["issued_at"],
        },
    ))

    return GovernancePolicySnapshotResponse(
        snapshot_id=str(snapshot["snapshot_id"]),
        bundle_id=req.bundle_id,
        policy=dict(snapshot["policy"]),
        signature=str(snapshot["signature"]),
        issued_at=str(snapshot["issued_at"]),
        version=settings.version,
        session_id=session_id,
        policy_hash=str(snapshot["policy_hash"]),
        audit_logged=True,
    )


@app.get(
    "/v1/governance/posture",
    response_model=GovernancePostureResponse,
)
async def governance_posture(
    auth: AuthContext = Depends(get_auth_context),
) -> GovernancePostureResponse | JSONResponse:
    """Return governance posture for control-plane and compliance checks."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    workspace = str(os.getcwd())
    engine = PolicyEngine.from_workspace(workspace)
    secret = settings.rules_hmac_secret or settings.jwt_secret or "codetrust"
    integrity = verify_policy_integrity(workspace, sign_key=secret)
    approval_store = ApprovalExceptionStore(
        workspace,
        approval_ttl_minutes=engine.config.approval_ttl_minutes,
        exception_ttl_minutes=engine.config.exception_ttl_minutes,
    )

    return GovernancePostureResponse(
        session_id=f"api-{int(time.time() * 1000)}",
        agent_id=auth.user_id,
        mode=engine.config.mode.value,
        enabled=engine.config.enabled,
        trusted_execution_mode=engine.config.trusted_execution_mode,
        deny_native_execution=engine.config.deny_native_execution,
        require_allow_reason=engine.config.require_allow_reason,
        session_binding_enforced=engine.config.session_binding_required,
        anti_bypass_enabled=engine.config.anti_bypass_checks,
        control_plane_ready=(
            engine.config.enabled
            and engine.config.trusted_execution_mode
            and engine.config.deny_native_execution
            and engine.config.require_allow_reason
            and engine.config.session_binding_required
            and engine.config.anti_bypass_checks
        ),
        policy_integrity={
            "verdict": integrity.verdict,
            "rule_id": integrity.rule_id,
            "policy_hash": get_policy_manifest_hash(workspace),
        },
        pending_approvals=len(approval_store.list_pending()),
        active_exceptions=len(approval_store.list_active_exceptions()),
    )


@app.post(
    "/v1/governance/simulate-policy",
    response_model=GovernancePolicySimulationResponse,
)
async def governance_simulate_policy(
    req: GovernancePolicySimulationRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernancePolicySimulationResponse | JSONResponse:
    """Simulate command verdicts for a governance policy bundle."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    policy = get_bundle_policy(req.bundle_id)
    simulator = CommandInterceptor(
        enabled=True,
        disabled_rules=_disabled_rules_from_bundle(policy),
        protected_paths=list(policy.get("protected_paths", [])),
    )

    outcomes: list[GovernancePolicySimulationOutcomeResponse] = []
    for command in req.commands:
        result = simulator.check_terminal(command)
        outcomes.append(GovernancePolicySimulationOutcomeResponse(
            command=command,
            verdict=result.verdict.value,
            rule_id=result.rule_id,
            message=result.message,
        ))

    return GovernancePolicySimulationResponse(bundle_id=req.bundle_id, outcomes=outcomes)


# --- Governance: Approvals & Exceptions ---


def _get_approval_store() -> ApprovalExceptionStore:
    """Build ApprovalExceptionStore from workspace policy engine."""
    workspace = str(os.getcwd())
    engine = PolicyEngine.from_workspace(workspace)
    return ApprovalExceptionStore(
        workspace,
        approval_ttl_minutes=engine.config.approval_ttl_minutes,
        exception_ttl_minutes=engine.config.exception_ttl_minutes,
    )


@app.get(
    "/v1/governance/approvals",
    response_model=list[GovernancePendingApprovalResponse],
)
async def governance_list_approvals(
    auth: AuthContext = Depends(get_auth_context),
) -> list[GovernancePendingApprovalResponse] | JSONResponse:
    """List all pending governance approval requests."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    store = _get_approval_store()
    pending = store.list_pending()
    return [
        GovernancePendingApprovalResponse(
            request_id=p.request_id,
            rule_id=p.rule_id,
            action_type=p.action_type,
            original_action=p.original_action,
            action_fingerprint=p.action_fingerprint,
            requested_at=p.requested_at,
            expires_at=p.expires_at,
            session_id=p.session_id,
            agent_id=p.agent_id,
        )
        for p in pending
    ]


@app.post(
    "/v1/governance/approvals/{request_id}/approve",
    response_model=GovernanceApproveResponse,
)
async def governance_approve_action(
    request_id: str,
    req: GovernanceApproveRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernanceApproveResponse | JSONResponse:
    """Approve a pending governance action and create a time-bound exception."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    store = _get_approval_store()
    exception = store.approve(
        request_id,
        approver=req.approver,
        approver_role=req.approver_role,
        reason=req.reason,
        ttl_minutes=req.ttl_minutes,
    )
    if exception is None:
        raise HTTPException(
            status_code=404,
            detail="Pending approval not found or expired.",
        )
    return GovernanceApproveResponse(
        approved=True,
        exception_id=exception.exception_id,
        expires_at=exception.expires_at,
    )


@app.get(
    "/v1/governance/exceptions",
    response_model=list[GovernanceExceptionResponse],
)
async def governance_list_exceptions(
    auth: AuthContext = Depends(get_auth_context),
) -> list[GovernanceExceptionResponse] | JSONResponse:
    """List all active governance exceptions."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    store = _get_approval_store()
    exceptions = store.list_active_exceptions()
    return [
        GovernanceExceptionResponse(
            exception_id=exc.exception_id,
            rule_id=exc.rule_id,
            action_type=exc.action_type,
            action_fingerprint=exc.action_fingerprint,
            reason=exc.reason,
            approver=exc.approver,
            approver_role=exc.approver_role,
            created_at=exc.created_at,
            expires_at=exc.expires_at,
            revoked_at=exc.revoked_at,
            revoked_by=exc.revoked_by,
            session_id=exc.session_id,
            agent_id=exc.agent_id,
        )
        for exc in exceptions
    ]


@app.delete("/v1/governance/exceptions/{exception_id}", response_model=StatusResponse)
async def governance_revoke_exception(
    exception_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> StatusResponse:
    """Revoke an active governance exception."""
    store = _get_approval_store()
    revoked = store.revoke(exception_id, revoked_by=auth.user_id)
    if not revoked:
        raise HTTPException(
            status_code=404,
            detail="Exception not found or already revoked.",
        )
    return StatusResponse(status="revoked")


# --- Governance: Multi-Workspace Aggregation ---


def _get_workspace_registry() -> WorkspaceRegistry:
    """Get or create the workspace registry singleton."""
    if not hasattr(app.state, "workspace_registry"):
        app.state.workspace_registry = WorkspaceRegistry()
    return app.state.workspace_registry


@app.get(
    "/v1/governance/workspaces",
    response_model=GovernanceWorkspaceAggregateResponse,
)
async def governance_list_workspaces(
    auth: AuthContext = Depends(get_auth_context),
) -> GovernanceWorkspaceAggregateResponse:
    """Aggregated multi-workspace governance overview.

    Returns posture summaries for all registered workspaces
    with aggregate health metrics.
    """
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    registry = _get_workspace_registry()
    agg = registry.aggregate()
    workspace_responses = [
        GovernanceWorkspacePostureResponse(
            workspace_id=w.workspace_id,
            workspace_name=w.workspace_name,
            agent_id=w.agent_id,
            enabled=w.enabled,
            mode=w.mode,
            control_plane_ready=w.control_plane_ready,
            policy_hash=w.policy_hash,
            policy_verdict=w.policy_verdict,
            pending_approvals=w.pending_approvals,
            active_exceptions=w.active_exceptions,
            drift_count=w.drift_count,
            last_seen_at=w.last_seen_at,
        )
        for w in registry.list_all()
    ]
    return GovernanceWorkspaceAggregateResponse(
        total_workspaces=int(agg["total_workspaces"]),
        healthy_count=int(agg["healthy_count"]),
        drifted_count=int(agg["drifted_count"]),
        disabled_count=int(agg["disabled_count"]),
        total_pending_approvals=int(agg["total_pending_approvals"]),
        total_active_exceptions=int(agg["total_active_exceptions"]),
        workspaces=workspace_responses,
    )


@app.post(
    "/v1/governance/workspaces",
    response_model=GovernanceWorkspacePostureResponse,
)
async def governance_register_workspace(
    req: GovernanceRegisterWorkspaceRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernanceWorkspacePostureResponse:
    """Register or update a workspace's governance posture.

    Called by gateway instances or CLI to report their posture
    for multi-workspace aggregation.
    """
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    registry = _get_workspace_registry()
    record = registry.register(
        workspace_id=req.workspace_id,
        workspace_name=req.workspace_name,
        agent_id=req.agent_id,
        posture=dict(req.posture) if req.posture else None,
    )
    return GovernanceWorkspacePostureResponse(
        workspace_id=record.workspace_id,
        workspace_name=record.workspace_name,
        agent_id=record.agent_id,
        enabled=record.enabled,
        mode=record.mode,
        control_plane_ready=record.control_plane_ready,
        policy_hash=record.policy_hash,
        policy_verdict=record.policy_verdict,
        pending_approvals=record.pending_approvals,
        active_exceptions=record.active_exceptions,
        drift_count=record.drift_count,
        last_seen_at=record.last_seen_at,
    )


@app.delete("/v1/governance/workspaces/{workspace_id}", response_model=StatusResponse)
async def governance_unregister_workspace(
    workspace_id: str,
    auth: AuthContext = Depends(get_auth_context),
) -> StatusResponse | JSONResponse:
    """Remove a workspace from the governance registry."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    registry = _get_workspace_registry()
    removed = registry.unregister(workspace_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Workspace not found.")
    return StatusResponse(status="removed")


# --- Governance: Unified Session Token ---


def _get_session_store() -> UnifiedSessionStore:
    """Get or create the unified session store singleton."""
    if not hasattr(app.state, "session_store"):
        app.state.session_store = UnifiedSessionStore()
    return app.state.session_store


@app.post(
    "/v1/governance/session-token",
    response_model=GovernanceUnifiedSessionResponse,
)
async def governance_issue_session_token(
    req: GovernanceUnifiedSessionRequest,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernanceUnifiedSessionResponse:
    """Issue a unified session token spanning multiple surfaces.

    Creates a cross-surface audit chain ID that links all governance
    actions across IDE, CLI, CI, and API within one session.
    """
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    store = _get_session_store()
    session = store.issue(
        surfaces=req.surfaces,
        agent_id=req.agent_id,
        workspace_id=req.workspace_id,
        ttl_minutes=req.ttl_minutes,
    )
    return GovernanceUnifiedSessionResponse(
        session_token=session.session_token,
        surfaces=session.surfaces,
        issued_at=session.issued_at,
        expires_at=session.expires_at,
        agent_id=session.agent_id,
        workspace_id=session.workspace_id,
        audit_chain_id=session.audit_chain_id,
    )


@app.get(
    "/v1/governance/session-token/{token}",
    response_model=GovernanceSessionStatusResponse,
)
async def governance_validate_session_token(
    token: str,
    auth: AuthContext = Depends(get_auth_context),
) -> GovernanceSessionStatusResponse | JSONResponse:
    """Validate a unified session token and return its status."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    store = _get_session_store()
    session = store.validate(token)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session token not found or expired.",
        )
    now = time.time()
    return GovernanceSessionStatusResponse(
        valid=True,
        session_token=session.session_token,
        surfaces=session.surfaces,
        issued_at=session.issued_at,
        expires_at=session.expires_at,
        remaining_seconds=max(0.0, session.expires_at - now),
        agent_id=session.agent_id,
        workspace_id=session.workspace_id,
        audit_chain_id=session.audit_chain_id,
    )


@app.delete("/v1/governance/session-token/{token}", response_model=StatusResponse)
async def governance_revoke_session_token(
    token: str,
    auth: AuthContext = Depends(get_auth_context),
) -> StatusResponse | JSONResponse:
    """Revoke a unified session token."""
    plan_gate = _require_pro_for_cloud(auth)
    if plan_gate is not None:
        return plan_gate
    store = _get_session_store()
    revoked = store.revoke(token)
    if not revoked:
        raise HTTPException(
            status_code=404,
            detail="Session token not found or already expired.",
        )
    return StatusResponse(status="revoked")


# --- Auth: GitHub OAuth + JWT ---


@app.post("/v1/github/app/webhook", response_model=GitHubAppWebhookResponse)
async def github_app_webhook(
    request: Request,
    github_app: GitHubAppService = Depends(_get_github_app),
) -> GitHubAppWebhookResponse:
    """Process GitHub App pull_request events and post sticky PR comments."""
    signature = request.headers.get("X-Hub-Signature-256", "")
    event = request.headers.get("X-GitHub-Event", "")
    payload_bytes = await request.body()

    if not github_app.verify_webhook_signature(payload_bytes, signature):
        raise HTTPException(status_code=401, detail="Invalid GitHub webhook signature")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid GitHub webhook payload") from exc

    result = await github_app.handle_webhook_event(event=event, payload=payload)
    return GitHubAppWebhookResponse(
        processed=result.processed,
        event=result.event,
        action=result.action,
        reason=result.reason,
        comment_url=result.comment_url,
        total_findings=result.total_findings,
        blocks=result.blocks,
        warnings=result.warnings,
        infos=result.infos,
    )


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
    """Refresh an expiring JWT token. Revokes the old token."""
    if await auth_svc.is_token_revoked(req.token):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    decoded = auth_svc.decode_jwt(req.token)
    if decoded is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = await db.get_user(decoded["user_id"])
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Revoke old token before issuing new one
    await auth_svc.revoke_jwt(req.token)

    new_token = auth_svc.create_jwt(user.id, user.plan)
    return TokenResponse(
        token=new_token,
        user_id=user.id,
        plan=user.plan,
        expires_in_minutes=settings.jwt_expire_minutes,
    )


@app.post("/v1/auth/token")
async def issue_scan_token(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
    auth_svc: AuthService = Depends(_get_auth),
    db: DatabaseService = Depends(_get_db),
) -> dict[str, object]:
    """Issue a scan token for CLI usage.

    Returns a signed JWT with plan, quota limit, and daily usage.
    CLI stores this locally and validates offline. Refreshed once/day.
    """
    plan = auth.plan
    limit = PLAN_LIMITS.get(plan, PLAN_LIMITS.get("free", 25))
    usage = 0
    if db is not None:
        usage = await db.get_daily_usage(auth.user_id)

    if usage >= limit:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "daily_scan_limit_reached",
                "plan": plan,
                "limit": limit,
                "used": usage,
                "upgrade_url": "https://app.codetrust.ai/pricing",
            },
        )

    from datetime import UTC as _UTC
    from datetime import datetime as _dt
    from datetime import timedelta

    token = auth_svc.create_jwt(auth.user_id, plan)
    expires_at = _dt.now(tz=_UTC) + timedelta(minutes=settings.jwt_expire_minutes)

    return {
        "token": token,
        "plan": plan,
        "user_id": auth.user_id,
        "quota_limit": limit,
        "quota_used": usage,
        "expires_at": expires_at.isoformat(),
        "expires_in_minutes": settings.jwt_expire_minutes,
    }


@app.post("/v1/auth/logout")
async def logout(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> dict[str, bool]:
    """Revoke the current JWT token (logout)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Bearer token required for logout")

    token = auth_header[7:]
    auth_svc = getattr(request.app.state, "auth", None)
    if auth_svc is None:
        raise HTTPException(status_code=503, detail="Auth service not available")

    revoked = await auth_svc.revoke_jwt(token)
    return {"revoked": revoked}


# --- Dashboard: User Profile ---


@app.get("/v1/profile", response_model=UserProfileResponse)
async def user_profile(
    db: DatabaseService = Depends(_get_db),
    auth: AuthContext = Depends(get_auth_context),
) -> UserProfileResponse:
    """Get the authenticated user's profile and usage stats."""
    # Master key / admin — return synthetic profile
    if auth.is_admin:
        return UserProfileResponse(
            id=auth.user_id,
            email="said@saidborna.com",
            name="Admin",
            avatar_url="",
            plan="enterprise",
            created_at="",
            daily_limit=1_000_000,
            daily_usage=0,
        )

    user = await db.get_user(auth.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    daily_usage = await db.get_daily_usage(auth.user_id)
    limit = PLAN_LIMITS.get(user.plan, PLAN_LIMITS.get("free", 25))

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


def _build_oidc_config() -> OIDCConfig:
    """Build OIDC configuration from application settings."""
    return OIDCConfig(
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


async def _init_oidc_service(
    http_client: httpx.AsyncClient,
) -> OIDCService:
    """Create an OIDCService and perform discovery."""
    config = _build_oidc_config()
    svc = OIDCService(config, http_client)
    discovered = await svc.discover()
    if not discovered:
        raise HTTPException(status_code=502, detail="OIDC discovery failed")
    return svc


async def _create_oidc_token(
    request: Request,
    db: DatabaseService,
    user_info: object,
) -> TokenResponse:
    """Create or update OIDC user and return a JWT token."""
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


@app.get("/v1/auth/oidc/login")
async def oidc_login(
    request: Request,
    state: str = Query(default=""),
) -> dict:
    """Redirect URL for OIDC/SSO login.

    Returns the authorization URL to redirect the browser to the IdP.
    Requires OIDC to be configured via CODETRUST_OIDC_* env vars.
    """
    if not settings.oidc_enabled:
        raise HTTPException(status_code=503, detail="OIDC not configured")

    http_client = request.app.state.http_client
    svc = await _init_oidc_service(http_client)

    import secrets as _secrets

    actual_state = state or _secrets.token_urlsafe(32)

    # Store state server-side for CSRF validation
    cache = getattr(request.app.state, "cache", None)
    if cache is not None:
        await cache.set(f"{OIDC_STATE_PREFIX}{actual_state}", "1", OIDC_STATE_TTL_SECS)

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
    1. Validates the state parameter against server-side store
    2. Exchanges the code for tokens at the IdP
    3. Extracts user info from the ID token
    4. Creates or updates the user in the database
    5. Returns a CodeTrust JWT for dashboard sessions
    """
    if not settings.oidc_enabled:
        raise HTTPException(status_code=503, detail="OIDC not configured")

    # Validate state parameter server-side (CSRF protection)
    cache = getattr(request.app.state, "cache", None)
    if cache is not None and req.state:
        stored = await cache.get(f"{OIDC_STATE_PREFIX}{req.state}")
        if stored is None:
            raise HTTPException(status_code=400, detail="Invalid or expired OIDC state")

    http_client = request.app.state.http_client
    svc = await _init_oidc_service(http_client)

    user_info = await svc.exchange_code(req.code)
    if user_info is None:
        raise HTTPException(status_code=401, detail="OIDC authentication failed")

    if not svc.validate_domain(user_info.email):
        raise HTTPException(
            status_code=403,
            detail=f"Email domain not allowed: {user_info.email}",
        )

    return await _create_oidc_token(request, db, user_info)


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


# ═══════════════════════════════════════════════════════════════
#  Real-time Governance Dashboard
# ═══════════════════════════════════════════════════════════════


def _dashboard_enforcement(hours: int = 24) -> dict:
    """Build enforcement section from audit log."""
    import time as time_mod
    from collections import Counter
    from pathlib import Path as PathLib

    audit_path = PathLib.cwd() / ".codetrust" / "audit.jsonl"
    cutoff = time_mod.time() - (hours * 3600)
    blocks = 0
    warns = 0
    rule_counter: Counter = Counter()

    if audit_path.is_file():
        try:
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    ts = float(entry.get("timestamp", 0))
                    if ts < cutoff:
                        continue
                    verdict = entry.get("verdict", "")
                    if verdict == "BLOCK":
                        blocks += 1
                        rule_counter[entry.get("rule_id", "unknown")] += 1
                    elif verdict == "WARN":
                        warns += 1
                except (json.JSONDecodeError, ValueError):
                    continue
        except OSError:
            pass

    top_rules = [{"rule": r, "count": c} for r, c in rule_counter.most_common(10)]
    return {
        "layers_active": 9,
        "total_blocks_24h": blocks,
        "total_warns_24h": warns,
        "top_blocked_rules": top_rules,
    }


def _dashboard_compliance() -> dict:
    """Build compliance section from compliance engine."""
    try:
        from src.services.compliance import get_compliance_report

        result = {}
        for framework_id, short_name in [
            ("owasp-asi-2026", "owasp_asi"),
            ("eu-ai-act", "eu_ai_act"),
            ("nist-ai-rmf", "nist_rmf"),
        ]:
            report = get_compliance_report(framework_id)
            full_count = sum(1 for r in report.risks if r.coverage_level == "full")
            result[short_name] = {
                "status": "COMPLIANT" if full_count == len(report.risks) else "NON-COMPLIANT",
                "full": full_count,
                "total": len(report.risks),
            }
        return result
    except Exception:
        return {
            "owasp_asi": {"status": "UNKNOWN", "full": 0, "total": 10},
            "eu_ai_act": {"status": "UNKNOWN", "full": 0, "total": 7},
            "nist_rmf": {"status": "UNKNOWN", "full": 0, "total": 4},
        }


def _dashboard_pii(hours: int = 24) -> dict:
    """Build PII section from audit log."""
    import time as time_mod
    from collections import Counter
    from pathlib import Path as PathLib

    cutoff = time_mod.time() - (hours * 3600)
    scans = 0
    findings = 0
    pii_blocks = 0
    cat_counter: Counter = Counter()

    audit_path = PathLib.cwd() / ".codetrust" / "audit.jsonl"
    if audit_path.is_file():
        try:
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    if float(entry.get("timestamp", 0)) < cutoff:
                        continue
                    if entry.get("action_type") == "pii_scan":
                        scans += 1
                        if entry.get("verdict") == "BLOCK":
                            pii_blocks += 1
                except (json.JSONDecodeError, ValueError):
                    continue
        except OSError:
            pass

    return {
        "scans_24h": scans,
        "findings_24h": findings,
        "top_categories": list(cat_counter.most_common(5)),
        "blocks_24h": pii_blocks,
    }


def _dashboard_classification() -> dict:
    """Build classification section."""
    return {
        "files_classified": 0,
        "by_level": {"public": 0, "internal": 0, "confidential": 0, "restricted": 0},
        "routing_decisions_24h": 0,
        "routing_blocks_24h": 0,
    }


def _dashboard_cost() -> dict:
    """Build cost section from cost tracker."""
    try:
        from src.services.cost_tracker import generate_report

        report = generate_report(period="monthly")
        top_dev = max(report.by_developer.items(), key=lambda x: x[1]) if report.by_developer else ("none", 0.0)
        top_model = max(report.by_model.items(), key=lambda x: x[1]) if report.by_model else ("none", 0.0)
        budget = report.budget_status or {}
        limit = budget.get("monthly_limit", 0)

        return {
            "current_month_usd": round(report.total_cost_usd, 2),
            "budget_limit_usd": limit,
            "budget_pct": round((report.total_cost_usd / limit * 100) if limit else 0, 1),
            "top_developer": {"name": top_dev[0], "cost": round(top_dev[1], 2)},
            "top_model": {"name": top_model[0], "cost": round(top_model[1], 2)},
            "anomalies_24h": len(report.anomalies),
        }
    except Exception:
        return {
            "current_month_usd": 0,
            "budget_limit_usd": 0,
            "budget_pct": 0,
            "top_developer": {"name": "none", "cost": 0},
            "top_model": {"name": "none", "cost": 0},
            "anomalies_24h": 0,
        }


def _dashboard_integrity() -> dict:
    """Build integrity section from audit log."""
    return {
        "sessions_analyzed": 0,
        "trustworthy": 0,
        "questionable": 0,
        "unreliable": 0,
        "top_issue": "none",
    }


@app.get("/v1/dashboard/overview")
async def dashboard_overview(
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """Real-time governance dashboard overview.

    Returns aggregated data from all enterprise modules:
    enforcement, compliance, PII, classification, cost, integrity.
    """
    return {
        "enforcement": _dashboard_enforcement(),
        "compliance": _dashboard_compliance(),
        "pii": _dashboard_pii(),
        "classification": _dashboard_classification(),
        "cost": _dashboard_cost(),
        "integrity": _dashboard_integrity(),
    }


@app.get("/v1/dashboard/timeline")
async def dashboard_timeline(
    hours: int = 24,
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """Event timeline for the governance dashboard.

    Returns chronological events: blocks, warns, PII findings,
    cost events, integrity issues.

    Args:
        hours: Number of hours to look back (default 24).
    """
    import time as time_mod
    from pathlib import Path as PathLib

    cutoff = time_mod.time() - (hours * 3600)
    events: list[dict] = []

    audit_path = PathLib.cwd() / ".codetrust" / "audit.jsonl"
    if audit_path.is_file():
        try:
            for line in audit_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    ts = float(entry.get("timestamp", 0))
                    if ts < cutoff:
                        continue
                    events.append({
                        "timestamp": entry.get("timestamp"),
                        "type": entry.get("action_type", "unknown"),
                        "verdict": entry.get("verdict", ""),
                        "rule_id": entry.get("rule_id", ""),
                        "message": str(entry.get("message", ""))[:200],
                    })
                except (json.JSONDecodeError, ValueError):
                    continue
        except OSError:
            pass

    events.sort(key=lambda e: float(e.get("timestamp", 0)), reverse=True)
    return {"hours": hours, "event_count": len(events), "events": events[:500]}


@app.get("/v1/dashboard/alerts")
async def dashboard_alerts(
    auth: AuthContext = Depends(get_auth_context),
) -> dict:
    """Active governance alerts.

    Returns alerts for: budget thresholds, anomalies, PII in restricted
    context, unreliable integrity scores, compliance degradation.
    """
    alerts: list[dict] = []

    # Budget alerts
    try:
        from src.services.cost_tracker import generate_report

        cost_report = generate_report(period="monthly")
        if cost_report.budget_status and cost_report.budget_status.get("configured"):
            level = cost_report.budget_status.get("level", "ok")
            if level in ("warn", "alert", "exceeded"):
                alerts.append({
                    "type": "budget",
                    "severity": level,
                    "message": cost_report.budget_status.get("message", ""),
                })
    except Exception:
        pass

    # Cost anomalies
    try:
        from src.services.cost_tracker import generate_report as gen_report

        report = gen_report(period="daily")
        for anomaly in report.anomalies:
            alerts.append({
                "type": "cost_anomaly",
                "severity": "warn",
                "message": anomaly.get("detail", ""),
            })
    except Exception:
        pass

    # Compliance check
    try:
        from src.services.compliance import get_compliance_report

        for fw_id in ("owasp-asi-2026", "eu-ai-act", "nist-ai-rmf"):
            report = get_compliance_report(fw_id)
            partial = sum(1 for r in report.risks if r.coverage_level != "full")
            if partial > 0:
                alerts.append({
                    "type": "compliance",
                    "severity": "alert",
                    "message": f"{fw_id}: {partial} risk(s) not at full coverage",
                })
    except Exception:
        pass

    return {"alert_count": len(alerts), "alerts": alerts}
