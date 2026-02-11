"""Pydantic response models for the CodeTrust API."""

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import Registry, Severity, VerifyStatus


class Finding(BaseModel):
    """Single verification finding."""

    model_config = ConfigDict(strict=True)

    rule_id: str = Field(..., description="Machine-readable rule identifier")
    severity: Severity
    message: str = Field(..., description="Human-readable description")
    file: str = Field(default="", description="File path if applicable")
    line: int = Field(default=0, description="Line number if applicable")
    suggestion: str = Field(default="", description="Suggested fix")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class PackageResult(BaseModel):
    """Result for a single package verification."""

    model_config = ConfigDict(strict=True)

    package: str
    registry: Registry
    status: VerifyStatus
    severity: Severity
    requested_version: str = Field(default="")
    latest_version: str = Field(default="")
    message: str = Field(default="")
    suggestion: str = Field(default="")
    deprecated_since: str = Field(default="")
    cached: bool = Field(default=False)


class DockerImageResult(BaseModel):
    """Result for a Docker image/tag verification."""

    model_config = ConfigDict(strict=True)

    image: str
    tag: str
    status: VerifyStatus
    severity: Severity
    message: str = Field(default="")
    suggestion: str = Field(default="")
    available_tags: list[str] = Field(default_factory=list, max_length=10)


class VerifyImportsResponse(BaseModel):
    """Response for /v1/verify/imports."""

    model_config = ConfigDict(strict=True)

    verified: int
    failed: int
    warnings: int
    results: list[PackageResult]
    latency_ms: int
    cached_ratio: float = Field(ge=0.0, le=1.0)


class VerifyDockerResponse(BaseModel):
    """Response for /v1/verify/dockerfile."""

    model_config = ConfigDict(strict=True)

    verified: int
    failed: int
    results: list[DockerImageResult]
    latency_ms: int


class StaticScanResponse(BaseModel):
    """Response for static analysis scan."""

    model_config = ConfigDict(strict=True)

    total_findings: int
    blocks: int
    warnings: int
    infos: int
    findings: list[Finding]
    verdict: str  # "PASS", "WARN", "BLOCK"


class AstScanResponse(BaseModel):
    """Response for AST analysis scan."""

    model_config = ConfigDict(strict=True)

    total_findings: int
    blocks: int
    warnings: int
    infos: int
    findings: list[Finding]
    verdict: str  # "PASS", "WARN", "BLOCK"


class SandboxResponse(BaseModel):
    """Response for sandbox code execution."""

    model_config = ConfigDict(strict=True)

    exit_code: int
    stdout: str = Field(default="")
    stderr: str = Field(default="")
    timed_out: bool = Field(default=False)
    error: str = Field(default="", description="Service-level error if Docker unavailable")
    latency_ms: int = Field(default=0)


class DeepScanResponse(BaseModel):
    """Response for /v1/scan/deep — combines all layers."""

    model_config = ConfigDict(strict=True)

    static_scan: StaticScanResponse
    ast_scan: AstScanResponse | None = None
    sandbox_result: SandboxResponse | None = None
    import_verification: VerifyImportsResponse | None = None
    docker_verification: VerifyDockerResponse | None = None
    overall_verdict: str  # "PASS", "WARN", "BLOCK"
    total_findings: int
    latency_ms: int


class HealthResponse(BaseModel):
    """Response for health check endpoint."""

    model_config = ConfigDict(strict=True)

    status: str = "ok"
    version: str
    cache_connected: bool


# --- Dashboard response models ---


class ApiKeyResponse(BaseModel):
    """API key info returned to the user (never includes the hash)."""

    model_config = ConfigDict(strict=True)

    id: str
    name: str
    prefix: str
    is_revoked: bool
    created_at: str
    last_used_at: str = ""


class ApiKeyCreatedResponse(BaseModel):
    """Response when a new API key is created (includes raw key once)."""

    model_config = ConfigDict(strict=True)

    key: str
    id: str
    name: str
    prefix: str


class ScanLogResponse(BaseModel):
    """Single scan log entry for history view."""

    model_config = ConfigDict(strict=True)

    id: str
    scan_type: str
    verdict: str
    findings_count: int
    language: str = ""
    filename: str = ""
    latency_ms: int = 0
    created_at: str


class ScanHistoryResponse(BaseModel):
    """Paginated scan history."""

    model_config = ConfigDict(strict=True)

    scans: list[ScanLogResponse]
    page: int
    per_page: int
    total: int


class UsageDayResponse(BaseModel):
    """Single day of usage data."""

    model_config = ConfigDict(strict=True)

    date: str
    scan_count: int
    findings_total: int
    avg_latency_ms: float


class UsageStatsResponse(BaseModel):
    """Usage statistics for the requested period."""

    model_config = ConfigDict(strict=True)

    days: list[UsageDayResponse]
    total_scans: int
    period_days: int


class UserProfileResponse(BaseModel):
    """User profile info for the dashboard."""

    model_config = ConfigDict(strict=True)

    id: str
    email: str
    name: str
    avatar_url: str
    plan: str
    created_at: str
    daily_limit: int
    daily_usage: int


class RevokeResponse(BaseModel):
    """Response when an API key is revoked."""

    model_config = ConfigDict(strict=True)

    revoked: bool


class UrlResponse(BaseModel):
    """Response containing a single URL (billing checkout/portal)."""

    model_config = ConfigDict(strict=True)

    url: str


class StatusResponse(BaseModel):
    """Generic status response."""

    model_config = ConfigDict(strict=True)

    status: str


class TokenResponse(BaseModel):
    """Response containing JWT token and user info."""

    model_config = ConfigDict(strict=True)

    token: str
    user_id: str
    plan: str
    expires_in_minutes: int


class RateLimitError(BaseModel):
    """Response when rate limit is exceeded (429)."""

    model_config = ConfigDict(strict=True)

    error: str = "rate_limit_exceeded"
    current_usage: int
    daily_limit: int
    plan: str
    message: str
