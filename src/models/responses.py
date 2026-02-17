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


# --- Vulnerability scanning responses ---


class VulnerabilityItem(BaseModel):
    """A single known vulnerability."""

    model_config = ConfigDict(strict=True)

    id: str = Field(description="CVE/GHSA identifier")
    summary: str = Field(default="")
    severity: str = Field(default="UNKNOWN")
    fixed_version: str = Field(default="")
    aliases: list[str] = Field(default_factory=list)
    reference_url: str = Field(default="")


class PackageVulnResponse(BaseModel):
    """Vulnerability results for a single package."""

    model_config = ConfigDict(strict=True)

    package: str
    ecosystem: str
    version: str = Field(default="")
    is_vulnerable: bool = Field(default=False)
    vulnerabilities: list[VulnerabilityItem] = Field(default_factory=list)
    error: str = Field(default="")


class VulnScanApiResponse(BaseModel):
    """Aggregated vulnerability scan results."""

    model_config = ConfigDict(strict=True)

    total_packages: int
    vulnerable_count: int
    clean_count: int
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    results: list[PackageVulnResponse]
    latency_ms: int


# --- License compliance responses ---


class LicenseItem(BaseModel):
    """License info for a single package."""

    model_config = ConfigDict(strict=True)

    package: str
    ecosystem: str
    license_name: str = Field(default="")
    risk: str = Field(default="unknown")
    spdx_id: str = Field(default="")


class LicenseScanApiResponse(BaseModel):
    """Aggregated license scan results."""

    model_config = ConfigDict(strict=True)

    total_packages: int
    permissive_count: int
    weak_copyleft_count: int
    strong_copyleft_count: int
    network_copyleft_count: int
    unknown_count: int
    compliant: bool
    risk_packages: list[LicenseItem]
    all_licenses: list[LicenseItem]
    latency_ms: int


# --- Cross-file analysis responses ---


class CrossFileEdge(BaseModel):
    """An import edge in the dependency graph."""

    model_config = ConfigDict(strict=True)

    source_file: str
    target_file: str
    import_name: str
    line: int = Field(default=0)


class CrossFileScanApiResponse(BaseModel):
    """Cross-file import graph analysis results."""

    model_config = ConfigDict(strict=True)

    total_files: int
    total_edges: int
    circular_dependencies: list[list[str]]
    orphan_files: list[str]
    hub_files: list[dict[str, object]]
    latency_ms: int


# --- Auto-fix responses ---


class FixedFileResponse(BaseModel):
    """A file with applied fixes."""

    model_config = ConfigDict(strict=True)

    path: str
    fixes_applied: list[str]


class AutoFixApiResponse(BaseModel):
    """Auto-fix results."""

    model_config = ConfigDict(strict=True)

    files_fixed: list[FixedFileResponse]
    total_fixes: int
    pr_url: str = Field(default="")
    branch_name: str = Field(default="")
    error: str = Field(default="")


# --- Team management responses ---


class OrgResponse(BaseModel):
    """Organization info."""

    model_config = ConfigDict(strict=True)

    id: str
    name: str
    slug: str
    plan: str
    owner_id: str
    member_count: int
    created_at: str


class MemberResponse(BaseModel):
    """Team member info."""

    model_config = ConfigDict(strict=True)

    id: str
    user_id: str
    email: str
    name: str
    role: str
    created_at: str


class OrgPolicyResponse(BaseModel):
    """Organization policy settings."""

    model_config = ConfigDict(strict=True)

    max_severity_allowed: str
    require_license_compliance: bool
    blocked_licenses: list[str]
    require_vuln_scan: bool
    max_critical_vulns: int
    max_high_vulns: int


class PolicyCheckResponse(BaseModel):
    """Result of checking a scan against org policies."""

    model_config = ConfigDict(strict=True)

    passed: bool
    violations: list[str]
