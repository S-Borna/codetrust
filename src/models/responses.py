# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
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


class SbomGenerateResponse(BaseModel):
    """Response for generating CycloneDX and SPDX SBOM documents."""

    model_config = ConfigDict(strict=True)

    ecosystem: str
    document_name: str
    component_count: int
    cyclonedx_json: str
    spdx_json: str
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
    upgrade_hints: list[str] = Field(default_factory=list)


class AstScanResponse(BaseModel):
    """Response for AST analysis scan."""

    model_config = ConfigDict(strict=True)

    total_findings: int
    blocks: int
    warnings: int
    infos: int
    findings: list[Finding]
    verdict: str  # "PASS", "WARN", "BLOCK"


class SignatureScanResponse(BaseModel):
    """Response for function signature validation."""

    model_config = ConfigDict(strict=True)

    total_findings: int
    blocks: int
    warnings: int
    infos: int
    hallucinations_caught: int
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
    signature_validation: SignatureScanResponse | None = None
    sandbox_result: SandboxResponse | None = None
    import_verification: VerifyImportsResponse | None = None
    docker_verification: VerifyDockerResponse | None = None
    taint_scan: AstScanResponse | None = None
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


class DashboardBootstrapApiKeyResponse(BaseModel):
    """Response for dashboard API key bootstrap."""

    model_config = ConfigDict(strict=True)

    user_id: str
    plan: str
    api_key: str
    key_id: str
    prefix: str


class AdminAdoptionOverviewResponse(BaseModel):
    """Admin adoption metrics across users, keys, and recent activity."""

    model_config = ConfigDict(strict=True)

    total_users: int
    free_users: int
    pro_users: int
    enterprise_users: int
    total_api_keys: int
    active_api_keys: int
    active_users_30d: int
    total_scans_30d: int


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


class PublicStatsDistributionPyPIResponse(BaseModel):
    """PyPI distribution metrics."""

    model_config = ConfigDict(strict=True)

    downloads_today: int
    downloads_this_week: int
    downloads_this_month: int
    downloads_total: int


class PublicStatsDistributionMarketplaceResponse(BaseModel):
    """VS Code Marketplace distribution metrics."""

    model_config = ConfigDict(strict=True)

    installs: int
    downloads: int
    updates: int


class PublicStatsDistributionOpenVsxResponse(BaseModel):
    """Open VSX distribution metrics."""

    model_config = ConfigDict(strict=True)

    downloads: int


class PublicStatsDistributionResponse(BaseModel):
    """Distribution section of public telemetry."""

    model_config = ConfigDict(strict=True)

    pypi: PublicStatsDistributionPyPIResponse
    marketplace: PublicStatsDistributionMarketplaceResponse
    open_vsx: PublicStatsDistributionOpenVsxResponse


class PublicStatsScansBySourceResponse(BaseModel):
    """Scans grouped by source surface."""

    model_config = ConfigDict(strict=True)

    cli: int
    vscode: int
    mcp: int
    github_action: int
    cloud_api: int


class PublicStatsFindingsBySeverityResponse(BaseModel):
    """Findings grouped by severity."""

    model_config = ConfigDict(strict=True)

    BLOCK: int
    WARN: int
    INFO: int


class PublicStatsUsageResponse(BaseModel):
    """Usage section of public telemetry."""

    model_config = ConfigDict(strict=True)

    total_scans: int
    scans_today: int
    scans_last_hour: int
    scans_by_source: PublicStatsScansBySourceResponse
    total_files_scanned: int
    total_findings: int
    findings_by_severity: PublicStatsFindingsBySeverityResponse
    unique_installations_total: int
    unique_installations_today: int


class PublicStatsImpactResponse(BaseModel):
    """Impact section of public telemetry."""

    model_config = ConfigDict(strict=True)

    hallucinations_caught: int
    gateway_commands_blocked: int
    gateway_commands_allowed: int
    gateway_commands_warned: int
    imports_verified: int
    docker_images_verified: int
    fixes_applied: int
    fix_files_changed: int
    fix_lines_changed: int
    pr_gates_passed: int
    pr_gates_failed: int
    ci_runs_total: int
    ci_gates_passed: int
    ci_gates_failed: int
    categories: dict[str, "PublicStatsImpactCategoryResponse"]
    top_rules: list["PublicStatsImpactTopRuleResponse"]


class PublicStatsImpactCategoryResponse(BaseModel):
    """Single impact category stats entry."""

    model_config = ConfigDict(strict=True)

    label: str
    count: int
    last_seen: str | None


class PublicStatsImpactTopRuleResponse(BaseModel):
    """Single impact leaderboard entry."""

    model_config = ConfigDict(strict=True)

    rule: str
    count: int
    category: str


class PublicStatsTopRuleResponse(BaseModel):
    """Single top-triggered rule entry."""

    model_config = ConfigDict(strict=True)

    rule: str
    count: int


class PublicStatsTrendDistributionResponse(BaseModel):
    """Trust trend distribution."""

    model_config = ConfigDict(strict=True)

    improving: int
    stable: int
    degrading: int


class PublicStatsQualityResponse(BaseModel):
    """Quality section of public telemetry."""

    model_config = ConfigDict(strict=True)

    average_trust_score: int
    trend_distribution: PublicStatsTrendDistributionResponse
    top_rules_triggered: list[PublicStatsTopRuleResponse]


class GovernanceCoverageSurfaceResponse(BaseModel):
    """Coverage details for a single surface."""

    model_config = ConfigDict(strict=True)

    events: int
    enforced_events: int
    enforced: bool
    score: int
    status: str


class GovernanceCoverageResponse(BaseModel):
    """Governance coverage scorecard across product surfaces."""

    model_config = ConfigDict(strict=True)

    model: str
    overall_score: int
    active_surfaces: int
    surfaces: dict[str, GovernanceCoverageSurfaceResponse]


class PublicStatsNestedResponse(BaseModel):
    """Nested, schema-versioned public stats contract."""

    model_config = ConfigDict(strict=True)

    schema_version: str
    source_of_truth: str
    updated_at: str
    distribution: PublicStatsDistributionResponse
    usage: PublicStatsUsageResponse
    impact: PublicStatsImpactResponse
    quality: PublicStatsQualityResponse
    coverage: GovernanceCoverageResponse
    languages: dict[str, int]
    layers: dict[str, int]


class PublicStatsResponse(BaseModel):
    """Backward-compatible envelope for /v1/stats/public."""

    model_config = ConfigDict(strict=True)

    total_scans: int
    hallucinated_packages_prevented: int
    destructive_commands_blocked: int
    pypi_downloads_last_week: int
    pypi_downloads_total: int
    marketplace_installs: int
    marketplace_downloads: int
    openvsx_downloads: int
    stats: PublicStatsNestedResponse


class GovernancePolicyBundleResponse(BaseModel):
    """Tenant policy bundle with signed metadata."""

    model_config = ConfigDict(strict=True)

    bundle_id: str
    name: str
    target_tier: str
    description: str
    policy: dict[str, object]
    signature: str
    issued_at: str
    version: str


class GovernancePolicySnapshotResponse(BaseModel):
    """Signed governance snapshot for audit and reproducibility."""

    model_config = ConfigDict(strict=True)

    snapshot_id: str
    bundle_id: str
    policy: dict[str, object]
    signature: str
    issued_at: str
    version: str
    session_id: str
    policy_hash: str
    audit_logged: bool


class GovernancePolicySimulationOutcomeResponse(BaseModel):
    """Single simulated governance decision for a command."""

    model_config = ConfigDict(strict=True)

    command: str
    verdict: str
    rule_id: str
    message: str


class GovernancePolicySimulationResponse(BaseModel):
    """Simulation results for a policy bundle over sample commands."""

    model_config = ConfigDict(strict=True)

    bundle_id: str
    outcomes: list[GovernancePolicySimulationOutcomeResponse]


class GovernancePolicyIntegrityResponse(BaseModel):
    """Policy integrity posture details."""

    model_config = ConfigDict(strict=True)

    verdict: str
    rule_id: str
    policy_hash: str


class GovernanceWorkspacePostureResponse(BaseModel):
    """Posture summary for a single workspace in multi-workspace view."""

    model_config = ConfigDict(strict=True)

    workspace_id: str = Field(..., description="Unique workspace identifier")
    workspace_name: str = Field(..., description="Human-readable workspace name")
    agent_id: str = Field(default="unknown", description="Last-seen agent ID")
    enabled: bool = Field(default=False, description="Governance engine enabled")
    mode: str = Field(default="audit", description="Governance mode")
    control_plane_ready: bool = Field(default=False)
    policy_hash: str = Field(default="", description="Current policy manifest hash")
    policy_verdict: str = Field(default="UNKNOWN", description="Policy integrity verdict")
    pending_approvals: int = Field(default=0)
    active_exceptions: int = Field(default=0)
    drift_count: int = Field(default=0, description="Number of drift violations")
    last_seen_at: float = Field(default=0.0, description="Unix timestamp of last telemetry")


class GovernanceWorkspaceAggregateResponse(BaseModel):
    """Aggregated multi-workspace governance overview."""

    model_config = ConfigDict(strict=True)

    total_workspaces: int = Field(default=0)
    healthy_count: int = Field(default=0, description="Workspaces with zero drift")
    drifted_count: int = Field(default=0, description="Workspaces with drift > 0")
    disabled_count: int = Field(default=0, description="Workspaces with governance off")
    total_pending_approvals: int = Field(default=0)
    total_active_exceptions: int = Field(default=0)
    workspaces: list[GovernanceWorkspacePostureResponse] = Field(default_factory=list)


class GovernanceUnifiedSessionResponse(BaseModel):
    """Unified session token that spans IDE, CLI, CI, and API surfaces."""

    model_config = ConfigDict(strict=True)

    session_token: str = Field(..., description="Unified cross-surface session token")
    surfaces: list[str] = Field(
        default_factory=list,
        description="Surfaces bound to this token (ide, cli, ci, api)",
    )
    issued_at: float = Field(..., description="Unix timestamp when token was issued")
    expires_at: float = Field(..., description="Unix timestamp when token expires")
    agent_id: str = Field(default="unknown")
    workspace_id: str = Field(default="")
    audit_chain_id: str = Field(
        ...,
        description="Stable chain ID linking all audit entries from this session",
    )


class GovernanceSessionStatusResponse(BaseModel):
    """Status of a unified session token."""

    model_config = ConfigDict(strict=True)

    valid: bool
    session_token: str
    surfaces: list[str]
    issued_at: float
    expires_at: float
    remaining_seconds: float
    agent_id: str
    workspace_id: str
    audit_chain_id: str


class GovernancePostureResponse(BaseModel):
    """Machine-readable governance posture for control-plane consumers."""

    model_config = ConfigDict(strict=True)

    session_id: str
    agent_id: str
    mode: str
    enabled: bool
    trusted_execution_mode: bool
    deny_native_execution: bool
    require_allow_reason: bool
    session_binding_enforced: bool
    anti_bypass_enabled: bool
    control_plane_ready: bool
    policy_integrity: GovernancePolicyIntegrityResponse
    pending_approvals: int
    active_exceptions: int


class GovernancePendingApprovalResponse(BaseModel):
    """A pending governance approval request."""

    model_config = ConfigDict(strict=True)

    request_id: str
    rule_id: str
    action_type: str
    original_action: str
    action_fingerprint: str
    requested_at: float
    expires_at: float
    session_id: str
    agent_id: str


class GovernanceExceptionResponse(BaseModel):
    """An active or revoked governance exception."""

    model_config = ConfigDict(strict=True)

    exception_id: str
    rule_id: str
    action_type: str
    action_fingerprint: str
    reason: str
    approver: str
    approver_role: str
    created_at: float
    expires_at: float
    revoked_at: float
    revoked_by: str
    session_id: str
    agent_id: str


class GovernanceApproveResponse(BaseModel):
    """Response after approving a governance action."""

    model_config = ConfigDict(strict=True)

    approved: bool
    exception_id: str
    expires_at: float


class GovernanceAuditEntryResponse(BaseModel):
    """A single governance audit log entry."""

    model_config = ConfigDict(strict=True)

    timestamp: float
    action_type: str
    verdict: str
    rule_id: str
    original_action: str
    message: str
    agent_id: str
    session_id: str


class GovernanceAuditStatsResponse(BaseModel):
    """Statistics for governance audit entries."""

    model_config = ConfigDict(strict=True)

    total: int
    by_verdict: dict[str, int]
    by_action_type: dict[str, int]
    top_rules: list[dict[str, object]]


class GovernanceAuditResponse(BaseModel):
    """Full governance audit response with entries and stats."""

    model_config = ConfigDict(strict=True)

    entries: list[GovernanceAuditEntryResponse]
    stats: GovernanceAuditStatsResponse


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


class GitHubAppWebhookResponse(BaseModel):
    """Response for GitHub App webhook processing."""

    model_config = ConfigDict(strict=True)

    processed: bool
    event: str
    action: str
    reason: str
    comment_url: str = ""
    total_findings: int = 0
    blocks: int = 0
    warnings: int = 0
    infos: int = 0


class RateLimitError(BaseModel):
    """Response when rate limit is exceeded (429)."""

    model_config = ConfigDict(strict=True)

    error: str = "rate_limit_exceeded"


class FeedbackReportResponse(BaseModel):
    """Response for user-submitted feedback reports."""

    model_config = ConfigDict(strict=True)

    status: str
    report_id: str


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
