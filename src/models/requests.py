# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Pydantic request models for the CodeTrust API and MCP server."""

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import Language


class DockerImageInput(BaseModel):
    """Input for a single Docker image to verify."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    image: str = Field(..., max_length=200, description="Image name, e.g. 'python' or 'nginx'")
    tag: str = Field(default="latest", max_length=200, description="Tag, e.g. '3.12-slim'")


class VerifyImportsRequest(BaseModel):
    """Request to verify package imports exist in registries."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    language: Language = Field(..., strict=False)
    imports: list[str] = Field(..., min_length=1, max_length=200)
    requirements: str = Field(
        default="",
        max_length=100_000,
        description="Raw requirements.txt / package.json content for version pinning",
    )


class VerifyDockerRequest(BaseModel):
    """Request to verify Docker images and tags."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    images: list[DockerImageInput] = Field(..., min_length=1, max_length=50)


class VerifyApiCallsRequest(BaseModel):
    """Request to verify API endpoints are reachable."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    urls: list[str] = Field(..., min_length=1, max_length=50)
    method: str = Field(default="HEAD", pattern="^(GET|HEAD|OPTIONS)$")


class StaticScanRequest(BaseModel):
    """Request for static anti-pattern scan."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled", max_length=500)
    language: Language | None = Field(default=None, strict=False)


class AstScanRequest(BaseModel):
    """Request for AST-based code analysis."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled", max_length=500)
    language: Language = Field(..., strict=False, description="Language is required for AST parsing")
    max_nesting: int = Field(default=4, ge=1, le=20)
    complexity_threshold: int = Field(default=10, ge=1, le=100)


class SandboxRequest(BaseModel):
    """Request to execute code in an isolated sandbox container."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=0, max_length=500_000)
    language: Language = Field(..., strict=False, description="Language determines sandbox image")
    timeout: int = Field(default=10, ge=1, le=30, description="Max seconds")
    filename: str = Field(default="untitled", max_length=500)


class SignatureScanRequest(BaseModel):
    """Request for function signature validation (hallucination detection)."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled", max_length=500)
    language: Language = Field(..., strict=False, description="Language for signature lookup")


class DeepScanRequest(BaseModel):
    """Request for full deep scan (all layers)."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled", max_length=500)
    language: Language | None = Field(default=None, strict=False)
    verify_imports: bool = Field(default=True)
    verify_signatures: bool = Field(default=True)
    verify_docker: bool = Field(default=False)
    sandbox_run: bool = Field(default=False)
    dockerfile_content: str = Field(default="", max_length=100_000)
    requirements_content: str = Field(default="", max_length=100_000)


# --- Vulnerability scanning ---


class VulnScanRequest(BaseModel):
    """Request to scan packages for known vulnerabilities (CVE/GHSA)."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    language: Language = Field(..., strict=False)
    packages: list[str] = Field(..., min_length=1, max_length=200)
    versions: dict[str, str] = Field(
        default_factory=dict,
        description="Optional package -> version mapping for precise matching",
    )


# --- License compliance ---


class LicenseScanRequest(BaseModel):
    """Request to check package licenses for compliance."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    language: Language = Field(..., strict=False)
    packages: list[str] = Field(..., min_length=1, max_length=200)


# --- Cross-file analysis ---


class CrossFileScanRequest(BaseModel):
    """Request for cross-file import graph analysis."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    files: dict[str, str] = Field(
        ...,
        min_length=1,
        description="Map of filename -> file content",
    )


# --- Auto-fix ---


class AutoFixRequest(BaseModel):
    """Request to apply auto-fix recipes to code."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    files: dict[str, str] = Field(
        ...,
        min_length=1,
        description="Map of filepath -> file content",
    )
    languages: dict[str, str] = Field(
        default_factory=dict,
        description="Optional map of filepath -> language (auto-detected if omitted)",
    )
    recipes: list[str] = Field(
        default_factory=list,
        description="Recipe names to apply (empty = all)",
    )
    create_pr: bool = Field(
        default=False,
        description="If True, create a GitHub PR with fixes",
    )
    github_owner: str = Field(default="", max_length=100)
    github_repo: str = Field(default="", max_length=200)
    github_base_branch: str = Field(default="main", max_length=200)


# --- Team Management ---


class CreateOrgRequest(BaseModel):
    """Request to create a new organization."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    name: str = Field(..., min_length=1, max_length=200)


class AddMemberRequest(BaseModel):
    """Request to add a member to an organization."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    user_id: str = Field(..., min_length=1, max_length=32)
    role: str = Field(default="member", pattern="^(owner|admin|member|viewer)$")


class UpdateMemberRoleRequest(BaseModel):
    """Request to update a member's role."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    role: str = Field(..., pattern="^(owner|admin|member|viewer)$")


class UpdateOrgPolicyRequest(BaseModel):
    """Request to update organization policy settings."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    max_severity_allowed: str = Field(
        default="BLOCK", pattern="^(INFO|WARN|BLOCK)$",
    )
    require_license_compliance: bool = Field(default=False)
    blocked_licenses: list[str] = Field(default_factory=list)
    require_vuln_scan: bool = Field(default=False)
    max_critical_vulns: int = Field(default=0, ge=0)
    max_high_vulns: int = Field(default=0, ge=0)


# --- MCP-specific input models (for local server) ---


class PreActionInput(BaseModel):
    """Validates the plan before any code is written."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    task_description: str = Field(..., min_length=5, max_length=2000)
    proposed_stack: str | None = None
    proposed_files: list[str] | None = None
    has_user_specified_stack: bool = False
    has_user_specified_structure: bool = False


class MidActionInput(BaseModel):
    """Checks code quality during implementation."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=0)
    filename: str = Field(default="untitled")
    language: Language | None = Field(default=None, strict=False)
    verify_imports: bool = Field(
        default=False,
        description="If True, also verify imports against registries (requires API key)",
    )


class PostActionInput(BaseModel):
    """Validates the completed work against enterprise standards."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    repo_root: str = Field(..., min_length=1)
    task_description: str = Field(..., min_length=5)
    files_changed: list[str] | None = None
    verify_imports: bool = Field(default=False)


class FullScanInput(BaseModel):
    """Runs all layers in one call."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    repo_root: str = Field(..., min_length=1)
    task_description: str = Field(..., min_length=5)
    proposed_stack: str | None = None
    has_user_specified_stack: bool = False
    files_to_scan: list[str] | None = None
    verify_imports: bool = Field(default=False)


# --- Dashboard request models ---


class CreateApiKeyRequest(BaseModel):
    """Request to create a new API key."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    name: str = Field(default="Default", max_length=100)


class ScanHistoryQuery(BaseModel):
    """Query parameters for scan history pagination."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    scan_type: str | None = Field(default=None)


class UsageQuery(BaseModel):
    """Query parameters for usage statistics."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    days: int = Field(default=30, ge=1, le=365)


class CheckoutRequest(BaseModel):
    """Request to create a Stripe checkout session."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    plan: str = Field(..., pattern="^(pro|enterprise)$")


class GithubAuthRequest(BaseModel):
    """Request to exchange a GitHub OAuth code for a JWT."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=1, max_length=200)


class RefreshRequest(BaseModel):
    """Request to refresh an expiring JWT token."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    token: str = Field(..., min_length=1, max_length=4096)


class OIDCCallbackRequest(BaseModel):
    """Request to exchange an OIDC authorization code for a JWT."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=1, max_length=2000)
    state: str = Field(default="", max_length=500)


# --- Anonymous telemetry ---


class TelemetryEventRequest(BaseModel):
    """Anonymous telemetry event.

    This payload must never include user PII, file paths, repo URLs, or code.
    It is designed to be aggregated into public stats.
    """

    model_config = ConfigDict(strict=True, str_strip_whitespace=True, extra="forbid")

    instance_id: str = Field(
        ...,
        min_length=16,
        max_length=64,
        pattern=r"^[a-f0-9]+$",
        description="Anonymous client instance identifier (random, not user-linked)",
    )
    client: str = Field(
        ...,
        pattern=r"^(cli|vscode|action|mcp)$",
        description="Telemetry source",
    )
    client_version: str = Field(default="", max_length=32)
    schema_version: int = Field(default=1, ge=1, le=10)

    event_type: str = Field(
        ...,
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9_.:-]+$",
        description="Event type identifier, e.g. scan_completed",
    )

    scan_type: str = Field(default="", max_length=30)
    verdict: str = Field(default="", max_length=10)
    language: str = Field(default="", max_length=20)

    delta_scans: int = Field(default=0, ge=0, le=10_000)
    delta_findings_total: int = Field(default=0, ge=0, le=10_000_000)
    delta_hallucinated_packages_prevented: int = Field(default=0, ge=0, le=10_000)
    delta_destructive_commands_blocked: int = Field(default=0, ge=0, le=10_000)
