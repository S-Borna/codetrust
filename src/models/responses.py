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


class DeepScanResponse(BaseModel):
    """Response for /v1/scan/deep — combines all layers."""

    model_config = ConfigDict(strict=True)

    static_scan: StaticScanResponse
    ast_scan: AstScanResponse | None = None
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
