"""Pydantic request models for the CodeTrust API and MCP server."""

from pydantic import BaseModel, ConfigDict, Field

from src.models.enums import Language


class DockerImageInput(BaseModel):
    """Input for a single Docker image to verify."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    image: str = Field(..., description="Image name, e.g. 'python' or 'nginx'")
    tag: str = Field(default="latest", description="Tag, e.g. '3.12-slim'")


class VerifyImportsRequest(BaseModel):
    """Request to verify package imports exist in registries."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    language: Language = Field(..., strict=False)
    imports: list[str] = Field(..., min_length=1, max_length=200)
    requirements: str = Field(
        default="",
        description="Raw requirements.txt / package.json content for version pinning",
    )


class VerifyDockerRequest(BaseModel):
    """Request to verify Docker images and tags."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    images: list[DockerImageInput] = Field(..., min_length=1, max_length=50)


class VerifyApiCallsRequest(BaseModel):
    """Request to verify API endpoints are reachable."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    urls: list[str] = Field(..., min_length=1, max_length=50)
    method: str = Field(default="HEAD", pattern="^(GET|HEAD|OPTIONS)$")


class StaticScanRequest(BaseModel):
    """Request for static anti-pattern scan."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled")
    language: Language | None = Field(default=None, strict=False)


class AstScanRequest(BaseModel):
    """Request for AST-based code analysis."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled")
    language: Language = Field(..., strict=False, description="Language is required for AST parsing")
    max_nesting: int = Field(default=4, ge=1, le=20)
    complexity_threshold: int = Field(default=10, ge=1, le=100)


class SandboxRequest(BaseModel):
    """Request to execute code in an isolated sandbox container."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=0, max_length=500_000)
    language: Language = Field(..., strict=False, description="Language determines sandbox image")
    timeout: int = Field(default=10, ge=1, le=30, description="Max seconds")
    filename: str = Field(default="untitled")


class DeepScanRequest(BaseModel):
    """Request for full deep scan (all layers)."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=0, max_length=500_000)
    filename: str = Field(default="untitled")
    language: Language | None = Field(default=None, strict=False)
    verify_imports: bool = Field(default=True)
    verify_docker: bool = Field(default=False)
    sandbox_run: bool = Field(default=False)
    dockerfile_content: str = Field(default="")
    requirements_content: str = Field(default="")


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

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    name: str = Field(default="Default", max_length=100)


class ScanHistoryQuery(BaseModel):
    """Query parameters for scan history pagination."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    scan_type: str | None = Field(default=None)


class UsageQuery(BaseModel):
    """Query parameters for usage statistics."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    days: int = Field(default=30, ge=1, le=365)


class CheckoutRequest(BaseModel):
    """Request to create a Stripe checkout session."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    plan: str = Field(..., pattern="^(pro|enterprise)$")


class GithubAuthRequest(BaseModel):
    """Request to exchange a GitHub OAuth code for a JWT."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=1, max_length=200)


class RefreshRequest(BaseModel):
    """Request to refresh an expiring JWT token."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    token: str = Field(..., min_length=1)


class OIDCCallbackRequest(BaseModel):
    """Request to exchange an OIDC authorization code for a JWT."""

    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=1, max_length=2000)
    state: str = Field(default="", max_length=500)
