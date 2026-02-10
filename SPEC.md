# SPEC.md — CodeTrust Technical Specification

## 1. Enums

```python
# src/models/enums.py
from enum import StrEnum

class Severity(StrEnum):
    BLOCK = "BLOCK"    # Must fix before proceeding
    WARN = "WARN"      # Should fix, not blocking
    INFO = "INFO"      # Suggestion/improvement

class VerifyStatus(StrEnum):
    VERIFIED = "VERIFIED"         # Exists and valid
    NOT_FOUND = "NOT_FOUND"       # Does not exist in registry
    DEPRECATED = "DEPRECATED"     # Exists but deprecated
    VERSION_MISMATCH = "VERSION_MISMATCH"  # Package exists, version doesn't
    TIMEOUT = "TIMEOUT"           # Registry didn't respond
    ERROR = "ERROR"               # Unexpected error
    SKIPPED = "SKIPPED"           # Not checkable (e.g. local package)

class Language(StrEnum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"

class Registry(StrEnum):
    PYPI = "pypi"
    NPM = "npm"
    CRATES = "crates"
    GO_PROXY = "go_proxy"
    DOCKER_HUB = "docker_hub"
    GHCR = "ghcr"
```

## 2. Response Models

```python
# src/models/responses.py
from pydantic import BaseModel, ConfigDict, Field

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

class DeepScanResponse(BaseModel):
    """Response for /v1/scan/deep — combines all layers."""
    model_config = ConfigDict(strict=True)

    static_scan: StaticScanResponse
    import_verification: VerifyImportsResponse | None = None
    docker_verification: VerifyDockerResponse | None = None
    overall_verdict: str  # "PASS", "WARN", "BLOCK"
    total_findings: int
    latency_ms: int

class HealthResponse(BaseModel):
    model_config = ConfigDict(strict=True)

    status: str = "ok"
    version: str
    cache_connected: bool
```

## 3. Request Models

```python
# src/models/requests.py
from pydantic import BaseModel, ConfigDict, Field

class VerifyImportsRequest(BaseModel):
    """Request to verify package imports exist in registries."""
    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    language: Language
    imports: list[str] = Field(..., min_length=1, max_length=200)
    requirements: str = Field(
        default="",
        description="Raw requirements.txt / package.json content for version pinning"
    )

class VerifyDockerRequest(BaseModel):
    """Request to verify Docker images and tags."""
    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    images: list[DockerImageInput] = Field(..., min_length=1, max_length=50)

class DockerImageInput(BaseModel):
    model_config = ConfigDict(strict=True)

    image: str = Field(..., description="Image name, e.g. 'python' or 'nginx'")
    tag: str = Field(default="latest", description="Tag, e.g. '3.12-slim'")

class VerifyApiCallsRequest(BaseModel):
    """Request to verify API endpoints are reachable."""
    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    urls: list[str] = Field(..., min_length=1, max_length=50)
    method: str = Field(default="HEAD", pattern="^(GET|HEAD|OPTIONS)$")

class StaticScanRequest(BaseModel):
    """Request for static anti-pattern scan."""
    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=1, max_length=500_000)
    filename: str = Field(default="untitled")
    language: Language | None = None

class DeepScanRequest(BaseModel):
    """Request for full deep scan (all layers)."""
    model_config = ConfigDict(strict=True, str_strip_whitespace=True)

    code: str = Field(..., min_length=1, max_length=500_000)
    filename: str = Field(default="untitled")
    language: Language | None = None
    verify_imports: bool = Field(default=True)
    verify_docker: bool = Field(default=False)
    dockerfile_content: str = Field(default="")
    requirements_content: str = Field(default="")

# --- MCP-specific input models (for local server) ---

class PreActionInput(BaseModel):
    """Validates the plan before any code is written."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    task_description: str = Field(..., min_length=5, max_length=2000)
    proposed_stack: str | None = None
    proposed_files: list[str] | None = None
    has_user_specified_stack: bool = False
    has_user_specified_structure: bool = False

class MidActionInput(BaseModel):
    """Checks code quality during implementation."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(..., min_length=1)
    filename: str = Field(default="untitled")
    language: Language | None = None
    verify_imports: bool = Field(
        default=False,
        description="If True, also verify imports against registries (requires API key)"
    )

class PostActionInput(BaseModel):
    """Validates the completed work against enterprise standards."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    repo_root: str = Field(..., min_length=1)
    task_description: str = Field(..., min_length=5)
    files_changed: list[str] | None = None
    verify_imports: bool = Field(default=False)

class FullScanInput(BaseModel):
    """Runs all layers in one call."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    repo_root: str = Field(..., min_length=1)
    task_description: str = Field(..., min_length=5)
    proposed_stack: str | None = None
    has_user_specified_stack: bool = False
    files_to_scan: list[str] | None = None
    verify_imports: bool = Field(default=False)
```

## 4. Configuration

```python
# src/config.py
from pydantic import ConfigDict
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    """All configuration via environment variables prefixed with CODETRUST_."""
    model_config = ConfigDict(env_prefix="CODETRUST_")

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    version: str = "1.0.0"

    # --- Auth ---
    api_key: str = ""  # Empty = no auth required (local dev)

    # --- Redis ---
    redis_url: str = "redis://localhost:6379"
    redis_enabled: bool = True

    # --- Cache TTLs (seconds) ---
    cache_ttl_package_exists: int = 86400       # 24h — package existence rarely changes
    cache_ttl_package_version: int = 3600       # 1h — new versions release frequently
    cache_ttl_docker_tag: int = 86400           # 24h
    cache_ttl_api_endpoint: int = 1800          # 30min — endpoints can change
    cache_ttl_not_found: int = 3600             # 1h — retry not-found after 1h

    # --- HTTP ---
    http_timeout: float = 10.0                  # seconds
    http_max_connections: int = 50
    http_max_keepalive: int = 20

    # --- Registry URLs ---
    pypi_url: str = "https://pypi.org/pypi/{package}/json"
    pypi_version_url: str = "https://pypi.org/pypi/{package}/{version}/json"
    npm_url: str = "https://registry.npmjs.org/{package}"
    crates_url: str = "https://crates.io/api/v1/crates/{package}"
    go_proxy_url: str = "https://proxy.golang.org/{package}/@latest"
    docker_hub_tags_url: str = "https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}"
    docker_hub_list_url: str = "https://hub.docker.com/v2/repositories/library/{image}/tags?page_size=100"

    # --- Rate Limits ---
    free_tier_daily_limit: int = 100
    pro_tier_daily_limit: int = 10_000

settings = Settings()
```

## 5. Service Interfaces

### 5a. Cache Service

```python
# src/services/cache.py
import redis.asyncio as redis
import json
import structlog

logger = structlog.get_logger()

class CacheService:
    """Redis-backed cache with TTL support. Gracefully degrades if Redis unavailable."""

    def __init__(self, redis_url: str) -> None: ...

    async def connect(self) -> None:
        """Initialize Redis connection pool."""

    async def disconnect(self) -> None:
        """Close Redis connection pool."""

    async def get(self, key: str) -> str | None:
        """Get cached value. Returns None on miss or Redis error."""

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Set cached value with TTL. Silently fails if Redis unavailable."""

    async def get_json(self, key: str) -> dict | None:
        """Get and deserialize JSON. Returns None on miss."""

    async def set_json(self, key: str, data: dict, ttl: int) -> None:
        """Serialize and cache JSON with TTL."""

    def _make_key(self, namespace: str, identifier: str) -> str:
        """Build cache key: 'codetrust:{namespace}:{identifier}'."""
        return f"codetrust:{namespace}:{identifier}"

    async def is_connected(self) -> bool:
        """Check if Redis is reachable."""
```

### 5b. Registry Service (CORE — Layer 2)

```python
# src/services/registry.py
import httpx
import structlog

logger = structlog.get_logger()

class RegistryService:
    """Verifies packages exist in language registries (PyPI, npm, crates.io, Go)."""

    def __init__(self, cache: CacheService, http_client: httpx.AsyncClient) -> None: ...

    async def verify_python_package(
        self, package: str, version: str = ""
    ) -> PackageResult:
        """
        Check if a Python package exists on PyPI.
        
        Flow:
        1. Check cache: codetrust:pypi:{package} or codetrust:pypi:{package}:{version}
        2. If miss: GET https://pypi.org/pypi/{package}/json
        3. If 200: package exists → check version if specified
        4. If 404: NOT_FOUND → run fuzzy match for suggestion
        5. Cache result with appropriate TTL
        6. Return PackageResult
        """

    async def verify_npm_package(
        self, package: str, version: str = ""
    ) -> PackageResult:
        """
        Check if an npm package exists on registry.npmjs.org.
        
        Flow: Same as Python but against npm registry.
        NPM returns 200 with full metadata, or 404.
        Version check: metadata["versions"][version] exists.
        """

    async def verify_packages(
        self, language: Language, packages: list[str], requirements: str = ""
    ) -> list[PackageResult]:
        """
        Verify a batch of packages concurrently.
        
        1. Parse requirements string to extract version pins
        2. Fan out verification calls with asyncio.gather
        3. Collect and return all results
        
        Uses asyncio.Semaphore(20) to limit concurrent registry calls.
        """

    async def _check_pypi(self, package: str) -> dict | None:
        """Raw PyPI API call. Returns JSON response or None on 404/error."""

    async def _check_npm(self, package: str) -> dict | None:
        """Raw npm registry call. Returns JSON response or None on 404/error."""

    def _parse_requirements(self, content: str) -> dict[str, str]:
        """
        Parse requirements.txt into {package: version} dict.
        Handles: ==, >=, ~=, <=, pins with extras like package[extra]==1.0
        Ignores: comments, blank lines, -r includes, git+ URLs
        """

    def _suggest_similar(self, package: str, known_packages: list[str]) -> str:
        """
        Fuzzy match against known popular packages.
        Uses rapidfuzz or difflib.get_close_matches.
        Returns suggestion string or empty.
        """
```

### 5c. Docker Verification Service

```python
# src/services/docker_verify.py

class DockerVerifyService:
    """Verifies Docker images and tags exist on Docker Hub."""

    def __init__(self, cache: CacheService, http_client: httpx.AsyncClient) -> None: ...

    async def verify_image_tag(self, image: str, tag: str) -> DockerImageResult:
        """
        Check if image:tag exists on Docker Hub.
        
        Flow:
        1. Cache check: codetrust:docker:{image}:{tag}
        2. GET https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}
        3. If 200: VERIFIED
        4. If 404: NOT_FOUND → fetch available tags for suggestion
        5. Cache result
        """

    async def verify_images(self, images: list[DockerImageInput]) -> list[DockerImageResult]:
        """Verify batch of images concurrently."""

    async def _fetch_available_tags(self, image: str, limit: int = 10) -> list[str]:
        """Fetch most popular/recent tags for an image to suggest alternatives."""

    def _parse_dockerfile(self, content: str) -> list[DockerImageInput]:
        """
        Extract FROM statements from Dockerfile content.
        Handles: multi-stage builds, ARG substitution, AS aliases.
        Returns list of DockerImageInput.
        """
```

### 5d. Static Analyzer (Layer 1 — migrated from Guardian v1)

```python
# src/services/static_analyzer.py

class StaticAnalyzer:
    """Regex-based anti-pattern detection. Runs locally, no network calls."""

    def __init__(self) -> None: ...

    def scan_code(self, code: str, filename: str = "") -> list[Finding]:
        """Run all anti-pattern rules against code string."""

    def check_repo_structure(self, root: str) -> list[Finding]:
        """Check repo for required/recommended files and structure issues."""

    def build_report(self, findings: list[Finding], title: str) -> str:
        """Format findings into human-readable markdown report."""
```

## 6. FastAPI Endpoints

```python
# src/api.py
from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

app = FastAPI(
    title="CodeTrust API",
    version="1.0.0",
    description="AI code verification platform",
)

# --- Auth ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(key: str | None = Security(api_key_header)) -> str:
    """Validate API key. Skip if CODETRUST_API_KEY is empty (local dev)."""

# --- Lifespan ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and teardown shared resources (httpx client, redis, services)."""
    # Startup: create httpx.AsyncClient, CacheService, RegistryService, etc.
    # Store on app.state
    # Shutdown: close all connections

# --- Endpoints ---

@app.get("/v1/status", response_model=HealthResponse)
async def health_check() -> HealthResponse: ...

@app.post("/v1/verify/imports", response_model=VerifyImportsResponse)
async def verify_imports(
    req: VerifyImportsRequest,
    api_key: str = Depends(verify_api_key),
) -> VerifyImportsResponse: ...

@app.post("/v1/verify/dockerfile", response_model=VerifyDockerResponse)
async def verify_dockerfile(
    req: VerifyDockerRequest,
    api_key: str = Depends(verify_api_key),
) -> VerifyDockerResponse: ...

@app.post("/v1/scan/static", response_model=StaticScanResponse)
async def static_scan(
    req: StaticScanRequest,
    api_key: str = Depends(verify_api_key),
) -> StaticScanResponse: ...

@app.post("/v1/scan/deep", response_model=DeepScanResponse)
async def deep_scan(
    req: DeepScanRequest,
    api_key: str = Depends(verify_api_key),
) -> DeepScanResponse: ...
```

## 7. MCP Server Tools

```python
# src/server.py
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("codetrust")

# --- Layer 1 tools (always local, no API key needed) ---

@mcp.tool(name="codetrust_static_scan")
async def codetrust_static_scan(params: MidActionInput) -> str:
    """Scan code for anti-patterns, security issues, and quality problems."""

@mcp.tool(name="codetrust_pre_action")
async def codetrust_pre_action(params: PreActionInput) -> str:
    """Validate plan before writing code."""

@mcp.tool(name="codetrust_post_action")
async def codetrust_post_action(params: PostActionInput) -> str:
    """Validate completed work against enterprise standards."""

# --- Layer 2 tools (call cloud API if API key is set, skip if not) ---

@mcp.tool(name="codetrust_verify_imports")
async def codetrust_verify_imports(params: VerifyImportsInput) -> str:
    """
    Verify that all imports in code exist in package registries.
    
    If CODETRUST_API_KEY is set: calls cloud API.
    If not set: extracts imports and checks PyPI/npm directly.
    """

@mcp.tool(name="codetrust_verify_dockerfile")
async def codetrust_verify_dockerfile(params: VerifyDockerInput) -> str:
    """Verify Docker base images and tags exist."""

@mcp.tool(name="codetrust_deep_scan")
async def codetrust_deep_scan(params: FullScanInput) -> str:
    """Run all validation layers in a single pass."""

@mcp.tool(name="codetrust_list_rules")
async def codetrust_list_rules() -> str:
    """List all rules and their severities."""

# --- Entry point ---
if __name__ == "__main__":
    mcp.run()
```

## 8. Anti-Pattern Rules (migrated + expanded)

```python
# src/rules/anti_patterns.py

ANTI_PATTERNS: list[dict[str, str]] = [
    # --- BLOCK severity ---
    {
        "id": "heredoc",
        "pattern": r"<<[-']?\w+",
        "message": "Heredoc detected. Use template files or multi-line strings.",
        "severity": "BLOCK",
    },
    {
        "id": "hardcoded_secret",
        "pattern": r'(?i)(api[_-]?key|secret|password|token|credentials)\s*[:=]\s*["\'][^"\']{8,}["\']',
        "message": "Possible hardcoded secret. Use environment variables.",
        "severity": "BLOCK",
    },
    {
        "id": "eval_exec",
        "pattern": r"\b(eval|exec)\s*\(",
        "message": "eval/exec is a security risk. Use safe alternatives.",
        "severity": "BLOCK",
    },
    {
        "id": "sql_injection",
        "pattern": r'(execute|cursor\.execute)\s*\(\s*f["\']|\.format\s*\(',
        "message": "Possible SQL injection via string formatting. Use parameterized queries.",
        "severity": "BLOCK",
    },
    {
        "id": "pickle_load",
        "pattern": r"pickle\.loads?\s*\(",
        "message": "pickle.load is unsafe with untrusted data. Use JSON or msgpack.",
        "severity": "BLOCK",
    },
    # --- WARN severity ---
    {
        "id": "todo_hack",
        "pattern": r"(?i)#\s*(todo|hack|fixme|xxx|temp)\b",
        "message": "Temporary marker found. Resolve before committing.",
        "severity": "WARN",
    },
    {
        "id": "console_log",
        "pattern": r"\bconsole\.(log|debug|info)\b",
        "message": "Use structured logger instead of console.log.",
        "severity": "WARN",
    },
    {
        "id": "print_debug",
        "pattern": r"^\s*print\s*\(",
        "message": "Use logging module instead of print().",
        "severity": "WARN",
    },
    {
        "id": "any_type",
        "pattern": r":\s*[Aa]ny\b",
        "message": "Avoid Any type. Use explicit types.",
        "severity": "WARN",
    },
    {
        "id": "wildcard_import",
        "pattern": r"from\s+\S+\s+import\s+\*",
        "message": "Wildcard imports reduce clarity. Import explicitly.",
        "severity": "WARN",
    },
    {
        "id": "nested_ternary",
        "pattern": r"\?[^:]+\?",
        "message": "Nested ternary reduces readability. Use if/else.",
        "severity": "WARN",
    },
    {
        "id": "bare_except",
        "pattern": r"except\s*:",
        "message": "Bare except catches everything including KeyboardInterrupt. Catch specific exceptions.",
        "severity": "WARN",
    },
    {
        "id": "mutable_default",
        "pattern": r"def\s+\w+\([^)]*(?::\s*(?:list|dict|set)\s*=\s*(?:\[\]|\{\}))",
        "message": "Mutable default argument. Use None and assign inside function.",
        "severity": "WARN",
    },
    # --- INFO severity ---
    {
        "id": "magic_number",
        "pattern": r"(?<!=)\s(?<!\w)[2-9]\d{2,}\b",
        "message": "Magic number detected. Extract to a named constant.",
        "severity": "INFO",
    },
    {
        "id": "long_function",
        "pattern": r"^(def |async def )",
        "message": "Function detected — verify it's under 40 lines.",
        "severity": "INFO",
        "special_handler": "check_function_length",
    },
]
```

## 9. Import Extraction Logic

```python
# src/utils/parsers.py

def extract_python_imports(code: str) -> list[str]:
    """
    Extract top-level package names from Python code.
    
    Handles:
      import foo                → "foo"
      import foo.bar            → "foo"
      from foo import bar       → "foo"
      from foo.bar import baz   → "foo"
      from . import something   → skip (relative import)
    
    Normalizes: underscores/hyphens (e.g. "PIL" → "Pillow" via known mapping)
    Skips: stdlib modules (use sys.stdlib_module_names on 3.10+)
    """

def extract_js_imports(code: str) -> list[str]:
    """
    Extract package names from JavaScript/TypeScript code.
    
    Handles:
      import x from 'foo'       → "foo"
      import { x } from 'foo'   → "foo"
      const x = require('foo')  → "foo"
      import('foo')             → "foo"
      from '@scope/pkg'         → "@scope/pkg"
    
    Skips: relative imports (./  ../), node builtins
    """

def parse_requirements_txt(content: str) -> dict[str, str]:
    """
    Parse requirements.txt to {package: version_spec}.
    
    Handles: ==, >=, ~=, !=, extras like [dev], comments, -r includes
    Skips: git+ URLs, file:// URLs, blank lines
    """

def parse_package_json_deps(content: str) -> dict[str, str]:
    """Parse package.json dependencies + devDependencies."""

def parse_dockerfile_from(content: str) -> list[tuple[str, str]]:
    """
    Extract (image, tag) tuples from Dockerfile.
    
    Handles:
      FROM python:3.12-slim            → ("python", "3.12-slim")
      FROM python:3.12-slim AS builder → ("python", "3.12-slim")
      FROM --platform=linux/amd64 node → ("node", "latest")
      ARG BASE=python:3.12             → tries to resolve
    """

# Known import-to-package mapping (Python)
PYTHON_IMPORT_TO_PACKAGE: dict[str, str] = {
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "gi": "PyGObject",
    "attr": "attrs",
    "dateutil": "python-dateutil",
    "dotenv": "python-dotenv",
    "jose": "python-jose",
    "jwt": "PyJWT",
    "magic": "python-magic",
    "serial": "pyserial",
    "usb": "pyusb",
    "wx": "wxPython",
}
```

## 10. Cache Key Schema

```
codetrust:pypi:{package_name}              → JSON: {exists: bool, latest: str, deprecated: bool}
codetrust:pypi:{package_name}:{version}    → JSON: {exists: bool}
codetrust:npm:{package_name}               → JSON: {exists: bool, latest: str, deprecated: bool}
codetrust:npm:{package_name}:{version}     → JSON: {exists: bool}
codetrust:docker:{image}:{tag}             → JSON: {exists: bool}
codetrust:docker:{image}:_tags             → JSON: {tags: [str]}
codetrust:api:{url_hash}                   → JSON: {reachable: bool, status: int}
```

All keys use the TTLs defined in Settings.
