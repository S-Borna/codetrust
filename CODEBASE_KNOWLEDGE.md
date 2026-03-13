# CODEBASE_KNOWLEDGE.md — CodeTrust Complete Codebase Reference

> **Purpose:** Bootstrap any new AI agent session with total knowledge of the CodeTrust codebase.
> **Generated:** 2026-03-10
> **Version:** v2.8.5
> **Owner:** Said Borna <said@saidborna.com>
> **Scope:** Every file, function, class, constant, endpoint, rule, and interconnection.

---

## TABLE OF CONTENTS

1. [Product Identity](#1-product-identity)
2. [Architecture Overview](#2-architecture-overview)
3. [Tech Stack](#3-tech-stack)
4. [Source Code — src/](#4-source-code--src)
   - 4.1 [Entry Points](#41-entry-points)
   - 4.2 [Models](#42-models)
   - 4.3 [Services](#43-services)
   - 4.4 [Rules Engine](#44-rules-engine)
   - 4.5 [Formatters](#45-formatters)
   - 4.6 [Gateway](#46-gateway)
   - 4.7 [Middleware](#47-middleware)
   - 4.8 [Utils](#48-utils)
   - 4.9 [Templates](#49-templates)
5. [Tests — tests/](#5-tests--tests)
6. [VS Code Extension — extension/](#6-vs-code-extension--extension)
7. [Dashboard — dashboard/](#7-dashboard--dashboard)
8. [GitHub Action — action/](#8-github-action--action)
9. [Scripts — scripts/](#9-scripts--scripts)
10. [Database & Migrations — alembic/](#10-database--migrations--alembic)
11. [Deploy & Infrastructure](#11-deploy--infrastructure)
12. [Documentation — docs/](#12-documentation--docs)
13. [Root Configuration Files](#13-root-configuration-files)
14. [Key Interconnections](#14-key-interconnections)
15. [Quick Reference Tables](#15-quick-reference-tables)

---

## 1. PRODUCT IDENTITY

**CodeTrust** is an **AI Governance Enforcement Platform** that validates AI-generated code before it reaches production. It is a paid, enterprise-grade product built by a solo founder.

### Four Strategic Moats

1. **AI Governance Gateway** — 82 rules that intercept IDE tool calls (terminal commands, file writes, package installs, file deletes) BEFORE execution. Works via MCP proxy tools in Claude Code, Cursor, Windsurf, and GitHub Copilot.
2. **Package Existence Verification + Hallucination Detection** — Verifies imports against 8 live registries (PyPI, npm, Maven, NuGet, RubyGems, crates.io, pkg.go.dev, Hex). Detects hallucinated function signatures via a curated database of 209 functions across 33 modules.
3. **AI Drift / Trust Score** — Quantifies how much a codebase has drifted from best practices. Scores 0–1.00 with letter grades (A+/A/B/C/D/F). Tracks per-commit/PR trends.
4. **Session-Level Universal IDE Enforcement** — Injects governance instructions into Claude Code, Cursor, Windsurf, and GitHub Copilot at session startup. The rules persist for the entire coding session.

### Delivery Surfaces (4)

| Surface | Technology | Entry Point |
|---------|-----------|-------------|
| CLI | Python (Click/Typer-style) | `src/cli.py` → `codetrust` command |
| VS Code Extension | TypeScript | `extension/src/extension.ts` |
| GitHub Action | Composite Action (Python) | `action/action.yml` + `action/scan_runner.py` |
| Cloud API | FastAPI | `src/api.py` → 60 endpoints |

### MCP Servers (2)

| Server | Entry Point | Tools |
|--------|-------------|-------|
| Scanner MCP | `src/server.py` | 10 tools (static_scan, pre_action, post_action, list_rules, verify_imports, verify_dockerfile, ast_scan, sandbox_run, sarif_export, deep_scan) |
| Gateway MCP | `src/gateway/server.py` | 17 tools (validate_command, validate_file_write, validate_file_delete, validate_package, run_in_terminal, create_file, replace_string_in_file, edit_notebook, governance_status, list_gateway_rules, audit_history, begin_trusted_session, approve_action, list_exceptions, revoke_exception, simulate_policy, governance_posture) |

### Key Metrics (v2.8.5)

- **286 total rules** (204 scan rules + 82 gateway rules)
- **60 API endpoints**
- **27 MCP tools** (10 scanner + 17 gateway)
- **1,937 tests**
- **20+ CLI commands**
- **17 languages supported**
- **209 curated function signatures** (24 Python modules + 17 JS/TS modules)
- **17 autofix recipes** + 3 structural recipes

---

## 2. ARCHITECTURE OVERVIEW

```
┌─────────────────────────────────────────────────────┐
│                  AI Agent / IDE                      │
│  (Claude Code, Cursor, Windsurf, GitHub Copilot)    │
└──────────────────┬──────────────────────────────────┘
                   │ MCP Protocol
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────┐   ┌─────────────────┐
│ Gateway MCP   │   │  Scanner MCP    │
│ (11 tools)    │   │  (10 tools)     │
│ BEFORE action │   │  code analysis  │
└───────┬───────┘   └────────┬────────┘
        │                    │
        ▼                    ▼
┌─────────────────────────────────────┐
│           Core Engine               │
│  ┌─────────────────────────────┐    │
│  │ StaticAnalyzer (Layer 1)    │    │
│  │ ASTAnalyzer (Layer 3)       │    │
│  │ SignatureEngine (Layer 3b)  │    │
│  │ RegistryVerifier (Layer 2)  │    │
│  │ DockerVerifier (Layer 2b)   │    │
│  │ SandboxRunner (Layer 4)     │    │
│  │ CommandInterceptor (Gate)   │    │
│  └─────────────────────────────┘    │
│  ┌─────────────────────────────┐    │
│  │ Enterprise Services         │    │
│  │ Auth, Billing, RBAC, GDPR   │    │
│  │ CVE, License, Cross-File    │    │
│  │ Autofix, Custom Rules       │    │
│  └─────────────────────────────┘    │
└──────────────────┬──────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────┐   ┌─────────────────┐
│  PostgreSQL   │   │     Redis       │
│  (via SQLAlch)│   │  (cache layer)  │
└───────────────┘   └─────────────────┘
```

### 10 Inspection Layers

1. **Static Analysis** — 260+ regex anti-pattern rules
2. **Root Cause Analysis** — Error path validation
3. **SQL Injection** — Parameterized query enforcement
4. **AST Analysis** — tree-sitter structural checks for 10 languages
5. **Container Scanning** — Dockerfile best practices
6. **IaC Scanning** — Terraform, Helm, Ansible, CloudFormation
7. **React/K8s** — Framework-specific patterns
8. **Import Verification** — 8 registry lookups
9. **Docker Image Verification** — Docker Hub tag validation
10. **AI Governance Gateway** — 82 interception rules

---

## 3. TECH STACK

### Python Backend

| Component | Package | Version |
|-----------|---------|---------|
| MCP Server | mcp[cli] (FastMCP) | >= 1.0.0 |
| HTTP API | FastAPI + uvicorn | latest |
| Validation | Pydantic v2 | strict mode |
| HTTP Client | httpx | async only |
| Cache | redis.asyncio | Upstash-compatible |
| AST Parsing | tree-sitter + tree-sitter-languages | 10 languages |
| Auth | PyJWT | RS256/HS256 |
| Database | SQLAlchemy (async) + Alembic | PostgreSQL |
| Billing | stripe | Stripe API |
| Logging | structlog | JSON output |
| CLI | click (via entry point) | — |
| Testing | pytest + pytest-asyncio + pytest-httpx | — |
| Linting | ruff | zero warnings policy |
| OIDC/SSO | (custom implementation) | — |

### TypeScript Extension

| Component | Package |
|-----------|---------|
| VS Code API | ^1.85.0 |
| Bundler | esbuild |
| Obfuscation | javascript-obfuscator |
| Testing | Mocha + @vscode/test-electron |

### Next.js Dashboard

| Component | Package |
|-----------|---------|
| Framework | Next.js 14 (App Router) |
| React | 18 |
| Auth | NextAuth 4 (GitHub OAuth) |
| ORM | Prisma 5 (PostgreSQL) |
| Billing | Stripe 17 |
| Styling | Tailwind CSS |
| Testing | Vitest + Playwright |

### Deployment

| Component | Details |
|-----------|---------|
| Platform | Railway |
| Container | Docker (Python 3.12-slim) |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| CI/CD | GitHub Actions (4 workflows) |
| Distribution | PyPI (wheel only, no sdist) |
| Marketplace | VS Code Marketplace |

---

## 4. SOURCE CODE — src/

### 4.1 ENTRY POINTS

#### src/**init**.py

Package marker. Exports `__version__ = "2.7.0"`.

#### src/config.py (~200 lines)

Central configuration via `pydantic-settings`. Class `Settings(BaseSettings)`:

**Key settings:**

- `CODETRUST_API_KEY`, `CODETRUST_API_URL` (default: `https://api.codetrust.ai`)
- `CODETRUST_REDIS_URL` (default: `redis://localhost:6379`)
- `CODETRUST_DATABASE_URL` (PostgreSQL connection string)
- `CODETRUST_STRIPE_*` (API key, webhook secret, price IDs for pro/enterprise)
- `CODETRUST_JWT_SECRET`, `CODETRUST_JWT_ALGORITHM` (HS256)
- `CODETRUST_GITHUB_CLIENT_ID`, `CODETRUST_GITHUB_CLIENT_SECRET`

**Constants:**

- `PYPI_BASE_URL`, `NPM_REGISTRY_URL`, `MAVEN_CENTRAL_URL`, `NUGET_API_URL`, `RUBYGEMS_API_URL`, `CRATES_IO_API_URL`, `GO_PROXY_URL`, `HEX_API_URL` — all 8 registry URLs
- `CACHE_TTL_PACKAGE = 3600`, `CACHE_TTL_DOCKER = 1800`, `CACHE_TTL_SCAN = 300`
- `FREE_TIER_RULE_IDS` — list of rule IDs available without API key
- `PREMIUM_RULE_IDS` — rules requiring paid subscription
- Rate limit settings, CORS origins, telemetry toggle

#### src/api.py (~2,680 lines)

**FastAPI application** — the HTTP API server with 60 endpoints.

**Lifespan:** Initializes `httpx.AsyncClient`, Redis connection, database session, Stripe client, auth service. Stores all in `app.state`.

**Endpoint groups:**

- `GET /health` — health check with service status
- `POST /v1/scan/static` — static analysis scan
- `POST /v1/scan/ast` — AST analysis scan
- `POST /v1/scan/signature` — signature validation scan
- `POST /v1/scan/deep` — deep scan orchestrator (static + AST + signature + imports + docker)
- `POST /v1/scan/sarif` — scan with SARIF output
- `POST /v1/verify/imports` — import verification against registries
- `POST /v1/verify/dockerfile` — Dockerfile verification
- `POST /v1/sandbox/run` — sandboxed code execution
- `GET /v1/rules` — list available rules
- `GET /v1/rules/download` — HMAC-signed premium rule delivery
- `POST /v1/fix/suggest` — autofix suggestions
- `POST /v1/fix/apply` — apply autofix recipe
- `POST /v1/auth/github` — GitHub OAuth callback
- `POST /v1/auth/token` — JWT token generation
- `GET /v1/auth/me` — current user info
- `POST /v1/billing/checkout` — Stripe checkout session
- `POST /v1/billing/webhook` — Stripe webhook handler
- `GET /v1/billing/subscription` — subscription status
- `GET /v1/dashboard/stats` — dashboard statistics
- `POST /v1/vuln/scan` — vulnerability scanning (OSV API)
- `POST /v1/license/scan` — license compliance checking
- `POST /v1/cross-file/analyze` — cross-file analysis
- `GET /v1/governance/audit` — governance audit log query
- `POST /v1/custom-rules` — custom rule management
- `GET /v1/stats/public` — public usage statistics
- `WebSocket /v1/stats/live` — real-time stats stream
- `POST /v1/telemetry` — telemetry ingestion
- **Org/Team endpoints (10):** CRUD for organizations, teams, members, invites, roles
- `POST /v1/gdpr/export` — GDPR data export
- `DELETE /v1/gdpr/delete` — GDPR data deletion
- `POST /v1/sso/oidc/callback` — SSO/OIDC authentication
- `GET /v1/webhook/config` — webhook configuration

**Authentication middleware:** `verify_api_key()` dependency — checks `X-API-Key` header against database, validates subscription status, enforces rate limits. Some endpoints are public (health, public stats, telemetry).

**Deep scan orchestration flow:**

1. Static analysis (regex rules)
2. AST analysis (tree-sitter)
3. Signature validation (function parameter checks)
4. Import verification (registry lookups)
5. Dockerfile verification (if applicable)
6. Cross-file analysis (if multiple files)
7. Aggregate findings, compute trust score, return unified report

#### src/server.py (~1,205 lines)

**MCP Scanner Server** via FastMCP. 10 tools:

1. **`static_scan`** — Runs StaticAnalyzer on code content. Params: `code: str`, `language: str`, `filename: str`. Returns findings list.
2. **`pre_action`** — Validates planned action description against enterprise rules. Params: `description: str`, `repo_root: str`. Returns verdict.
3. **`post_action`** — Validates completed work. Params: `repo_root: str`, `changed_files: list[str]`. Runs full scan on changed files, returns findings.
4. **`list_rules`** — Returns all available scan rules with metadata.
5. **`verify_imports`** — Checks import statements against registries. Params: `code: str`, `language: str`. Returns verification results.
6. **`verify_dockerfile`** — Validates Dockerfile content. Params: `dockerfile: str`. Returns findings.
7. **`ast_scan`** — tree-sitter AST analysis. Params: `code: str`, `language: str`. Returns structural findings.
8. **`sandbox_run`** — Execute code in isolated Docker container. Params: `code: str`, `language: str`, `timeout: int`. Returns output.
9. **`sarif_export`** — Convert findings to SARIF v2.1.0 format.
10. **`deep_scan`** — Full multi-layer scan orchestration.

Startup: Loads all services, anti-pattern rules, signature database.

#### src/cli.py (~4,359 lines)

**CLI entry point** with 20+ subcommands:

| Command | Purpose |
|---------|---------|
| `codetrust init` | Initialize project config (`.codetrust.toml`) |
| `codetrust setup` | Bootstrap governance (pre-commit hook, MCP config, IDE instructions) |
| `codetrust add` | Add custom rules |
| `codetrust scan` | Scan files/directories for anti-patterns |
| `codetrust fix` | Auto-fix findings with recipes |
| `codetrust vuln` | Vulnerability scanning via OSV API |
| `codetrust license` | License compliance checking |
| `codetrust status` | Show project governance status |
| `codetrust doctor` | Diagnose installation/config issues |
| `codetrust pr-risk` | Analyze PR risk score from git diff |
| `codetrust trust-diff` | Trust score diff between commits |
| `codetrust trend` | Trust score trend visualization |
| `codetrust governance` | Governance policy management |
| `codetrust policy` | Policy wizard for `.codetrust.toml` |
| `codetrust audit` | Query governance audit log |
| `codetrust cross-file` | Cross-file dependency analysis |
| `codetrust report` | Generate detailed scan report |
| `codetrust config` | View/edit configuration |
| `codetrust auth` | Authentication management |
| `codetrust upgrade` | Check for updates |

**Key CLI features:**

- `--format json/table/markdown` output modes
- `--severity block/warn/info` filtering
- `--exclude` pattern support
- `--fix` auto-apply mode
- Color-coded terminal output with severity indicators
- Progress bars for multi-file scans
- Trust score computation with letter grades
- Git-aware scanning (diff-based, PR mode)

#### src/telemetry_client.py (~120 lines)

**Fire-and-forget telemetry** — sends anonymous usage events to the CodeTrust API. Events: scan_completed, cli_command, extension_activated, action_run. Includes: event type, version, OS, language, file count, finding count. Respects `CODETRUST_TELEMETRY_ENABLED` setting. Uses background task with 5s timeout. Never fails the main operation.

---

### 4.2 MODELS

#### src/models/**init**.py

Package marker.

#### src/models/enums.py (~80 lines)

Core enumerations:

- **`Severity`**: `BLOCK`, `WARN`, `INFO` — finding severity levels
- **`Language`**: `PYTHON`, `JAVASCRIPT`, `TYPESCRIPT`, `GO`, `RUST`, `JAVA`, `RUBY`, `PHP`, `SQL`, `DOCKERFILE`, `TERRAFORM`, `HELM`, `YAML`, `JSON`, `TOML`, `SHELL`, `POWERSHELL`
- **`ScanType`**: `STATIC`, `AST`, `SIGNATURE`, `DEEP`, `IMPORT`, `DOCKER`, `SANDBOX`
- **`Verdict`**: `PASS`, `WARN`, `BLOCK`
- **`SubscriptionTier`**: `FREE`, `PRO`, `ENTERPRISE`
- **`GatewayAction`**: `ALLOW`, `WARN`, `BLOCK`

#### src/models/requests.py (~250 lines)

Pydantic v2 request models (all `strict=True`):

- **`ScanRequest`**: `code: str`, `language: Language`, `filename: str | None`, `rules: list[str] | None`
- **`DeepScanRequest`**: extends ScanRequest with `include_ast: bool`, `include_imports: bool`, `include_docker: bool`, `include_signatures: bool`
- **`ImportVerifyRequest`**: `code: str`, `language: Language`
- **`DockerVerifyRequest`**: `dockerfile: str`
- **`SandboxRequest`**: `code: str`, `language: Language`, `timeout: int = 30`
- **`FixRequest`**: `code: str`, `language: Language`, `rule_id: str`
- **`FixApplyRequest`**: `code: str`, `recipe_id: str`, `language: Language`
- **`VulnScanRequest`**: `requirements: str` (requirements.txt content)
- **`LicenseScanRequest`**: `packages: list[str]`, `language: Language`
- **`CrossFileRequest`**: `files: dict[str, str]` (filename → content mapping)
- **`CustomRuleRequest`**: `name: str`, `pattern: str`, `severity: Severity`, `message: str`, `languages: list[Language]`
- **`GDPRExportRequest`**: `user_id: str`
- **`OrgCreateRequest`**: `name: str`, `plan: SubscriptionTier`
- **`TeamMemberRequest`**: `user_id: str`, `role: str`

#### src/models/responses.py (~300 lines)

Pydantic v2 response models:

- **`Finding`**: `rule_id: str`, `severity: Severity`, `message: str`, `line: int | None`, `column: int | None`, `suggestion: str | None`, `file: str | None`, `category: str | None`
- **`ScanResponse`**: `verdict: Verdict`, `findings: list[Finding]`, `trust_score: float | None`, `scan_type: ScanType`, `language: Language`, `file_count: int`, `duration_ms: float`
- **`ImportVerifyResponse`**: `verified: list[ImportResult]`, `unverified: list[ImportResult]`
- **`ImportResult`**: `name: str`, `registry: str`, `exists: bool`, `version: str | None`, `suggestion: str | None`
- **`FixSuggestion`**: `rule_id: str`, `recipe_id: str`, `description: str`, `before: str`, `after: str`, `confidence: float`
- **`FixApplyResult`**: `success: bool`, `code: str`, `changes: list[str]`
- **`VulnResult`**: `package: str`, `version: str`, `cve_id: str | None`, `severity: str`, `description: str`, `fixed_version: str | None`
- **`LicenseResult`**: `package: str`, `license: str`, `compatible: bool`, `risk: str`
- **`CrossFileResult`**: `findings: list[Finding]`, `dependency_graph: dict`, `complexity_score: float`
- **`DashboardStats`**: scan counts, finding counts, threat counts, top rules, trend data
- **`PublicStats`**: total_scans, total_findings, threats_blocked, downloads, installs_by_source
- **`GatewayAuditEntry`**: `timestamp: str`, `action: GatewayAction`, `rule_id: str`, `context: str`, `verdict: str`

#### src/models/database.py (~200 lines)

SQLAlchemy async ORM models:

- **`User`**: id, github_id, email, name, api_key, subscription_tier, stripe_customer_id, created_at, updated_at
- **`Organization`**: id, name, owner_id, plan, stripe_subscription_id, created_at
- **`TeamMember`**: id, org_id, user_id, role (admin/member/viewer), invited_by, joined_at
- **`ScanRecord`**: id, user_id, scan_type, language, verdict, finding_count, trust_score, duration_ms, created_at
- **`CustomRule`**: id, org_id, name, pattern, severity, message, languages, enabled, created_at
- **`AuditLog`**: id, user_id, action, resource, details, ip_address, created_at
- **`WebhookConfig`**: id, org_id, url, events, secret, active

---

### 4.3 SERVICES

#### src/services/**init**.py

Package marker.

#### src/services/static_analyzer.py (~350 lines)

**Layer 1: Regex Anti-Pattern Engine**

Class `StaticAnalyzer`:

- `__init__(rules: list[AntiPatternRule])` — loads rules from `src/rules/anti_patterns.py`
- `scan(code: str, language: Language, filename: str | None) -> list[Finding]` — main scan method
- `_match_rule(rule, line, line_number) -> Finding | None` — per-line regex matching
- `_filter_by_language(rules, language) -> list[AntiPatternRule]` — language-specific rule filtering
- `_is_comment(line, language) -> bool` — skip comment lines
- `_compute_trust_score(findings, total_lines) -> float` — trust score calculation

**Trust score formula:** `1.0 - (weighted_findings / total_lines)` where BLOCK=1.0, WARN=0.3, INFO=0.1 weights. Clamped to [0.0, 1.0].

#### src/services/ast_analyzer.py (~400 lines)

**Layer 3: tree-sitter AST Analysis**

Class `ASTAnalyzer`:

- Languages supported: Python, JavaScript, TypeScript, Go, Rust, Java, Ruby, PHP, C, C++
- `analyze(code: str, language: Language) -> list[Finding]` — parse code into AST, run structural checks
- Checks: unused imports, unreachable code, empty except blocks, overly complex functions (cyclomatic complexity), deeply nested code, missing return types, class complexity
- Uses `tree_sitter.Parser` and `tree_sitter_languages.get_parser()`

#### src/services/signature_engine.py (~300 lines)

**Layer 3b: Function Signature Validation**

Class `SignatureEngine`:

- Loads curated signature database from `src/rules/signatures.py`
- `validate(code: str, language: Language) -> list[Finding]` — detect hallucinated or incorrect function calls
- Checks: wrong parameter names, wrong parameter count, deprecated functions, non-existent methods
- Uses regex + AST hybrid approach for function call extraction

#### src/services/registry.py (~450 lines)

**Layer 2: Package Registry Verification**

Class `RegistryVerifier`:

- `verify_package(name: str, registry: str) -> ImportResult` — check if package exists
- Supported registries and their APIs:
  - **PyPI**: `GET https://pypi.org/pypi/{name}/json`
  - **npm**: `GET https://registry.npmjs.org/{name}`
  - **Maven**: `GET https://search.maven.org/solrsearch/select?q=a:{artifact}`
  - **NuGet**: `GET https://api.nuget.org/v3-flatcontainer/{name}/index.json`
  - **RubyGems**: `GET https://rubygems.org/api/v1/gems/{name}.json`
  - **crates.io**: `GET https://crates.io/api/v1/crates/{name}`
  - **Go**: `GET https://proxy.golang.org/{module}/@latest`
  - **Hex**: `GET https://hex.pm/api/packages/{name}`
- Each registry call: 10s timeout, retry once, cache results in Redis (TTL: 3600s)
- Uses `httpx.AsyncClient` with connection pooling
- Fuzzy matching for "did you mean?" suggestions via `src/utils/similarity.py`

#### src/services/docker_verify.py (~250 lines)

**Layer 2b: Docker Image Verification**

Class `DockerVerifier`:

- `verify_image(image: str, tag: str) -> Finding | None` — check Docker Hub for image:tag existence
- `verify_dockerfile(content: str) -> list[Finding]` — parse Dockerfile, verify all FROM images
- Checks: image exists, tag exists, latest tag warning, non-official image warning, multi-stage build validation
- API: `GET https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}`
- Cache TTL: 1800s

#### src/services/import_verifier.py (~350 lines)

**Import Verification Orchestrator**

Class `ImportVerifier`:

- `verify(code: str, language: Language) -> ImportVerifyResponse` — extract imports, verify each
- Uses `src/utils/parsers.py` for import extraction
- Delegates to `RegistryVerifier` for each package
- Aggregates results into verified/unverified lists
- Handles language-specific import syntax (Python `import`/`from`, JS `require`/`import`, Go `import`, Rust `use`)

#### src/services/sandbox.py (~300 lines)

**Layer 4: Isolated Docker Sandbox Execution**

Class `SandboxRunner`:

- `run(code: str, language: Language, timeout: int = 30) -> SandboxResult` — execute code in Docker container
- Docker images per language: `codetrust-sandbox-python`, `codetrust-sandbox-node`, `codetrust-sandbox-go`, `codetrust-sandbox-rust`
- Security: no network, read-only filesystem, memory limit (256MB), CPU limit, no-new-privileges
- Captures stdout/stderr, exit code, execution time
- Cleans up container after execution

#### src/services/cache.py (~180 lines)

**Redis Caching Layer**

Class `CacheService`:

- `get(key: str) -> str | None` — get cached value
- `set(key: str, value: str, ttl: int) -> None` — set with TTL
- `delete(key: str) -> None` — invalidate
- `exists(key: str) -> bool` — check existence
- Key patterns: `codetrust:pkg:{registry}:{name}`, `codetrust:docker:{image}:{tag}`, `codetrust:scan:{hash}`
- Connection: `redis.asyncio.from_url()` with decode_responses=True
- Graceful degradation: all methods wrapped in try/except, return None on connection error

#### src/services/database.py (~400 lines)

**Async Database Service**

Class `DatabaseService`:

- Uses SQLAlchemy async engine + async session maker
- `create_user(github_id, email, name) -> User`
- `get_user_by_api_key(api_key) -> User | None`
- `get_user_by_github_id(github_id) -> User | None`
- `record_scan(user_id, scan_type, language, verdict, finding_count, trust_score, duration_ms) -> ScanRecord`
- `get_dashboard_stats(user_id) -> DashboardStats`
- `get_org(org_id) -> Organization`
- `create_org(name, owner_id, plan) -> Organization`
- `add_team_member(org_id, user_id, role) -> TeamMember`
- `get_custom_rules(org_id) -> list[CustomRule]`
- `upsert_custom_rule(org_id, rule_data) -> CustomRule`
- `log_audit(user_id, action, resource, details, ip) -> AuditLog`
- `gdpr_export(user_id) -> dict` — exports all user data
- `gdpr_delete(user_id) -> None` — anonymizes/deletes user data

#### src/services/auth_service.py (~350 lines)

**Authentication & Authorization**

Class `AuthService`:

- `github_oauth(code: str) -> tuple[User, str]` — exchange GitHub OAuth code for user + JWT
- `generate_jwt(user: User) -> str` — create JWT with user_id, email, tier, exp claims
- `verify_jwt(token: str) -> dict` — decode and validate JWT
- `generate_api_key() -> str` — generate `ct_` prefixed API key (32 bytes hex)
- `verify_api_key(key: str) -> User` — lookup user by API key
- `check_rate_limit(user: User) -> bool` — per-tier rate limiting (free: 100/day, pro: 10000/day, enterprise: unlimited)
- `check_permission(user: User, resource: str) -> bool` — RBAC permission check

Rate limits stored in Redis with sliding window (key: `codetrust:ratelimit:{user_id}:{date}`).

#### src/services/billing.py (~400 lines)

**Stripe Billing Integration**

Class `BillingService`:

- `create_checkout_session(user: User, plan: str) -> str` — Stripe Checkout URL
- `handle_webhook(payload: bytes, signature: str) -> None` — process Stripe webhooks
- Webhook events: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`, `invoice.payment_failed`
- `get_subscription(user: User) -> dict` — current subscription details
- `cancel_subscription(user: User) -> None` — cancel at period end
- `upgrade_subscription(user: User, new_plan: str) -> None` — plan upgrade
- Price IDs from config: `CODETRUST_STRIPE_PRO_PRICE_ID`, `CODETRUST_STRIPE_ENTERPRISE_PRICE_ID`
- Creates Stripe customer on first checkout, stores `stripe_customer_id` on User

#### src/services/vuln_scanner.py (~250 lines)

**Vulnerability Scanning via OSV API**

Class `VulnScanner`:

- `scan_requirements(requirements: str) -> list[VulnResult]` — parse requirements.txt, check each package
- API: `POST https://api.osv.dev/v1/query` with package name + version
- Returns CVE IDs, severity, description, fixed versions
- Caches results in Redis (TTL: 3600s)
- Supports Python (requirements.txt), Node (package.json), Go (go.sum)

#### src/services/license_checker.py (~200 lines)

**License Compliance Checking**

Class `LicenseChecker`:

- `check_packages(packages: list[str], language: Language) -> list[LicenseResult]`
- Fetches license info from registries (PyPI metadata, npm metadata)
- Classifies licenses: permissive (MIT, Apache-2.0, BSD), copyleft (GPL, AGPL), restrictive (proprietary)
- Risk assessment: LOW (permissive), MEDIUM (weak copyleft), HIGH (strong copyleft), CRITICAL (unknown/proprietary)
- Checks compatibility with project license

#### src/services/cross_file_analyzer.py (~300 lines)

**Cross-File Dependency Analysis**

Class `CrossFileAnalyzer`:

- `analyze(files: dict[str, str]) -> CrossFileResult`
- Builds dependency graph from imports across files
- Detects: circular imports, unused exports, missing dependencies, high coupling
- Computes complexity score based on coupling metrics
- Uses import extraction from `src/utils/parsers.py`

#### src/services/autofix.py (~500 lines)

**Autofix Recipe Engine**

Class `AutofixEngine`:

- `suggest(code: str, language: Language, rule_id: str) -> list[FixSuggestion]` — suggest fixes
- `apply(code: str, recipe_id: str, language: Language) -> FixApplyResult` — apply fix

**17 Code Recipes:**

1. `bare_except_to_specific` — `except:` → `except Exception:`
2. `wildcard_import_expand` — `from x import *` → explicit imports
3. `eval_to_safe_alternative` — `eval()` → `ast.literal_eval()` or `json.loads()`
4. `hardcoded_secret_to_env` — literal secrets → `os.environ.get()`
5. `print_to_logging` — `print()` → `logger.info()`
6. `sql_injection_parameterize` — string concat SQL → parameterized queries
7. `mutable_default_fix` — `def f(x=[])` → `def f(x=None): x = x or []`
8. `type_any_to_explicit` — `Any` → specific type
9. `magic_number_to_constant` — inline numbers → named constants
10. `todo_to_issue` — TODO comments → issue references
11. `console_log_to_logger` — `console.log` → structured logging
12. `nested_ternary_expand` — nested ternary → if/else
13. `string_concat_url_fix` — string concat URLs → URL builder
14. `heredoc_to_file` — heredoc → file read
15. `pickle_to_safe` — `pickle.load` → safer alternatives
16. `chmod_777_fix` — `chmod 777` → specific permissions
17. `curl_pipe_fix` — `curl | sh` → download + verify + execute

**3 Structural Recipes:**

1. `split_long_function` — extract sub-functions from 40+ line functions
2. `extract_constant` — move magic numbers to module-level constants
3. `add_type_hints` — add type annotations to untyped functions

#### src/services/custom_rules.py (~200 lines)

**Custom Rule Management**

Class `CustomRuleService`:

- `create_rule(org_id, rule_data) -> CustomRule`
- `update_rule(rule_id, rule_data) -> CustomRule`
- `delete_rule(rule_id) -> None`
- `get_rules(org_id) -> list[CustomRule]`
- `validate_pattern(pattern: str) -> bool` — regex validation
- `compile_rules(custom_rules) -> list[AntiPatternRule]` — convert to scan-compatible format
- Stores rules in database, loads at scan time for org-specific scanning

#### src/services/team_service.py (~250 lines)

**Team & RBAC Management**

Class `TeamService`:

- `create_org(name, owner_id, plan) -> Organization`
- `invite_member(org_id, email, role) -> invite_token`
- `accept_invite(token) -> TeamMember`
- `remove_member(org_id, user_id) -> None`
- `update_role(org_id, user_id, new_role) -> TeamMember`
- `get_members(org_id) -> list[TeamMember]`
- Roles: `owner` (full access), `admin` (manage members + rules), `member` (scan + view), `viewer` (read-only)
- Permission matrix enforced at API endpoint level

#### src/services/sso_service.py (~200 lines)

**SSO/OIDC Service**

Class `SSOService`:

- `initiate_oidc(provider_url: str, client_id: str) -> str` — generate OIDC authorization URL
- `handle_callback(code: str, state: str) -> User` — exchange code for user
- `validate_token(id_token: str) -> dict` — validate OIDC ID token
- Supports generic OIDC providers (Okta, Auth0, Azure AD)
- Maps OIDC claims to CodeTrust user attributes

#### src/services/gdpr_service.py (~180 lines)

**GDPR Compliance**

Class `GDPRService`:

- `export_user_data(user_id: str) -> dict` — comprehensive data export (user, scans, audit logs, custom rules)
- `delete_user_data(user_id: str) -> None` — anonymize + soft delete all user data
- `get_consent_status(user_id: str) -> dict` — check consent records
- Data retention: 90 days for scan records, 365 days for audit logs
- Export format: JSON with all associated records

#### src/services/rate_limiter.py (~150 lines)

**Rate Limiting Service**

Class `RateLimiter`:

- Sliding window counter in Redis
- Per-tier limits: FREE=100/day, PRO=10000/day, ENTERPRISE=unlimited
- `check(user_id: str, tier: str) -> bool` — returns True if within limit
- `get_remaining(user_id: str, tier: str) -> int` — remaining requests
- Key: `codetrust:ratelimit:{user_id}:{date}`

#### src/services/webhook_service.py (~200 lines)

**Webhook Delivery**

Class `WebhookService`:

- `deliver(org_id: str, event: str, payload: dict) -> None` — deliver webhook with HMAC signature
- Events: `scan.completed`, `finding.block`, `subscription.changed`, `member.added`
- Retry policy: 3 attempts with exponential backoff
- HMAC-SHA256 signature in `X-CodeTrust-Signature` header
- Stores delivery status for debugging

#### src/services/telemetry.py (~150 lines)

**Server-Side Telemetry**

Class `TelemetryService`:

- `ingest(event: dict) -> None` — store telemetry event
- `get_public_stats() -> PublicStats` — aggregate anonymous statistics
- `get_live_stats() -> dict` — real-time metrics for WebSocket stream
- Aggregates: total scans, findings, threats blocked, downloads (PyPI API), installs by source
- Used by the marketing website live dashboard

#### src/services/rule_delivery.py (~200 lines)

**Server-Side Rule Delivery**

Class `RuleDeliveryService`:

- `get_rules(tier: str) -> list[dict]` — returns rules based on subscription tier
- `sign_rules(rules: list[dict]) -> str` — HMAC-SHA256 signed rule payload
- `verify_signature(payload: str, signature: str) -> bool` — verify rule integrity
- Free tier gets `FREE_TIER_RULE_IDS` only
- Pro/Enterprise get all 286 rules
- Prevents tampering with rule definitions in transit

#### src/services/public_stats.py (~100 lines)

**Public Statistics**

Class `PublicStatsService`:

- `get_stats() -> PublicStats` — aggregated public metrics
- Sources: database (scan/finding counts), PyPI API (download counts), VS Code Marketplace API (install counts)
- Cached in Redis (TTL: 300s)
- Used by marketing website and docs

---

### 4.4 RULES ENGINE

#### src/rules/**init**.py

Package marker.

#### src/rules/anti_patterns.py (~1,676 lines)

**260+ regex anti-pattern rules** organized in 25+ categories:

**Data structure:** Each rule is a dict with keys: `id`, `pattern` (compiled regex), `severity` (BLOCK/WARN/INFO), `message`, `suggestion`, `languages` (list of applicable languages), `category`.

**Categories and notable rules:**

| Category | Count | Notable Rules |
|----------|-------|---------------|
| **Generic Security** | ~30 | eval/exec, hardcoded secrets, SQL injection, pickle.load, yaml.load, shell injection, path traversal |
| **SQL** | ~10 | String concatenation in queries, no parameterized queries, DROP TABLE, GRANT ALL |
| **DevOps** | ~15 | chmod 777, curl\|sh, rm -rf, hardcoded credentials in CI, exposed ports |
| **React** | ~10 | dangerouslySetInnerHTML, useEffect missing deps, direct DOM access |
| **Kubernetes** | ~10 | privileged containers, hostNetwork, no resource limits, latest tag |
| **AI Agent** | ~15 | git push, force push, sudo su, dd of=, mkfs, eval in shell, heredoc |
| **Hallucination Detection** | ~20 | Non-existent Python/JS modules, fake API endpoints, made-up CLI flags |
| **Ruby** | ~10 | send/public_send, system/exec, instance_eval, mass assignment |
| **PHP** | ~10 | eval, system/exec/passthru, unserialize, extract, $$var |
| **PowerShell** | ~10 | Invoke-Expression, -ExecutionPolicy Bypass, ConvertTo-SecureString |
| **Terraform** | ~10 | hardcoded secrets, no encryption, public access, wildcard IAM |
| **Helm** | ~8 | hardcoded secrets, no security context, host network, privileged |
| **Ansible** | ~8 | shell/command without changed_when, no_log missing, vault secrets |
| **Nginx** | ~8 | server_tokens on, autoindex on, no rate limiting, weak SSL |
| **CloudFormation** | ~8 | hardcoded secrets, public S3, no encryption, wildcard IAM |
| **Azure** | ~8 | hardcoded connection strings, public blobs, HTTP endpoints |
| **Redis** | ~5 | no requirepass, bind 0.0.0.0, KEYS command in production |
| **Vault** | ~5 | disable_mlock, plaintext secrets, dev mode in production |
| **Prometheus** | ~5 | no auth, exposed metrics, cardinality bombs |
| **systemd** | ~5 | ExecStart with curl\|sh, no User directive, PermissionsStartOnly |
| **Docker Compose** | ~8 | privileged, network_mode host, no mem_limit, .env in build |
| **GitHub Actions** | ~8 | secrets in logs, no pinned actions, script injection, self-hosted runners |
| **Config Hygiene** | ~10 | TODO/HACK/FIXME, console.log, print(), Any type, wildcard imports |

**Key function:** `get_all_rules() -> list[dict]` — returns all compiled rules. Used by StaticAnalyzer, MCP server, and CLI.

#### src/rules/enterprise.py (~250 lines)

**Enterprise Structure Rules**

File-level and project-level checks (not line-by-line regex):

- Missing README.md, LICENSE, .gitignore
- Missing copyright headers
- Files > 500 lines (WARN), > 1000 lines (BLOCK)
- Functions > 40 lines
- Directories > 5 levels deep
- Missing test files for source modules
- Missing type annotations on public functions
- Missing docstrings on public classes/functions

**Key function:** `get_enterprise_rules() -> list[dict]` — returns enterprise rule definitions.

#### src/rules/signatures.py (~2,678 lines)

**Curated Function Signature Database**

**Purpose:** Detect hallucinated function calls — when AI generates code calling functions with wrong parameters, wrong return types, or functions that don't exist.

**Structure:** Dictionary mapping `module.function` → `SignatureSpec`:

- `params: list[ParamSpec]` — expected parameters with names, types, default values, required flags
- `return_type: str` — expected return type
- `deprecated: bool` — whether the function is deprecated
- `deprecated_since: str | None` — version when deprecated
- `replacement: str | None` — suggested replacement
- `min_args: int`, `max_args: int` — argument count bounds

**Coverage:**

**Python modules (24):**
`os`, `os.path`, `sys`, `json`, `re`, `datetime`, `collections`, `itertools`, `functools`, `pathlib`, `subprocess`, `hashlib`, `hmac`, `secrets`, `typing`, `dataclasses`, `asyncio`, `urllib.parse`, `http.client`, `sqlite3`, `logging`, `csv`, `math`, `shutil`

**JS/TS modules (17):**
`Array.prototype`, `String.prototype`, `Object`, `Math`, `JSON`, `Promise`, `Date`, `Map`, `Set`, `RegExp`, `console`, `fs`, `path`, `crypto`, `http`, `url`, `Buffer`

**Total: 209 individual function signatures** with full parameter validation.

#### src/rules/license_guard.py (~100 lines)

**License Validation Guard**

- Validates that the LICENSE file exists and matches expected content
- Checks copyright year is current
- Verifies license type matches `pyproject.toml` declaration
- Used in API startup and release security gate

---

### 4.5 FORMATTERS

#### src/formatters/**init**.py

Package marker.

#### src/formatters/sarif.py (~250 lines)

**SARIF v2.1.0 Output Formatter**

Class `SARIFFormatter`:

- `format(findings: list[Finding], tool_name: str = "CodeTrust") -> dict` — convert findings to SARIF
- Produces valid SARIF 2.1.0 JSON with:
  - `$schema`, `version`, `runs[0].tool.driver` (name, version, rules)
  - `runs[0].results` — each finding mapped to a SARIF result with level, message, location
  - Rule metadata with `helpUri`, `shortDescription`, `fullDescription`
- Severity mapping: BLOCK → error, WARN → warning, INFO → note
- Used by CLI (`--format sarif`), API (`/v1/scan/sarif`), and GitHub Action

---

### 4.6 GATEWAY

#### src/gateway/**init**.py

Package marker.

#### src/gateway/server.py (~980 lines)

**MCP Gateway Server** via FastMCP. 17 gateway tools:

**Interception tools (4):**

1. **`validate_command`** — Check terminal command before execution. Returns ALLOW/WARN/BLOCK.
2. **`validate_file_write`** — Check file path + content before writing. Detects secrets, eval, protected files.
3. **`validate_file_delete`** — Check file path before deletion. Protects critical files.
4. **`validate_package`** — Check package name before installation. Blocks suspicious/typosquatted packages.

**Proxy tools (4):**
5. **`run_in_terminal`** — Proxy for native `run_in_terminal`. Validates command first, then returns APPROVED/BLOCKED.
6. **`create_file`** — Proxy for native `create_file`. Validates content first.
7. **`replace_string_in_file`** — Proxy for native `replace_string_in_file`. Validates new content.
8. **`edit_notebook`** — Proxy for native `edit_notebook_file`.

**Utility tools (9):**
9. **`governance_status`** — Show active governance config from `.codetrust.toml`.
10. **`list_gateway_rules`** — List all 82 gateway interception rules.
11. **`audit_history`** — Query `.codetrust/audit.jsonl` by hours/verdict/limit.
12. **`begin_trusted_session`** — Issue trusted execution session token.
13. **`approve_action`** — Approve high-risk action with approver role metadata.
14. **`list_exceptions`** — List active time-bound exceptions.
15. **`revoke_exception`** — Revoke exception by ID with actor tracking.
16. **`simulate_policy`** — Simulate bundle policies across candidate commands.
17. **`governance_posture`** — Snapshot control-plane posture and enforcement readiness.

**Configuration:** Reads `.codetrust.toml` for mode (enforce/audit/off), custom blocked commands, protected paths.

#### src/gateway/interceptor.py (~1,021 lines)

**Core Interception Engine**

Class `CommandInterceptor`:

- `check_command(command: str) -> GatewayResult` — evaluate terminal command
- `check_content(path: str, content: str) -> GatewayResult` — evaluate file content
- `check_package(name: str, registry: str) -> GatewayResult` — evaluate package install
- `check_delete(path: str) -> GatewayResult` — evaluate file deletion

**82 Gateway Rules:**

**Terminal command patterns (~50):**

- BLOCK: `heredoc (<<)`, `eval`, `exec`, `curl|sh`, `wget|sh`, `rm -rf /`, `chmod 777`, `git push`, `git push --force`, `sudo su`, `sudo -i`, `dd of=`, `mkfs`, `:(){:|:&};:` (fork bomb), `nohup` with redirect, `>(` process substitution
- BLOCK: `npm publish`, `pip upload`, `docker push` (prevent accidental publishes)
- BLOCK: `kill -9 1`, `shutdown`, `reboot`, `init 0`
- WARN: `sudo` (general), `docker run --privileged`, `--no-verify` (git), `--skip-ci`

**Content write rules (~15):**

- BLOCK: Hardcoded AWS keys (`AKIA...`), GitHub tokens (`ghp_...`), Stripe keys (`sk_live_...`), private keys (`BEGIN.*PRIVATE KEY`), generic passwords/secrets
- BLOCK: `eval()`, `exec()`, `Function()` constructor
- WARN: Writing to `.env`, `.env.production`, `LICENSE`

**Package rules (~11):**

- BLOCK: Known malicious packages (e.g., `event-stream` compromised version)
- WARN: Packages with suspicious names (typosquatting detection using Levenshtein distance)

**File deletion rules:**

- BLOCK: `LICENSE`, `.gitignore`, `README.md`, `.env`, `pyproject.toml`, `package.json`
- WARN: Any `.py` or `.ts` source file deletion

**Audit logging:** Every check logged to `.codetrust/audit.jsonl` with timestamp, rule_id, action, context, verdict.

#### src/gateway/rules.py (~200 lines)

**Gateway Rule Definitions**

Structured rule data for the interceptor:

- `TERMINAL_RULES: list[dict]` — pattern, action, message, suggestion, category
- `CONTENT_RULES: list[dict]` — pattern, action, message, applies_to (file extensions)
- `PACKAGE_RULES: list[dict]` — name pattern, action, message
- `DELETE_RULES: list[dict]` — path pattern, action, message
- `PROTECTED_PATHS: list[str]` — paths that trigger WARN on write

---

### 4.7 MIDDLEWARE

#### src/middleware/**init**.py

Package marker.

#### src/middleware/auth.py (~150 lines)

FastAPI middleware/dependencies for authentication:

- `verify_api_key(request: Request) -> User` — dependency that extracts and validates API key
- `require_tier(minimum: SubscriptionTier)` — dependency factory for tier-gated endpoints
- `require_org_role(role: str)` — dependency factory for RBAC checks
- Adds `request.state.user` for downstream use

#### src/middleware/rate_limit.py (~100 lines)

FastAPI middleware for rate limiting:

- Checks per-user rate limit via `RateLimiter` service
- Returns 429 with `Retry-After` header when exceeded
- Skips rate limiting for health check and public endpoints

#### src/middleware/cors.py (~50 lines)

CORS configuration:

- Allowed origins from `Settings.CODETRUST_CORS_ORIGINS`
- Default: `["https://www.codetrust.ai", "https://dashboard.codetrust.ai", "http://localhost:3000"]`
- All methods, credentials allowed, specific headers exposed

#### src/middleware/tenant.py (~100 lines)

Multi-tenant isolation middleware:

- Extracts org_id from JWT claims or API key lookup
- Sets `request.state.org_id` for downstream use
- Ensures all database queries are scoped to the tenant's org

---

### 4.8 UTILS

#### src/utils/**init**.py

Package marker.

#### src/utils/parsers.py (~300 lines)

**Import Extraction & Parsing**

Functions:

- `extract_imports(code: str, language: Language) -> list[str]` — extract import names from code
  - Python: `import x`, `from x import y`, handles relative imports
  - JavaScript/TypeScript: `import ... from 'x'`, `require('x')`, `import('x')`
  - Go: `import "x"`, `import ("x" "y")`
  - Rust: `use x::y`, `extern crate x`
  - Ruby: `require 'x'`, `gem 'x'`
  - PHP: `use X\Y`, `require 'x'`
- `parse_requirements(content: str) -> list[tuple[str, str]]` — parse requirements.txt → (name, version) pairs
- `parse_package_json(content: str) -> list[tuple[str, str]]` — parse package.json dependencies
- `parse_go_sum(content: str) -> list[tuple[str, str]]` — parse go.sum
- `detect_language(filename: str) -> Language` — detect language from file extension
- `is_test_file(filename: str) -> bool` — check if file is a test file

#### src/utils/similarity.py (~100 lines)

**Fuzzy Matching**

Functions:

- `levenshtein_distance(s1: str, s2: str) -> int` — edit distance
- `find_similar(name: str, candidates: list[str], threshold: float = 0.8) -> list[str]` — find similar names
- Used for "did you mean?" suggestions when a package is not found on registry
- Helps detect typosquatting (e.g., `requets` → "Did you mean `requests`?")

#### src/utils/trust_score.py (~150 lines)

**Trust Score Computation**

Functions:

- `compute_trust_score(findings: list[Finding], total_lines: int) -> float` — weighted score 0.0–1.0
- `score_to_grade(score: float) -> str` — letter grade (A+: ≥0.95, A: ≥0.90, B: ≥0.80, C: ≥0.70, D: ≥0.60, F: <0.60)
- `compute_drift(old_findings: list[Finding], new_findings: list[Finding]) -> dict` — drift analysis between two scans
- Weights: BLOCK=1.0, WARN=0.3, INFO=0.1

#### src/utils/file_discovery.py (~100 lines)

**File Discovery**

Functions:

- `discover_files(path: str, language: Language | None, exclude: list[str]) -> list[str]` — find scannable files
- Default exclusions: `.git`, `node_modules`, `__pycache__`, `.venv`, `venv`, `dist`, `build`, `.tox`
- Language-specific extensions: `.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`, `.rb`, `.php`, etc.
- Max file size: 1MB (configurable)

---

### 4.9 TEMPLATES

#### src/templates/

**IDE Instruction Templates** for session-level governance injection:

- `claude.md` — Claude Code instruction template (injected into `.claude/CLAUDE.md`)
- `cursor.md` — Cursor instruction template (injected into `.cursor/rules/codetrust.mdc`)
- `windsurf.md` — Windsurf instruction template (injected into `.windsurf/rules/codetrust.md`)
- `copilot.md` — GitHub Copilot instruction template (injected into `.github/copilot-instructions.md`)

Each template contains:

- Governance protocol (use proxy tools, validate before every action)
- Code quality rules (prohibitions + required practices)
- Git discipline (never push, atomic commits)
- Pre/post action protocols

These are written by `codetrust setup` CLI command and by the VS Code extension's universal IDE injection.

---

## 5. TESTS — tests/

**68+ test files, ~24,000+ lines, ~1,300+ test functions, 1,937 tests collected by pytest.**

### Test Configuration

#### tests/conftest.py (~200 lines)

Shared fixtures:

- `sample_python_code` — Python code with common anti-patterns for testing
- `sample_js_code` — JavaScript code with anti-patterns
- `sample_dockerfile` — Dockerfile with issues
- `mock_redis` — fakeredis fixture (no real Redis needed)
- `mock_httpx` — pytest-httpx fixture for mocking HTTP calls
- `async_client` — FastAPI TestClient
- `settings` — test Settings with overrides
- `db_session` — async database session (SQLite in-memory for tests)

### Test File Map

| File | Tests | Coverage Area |
|------|-------|---------------|
| `test_static.py` | ~50 | StaticAnalyzer — all rule categories, language filtering, trust score |
| `test_ast.py` | ~30 | ASTAnalyzer — structural checks for all supported languages |
| `test_registry.py` | ~40 | RegistryVerifier — all 8 registries, timeout handling, caching |
| `test_docker.py` | ~25 | DockerVerifier — image/tag verification, Dockerfile parsing |
| `test_deep_scan.py` | ~20 | Deep scan orchestration — all layers combined |
| `test_models.py` | ~30 | Pydantic model validation — strict mode, edge cases |
| `test_api_endpoints.py` | ~60 | All 46 FastAPI endpoints — happy path + error cases |
| `test_api_coverage.py` | ~10 | Meta-test ensuring all endpoints have tests |
| `test_cache.py` | ~15 | CacheService — get/set/delete with fakeredis |
| `test_cache_service.py` | ~15 | Extended cache tests — TTL, connection errors |
| `test_similarity.py` | ~10 | Levenshtein distance, fuzzy matching |
| `test_parsers.py` | ~25 | Import extraction for all languages, requirements parsing |
| `test_sarif.py` | ~15 | SARIF formatter — valid output, severity mapping |
| `test_sandbox.py` | ~15 | SandboxRunner — execution, timeout, security |
| `test_billing.py` | ~20 | BillingService — Stripe integration, webhooks |
| `test_database.py` | ~25 | DatabaseService — CRUD, audit logging, GDPR |
| `test_auth_service.py` | ~20 | AuthService — OAuth, JWT, API keys, rate limiting |
| `test_cli.py` | ~40 | CLI commands — all subcommands, output formats |
| `test_cli_commands_extra.py` | ~20 | Extended CLI tests — edge cases, error handling |
| `test_cli_coverage.py` | ~10 | Meta-test ensuring all CLI commands have tests |
| `test_cli_pr_risk.py` | ~15 | PR risk analysis — git diff parsing, scoring |
| `test_gateway.py` | ~30 | CommandInterceptor — all 82 rules, ALLOW/WARN/BLOCK |
| `test_gateway_server.py` | ~25 | Gateway MCP server — all 17 tools |
| `test_custom_rules.py` | ~15 | Custom rule CRUD, pattern validation |
| `test_enterprise_features.py` | ~20 | Enterprise rules, RBAC, org management |
| `test_gdpr.py` | ~15 | GDPR export/delete, data retention |
| `test_dashboard_api.py` | ~20 | Dashboard stats, webhook config |
| `test_github_action.py` | ~15 | Action scan runner, PR mode, annotations |
| `test_e2e_integration.py` | ~15 | End-to-end integration tests |
| `test_devops_rules.py` | ~20 | DevOps/IaC anti-pattern rules |
| `test_batch3_config_rules.py` | ~15 | Config hygiene rules |
| `test_autofix_recipes.py` | ~25 | All 17+3 autofix recipes |
| `test_signature*.py` | ~30 | Signature validation engine, all 209 functions |
| `test_vuln*.py` | ~15 | Vulnerability scanning, OSV API |
| `test_license*.py` | ~15 | License compliance checking |
| `test_cross_file*.py` | ~15 | Cross-file dependency analysis |
| `test_telemetry*.py` | ~10 | Telemetry client, ingestion |
| `test_webhook*.py` | ~10 | Webhook delivery, HMAC signing |
| `test_rate_limit*.py` | ~10 | Rate limiting, sliding window |
| `test_sso*.py` | ~10 | SSO/OIDC integration |
| `test_rule_delivery*.py` | ~10 | Server-side rule delivery, HMAC signing |

### Testing Patterns

- **All external HTTP calls mocked** via `pytest-httpx` — never hits real registries
- **fakeredis** for cache tests — no running Redis required
- **SQLite in-memory** for database tests — no running PostgreSQL required
- **Every public function** has at least happy-path + error-path test
- **Verification pattern:** Tests check findings list length, finding.rule_id, finding.severity, finding.message
- **Asyncio:** All async tests use `@pytest.mark.asyncio` with `pytest-asyncio`

---

## 6. VS CODE EXTENSION — extension/

### Architecture

```
extension/
├── src/
│   ├── extension.ts          # Activation orchestrator (289 lines)
│   ├── embedded-scanner.ts   # Offline scanner engine (1,657 lines)
│   ├── commands.ts           # Command handlers (1,114 lines)
│   ├── api-client.ts         # HTTP client for CodeTrust API (~300 lines)
│   ├── config.ts             # Configuration management (~150 lines)
│   ├── diagnostics.ts        # VS Code diagnostics integration (~200 lines)
│   ├── status-bar.ts         # Status bar management (~100 lines)
│   ├── webview.ts            # Webview panels for reports (~400 lines)
│   ├── copilot-instructions.ts # Universal IDE instruction injection (~250 lines)
│   ├── verification-cache.ts # Scan result cache (~150 lines)
│   └── test/
│       ├── suite/
│       │   └── extension.test.ts  # Mocha tests
│       └── runTest.ts
├── resources/
│   ├── codetrust-instructions.md  # Hardcoded governance instructions
│   └── *.svg                      # UI icons
├── scripts/
│   └── build.js               # esbuild + obfuscation pipeline
├── package.json               # Extension manifest
├── tsconfig.json
└── images/
    └── icon.png               # Extension icon (256x256)
```

### Key Files

#### extension/src/extension.ts (289 lines)

**Activation orchestrator** — entry point for VS Code extension.

`activate(context: ExtensionContext)`:

1. Initialize configuration from VS Code settings
2. Create API client instance
3. Register file watchers (scan-on-save, scan-on-type)
4. Register 11 commands (see commands.ts)
5. Create status bar item
6. Initialize diagnostics collection
7. Inject Copilot instructions (if enabled)
8. Inject universal IDE instructions (Claude, Cursor, Windsurf)
9. Run initial workspace scan (if auto-scan enabled)

`deactivate()`: Cleanup watchers, dispose diagnostics.

#### extension/src/embedded-scanner.ts (1,657 lines)

**Self-contained offline scanner** — works without API connectivity.

67 embedded rules (56 regex + 11 file-level):

**Security (15):** eval/exec, hardcoded secrets (8 patterns), SQL injection, pickle.load, yaml.load, shell injection, path traversal, XXE
**Quality (20):** bare except, wildcard imports, Any type, TODO/HACK, console.log, print(), magic numbers, nested ternary, mutable defaults, string concat URLs, long functions, deep nesting
**Hallucination (12):** Non-existent Python modules (6), non-existent JS/TS APIs (6)
**DevOps (9):** chmod 777, curl|sh, rm -rf, heredoc, docker --privileged, exposed secrets in CI
**File-level (11):** Missing copyright, file too long (>500 lines), missing docstring, missing type annotations

Key class `EmbeddedScanner`:

- `scan(document: TextDocument) -> Finding[]` — scan single document
- `scanWorkspace() -> Map<string, Finding[]>` — scan all workspace files
- `computeTrustScore(findings, lineCount) -> number` — trust score
- No VS Code API dependency — pure TypeScript, can run in any context

#### extension/src/commands.ts (1,114 lines)

**11 Command Handlers:**

1. **`codetrust.scanFile`** — Scan current file (API-first, offline fallback)
2. **`codetrust.scanWorkspace`** — Scan entire workspace
3. **`codetrust.healthCheck`** — Verify API connectivity + extension config
4. **`codetrust.showReport`** — Open webview with detailed scan report
5. **`codetrust.quickFix`** — Apply autofix recipe for a finding
6. **`codetrust.verifyImports`** — Verify imports in current file
7. **`codetrust.showRules`** — List all available rules
8. **`codetrust.openSettings`** — Open extension settings
9. **`codetrust.trustScore`** — Show trust score for workspace
10. **`codetrust.generateConfig`** — Create `.codetrust.toml`
11. **`codetrust.injectInstructions`** — Manually trigger IDE instruction injection

**Pattern:** Every command tries API first → falls back to embedded scanner on failure.

#### extension/src/copilot-instructions.ts (~250 lines)

**Universal IDE Instruction Injection**

Function `injectInstructions(workspaceRoot: string)`:

1. Detect which IDEs are in use (check for `.claude/`, `.cursor/`, `.windsurf/`, `.github/`)
2. For each detected IDE, write governance instructions to the appropriate config file:
   - Claude Code: `.claude/CLAUDE.md`
   - Cursor: `.cursor/rules/codetrust.mdc`
   - Windsurf: `.windsurf/rules/codetrust.md`
   - GitHub Copilot: `.github/copilot-instructions.md`
3. Instructions sourced from `resources/codetrust-instructions.md`
4. Non-destructive: appends CodeTrust section with markers, preserves existing content
5. Called on extension activation and on-demand via command

#### extension/src/api-client.ts (~300 lines)

**HTTP Client for CodeTrust API**

Class `APIClient`:

- `scan(code, language, filename) -> ScanResponse`
- `deepScan(code, language) -> ScanResponse`
- `verifyImports(code, language) -> ImportVerifyResponse`
- `suggestFix(code, language, ruleId) -> FixSuggestion[]`
- `applyFix(code, recipeId, language) -> FixApplyResult`
- `healthCheck() -> boolean`
- Base URL from settings, API key from settings
- Timeout: 30s, retry: 1
- Error handling: returns null on failure (triggers offline fallback)

#### extension/package.json

**Extension manifest:**

- Name: `codetrust`
- Display Name: "CodeTrust — AI Code Verification"
- Version: `2.7.0`
- Publisher: `SaidBorna`
- Engines: `vscode ^1.85.0`
- Activation events: `onStartupFinished`
- 11 commands registered
- Configuration contributes: `codetrust.apiKey`, `codetrust.apiUrl`, `codetrust.scanOnSave`, `codetrust.scanOnType`, `codetrust.autoInjectInstructions`, `codetrust.severityFilter`, `codetrust.excludePatterns`

#### extension/scripts/build.js

**Build pipeline:**

1. `esbuild` bundle to `dist/extension.js` (CommonJS, Node platform, external: vscode)
2. `javascript-obfuscator` on the bundle (IP protection):
   - `compact: true`, `controlFlowFlattening: true`
   - `deadCodeInjection: true`, `stringArrayEncoding: ['rc4']`
   - `selfDefending: true`, `debugProtection: true`
3. Source maps disabled in production
4. Output: single obfuscated `extension.js` file

---

## 7. DASHBOARD — dashboard/

### Architecture

```
dashboard/
├── app/
│   ├── layout.tsx           # Root layout with providers
│   ├── page.tsx             # Landing page
│   ├── login/page.tsx       # NextAuth login
│   ├── pricing/page.tsx     # Stripe pricing plans
│   ├── dashboard/
│   │   ├── page.tsx         # Dashboard home (stats, charts)
│   │   ├── api-keys/page.tsx    # API key management
│   │   ├── governance/page.tsx  # Governance audit viewer
│   │   └── settings/page.tsx    # User settings
│   └── api/
│       ├── auth/[...nextauth]/route.ts  # NextAuth handler
│       └── stripe/webhook/route.ts      # Stripe webhook
├── src/
│   ├── components/
│   │   ├── Header.tsx       # Navigation header
│   │   ├── Footer.tsx       # Footer
│   │   ├── Sidebar.tsx      # Dashboard sidebar
│   │   ├── StatsCard.tsx    # Metric card component
│   │   ├── FindingsTable.tsx # Findings data table
│   │   ├── TrustScoreChart.tsx # Trust score visualization
│   │   └── PricingCard.tsx  # Pricing plan card
│   ├── lib/
│   │   ├── auth.ts          # NextAuth config (GitHub OAuth)
│   │   ├── prisma.ts        # Prisma client singleton
│   │   ├── stripe.ts        # Stripe client
│   │   └── api-client.ts    # CodeTrust Python API client
│   └── types/
│       └── index.ts         # TypeScript type definitions
├── prisma/
│   └── schema.prisma        # Database schema
├── e2e/
│   └── *.spec.ts           # Playwright e2e tests
├── package.json
├── next.config.js
├── tailwind.config.ts
├── tsconfig.json
└── vitest.config.ts
```

### Key Files

#### dashboard/prisma/schema.prisma

**Database schema** (PostgreSQL):

- **User**: id, name, email, emailVerified, image, apiKey, subscriptionTier, stripeCustomerId
- **Account**: OAuth account linking (NextAuth)
- **Session**: Session management (NextAuth)
- **VerificationToken**: Email verification (NextAuth)

#### dashboard/src/lib/auth.ts

NextAuth 4 configuration:

- Provider: GitHub OAuth (`GITHUB_ID`, `GITHUB_SECRET`)
- Adapter: Prisma
- Session strategy: JWT
- Callbacks: session (adds user.id, user.apiKey, user.tier)

#### dashboard/src/lib/api-client.ts

Client for the Python backend API:

- `getScanStats(apiKey) -> DashboardStats`
- `getGovernanceAudit(apiKey, hours) -> AuditEntry[]`
- `getSubscription(apiKey) -> Subscription`
- Base URL: `NEXT_PUBLIC_API_URL` or `https://api.codetrust.ai`

#### Dashboard Pages

- **Landing** (`/`): Marketing page with hero, features, CTA
- **Login** (`/login`): GitHub OAuth sign-in
- **Pricing** (`/pricing`): 3 plans (Free/Pro/Enterprise) with Stripe checkout
- **Dashboard Home** (`/dashboard`): Scan stats, finding trends, trust score chart, recent scans
- **API Keys** (`/dashboard/api-keys`): Generate/revoke API keys, usage stats
- **Governance** (`/dashboard/governance`): Audit log viewer with filtering, finding details
- **Settings** (`/dashboard/settings`): Profile, notification preferences, subscription management

---

## 8. GITHUB ACTION — action/

### action/action.yml

**Composite GitHub Action** — "CodeTrust Scan"

- Uses: Python 3.12
- Inputs: `api-url`, `api-key`, `files`, `fail-on` (block/warn/never), `scan-type` (static/deep), `language`, `sarif`
- Outputs: `verdict`, `total-findings`, `blocks`, `report`, `sarif-file`
- Auto-detects changed files via `git diff` against PR base or HEAD~1

### action/scan_runner.py (929 lines)

**Advanced CI scan runner** — full-featured version:

- File discovery with language-specific globs and exclusions
- Static analysis via `StaticAnalyzer`
- Governance scanning via `CommandInterceptor` content rules
- Import verification against live registries
- PR-mode: extract base SHA from event payload, compute git diff, gate on **new findings only**
- PR commenting: upsert GitHub PR comments with stable HTML markers
- Trust score computation
- SARIF output generation
- GitHub Actions annotations (`::error::`, `::warning::`)
- Step summary to `GITHUB_STEP_SUMMARY`
- Outputs to `GITHUB_OUTPUT`
- Configurable failure: `--fail-on block/warn/never`, `--new-findings-only auto/always/never`

### action/scan.py (287 lines)

**Simple, self-contained CI scanner** — works without full `src/` package:

- 5 BLOCK rules + 6 WARN rules embedded inline
- Supports local scanning (embedded rules) and API scanning (via httpx)
- Markdown report generation
- Telemetry to `/v1/telemetry`
- Excludes test files from BLOCK enforcement

---

## 9. SCRIPTS — scripts/

| File | Lines | Purpose |
|------|-------|---------|
| `build_compiled.py` | 340 | Cython compilation pipeline for IP protection. Compiles `.py` → `.so`/`.pyd`. Creates wheel with only compiled extensions. |
| `export_openapi.py` | 20 | Export OpenAPI spec from FastAPI → `docs/openapi.json` |
| `generate_icons.py` | 93 | Generate PNG icons from inline SVG (shield + logo) using cairosvg |
| `generate_metrics.py` | 146 | Count rules/tools/endpoints/tests → `metrics.json`. Used to validate README. |
| `release_security_gate.py` | 402 | 9 pre-release security gates (S1-S9): sdist blocked, copyright headers, no source maps, minified output, license guard, CLA, no secrets, production mode, server-side rules |
| `validate_readme_metrics.py` | 62 | Compare README numbers vs `metrics.json`. Fails CI on mismatch. |
| `verify_publish.py` | 181 | Post-publish verification: wheel size, file count, entry points, integrity markers, PyPI vs local comparison |
| `scan_all_projects.py` (root) | 118 | Batch scan all projects under `~/Desktop/DevOps/` and `~/Desktop/Portfolios/` via API |

---

## 10. DATABASE & MIGRATIONS — alembic/

### Configuration

- `alembic.ini` — Alembic config, `sqlalchemy.url` from env var `CODETRUST_DATABASE_URL`
- `alembic/env.py` — Migration environment, imports all models from `src/models/database.py`, async engine support

### Migration History

| Revision | Description |
|----------|-------------|
| Initial | Create users, scan_records tables |
| +orgs | Add organizations, team_members tables |
| +billing | Add stripe_customer_id, subscription fields |
| +custom_rules | Add custom_rules table |
| +audit | Add audit_log table |
| +webhooks | Add webhook_config table |
| +gdpr | Add GDPR-related fields (consent, data_exported_at) |

All migrations are reversible with downgrade functions.

---

## 11. DEPLOY & INFRASTRUCTURE

### Docker

#### Dockerfile

```
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml .
RUN pip install --no-cache-dir .
COPY src/ src/
COPY alembic/ alembic/
COPY alembic.ini .
EXPOSE 8000
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
```

#### docker-compose.yml

3 services:

- `api`: The CodeTrust API (port 8000)
- `postgres`: PostgreSQL 16 (port 5432)
- `redis`: Redis 7 (port 6379)
Volumes for data persistence. Environment from `.env`.

### Railway

#### railway.toml

```toml
[build]
builder = "dockerfile"
dockerfilePath = "Dockerfile"

[deploy]
healthcheckPath = "/health"
healthcheckTimeout = 30
restartPolicyType = "on_failure"
```

#### Procfile

```
web: uvicorn src.api:app --host 0.0.0.0 --port $PORT
```

### Sandbox Docker Images

Located in `sandbox/`:

- `sandbox/python/Dockerfile` — Python 3.12-slim, no pip, no network
- `sandbox/node/Dockerfile` — Node 20-slim, no npm, no network
- `sandbox/go/Dockerfile` — Go 1.21-alpine, no network
- `sandbox/rust/Dockerfile` — Rust 1.74-slim, no cargo, no network

All sandbox images: read-only filesystem, 256MB memory limit, no-new-privileges.

### CI/CD — GitHub Actions

4 workflows in `.github/workflows/`:

1. **`ci.yml`** — Main CI: lint (ruff), test (pytest), coverage check, metrics validation, security gate
2. **`publish.yml`** — PyPI publish: build wheel, publish to PyPI, post-publish verification
3. **`extension.yml`** — Extension CI: npm install, build, test, package .vsix
4. **`dashboard.yml`** — Dashboard CI: npm install, build, test (Vitest + Playwright)

### Hooks

#### hooks/pre-commit

Git pre-commit hook:

- Runs `ruff check` on staged `.py` files
- Runs `codetrust scan` on staged files (with `--fail-on block`)
- Blocks commit if any BLOCK findings

---

## 12. DOCUMENTATION — docs/

| File | Purpose |
|------|---------|
| `index.html` (1,644 lines) | Main marketing website — full single-page site with live telemetry, 4 moats, architecture flow, 286 rules grid, 5 install methods |
| `style.css` (2,744 lines) | Dark theme design system — CSS variables, animations, responsive |
| `demo.html` (1,247 lines) | Interactive browser-based scanner demo — 27 embedded rules, AI Drift Score |
| `404.html` | Custom 404 error page |
| `openapi.json` (3,361 lines) | OpenAPI 3.1.0 spec — all 60 endpoints documented |
| `llms.txt` | AI model discovery file for crawlers |
| `feed.xml` | RSS feed with 4 release items |
| `sitemap.xml` | 7 URLs for search engines |
| `robots.txt` | Allows all crawlers including AI bots |
| `tos.html` | Terms of Service — 12 sections, Swedish jurisdiction |
| `CODETRUST_OVERVIEW.md` | One-page product overview (investor/press quality) |
| `RELEASE_CHECKLIST.md` (168 lines) | 13-step + 7 IP gates release procedure |
| `roadmap.md` | 7-phase implementation roadmap (all complete) |
| `backlog-status.md` | Feature backlog with implementation status |
| `compliance/soc2-controls.md` | SOC 2 Trust Service Criteria mapping |
| `pack/investor-one-pager.md` | Investor/customer one-pager |
| `pack/beta-testers.md` | Beta tester guide |
| `pack/enterprise-security.md` | Enterprise procurement overview |
| `pack/RELEASE_NOTES.md` | External-facing release notes |
| `_generate_pdf.py` | Convert overview to A4 PDF |

### Website Features

- **Live telemetry dashboard** — WebSocket (`wss://api.codetrust.ai/v1/stats/live`) with polling fallback
- **SEO** — Open Graph, Twitter Card, JSON-LD (SoftwareApplication, FAQPage), canonical URL
- **WebMCP** — `navigator.modelContext` imperative API for AI discovery
- **Dark theme** — indigo/green color scheme, noise texture overlay, floating parallax orbs
- **Interactive demo** — client-side scanning with 27 rules, live trust score

---

## 13. ROOT CONFIGURATION FILES

| File | Purpose |
|------|---------|
| `pyproject.toml` | v2.7.0, hatchling build, 24 runtime deps, 4 entry points, sdist excluded |
| `Dockerfile` | Python 3.12-slim production image |
| `docker-compose.yml` | 3-service stack (api + postgres + redis) |
| `railway.toml` | Railway deployment config |
| `Procfile` | `web: uvicorn src.api:app` |
| `alembic.ini` | Database migration config |
| `.env.example` | All required env vars documented |
| `.gitignore` | Standard Python + Node ignores |
| `README.md` | Full product README with badges, install, usage |
| `CHANGELOG.md` | Version history from v1.0.0 to v2.7.0 |
| `LICENSE` | Proprietary license |
| `PLAN.md` | 4-phase build plan with acceptance criteria |
| `SPEC.md` | Technical specification document |
| `PRODUCT.md` | Product strategy and positioning |
| `PITCH.md` | Investor pitch document |
| `COMPARISON.md` | Competitive comparison matrix |
| `SECURITY.md` | Security policy and disclosure process |
| `CONTRIBUTING.md` | Contribution guidelines (CLA required) |
| `CLA.md` | Contributor License Agreement |
| `IP_HANDOVER.md` | IP ownership documentation |
| `TEST_EVIDENCE.md` | Test coverage evidence for auditors |
| `SESSION_LOG.md` | AI agent session checkpoints |
| `CLAUDE.md` | Project-specific agent rules |
| `metrics.json` | Auto-generated metrics (rules, tools, tests counts) |
| `codetrust-results.sarif` | Sample SARIF output |
| `codetrust-report.md` | Sample scan report |
| `setup.sh` | Quick development setup script |
| `smoke_test.sh` | Post-deploy smoke test |
| `scan_all_projects.py` | Batch scanner for local projects |

### pyproject.toml — Key Details

```toml
[project]
name = "codetrust"
version = "2.7.0"
requires-python = ">=3.12"

[project.scripts]
codetrust = "src.cli:main"
codetrust-mcp = "src.server:main"
codetrust-gateway-mcp = "src.gateway.server:main"
codetrust-api = "src.api:main"

[tool.hatch.build.targets.sdist]
exclude = ["*"]  # IP protection: no source distribution

[tool.hatch.build.targets.wheel]
packages = ["src"]
```

**24 runtime dependencies:** fastapi, uvicorn, mcp[cli], pydantic, pydantic-settings, httpx, redis, sqlalchemy[asyncio], asyncpg, alembic, stripe, pyjwt, structlog, tree-sitter, tree-sitter-languages, click, rich, jinja2, python-multipart, cryptography, python-jose, aiofiles, websockets, toml

---

## 14. KEY INTERCONNECTIONS

### Data Flow: Scan Request

```
Client (CLI/Extension/Action/API)
  → src/api.py (HTTP endpoint)
    → src/services/static_analyzer.py (Layer 1: regex rules)
    → src/services/ast_analyzer.py (Layer 3: tree-sitter AST)
    → src/services/signature_engine.py (Layer 3b: function signatures)
    → src/services/import_verifier.py (Layer 2: registry checks)
      → src/services/registry.py (8 registry clients)
      → src/services/cache.py (Redis caching)
    → src/services/docker_verify.py (Layer 2b: Docker Hub)
    → src/utils/trust_score.py (score computation)
  → src/models/responses.py (ScanResponse)
  → src/formatters/sarif.py (optional SARIF output)
```

### Data Flow: Gateway Interception

```
AI Agent (Claude/Cursor/Windsurf/Copilot)
  → src/gateway/server.py (MCP tool call)
    → src/gateway/interceptor.py (rule matching)
      → src/gateway/rules.py (82 rules)
    → .codetrust/audit.jsonl (audit log)
  → APPROVED / BLOCKED / WARN response
```

### Data Flow: Authentication

```
User → GitHub OAuth → src/services/auth_service.py
  → src/services/database.py (User lookup/create)
  → JWT generation → Returned to client

API Request → X-API-Key header → src/middleware/auth.py
  → src/services/auth_service.py (key validation)
  → src/services/rate_limiter.py (rate check)
  → request.state.user populated
```

### Data Flow: Billing

```
User → /v1/billing/checkout → src/services/billing.py
  → Stripe Checkout Session → Redirect to Stripe
  → Stripe Webhook → /v1/billing/webhook
    → src/services/billing.py (handle_webhook)
    → src/services/database.py (update subscription tier)
```

### Entry Points → Modules

| Entry Point | Imports From |
|-------------|-------------|
| `src/cli.py` | config, services/*, rules/*, utils/*, formatters/*, models/* |
| `src/api.py` | config, services/*, models/*, middleware/*, formatters/* |
| `src/server.py` | config, services/*, rules/*, models/*, formatters/* |
| `src/gateway/server.py` | gateway/interceptor, gateway/rules, config |
| `action/scan_runner.py` | services/static_analyzer, gateway/interceptor, services/import_verifier, formatters/sarif, utils/* |

---

## 15. QUICK REFERENCE TABLES

### All API Endpoints (46)

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/health` | No | Health check |
| POST | `/v1/scan/static` | Yes | Static analysis |
| POST | `/v1/scan/ast` | Yes | AST analysis |
| POST | `/v1/scan/signature` | Yes | Signature validation |
| POST | `/v1/scan/deep` | Yes | Full multi-layer scan |
| POST | `/v1/scan/sarif` | Yes | Scan with SARIF output |
| POST | `/v1/verify/imports` | Yes | Import verification |
| POST | `/v1/verify/dockerfile` | Yes | Dockerfile verification |
| POST | `/v1/sandbox/run` | Yes | Sandboxed execution |
| GET | `/v1/rules` | Yes | List rules |
| GET | `/v1/rules/download` | Yes | HMAC-signed rule delivery |
| POST | `/v1/fix/suggest` | Yes | Suggest autofixes |
| POST | `/v1/fix/apply` | Yes | Apply autofix recipe |
| POST | `/v1/auth/github` | No | GitHub OAuth |
| POST | `/v1/auth/token` | No | JWT generation |
| GET | `/v1/auth/me` | Yes | Current user |
| POST | `/v1/billing/checkout` | Yes | Stripe checkout |
| POST | `/v1/billing/webhook` | No* | Stripe webhook |
| GET | `/v1/billing/subscription` | Yes | Subscription status |
| GET | `/v1/dashboard/stats` | Yes | Dashboard statistics |
| POST | `/v1/vuln/scan` | Yes | Vulnerability scan |
| POST | `/v1/license/scan` | Yes | License compliance |
| POST | `/v1/cross-file/analyze` | Yes | Cross-file analysis |
| GET | `/v1/governance/audit` | Yes | Audit log query |
| POST | `/v1/custom-rules` | Yes | Create custom rule |
| GET | `/v1/custom-rules` | Yes | List custom rules |
| PUT | `/v1/custom-rules/{id}` | Yes | Update custom rule |
| DELETE | `/v1/custom-rules/{id}` | Yes | Delete custom rule |
| GET | `/v1/stats/public` | No | Public statistics |
| WS | `/v1/stats/live` | No | Live stats WebSocket |
| POST | `/v1/telemetry` | No | Telemetry ingestion |
| POST | `/v1/orgs` | Yes | Create organization |
| GET | `/v1/orgs/{id}` | Yes | Get organization |
| PUT | `/v1/orgs/{id}` | Yes | Update organization |
| DELETE | `/v1/orgs/{id}` | Yes | Delete organization |
| POST | `/v1/orgs/{id}/members` | Yes | Add team member |
| GET | `/v1/orgs/{id}/members` | Yes | List members |
| PUT | `/v1/orgs/{id}/members/{uid}` | Yes | Update member role |
| DELETE | `/v1/orgs/{id}/members/{uid}` | Yes | Remove member |
| POST | `/v1/orgs/{id}/invite` | Yes | Send invite |
| POST | `/v1/gdpr/export` | Yes | GDPR data export |
| DELETE | `/v1/gdpr/delete` | Yes | GDPR data deletion |
| POST | `/v1/sso/oidc/callback` | No | SSO/OIDC callback |
| GET | `/v1/webhook/config` | Yes | Get webhook config |
| PUT | `/v1/webhook/config` | Yes | Update webhook config |
| POST | `/v1/webhook/test` | Yes | Test webhook delivery |

### All MCP Tools (21)

**Scanner Server (10):**
`static_scan`, `pre_action`, `post_action`, `list_rules`, `verify_imports`, `verify_dockerfile`, `ast_scan`, `sandbox_run`, `sarif_export`, `deep_scan`

**Gateway Server (11):**
`validate_command`, `validate_file_write`, `validate_file_delete`, `validate_package`, `run_in_terminal`, `create_file`, `replace_string_in_file`, `edit_notebook`, `governance_status`, `list_gateway_rules`, `audit_history`

### All CLI Commands (20+)

`init`, `setup`, `add`, `scan`, `fix`, `vuln`, `license`, `status`, `doctor`, `pr-risk`, `trust-diff`, `trend`, `governance`, `policy`, `audit`, `cross-file`, `report`, `config`, `auth`, `upgrade`

### File Size Reference (largest files)

| File | Lines | Purpose |
|------|-------|---------|
| `src/cli.py` | 4,359 | CLI entry point |
| `docs/openapi.json` | 3,361 | OpenAPI spec |
| `docs/style.css` | 2,744 | Website stylesheet |
| `src/rules/signatures.py` | 2,678 | Function signature DB |
| `src/api.py` | 2,680 | HTTP API server |
| `src/rules/anti_patterns.py` | 1,676 | Anti-pattern rules |
| `extension/src/embedded-scanner.ts` | 1,657 | Offline scanner |
| `docs/index.html` | 1,644 | Marketing website |
| `docs/demo.html` | 1,247 | Interactive demo |
| `src/server.py` | 1,205 | MCP scanner server |
| `extension/src/commands.ts` | 1,114 | Extension commands |
| `src/gateway/interceptor.py` | 1,021 | Gateway interceptor |
| `action/scan_runner.py` | 929 | CI scan runner |

### Version History (Major)

| Version | Key Features |
|---------|-------------|
| v1.0.0 | Initial release — static analysis, CLI, basic rules |
| v2.0.0 | MCP server, AST analysis, import verification |
| v2.3.0 | VS Code extension, scan-on-save/type, trust score |
| v2.4.0 | 275 rules, Ruby/PHP, Maven/NuGet, IaC rules |
| v2.5.0 | Enterprise: RBAC, billing, GDPR, dashboard |
| v2.6.0 | AI Governance Gateway (76 rules), MCP proxy tools, Guardian |
| v2.6.1 | Signature engine (209 functions), 17 autofix recipes, demo |
| v2.7.0 | Signature hardening, autofix fixes, JWT/WebSocket/OIDC/CORS security, 1,898 tests, 280 rules, 46 endpoints, 21 MCP tools |
| v2.8.0 | Ultimate governance sprint, trusted sessions/approvals/exceptions/simulation/posture, multi-workspace + unified session-token, MCP auto-injection hardening, 1,937 tests, 286 rules, 60 endpoints, 27 MCP tools |
| v2.8.1 | MCP global runtime hardening across new workspaces, injected tool-name alignment to `mcp_codetrust-gat_codetrust_*`, billing error sanitization hardening |

---

> **End of CODEBASE_KNOWLEDGE.md** — This file contains everything needed to bootstrap a new session with complete CodeTrust codebase knowledge.
