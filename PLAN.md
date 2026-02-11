# PLAN.md — CodeTrust Build Plan

> **Rule: Build one phase at a time. Each phase must pass its acceptance criteria before starting the next.**

---

## Phase 1 — Foundation & Static Analysis (Layer 1) ✅

**Goal:** Working project skeleton with static analysis engine migrated from Guardian v1.

### Steps

1. **Create project structure** — All directories and `__init__.py` files as defined in CLAUDE.md
2. **Create `pyproject.toml`** with all dependencies
3. **Create `src/config.py`** — Settings class with all config values from SPEC.md §4
4. **Create `src/models/enums.py`** — All enums from SPEC.md §1
5. **Create `src/models/responses.py`** — Finding, StaticScanResponse from SPEC.md §2
6. **Create `src/models/requests.py`** — StaticScanRequest, PreActionInput, MidActionInput, PostActionInput from SPEC.md §3
7. **Create `src/rules/anti_patterns.py`** — All rules from SPEC.md §8
8. **Create `src/rules/enterprise.py`** — Required/recommended files lists (migrate from Guardian v1)
9. **Create `src/services/static_analyzer.py`** — Migrate and refactor from Guardian v1 server.py:
   - `scan_code()` — regex engine
   - `check_repo_structure()` — file/dir checks
   - `build_report()` — markdown formatter
10. **Create `src/server.py`** — MCP server with Layer 1 tools only:
    - `codetrust_static_scan`
    - `codetrust_pre_action`
    - `codetrust_post_action`
    - `codetrust_list_rules`
11. **Create `tests/test_static.py`** — Tests for static analyzer
12. **Create `tests/test_models.py`** — Tests for Pydantic models
13. **Create `.env.example`**, `.gitignore`, `README.md`, `LICENSE` (MIT), `Dockerfile`

### Acceptance Criteria

```bash
# All must pass before Phase 2
ruff check src/                          # Zero warnings
pytest tests/test_static.py -v           # All pass
pytest tests/test_models.py -v           # All pass
python -m src.server                     # MCP server starts without error (ctrl+C to stop)
python -c "from src.config import settings; print(settings.version)"  # Prints "1.0.0"
```

---

## Phase 2 — Cache + Registry Verification (Layer 2 Core) ✅

**Goal:** Can verify Python and npm packages against real registries with Redis caching.

### Steps

1. **Create `src/services/cache.py`** — Redis cache service (SPEC.md §5a)
   - All methods must gracefully degrade if Redis unavailable
   - Test with `fakeredis`
2. **Create `src/utils/parsers.py`** — Import extraction (SPEC.md §9)
   - `extract_python_imports()`
   - `extract_js_imports()`
   - `parse_requirements_txt()`
   - Include `PYTHON_IMPORT_TO_PACKAGE` mapping
3. **Create `src/utils/similarity.py`** — Fuzzy matching for suggestions
   - Use `difflib.get_close_matches` (no extra dependency needed)
   - Maintain a list of top 500 PyPI packages and top 500 npm packages for matching
4. **Create `src/services/registry.py`** — Registry verification service (SPEC.md §5b)
   - `verify_python_package()` — PyPI check
   - `verify_npm_package()` — npm check
   - `verify_packages()` — concurrent batch verification
   - `_parse_requirements()` — version extraction
   - `_suggest_similar()` — fuzzy suggestions
5. **Create `src/models/requests.py`** — Add VerifyImportsRequest (if not done in Phase 1)
6. **Create `src/models/responses.py`** — Add PackageResult, VerifyImportsResponse
7. **Update `src/server.py`** — Add MCP tool `codetrust_verify_imports`
8. **Create `tests/test_registry.py`** — Mock all HTTP calls with pytest-httpx:
   - Test: known package returns VERIFIED
   - Test: unknown package returns NOT_FOUND with suggestion
   - Test: known package, wrong version returns VERSION_MISMATCH
   - Test: registry timeout returns TIMEOUT
   - Test: cache hit skips HTTP call
   - Test: batch verify runs concurrently
9. **Create `tests/conftest.py`** — Shared fixtures (fakeredis, mock httpx client)

### Acceptance Criteria

```bash
ruff check src/
pytest tests/ -v                         # All pass including new registry tests
# Manual test: python script that verifies ["fastapi", "flask", "nonexistent_pkg_xyz"]
```

---

## Phase 3 — FastAPI + Docker Verification ✅

**Goal:** HTTP API running with auth, plus Docker image verification.

### Steps

1. **Create `src/api.py`** — FastAPI application (SPEC.md §6)
   - Lifespan handler (create/destroy httpx client, cache, services)
   - Auth middleware (X-API-Key header)
   - Endpoints:
     - `GET /v1/status`
     - `POST /v1/verify/imports`
     - `POST /v1/scan/static`
     - `POST /v1/scan/deep`
2. **Create `src/services/docker_verify.py`** — Docker Hub verification (SPEC.md §5c)
   - `verify_image_tag()`
   - `verify_images()` (batch)
   - `_fetch_available_tags()` for suggestions
3. **Update `src/utils/parsers.py`** — Add `parse_dockerfile_from()`
4. **Add endpoint** `POST /v1/verify/dockerfile` to api.py
5. **Update `src/server.py`** — Add MCP tool `codetrust_verify_dockerfile`
6. **Create `tests/test_docker.py`** — Mock Docker Hub API
7. **Create `tests/test_api_endpoints.py`** — Test FastAPI endpoints with TestClient
8. **Create `docker-compose.yml`** — API + Redis for local dev

### Acceptance Criteria

```bash
ruff check src/
pytest tests/ -v                         # All pass
# Start API and test manually:
uvicorn src.api:app --reload
curl http://localhost:8000/v1/status      # Returns {"status": "ok", ...}
curl -X POST http://localhost:8000/v1/verify/imports \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "imports": ["fastapi", "nonexistent_xyz"]}'
# Returns proper VerifyImportsResponse with VERIFIED and NOT_FOUND
```

---

## Phase 4 — Deep Scan + Polish + Deploy ✅

**Goal:** Full deep scan combining all layers, deployed on Railway.

### Steps

1. **Create deep scan orchestrator** in api.py — combines static + imports + docker in one call
2. **Update `src/server.py`** — Add `codetrust_deep_scan` MCP tool that:
   - Runs static analysis (local)
   - If API key set: also verifies imports and Docker images via cloud API
   - Returns combined report
3. **Create `Dockerfile`** — Multi-stage build, runs both MCP server and API
4. **Create Railway deployment config** — `railway.toml` or Procfile
5. **Update README.md** — Full documentation:
   - Quick start (pip install)
   - MCP configuration for Claude Code
   - API usage examples
   - All endpoints documented
6. **Create `CHANGELOG.md`** — v1.0.0 entry
7. **Final test sweep** — Run full test suite, fix any issues
8. **Add structlog** — Replace any remaining print/basic logging with structlog JSON

### Acceptance Criteria

```bash
ruff check src/
pytest tests/ -v --tb=short             # All pass, zero warnings
docker build -t codetrust .             # Builds successfully
docker run -p 8000:8000 codetrust       # API starts and serves requests
# MCP server works in Claude Code config
```

---

## Phase 5 — Go & Rust Registry Support ✅

**Goal:** Extend registry verification to Go modules (proxy.golang.org) and Rust crates (crates.io).

### Steps

1. **Update `src/services/registry.py`** — Add two new verification methods:
   - `verify_go_module(module: str, version: str)` — GET `https://proxy.golang.org/{module}/@latest`
     - 200 → VERIFIED (parse JSON for `Version` field)
     - 404/410 → NOT_FOUND
     - If version specified: GET `https://proxy.golang.org/{module}/@v/{version}.info`
   - `verify_crates_package(crate: str, version: str)` — GET `https://crates.io/api/v1/crates/{crate}`
     - 200 → VERIFIED (parse `crate.max_version`)
     - 404 → NOT_FOUND with fuzzy suggestion
     - Version check: `versions[].num` contains requested version
   - Update `_verify_single()` to route `Language.GO` → `verify_go_module` and `Language.RUST` → `verify_crates_package`
2. **Update `src/utils/parsers.py`** — Add:
   - `extract_go_imports(code: str)` — regex for `import "..."` and `import (...)` blocks, skip stdlib
   - `extract_rust_imports(code: str)` — regex for `use crate_name::...` and `extern crate crate_name`, skip `std`/`core`/`alloc`
   - `parse_go_mod(content: str)` — parse `require (...)` blocks to `{module: version}` dict
   - `parse_cargo_toml(content: str)` — parse `[dependencies]` to `{crate: version}` dict (use `tomllib`)
3. **Update `src/utils/similarity.py`** — Add:
   - `TOP_CRATES_PACKAGES` — top 200+ popular crates.io crates
   - `TOP_GO_MODULES` — top 200+ popular Go modules
   - `suggest_crates_package(crate: str)` — fuzzy match against crates list
   - `suggest_go_module(module: str)` — fuzzy match against Go modules list
4. **Update `src/services/registry.py`** imports to use new similarity functions
5. **Update `src/server.py`** — `_extract_imports()` to handle `Language.GO` and `Language.RUST`
6. **Update `src/api.py`** — `_verify_imports_from_code()` to handle Go and Rust
7. **Add crates.io User-Agent header** — crates.io requires a User-Agent, add to config or hardcode as `CodeTrust/1.0.0`
8. **Write `tests/test_go_rust_registry.py`** — comprehensive tests:
   - Go: known module verified, unknown module not found, version check, timeout
   - Rust: known crate verified, unknown crate not found with suggestion, version check
   - Go import extraction from code
   - Rust import extraction from code
   - `go.mod` parsing
   - `Cargo.toml` parsing
   - Cache hit/miss behavior
   - Batch verification for Go/Rust languages

### Acceptance Criteria

```bash
ruff check src/ tests/
pytest tests/ -v                         # All pass including new Go/Rust tests
# Verify routing works:
# Language.GO packages route to proxy.golang.org
# Language.RUST packages route to crates.io
```

---

## Phase 6 — AST Parsing with tree-sitter (Layer 3) ✅

**Goal:** Deep code analysis via Abstract Syntax Trees instead of regex-only scanning. Enables precise detection of patterns that regex can't reliably catch: unused variables, unreachable code, complexity metrics (cyclomatic, cognitive), call graph analysis.

### Steps

1. **Add dependencies** — `tree-sitter`, `tree-sitter-languages` to `pyproject.toml`
2. **Create `src/services/ast_analyzer.py`** — AST-based analysis service:
   - `parse_code(code: str, language: Language) -> Tree` — parse source into tree-sitter AST
   - `analyze_complexity(tree: Tree) -> list[Finding]` — cyclomatic complexity per function
   - `find_unused_variables(tree: Tree) -> list[Finding]` — variables defined but never referenced
   - `find_unreachable_code(tree: Tree) -> list[Finding]` — code after return/raise/break
   - `find_deep_nesting(tree: Tree, max_depth: int) -> list[Finding]` — nesting > N levels
   - `analyze(code: str, language: Language) -> list[Finding]` — orchestrates all checks
3. **Update `src/server.py`** — Add `codetrust_ast_scan` MCP tool
4. **Update `src/api.py`** — Add `POST /v1/scan/ast` endpoint
5. **Update deep scan** to include AST layer when available
6. **Create `tests/test_ast.py`** — Test AST analysis with known code patterns
7. **Add models** — `AstScanRequest`, `AstScanResponse` to request/response models

### Acceptance Criteria

```bash
ruff check src/ tests/
pytest tests/ -v
# Verify: cyclomatic complexity > 10 is flagged
# Verify: unused variables detected
# Verify: unreachable code after return detected
```

---

## Phase 7 — Sandbox Execution (Layer 4) ✅

**Goal:** Execute code in isolated Docker containers to verify it runs without errors. Catches import errors, syntax errors, and runtime crashes that static analysis misses.

### Steps

1. **Create `src/services/sandbox.py`** — Sandbox execution service:
   - `execute_code(code: str, language: Language, timeout: int) -> SandboxResult` — run code in container
   - Uses Docker SDK (`docker` Python package) or subprocess to `docker run`
   - Strict resource limits: 256MB memory, 10s timeout, no network, read-only filesystem
   - Captures stdout, stderr, exit code
   - Returns structured result with pass/fail/error
2. **Add models** — `SandboxRequest`, `SandboxResult` (exit_code, stdout, stderr, timed_out)
3. **Pre-built images** — `codetrust-sandbox-python:3.12`, `codetrust-sandbox-node:20`
4. **Create `sandbox/` directory** — Dockerfiles for sandbox images
5. **Update `src/server.py`** — Add `codetrust_sandbox_run` MCP tool
6. **Update `src/api.py`** — Add `POST /v1/sandbox/run` endpoint
7. **Security audit** — Ensure no container escape, no network, no persistent storage
8. **Create `tests/test_sandbox.py`** — Test sandbox with known-good and known-bad code
9. **Update deep scan** — Optional sandbox execution layer

### Acceptance Criteria

```bash
ruff check src/ tests/
pytest tests/ -v
docker build -t codetrust-sandbox-python sandbox/python/
# Verify: valid Python code returns exit_code=0
# Verify: syntax error returns exit_code=1 with stderr
# Verify: infinite loop is killed after timeout
# Verify: no network access from sandbox
```

---

## Phase 8 — GitHub Action for CI/CD (Layer 5) ✅

**Goal:** Publish a reusable GitHub Action that runs CodeTrust scans in CI pipelines. Developers add one YAML step and get static analysis + import verification + Docker checks on every PR.

### Steps

1. **Create `action.yml`** — GitHub Action metadata:
   - Inputs: `api-key`, `scan-type` (static/deep/imports/docker), `fail-on` (block/warn), `language`
   - Runs: Composite action using Docker or direct Python
2. **Create `action/entrypoint.sh`** — Entry script that calls CodeTrust API or runs locally
3. **PR comment integration** — Post scan results as PR comment using GitHub API
4. **SARIF output** — Generate SARIF format for GitHub Security tab integration
5. **Create `src/formatters/sarif.py`** — Convert Finding list to SARIF JSON
6. **Create `.github/workflows/test.yml`** — CI workflow for CodeTrust itself
7. **Create `tests/test_sarif.py`** — Test SARIF output format
8. **Documentation** — Usage examples in README, marketplace listing

### Acceptance Criteria

```bash
# Action runs in a test repo
# PR comment shows scan results
# SARIF upload populates GitHub Security tab
# Action fails on BLOCK findings when fail-on=block
```

---

## Phase 9 — Dashboard (Next.js) + Stripe Billing ✅

**Goal:** Web dashboard for managing API keys, viewing scan history, usage analytics, and subscription management via Stripe.

### Steps

1. **Create `dashboard/` directory** — Next.js 14+ project (App Router)
2. **Pages:**
   - `/` — Landing page with pricing
   - `/dashboard` — Scan history, usage charts
   - `/dashboard/api-keys` — API key management (create, revoke, rotate)
   - `/dashboard/settings` — Account settings
   - `/pricing` — Plan comparison (Free, Pro, Enterprise)
3. **Auth** — NextAuth.js with GitHub OAuth
4. **Database** — PostgreSQL via Prisma for users, API keys, scan logs
5. **Stripe integration** — `stripe` package for subscriptions:
   - Checkout sessions
   - Webhook handler for payment events
   - Usage-based billing metering
6. **API expansion** — Add endpoints for dashboard:
   - `GET /v1/scans/history` — paginated scan history
   - `GET /v1/usage` — daily/monthly usage stats
   - `POST /v1/api-keys` — create API key
   - `DELETE /v1/api-keys/{key_id}` — revoke API key
7. **Create `src/models/database.py`** — SQLAlchemy models for users, keys, scans
8. **Create `src/services/billing.py`** — Stripe service
9. **Tests** — Dashboard component tests, API key lifecycle tests, billing webhook tests

### Acceptance Criteria

```bash
# Dashboard builds and serves
cd dashboard && npm run build
# Stripe test mode: create subscription, verify webhook
# API key: create, use for scan, revoke, verify revoked key rejected
# Usage: scan counts increment, daily limits enforced
```

---

## Phase 10 — VS Code / Cursor Extension ✅

**Goal:** Editor extension that runs CodeTrust scans inline, showing findings as diagnostics (squiggly lines), with quick-fix suggestions.

### Steps

1. **Create `extension/` directory** — VS Code extension project (TypeScript)
2. **Extension features:**
   - Scan on save — runs static analysis, shows diagnostics
   - Scan on demand — command palette: "CodeTrust: Scan File"
   - Import verification — command: "CodeTrust: Verify Imports"
   - Docker verification — command: "CodeTrust: Verify Dockerfile"
   - Inline code actions — quick-fix suggestions from findings
   - Status bar — shows last scan verdict (PASS/WARN/BLOCK)
3. **Communication** — HTTP to CodeTrust API (cloud) or spawn MCP server locally
4. **Settings** — API key, scan-on-save toggle, severity threshold, language filter
5. **Create `extension/src/extension.ts`** — Main extension entry point
6. **Create `extension/src/diagnostics.ts`** — Diagnostic provider
7. **Create `extension/src/commands.ts`** — Command handlers
8. **Create `extension/src/api-client.ts`** — HTTP client for CodeTrust API
9. **Marketplace** — Package and publish to VS Code Marketplace
10. **Tests** — Extension integration tests

### Acceptance Criteria

```bash
cd extension && npm run build
# Extension activates in VS Code
# Diagnostics appear on known anti-patterns
# Quick-fix suggestions are actionable
# Settings page works
# Status bar updates after scan
```

---

## Phase 11 — Production Hardening: Auth, Rate Limiting & Usage Tracking ✅

**Goal:** Make every API endpoint production-grade with database-backed authentication, per-user rate limiting, and full scan logging. This is the final phase before paid launch.

### Steps

1. **Create `src/services/auth.py`** — Authentication service:
   - `exchange_github_code(code)` — GitHub OAuth code → access token → user info
   - `create_jwt(user_id, plan)` — mint signed JWT for dashboard sessions
   - `decode_jwt(token)` — validate and decode JWT tokens
   - `is_configured()` — check if OAuth credentials are set
2. **Create `src/services/rate_limiter.py`** — Rate limiting service:
   - `check_limit(user_id, plan)` → (allowed, current_usage, daily_limit)
   - `increment(user_id, findings_count, latency_ms)` — update daily counters
   - Uses existing `DatabaseService.get_daily_usage()` and `increment_daily_usage()`
   - Uses existing `PLAN_LIMITS` from billing.py
3. **Update `src/api.py`** — Production auth + rate limiting:
   - Enhanced `verify_api_key()`:
     a. Master key (`CODETRUST_API_KEY`) → admin, unlimited
     b. Database-backed keys (`ct_live_*`) → lookup hash, get user, check plan
     c. JWT Bearer tokens → decode, get user
     d. No auth + empty master key → local dev mode
   - Rate limit middleware on all scan endpoints
   - Scan logging on every endpoint (log_scan + increment_daily_usage)
   - New endpoints:
     - `POST /v1/auth/github` — exchange OAuth code for JWT
     - `GET /v1/profile` — authenticated user profile + usage
     - `POST /v1/auth/refresh` — refresh an expiring JWT
4. **Update `src/config.py`** — Add GitHub OAuth URLs
5. **Update models** — Add `GithubAuthRequest`, `TokenResponse`, `RefreshRequest`
6. **Fix `action.yml`** — Add `tree-sitter-*` packages for AST scan in CI
7. **Update `pyproject.toml`** — Add `PyJWT` dependency
8. **Create `tests/test_auth_service.py`** — Test OAuth, JWT, and token lifecycle
9. **Create `tests/test_rate_limit.py`** — Test rate limiting logic
10. **Update `tests/test_api_endpoints.py`** — Test new endpoints and auth flows

### Acceptance Criteria

```bash
ruff check src/ tests/
pytest tests/ -v                                    # All pass
# Auth: master key works, DB key works, JWT works, bad key → 401
# Rate limit: free tier (100/day) enforced, pro tier (10K/day) enforced
# Scan logging: every scan creates a ScanLog + UsageDay record
# Profile: GET /v1/profile returns user info with usage stats
# OAuth: POST /v1/auth/github exchanges code for JWT (mocked in tests)
# action.yml: tree-sitter packages included for CI AST scans
```

---

## ✅ FINAL CHECKPOINT — Ready for Paying Users & Launch

All systems verified (2026-02-11):

- **Core Engine**: Static analysis (30+ anti-pattern rules), AST analysis (tree-sitter), registry verification (PyPI, npm, crates.io, Go proxy), Docker verification, sandbox execution
- **API**: 19 endpoints, all authenticated, rate-limited, scan-logged
- **Auth**: GitHub OAuth → JWT, database-backed API keys (hashed), master key for admin
- **Billing**: Stripe integration (checkout, portal, webhooks, plan management)
- **Rate Limiting**: Plan-tier enforcement (Free: 100/day, Pro: 10K/day, Enterprise: 100K/day)
- **Database**: Users, API keys, scan logs, usage tracking (SQLAlchemy async)
- **MCP Server**: 10 tools for Claude Code / Cursor integration
- **GitHub Action**: CI/CD integration with SARIF output
- **VS Code Extension**: Scan-on-save, diagnostics, status bar (skeleton)
- **Dashboard**: Next.js admin panel (skeleton)
- **Deployment**: Docker, docker-compose, Railway, Procfile
- **Testing**: 558 tests passing, ruff 0 errors, self-scan 0 findings in src/
- **Documentation**: SPEC.md, README.md, CHANGELOG.md, OpenAPI schema
