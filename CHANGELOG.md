# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0] - 2026-02-11

### Added

- **The Three Laws enforcement** — CodeTrust now enforces three core principles:
  1. *Law 1: Don't hallucinate* — every reference must be verifiable
  2. *Law 2: Assume nothing* — every choice must be justified
  3. *Law 3: Fix the cause, never the symptom* — every fix must answer "why?"

- **Symptom-Fix Detection rules** (Law 3) — 4 new rules
  - `except_swallow` — BLOCK — flags `except: pass/...` that silently swallow errors
  - `null_coalesce_smell` — WARN — flags `x = x or ""` defensive patterns
  - `suppress_lint` — WARN — flags `noqa`, `type: ignore`, `eslint-disable`, `@SuppressWarnings`
  - `sleep_no_context` — INFO — flags `sleep()` without preceding comment explaining why

- **Anti-Assumption rules** (Law 2) — 2 new rules
  - `debug_mode_enabled` — WARN — flags `DEBUG=True` left in code
  - `hardcoded_port` — INFO — flags hardcoded port numbers

- **Container Hardening rules** — 4 new rules
  - `docker_root_user` — WARN — flags Dockerfiles running as root (no USER)
  - `docker_latest_tag` — WARN — flags `FROM image:latest` or untagged images
  - `docker_no_workdir` — INFO — flags Dockerfiles without WORKDIR
  - `docker_env_secret` — BLOCK — flags secrets in ENV/ARG instructions

- **CI/CD Pipeline rules** — 2 new rules
  - `ci_unpinned_action` — WARN — flags `uses: action@main` instead of pinned SHA/version
  - `ci_no_timeout` — INFO — flags CI jobs without `timeout-minutes`

- **IaC rules** — 2 new rules
  - `hardcoded_ip` — WARN — flags hardcoded IP addresses in infrastructure files
  - `api_key_in_config` — BLOCK — flags API keys/secrets in YAML/TOML config files

- **AI Drift Score** — composite trust metric (0-100, grades A-F) calculated from
  scan findings, weighted by severity (BLOCK=10, WARN=3, INFO=1). Broken down by
  category: anti_hallucination, anti_assumption, root_cause, container_hygiene, ci_cd, devops.
  Available in API deep scan response and CLI `--json` output.

- **CLI enhanced** — scan engine now includes all new rule categories, Dockerfile
  file-level checks (USER, WORKDIR), CI rule routing, and drift score in output.

- **Pre-commit hook enhanced** — added suppress_lint, null_coalesce, debug_mode,
  docker_latest_tag, ci_unpinned_action, and docker_env_secret patterns.

- **54 new tests** — comprehensive test coverage for all new rules, drift score
  calculation, and CLI scan engine enhancements. Total: 672 tests passing.

## [1.7.0] - 2026-02-11

### Added

- **DevOps anti-pattern rules** — 7 new rules, 18 tests (35 total rules)
  - `connection_no_timeout` — flags Redis/httpx/SQLAlchemy connections without timeout
  - `unbounded_retry` — flags retry counts >= 5 without total deadline
  - `retry_exponential_unbounded` — flags exponential backoff without timeout cap
  - `blocking_prestart` — flags migrations blocking server startup (alembic && uvicorn)
  - `dockerfile_no_healthcheck` — flags Dockerfile CMD without HEALTHCHECK
  - `compose_no_healthcheck` — flags Docker Compose services without healthcheck
  - `healthcheck_timeout_low` — flags healthcheck timeouts under 30s
- **Offline local scanning** — CLI scan engine (`codetrust scan`) now includes
  DevOps, SQL, and all generic rules with file-type routing. No API dependency.
- **Pre-commit local fallback** — hook tries full CLI engine first (`python -m src.cli scan`),
  falls back to embedded regex if CLI unavailable. Zero network dependency.
- **CI local fallback** — GitHub Actions workflows check API health before scanning;
  if API is unreachable, runs local scan automatically instead of silently failing.
- SQL and DevOps file types added to scan coverage (`.sql`, `.yml`, `.yaml`, `.toml`)

### Fixed

- **Railway deployment** — restored clean `preDeployCommand` with timeout guard,
  reverted unnecessary retry logic and env var fallback complexity

## [1.6.0] - 2026-02-11

### Added

- **SQL anti-pattern rules** — 13 rules for `.sql` file scanning
- File-type routing in static analyzer (SQL rules only fire on `.sql` files)
- Pre-commit hook updated with DevOps patterns

## [1.5.0] - 2026-02-11

### Added

- **Published to PyPI** — `pip install codetrust` — [pypi.org/project/codetrust](https://pypi.org/project/codetrust/)
- **Published to VS Code Marketplace** — [SaidBorna.codetrust](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust)
- **CLI tool** (`codetrust init/scan/status/doctor`) — install enforcement layers into any project
- **Enforcement templates** — CLAUDE.md, .cursorrules, pre-commit hook, GitHub Action (in `src/templates/`)
- **VS Code / Cursor Extension** (Phase 10) — editor extension for inline code verification
  - `extension/` TypeScript project with full VS Code extension scaffolding
  - Scan on save — automatic static analysis when saving supported files
  - Command palette: Scan File, Deep Scan, Verify Imports, Verify Dockerfile, Clear Diagnostics
  - Inline diagnostics — findings shown as squiggly lines (error/warning/info severity)
  - Quick-fix code actions — suppress rules, apply suggestions, remove problematic lines
  - Status bar — shows last scan verdict (PASS/WARN/BLOCK) with click-to-scan
  - Import verification — extracts imports from Python, JS/TS, Go, Rust and verifies against registries
  - Docker verification — parses FROM directives and validates images/tags
  - Configurable settings: API URL, API key, scan type, severity threshold, language filter, timeout
  - API client using Node.js native http/https (zero runtime dependencies)
  - Parser utilities for Python, JavaScript/TypeScript, Go, Rust imports and Dockerfile images
  - 3 test suites (parser tests, API client tests, type tests)
  - ESLint, TypeScript strict mode, source maps

## [1.4.0] - 2026-02-11

### Added

- **Dashboard (Next.js 14+)** (Phase 9) — web dashboard for API key management and usage analytics
  - Landing page with hero section and feature cards
  - Pricing page with Free / Pro / Enterprise tier comparison
  - GitHub OAuth login via NextAuth.js with Prisma adapter
  - Dashboard overview with stats cards, usage chart, and scan history table
  - API key management — create, list, revoke keys (`ct_live_` format, SHA-256 hashed)
  - Account settings page with profile, subscription, and danger zone
  - Tailwind CSS styling with dark-mode-ready custom palette
- **Stripe Billing** — subscription management with checkout, portal, and webhooks
  - `src/services/billing.py` — `BillingService` wrapping Stripe SDK
  - Checkout sessions, customer portal, subscription status, plan limits
  - Webhook handler for `checkout.session.completed` and `customer.subscription.deleted`
  - Plan limits: FREE=100, PRO=10,000, ENTERPRISE=100,000 scans/day
- **Database layer (SQLAlchemy 2.0 async)** — persistent storage for users, keys, scans
  - `src/models/database.py` — `User`, `ApiKeyRecord`, `ScanLog`, `UsageDay` ORM models
  - `src/services/database.py` — async CRUD service (~280 lines)
  - PostgreSQL (asyncpg) for production, SQLite (aiosqlite) for tests
- **8 new API endpoints** — dashboard backend
  - `POST /v1/api-keys`, `GET /v1/api-keys`, `DELETE /v1/api-keys/{key_id}`
  - `GET /v1/scans/history`, `GET /v1/usage`
  - `POST /v1/billing/checkout`, `POST /v1/billing/portal`, `POST /v1/webhooks/stripe`
- CORS middleware for dashboard cross-origin requests
- Docker Compose: added PostgreSQL 16 service with health checks
- 66 new tests (30 database + 22 billing + 15 dashboard API) — **476 tests total**

### Changed

- `PlanTier` and `ScanType` enums added to `src/models/enums.py`
- Config expanded: database, Stripe, OAuth, JWT, dashboard settings
- `pyproject.toml`: added sqlalchemy, asyncpg, stripe, aiosqlite dependencies

## [1.3.0] - 2026-02-11

### Added

- **GitHub Action for CI/CD** (Phase 8) — reusable composite action for PR scanning
  - `action.yml` with configurable inputs: scan-type, fail-on threshold, language, SARIF output
  - `action/entrypoint.sh` entry script and `action/scan_runner.py` Python runner
  - Language-aware file discovery with exclusion patterns (.git, .venv, node_modules, etc.)
  - GitHub workflow annotations (`::error::`, `::warning::`) for inline PR feedback
- **SARIF v2.1.0 output** — standard format for GitHub Security tab integration
  - `src/formatters/sarif.py` — converts Finding objects to SARIF JSON
  - `POST /v1/scan/static/sarif` and `POST /v1/scan/deep/sarif` API endpoints
  - `codetrust_sarif_export` MCP tool
  - Security-severity mapping (BLOCK→high, WARN→medium, INFO→low)
- **CI pipeline** — `.github/workflows/ci.yml` with lint, test, and self-scan jobs
- 77 new tests (45 GitHub Action + 32 SARIF) — **410 tests total**

## [1.2.0] - 2026-02-10

### Added

- **Sandbox Execution** (Phase 7) — isolated Docker container code execution (Layer 4)
  - `src/services/sandbox.py` — `SandboxService` with inline and file execution strategies
  - Security: `--network=none`, `--read-only`, `--memory=256m`, `--pids-limit=64`
  - Supported languages: Python, JavaScript, TypeScript, Go, Rust
  - `sandbox/` directory with 4 Dockerfiles (python, node, go, rust)
  - `POST /v1/sandbox/run` API endpoint
  - `codetrust_sandbox_run` MCP tool
  - Sandbox layer integrated into deep scan (optional `sandbox_run` field)
- 63 new sandbox tests — **333 tests total**

## [1.0.1] - 2026-02-10

### Added

- **Go & Rust Registry Support** (Phase 5) — extended registry verification to two new ecosystems
  - `verify_go_module()` — verification against proxy.golang.org with version check
  - `verify_crates_package()` — verification against crates.io with version check
  - `extract_go_imports()` — regex parser for `import "..."` and `import (...)` blocks, skips stdlib
  - `extract_rust_imports()` — regex parser for `use crate::` and `extern crate`, skips std/core/alloc
  - `parse_go_mod()` — parses `require (...)` blocks to module→version mapping
  - `parse_cargo_toml()` — parses `[dependencies]` to crate→version mapping
  - Fuzzy matching suggestions for Go modules and Rust crates (top 200+ each)
  - crates.io User-Agent header (`CodeTrust/1.0.0`)
  - Language routing: `Language.GO` → Go proxy, `Language.RUST` → crates.io
  - Comprehensive tests for Go/Rust verification, import extraction, manifest parsing

## [1.1.0] - 2026-02-10

### Added

- **AST Parsing with tree-sitter** (Phase 6) — deep code analysis via Abstract Syntax Trees (Layer 3)
  - `src/services/ast_analyzer.py` — cyclomatic complexity, unused variables, unreachable code, deep nesting
  - Supports Python, JavaScript, TypeScript, Go, Rust via tree-sitter grammars
  - `POST /v1/scan/ast` API endpoint
  - `codetrust_ast_scan` MCP tool
  - AST layer integrated into deep scan
- 270 tests total after Phase 6

## [1.0.0] - 2026-02-10

### Added

- **Static Analysis Engine** — 35+ anti-pattern rules with BLOCK/WARN/INFO severity levels
  - Heredoc detection, hardcoded secrets, eval/exec, SQL injection, pickle.load
  - Bare except, wildcard imports, Any types, mutable defaults, magic numbers
  - Function length checking (40-line threshold)
- **Package Registry Verification** — verify imports against real registries
  - PyPI support for Python packages
  - npm support for JavaScript/TypeScript packages
  - Version mismatch detection
  - Typosquatting suggestions via fuzzy matching
- **Docker Image Verification** — verify base images and tags exist on Docker Hub
  - FROM statement parsing with multi-stage build support
  - Available tag suggestions for unknown tags
- **Enterprise Structure Validation** — check repos for required files
  - README, LICENSE, tests, .gitignore, pyproject.toml / package.json
- **Deep Scan** — combined all-layer analysis in a single pass
- **FastAPI HTTP API** with 5 endpoints
  - `GET /v1/status` — health check
  - `POST /v1/verify/imports` — package verification
  - `POST /v1/verify/dockerfile` — Docker verification
  - `POST /v1/scan/static` — static analysis
  - `POST /v1/scan/deep` — full deep scan
- **MCP Server** with 7 tools for Claude Code integration
  - `codetrust_static_scan`, `codetrust_pre_action`, `codetrust_post_action`
  - `codetrust_list_rules`, `codetrust_verify_imports`
  - `codetrust_verify_dockerfile`, `codetrust_deep_scan`
- **Redis caching** with TTL management and graceful degradation
- **X-API-Key authentication** (optional — skipped in local dev)
- **Pre-commit hook** with BLOCK/WARN pattern scanning
- **Docker Compose** stack for API + Redis
- **Railway deployment** configuration (railway.toml + Procfile)
- **Multi-stage Dockerfile** with non-root user
- **structlog** JSON logging throughout
