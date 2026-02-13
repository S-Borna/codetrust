# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — Production Polish (10/10 Sprint)

- **E2E integration tests** — `tests/test_e2e_integration.py` with real in-memory SQLite DB,
  18 tests covering full HTTP→service→DB→response lifecycle: health, static scan, deep scan,
  SARIF, API key lifecycle, scan history, usage stats, GDPR export/delete, auth errors
- **Dashboard E2E (Playwright)** — `dashboard/playwright.config.ts` + `dashboard/e2e/dashboard.spec.ts`
  with 7 tests: page load, navigation, API error handling, accessibility checks (lang, duplicate IDs).
  `@playwright/test` added to dashboard devDependencies; `test:e2e` npm script
- **OIDC integration test** — `tests/test_oidc_integration.py` with mock OIDC provider
  (MockOIDCTransport), tests full Authorization Code Flow: discovery → auth URL → token
  exchange → ID token parsing → userinfo fallback → domain validation. 26 tests
- **Helm chart CI validation** — new `helm-lint` job in `.github/workflows/ci.yml` using
  `azure/setup-helm@v4`; runs `helm lint`, `helm template` (basic + production values)
- **Load test baseline docs** — `tests/load/README.md` with per-endpoint p50/p95/p99
  targets, scalability matrix (10–1000 users), alerting thresholds, CI integration guide
- **Code coverage > 80%** — from 76.59% → **81.03%** (+4.44%). New test files:
  `test_metrics.py` (24 tests), `test_cache_service.py` (16 tests), `test_gateway_server.py` (18 tests),
  `test_cli_coverage.py` (33 tests), `test_api_coverage.py` (14 tests).
  CI `--cov-fail-under` bumped from 70 to **80** in both `ci.yml` and `release.yml`
- **Multi-tenant data isolation** — `src/services/tenant.py` with `TenantService`,
  `TenantContext`, `Organization` model. Org-scoped queries, member management with
  admin-only guards, cross-tenant access validation, org limit enforcement. 17 tests
- **Signed releases (Sigstore)** — `sigstore/gh-action-sigstore-python@v3` added to
  `release.yml`; signs all distributions (`dist/*`) after PyPI publish; signed artifacts
  uploaded to GitHub Release alongside SBOM

### Added — Tier 1 (Foundation Hardening)

- **SECURITY.md** — vulnerability disclosure policy, responsible disclosure process
- **CONTRIBUTING.md** — contributor guide with code standards, PR process
- **.github/dependabot.yml** — automated dependency updates for pip + npm + GitHub Actions
- **pytest-cov** — `--cov=src --cov-fail-under=80` enforced in CI
- **Dockerfile hardening** — non-root user, `HEALTHCHECK`, read-only root, `dumb-init`
- **OpenAPI spec** — `docs/openapi.json` with all 21 endpoints
- **Release pipeline** — `.github/workflows/release.yml` with tag-triggered PyPI + VSIX + GitHub Release
- **Architecture diagram** — Mermaid flowchart in README showing all components

### Added — Tier 2 (Observability & Compliance)

- **Prometheus /metrics endpoint** — `src/middleware/metrics.py` with `MetricsMiddleware`
  (ASGI), 4 metrics: requests_total, request_duration, active_requests, uptime_seconds
- **SIEM audit export** — `src/gateway/siem.py` with CEF, LEEF, Syslog RFC 5424, and
  ECS JSON output formats; CLI `--format` flag; 41 tests
- **Gateway webhooks** — `src/gateway/webhooks.py` with Slack, Teams, PagerDuty, and
  Generic webhook providers; configurable in `.codetrust.toml`; 29 tests
- **Custom rule YAML/TOML** — `src/gateway/custom_rules.py` loads user-authored rules
  from `.codetrust/custom_rules.yaml` or TOML; auto-prefixes `custom_`; 26 tests
- **SBOM generation** — CycloneDX SBOM generated in CI (`ci.yml`) and attached to
  GitHub Releases (`release.yml`)
- **Dashboard tests** — Vitest + React Testing Library, 18 tests across 3 component
  test files (scan-history, governance-audit, dashboard-nav)
- **Data retention policy** — `AuditLogger.purge(older_than_days=)`, CLI `--purge` flag,
  `retention_days` config in `.codetrust.toml`

### Added — Tier 3 (Enterprise Requirements)

- **SSO/OIDC authentication** — `src/services/sso.py` with full Authorization Code Flow:
  OIDC discovery, auth URL building, code exchange, ID token parsing, userinfo fetch.
  Supports Azure AD, Okta, Auth0, Google, Keycloak. Domain restriction, role mapping.
  8 new `CODETRUST_OIDC_*` settings. API endpoints: `GET /v1/auth/oidc/login`,
  `POST /v1/auth/oidc/callback`. 34 tests
- **SOC2 controls mapping** — `docs/compliance/soc2-controls.md` with full mapping to
  AICPA Trust Service Criteria CC1–CC9, Availability (A1), Processing Integrity (PI1),
  Confidentiality (C1), Privacy (P1); implementation references and audit evidence list
- **GDPR data export/delete** — `src/services/gdpr.py` with `export_user_data()` (Art. 15),
  `delete_user_data()` (Art. 17), `anonymize_audit_entries()`. API endpoints:
  `GET /v1/user/export`, `DELETE /v1/user/delete`. 24 tests
- **Kubernetes Helm charts** — `deploy/helm/codetrust/` with Chart.yaml, values.yaml,
  templates (Deployment, Service, Ingress, Secret, ConfigMap, HPA, ServiceAccount).
  Pod security: non-root, readOnlyRootFilesystem, drop ALL capabilities.
  Prometheus scrape annotations. Redis sub-chart. HPA (2–10 replicas, CPU/memory targets)
- **Locust load testing** — `tests/load/locustfile.py` with 2 user classes (normal + heavy),
  9 task scenarios covering health, static scans, deep scans, SARIF, governance audit, metrics

### Added — Config Hallucination Detectors (5 new rules)

- `hallucinated_localhost_port` (WARN) — flags `localhost:XXXX` with unverified port
- `hallucinated_api_endpoint` (WARN) — flags AI-generated API paths
- `hallucinated_env_var` (INFO) — flags env vars that may not exist
- `placeholder_url` (WARN) — flags `example.com`, `your-app.com` placeholder URLs
- `fake_api_key_format` (BLOCK) — flags `sk-...`, `pk_test_...` mock API keys

### Changed

- **Total tests** — 1168 passing, 2 skipped (from 845 at v2.0.0 release)
- **Code coverage** — 81.03% (from ~60% at v2.0.0 release)
- **Total rules** — 82 (67 scan rules + 15 gateway rules)

## [2.0.0] - 2026-02-13

### Added

- **AI Governance Gateway** — pre-execution interception layer for AI agent actions
  - `src/gateway/interceptor.py` — `CommandInterceptor` with 13 terminal rules + 2 content rules
  - Blocks: heredoc, eval, curl|sh, rm -rf /, chmod 777, sudo su, dd of=, git push,
    git force push, pip unverified, env secret export, mkfs, fork bomb
  - Content scanning: eval/exec in file writes, hardcoded secrets in file writes
  - `src/gateway/policies.py` — `PolicyEngine` with configurable governance modes
    (enforce/audit/off), loads from `.codetrust.toml` or `pyproject.toml`
  - `src/gateway/audit.py` — JSONL append-only audit logger with filtering and stats
  - `src/gateway/server.py` — MCP gateway server ("codetrust-gateway") with 7 tools:
    `codetrust_validate_command`, `codetrust_validate_file_write`,
    `codetrust_validate_file_delete`, `codetrust_validate_package`,
    `codetrust_governance_status`, `codetrust_audit_history`, `codetrust_list_gateway_rules`
- **CLI `codetrust governance`** — `--setup`, `--status`, `--mode` subcommands
- **CLI `codetrust audit`** — `--hours`, `--verdict`, `--stats` subcommands
- **CLI `codetrust init`** — now installs `.codetrust.toml` + `.codetrust/` audit directory
- **Extension governance settings** — 7 new VS Code settings for governance configuration
- **77 rules** — expanded from 49 to 77 (62 scan rules + 15 gateway rules)
- **67 scan rules** — expanded from 62 with 5 new config hallucination detectors:
  `hallucinated_localhost_port` (WARN), `hallucinated_api_endpoint` (WARN),
  `hallucinated_env_var` (INFO), `placeholder_url` (WARN), `fake_api_key_format` (BLOCK)
- **82 total rules** — 67 scan rules + 15 gateway rules
- **CI governance enforcement** — GitHub Action `scan_runner.py` now runs gateway
  content rules on PR files, merging governance findings with scan findings
- **Multi-agent audit correlation** — auto-detects Claude, Copilot, Cursor, Windsurf,
  and GitHub Actions via environment variables; logs `agent_id` on every audit entry
- **Dashboard governance view** — Next.js page at `/dashboard/governance` with
  `GovernanceAuditView` component: stats cards, verdict badges, filterable audit table
- **`/v1/governance/audit` API endpoint** — query audit log with `hours`, `verdict`,
  and `limit` parameters; returns entries + stats JSON for dashboard consumption
- **62 rules** — expanded from 49 to 62 rules (51 regex + 11 file-level)
- **React/JSX rules** (7 new) — `dangerouslySetInnerHTML` (BLOCK), `innerHTML` string
  (BLOCK), missing `key` in list, `document.getElementById` usage, `useEffect` without
  deps array, `setState` in render, `index` as key prop
- **Kubernetes YAML rules** (6 new) — `privileged: true` (BLOCK), `hostNetwork`,
  `hostPID`, `runAsUser: 0`, missing resource limits, `latest` image tag
- **CLI `--sarif` / `--sarif-file`** — emit SARIF v2.1.0 output for CI integration
  (e.g. GitHub Code Scanning upload)
- **CLI config file support** — reads `.codetrust.toml` or `pyproject.toml
  [tool.codetrust]` for `exclude_paths`, `ignore_rules`, and `severity_overrides`
- **CLI special handlers** — implemented 7 new file-level checks: `except_swallow`,
  `sleep_no_context`, `long_function` (>40 lines), `connection_no_timeout`,
  `compose_no_healthcheck`, `ci_no_timeout`, `dockerfile_no_healthcheck`
- **GitHub Action inputs** — `fail-on` (block/warn/never), `scan-type` (static/deep),
  `language`, `sarif` (true/false); `sarif-file` output; expanded file detection to
  `.tsx`, `.jsx`, `.sql`, `.yml`, `.yaml`
- **Extension "Scan Workspace"** command — scans up to 500 files with progress UI,
  cancel support, and summary notification with block count
- **Extension embedded scanner** — extended with React and Kubernetes rule arrays
  and `.jsx`/`.tsx` file routing

### Changed

- **CLAUDE.md** — added Layer A (Gateway) enforcement protocol: AI agents must call
  `codetrust_validate_command` before every terminal command
- **Total rules** — 82 (67 scan rules + 15 gateway rules)
- **Total MCP tools** — 15 (8 scanner + 7 gateway)
- **Parity test counts** updated to 67 total / 56 regex / 11 special handlers
- **845 tests** at release (expanded to 1168 in subsequent sessions)

## [1.9.0] - 2026-02-12

### Added

- **Offline Mode documentation** — extension README now documents offline scanning
  capabilities, verification cache, and online/offline feature comparison table
- **CI extension build job** — new `extension-build` job in GitHub Actions validates
  TypeScript compilation (`tsc --noEmit`) and npm build on every push
- **CI Python matrix** — tests now run against Python 3.12 and 3.13 in parallel
- **CI pip caching** — pip dependencies cached via `actions/cache@v4` for faster builds
- **CI timeouts** — all jobs have `timeout-minutes` to prevent stuck workflows

### Fixed

- **API URL consistency** — GitHub Action `scan_runner.py` default URL updated from
  `api.codetrust.dev` to `codetrust-api-production.up.railway.app` matching all other
  entry points
- **Self-scan noise** — CLI entry points (`cli.py`, `scan_runner.py`, `scan.py`) now
  exempt from `print_debug` rule since `print()` is correct user output for CLI tools
- **Test fixture false positives** — self-scan now skips `.test.` and `.spec.` files
  and `test`/`__tests__` directories that contain intentional anti-patterns

## [1.8.1] - 2026-02-11

### Changed

- **9 Verification Layers** — expanded from 7 to 9 layers across all docs, PyPI, and Marketplace:
  - Layer 02: Root Cause Analysis (4 symptom-fix rules) — NEW
  - Layer 05: Container Hardening (10 rules) — NEW
  - Layer 06: IaC & Config (7 rules) — NEW
- **Website Trust color** reverted from `#38d8fd` (cyan) to `var(--green)` matching logo
- **PyPI description** updated with 9-layer table
- **Extension README** updated with 9-layer table
- **PRODUCT.md** layers rewritten from 7 to 9

### Fixed

- **Procfile** — removed `alembic upgrade head &&` that blocked server start; migration now handled by `preDeployCommand`
- **railway.toml** — removed `preDeployCommand` (alembic migration was hanging on DB lock)
- **blocking_prestart self-scan** — split regex string with concatenation to prevent rule definitions from self-matching in `cli.py`, `anti_patterns.py`, `pre-commit`, `templates/pre-commit`
- **GitHub Action heredoc** — replaced `<<EOF` with dynamic delimiter in `.github/workflows/codetrust-scan.yml`
- **4 except_swallow BLOCK violations** in production code:
  - `src/cli.py:522` — `except: pass` → `hooks_path_set = False`
  - `src/services/registry.py:539` — `except: pass` → `logger.debug()`
  - `src/services/sandbox.py:251` — `except: pass` → `return` with comment
  - `action/scan_runner.py:118` — `except: continue` → print warning + continue

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
