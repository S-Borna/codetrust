# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
