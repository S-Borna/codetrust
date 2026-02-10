# PLAN.md — CodeTrust Build Plan

> **Rule: Build one phase at a time. Each phase must pass its acceptance criteria before starting the next.**

---

## Phase 1 — Foundation & Static Analysis (Layer 1)

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

## Phase 2 — Cache + Registry Verification (Layer 2 Core)

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

## Phase 3 — FastAPI + Docker Verification

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

## Phase 4 — Deep Scan + Polish + Deploy

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

## Post-MVP — Future Phases

These are NOT part of the initial build. Document them but do not implement.

- **Phase 5:** Go/Rust/crates.io registry support
- **Phase 6:** AST parsing with tree-sitter (Layer 3)
- **Phase 7:** Sandbox execution (Layer 4)
- **Phase 8:** GitHub Action for CI/CD (Layer 5)
- **Phase 9:** Dashboard (Next.js) + Stripe billing
- **Phase 10:** VS Code / Cursor extension
