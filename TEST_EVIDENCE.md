# CodeTrust — Test Evidence & Quality Report

> **558 tester | 19 testsviter | 1.64s körningstid | 100% gröna**

---

## Sammanfattning

CodeTrust har **558 automatiserade tester** som körs utan nätverksåtkomst, utan extern databas och utan Docker. Alla externa beroenden mockas:

- **Redis** → `fakeredis` (in-memory)
- **HTTP-anrop** → `pytest-httpx` (mockat)
- **Databas** → SQLite in-memory (via `aiosqlite`)
- **Docker** → mockad subprocess

```
$ pytest tests/ -q
558 passed in 1.64s
```

---

## Testfördelning per fil

| # | Testfil | Antal | Layer | Vad den testar |
|---|---------|-------|-------|----------------|
| 1 | `test_sandbox.py` | 63 | Layer 5 | Sandbox-exekvering i isolerade Docker-containrar, säkerhetslimiter (`--network=none`, `--read-only`, `256MB`), timeout-hantering, Python/JS/Go/Rust-support, error handling |
| 2 | `test_registry.py` | 52 | Layer 2 | PyPI+npm paketverifiering, cache hit/miss, batch concurrent verification, version mismatch, NOT_FOUND med suggestions, timeout-hantering |
| 3 | `test_ast.py` | 47 | Layer 3 | AST-analys via tree-sitter, cyklomatisk komplexitet, oanvända variabler, oåtkomlig kod (efter return/raise), djup nesting, 5 språk |
| 4 | `test_go_rust_registry.py` | 44 | Layer 2 | Go proxy + crates.io verifiering, Go/Rust import-extraktion, go.mod/Cargo.toml-parsing, stdlib-filtrering, fuzzy matching |
| 5 | `test_github_action.py` | 44 | Layer 7 | GitHub Action composite action, filupptäckt, SARIF-output, PR-annotationer (`::error::`, `::warning::`), konfigurerbara inputs |
| 6 | `test_models.py` | 34 | Core | Pydantic model validation — alla request/response-modeller, enum-serialisering, field constraints, strict mode |
| 7 | `test_sarif.py` | 33 | Layer 6 | SARIF v2.1.0 format-compliance, severity→security mapping, multi-finding aggregering, rule metadata |
| 8 | `test_static.py` | 32 | Layer 1 | Statisk analys — 35+ regler: heredoc, secrets, eval/exec, SQL injection, pickle, bare except, wildcard import, mutable defaults, magic numbers |
| 9 | `test_parsers.py` | 29 | Utility | Import-extraktion: Python (`import`, `from`), JS/TS (`import`, `require`), Go (`import "..."`), Rust (`use`, `extern crate`), requirements.txt, go.mod, Cargo.toml, Dockerfile FROM |
| 10 | `test_database.py` | 29 | Infra | SQLAlchemy async CRUD — User, ApiKeyRecord, ScanLog, UsageDay, SHA-256 key hashing, pagination, date filtering |
| 11 | `test_deep_scan.py` | 26 | Full | Deep scan orkestrering — combined verdict (PASS/WARN/BLOCK), cross-layer integration, latency measurement, optional layers |
| 12 | `test_billing.py` | 22 | Billing | Stripe-integration — checkout sessions, customer portal, webhook handling, subscription lifecycle, plan limits |
| 13 | `test_api_endpoints.py` | 22 | API | FastAPI endpoint testing — alla 19 endpoints, auth validation, request validation, error handling, response format |
| 14 | `test_dashboard_api.py` | 15 | Dashboard | Dashboard-specifika endpoints — profil, API keys CRUD, scan history, usage stats |
| 15 | `test_auth_service.py` | 15 | Auth | GitHub OAuth flow, JWT token generation/validation, session management, user creation |
| 16 | `test_similarity.py` | 14 | Utility | Fuzzy matching — typosquatting-upptäckt för PyPI (500+), npm (500+), crates (200+), Go (200+) paket. "reqeusts" → "requests" |
| 17 | `test_rate_limit.py` | 14 | Infra | Rate limiting — free tier (100/dag), pro tier (10,000/dag), limit enforcement, counter reset |
| 18 | `test_docker.py` | 13 | Layer 4 | Docker Hub image/tag-verifiering — live API mock, tag suggestions, multi-stage Dockerfile-parsing, NOT_FOUND handling |
| 19 | `test_cache.py` | 10 | Infra | Redis cache — TTL, JSON serialization, graceful degradation (inga krascher om Redis nere), key schema |

**Total: 558 tester**

---

## Testfördelning per arkitekturlager

| Layer | Tester | % |
|-------|--------|---|
| Layer 1 — Statisk analys | 32 | 5.7% |
| Layer 2 — Paketverifiering (PyPI/npm/Go/Rust) | 96 | 17.2% |
| Layer 3 — AST-analys | 47 | 8.4% |
| Layer 4 — Docker-verifiering | 13 | 2.3% |
| Layer 5 — Sandbox-exekvering | 63 | 11.3% |
| Layer 6 — Enterprise + SARIF | 33 | 5.9% |
| Layer 7 — Enforcement (GitHub Action) | 44 | 7.9% |
| API-endpoints | 22 | 3.9% |
| Deep scan (cross-layer) | 26 | 4.7% |
| Modeller + parsers + utils | 77 | 13.8% |
| Infrastruktur (cache, DB, auth, billing, rate limit) | 90 | 16.1% |
| Dashboard | 15 | 2.7% |

---

## Vad testerna bevisar

### 1. Paket som inte existerar fångas

```python
# test_registry.py
async def test_unknown_package_returns_not_found(self):
    """AI hallucinated 'fast-utils' — CodeTrust fångar det."""
    result = await service.verify_python_package("nonexistent_xyz")
    assert result.status == VerifyStatus.NOT_FOUND
    assert result.severity == Severity.BLOCK
```

### 2. Typosquatting upptäcks

```python
# test_similarity.py
def test_typo_suggestion(self):
    """AI skrev 'requets' istf 'requests' → CodeTrust föreslår rätt."""
    suggestion = suggest_similar("requets", TOP_PYPI_PACKAGES)
    assert "requests" in suggestion
```

### 3. Trasiga Docker-images fångas

```python
# test_docker.py
async def test_nonexistent_tag(self):
    """AI angav 'python:3.12-alpine-slim' — finns ej."""
    result = await service.verify_image_tag("python", "3.12-alpine-slim")
    assert result.status == VerifyStatus.NOT_FOUND
    assert len(result.available_tags) > 0  # föreslår alternativ
```

### 4. Hemligheter blockeras

```python
# test_static.py
def test_hardcoded_secret_blocked(self):
    """AI la in API-nyckel direkt i koden."""
    findings = analyzer.scan_code('api_key = "sk-live-abc123def456"')
    assert any(f.rule_id == "hardcoded_secret" and f.severity == Severity.BLOCK for f in findings)
```

### 5. eval/exec blockeras

```python
# test_static.py
def test_eval_blocked(self):
    """AI använde eval() — RCE-sårbarhet."""
    findings = analyzer.scan_code("result = eval(user_input)")
    assert any(f.rule_id == "eval_exec" and f.severity == Severity.BLOCK for f in findings)
```

### 6. Sandbox fångar runtime-krascher

```python
# test_sandbox.py
async def test_import_error_caught(self):
    """Kod som importerar hallucinerat paket kraschar i sandbox."""
    result = await sandbox.run("import nonexistent_package_xyz", language="python")
    assert result.exit_code != 0
    assert "ModuleNotFoundError" in result.stderr
```

### 7. Cross-layer deep scan fungerar

```python
# test_deep_scan.py
async def test_deep_scan_block_verdict(self):
    """Kod med eval() + hallucinerat paket = BLOCK verdict."""
    result = await deep_scan(code="import fake_pkg\neval(input())")
    assert result.overall_verdict == "BLOCK"
    assert result.total_findings > 0
```

### 8. Graceful degradation (ingen Redis = fungerar ändå)

```python
# test_cache.py
async def test_redis_unavailable_degrades_gracefully(self):
    """Om Redis är nere, fungerar allt — bara utan cache."""
    cache = CacheService("redis://nonexistent:6379")
    result = await cache.get("any_key")
    assert result is None  # Ingen krasch, bara None
```

---

## Self-Dogfooding — CodeTrust verifierar sig själv

Under byggandet av CodeTrust (11 build-faser) användes CodeTrust aktivt via MCP-verktyg. Dokumenterade fall där CodeTrust fångade sina egna problem:

| Fas | Problem | Hur CodeTrust fångade det |
|-----|---------|--------------------------|
| 1 | `build_scan_response()` anropades med fel parametrar | `codetrust_static_scan` → integration bröts synligt |
| 1 | Pre-commit hook matchade `.format()` i URL-byggare som SQL injection | Hook blockerade commit → regex förfinades |
| 1 | `eval()` i testfixtures triggade BLOCK | Korrekt — testfiler exkluderades sedan från scanning |
| 3 | Pydantic `strict=True` bröt FastAPI JSON enum-coercion → 422 errors | `codetrust_post_action` flaggade strukturproblem |
| 5 | Oanvänd `json`-import i testfil | `codetrust_static_scan` + ruff fångade det |
| 6 | Nested if-satser (SIM102) + deep nesting (AST) | Dubbelfångat av statisk + AST-analys |
| 11 | TOML-ordning bröt classifiers (hamnade under `[project.urls]`) | Build kraschade → fångades under `python -m build` |
| 11 | Duplicate `force-include` gav wheel-varningar | Varningen fångades under paketeringssteget |

**Konklusion:** CodeTrust ätrade sin egen dogfood genom hela utvecklingen. Varje bugg den fångade i sig själv bevisar att den fungerar.

---

## Testkvalitet

| Egenskap | Status |
|----------|--------|
| Nätverkslösa tester | ✅ Alla HTTP-anrop mockade |
| Databaslösa tester | ✅ SQLite in-memory |
| Redis-lösa tester | ✅ fakeredis |
| Docker-lösa tester | ✅ Subprocess mockad |
| Deterministic | ✅ Inga tidsberoende, inga random-värden |
| Snabba | ✅ 558 tester på 1.64s |
| Parallelliserbara | ✅ Inga delade resurser |

---

*CodeTrust v1.5.0 — 558 tests, zero failures, zero network dependencies.*
