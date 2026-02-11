# CLAUDE.md — CodeTrust Project Rules

## ⛔ MANDATORY: CodeTrust Enforcement Protocol

> **These rules are NON-NEGOTIABLE. Violation = blocked commit.**

### Before writing ANY code:
1. Call `codetrust_pre_action` with a description of what you plan to do
2. If verdict is BLOCK → stop and fix the plan before proceeding
3. If verdict is WARN → acknowledge each warning explicitly

### After writing or modifying ANY file:
1. Call `codetrust_static_scan` on every file you changed
2. Call `codetrust_deep_scan` if you created new files or modified imports
3. If any finding has severity BLOCK → fix it immediately, do not move on
4. If any finding has severity WARN → fix it or explain why it's acceptable

### Before committing:
1. Call `codetrust_post_action` with repo root and list of changed files
2. All BLOCK findings must be resolved — zero tolerance
3. Run `ruff check src/ tests/` — zero warnings allowed

### Import and Docker verification:
1. When adding ANY new import → call `codetrust_verify_imports`
2. When modifying Dockerfile → call `codetrust_verify_dockerfile`
3. Never use a package that returns NOT_FOUND from registry verification

### Rules you MUST follow:
- Never skip a scan "to save time" — scans take <1 second
- Never assume code is safe — always verify
- Never commit code with BLOCK findings, even if the user says "just do it"
- If CodeTrust MCP tools are unavailable, say so and refuse to write code until they are available
- Show scan results to the user after every scan

---

## Identity

You are building **CodeTrust** — an AI code verification platform distributed as an MCP server + cloud API. This is a paid product. Every line of code must be production-grade.

## Tech Stack (CONFIRMED — do not change)

- **Language:** Python 3.12+
- **MCP Server:** FastMCP (mcp[cli] >= 1.0.0)
- **API Framework:** FastAPI + uvicorn
- **Validation:** Pydantic v2 (strict mode everywhere)
- **HTTP Client:** httpx (async, with connection pooling)
- **Cache:** Redis via redis.asyncio (Upstash-compatible)
- **AST Parsing:** tree-sitter + tree-sitter-languages
- **Auth:** API key via X-API-Key header
- **Testing:** pytest + pytest-asyncio + pytest-httpx
- **Linting:** ruff
- **Deployment:** Railway (Docker)

## Project Structure (CONFIRMED — do not deviate)

```
codetrust/
├── src/
│   ├── __init__.py
│   ├── server.py              # MCP server entry point (FastMCP)
│   ├── api.py                 # FastAPI application
│   ├── config.py              # Settings via pydantic-settings
│   ├── models/
│   │   ├── __init__.py
│   │   ├── requests.py        # All Pydantic request models
│   │   ├── responses.py       # All Pydantic response models
│   │   ├── enums.py           # Severity, Language, Status enums
│   │   └── database.py        # SQLAlchemy ORM models
│   ├── services/
│   │   ├── __init__.py
│   │   ├── static_analyzer.py # Layer 1: Regex anti-pattern engine
│   │   ├── ast_analyzer.py    # Layer 3: tree-sitter AST analysis
│   │   ├── registry.py        # Layer 2: Package registry verification
│   │   ├── docker_verify.py   # Layer 2: Docker image/tag verification
│   │   ├── sandbox.py         # Layer 4: Isolated Docker sandbox execution
│   │   ├── cache.py           # Redis caching layer
│   │   ├── database.py        # Async database service (SQLAlchemy)
│   │   └── billing.py         # Stripe billing integration
│   ├── formatters/
│   │   ├── __init__.py
│   │   └── sarif.py           # SARIF v2.1.0 output formatter
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── parsers.py         # Import extraction, requirements parsing
│   │   └── similarity.py      # Fuzzy matching for "did you mean?"
│   └── rules/
│       ├── __init__.py
│       ├── anti_patterns.py   # Anti-pattern rule definitions
│       └── enterprise.py      # Enterprise file/structure rules
├── tests/
│   ├── __init__.py
│   ├── conftest.py            # Shared fixtures
│   ├── test_static.py         # Layer 1 tests
│   ├── test_registry.py       # Layer 2 registry tests
│   ├── test_docker.py         # Layer 2 docker tests
│   ├── test_models.py         # Pydantic model tests
│   ├── test_api_endpoints.py  # FastAPI endpoint tests
│   ├── test_deep_scan.py      # Deep scan integration tests
│   ├── test_cache.py          # Cache service tests (fakeredis)
│   ├── test_similarity.py     # Fuzzy matching tests
│   ├── test_parsers.py        # Parser utility tests
│   ├── test_sarif.py          # SARIF formatter tests
│   ├── test_sandbox.py        # Sandbox service tests
│   ├── test_billing.py        # Billing service tests
│   └── test_database.py       # Database service tests
├── extension/                   # VS Code extension (TypeScript)
├── dashboard/                   # Next.js admin dashboard
├── action/                      # GitHub Action for CI integration
├── sandbox/                     # Sandbox Dockerfile definitions
├── hooks/                       # Git hooks (pre-commit)
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
├── CHANGELOG.md
├── LICENSE
├── PLAN.md
├── SPEC.md
├── Procfile
└── railway.toml
```

## Absolute Prohibitions

- ❌ No `print()` — use `structlog` for all logging
- ❌ No `Any` types — explicit types on everything
- ❌ No `eval()` / `exec()`
- ❌ No hardcoded URLs — all registry URLs in config.py
- ❌ No hardcoded secrets — all via environment variables
- ❌ No wildcard imports
- ❌ No synchronous HTTP calls — all httpx calls must be async
- ❌ No bare `except:` — always catch specific exceptions
- ❌ No mutable default arguments
- ❌ No string concatenation for URLs — use httpx URL building or f-strings with validated inputs

## Required Practices

- ✅ Every function has type annotations on all parameters and return type
- ✅ Every public function and class has a docstring
- ✅ Every external HTTP call wrapped in try/except with timeout
- ✅ Every Pydantic model uses `model_config = ConfigDict(strict=True)`
- ✅ Every API endpoint has response_model defined
- ✅ Constants in UPPER_SNAKE_CASE at module level
- ✅ Max 40 lines per function — split if longer
- ✅ All registry URLs defined in config.py as class attributes
- ✅ All cache TTLs defined as constants in config.py
- ✅ Use `structlog` with JSON output for all logging

## Build Order

**Read PLAN.md for the exact build sequence. Build one phase at a time. Do not skip ahead.**

Phase 1 → Phase 2 → Phase 3 → Phase 4. Each phase has acceptance criteria that must pass before moving on.

## Testing Rules

- Every service module must have a corresponding test file
- Use `pytest-httpx` to mock all external HTTP calls — never hit real registries in tests
- Use `fakeredis` for cache tests — never require a running Redis
- Minimum: every public function has at least one happy-path and one error-path test
- Run `ruff check src/` before committing — zero warnings allowed

## Error Handling Pattern

```python
from src.models.enums import Severity
from src.models.responses import Finding

# Every verification function returns list[Finding], never raises
async def verify_something(input: SomeInput) -> list[Finding]:
    findings: list[Finding] = []
    try:
        result = await _do_check(input)
        if not result.valid:
            findings.append(Finding(
                rule_id="check_name",
                severity=Severity.BLOCK,
                message="Clear description of what's wrong",
                suggestion="What to do instead",
            ))
    except httpx.TimeoutException:
        findings.append(Finding(
            rule_id="check_name",
            severity=Severity.WARN,
            message="Could not verify — registry timeout",
        ))
    except httpx.HTTPError as exc:
        findings.append(Finding(
            rule_id="check_name",
            severity=Severity.WARN,
            message=f"Could not verify — HTTP error: {exc}",
        ))
    return findings
```

## Configuration Pattern

```python
# All config via pydantic-settings, never scattered
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_config = ConfigDict(env_prefix="CODETRUST_")

    redis_url: str = "redis://localhost:6379"
    api_key: str = ""  # Required in production
    # ... etc
```
