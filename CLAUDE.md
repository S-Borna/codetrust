# CLAUDE.md — CodeTrust Project Rules

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
│   │   └── enums.py           # Severity, Language, Status enums
│   ├── services/
│   │   ├── __init__.py
│   │   ├── static_analyzer.py # Layer 1: Regex anti-pattern engine
│   │   ├── registry.py        # Layer 2: Package registry verification
│   │   ├── docker_verify.py   # Layer 2: Docker image/tag verification
│   │   ├── api_verify.py      # Layer 2: API endpoint verification
│   │   ├── dep_audit.py       # Layer 2: Dependency audit orchestrator
│   │   └── cache.py           # Redis caching layer
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
│   ├── test_api_verify.py     # Layer 2 API tests
│   ├── test_models.py         # Pydantic model tests
│   └── test_api_endpoints.py  # FastAPI endpoint tests
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
├── CHANGELOG.md
├── LICENSE
└── PLAN.md
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
