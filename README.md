# CodeTrust

AI code verification platform — MCP server + cloud API that catches hallucinated packages, broken configs, and code anti-patterns before they hit production.

## What It Does

| Layer | Capability | How |
|-------|-----------|-----|
| **Static Analysis** | Detect anti-patterns, secrets, eval/exec, SQL injection, etc. | Regex engine, 35+ rules |
| **Package Verification** | Verify imports exist in real registries | PyPI, npm, Docker Hub |
| **Docker Verification** | Verify base images and tags exist | Docker Hub API |
| **Enterprise Checks** | Validate repo structure | README, LICENSE, tests, etc. |
| **Deep Scan** | All layers combined in one pass | Orchestrated scan |

## Quick Start

### Install

```bash
# Clone and install
git clone https://github.com/yourorg/codetrust.git
cd codetrust
pip install -e ".[dev]"

# Or use the setup script
chmod +x setup.sh && ./setup.sh --all
```

### Run MCP Server (for Claude Code)

```bash
python -m src.server
```

### Run HTTP API

```bash
# Local (no Redis required — degrades gracefully)
uvicorn src.api:app --host 0.0.0.0 --port 8000

# With Redis (recommended for caching)
docker compose up -d
```

## MCP Configuration for Claude Code

Add to your Claude Code MCP settings (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "codetrust": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/codetrust"
    }
  }
}
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `codetrust_static_scan` | Scan code for anti-patterns and security issues |
| `codetrust_pre_action` | Validate plan before writing code |
| `codetrust_post_action` | Validate completed work against enterprise standards |
| `codetrust_list_rules` | List all rules and their severities |
| `codetrust_verify_imports` | Verify package imports exist in registries |
| `codetrust_verify_dockerfile` | Verify Docker base images and tags exist |
| `codetrust_deep_scan` | Run all validation layers in a single pass |

## API Endpoints

All endpoints require `X-API-Key` header when `CODETRUST_API_KEY` is set. In local dev (no key set), auth is skipped.

### `GET /v1/status`

Health check. Returns version and cache status.

```bash
curl http://localhost:8000/v1/status
# {"status":"ok","version":"1.0.0","cache_connected":true}
```

### `POST /v1/scan/static`

Static anti-pattern analysis.

```bash
curl -X POST http://localhost:8000/v1/scan/static \
  -H "Content-Type: application/json" \
  -d '{"code": "import os\neval(input())", "filename": "app.py"}'
```

### `POST /v1/verify/imports`

Verify package imports exist in registries.

```bash
curl -X POST http://localhost:8000/v1/verify/imports \
  -H "Content-Type: application/json" \
  -d '{"language": "python", "imports": ["fastapi", "nonexistent_xyz"]}'
```

### `POST /v1/verify/dockerfile`

Verify Docker images and tags.

```bash
curl -X POST http://localhost:8000/v1/verify/dockerfile \
  -H "Content-Type: application/json" \
  -d '{"images": [{"image": "python", "tag": "3.12-slim"}]}'
```

### `POST /v1/scan/deep`

Full deep scan combining all layers.

```bash
curl -X POST http://localhost:8000/v1/scan/deep \
  -H "Content-Type: application/json" \
  -d '{
    "code": "import fastapi\nimport nonexistent_xyz",
    "filename": "app.py",
    "language": "python",
    "verify_imports": true,
    "verify_docker": false
  }'
```

## Configuration

All settings via environment variables prefixed with `CODETRUST_`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CODETRUST_HOST` | `0.0.0.0` | API bind host |
| `CODETRUST_PORT` | `8000` | API bind port |
| `CODETRUST_DEBUG` | `false` | Enable debug/reload mode |
| `CODETRUST_API_KEY` | `""` | API key (empty = no auth) |
| `CODETRUST_REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `CODETRUST_HTTP_TIMEOUT` | `10.0` | HTTP client timeout (seconds) |
| `CODETRUST_CACHE_TTL_PACKAGE_EXISTS` | `86400` | Cache TTL for package existence |
| `CODETRUST_CACHE_TTL_DOCKER_TAG` | `86400` | Cache TTL for Docker tags |

See [.env.example](.env.example) for all available options.

## Docker

```bash
# Build
docker build -t codetrust .

# Run API server
docker run -p 8000:8000 codetrust

# Run MCP server
docker run codetrust python -m src.server

# Full stack with Redis
docker compose up -d
```

## Deployment (Railway)

1. Connect your GitHub repo to [Railway](https://railway.app)
2. Add a Redis service
3. Set environment variables: `CODETRUST_API_KEY`, `CODETRUST_REDIS_URL`
4. Deploy — Railway uses the included `railway.toml`

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/

# Run with pre-commit hooks
./setup.sh --hooks
```

## Architecture

```
┌─────────────────────────────────────┐
│         Claude Code / Client        │
└──────────┬──────────────────────────┘
           │ MCP Protocol
┌──────────▼──────────────────────────┐
│       MCP Server (server.py)        │
│  7 tools: scan, verify, deep_scan   │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│       FastAPI (api.py)              │
│  5 endpoints, X-API-Key auth        │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│          Services Layer             │
│  StaticAnalyzer │ Registry │ Docker │
└──────────┬──────────────────────────┘
           │
┌──────────▼──────────────────────────┐
│    Redis Cache (graceful degrade)   │
└─────────────────────────────────────┘
```

## License

MIT
