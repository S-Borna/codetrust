# CodeTrust

AI code verification platform — MCP server + cloud API that catches hallucinated packages, broken configs, and code anti-patterns.

## Features

- **Static Analysis (Layer 1):** Regex-based anti-pattern detection for security issues, code quality, and best practices
- **Package Verification (Layer 2):** Verify imports exist in real registries (PyPI, npm)
- **Docker Verification (Layer 2):** Verify Docker base images and tags exist on Docker Hub
- **Enterprise Structure Checks:** Validate repo structure against best practices

## Quick Start

### Installation

```bash
pip install -e ".[dev]"
```

### Run MCP Server

```bash
python -m src.server
```

### Run API Server

```bash
uvicorn src.api:app --host 0.0.0.0 --port 8000
```

## MCP Tools

| Tool | Description |
|------|-------------|
| `codetrust_static_scan` | Scan code for anti-patterns and security issues |
| `codetrust_pre_action` | Validate plan before writing code |
| `codetrust_post_action` | Validate completed work against enterprise standards |
| `codetrust_list_rules` | List all rules and their severities |

## Configuration

All settings via environment variables prefixed with `CODETRUST_`. See `.env.example` for available options.

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Lint
ruff check src/
```

## License

MIT
