# CodeTrust — VS Code Extension

AI code verification that catches hallucinated packages, broken configs, and anti-patterns — inline in your editor.

## Features

- **Scan on Save** — Automatically runs static analysis when you save a file
- **Command Palette** — `CodeTrust: Scan File`, `CodeTrust: Deep Scan`, `CodeTrust: Verify Imports`, `CodeTrust: Verify Dockerfile`
- **Inline Diagnostics** — Findings appear as squiggly lines with severity-based coloring (error/warning/info)
- **Quick-Fix Actions** — Apply suggestions, suppress rules, or remove problematic lines
- **Status Bar** — Shows last scan verdict (PASS ✓ / WARN ⚠ / BLOCK ✗)
- **Import Verification** — Checks that imported packages actually exist in PyPI, npm, crates.io, Go proxy
- **Docker Verification** — Validates Docker images and tags exist on Docker Hub / GHCR

## Supported Languages

- Python
- JavaScript / TypeScript (including JSX/TSX)
- Go
- Rust
- Dockerfile

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.apiUrl` | `http://localhost:8000` | CodeTrust API server URL |
| `codetrust.apiKey` | `""` | API key for authentication |
| `codetrust.scanOnSave` | `true` | Auto-scan files on save |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.enabledLanguages` | All 5 | Languages to scan |
| `codetrust.scanType` | `static` | `static` or `deep` scan mode |
| `codetrust.verifyImportsOnSave` | `false` | Also verify imports on save |
| `codetrust.timeout` | `15000` | Request timeout (ms) |

## Getting Started

1. Install the extension
2. Start the CodeTrust API server (`docker compose up` or `python -m src.api`)
3. Open a Python/JS/TS/Go/Rust file
4. Save the file — diagnostics appear automatically

For cloud usage, set `codetrust.apiUrl` to your deployed API URL and add your `codetrust.apiKey`.

## Commands

- `CodeTrust: Scan File` — Run configured scan type on the active file
- `CodeTrust: Deep Scan` — Run full deep scan (static + AST + imports)
- `CodeTrust: Verify Imports` — Check all imported packages against registries
- `CodeTrust: Verify Dockerfile` — Validate Docker images and tags
- `CodeTrust: Clear Diagnostics` — Remove all CodeTrust diagnostics

## Development

```bash
cd extension
npm install
npm run compile
# Press F5 in VS Code to launch Extension Development Host
```

## License

MIT
