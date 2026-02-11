# CodeTrust — VS Code Extension

AI code verification that catches hallucinated packages, broken configs, anti-patterns, container & CI/CD issues — inline in your editor.

## Features

- **Scan on Save** — Automatically runs static analysis when you save a file
- **Command Palette** — `CodeTrust: Scan File`, `CodeTrust: Deep Scan`, `CodeTrust: Verify Imports`, `CodeTrust: Verify Dockerfile`
- **Inline Diagnostics** — Findings appear as squiggly lines with severity-based coloring (error/warning/info)
- **Quick-Fix Actions** — Apply suggestions, suppress rules, or remove problematic lines
- **Status Bar** — Shows last scan verdict (PASS ✓ / WARN ⚠ / BLOCK ✗)
- **Import Verification** — Checks that imported packages actually exist in PyPI, npm, crates.io, Go proxy
- **Docker Verification** — Validates Docker images and tags exist on Docker Hub / GHCR
- **SQL Scanning** — 13 rules for `.sql` files: SELECT *, DELETE/UPDATE without WHERE, FLOAT for money, GRANT ALL, and more
- **Container Hardening** — Detects root user, latest tags, missing WORKDIR, secrets baked into ENV
- **CI/CD Analysis** — Unpinned GitHub Actions, missing timeouts in workflows
- **AI Drift Score** — Composite 0–100 trust metric with A–F grades across 6 categories

## Supported Languages

- Python
- JavaScript / TypeScript (including JSX/TSX)
- Go
- Rust
- **SQL** (migrations, schemas, seed files)
- Dockerfile
- **YAML** (GitHub Actions, CI/CD workflows)

## SQL Rules

| Rule | Severity | What it catches |
| ---- | -------- | --------------- |
| `sql_select_star` | BLOCK | `SELECT *` — specify columns explicitly |
| `sql_delete_no_where` | BLOCK | `DELETE` without `WHERE` clause |
| `sql_update_no_where` | BLOCK | `UPDATE` without `WHERE` clause |
| `sql_drop_no_if_exists` | BLOCK | `DROP TABLE/DATABASE` without `IF EXISTS` |
| `sql_grant_all` | BLOCK | `GRANT ALL` — excessive privileges |
| `sql_foreign_key_checks_off` | BLOCK | Disabling FK checks bypasses integrity |
| `sql_float_for_money` | WARN | `FLOAT` for monetary columns — use `DECIMAL` |
| `sql_varchar_no_length` | WARN | `VARCHAR()` without specified length |
| `sql_todo_hack` | WARN | `-- TODO/FIXME` markers in SQL |
| `sql_composite_pk_auto_increment` | WARN | AUTO_INCREMENT in composite PK |
| `sql_autocommit_off` | INFO | Manual transaction control — verify COMMIT exists |
| `sql_hardcoded_id` | INFO | IDs as strings (`'1'`) instead of integers |
| `sql_no_index_hint` | INFO | FK detected — verify index exists |

## Container & CI/CD Rules

| Rule | Severity | What it catches |
| ---- | -------- | --------------- |
| `docker_root_user` | BLOCK | Dockerfile without USER directive — runs as root |
| `docker_env_secret` | BLOCK | Secret value baked into Dockerfile ENV |
| `docker_latest_tag` | WARN | FROM image:latest — pin to specific version |
| `docker_no_workdir` | INFO | No WORKDIR set — files land in root directory |
| `ci_unpinned_action` | WARN | GitHub Action uses @master/@main — pin to SHA or version |
| `ci_no_timeout` | WARN | CI job has no timeout-minutes |
| `except_swallow` | WARN | Exception caught and silently ignored |
| `suppress_lint` | WARN | Linter suppression without justification |
| `debug_mode_enabled` | WARN | Debug mode left enabled in config |
| `hardcoded_ip` | WARN | Hardcoded IP address — use DNS or config |

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.apiUrl` | `http://localhost:8000` | CodeTrust API server URL |
| `codetrust.apiKey` | `""` | API key for authentication |
| `codetrust.scanOnSave` | `true` | Auto-scan files on save |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.enabledLanguages` | All 6 | Languages to scan |
| `codetrust.scanType` | `static` | `static` or `deep` scan mode |
| `codetrust.verifyImportsOnSave` | `false` | Also verify imports on save |
| `codetrust.timeout` | `15000` | Request timeout (ms) |

## Getting Started

1. Install the extension
2. Start the CodeTrust API server (`docker compose up` or `python -m src.api`)
3. Open a Python/JS/TS/Go/Rust/SQL file
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

Proprietary — Copyright (c) 2026 Said Borna. All rights reserved.
