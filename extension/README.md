# CodeTrust — VS Code Extension

AI code governance and verification platform — **82 rules across 10 enforcement layers** (67 scan + 15 gateway). Prevents hallucinated packages, unsafe patterns, and CI/CD failures inline in your editor. Includes pre-execution AI governance gateway. Works offline.

---

## What's New in 2.0

- **82 total rules** — 67 scan rules (56 regex + 11 file-level) + 15 gateway rules
- **React / JSX** — `dangerouslySetInnerHTML`, `innerHTML`, missing `key`, direct DOM, `useEffect` without deps
- **Kubernetes** — `privileged: true`, `hostNetwork`, `runAsUser: 0`, missing resource limits, `:latest` tag
- **SARIF output** — `codetrust scan --sarif` for GitHub Code Scanning
- **Project config** — `.codetrust.toml` with `exclude_paths`, `ignore_rules`, `severity_overrides`
- **Scan Workspace** — Scans up to 500 files with progress UI

---

## 9 Enforcement Layers

| # | Layer | Rules | What It Catches |
|:-:|-------|:-----:|-----------------|
| 01 | **Static Analysis** | 15 | Secrets, `eval`/`exec`, bare `except`, mutable defaults, magic numbers |
| 02 | **Root Cause Analysis** | 4 | Swallowed exceptions, lint suppression, sleep without context, debug mode |
| 03 | **SQL Analysis** | 13 | `SELECT *`, `DELETE` without `WHERE`, `FLOAT` for money, `GRANT ALL` |
| 04 | **AST Analysis** | — | Cyclomatic complexity, unused variables, unreachable code (tree-sitter) |
| 05 | **Container Hardening** | 10 | Root user, `:latest` tags, missing `WORKDIR`, `ENV` secrets, no healthcheck |
| 06 | **IaC & Config** | 7 | Hardcoded IPs, debug mode in config, API keys, unbounded retries |
| 07 | **React & Kubernetes** | 13 | `dangerouslySetInnerHTML`, `privileged: true`, missing resource limits |
| 08 | **Package Verification** | — | Verify imports exist in PyPI, npm, crates.io, Go proxy |
| 09 | **Docker Verification** | — | Verify base images and tags against Docker Hub / GHCR |

---

## Features

- **Scan on Save** — Automatically runs static analysis when you save
- **Scan Workspace** — Scan up to 500 files with progress bar
- **Inline Diagnostics** — Findings as squiggly lines with severity coloring
- **Quick-Fix Actions** — Apply suggestions, suppress rules, or remove lines
- **Status Bar** — Last scan verdict (PASS / WARN / BLOCK) with online/offline indicator
- **Offline Mode** — All 62 static rules run locally, no API needed
- **Verification Cache** — Import and Docker results cached 7 days
- **SARIF Export** — Standard format for CI/CD integration

---

## Offline vs Online

| Capability | Offline | Online |
|------------|:-------:|:------:|
| Static analysis (67 rules) | Yes | Yes |
| File-level checks (11 handlers) | Yes | Yes |
| AST analysis (tree-sitter) | — | Yes |
| Import verification | Cached | Live |
| Docker verification | Cached | Live |
| Sandbox execution | — | Yes |

---

## Supported Languages

Python, JavaScript, TypeScript, JSX, TSX, Go, Rust, SQL, Dockerfile, YAML

---

## Commands

| Command | Description |
|---------|-------------|
| `CodeTrust: Scan File` | Run configured scan on active file |
| `CodeTrust: Deep Scan` | Full deep scan (static + AST + imports) |
| `CodeTrust: Scan Workspace` | Scan all supported files in workspace |
| `CodeTrust: Verify Imports` | Check packages against registries |
| `CodeTrust: Verify Dockerfile` | Validate Docker images and tags |
| `CodeTrust: Clear Diagnostics` | Remove all CodeTrust diagnostics |

---

## AI Governance

The extension includes configurable governance policies that control AI agent behavior:

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.governance.enabled` | `true` | Master switch for governance |
| `codetrust.governance.mode` | `enforce` | `enforce` / `audit` / `off` |
| `codetrust.governance.blockHeredoc` | `true` | Block heredoc in terminals |
| `codetrust.governance.blockEval` | `true` | Block eval in terminals |
| `codetrust.governance.blockGitPush` | `true` | Block git push by AI |
| `codetrust.governance.protectedPaths` | LICENSE, .env | Warn on writes to these files |

All governance rules can be disabled per-project via settings or `.codetrust.toml`.

---

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.apiUrl` | Cloud URL | API server URL |
| `codetrust.apiKey` | — | API key for authentication |
| `codetrust.scanOnSave` | `true` | Auto-scan files on save |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.scanType` | `static` | `static` or `deep` |

---

## Getting Started

1. Install from the VS Code Marketplace
2. Open any supported file
3. Save — diagnostics appear automatically

Works offline with all 67 scan rules. For deep scanning, add an API key or self-host.

---

## License

Proprietary — Copyright (c) 2026 Said Borna. All rights reserved.
