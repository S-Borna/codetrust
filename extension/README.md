# CodeTrust — AI Code Safety for VS Code

**The only extension that stops AI-generated code from reaching production unchecked.**

132 rules across 10 enforcement layers. Three capabilities no linter, SAST tool, or formatter has:

1. **AI Governance Gateway** — 57 real-time interception rules block destructive AI agent actions *before* they execute
2. **Hallucination Detection** — Live verification of every import against PyPI, npm, crates.io, and Go proxy
3. **Trust Score & Drift Tracking** — Baseline your codebase and detect safety regression over time

Works with **Claude Code**, **Cursor**, **GitHub Copilot**, and any AI coding assistant.

---

## What's New in 2.2

- **132 total rules** — 75 scan rules + 57 gateway interception rules
- **AI Governance Gateway** — 46 terminal rules + 11 content rules intercept AI agent actions in real-time
- **Live import verification** — Every package checked against PyPI/npm/crates.io/Go proxy
- **Trust Score** — Quantified code safety with baseline trending and drift detection
- **27 API endpoints** — Full REST API with auth, billing, SSO, and SARIF export
- **17 MCP tools** — Model Context Protocol server for AI agent integration
- **Live telemetry** — Real-time usage stats from production Cloud API

---

## Three Moats — What Makes CodeTrust Different

### Moat 1: AI Governance Gateway (57 Rules)

The gateway intercepts AI agent actions **before execution**. Terminal commands, file writes, and package installs are validated in real-time.

| Category | Rules | Examples |
|----------|:-----:|---------|
| File Destruction | 8 | `rm -rf /`, `find -delete`, `shred` |
| Code Execution | 6 | `eval()`, `base64 -d \| bash`, `python -c` |
| Privilege Escalation | 5 | `chmod 777`, `sudo su`, `chown root` |
| Git Operations | 4 | `git push --force`, `git reset --hard` |
| Container Escape | 5 | `--privileged`, `--pid=host`, `docker.sock` mount |
| Network Exfiltration | 5 | `curl \| sh`, `wget -O- \| bash`, `nc -e` |
| Secrets Exposure | 4 | `printenv`, `cat .env`, `echo $SECRET` |
| Supply Chain | 5 | `pip install --index-url`, `npm publish`, typosquatting |
| Resource Abuse | 4 | Fork bombs, `:(){ :\|: & };:`, crypto miners |
| **Content Rules** | **11** | Hardcoded secrets, private keys, AWS keys, SSL bypass, CORS wildcards, pickle, eval/exec in files |

### Moat 2: Hallucination Detection Engine

Every scan extracts imports from your Python and JavaScript files and verifies them against live package registries.

- **`flask-restful-api`** → NOT FOUND on PyPI. Did you mean `flask-restful`?
- **`@google/cloud-storage`** → NOT FOUND on npm. Did you mean `@google-cloud/storage`?
- Deprecated packages flagged as warnings
- Results cached 7 days for offline use

### Moat 3: Trust Score & Drift Tracking

Quantified code safety that tracks how your codebase evolves:

- **Baseline scanning** — Establish your project's safety score
- **Trend graphs** — Visualize improvement or regression over time
- **Per-file scoring** — Identify which files carry the most risk
- **CI/CD integration** — Fail builds when trust score drops below threshold

---

## 10 Enforcement Layers

| # | Layer | Rules | What It Catches |
|:-:|-------|:-----:|-----------------|
| 01 | **Static Analysis** | 15 | Secrets, `eval`/`exec`, bare `except`, mutable defaults, magic numbers |
| 02 | **Root Cause Analysis** | 4 | Swallowed exceptions, lint suppression, sleep hacks, debug mode in prod |
| 03 | **SQL Analysis** | 13 | `SELECT *`, `DELETE` without `WHERE`, `FLOAT` for money, `GRANT ALL` |
| 04 | **AST Analysis** | — | Cyclomatic complexity, unused variables, unreachable code (tree-sitter) |
| 05 | **Container Hardening** | 10 | Root user, `:latest` tags, missing `WORKDIR`, `ENV` secrets |
| 06 | **IaC & Config** | 7 | Hardcoded IPs, debug mode, API keys in config, unbounded retries |
| 07 | **React & Kubernetes** | 13 | `dangerouslySetInnerHTML`, `privileged: true`, missing resource limits |
| 08 | **DevOps & CI/CD** | 13 | Secret echoing, `--no-verify`, `latest` deploys, unbounded retries |
| 09 | **Import Verification** | — | Every import checked against PyPI, npm, crates.io, Go proxy |
| 10 | **Docker Verification** | — | Every base image verified against Docker Hub and GHCR |

---

## Five Ways to Use CodeTrust

| Surface | Install | What You Get |
|---------|---------|--------------|
| **VS Code Extension** | Install from Marketplace | Scan on save, inline diagnostics, governance |
| **CLI** | `pip install codetrust` | `codetrust scan .` — full scan from terminal |
| **GitHub Action** | Add `codetrust/action@v2` | PR checks with SARIF upload to Security tab |
| **MCP Server** | 17 tools for AI agents | Claude Code / Cursor get real-time safety |
| **REST API** | 27 authenticated endpoints | Integrate into any pipeline |

---

## Features

- **Scan on Save** — Automatic static analysis when you save any supported file
- **Scan Workspace** — Scan up to 500 files with progress bar and aggregate results
- **Inline Diagnostics** — Findings shown as squiggly lines with severity coloring
- **Quick-Fix Actions** — Apply suggestions, suppress rules, or remove problematic lines
- **Status Bar** — Last scan verdict (PASS / WARN / BLOCK) with online/offline indicator
- **AI Governance** — Configurable policies that intercept AI agent terminal commands and file writes
- **Offline Mode** — All 75 scan rules run locally. No API, no network, no excuses
- **Import Verification** — Check every package against live registries (cached 7 days)
- **Docker Verification** — Validate base images and tags against Docker Hub / GHCR
- **SARIF Export** — Standard format for GitHub Security tab and CI/CD pipelines

---

## Supported Languages

| Language | Static | AST | Import Verify |
|----------|:------:|:---:|:-------------:|
| Python | ✅ | ✅ | ✅ (PyPI) |
| JavaScript / TypeScript | ✅ | ✅ | ✅ (npm) |
| JSX / TSX | ✅ | ✅ | ✅ (npm) |
| Go | ✅ | ✅ | ✅ (proxy.golang.org) |
| Rust | ✅ | ✅ | ✅ (crates.io) |
| SQL | ✅ | — | — |
| Dockerfile | ✅ | — | ✅ (Docker Hub) |
| YAML / Kubernetes | ✅ | — | — |

---

## Commands

| Command | Description |
|---------|-------------|
| `CodeTrust: Scan File` | Run configured scan on the active file |
| `CodeTrust: Deep Scan` | Full analysis — static + AST + imports |
| `CodeTrust: Scan Workspace` | Scan all supported files in workspace |
| `CodeTrust: Verify Imports` | Check all packages against live registries |
| `CodeTrust: Verify Dockerfile` | Validate Docker base images and tags |
| `CodeTrust: Governance Status` | Show current governance rules and mode |
| `CodeTrust: Clear Diagnostics` | Remove all CodeTrust diagnostics |

---

## AI Governance Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.governance.enabled` | `true` | Master switch for AI governance |
| `codetrust.governance.mode` | `enforce` | `enforce` (block) / `audit` (log only) / `off` |
| `codetrust.governance.blockHeredoc` | `true` | Block heredoc patterns that corrupt files |
| `codetrust.governance.blockEval` | `true` | Block eval/exec in terminal commands |
| `codetrust.governance.blockGitPush` | `true` | Block AI agents from pushing to remote |
| `codetrust.governance.protectedPaths` | LICENSE, .env | Files that require confirmation before writes |

---

## Extension Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.scanOnSave` | `true` | Auto-scan files on save |
| `codetrust.scanType` | `static` | `static` (fast) or `deep` (full analysis) |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.verifyImportsOnSave` | `false` | Verify imports on save (requires network) |
| `codetrust.apiUrl` | Cloud URL | API server — cloud or self-hosted |
| `codetrust.apiKey` | — | API key for authenticated features |
| `codetrust.timeout` | `15000` | Request timeout in milliseconds |

---

## Getting Started

1. **Install** from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust)
2. **Open** any Python, JavaScript, TypeScript, Go, Rust, SQL, Dockerfile, or YAML file
3. **Save** — diagnostics appear automatically

All 75 scan rules work offline. Import verification, AI governance, and deep scanning work out of the box with the default cloud API.

---

## Links

- [Website](https://codetrust.saidborna.com)
- [PyPI](https://pypi.org/project/codetrust/)
- [GitHub](https://github.com/S-Borna/codetrust)
- [Changelog](https://github.com/S-Borna/codetrust/blob/main/CHANGELOG.md)

---

**License** — Proprietary. Copyright (c) 2026 Said Borna. All rights reserved.
