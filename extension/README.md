# CodeTrust — AI Code Safety for VS Code

**Stop AI-generated code from reaching production unchecked.**

## Features

- Blocks hallucinated packages before install
- Intercepts destructive AI agent commands before execution
- Enforces governance in CI/CD pipelines
- Trust score tracking and drift analysis
- Works with Claude Code, Cursor, GitHub Copilot, and any AI assistant

---

132 rules across 10 enforcement layers. Three capabilities no linter, SAST tool, or formatter has:

1. **AI Governance Gateway** — 57 real-time interception rules block destructive AI agent actions *before* they execute
2. **Hallucination Detection** — Live verification of every import against PyPI, npm, crates.io, and Go proxy
3. **Trust Score & Drift Tracking** — Baseline your codebase and detect safety regression over time

Works with **Claude Code**, **Cursor**, **GitHub Copilot**, and any AI coding assistant.

---

## What's New in 2.2

- **132 total rules** — scan rules + gateway interception rules working together
- **AI Governance Gateway** — intercepts destructive AI agent actions in real-time
- **Live import verification** — every package checked against live registries
- **Trust Score** — quantified code safety with baseline trending and drift detection
- **Full REST API** — authenticated endpoints with SSO, billing, and SARIF export
- **17 MCP tools** — Model Context Protocol server for AI agent integration
- **Live telemetry** — real-time usage stats from production Cloud API

---

## Why CodeTrust

AI coding assistants produce failure modes no existing tool detects:

- **Hallucinated packages** — AI suggests packages that don't exist on PyPI/npm
- **Destructive commands** — AI agents run `rm -rf /`, `eval()`, `curl|sh`
- **Ghost Docker images** — AI references images that don't exist
- **Invisible drift** — AI code quality degrades without measurement

SonarQube, Snyk, Semgrep, Ruff — none of them intercept AI agents, verify imports against live registries, or track trust scores. CodeTrust uniquely combines all three.

---

## Features

- **Scan on Save** — automatic analysis when you save any supported file
- **Scan Workspace** — scan up to 500 files with progress bar
- **Inline Diagnostics** — findings as squiggly lines with severity coloring
- **Quick-Fix Actions** — apply suggestions, suppress rules, or remove lines
- **Status Bar** — last scan verdict (PASS / WARN / BLOCK) with online/offline indicator
- **AI Governance** — configurable policies that intercept AI agent actions
- **Offline Mode** — all scan rules run locally. No API, no network, no excuses
- **Import Verification** — every package checked against live registries
- **Docker Verification** — base images validated against Docker Hub / GHCR
- **SARIF Export** — standard format for GitHub Security tab and CI/CD

---

## When to Use CodeTrust

- **AI-assisted development** — Claude Code, GitHub Copilot, Cursor
- **CI/CD pipelines** requiring governance enforcement
- **Preventing hallucinated dependencies** from reaching production
- **Blocking destructive agent actions** before they execute
- **Tracking code safety trends** to catch regression early

---

## Performance

| Operation | Typical Time |
|-----------|:------------:|
| Static scan (per file) | < 200ms |
| Gateway validation (per command) | < 5ms |
| Deep scan (typical project) | < 2s |
| Import verification (cached) | < 50ms |
| Production runtime overhead | Zero |

---

## Supported Languages

| Language | Static | AST | Import Verification |
|----------|:------:|:---:|:-------------------:|
| Python | ✅ | ✅ | ✅ (PyPI) |
| JavaScript / TypeScript | ✅ | ✅ | ✅ (npm) |
| Go | ✅ | ✅ | ✅ (Go proxy) |
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
| `CodeTrust: Verify Imports` | Check packages against live registries |
| `CodeTrust: Verify Dockerfile` | Validate Docker base images and tags |
| `CodeTrust: Governance Status` | Show current governance rules and mode |
| `CodeTrust: Clear Diagnostics` | Remove all CodeTrust diagnostics |

---

## Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.scanOnSave` | `true` | Auto-scan on save |
| `codetrust.scanType` | `static` | `static` (fast) or `deep` (full analysis) |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.verifyImportsOnSave` | `false` | Verify imports on save (requires network) |
| `codetrust.governance.enabled` | `true` | Enable AI governance |
| `codetrust.governance.mode` | `enforce` | `enforce` (block) / `audit` (log) / `off` |
| `codetrust.governance.blockHeredoc` | `true` | Block heredoc patterns |
| `codetrust.governance.blockEval` | `true` | Block eval/exec in terminals |
| `codetrust.governance.blockGitPush` | `true` | Block AI agents from pushing |
| `codetrust.governance.protectedPaths` | LICENSE, .env | Require confirmation before writes |

---

## Also Available As

| Surface | Install |
|---------|---------|
| **CLI** | `pip install codetrust` |
| **GitHub Action** | `uses: S-Borna/codetrust@v2` |
| **MCP Server** | 17 tools for Claude Code / Cursor |
| **REST API** | 27 authenticated endpoints |
| **Website** | [codetrust.saidborna.com](https://codetrust.saidborna.com) |

---

## Getting Started

1. **Install** from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust)
2. **Open** any Python, JavaScript, TypeScript, Go, Rust, SQL, Dockerfile, or YAML file
3. **Save** — diagnostics appear automatically

All scan rules work offline. Import verification, AI governance, and deep scanning work out of the box with the default cloud API.

---

## Links

- [Website](https://codetrust.saidborna.com)
- [PyPI](https://pypi.org/project/codetrust/)
- [GitHub](https://github.com/S-Borna/codetrust)
- [Changelog](https://github.com/S-Borna/codetrust/blob/main/CHANGELOG.md)

---

**License** — Proprietary. Copyright (c) 2026 Said Borna. All rights reserved.
