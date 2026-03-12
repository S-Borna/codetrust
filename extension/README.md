# CodeTrust — AI Governance Enforcement for VS Code

**Stop AI-generated code from reaching production unchecked.**

286 rules across 10 enforcement layers. Four capabilities no linter, SAST tool, or formatter has:

1. **AI Governance Gateway** — 82 real-time interception rules block destructive AI agent actions *before* they execute
2. **Hallucination Detection** — Live verification of every import against PyPI, npm, crates.io, Go proxy, Maven, NuGet, RubyGems, and Packagist
3. **Trust Score & Drift Tracking** — Baseline your codebase and detect safety regression over time
4. **Universal IDE Injection** — governance rules injected into every AI IDE globally on install; active monitoring detects and recovers from disruptions

Works with **Claude Code**, **Cursor**, **Windsurf**, **GitHub Copilot**, and any AI coding assistant.

---

## What's New in 2.8.2

- **Vision-complete release** — all 22 PRODUCT.md promises verified against actual code. Zero gaps between marketing and reality
- **10-language AST analysis** — Python, JS, TS, Go, Rust, Java, C#, C++, Ruby, PHP with cyclomatic complexity, unused variables, unreachable code, deep nesting
- **Signature Validation** — curated function database (33 modules, 223 functions) validates call signatures with min/max argument enforcement, catching AI hallucinations at the function-call level
- **1100+ typosquatting-protected packages** across 8 registries (PyPI, npm, crates.io, Go, Maven, NuGet, RubyGems, Packagist)
- **Universal IDE Injection** — governance rules injected into the global config of every AI IDE on your machine (Claude Code, Cursor, Windsurf, GitHub Copilot)
- **Secret Storage hardening** — API key migration always overwrites stale credentials
- **Global MCP config fix** — `${workspaceFolder}` no longer crashes in non-workspace contexts
- **Tenant Policy Bundles & Signed Snapshots** — `/v1/governance/policy-bundles` and `/v1/governance/policy-snapshot`
- **Explainable Gateway BLOCKs** — blocked responses include `root_cause` and `safe_fix`
- **27 MCP tools, 60 API endpoints, 286 rules****

---

## Why CodeTrust

AI coding assistants produce failure modes no existing tool detects:

- **Hallucinated packages** — AI suggests packages that don't exist on PyPI/npm
- **Destructive commands** — AI agents run `rm -rf /`, dynamic code execution, `curl|sh`
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
| Java | ✅ | ✅ | ✅ (Maven) |
| C# | ✅ | ✅ | ✅ (NuGet) |
| Ruby | ✅ | ✅ | ✅ (RubyGems) |
| PHP | ✅ | ✅ | ✅ (Packagist) |
| C / C++ | ✅ | ✅ | — |
| Shell / Bash | ✅ | — | — |
| Terraform / HCL | ✅ | — | — |
| HTML | ✅ | — | — |
| SQL | ✅ | — | — |
| Dockerfile | ✅ | — | ✅ (Docker Hub) |
| YAML / Kubernetes | ✅ | — | — |
| PowerShell | ✅ | — | — |

---

## Commands

| Command | Description |
|---------|-------------|
| `CodeTrust: Scan File` | Run configured scan on the active file |
| `CodeTrust: Guided Onboarding` | Configure API URL/key and run your first scan |
| `CodeTrust: Create CodeTrust Profile` | Create a reusable CodeTrust profile for this workspace |
| `CodeTrust: Apply CodeTrust Profile` | Apply a CodeTrust profile to current settings |
| `CodeTrust: Health Check` | Validate API URL/key configuration and connectivity |
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
| `codetrust.apiUrl` | `https://api.codetrust.ai` | CodeTrust API server URL |
| `codetrust.apiKey` | `""` | Deprecated: API key is stored in VS Code Secret Storage (use Guided Onboarding) |
| `codetrust.scanOnSave` | `true` | Auto-scan on save |
| `codetrust.scanOnType` | `false` | Scan while typing (embedded offline scanner) |
| `codetrust.scanOnTypeDebounceMs` | `600` | Debounce delay for scan while typing |
| `codetrust.scanType` | `static` | `static` (fast) or `deep` (full analysis) |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.enabledLanguages` | `[...]` | Languages to scan |
| `codetrust.verifyImportsOnSave` | `false` | Verify imports on save (requires network) |
| `codetrust.timeout` | `15000` | Request timeout in milliseconds |
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
| **GitHub Action** | `uses: S-Borna/codetrust@v2.8.2` |
| **MCP Server** | 27 tools for Claude Code / Cursor / Windsurf |
| **REST API** | 60 endpoints |
| **Website** | [codetrust.ai](https://codetrust.ai) |

---

## Getting Started

1. **Install** from the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust)
2. **Open** any Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby, PHP, C++, Shell, PowerShell, Terraform, HTML, SQL, Dockerfile, or YAML file
3. **Save** — diagnostics appear automatically

All scan rules work offline. Import verification, AI governance, and deep scanning work out of the box with the default cloud API.

---

## Links

- [Website](https://codetrust.ai)
- [PyPI](https://pypi.org/project/codetrust/)
- [Changelog](https://codetrust.ai)

---

**License** — Proprietary. Copyright (c) 2026 Said Borna. All rights reserved.
