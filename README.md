<p align="center">
  <img src="https://raw.githubusercontent.com/S-Borna/codetrust/main/docs/logo.png" alt="CodeTrust" width="420">
</p>

<p align="center">
  <strong>Trust the code. Ship with proof.</strong>
</p>

<p align="center">
  <a href="https://pypi.org/project/codetrust/"><img src="https://img.shields.io/pypi/v/codetrust?style=flat-square&color=38d8fd" alt="PyPI"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust"><img src="https://img.shields.io/visual-studio-marketplace/v/SaidBorna.codetrust?style=flat-square&color=5bca78" alt="VS Code Marketplace"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Proprietary-333?style=flat-square" alt="License"></a>
  <a href="https://github.com/S-Borna/codetrust/actions"><img src="https://img.shields.io/github/actions/workflow/status/S-Borna/codetrust/ci.yml?style=flat-square&label=CI" alt="CI"></a>
</p>

<p align="center">
  <a href="https://codetrust.saidborna.com">Website</a> &middot;
  <a href="https://pypi.org/project/codetrust/">PyPI</a> &middot;
  <a href="https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust">VS Code</a> &middot;
  <a href="https://github.com/S-Borna/codetrust">GitHub</a> &middot;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## What CodeTrust Is

**AI Governance Enforcement Platform** — 132 rules across 10 enforcement layers, 17 MCP tools, 27 API endpoints. 1,314 tests.

CodeTrust prevents unsafe, hallucinated, and destructive AI-generated code from reaching production. It enforces safety across the entire development lifecycle — before execution, during development, before commit, during CI/CD, and before deployment.

CodeTrust is not a linter. It is not a formatter. It is a **governance enforcement platform** purpose-built for the era of AI-generated code, with three capabilities no existing tool provides.

---

## The Three Moats

### Moat 1: AI Governance Gateway

The Gateway intercepts AI agent actions **before execution** — not scanning files after the fact. Terminal commands, file writes, and package installs are validated against configurable policies in real-time.

57 interception rules across 9 categories: file destruction, code execution, privilege escalation, git operations, container escape, network exfiltration, secrets exposure, supply chain attacks, and resource abuse — plus content rules for file writes.

All rules are configurable. Any rule can be disabled per-project.

**Real proof:** During the development of v2.1.0, our own AI agent attempted to create a file using a heredoc pattern. The CodeTrust gateway blocked it in real-time — the product protected itself from its own builder.

### Moat 2: Hallucination Detection Engine

Every scan extracts imports from your source files and verifies them against **live package registries**. Hallucinated packages are flagged with exact file and line number.

```
$ codetrust scan app.py

🛡️  CodeTrust Scan
   Files: 1 | Findings: 2
   AI Drift Score: 87/100 (B)

  🚫 BLOCK — must fix:
     app.py:4 [import_not_found] Package 'flask_magic_utils' not found
     on pypi — possible AI hallucination.
```

`flask_magic_utils` does not exist on PyPI. Most traditional tools do not verify imports against live registries at development time.

CodeTrust also includes static hallucination rules that detect fabricated methods, config options, CLI flags, API endpoints, environment variables, and placeholder URLs — without network access.

### Moat 3: Trust Score & Drift Tracking

A quantified safety metric that tracks your codebase over time. Not a snapshot — a trend.

- Baseline your project's safety score
- Track improvement or regression across commits
- Grade curve: A+ through F
- Fail CI when the score drops below your threshold

```
🛡️  CodeTrust Scan
   Files: 47 | Findings: 3
   AI Drift Score: 94/100 (A)
   Trend: improving (+6 from baseline)
```

---

## Why CodeTrust Exists

AI writes code fast. But fast doesn't mean safe. **78% of developers** use AI coding assistants daily (2025). These tools produce failure modes that no existing tool detects:

| Failure Mode | What Happens | Who Catches It |
|---|---|---|
| **Hallucinated packages** | `pip install` fails — or worse: typosquatted malware installs | CodeTrust verifies imports against live registries |
| **Destructive agent commands** | `rm -rf /`, `eval()`, `curl\|sh` — data loss, RCE, supply chain compromise | CodeTrust Gateway intercepts before execution |
| **Ghost Docker images** | AI references images that don't exist — build breaks at 2AM | CodeTrust validates images against Docker Hub |
| **Invisible code drift** | AI code quality degrades gradually — no one measures it | CodeTrust tracks trust score over time |

### What existing tools miss

| Tool | What it does | What it doesn't do |
|---|---|---|
| **SonarQube** | 5,000+ quality rules | Does not intercept AI agents, verify imports, or track trust scores |
| **Snyk** | CVEs in known packages | Does not intercept AI agents, detect hallucinated packages, or track trust scores |
| **Semgrep** | Cross-file dataflow analysis | Does not intercept AI agents, verify imports against registries, or track trust scores |
| **Ruff / ESLint** | Code style, formatting | Does not intercept AI agents, verify imports, or track trust scores |

Unlike traditional tools, CodeTrust uniquely combines pre-execution interception, live registry verification, and quantified safety tracking.

---

## 10 Enforcement Layers

CodeTrust scans code across 10 layers covering static analysis, root cause analysis, SQL safety, AST structural analysis, container hardening, infrastructure-as-code, framework-specific rules (React, Kubernetes, CI/CD), live import verification, Docker image verification, and the real-time AI governance gateway.

**75 scan rules + 57 gateway rules = 132 total.** Every rule produces a BLOCK, WARN, or INFO verdict.

---

## Enforcement Model

CodeTrust enforces policies when integrated via MCP, pre-commit hooks, or CI/CD pipelines. Enforcement strength depends on integration point.

**Strong enforcement:**

| Integration | Guarantee |
|---|---|
| **Pre-commit hook** | Prevents unsafe commits — commit rejected until fixed |
| **CI/CD (GitHub Action)** | Prevents unsafe merges — PR fails required status check |
| **Gateway via MCP** | Prevents unsafe agent actions — command intercepted before execution |

**Advisory enforcement:**

| Integration | Behavior |
|---|---|
| **VS Code Extension** | Inline diagnostics — informs, does not block |
| **CLI scan** | Exit code 1 on BLOCK findings — enforcement depends on pipeline gating |

---

## When to Use CodeTrust

- **AI-assisted development** — Claude Code, GitHub Copilot, Cursor, or any AI coding assistant
- **CI/CD pipelines** requiring governance enforcement before merge
- **Preventing hallucinated dependencies** from reaching production
- **Blocking destructive agent actions** before they execute
- **Enforcing DevOps and infrastructure safety policies** across teams
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

CodeTrust runs at development time only. Zero runtime overhead in production.

---

## Quick Start

```bash
pip install codetrust
cd your-project
codetrust init
codetrust scan .
```

`codetrust init` sets up enforcement layers in your project: pre-commit hook, GitHub Action, AI assistant rules, governance config, and audit directory.

---

## Five Ways In

| Surface | Install | What You Get |
|---------|---------|--------------|
| **CLI** | `pip install codetrust` | Full scan from terminal with exit code enforcement |
| **VS Code** | Install from Marketplace | Scan on save, inline diagnostics, AI governance |
| **GitHub Action** | `uses: S-Borna/codetrust@v2` | PR checks with SARIF upload to Security tab |
| **MCP Server** | 17 tools for AI agents | Claude Code / Cursor get real-time safety feedback |
| **REST API** | 27 endpoints with rate limiting | Integrate into any pipeline or platform |

---

## CLI Usage

```bash
codetrust scan app.py              # Scan a file
codetrust scan src/                # Scan a directory
codetrust scan . --sarif           # SARIF output for CI
codetrust scan . --json            # JSON output
codetrust scan . --no-verify-imports  # Skip registry checks (offline)

codetrust status                   # Check enforcement status
codetrust doctor                   # Diagnose installation

codetrust governance --status      # Governance overview
codetrust governance --mode audit  # Switch to audit mode
codetrust audit --hours 24         # Review recent actions
```

---

## VS Code Extension

```bash
code --install-extension SaidBorna.codetrust
```

- Scans on save (configurable)
- Inline diagnostics with severity levels
- Works fully offline — all scan rules embedded
- "Scan Workspace" — up to 500 files with progress UI
- AI governance controls built in
- Deep scan mode for full analysis

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.scanOnSave` | `true` | Auto-scan on save |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.scanType` | `static` | `static` or `deep` |
| `codetrust.governance.enabled` | `true` | Enable AI governance |
| `codetrust.governance.mode` | `enforce` | `enforce` / `audit` / `off` |

---

## GitHub Action

```yaml
- uses: S-Borna/codetrust@v2
  with:
    fail-on: block
    scan-type: static
    sarif: true

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: codetrust-results.sarif
```

BLOCK findings fail the status check. Hallucinated packages appear as inline PR annotations.

---

## MCP Server

### 17 MCP Tools

Two MCP servers — one for scanning, one for governance. Works with Claude Code, Cursor, and any MCP-compatible agent.

Add to your MCP configuration and AI agents get real-time code safety feedback, pre-action validation, post-action quality checks, import verification, and governance enforcement — all through the Model Context Protocol.

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

## Configuration

CodeTrust is configured via `.codetrust.toml` or `[tool.codetrust]` in `pyproject.toml`.

You can:

- Exclude paths from scanning
- Ignore specific rules
- Override severity levels
- Set governance mode (enforce / audit / off)
- Define protected files
- Enable or disable gateway rule categories

See `codetrust init` for a starter configuration.

---

## Security & Compliance

| Property | Description |
|----------|-------------|
| **Audit trail** | Append-only, immutable log of all governance actions |
| **Agent identification** | Auto-detects Claude, Copilot, Cursor, Windsurf, GitHub Actions |
| **Secret scanning** | Catches hardcoded secrets, private keys, and credentials |
| **Rate limiting** | Per-key and IP-based with sliding windows |
| **SSO** | Azure AD, Okta, Auth0, Google, Keycloak |
| **GDPR** | Data export (Art. 15) and right to erasure (Art. 17) |
| **SIEM export** | CEF, LEEF, Syslog, ECS JSON |
| **SBOM** | CycloneDX generated in CI |
| **Signed releases** | Sigstore signing of distributions |

---

## Distribution

| Channel | Install |
|---------|---------|
| **PyPI** | `pip install codetrust` |
| **VS Code Marketplace** | `code --install-extension SaidBorna.codetrust` |
| **GitHub Action** | `uses: S-Borna/codetrust@v2` |
| **Cloud API** | Available at `codetrust-api.saidborna.com` |
| **MCP Server** | Included in the package |
| **Website** | [codetrust.saidborna.com](https://codetrust.saidborna.com) |

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v           # 1314 tests
ruff check src/ tests/     # zero warnings
```

All counts in this README are generated from source and validated in CI.

---

## License

Proprietary — Copyright (c) 2026 Said Borna. All rights reserved. See [LICENSE](LICENSE).
