<p align="center">
  <img src="https://codetrust.ai/logo.png" alt="CodeTrust — AI Governance Enforcement Platform" width="420">
</p>

<p align="center">
  <strong>AI Governance Enforcement Platform — Prevent unsafe AI-generated code from reaching production.</strong>
</p>

<p align="center">
  <code>Current: v2.4.0</code> &middot; <code>1672 tests</code> &middot; <code>275 rules</code> &middot; <code>10 layers</code>
</p>

<p align="center">
  <a href="https://pypi.org/project/codetrust/"><img src="https://img.shields.io/pypi/v/codetrust?style=flat-square&color=38d8fd" alt="PyPI"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust"><img src="https://img.shields.io/visual-studio-marketplace/v/SaidBorna.codetrust?style=flat-square&color=5bca78" alt="VS Code Marketplace"></a>
  <a href="https://github.com/marketplace/actions/codetrust-scan"><img src="https://img.shields.io/badge/GitHub_Action-available-333?style=flat-square" alt="GitHub Action"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Proprietary-333?style=flat-square" alt="License"></a>
</p>

<p align="center">
  <a href="https://codetrust.ai">Website</a> &middot;
  <a href="https://api.codetrust.ai/docs">API Docs</a> &middot;
  <a href="https://pypi.org/project/codetrust/">PyPI</a> &middot;
  <a href="https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust">VS Code</a> &middot;
  <a href="https://github.com/marketplace/actions/codetrust-scan">GitHub Action</a> &middot;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## What CodeTrust Is

**AI Governance Enforcement Platform** — 275 rules across 10 enforcement layers, 17 MCP tools, 42 API endpoints. 5 enterprise services: CVE/vulnerability scanning, license compliance, cross-file analysis, auto-fix PRs, and team management with RBAC. 1,665 tests.

CodeTrust prevents unsafe, hallucinated, and destructive AI-generated code from reaching production. It enforces safety across the entire development lifecycle — before execution, during development, before commit, during CI/CD, and before deployment.

CodeTrust is not a linter. It is not a formatter. It is a **governance enforcement platform** purpose-built for the era of AI-generated code, with three capabilities no existing tool provides.

---

## The Three Moats

### Moat 1: AI Governance Gateway

The Gateway intercepts AI agent actions **before execution** — not scanning files after the fact. Terminal commands, file writes, and package installs are validated against configurable policies in real-time.

76 interception rules across 11 categories: file destruction, code execution, privilege escalation, git operations, container escape, network exfiltration, secrets exposure, supply chain attacks, AI agent enforcement, resource abuse, and root-cause enforcement — plus content rules for file writes.

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
| **Destructive agent commands** | `rm -rf /`, dynamic code execution, `curl\|sh` — data loss, RCE, supply chain compromise | CodeTrust Gateway intercepts before execution |
| **Ghost Docker images** | AI references images that don't exist — build breaks at 2AM | CodeTrust validates images against Docker Hub |
| **Invisible code drift** | AI code quality degrades gradually — no one measures it | CodeTrust tracks trust score over time |

### What existing tools miss

| Tool | What it does | What it doesn't do |
|---|---|---|
| **SonarQube** | 5,000+ quality rules | Does not intercept AI agents, verify imports, or track trust scores |
| **Snyk** | CVEs in known packages | Does not intercept AI agents, detect hallucinated packages, or track trust scores |
| **Semgrep** | Cross-file dataflow analysis | Does not intercept AI agents, verify imports against registries, or track trust scores |
| **FOSSA / WhiteSource** | License compliance scanning | Does not intercept AI agents, detect hallucinated packages, or scan code quality |
| **Ruff / ESLint** | Code style, formatting | Does not intercept AI agents, verify imports, or track trust scores |

CodeTrust combines pre-execution interception, live registry verification, quantified safety tracking, CVE scanning, license compliance, cross-file analysis, auto-fix PRs, and team management — all in one platform, all free.

---

## 10 Enforcement Layers

CodeTrust scans code across 10 layers covering static analysis, root cause analysis, SQL safety, AST structural analysis, container hardening, infrastructure-as-code, framework-specific rules (React, Kubernetes, CI/CD), live import verification, Docker image verification, and the real-time AI governance gateway.

**199 scan rules + 76 gateway rules = 275 total.** Every rule produces a BLOCK, WARN, or INFO verdict.

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
| **GitHub Action** | `uses: S-Borna/codetrust@v2.4.0` | PR checks with SARIF upload to Security tab |
| **MCP Server** | 17 tools for AI agents | Claude Code / Cursor get real-time safety feedback |
| **REST API** | 42 endpoints with rate limiting | Integrate into any pipeline or platform |

---

## CLI Usage

```bash
codetrust scan app.py              # Scan a file
codetrust scan src/                # Scan a directory
codetrust scan . --sarif           # SARIF output for CI
codetrust scan . --json            # JSON output
codetrust scan . --no-verify-imports  # Skip registry checks (offline)
codetrust scan . --changed-only --dedupe  # Reduce noise in large repos
codetrust scan . --suppress-lint-noise    # Optional suppression for lint-heavy output

codetrust status                   # Check enforcement status
codetrust doctor                   # Diagnose installation

codetrust pr-risk                  # Repo-aware PR risk summary (git diff aware)
codetrust trust-diff               # Compare trust score: HEAD vs working tree
codetrust trend record             # Record a local snapshot
codetrust trend show               # Show recorded snapshots

codetrust policy wizard            # Generate governance policy presets + TOML autocomplete

codetrust vuln                     # Scan dependencies for known CVEs (OSV database)
codetrust license                  # Check dependency license compliance
codetrust fix                      # Apply auto-fix recipes
codetrust fix --pr                 # Apply fixes and open a GitHub PR

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
- Scan on type (opt-in, debounced) using the embedded offline scanner
- Inline diagnostics with severity levels
- Works fully offline — all scan rules embedded
- "Scan Workspace" — up to 500 files with progress UI
- Profile create/apply commands for quick setup
- Quick Fixes for common findings
- Health Check command for connectivity and config sanity
- AI governance controls built in
- Deep scan mode for full analysis

| Setting | Default | Description |
|---------|---------|-------------|
| `codetrust.apiUrl` | `https://api.codetrust.ai` | API server URL |
| `codetrust.apiKey` | `""` | Deprecated: stored in VS Code Secret Storage. Use Guided Onboarding to set it |
| `codetrust.scanOnSave` | `true` | Auto-scan on save |
| `codetrust.scanOnType` | `false` | Scan while typing (embedded offline scanner) |
| `codetrust.scanOnTypeDebounceMs` | `600` | Debounce delay for scan while typing |
| `codetrust.severityThreshold` | `INFO` | Minimum severity to show |
| `codetrust.enabledLanguages` | `[...]` | Languages to scan |
| `codetrust.scanType` | `static` | `static` or `deep` |
| `codetrust.verifyImportsOnSave` | `false` | Verify imports on save (network) |
| `codetrust.timeout` | `15000` | Request timeout in milliseconds |
| `codetrust.governance.enabled` | `true` | Enable AI governance |
| `codetrust.governance.mode` | `enforce` | `enforce` / `audit` / `off` |

Self-hosting: set `codetrust.apiUrl` to your own API base URL.

---

## GitHub Action

Add CodeTrust to any GitHub Actions workflow. BLOCK findings fail the status check. Hallucinated packages appear as inline PR annotations via SARIF.

<details>
<summary><strong>Complete workflow file</strong> — copy to <code>.github/workflows/codetrust.yml</code></summary>

```yaml
name: CodeTrust Scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  actions: read
  contents: read
  pull-requests: write
  security-events: write

jobs:
  codetrust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: S-Borna/codetrust@v2.4.0
        with:
          fail-on: block          # block | warn | info
          scan-type: static       # static | deep
          sarif: true             # upload to GitHub Security tab
          # api-key: ${{ secrets.CODETRUST_API_KEY }}  # optional

      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: codetrust-results.sarif
```

</details>

**Inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `fail-on` | `block` | Minimum severity to fail the check |
| `scan-type` | `static` | `static` or `deep` |
| `sarif` | `true` | Generate SARIF for GitHub Security tab |
| `api-key` | — | Optional API key (from `secrets.CODETRUST_API_KEY`) |
| `telemetry` | `true` | Anonymous usage telemetry |

---

## MCP Servers

CodeTrust ships two MCP servers for different purposes:

| Server | Command | Purpose | Tools |
|--------|---------|---------|-------|
| **Scan Server** | `codetrust-mcp` | Code scanning, import verification, SARIF export | 10 tools |
| **Gateway Server** | `codetrust-gateway-mcp` | Real-time AI action interception — blocks destructive commands before execution | 7 tools |

**Use both for full coverage.** The Scan Server gives AI agents code analysis capabilities. The Gateway Server intercepts and validates every command, file write, and package install the agent attempts.

### Scan Server tools

`codetrust_static_scan` · `codetrust_ast_scan` · `codetrust_deep_scan` · `codetrust_verify_imports` · `codetrust_verify_dockerfile` · `codetrust_sandbox_run` · `codetrust_sarif_export` · `codetrust_pre_action` · `codetrust_post_action` · `codetrust_list_rules`

### Gateway Server tools

`codetrust_validate_command` · `codetrust_validate_file_write` · `codetrust_validate_file_delete` · `codetrust_validate_package` · `codetrust_governance_status` · `codetrust_audit_history` · `codetrust_list_gateway_rules`

### Setup: Claude Desktop / Claude Code

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "codetrust": {
      "command": "codetrust-mcp"
    },
    "codetrust-gateway": {
      "command": "codetrust-gateway-mcp"
    }
  }
}
```

### Setup: Cursor

Add to `.cursor/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "codetrust": {
      "command": "codetrust-mcp"
    },
    "codetrust-gateway": {
      "command": "codetrust-gateway-mcp"
    }
  }
}
```

### Setup: Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "codetrust": {
      "command": "codetrust-mcp"
    },
    "codetrust-gateway": {
      "command": "codetrust-gateway-mcp"
    }
  }
}
```

Requires `pip install codetrust` so that `codetrust-mcp` and `codetrust-gateway-mcp` are on your PATH.

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

## Configuration

CodeTrust is configured via `.codetrust.toml` in your project root, or `[tool.codetrust]` in `pyproject.toml`. Run `codetrust init` to generate a starter config.

<details>
<summary><strong>Full configuration reference</strong></summary>

```toml
# .codetrust.toml

[codetrust]
exclude_paths = ["migrations/", "vendor/", "node_modules/"]
ignore_rules  = []                    # e.g. ["eval_exec", "hardcoded_secret"]

[codetrust.governance]
enabled = true
mode    = "enforce"                   # enforce | audit | off

[codetrust.governance.terminal]
block_heredoc     = true              # Block heredoc (<<EOF) patterns
block_eval        = true              # Block eval/exec calls
block_sudo        = false             # Block sudo commands
block_rm_rf       = true              # Block rm -rf /
block_curl_pipe_sh = true             # Block curl|sh piping
block_git_push    = true              # Block git push from AI agents
block_chmod_777   = true              # Block chmod 777

[codetrust.governance.files]
protected_paths    = ["LICENSE", ".env", ".env.production"]
scan_before_write  = true             # Scan file content before allowing write

[codetrust.governance.packages]
verify_before_install    = true       # Registry lookup before pip/npm install
block_suspicious_packages = true      # Block known typosquat patterns

[codetrust.governance.audit]
enabled        = true
path           = ".codetrust/audit.jsonl"   # Append-only audit log
retention_days = 90

[codetrust.governance.webhooks]
# url       = "https://hooks.slack.com/services/T.../B.../xxx"
# provider  = "slack"                 # slack | teams | generic
# on_block  = true
# on_warn   = false
```

</details>

**Override any setting via environment variable:** `CODETRUST_GOVERNANCE_MODE=audit`

### Custom Rules

Add your own governance rules without modifying CodeTrust source. Define them in `.codetrust/custom_rules.yaml` or under `[codetrust.governance.custom_rules]` in `.codetrust.toml`.

<details>
<summary><strong>YAML example — <code>.codetrust/custom_rules.yaml</code></strong></summary>

```yaml
terminal_rules:
  - id: no_docker_privileged
    pattern: "docker\\s+run\\s+--privileged"
    message: "Privileged Docker containers are not allowed"
    suggestion: "Remove --privileged flag"
    severity: BLOCK

  - id: no_force_push
    pattern: "git\\s+push\\s+--force"
    message: "Force push is blocked by policy"
    suggestion: "Use --force-with-lease instead"
    severity: BLOCK

content_rules:
  - id: no_console_log
    pattern: "console\\.log\\("
    message: "console.log found in production code"
    suggestion: "Use a structured logger"
    severity: WARN
```

</details>

**Rules:**

- `id` — unique identifier (auto-prefixed with `custom_` at runtime)
- `pattern` — Python regex matched against terminal commands or file content
- `message` — shown when the rule triggers
- `suggestion` — recommended fix (optional)
- `severity` — `BLOCK` (hard stop) or `WARN` (flag only)

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

## Enterprise Services

Five capabilities that match or exceed paid features from Snyk, SonarQube, Semgrep, FOSSA, and WhiteSource — included free.

### CVE / Vulnerability Scanning

Checks dependencies against the [OSV](https://osv.dev) vulnerability database (Google). Supports PyPI, npm, crates.io, Go, Maven, NuGet, RubyGems, Packagist.

```bash
codetrust vuln                     # Scan from requirements.txt / package.json
codetrust vuln --language python   # Explicit language
codetrust vuln --json              # Machine-readable output
```

**API:** `POST /v1/vuln/scan` — batch check up to 200 packages in a single request.

### License Compliance

Extracts licenses from package registries (PyPI, npm, RubyGems, Packagist, Maven, NuGet). Classifies as permissive, weak copyleft, strong copyleft, or network copyleft (AGPL). Flags compliance risks.

```bash
codetrust license                  # Check from dependency files
codetrust license --json           # Machine-readable output
```

**API:** `POST /v1/license/scan`

### Cross-File Import Analysis

Builds the import dependency graph for a project. Detects circular dependencies, orphan files, hub files, and propagates findings across import chains.

**API:** `POST /v1/scan/cross-file`

### Auto-Fix PRs

Applies safe, deterministic fix recipes (print→logging, bare except, hardcoded secrets→env vars) and optionally opens a GitHub PR with the fixes.

```bash
codetrust fix                      # Apply fixes locally
codetrust fix --pr                 # Create a GitHub PR with fixes
```

**API:** `POST /v1/fix/apply` — supports optional PR creation via GitHub API.

### Team Management & RBAC

Organizations, team memberships, and role-based access control. Enforce org-wide policies: maximum severity gates, vulnerability thresholds, blocked licenses.

| Role | Permissions |
|------|------------|
| **Owner** | Full control, billing, transfer ownership, delete org |
| **Admin** | Manage members, edit policies, view billing |
| **Member** | Run scans, create API keys |
| **Viewer** | View scans and policies |

**API:** 10 endpoints under `/v1/orgs/*` — create/list/delete orgs, manage members, enforce policies.

---

## Distribution

| Channel | Install |
|---------|---------|
| **PyPI** | `pip install codetrust` |
| **VS Code Marketplace** | `code --install-extension SaidBorna.codetrust` |
| **GitHub Action** | `uses: S-Borna/codetrust@v2.4.0` |
| **Cloud API** | Available at `api.codetrust.ai` |
| **MCP Server** | Included in the package |
| **Website** | [codetrust.ai](https://codetrust.ai) |

---

## Development

```bash
pip install -e ".[dev]"
pytest                     # 1672 tests
ruff check .               # zero warnings
```

All counts in this README are generated from source and validated in CI.

---

## License

Proprietary — Copyright (c) 2026 Said Borna. All rights reserved. See [LICENSE](LICENSE).
