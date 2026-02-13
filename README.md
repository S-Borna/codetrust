<p align="center">
  <img src="docs/logo.png" alt="CodeTrust" width="420">
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

## Table of Contents

**Intro**

- [What CodeTrust Is](#what-codetrust-is)
- [Why CodeTrust Exists](#why-codetrust-exists)
- [How CodeTrust Works](#how-codetrust-works)

**The Three Moats**

- [Moat 1: AI Governance Gateway](#moat-1-ai-governance-gateway)
- [Moat 2: Hallucination Detection Engine](#moat-2-hallucination-detection-engine)
- [Moat 3: Trust Score & Drift Tracking](#moat-3-trust-score--drift-tracking)

**Enforcement**

- [Enforcement Model: What CodeTrust Can and Cannot Enforce](#enforcement-model-what-codetrust-can-and-cannot-enforce)
- [Enforcement Guarantees vs Advisory Layers](#enforcement-guarantees-vs-advisory-layers)

**Usage**

- [Quick Start (2 minutes)](#quick-start-2-minutes)
- [CLI Usage](#cli-usage)
- [VS Code Extension](#vs-code-extension)
- [GitHub Action](#github-action)
- [MCP Gateway](#mcp-gateway)
- [HTTP API](#http-api)

**Reference**

- [Supported Languages](#supported-languages)
- [Configuration](#configuration)
- [Architecture Details](#architecture-details)
- [Security Model](#security-model)
- [Distribution](#distribution)
- [Development](#development)

---

## What CodeTrust Is

**AI Governance Enforcement Platform** — 132 rules across 10 enforcement layers, 17 MCP tools, 26 API endpoints.

CodeTrust is an AI governance and enforcement platform that prevents unsafe, hallucinated, and destructive code from reaching production.

Unlike traditional static analysis tools that detect issues after code is written, CodeTrust enforces safety across the entire development lifecycle:

- **Before execution** — Gateway intercepts destructive commands in real-time
- **During development** — VS Code Extension shows inline diagnostics on save
- **Before commit** — Pre-commit hook rejects unsafe code
- **During CI/CD** — GitHub Action fails the PR status check
- **Before deployment** — CLI and API scan with exit code enforcement

This creates an enforcement layer between AI-generated code and production systems.

CodeTrust is not a linter. It is not a formatter. It is a **governance enforcement platform** purpose-built for the era of AI-generated code. It has three capabilities no existing tool provides:

1. **AI Governance Gateway** — 57 real-time interception rules that block destructive AI agent actions *before execution*
2. **Hallucination Detection Engine** — extracts imports from source files and verifies every package against live PyPI/npm registries. Catches hallucinated packages with exact file + line number
3. **Trust Score & Drift Tracking** — measures how safe your AI-generated code is over time, with baseline trending, delta tracking, and grade curves

One command to install. Works offline. Works in CI. Works across CLI, GitHub Action, MCP server, and VS Code extension.

---

## Why CodeTrust Exists

AI writes code fast. But fast doesn't mean safe.

**78% of developers** use AI coding assistants daily (2025). These tools produce new failure modes that no existing tool detects:

| Failure Mode | What Happens | Who Catches It |
|---|---|---|
| **Hallucinated packages** — AI suggests `import fast-utils` that doesn't exist | `pip install` fails, or worse: typosquatted malware installs | **CodeTrust** (nobody else) |
| **Destructive agent commands** — AI runs `rm -rf /`, `eval()`, `curl\|sh` | Data loss, remote code execution, supply chain compromise | **CodeTrust** (nobody else) |
| **Ghost Docker images** — AI references `python:3.12-alpine-slim` that doesn't exist | Build fails at 2AM on deploy night | **CodeTrust** (nobody else) |
| **Embedded secrets** — AI pastes `api_key = "sk-live-abc..."` | Pushed to GitHub, scraped by bots within seconds | Many tools |
| **Invisible code drift** — AI code quality degrades gradually, no one measures it | Technical debt accumulates without signal | **CodeTrust** (nobody else) |

### What existing tools miss

| Tool | What it does | What it does NOT do |
|---|---|---|
| **SonarQube** | 5,000+ code quality rules | No AI agent blocking. No import verification. No trust score |
| **Snyk** | CVEs in known packages | No AI agent blocking. No hallucination detection. No trust score |
| **Semgrep** | Cross-file dataflow analysis | No AI agent blocking. No registry verification. No trust score |
| **Ruff / ESLint** | Code style, formatting | No AI agent blocking. No import verification. No trust score |

**None of them have any of our three moats.**

---

## How CodeTrust Works

```mermaid
flowchart TB
    subgraph Clients
        CLI["CLI<br/>codetrust scan"]
        EXT["VS Code Extension<br/>75 embedded rules"]
        GHA["GitHub Action<br/>CI/CD pipeline"]
        DASH["Dashboard<br/>Next.js"]
    end

    subgraph Gateway["AI Governance Gateway — 57 rules"]
        MCP_GW["MCP Server<br/>7 gateway tools"]
        INT["CommandInterceptor<br/>46 terminal + 11 content rules"]
        POL["PolicyEngine<br/>.codetrust.toml"]
        AUD["AuditLogger<br/>JSONL append-only"]
    end

    subgraph API["FastAPI Backend"]
        REST["REST API<br/>26 endpoints"]
        SCAN["StaticAnalyzer<br/>75 scan rules"]
        IMPORT["ImportVerifier<br/>live PyPI/npm check"]
        AST["AstAnalyzer<br/>tree-sitter"]
        REG["RegistryService<br/>PyPI · npm · crates · Go"]
        DOCK["DockerVerify<br/>Docker Hub · GHCR"]
        SAND["Sandbox<br/>Python · Node · Go · Rust"]
        AUTH["Auth + Billing<br/>JWT · Stripe"]
    end

    subgraph Storage
        PG[(PostgreSQL)]
        REDIS[(Redis)]
        JSONL[("audit.jsonl")]
    end

    CLI --> SCAN
    CLI --> IMPORT
    EXT -->|offline| SCAN
    EXT -->|online| REST
    GHA --> SCAN
    GHA --> IMPORT
    DASH --> REST

    MCP_GW --> INT
    INT --> POL
    INT --> AUD
    AUD --> JSONL

    IMPORT --> REG
    REST --> SCAN
    REST --> AST
    REST --> REG
    REST --> DOCK
    REST --> SAND
    REST --> AUTH
    AUTH --> PG
    REST --> REDIS
```

**Five entry points** (CLI, Extension, Action, MCP, Dashboard) feed into a shared services layer. The Gateway sits between AI agents and tools, intercepting commands before execution. The ImportVerifier bridges static analysis with live registry checks. Everything logs to an append-only audit trail.

---

## Moat 1: AI Governance Gateway

The Gateway intercepts AI agent actions **before execution** — not scanning files after the fact. It sits between the AI model and the tools, validating every terminal command, file write, and package install against configurable policies.

```
AI Agent → Gateway (validate) → Allow / BLOCK → Execute
                 ↓
            Audit Log (.codetrust/audit.jsonl)
```

### 57 rules across 9 categories

| Category | Rules | Examples |
|----------|:-----:|---------|
| File Destruction | 5 | `rm -rf /`, `shred`, `dd of=/dev/` |
| Code Execution | 7 | `eval`, `curl\|sh`, heredoc, `python -c` |
| Privilege Escalation | 5 | `chmod 777`, `sudo su`, `chown root` |
| Git Operations | 3 | `git push`, `git push --force`, `git reset --hard` |
| Container Escape | 4 | `--privileged`, `--pid=host`, `--net=host` |
| Network Exfiltration | 5 | `curl POST`, `nc`, `scp`, DNS tunneling |
| Secrets Exposure | 6 | `export API_KEY`, `.env` cat, AWS credentials |
| Supply Chain | 6 | `pip install --index-url`, `npm set registry` |
| Resource Abuse | 5 | Fork bomb, `stress`, `crypto-miner` |

Plus **11 content rules** applied on file writes: hardcoded secrets, private keys, AWS keys, SSL bypass, CORS wildcards, obfuscated exec, pickle deserialization, subprocess shell, debug mode, webhook exfiltration, eval/exec.

All rules are **configurable** — disable any rule via `.codetrust.toml`.

### Real proof

During the development of v2.1.0, our own AI agent attempted to create a file using a heredoc (`<< 'PYEOF'`). The CodeTrust gateway **blocked it in real-time** — the product protected itself from its own builder.

---

## Moat 2: Hallucination Detection Engine

Every `codetrust scan` extracts imports from Python and JavaScript files, then verifies them against **live PyPI/npm registries**. Hallucinated packages produce BLOCK findings with exact file and line number.

### How it works

1. `extract_python_imports()` / `extract_js_imports()` parse source files
2. `RegistryService.verify_packages()` checks each package against live APIs
3. Results mapped back to exact line numbers via `_find_import_line()`
4. Hallucinated packages → BLOCK finding in the scan report

### Real proof

```
$ codetrust scan app.py

🔍 Verifying imports against registries... (1 file(s))
   Found 1 unverified import(s)

🛡️  CodeTrust Scan
   Files: 1 | Findings: 2
   AI Drift Score: 87/100 (B)

  🚫 BLOCK — must fix:
     app.py:4 [import_not_found] Package 'flask_magic_utils' not found
     on pypi — possible AI hallucination.
```

`flask_magic_utils` does not exist on PyPI. No other tool catches this.

### 13 AI-specific static rules

In addition to live registry checks, CodeTrust has 13 static hallucination rules:

`hallucinated_import_nonexistent`, `hallucinated_import_misspelled`, `hallucinated_method_chain`, `hallucinated_config_option`, `hallucinated_cli_flag`, `hallucinated_version`, `phantom_file_reference`, `hallucinated_http_status`, `hallucinated_localhost_port`, `hallucinated_api_endpoint`, `hallucinated_env_var`, `placeholder_url`, `fake_api_key_format`

---

## Moat 3: Trust Score & Drift Tracking

Not a snapshot — a real metric that tracks code safety over time.

| Feature | Description |
|---------|-------------|
| **AI Trust sub-score** | Hallucination findings penalized 15x in scoring |
| **Grade curve** | A+ / A / B+ / B / C+ / C / D / F |
| **Baseline storage** | `.codetrust/drift_baseline.json` persists between runs |
| **Delta tracking** | Shows improvement or regression from previous baseline |
| **Trend analysis** | `improving` / `degrading` / `stable` based on history |
| **History cap** | 100 data points retained |

```
🛡️  CodeTrust Scan
   Files: 47 | Findings: 3
   AI Drift Score: 94/100 (A)
   Trend: improving (+6 from baseline)
```

Run `codetrust scan .` repeatedly → delta appears. The score answers: **"Is our AI-generated code getting safer or more dangerous?"**

---

## Enforcement Model: What CodeTrust Can and Cannot Enforce

| # | Layer | Rules | What It Catches | Type |
|:-:|-------|:-----:|-----------------|:----:|
| 01 | **Static Analysis** | 15 | Secrets, `eval`/`exec`, bare `except`, mutable defaults, magic numbers | Blocking |
| 02 | **Root Cause Analysis** | 4 | Swallowed exceptions, lint suppression, sleep without context, debug mode | Blocking |
| 03 | **SQL Analysis** | 13 | `SELECT *`, `DELETE` without `WHERE`, `FLOAT` for money, `GRANT ALL` | Blocking |
| 04 | **AST Analysis** | — | Cyclomatic complexity, unused variables, unreachable code (tree-sitter) | Advisory |
| 05 | **Container Hardening** | 10 | Root user, `:latest` tags, missing `WORKDIR`, `ENV` secrets, no healthcheck | Blocking |
| 06 | **IaC & Config** | 7 | Hardcoded IPs, debug mode in config, API keys, unbounded retries | Blocking |
| 07 | **React & Kubernetes** | 13 | `dangerouslySetInnerHTML`, `privileged: true`, missing resource limits | Blocking |
| 08 | **Import Verification** | — | **Live PyPI/npm check** — catches hallucinated packages automatically | Blocking |
| 09 | **Docker Verification** | — | Verify base images and tags against Docker Hub / GHCR | Blocking |
| 10 | **AI Governance Gateway** | 57 | **Real-time interception** — blocks destructive AI actions before execution | Blocking |

**75 scan rules + 57 gateway rules = 132 total.**

---

## Enforcement Guarantees vs Advisory Layers

CodeTrust distinguishes between **enforcement** (will block your pipeline) and **advisory** (will inform, not block).

| Layer | Guarantee | Mechanism |
|-------|-----------|-----------|
| **Gateway (Layer 10)** | **Absolute** | Pre-execution interception. Command never runs. Cannot bypass |
| **Pre-commit hook** | **Hard block** | Commit rejected. Developer must fix before committing |
| **GitHub Action** | **Hard block** | PR fails required status check. Cannot merge |
| **CLI scan** | **Soft block** | Exit code 1 on BLOCK findings. Developer decides |
| **VS Code Extension** | **Advisory** | Inline diagnostics. No blocking |
| **CLAUDE.md / .cursorrules** | **Advisory** | AI reads and follows. No enforcement mechanism |
| **AST Analysis** | **Advisory** | Complexity warnings. No pipeline blocking |

The stack is designed so that:

- **Layers 1–3, 5–9** produce BLOCK/WARN/INFO findings
- **Layer 10 (Gateway)** prevents execution entirely — strongest guarantee
- **Pre-commit + GitHub Action** enforce at infrastructure level — cannot be skipped
- **Extension + CLAUDE.md** are advisory — useful but bypassable

---

## Quick Start (2 minutes)

```bash
# Install
pip install codetrust

# Initialize enforcement layers in your project
cd your-project
codetrust init

# Scan everything
codetrust scan .

# Verify installation
codetrust doctor
```

`codetrust init` installs: CLAUDE.md, .cursorrules, pre-commit hook, GitHub Action, `.codetrust.toml`, audit directory.

---

## CLI Usage

```bash
# Scan a single file
codetrust scan app.py

# Scan a directory
codetrust scan src/

# Scan with SARIF output for CI
codetrust scan src/ --sarif --sarif-file results.sarif

# Scan without live import verification (offline)
codetrust scan . --no-verify-imports

# JSON output
codetrust scan . --json

# Check enforcement status
codetrust status

# Diagnose installation
codetrust doctor

# Governance management
codetrust governance --status
codetrust governance --setup
codetrust governance --mode audit

# Audit log
codetrust audit --hours 24
codetrust audit --verdict BLOCK
codetrust audit --stats
```

---

## VS Code Extension

```bash
code --install-extension SaidBorna.codetrust
```

**Features:**

- Scans on save (configurable)
- Inline diagnostics with severity levels
- 75 embedded rules — works fully offline
- "Scan Workspace" command — up to 500 files with progress UI
- Governance settings — 7 configurable options
- Deep scan mode (requires API)

**Key settings:**

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
    fail-on: block           # block | warn | never
    scan-type: static        # static | deep
    sarif: true              # emit SARIF for Code Scanning
  env:
    CODETRUST_API_KEY: ${{ secrets.CODETRUST_API_KEY }}

# Upload SARIF results
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: codetrust-results.sarif
```

The Action runs static scan + import verification. BLOCK findings fail the status check. Hallucinated packages appear as inline PR annotations.

---

## MCP Gateway

Two MCP servers — one for scanning, one for governance.

Add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "codetrust": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/codetrust"
    },
    "codetrust-gateway": {
      "command": "python",
      "args": ["-m", "src.gateway.server"],
      "cwd": "/path/to/codetrust"
    }
  }
}
```

### 17 MCP Tools

| Tool | Server | Description |
|------|--------|-------------|
| `codetrust_static_scan` | Scanner | Scan code for anti-patterns and security issues |
| `codetrust_pre_action` | Scanner | Validate plan before writing code |
| `codetrust_post_action` | Scanner | Validate completed work against enterprise standards |
| `codetrust_list_rules` | Scanner | List all rules and their severities |
| `codetrust_verify_imports` | Scanner | Verify package imports exist in real registries |
| `codetrust_verify_dockerfile` | Scanner | Verify Docker base images and tags |
| `codetrust_ast_scan` | Scanner | AST structural analysis via tree-sitter |
| `codetrust_sandbox_run` | Scanner | Execute code in isolated sandbox |
| `codetrust_sarif_export` | Scanner | Export scan results as SARIF |
| `codetrust_deep_scan` | Scanner | Run all validation layers in a single pass |
| `codetrust_validate_command` | Gateway | Validate terminal command before execution |
| `codetrust_validate_file_write` | Gateway | Validate file content before writing |
| `codetrust_validate_file_delete` | Gateway | Validate file deletion |
| `codetrust_validate_package` | Gateway | Validate package name before install |
| `codetrust_governance_status` | Gateway | Show governance config and policy status |
| `codetrust_audit_history` | Gateway | Query governance audit log |
| `codetrust_list_gateway_rules` | Gateway | List all gateway interception rules |

---

## HTTP API

All endpoints require `X-API-Key` header when `CODETRUST_API_KEY` is set.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/status` | Health check — version, cache status |
| `POST` | `/v1/scan/static` | Static anti-pattern scan |
| `POST` | `/v1/scan/deep` | Full deep scan (all layers) |
| `POST` | `/v1/scan/static/sarif` | Static scan with SARIF output |
| `POST` | `/v1/scan/deep/sarif` | Deep scan with SARIF output |
| `POST` | `/v1/scan/ast` | AST structural analysis |
| `POST` | `/v1/verify/imports` | Verify package imports |
| `POST` | `/v1/verify/dockerfile` | Verify Docker images and tags |
| `POST` | `/v1/sandbox/run` | Execute code in isolated sandbox |
| `POST` | `/v1/api-keys` | Create API key |
| `GET` | `/v1/api-keys` | List API keys |
| `DELETE` | `/v1/api-keys/{key_id}` | Revoke API key |
| `GET` | `/v1/scans/history` | Scan history |
| `GET` | `/v1/usage` | Usage statistics |
| `POST` | `/v1/billing/checkout` | Create billing checkout session |
| `POST` | `/v1/billing/portal` | Billing portal redirect |
| `POST` | `/v1/webhooks/stripe` | Stripe webhook handler |
| `POST` | `/v1/auth/github` | GitHub OAuth authentication |
| `POST` | `/v1/auth/refresh` | Refresh JWT token |
| `GET` | `/v1/profile` | User profile |
| `GET` | `/v1/auth/oidc/login` | SSO/OIDC login redirect |
| `POST` | `/v1/auth/oidc/callback` | SSO/OIDC callback |
| `GET` | `/v1/user/export` | GDPR data export (Art. 15) |
| `DELETE` | `/v1/user/delete` | GDPR right to erasure (Art. 17) |
| `GET` | `/v1/governance/audit` | Governance audit log |
| `GET` | `/metrics` | Prometheus metrics |

```bash
curl https://codetrust-api-production.up.railway.app/v1/status
```

---

## Supported Languages

| Language | Static | AST | Registry | Extensions |
|----------|:------:|:---:|:--------:|------------|
| Python | Yes | Yes | PyPI | `.py` |
| JavaScript | Yes | Yes | npm | `.js`, `.jsx` |
| TypeScript | Yes | Yes | npm | `.ts`, `.tsx` |
| Go | Yes | Yes | Go proxy | `.go` |
| Rust | Yes | Yes | crates.io | `.rs` |
| SQL | Yes | — | — | `.sql` |
| Dockerfile | Yes | — | Docker Hub | `Dockerfile` |
| YAML / CI | Yes | — | — | `.yml`, `.yaml` |

---

## Configuration

### Project config (`.codetrust.toml`)

```toml
[codetrust]
exclude_paths = ["migrations/", "vendor/", "*.generated.py"]
ignore_rules = ["sql_todo_hack", "sql_no_index_hint"]

[codetrust.severity_overrides]
magic_number = "INFO"
hardcoded_ip = "BLOCK"

[codetrust.governance]
enabled = true
mode = "enforce"    # enforce | audit | off

[codetrust.governance.terminal]
block_heredoc = true
block_eval = true
block_git_push = true

[codetrust.governance.files]
protected_paths = ["LICENSE", ".env"]

[codetrust.governance.audit]
enabled = true
path = ".codetrust/audit.jsonl"
```

Or in `pyproject.toml`:

```toml
[tool.codetrust]
exclude_paths = ["migrations/"]
ignore_rules = ["sql_todo_hack"]
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CODETRUST_API_KEY` | — | API authentication key |
| `CODETRUST_HOST` | `0.0.0.0` | API bind host |
| `CODETRUST_PORT` | `8000` | API bind port |
| `CODETRUST_REDIS_URL` | `redis://localhost:6379` | Redis cache URL |
| `CODETRUST_HTTP_TIMEOUT` | `10.0` | HTTP client timeout (seconds) |
| `CODETRUST_DEBUG` | `false` | Debug mode |

---

## Architecture Details

```
+----------------------------------------------+
|      VS Code Extension  .  CLI  .  Action    |
|         (75 rules, offline-capable)           |
+-------------------+--------------------------+
                    |
+-------------------v--------------------------+
|        AI Governance Gateway (MCP)           |
|   57 rules . Intercept . Audit . Block       |
+-------------------+--------------------------+
                    |
+-------------------v--------------------------+
|           MCP Server  .  HTTP API            |
|     17 tools  .  26 endpoints  .  auth       |
+-------------------+--------------------------+
                    |
+-------------------v--------------------------+
|              Services Layer                  |
|  StaticAnalyzer . ImportVerifier . AST       |
|  Registry . Docker . Sandbox . Billing       |
+-------------------+--------------------------+
                    |
+-------------------v--------------------------+
|    PostgreSQL  .  Redis Cache  .  Stripe     |
+----------------------------------------------+
```

**Key components:**

| Component | Location | Responsibility |
|-----------|----------|---------------|
| StaticAnalyzer | `src/services/static_analyzer.py` | 75 regex + file-level rules |
| ImportVerifier | `src/services/import_verifier.py` | Bridge between parsers and live registries |
| AstAnalyzer | `src/services/ast_analyzer.py` | tree-sitter structural analysis |
| RegistryService | `src/services/registry.py` | PyPI, npm, crates.io, Go proxy verification |
| CommandInterceptor | `src/gateway/interceptor.py` | 46 terminal + 11 content interception rules |
| PolicyEngine | `src/gateway/policies.py` | Configurable governance modes |
| AuditLogger | `src/gateway/audit.py` | Append-only JSONL audit trail |
| CacheService | `src/services/cache.py` | Redis with graceful degradation |

---

## Security Model

| Property | Implementation |
|----------|----------------|
| **API authentication** | `X-API-Key` header, SHA-256 hashed storage |
| **Audit trail** | Append-only JSONL, immutable once written |
| **Agent identification** | Auto-detects Claude, Copilot, Cursor, Windsurf, GitHub Actions |
| **Secret scanning** | 6 gateway rules + static `hardcoded_secret` rule |
| **Protected paths** | Configurable list of files requiring confirmation before write/delete |
| **Rate limiting** | Per-key and IP-based rate limiting with sliding windows |
| **Governance modes** | `enforce` (block), `audit` (log only), `off` (disabled) |
| **SIEM export** | CEF, LEEF, Syslog RFC 5424, ECS JSON |
| **SSO/OIDC** | Azure AD, Okta, Auth0, Google, Keycloak |
| **GDPR** | Data export (Art. 15) + right to erasure (Art. 17) |
| **Signed releases** | Sigstore signing of PyPI distributions |
| **SBOM** | CycloneDX generated in CI, attached to releases |

---

## Distribution

| Channel | Install | Status |
|---------|---------|:------:|
| **PyPI** | `pip install codetrust` | Live |
| **VS Code Marketplace** | `code --install-extension SaidBorna.codetrust` | Live |
| **GitHub Action** | `uses: S-Borna/codetrust@v2` | Live |
| **Cloud API** | `https://codetrust-api-production.up.railway.app` | Live |
| **MCP Server** | `python -m src.server` | Live |
| **Website** | [codetrust.saidborna.com](https://codetrust.saidborna.com) | Live |

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v           # 1314 tests
ruff check src/ tests/     # zero warnings
cd extension && npx tsc --noEmit   # TypeScript
```

### Metrics

All counts in this README (rules, tools, endpoints, tests) are generated from source via:

```bash
python scripts/generate_metrics.py   # → metrics.json
```

Counts are generated from source and validated in CI. See [metrics.json](metrics.json) for current values.

---

## License

Proprietary — Copyright (c) 2026 Said Borna. All rights reserved. See [LICENSE](LICENSE).
