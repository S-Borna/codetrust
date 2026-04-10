<p align="center">
  <img src="https://codetrust.ai/logo.png" alt="CodeTrust — AI Governance Enforcement Platform" width="420">
</p>

<p align="center">
  <strong>Your AI agent just wrote 40% of your codebase. Do you know which 40%?</strong>
</p>

<p align="center">
  <code>v4.1.0</code> &middot; <code>2,928 scan rules</code> &middot; <code>9 enforcement layers</code> &middot; <code>3,087 tests</code>
</p>

<p align="center">
  <a href="https://pypi.org/project/codetrust/"><img src="https://img.shields.io/pypi/v/codetrust?style=flat-square&color=38d8fd" alt="PyPI"></a>
  <a href="https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust"><img src="https://img.shields.io/visual-studio-marketplace/v/SaidBorna.codetrust?style=flat-square&color=5bca78" alt="VS Code Marketplace"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Proprietary-333?style=flat-square" alt="License"></a>
  <a href="https://globaldex.ai/domain/codetrust.ai"><img src="https://globaldex.ai/api/v1/badge?domain=codetrust.ai" alt="GlobalDex Score" height="20"></a>
</p>

<p align="center">
  <a href="https://codetrust.ai">Website</a> &middot;
  <a href="https://codetrust.ai/demo">Live Demo</a> &middot;
  <a href="https://api.codetrust.ai/docs">API Docs</a> &middot;
  <a href="https://pypi.org/project/codetrust/">PyPI</a> &middot;
  <a href="https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust">VS Code</a> &middot;
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## AI Agents Run Your Codebase. Nobody Governs Them. Until Now.

GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3 — these models write code, run terminal commands, install packages, modify configs, and push to production. They hallucinate packages that don't exist. They run destructive commands without asking. They produce code that drifts in quality silently. And nobody tracks which model wrote which line.

**CodeTrust is the governance layer that controls what AI agents can do — before they do it.**

```bash
pip install codetrust && codetrust init && codetrust doctor
# 9/9 layers active — governance enforced. 30 seconds.
```

---

## Without CodeTrust

| What happens today | The cost |
|---|---|
| AI agent runs `git push --force` and overwrites your colleague's branch | Lost work. Broken trust. Manual recovery. |
| AI hallucinates `from utils.helpers import validate` — module doesn't exist | Import fails in production. 3AM incident. |
| 40% of your codebase was written by GPT-5.3. Senior dev quits. Nobody knows which 40%. | Unmaintainable code. No accountability. No audit trail. |
| AI agent modifies its own CLAUDE.md to remove restrictions | Self-modifying agent. Zero oversight. Governance bypassed. |
| Junior dev uses an unregistered AI model with training data from a competitor's leaked repo | Legal liability. IP contamination. Compliance violation. |
| AI-generated code quality degrades over time. Nobody measures it. | Technical debt compounds silently until production breaks. |

**Every one of these scenarios is happening right now, at companies using AI coding assistants without governance.**

---

## With CodeTrust

| Scenario | What CodeTrust does |
|---|---|
| Agent tries `git push --force` | **BLOCKED.** BASH_ENV guard intercepts at bash level. Exit code 2. Agent cannot proceed. |
| Agent imports hallucinated package | **BLOCKED.** Live verification against 8 registries. Package doesn't exist = commit rejected. |
| CTO asks "which AI wrote this code?" | **AI Attribution.** Per-line model tracking. GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3 — 26 models detected. Shadow AI flagged. Full audit trail. |
| Agent tries to edit its own governance rules | **BLOCKED.** File-write guard protects 13 governance paths. Agent cannot modify its own restrictions. |
| Unauthorized AI model used in commit | **AI Policy Engine.** Model allowlist/blocklist enforced. Max AI ratio per commit. Violation = commit blocked. |
| Code quality drifting | **Trust Score.** 0-100 per commit. Baseline comparison. CI fails below threshold. |

---

## What No Other Tool Does

SonarQube has 5,000+ rules. Snyk tracks CVEs. Semgrep does dataflow analysis. Ruff formats code. **None of them do this:**

| Capability | CodeTrust | SonarQube | Snyk | Semgrep | Ruff |
|---|:---:|:---:|:---:|:---:|:---:|
| Block AI agent commands before execution | **Yes** | No | No | No | No |
| Detect hallucinated packages via live registry | **Yes** | No | No | No | No |
| Per-line AI model attribution | **Yes** | No | No | No | No |
| AI model allowlist/blocklist policy | **Yes** | No | No | No | No |
| Prevent agent from editing its own rules | **Yes** | No | No | No | No |
| Track AI code drift with Trust Score | **Yes** | Quality Gate | No | No | No |
| Works as MCP server for AI agents | **Yes** | New in 2025 | No | No | No |

**Keep your existing stack. Add CodeTrust as the AI governance control plane.**

Learn more at [codetrust.ai](https://codetrust.ai).

---

## Enforcement Matrix — Honest Capabilities

| IDE / Environment | Enforcement Level | Mechanism | Bypass Possible? |
|---|---|---|---|
| **Claude Code CLI** | **Hard block** | PreToolUse hook + BASH_ENV guard | No |
| **Claude Code VS Code ext.** | **Hard block** | BASH_ENV guard (PreToolUse hooks inactive in extension) | No |
| **VS Code (other agents)** | Advisory + scan | Extension on-save scanning, MCP tools | Yes |
| **Cursor** | Advisory | `.cursorrules` + MCP tools | Yes |
| **Windsurf** | Advisory | `.windsurfrules` + MCP tools | Yes |
| **GitHub Copilot** | Scan only | MCP tools, no interception hook | Yes |
| **CI/CD** | Blocking | Pre-commit hook + GitHub Action | No |
| **REST API** | Blocking | Server-side enforcement | No |

The BASH_ENV guard intercepts every `/bin/bash -c` command on the machine — it works for any AI agent that spawns bash locally, regardless of IDE.

---

## The Six Features That Define CodeTrust

### 1. Real-Time Agent Interception

`codetrust init` auto-installs two enforcement layers:

- **BASH_ENV guard** — intercepts every bash command before execution. Works in all IDEs, all agents, cannot be bypassed by the agent. Pure bash, 26ms overhead, zero dependencies.
- **PreToolUse hooks** — Claude Code CLI-specific interception. 44 blocked patterns, 14 protected paths, 6 secret detection rules.

`git push` → BLOCKED. `rm -rf /` → BLOCKED. Heredoc → BLOCKED. `curl | sh` → BLOCKED.

### 2. AI Attribution — Know Who Wrote What

Every line of code attributed to its source: human developer, GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3, or any of 26 detected models. Per-commit AI ratio tracking. Shadow AI detection flags unregistered models.

This is the difference between "we use AI" and "we govern AI."

### 3. AI Policy Engine — The CTO Decides, CodeTrust Enforces

- **Model allowlist/blocklist** — only approved AI models can contribute code
- **Max AI ratio per commit** — no commit exceeds your threshold
- **Attribution requirements** — every AI-generated line must be traceable
- **Editor restrictions** — control which IDEs and extensions are approved

No other tool gives engineering leadership this level of control over AI usage.

### 4. Repo Guard — Agents Cannot Change Their Own Rules

AI agents are instructed by governance files (CLAUDE.md, .cursorrules, .codetrust.toml). Without protection, the agent can modify these files to remove its own restrictions.

CodeTrust's file-write guard protects 14 governance file paths. Any attempt to modify governance files → **BLOCKED**. The agent cannot weaken its own oversight.

### 5. Commit Guards — Nothing Unsafe Reaches Main

Every commit passes through CodeTrust's pre-commit hook. 2,928 rules scanned against staged files. BLOCK findings reject the commit. Every event logged to an append-only audit trail.

The pre-commit hook runs at OS level — it works regardless of which IDE, agent, or terminal triggered the commit. The GitHub Action provides a second gate at PR time.

### 6. Hallucination Detection — Catch What Doesn't Exist

Live import verification against 8 registries (PyPI, npm, crates.io, Go proxy, Maven, NuGet, RubyGems, Packagist). Signature validation: 50 modules, 405 functions. Static rules catch fabricated methods, phantom configs, fake API keys.

AI agents hallucinate packages and functions that don't exist. CodeTrust catches them before they reach production.

---

## 8 More Capabilities

### 7. PII Detection — 16 Categories
Emails, phone numbers, credit cards (Luhn-validated), Swedish personnummer, API keys, passwords, JWTs, IBANs, IP addresses, private keys, URLs with credentials, SSNs, names, addresses, dates of birth, passport numbers. Auto-redaction. Policy enforcement (block/warn/redact per category).

### 8. Data Classification + Model Routing
Automatic sensitivity assessment: PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED. Per-sensitivity model routing — restrict which LLMs can access which data. Auto-redact restricted content before sending to any model.

### 9. LLM Cost Tracking
20 models with current pricing (Claude 4.x, GPT-4.1/o3/o4, Gemini 2.x, Llama 4). Per-developer, per-team, per-model aggregation. Budget enforcement (warn/alert/block). Anomaly detection (3x daily average, 50%+ team concentration).

### 10. Compliance Frameworks — 21/21 Full
OWASP Agentic Security Initiative 2026 (10/10), EU AI Act (7/7), NIST AI Risk Management Framework (4/4). All verified via `codetrust compliance --framework <id> --strict`. Definition of Done enforcement gate.

### 11. Agent Integrity Verification
4 behavioral patterns: sycophantic retraction, unsubstantiated claims, unverified references, contradictory positions. Calibrated against 20 real session incidents. 100% detection rate. CLI: `codetrust integrity`.

### 12. Framework Integrations
LangChain (`CodeTrustGovernance` callback handler), CrewAI (`CodeTrustCrew` governed crew), OpenAI Agents SDK (`governed_agent` tool wrapper). 3 lines of code to add governance. `pip install codetrust[langchain]`.

### 13. Real-time Governance Dashboard
6-section overview (enforcement, compliance, PII, classification, cost, integrity). Live polling every 30s. Timeline, alerts, per-framework detail pages. `app.codetrust.ai`.

### 14. Guided Remediation — 2,928 Individual Suggestions
Every BLOCK finding includes root cause, exact fix, CVE references. 17 special handlers. The agent reads the suggestion and self-corrects. Zero templates.

---

## Scan Coverage

Static analysis (2,928 rules, 89 extensions), AST structural analysis (10 tree-sitter checks), cross-language taint (7 languages), container/IaC hardening, live import verification (8 registries), and real-time AI governance gateway (44 BLOCK patterns).

---

## Quick Start

```bash
pip install codetrust
cd your-project
codetrust init          # Installs 9 enforcement layers
codetrust scan .        # First scan: establishes baseline (existing code accepted)
codetrust scan .        # Second scan: shows only NEW issues from now on
codetrust status        # One-line health check
```

**Why two scans?** CodeTrust accepts your existing codebase as "baseline" on
the first scan and then only flags NEW issues introduced after that. You don't
get judged for legacy code — you get protected going forward. Run
`codetrust baseline status` to inspect, `baseline reset` to start over,
or `baseline share` to commit it for team workflow.

---

## By the Numbers

| Metric | Value |
|--------|-------|
| Scan rules | 2,928 (89 file extensions) |
| Gateway interceptor | 62 rules (44 BLOCK) |
| Enforcement layers | 9 (verified by `codetrust doctor`) |
| Guided remediation | 2,928 individual suggestions |
| PII detection | 16 categories with validators |
| Compliance frameworks | 3 (OWASP 10/10, EU 7/7, NIST 4/4) |
| Cost tracking models | 20 across 4 providers |
| Framework integrations | 3 (LangChain, CrewAI, OpenAI) |
| API endpoints | 72 |
| CLI commands | 52 |
| Tests | 3,033 |

---

## Six Ways In

| Surface | Install | What You Get |
|---------|---------|--------------|
| **CLI** | `pip install codetrust` | Full scan + enforcement |
| **VS Code** | [Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust) | Scan on save, diagnostics, governance |
| **Chrome** | Chrome Web Store | Browser-side scans on GitHub |
| **GitHub Action** | `pip install codetrust` in CI | PR gate with SARIF upload |
| **MCP Server** | 2 servers | Governance for Claude Code / Cursor / Windsurf |
| **REST API** | [api.codetrust.ai](https://api.codetrust.ai/docs) | 72 endpoints |

---

## What's New in 4.1.0

- **Hallucination detection at 95%** — verified against a ground-truth dataset with 0% false positives. Covers fake packages, misspelled imports, invented APIs, fake sanitizers, and hallucinated configuration options.
- **Scan baseline** — first scan accepts existing code as legacy. Subsequent scans show only new issues. Share baselines across teams with `codetrust baseline share`.
- **Reduced mode** — when the free daily scan quota is exhausted, scans continue with critical safety rules instead of stopping. Gateway protection stays active at all times.
- **Language-aware remediation** — scan findings recommend fixes in the language you're writing (Python, JavaScript, TypeScript, Ruby, PHP).
- **`codetrust today`** — daily summary of governance activity, scan quota, and top rules triggered.
- **PII Detection** — 16 categories with Luhn, IBAN checksum, and format validation. Auto-redaction and per-category policy controls.
- **Compliance** — OWASP ASI 2026 (10/10), EU AI Act (7/7), NIST AI RMF 1.0 (4/4) with evidence-linked mappings.
- **Agent Integrity** — detects sycophantic retractions, unsubstantiated claims, and contradictory positions in AI agent sessions.
- **Governance Dashboard** — scan quota widget, enforcement overview, compliance status, and PII metrics at `app.codetrust.ai`.
- **VS Code extension parity** — offline scans now use the full rule set when the CLI is installed locally.
- **Definition of Done** — configurable acceptance gates in TOML, enforced at pre-commit and in CI.

---

## CLI

```bash
codetrust init                     # Install governance
codetrust scan .                   # Scan your project
codetrust today                    # Daily governance summary
codetrust doctor                   # Verify 9 enforcement layers
codetrust status                   # Quick protection check
codetrust baseline status          # View scan baseline
codetrust fix --apply              # Auto-fix detected issues
codetrust audit --since today      # Governance audit trail
codetrust pii scan src/            # PII detection
codetrust compliance --framework owasp-asi-2026  # Compliance report
codetrust integrity                # Agent integrity analysis
codetrust dod                      # Definition of Done gate
codetrust --help-all               # All 40+ commands
```

---

## MCP Servers

| Server | Command | Tools |
|--------|---------|-------|
| **Guardian** | `codetrust-mcp` | Scan, compliance, audit, attribution |
| **Gateway** | `codetrust-gateway-mcp` | Real-time interception, PII, classification, cost |

```json
{
  "mcpServers": {
    "codetrust": { "command": "codetrust-mcp" },
    "codetrust-gateway": { "command": "codetrust-gateway-mcp" }
  }
}
```

Works with Claude Code, Claude Desktop, Cursor, Windsurf. Requires `pip install codetrust`.

---

## Configuration

`.codetrust.toml` in project root. `codetrust init` generates it.

<details>
<summary><strong>Full reference</strong></summary>

```toml
[codetrust]
exclude_paths = ["migrations/", "vendor/"]

[codetrust.governance]
enabled = true
mode    = "enforce"

[codetrust.governance.terminal]
block_heredoc      = true
block_git_push     = true
block_rm_rf        = true
block_curl_pipe_sh = true

[codetrust.governance.files]
protected_paths   = ["LICENSE", ".env"]
scan_before_write = true

[codetrust.governance.packages]
verify_before_install     = true
block_suspicious_packages = true

[codetrust.governance.audit]
enabled        = true
path           = ".codetrust/audit.jsonl"
retention_days = 90
```

</details>

---

## Supported Languages

Python, JavaScript, TypeScript, Go, Rust, Java, C#, C/C++, Ruby, PHP, Shell, PowerShell, Terraform, HCL, Dockerfile, SQL, YAML, HTML, Kotlin, Swift, Dart, Elixir, Clojure, and 70+ more.

---

## Security & Compliance

Append-only audit trail. 3 compliance frameworks (OWASP ASI 10/10, EU AI Act 7/7, NIST RMF 4/4). PII detection with auto-redaction. Agent auto-detection (26 models). Secret scanning. Rate limiting. SSO (Azure AD, Okta, Auth0, Google). GDPR export and erasure. Definition of Done enforcement gate.

---

## Enterprise

PII detection (16 categories, GDPR compliance). Data classification with model routing. LLM cost tracking per developer/team. Compliance dashboards (OWASP, EU AI Act, NIST). Agent integrity verification. Framework integrations (LangChain, CrewAI, OpenAI). SSO (Azure AD, Okta, Auth0). Team RBAC. Org-wide policy enforcement.

---

| Channel | Install |
|---------|---------|
| **PyPI** | `pip install codetrust` |
| **VS Code** | `code --install-extension SaidBorna.codetrust` |
| **Chrome** | Chrome Web Store |
| **GitHub Action** | `pip install codetrust` in CI |
| **API** | [api.codetrust.ai](https://api.codetrust.ai/docs) |
| **Website** | [codetrust.ai](https://codetrust.ai) |

---

**Support:** [codetrust.ai/report.html](https://codetrust.ai/report.html) · **Security:** [SECURITY.md](SECURITY.md)

**License** — Proprietary. Copyright (c) 2026 Said Borna. All rights reserved.
