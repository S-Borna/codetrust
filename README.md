<p align="center">
  <img src="https://codetrust.ai/logo.png" alt="CodeTrust — AI Governance Enforcement Platform" width="420">
</p>

<p align="center">
  <strong>Your AI agent just wrote 40% of your codebase. Do you know which 40%?</strong>
</p>

<p align="center">
  <code>v4.0.5</code> &middot; <code>3,006 rules</code> &middot; <code>8 enforcement layers</code> &middot; <code>2,509 tests</code>
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
# 8/8 layers active — governance enforced. 30 seconds.
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
- **PreToolUse hooks** — Claude Code CLI-specific interception. 44 blocked patterns, 13 protected paths, 6 secret detection rules.

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

CodeTrust's file-write guard protects 13 governance file paths. Any attempt to modify governance files → **BLOCKED**. The agent cannot weaken its own oversight.

### 5. Commit Guards — Nothing Unsafe Reaches Main

Every commit passes through CodeTrust's pre-commit hook. 2,924 rules scanned against staged files. BLOCK findings reject the commit. Every event logged to an append-only audit trail.

The pre-commit hook runs at OS level — it works regardless of which IDE, agent, or terminal triggered the commit. The GitHub Action provides a second gate at PR time.

### 6. Hallucination Detection — Catch What Doesn't Exist

Live import verification against 8 registries (PyPI, npm, crates.io, Go proxy, Maven, NuGet, RubyGems, Packagist). Signature validation: 50 modules, 405 functions. Static rules catch fabricated methods, phantom configs, fake API keys.

AI agents hallucinate packages and functions that don't exist. CodeTrust catches them before they reach production.

---

## 8 More Capabilities

### 7. AI Governance Gateway
82 interception rules. 4 validators (command, file write, file delete, package). 4 proxy tools. Interpreter -c/-e bypass detection. Governance weakening detection.

### 8. Guided Remediation — 2,924 Individual Suggestions
Every BLOCK finding includes root cause, exact fix, CVE references. 17 special handlers. The agent reads the suggestion and self-corrects. Zero templates.

### 9. Cross-Language Taint Analysis
323 definitions across 7 languages (Python, JS/TS, Go, Java, C#, Kotlin, Rust). Cross-file + cross-language (HTTP/gRPC boundary) tracking. SQL injection, XSS, SSRF, path traversal, deserialization.

### 10. Static Analysis — 2,924 Rules
92 file extensions. 23+ languages. Pre-indexed by extension, pre-compiled regex. 2ms worst case.

### 11. AST Deep Analysis
10 tree-sitter structural checks. 9 languages. Missing timeout, resource limits, broad exception, silent swallow, unbounded loops, mutable state.

### 12. Trust Score & Drift Tracking
0-100 safety score. Baseline comparison. Grade curve A+ through F. CI fail threshold. `codetrust trust-diff`, `codetrust trend`.

### 13. Vulnerability & License Scanning
CVE scanning via OSV + NVD CVSS enrichment. License compliance. SBOM generation (CycloneDX, SPDX).

### 14. Docker & Infrastructure Verification
Ghost image detection. Root user, missing WORKDIR/healthcheck. Kubernetes resource limits. Terraform/HCL rules.

---

## Scan Coverage — 10 Analysis Categories

Static analysis, root cause analysis, SQL safety, AST structural analysis, container hardening, infrastructure-as-code, framework rules (React, Kubernetes, CI/CD), live import verification, Docker image verification, and real-time AI governance gateway.

**2,924 scan rules + 82 gateway rules = 3,006 total.**

---

## Quick Start

```bash
pip install codetrust
cd your-project
codetrust init          # Installs 8 enforcement layers
codetrust doctor        # Verifies all layers active
codetrust scan .        # Scan your code
```

---

## By the Numbers

| Metric | Value |
|--------|-------|
| Scan rules | 2,924 |
| Gateway rules | 82 |
| Total rules | 3,006 |
| Enforcement layers | 8 |
| Guided remediation suggestions | 2,924 |
| Taint definitions | 323 across 7 languages |
| AST checks | 10 |
| Signature database | 50 modules, 405 functions |
| Import registries | 8 |
| File extensions | 92 |
| MCP tools | 39 (21 scan + 18 gateway) |
| API endpoints | 65 |
| CLI commands | 22 |
| Tests | 2,509 |

---

## Six Ways In

| Surface | Install | What You Get |
|---------|---------|--------------|
| **CLI** | `pip install codetrust` | Full scan + enforcement |
| **VS Code** | [Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust) | Scan on save, diagnostics, governance |
| **Chrome** | Chrome Web Store | Browser-side scans on GitHub |
| **GitHub Action** | `pip install codetrust` in CI | PR gate with SARIF upload |
| **MCP Server** | 39 tools | Governance for Claude Code / Cursor / Windsurf |
| **REST API** | [api.codetrust.ai](https://api.codetrust.ai/docs) | 65 endpoints |

---

## What's New in v4.0.5

- **BASH_ENV guard** — universal real-time enforcement across all IDEs and agents
- **8 enforcement layers** — all verified by `codetrust doctor`
- **Pre-commit audit trail** — every commit logged
- **Quote-aware heredoc detection** — zero false positives
- **Scanner quality** — FP 80% → 0%, performance 27s → 2ms
- **Cross-language taint** — 7 languages, 323 definitions
- **AI Observability** — model enumeration, attribution, shadow AI detection

---

## CLI

```bash
codetrust scan app.py              # Scan a file
codetrust scan . --sarif           # SARIF for CI
codetrust scan . --json            # JSON output
codetrust doctor                   # Verify 8 layers
codetrust pr-risk                  # PR risk summary
codetrust trust-diff               # Trust score diff
codetrust vuln                     # CVE scan
codetrust license                  # License compliance
codetrust fix --pr                 # Auto-fix PR
codetrust governance --status      # Governance overview
codetrust audit --hours 24         # Audit trail
```

---

## MCP Servers

| Server | Command | Tools |
|--------|---------|-------|
| **Scan** | `codetrust-mcp` | 21 — analysis, verification, SARIF |
| **Gateway** | `codetrust-gateway-mcp` | 18 — real-time interception |

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

Append-only audit trail. Agent auto-detection (Claude Opus 4.6, GPT-5.3, Codex 5.3, Gemini 3, Copilot, Cursor, Windsurf). Secret scanning. Rate limiting. SSO (Azure AD, Okta, Auth0, Google). GDPR export and erasure.

---

## Enterprise

CVE scanning (OSV + NVD). License compliance. Cross-file import analysis. Auto-fix PRs. Team RBAC. Org-wide policy enforcement.

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
