# CodeTrust — AI Governance Enforcement Platform

**Your AI agent just wrote 40% of your codebase. Do you know which 40%?**

GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3 — these models write code, run commands, and push to production. Nobody tracks which model wrote which line. Nobody blocks destructive commands before they execute. Nobody catches hallucinated packages before they ship.

**CodeTrust is the governance layer that controls what AI agents can do — before they do it.**

2,928 rules. 9 enforcement layers. Real-time interception. One command: `pip install codetrust && codetrust init`

Works with **Claude Code**, **Cursor**, **Windsurf**, **GitHub Copilot**, and any AI coding assistant.

Learn more at [codetrust.ai](https://codetrust.ai)

---

## Why CodeTrust

| Without CodeTrust | With CodeTrust |
|---|---|
| Agent runs `git push --force` | **BLOCKED.** BASH_ENV guard intercepts. Exit code 2. |
| Agent imports hallucinated package | **BLOCKED.** Live verification against 8 registries. |
| Nobody knows which AI wrote what | **AI Attribution.** Per-line model tracking. 26 models detected. |
| Agent edits its own governance rules | **BLOCKED.** File-write guard protects 13 paths. |
| Unauthorized AI model used | **AI Policy.** Model allowlist enforced. Commit blocked. |
| Code quality drifts silently | **Trust Score.** 0-100 tracked per commit. CI gate. |

---

## What's New in 4.0.6

- **BASH_ENV guard** — OS-level enforcement for VS Code extension. Blocks dangerous commands at bash level regardless of IDE hook support. 26ms overhead. Zero dependencies. Cannot be bypassed by the agent.
- **9 enforcement layers** — BASH_ENV guard, PreToolUse hooks, MCP Gateway, pre-commit hook, GitHub Action, advisory files, governance config, allow-list audit. All verified by `codetrust doctor`.
- **AI Attribution** — per-line model tracking. GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3. Shadow AI detection flags unregistered models.
- **AI Policy Engine** — model allowlist/blocklist. Max AI ratio per commit. The CTO decides, CodeTrust enforces.
- **Repo Guard** — agent cannot modify CLAUDE.md, .cursorrules, .codetrust.toml or 10 other governance paths.
- **Commit Guards** — pre-commit hook scans 2,924 rules. BLOCK = commit rejected. Audit trail logged.
- **Quote-aware heredoc detection** — zero false positives on `echo '<<'` and `grep '<<'`.
- **Guided remediation** — 2,924 individually crafted suggestions. Root cause + exact fix + CVE refs.
- **Scanner quality** — FP rate 0% on own code, Flask 0%, Django 8.6%. Performance: 27s → 2ms.
- **Cross-language taint** — 323 definitions across 7 languages. Cross-file + cross-language tracking.

---

## The Six Features That Define CodeTrust

### 1. Real-Time Agent Interception

BASH_ENV guard + PreToolUse hooks auto-installed by `codetrust init`. 44 blocked patterns. `git push` → BLOCKED. `rm -rf /` → BLOCKED. Heredoc → BLOCKED. Works in Claude Code CLI and VS Code extension.

### 2. AI Attribution — Know Who Wrote What

Every line attributed to its source: GPT-5.3, Claude Opus 4.6, Gemini 3, Codex 5.3, or human. Per-commit AI ratio. Shadow AI flagged.

### 3. AI Policy Engine

Model allowlist/blocklist. Max AI ratio per commit. Attribution requirements. Editor restrictions.

### 4. Repo Guard

13 governance file paths protected. Agent cannot modify its own rules.

### 5. Commit Guards

2,924 rules scanned at commit time. BLOCK = rejected. GitHub Action as second gate.

### 6. Hallucination Detection

Live import verification against 8 registries. Signature validation: 50 modules, 405 functions.

---

## 8 More Capabilities

| # | Capability | Detail |
|---|---|---|
| 7 | AI Governance Gateway | 82 interception rules, 4 validators, 4 proxy tools |
| 8 | Guided Remediation | 2,924 individual suggestions with root cause and fix |
| 9 | Cross-Language Taint | 323 definitions, 7 languages, cross-file tracking |
| 10 | Static Analysis | 2,924 rules, 92 file extensions, 2ms worst case |
| 11 | AST Deep Analysis | 10 tree-sitter checks, 9 languages |
| 12 | Trust Score | 0-100 safety score per commit, CI threshold |
| 13 | Vuln & License | CVE scanning (OSV + NVD), license compliance, SBOM |
| 14 | Docker & Infra | Ghost image detection, K8s resource limits, Terraform |

---

## Enforcement Matrix

| Environment | Level | Mechanism |
|---|---|---|
| **Claude Code CLI** | Hard block | PreToolUse hook + BASH_ENV |
| **Claude Code VS Code** | Hard block | BASH_ENV guard |
| **Other VS Code agents** | Advisory + scan | Extension scan + MCP |
| **Cursor** | Advisory | .cursorrules + MCP |
| **CI/CD** | Blocking | Pre-commit + GitHub Action |

---

## By the Numbers

| Metric | Value |
|--------|-------|
| Scan rules | 2,924 |
| Gateway rules | 82 |
| Total rules | 2,928 |
| Enforcement layers | 8 |
| Guided remediation | 2,924 |
| Taint definitions | 323 across 7 languages |
| AST checks | 10 |
| Signature database | 50 modules, 405 functions |
| Import registries | 8 |
| File extensions | 92 |
| MCP tools | 39 (21 scan + 18 gateway) |
| API endpoints | 65 |
| Tests | 2,509 |

---

## Also Available As

| Surface | Install |
|---------|---------|
| **CLI** | `pip install codetrust` |
| **GitHub Action** | `pip install codetrust` in CI workflow |
| **MCP Server** | 39 tools for Claude Code / Cursor / Windsurf |
| **REST API** | [api.codetrust.ai](https://api.codetrust.ai/docs) — 65 endpoints |
| **Chrome Extension** | Chrome Web Store |
| **Website** | [codetrust.ai](https://codetrust.ai) |

---

## Getting Started

1. Install from VS Code Marketplace or Open VSX
2. Run `pip install codetrust && codetrust init`
3. Run `codetrust doctor` — verify 8/8 layers active
4. Open any file — diagnostics appear on save

For full governance: `pip install codetrust && codetrust init && codetrust doctor`

---

## Supported Languages

Python, JavaScript, TypeScript, Go, Rust, Java, C#, C/C++, Ruby, PHP, Shell, PowerShell, Terraform, HCL, Dockerfile, SQL, YAML, HTML, Kotlin, Swift, Dart, Elixir, Clojure, and 70+ more.

---

**License** — Proprietary. Copyright (c) 2026 Said Borna. All rights reserved.
