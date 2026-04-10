# CodeTrust — AI Governance Enforcement Platform

**Your AI agent just ran `git push --force`. CodeTrust stopped it before it executed.**

AI models write code, run commands, and modify your codebase. CodeTrust is the governance layer that controls what they can do — before they do it.

2,928 rules. 9 enforcement layers. 95% hallucination detection. One command: `pip install codetrust && codetrust init`

Works with **Claude Code**, **Cursor**, **Windsurf**, **GitHub Copilot**, and any AI coding assistant.

Learn more at [codetrust.ai](https://codetrust.ai)

---

## What CodeTrust Does

| Without CodeTrust | With CodeTrust |
|---|---|
| Agent runs `git push --force` | **BLOCKED.** Real-time interception before execution. |
| Agent imports hallucinated package | **BLOCKED.** Verified against 8 live registries. |
| Agent writes secrets to files | **BLOCKED.** API keys, private keys, passwords detected. |
| Agent edits its own governance rules | **BLOCKED.** 13 protected paths enforced. |
| Code quality drifts silently | **Trust Score.** Tracked per scan with guided remediation. |
| Nobody knows which AI wrote what | **AI Attribution.** Per-line model tracking. |

---

## Key Capabilities

### Real-Time Agent Interception
9 enforcement layers auto-installed by `codetrust init`. Gateway hooks block destructive commands, heredoc, and shell tricks before they reach the terminal.

### Hallucination Detection
95% detection rate against a ground-truth dataset. Combines regex patterns, live registry verification (PyPI, npm, Go, crates.io, RubyGems, Packagist, Maven, NuGet), signature validation, and taint analysis.

### Guided Remediation
2,928 individually crafted suggestions with language-aware fix guidance. Python scans get Python alternatives; JavaScript scans get JavaScript alternatives.

### Scan Baseline
First scan accepts existing code as legacy. Subsequent scans show only new issues — no grading on code you didn't write.

### PII Detection
16 categories including email, phone, credit card (Luhn-validated), IBAN, API keys, JWT, private keys, and Swedish personnummer. Auto-redaction and per-category policy controls.

### Compliance
OWASP Agentic Security Initiative 2026 (10/10), EU AI Act (7/7), NIST AI RMF 1.0 (4/4). Evidence-linked mappings.

### Agent Integrity
Detects sycophantic retractions, unsubstantiated claims, unverified references, and contradictory positions in AI agent sessions.

---

## By the Numbers

| Metric | Value |
|--------|-------|
| Scan rules | 2,928 |
| Enforcement layers | 9 |
| Hallucination detection | 95% |
| PII categories | 16 |
| Import registries | 8 |
| File extensions | 89 |
| MCP tools | 39 |
| Tests | 3,087 |

---

## Getting Started

1. Install from VS Code Marketplace
2. Run `pip install codetrust && codetrust init`
3. Run `codetrust doctor` — verify 9/9 layers active
4. Open any file — diagnostics appear on save
5. Run `codetrust today` — see what your agents did

---

## Offline Support

When the API is unavailable, the extension automatically delegates to your locally installed `codetrust` CLI for full rule coverage. If the CLI is not installed, it falls back to a built-in scanner with the most critical safety rules.

---

## Supported Languages

Python, JavaScript, TypeScript, Go, Rust, Java, C#, C/C++, Ruby, PHP, Shell, PowerShell, Terraform, HCL, Dockerfile, SQL, YAML, HTML, Kotlin, Swift, Dart, and 65+ more.

---

**License** — Proprietary. Copyright (c) 2026 Said Borna. All rights reserved.
