# CodeTrust — Backlog status (snapshot)

This document maps the proposed backlog to what already exists in this repository.

Legend:

- ✅ = already implemented (or effectively delivered)
- 🟡 = partially implemented / low effort to complete
- ❌ = not implemented yet

## A) Zero‑setup / Always‑on (global)

- ✅ Auto-detect first workspace open and ask once: “Enable Always‑On CodeTrust for all workspaces?” (persist globally)
- ✅ VS Code Profiles support: “Create/Apply CodeTrust Profile” (one click)
- ✅ Enable “scan active file” + “scan on save” by default (with a clear toggle)
- ✅ When “No active file to scan” → fallback to scanning the most recently changed git file or last saved file
- 🟡 Add a “Health Check” panel: active file, watchers, rulepack loaded, last scan time

## B) Workspace bootstrap (repo-level) — minimal manual

- ✅ Generator: “Add CodeTrust to repo” → writes `.vscode/extensions.json` + optional `.vscode/settings.json` (never overwrites existing without diff/confirm)
- ✅ Generator: “Add DevContainer auto-install” → creates `.devcontainer/devcontainer.json` with extension list
- ✅ Generator: “Add CONTRIBUTING snippet” → adds DoD + how CodeTrust complements `npm run verify`
- 🟡 Templates per stack (Next.js/TS, Python, Go) with sane defaults (partial: `codetrust add --settings --stack auto|…` presets)

## C) Enforce as hard gate (CI / pre-commit)

- ✅ Stable CLI scan surface exists (`codetrust scan …`) with structured outputs (JSON/SARIF) and enforcement integration
- ✅ GitHub Action surface exists (composite action + templates)
- ✅ Pre-commit mode exists (scans staged files; tries CLI first)
- ✅ Policy modes exist in multiple surfaces (warn/block behavior is configurable, but UX can be unified)
- ✅ Machine outputs: JSON + SARIF

## D) AI assist “per line” (practical IDE loop)

- ✅ Live feedback while typing (debounced): implemented (opt-in) via text-change listener using embedded offline scanner
- 🟡 Quick Fixes in Problems: Code actions exist; expanding safe autofix coverage is incremental
- ❌ Auto-refactor recipes (nested ternary → if/else, `any` → typed, `console.log` → logger)
- 🟡 One-line “why” + “safe fix plan”: findings already have messages; summarization can be improved

## E) Repo-aware intelligence (real build value)

- ✅ Detect `npm run verify` gates and pre-warn before running (CLI human-output hint)
- 🟡 Read ESLint/Prettier/TS configs and avoid duplicate noise (partial: CLI `--suppress-lint-noise`)
- 🟡 PR risk radar: `codetrust pr-risk` (changed files + diff stats + keyword signals + touched endpoints)

## F) Policy & config UX

- ✅ `.codetrust.toml` is supported; policy wizard + schema/autocomplete implemented
- ❌ `codetrust.json` schema + auto-complete
- ✅ “Policy Wizard”: Startup / Team / Enterprise → generates rulepack
- 🟡 Per-repo overrides with reason + audit trail: governance audit exists; UX for “reasoned overrides” can be formalized

## G) Drift / Trust score (more actionable)

- 🟡 Trust score concepts exist; actionable diffs/trends per commit/PR are not yet first-class
- 🟡 Trust diff (initial): `codetrust trust-diff` compares drift/findings vs HEAD for changed files
- 🟡 Trend view (initial): `codetrust trend record` + `codetrust trend show`
- 🟡 Noise control: dedupe findings and focus on changed lines (CLI flags: `--dedupe`, `--changed-only`)

## H) Security / Compliance (enterprise)

- ✅ Guard destructive agent actions (governance interceptor + policies)
- ✅ Secrets hygiene: detection exists across multiple layers
- 🟡 Tenant boundary checks: some rules exist; expanding to framework-specific tenancy patterns is incremental

---

## Notes

This is a product-facing view of status. Some 🟡 items are “almost there” because the repo already contains the primitives (API endpoints, policy engine, templates); what’s missing is UX glue and predictable defaults.
