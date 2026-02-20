# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.1] - 2026-02-20

### Added — Agent Optimizer, Integrity Verification, Version Enforcement

#### Agent Optimizer (`codetrust setup`)

- **New CLI command: `codetrust setup`** — configures AI agent optimization for
  any project. Installs CLAUDE.md (Agent Operating System), SESSION_LOG.md
  (session tracking), VS Code settings (instruction files), and .cursorrules.
- **Templates:** `agent-claude.md`, `SESSION_LOG.md`, `vscode-settings.json`
  added to template library.
- **Differentiator:** No other product optimizes how AI coding agents work.

#### IP Protection — Integrity Verification

- **Integrity verification markers** embedded in the rule catalog for
  distribution authenticity validation and IP protection.
- Used by the post-publish verification pipeline to confirm wheel integrity.

#### Client Version Enforcement

- **`VersionEnforcementMiddleware`** — API middleware that rejects requests from
  clients below `MIN_CLIENT_VERSION` with HTTP 426 Upgrade Required.
- **`X-Client-Version` header** — sent by CLI telemetry client on all API calls.
- **`CODETRUST_MIN_CLIENT_VERSION`** — configurable via environment variable.
- **Exempt paths:** `/health`, `/v1/stats/public`, `/v1/license/validate`, etc.

#### Post-Publish Verification

- **`scripts/verify_publish.py`** — automated verification of published wheels.
  Downloads from PyPI and validates: file count (≥50 .py), size (≥500 KB),
  required entry points, integrity markers, size parity with local build.
- Prevents the v2.6.0 empty wheel incident from recurring.

### Fixed

- **Empty wheel on PyPI (v2.6.0)** — v2.6.0 was published with 0 Python files
  (11 KB). Root cause: build artifact issue. v2.6.1 verified locally with 55+
  Python files (977+ KB).

---

## [2.6.0] - 2026-02-20

### Added — IP Protection & Security Hardening

This release introduces comprehensive intellectual property protection and runtime
license validation across the entire CodeTrust platform.

#### Runtime License Validation

- **License validation module** — validates installations against the cloud API at
  startup with configurable intervals.
- **Offline grace period** — configurable offline window before license lockout,
  with local cached status.
- **Machine fingerprinting** — hashed installation ID (not hardware) for license
  binding. No personally identifiable hardware data is transmitted.
- **Degraded mode** — unlicensed installations limited to a subset of rules
  across scan and gateway layers. CLI warns but does not block.
- **`POST /v1/license/validate`** — new endpoint for license key validation with
  feature entitlements and plan details.
- **Integration** — license check runs at API startup, MCP tool invocation, and
  CLI main entry.
- **Configuration** — `CODETRUST_LICENSE_KEY`, `CODETRUST_LICENSE_CHECK_INTERVAL`,
  `CODETRUST_LICENSE_OFFLINE_GRACE_DAYS` env vars.

#### IP Protection Infrastructure

- **Copyright headers** — all Python and TypeScript files carry
  `Copyright (c) 2026 Said Borna. All rights reserved. Proprietary — see LICENSE`.
- **sdist blocked** — `pyproject.toml` excludes all files from source distribution.
  Only wheel (`.whl`) is published.
- **Source maps disabled** — no `.map` files ship in any published package.
- **Extension bundling** — esbuild bundles and minifies the extension into a single
  file. `vscode:prepublish` runs the bundler instead of plain `tsc` compilation.
- **Contributor License Agreement** — `CLA.md` requires all contributors to grant
  perpetual IP rights. `CONTRIBUTING.md` references CLA before merge.

#### Release Security Gates

- **Automated gate script** — multi-check verification runs before every release
  covering distribution format, copyright, source protection, license validation,
  CLA, secrets audit, and runtime integrity.
- **Updated release checklist** — mandatory security gates section. Release is
  blocked if any gate fails.
- **Post-release verification** — checklist requires distribution audit after
  every publish.

#### Security Hardening

- Additional runtime license enforcement for production deployments.
- Rule delivery architecture hardened for cloud-first distribution.
- Build pipeline improvements for compiled and obfuscated output.
- Source protection expanded across Python and TypeScript targets.

#### Legal & Compliance

- **Terms of Service** — `docs/tos.html` published at codetrust.ai/tos covering
  license grant, restrictions, IP ownership, data collection, GDPR compliance,
  and governing law (Sweden).
- **Website footer** — Terms of Service and <www.saidborna.com> links added.
- **Contact updated** — contact email changed to <said@saidborna.com> on website.

---

## [2.5.2] - 2026-02-19

### Fixed

- Removed all stale version references visible to AI agents fetching platform docs
- Consolidated duplicate "What's New" sections in Marketplace README into single current entry
- Trimmed CHANGELOG from 780 lines of historical entries to current release only
- Removed specific old version numbers (`v2.1.0`, `v2.4.0`) from README and website copy

---

## [2.5.1] - 2026-02-19

### Fixed

- Extension Marketplace README corrected: now accurately describes all four moats, 21 MCP tools, and v2.5.0 features (Universal IDE Injection, Governance Disruption Monitoring)
- Stale `v2.4.0` GitHub Action references in root README updated to `v2.5.1`
- Stale `17 tools` MCP count in root README updated to `21`
- `softwareVersion` in website JSON-LD schema corrected from `2.4.0` to `2.5.1`
- Extension `package.json` description updated from "3 capabilities" to "4 capabilities"

---

## [2.5.0] - 2026-02-19

### Added — Fourth Moat: Session-Level Universal Enforcement

This release introduces the fourth and final competitive moat: **enforcement that is active from
session one, across every AI model, every workspace, automatically — with zero configuration.**

Previously, CodeTrust required an AI agent to voluntarily call governance tools. Starting with v2.5.0,
governance is active before the AI writes a single line of code, and every tool call is validated
and logged regardless of the agent's cooperation.

#### MCP Proxy Enforcement Layer (`src/gateway/server.py`)

Four new proxy tools that AI agents MUST call instead of the native VS Code tools.
The gateway returns `APPROVED` or `BLOCKED` before the native tool is invoked:

- **`codetrust_run_in_terminal`** — proxy gate for `run_in_terminal`. BLOCKED verdict
  halts execution; action and verdict logged to audit trail.
- **`codetrust_create_file`** — proxy gate for `create_file`. Validates content for
  hardcoded secrets and protected path violations before the file is written.
- **`codetrust_replace_string_in_file`** — proxy gate for `replace_string_in_file`.
  Validates the replacement content before applying edits.
- **`codetrust_edit_notebook`** — proxy gate for `edit_notebook_file`. Validates
  notebook cell content before execution.

All four proxy tools use the existing `CommandInterceptor` and `AuditLogger`, producing
ALLOW / WARN / BLOCK verdicts consistent with gateway policy. Mode `enforce` = full block.
Mode `audit` = log and warn without blocking.

#### Global Copilot Instruction Injection (`extension/src/extension.ts`)

The VS Code extension now automatically injects CodeTrust governance rules into VS Code's
global `github.copilot.chat.codeGeneration.instructions` setting on every activation:

- **Zero configuration** — no workspace setup, no `CLAUDE.md`, no `.codetrust.toml` required.
- **Global scope** — `ConfigurationTarget.Global` ensures rules apply across every workspace.
- **Every AI model, every session** — rules are injected before the AI writes a single character.
- **Idempotent** — duplicate injection is detected and skipped via a unique marker.
- **Clean uninstall** — `deactivate()` removes injected rules automatically.

#### Universal IDE Injection (`extension/src/universal-instructions.ts`)

A new module that extends governance injection beyond VS Code to every major AI coding IDE.
On activation the extension writes the proxy model rules to the global configuration file of
each installed IDE — skipping any that are not installed:

| IDE | Global Config File |
|---|---|
| Claude Code | `~/.claude/CLAUDE.md` |
| Cursor | `~/.cursor/rules/codetrust.mdc` |
| Windsurf | `~/.codeium/windsurf/memories/global_rules.md` |
| GitHub Copilot | VS Code global settings (`codeGeneration.instructions`) |

Rules are injected once, idempotently, at global scope. Every subsequent session in every
workspace in every supported IDE enforces the proxy model without any user configuration.
On deactivation all injected content is removed cleanly, leaving the user's configs intact.

#### Governance Disruption Monitoring (`watchForGovernanceDisruption`)

CodeTrust now actively monitors injected governance files for disruptions after installation:

- **File watchers** — if an IDE update overwrites a watched config file and removes the
  CodeTrust marker, a VS Code warning notification appears immediately with a
  "Re-inject Now" action that restores enforcement in one click.
- **Window-focus check** — each time VS Code regains focus, CodeTrust scans for IDE
  config directories that now exist but whose rules are absent or corrupted (e.g. an IDE
  installed after CodeTrust). A "Inject Now" notification offers immediate recovery.
- **Zero user effort** — watchers are registered in `context.subscriptions` and cleaned up
  automatically on extension deactivation.

#### New Commands

- **`codetrust.injectCopilotInstructions`** (`CodeTrust: Inject Copilot Instructions`) —
  force re-inject governance rules into global Copilot instructions.
- **`codetrust.governanceStatus`** (`CodeTrust: Governance Status`) — show the current
  governance mode, injection status, and mandatory validation sequence in the output channel.

#### Documentation

- `extension/resources/copilot-instructions.md` — canonical reference for the proxy model,
  describing the two-step validation workflow and absolute prohibitions.

---

## Older Releases

For release notes prior to v2.5.0, see the [full git history](https://github.com/S-Borna/codetrust/commits/main) or run `git log --oneline` locally.

**Current version: 2.6.1** — install via `pip install codetrust` or the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust).
