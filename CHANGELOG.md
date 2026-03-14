# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### What's Coming

- Policy packs for SOC 2 / ISO 27001 / PCI-DSS presets.
- Org-level governance alerting for drift and repeat BLOCK events.
- Exception lifecycle tightening with owner assignment and escalation rules.

## [2.8.6] - 2026-03-14

### What's New (since 2.8.5)

### Added

- Formal issue intake via GitHub issue templates for bug reports and feature requests.
- Public report form route with direct API intake (`/v1/feedback/report`) so users can submit without repository access or local mail client dependency.

### Fixed

- Cross-platform CI stability hardening for Windows path/permission edge cases in telemetry and test cleanup paths.
- Trust DOD execution in release smoke now reuses already-passed test gates to avoid redundant flaky reruns.
- Claude Desktop MCP startup reliability hardened for existing users: gateway/scan startup no longer crashes on unreadable workspace policy/audit files.
- MCP stdio transport hardened: server logging is routed to stderr, preventing JSON-RPC corruption from stdout noise.
- MCP runtime auto-resolution for global targets now prefers portable commands and avoids workspace-bound `.venv` defaults.

### Changed

- Release metadata and public counters synchronized to current measured values (tests/endpoints).
- Website and release sign-off documentation aligned with 2.8.6 publication and verification evidence.
- Chrome extension release surfaces synchronized to 2.8.6 for store and runtime consistency.
- Documentation now recommends non-TCC workspace paths (for example `~/Projects` or `~/codetrust-workspace`) for Claude Desktop MCP runtime stability.

## [2.8.5] - 2026-03-13

### Added

- GitHub App webhook integration for pull request scanning and sticky CodeTrust PR comments.
- SBOM generation endpoint and service with CycloneDX and SPDX JSON outputs.
- Team dashboard org-member-policy workflows completed.
- Governance analytics score and trend view added to dashboard/governance surfaces.
- Policy rollout simulation controls added for safer governance changes.
- IDE quick-fixes expanded for `bare except` and hardcoded secrets.
- Release smoke gate workflow added for release readiness checks.

### Changed

- Signature validation database expanded to 50 modules and 405 functions.
- Live telemetry dashboard restructured to show honest, non-inflated metrics.
- Protection card presentation reworked to capability labels, while restoring meaningful sub-stats.

### Fixed

- Extension MCP recovery and scan stability hardened.
- MCP config injection now self-heals malformed config and deduplicates inject prompts.
- Release smoke gate now self-heals in local execution paths.
- Dashboard moat stats layout corrected to a stable single-row presentation.

### Docs / Quality

- Roadmap and release checkpoint docs truth-synced after delivery.
- OpenVSX publish step added to the release checklist.

## [2.8.2] - 2026-03-12

### Fixed

- Secret Storage migration now always overwrites stale API keys instead of skipping when a value exists.
- Global MCP config no longer injects `${workspaceFolder}` env var which crashes in non-workspace contexts.
- MCP auto-injection uses correct `servers` key format for VS Code.
- JavaScript obfuscator no longer breaks extension `activate` export.

### Changed

- PRODUCT.md corrected to match verified code reality: AST supports 10 languages (was listed as 5), typosquatting covers 1100+ packages total (was inflated to 500+ per ecosystem).
- All 22 product promises audited and verified against actual implementation. Zero gaps.

### Verified

- 1939 tests passing, 0 failed
- Security audit: no API key leakage in codebase
- All distribution channels live: PyPI, VS Code Marketplace, Railway, GitHub

## [2.8.1] - 2026-03-10

### Fixed

- Billing routes now sanitize provider errors and avoid exposing raw Stripe/backend error text to end users.
- Dashboard billing UI now applies defensive error-message sanitization and safe fallback messaging for 5xx failures.
- MCP governance instruction templates now reference actual gateway tool names (`mcp_codetrust-gat_codetrust_*`) instead of legacy aliases.
- MCP auto-injection now resolves a stable CodeTrust runtime in new workspaces by reusing known global config roots and prioritizing project venv Python.

### Changed

- Release docs and website metadata aligned to `v2.8.1` across README, docs/index, OpenAPI metadata, extension/chrome release surfaces, and product collateral.

#### Added

- Gateway governance extensions:
  - Trusted execution session lifecycle (`begin_trusted_session`)
  - Approval flow with exception store (`approve_action`, `list_exceptions`, `revoke_exception`)
  - Policy simulation and control-plane posture surfaces (`simulate_policy`, `governance_posture`)
- New enforcement rules in gateway interception:
  - `gateway_native_tool_bypass_attempt` (BLOCK)
  - `gateway_disable_governance_env` (BLOCK)

#### Changed

- Gateway policy and template configuration updated for stricter governance behavior.
- Regex patterns in interception/content checks refactored for Guardian portability/quality compliance.

#### Quality / Hardening

- Guardian remediation sweep completed across:
  - Python test suite
  - VS Code extension sources/tests/scripts
  - Chrome extension scripts/content
  - Dashboard Tailwind configuration
- Repository quality gates remain green:
  - Full test run: 1935 passed, 0 failed
  - Guardian full scan: 0 BLOCK, 0 WARN (INFO-only test magic-number notes)

---

## [2.8.0] - 2026-03-08

### Added — Ultimate Governance Sprint

#### Multi-Workspace Aggregation

- **`src/services/workspace_registry.py`** — In-memory workspace posture registry
  with register/unregister/aggregate across multiple workspaces.
- 3 new API endpoints: `GET/POST /v1/governance/workspaces`,
  `DELETE /v1/governance/workspaces/{workspace_id}`.
- **`dashboard/src/components/multi-workspace-view.tsx`** — Bird's-eye dashboard
  with aggregate health bar (healthy/drifted/disabled), summary counters,
  and workspace table with drift/policy/pending indicators.

#### Unified Session Token

- **`src/services/unified_session.py`** — Cross-surface session tokens spanning
  IDE, CLI, CI, and API. SHA-256 audit chain IDs for traceability.
- 3 new API endpoints: `POST/GET/DELETE /v1/governance/session-token`.

#### Governance Dashboard (Live)

- **Governance posture component** with live status indicators (mode, control
  plane, policy hash, agent identity).
- **Drift alerts component** displaying real-time policy drift with
  severity-colored indicators and timestamps.
- **Exception management UI** with approve/revoke workflow for pending
  approvals and active exceptions.
- **Governance audit log** viewer with session/agent/action columns.
- Dashboard API client wired to all governance endpoints (audit, posture,
  approvals, exceptions, workspaces, simulation).

#### Governance Engine (Backend)

- **Runtime attestation** for governance actions — cryptographic proof of
  action execution via `src/gateway/attestation.py`.
- **Policy integrity protection** — tamper detection for gateway policy files
  via `src/gateway/policies.py`.
- **Governance approvals/exceptions REST endpoints** with typed Pydantic models.
- **Governance API client methods** (audit, posture, approvals, exceptions,
  simulate).
- Trusted execution mode with tokenized trusted-session gate in Gateway.
- Approval workflow for high-risk rules (`REQUIRES_APPROVAL`).
- Time-bound governance exceptions with list/revoke/match flow.
- Policy simulator and governance posture surfaces.

### Added — MCP Auto-Injection (Critical bugfix + new feature)

> **Highlight:** This is the most impactful change since the Gateway launch.
> Without it, AI agents received governance instructions but the MCP servers
> providing those tools were never registered — governance enforcement was broken.

#### MCP Runtime Registration

- Extension and CLI now automatically register required MCP runtimes across supported IDE targets on activation/setup.
- Registration is idempotent, resilient to malformed configs, and avoids overwriting user-owned custom entries.
- Runtime resolution logic was hardened to reduce environment-specific startup regressions.

### Fixed

- Governance instructions and runtime registration are now aligned so required validation tools are available at runtime.

### Added — New Distribution & Web Presence Builds

- **Chrome extension delivery channel** added under `chrome-extension/`:
  manifest, popup/options/content/background scripts, icons, store assets, and
  packaged artifact (`codetrust-chrome-extension.zip`).
- **Discovery & search distribution assets** added for web indexability and AI
  discoverability: `docs/llms.txt`, `docs/llms-full.txt`, `docs/feed.xml`,
  `docs/robots.txt`, `docs/sitemap.xml`, and verification files.
- **IndexNow ping utility** added (`scripts/indexnow-ping.mjs`) for search
  engine update propagation.

### Changed

- **Website and docs surface updated** (`docs/index.html`, `docs/style.css`,
  `docs/privacy.html`, headers and metadata files) for improved telemetry
  presentation, SEO clarity, and mobile responsiveness.
- **API/web security posture hardened** in the FastAPI surface and middleware,
  including auth flow updates, websocket guardrails, and IP/rate-limit handling.

### Fixed

- **Website telemetry/details alignment** fixes for public-facing counters,
  copy consistency, and sitemap URL correctness.
- **IDE configuration UX polish** in extension messaging (icon and status copy
  corrections) to reduce ambiguity during setup.

### Verified

- Backend tests: 1,937 pass, 0 fail.
- Dashboard tests: 54 pass.
- `ruff check src/ tests/`: pass (0 errors).
- API endpoints: 60. MCP tools: 21. Total rules: 284.

---

## [2.7.0] - 2026-02-20

### Added — Signature Engine Hardening, min_args Enforcement, Documentation Overhaul

#### Signature Validator Improvements

- **Depth-aware argument extraction:** `_CALL_RE` replaced with `_CALL_OPEN_RE` +
  `_extract_balanced_args()` — correctly handles nested function calls like
  `os.path.join(os.getcwd(), "file")`.
- **min_args / max_args enforcement:** new `_check_arg_count()` validates positional
  argument counts against signature database, emitting WARN for too few or too many args.
- **Commented import filtering:** `_resolve_python_imports()` now skips lines starting
  with `#` — prevents false positives from commented-out import statements.
- **From-import merging:** parenthesized and single-line imports for the same module
  are now merged instead of skipped, preserving all bindings.

#### Autofix Recipe Fixes

- **fix_mutable_default:** complete rewrite — handles ALL mutable default parameters
  per function (not just the first) using per-param regex `_MUTABLE_PARAM_RE`.
  New `_skip_docstring()` helper correctly handles single-line docstrings.
- **fix_connection_no_timeout:** new `_inject_timeout_param()` uses bracket-depth
  paren matching instead of naive line-ending check.
- **fix_os_system:** uses `shlex.split()` instead of `str.split()` for proper
  shell-safe argument parsing.

#### Signature Database

- 12 new modules added in v2.6.1 (subprocess, re, datetime, hashlib, collections,
  openai, asyncio, sys, crypto, http, child_process, next/navigation).
- Removed `useDispatch` and `useSelector` from React hallucination list — these are
  real functions from react-redux.
- Total: 33 modules, 209 functions.

### Fixed

- Signature validator: 4 critical/high bugs fixed — `_is_kwarg_token()` for `=` vs `==`,
  `_CALL_RE` updated for chained calls, unknown functions emit INFO not silent drop,
  `_PY_FROM_IMPORT_PAREN_RE` for multi-line imports.
- All documentation numbers synced to authoritative metrics:
  1,898 tests, 21 MCP tools (10 scan + 11 gateway), 46 API endpoints, 280 rules.
- Gateway Server docs updated: 7 → 11 tools (added 4 proxy tools).
- Removed aspirational compliance claims (SSO/OIDC, Sigstore, CycloneDX SBOM) from
  website — replaced with implemented features (Signature Validation).
- Added demo.html link to website navigation.

### Changed

- Test count: 1,896 → 1,898.
- Scan rules: 199 → 204.
- COMPARISON.md and PRODUCT.md fully rewritten to match v2.7.0 state.

---

## [2.6.1] - 2026-02-20

### Added — Signature Validation, Extended Autofix, Interactive Demo

#### Signature Validation Engine

- **Signature knowledge base** covering 16 Python + 11 JS/TS modules with
  function signatures, parameter types, and deprecation metadata.
- **Signature validator** catches hallucinated functions, unknown parameters,
  deprecated usage, and provides typo suggestions via Levenshtein distance.
- **CLI flag:** `--no-verify-signatures` to skip signature validation.
- **API endpoint:** `POST /v1/scan/signatures` for standalone signature checks.
- **Deep scan integration:** signature layer included in full deep scans.

#### Extended Autofix (17 new recipes)

- 17 new deterministic autofix recipes registered in the autofix engine:
  `console_log`, `mutable_default`, `datetime_utcnow`, `except_swallow`,
  `debug_mode_enabled`, `hardcoded_port`, `env_var_no_default`,
  `subprocess_shell`, `docker_latest_tag`, `sql_select_star`, `any_type`,
  `sleep_no_context`, `connection_no_timeout`, `suppress_lint`,
  `react_index_as_key`, `os_system`, `string_concat_sql`.

#### Interactive Web Demo

- Client-side interactive demo (`docs/demo.html`) with 25+ JS scanning rules,
  verdict badge (PASS/WARN/BLOCK), AI drift score with A–F grading,
  category breakdown (Security, Hallucination, Quality, DevOps), and
  per-finding category icons.

#### New Scan Rule

- `hardcoded_port` — detects hardcoded port numbers in application code.

### Fixed

- Scanning engine: finds ALL occurrences per rule (removed early-break bug),
  deduplicates per-line, clean multi-line fallback only when needed.
- `react_index_key` regex updated to use word boundaries (false positive fix).
- Code quality: refactored long functions in signature_validator.py (>40 lines → ≤40),
  extracted named constants, fixed weak type annotation in autofix_recipes.py.

### Changed

- Test count: 1795 → 1896 tests (101 new: 58 signature + 43 autofix).
- Synced test count and rule count across all documentation (README, pyproject.toml,
  metrics.json, docs/index.html, extension/package.json).

---

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
