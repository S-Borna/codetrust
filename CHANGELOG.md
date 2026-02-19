# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

For release notes prior to v2.5.0, see the [full git history](https://github.com/SaidBorna/codetrust/commits/main) or run `git log --oneline` locally.

**Current version: 2.5.2** — install via `pip install codetrust` or the [VS Code Marketplace](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust).
