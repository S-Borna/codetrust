# Plan A Roadmap — Deterministic MCP Startup (VSX + Cross-Editor)

## Why This Roadmap Exists

CodeTrust startup reliability has improved, but still shows recurring friction in fresh workspaces and mixed editor environments.

The user requirement is explicit: installation alone should be enough for CodeTrust to start and enforce governance, independent of editor, workspace age, and platform.

## Problem Statement (Root Causes)

1. Workspace override drift
- A workspace-local MCP config can override a healthy global config.
- If the workspace entry points to an unresolved command, startup fails despite healthy global state.

2. Runtime resolution variability
- Command discovery depends on host process environment (PATH, shell startup behavior, interpreter exposure).
- VS Code extension host environment can differ from user terminal environment.

3. Health-check false negatives and noisy failures
- Prior checks could report unresolved workspace entries even when a resolvable global entry existed.
- This increases operator confusion and trust erosion.

4. Cross-editor schema and target differences
- VS Code expects servers while other editors use mcpServers.
- Any mismatch or migration gap causes silent non-activation.

5. Release lag between fix and field adoption
- Even correct fixes provide no user benefit until shipped through marketplace channels.

## Current State (Already Implemented)

1. Hardened workspace behavior in MCP injection
- Prefer resolvable global entries over unresolved workspace entries.
- Remove unresolved auto-injected workspace entries to restore global fallback behavior.

2. Improved command resolution in MCP injection
- Added Python module fallback when script command is not directly resolvable.

3. Commit already created
- 60e58a0e fix: harden MCP auto-setup across new workspaces.

## Plan A Goal

Create a deterministic startup contract where CodeTrust activation does not depend on opportunistic environment state.

Deterministic means:
- Same startup decision outcome given same machine/editor state.
- Self-healing config behavior.
- No hard failure when a healthy path exists.

## Execution Roadmap

### Phase 0 — Ship Existing Fixes (VSX Patch Release)

Objective:
- Deliver already-implemented reliability fixes to all users.

Scope:
- Bump extension version (patch).
- Update changelog release notes for MCP startup hardening.
- Build VSIX and publish to VS Marketplace/Open VSX.
- Verify install in clean workspace.

Problems addressed:
- Immediate field impact gap (#5).

Acceptance criteria:
- New release visible on marketplace.
- Clean install in a new workspace does not fail when global MCP entries are resolvable.

### Phase 1 — Deterministic Command Resolution Contract

Objective:
- Replace opportunistic resolution order with explicit, testable priority and consistency rules.

Scope:
- Define and enforce a single resolution policy with confidence levels.
- Persist last known good resolution choice per editor target.
- Require revalidation before switching away from last known good.

Problems addressed:
- Runtime resolution variability (#2).

Acceptance criteria:
- Same workspace opens produce identical command choice across restarts.
- Resolution selection and reason are logged in a structured, single-line format.

### Phase 1B — JSON/JSONC First-Class Language Support

Objective:
- Include JSON-family files as first-class scan targets in the extension and backend contracts.

Scope:
- Add json/jsonc activation coverage in extension contribution points.
- Extend extension language mapping and workspace scan file globs to include json/jsonc.
- Extend backend language enum and request validation path to include json.
- Add parity tests for single-file scan, workspace scan, and unsupported-language messaging transitions.

Problems addressed:
- Current user-visible mismatch where JSON files show unsupported status despite being central config artifacts.

Acceptance criteria:
- JSON/JSONC files are recognized as supported in editor feedback.
- Scan File and Scan Workspace include JSON-family files by default.
- API accepts and processes json language payloads without schema rejection.

### Phase 2 — Self-Healing Config Orchestration

Objective:
- Make config mutation corrective instead of additive-only.

Scope:
- If workspace entry is unresolved and global is healthy, auto-demote workspace entry.
- If wrong key is detected for target editor, auto-migrate and compact stale keys.
- Add integrity marker versioning for future migrations.

Problems addressed:
- Workspace override drift (#1), schema differences (#4).

Acceptance criteria:
- Opening a broken workspace config recovers without user action.
- Health check reports resolved state after self-heal pass.

### Phase 3 — Health Model and Operator Clarity

Objective:
- Ensure health reporting mirrors actual executable reality.

Scope:
- Report effective resolution source (workspace/global) per server.
- Distinguish blocking issues from non-blocking degradations.
- Show exact remediations for each blocking issue.

Problems addressed:
- False negatives/noisy failures (#3).

Acceptance criteria:
- No warning is emitted when effective startup path is healthy.
- Blocking warnings always include actionable remediation and target file.

### Phase 4 — Cross-Platform + Cross-Editor Startup Matrix

Objective:
- Institutionalize reliability via automated validation, not ad hoc manual checks.

Scope:
- Add matrix tests for macOS/Linux/Windows and new/existing workspaces.
- Validate target schema correctness for VS Code, Claude, Cursor.
- Validate migration from stale/legacy injected configs.

Problems addressed:
- Runtime variability (#2), schema variance (#4), release confidence (#5).

Acceptance criteria:
- CI startup matrix green before release tagging.
- Release blocked if any target fails deterministic startup checks.

### Phase 5 — Fallback Reduction (After Proven Stability)

Objective:
- Keep only strategically necessary fallbacks.

Scope:
- Remove fallback branches that are never selected in production telemetry.
- Keep one guarded emergency fallback path only.

Problems addressed:
- Long-term complexity and maintenance drift.

Acceptance criteria:
- Reduced decision branches with unchanged startup success rate.

## Delivery Sequencing

1. First ship Phase 0 patch release containing commit 60e58a0e.
2. Then execute Phases 1-3 in a single reliability stream.
3. Gate Phases 4-5 on automated startup matrix readiness.

## Risks and Controls

1. Risk: accidental removal of user-customized entries.
- Control: only mutate auto-injected entries (marker-bound), never user-owned entries.

2. Risk: platform-specific command behavior divergence.
- Control: matrix tests + per-platform resolution probes.

3. Risk: noisy telemetry/health logs masking true blockers.
- Control: strict severity model (BLOCK/WARN/INFO) tied to effective startup path.

## Definition of Done (Plan A Stream)

1. Fresh install startup succeeds on macOS/Linux/Windows without manual PATH edits when a valid runtime path exists.
2. Workspace corruption is auto-healed to a healthy effective configuration.
3. Health output reports only real blockers.
4. VSX/Marketplace release notes include startup reliability guarantees and known limits.

## Status

- Documentation checkpoint complete.
- Implementation of new Plan A phases not started (awaiting user approval).