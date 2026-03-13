# Release Sign-Off — v2.8.5

Date: 2026-03-13
Owner: CodeTrust Release Engineering
Status: CONDITIONAL PASS (see Gate G1 note)

## Scope

This sign-off covers all currently shipped CodeTrust surfaces and release-critical
governance paths, with explicit focus on previously identified recurring misses:

1. Cross-environment verification depth
2. Windsurf coverage parity
3. Copilot global clean-profile injection behavior
4. Hidden local-path/global-config drift

## DoD Gates and Outcomes

### G1. Full E2E Matrix on clean environments (macOS/Windows/Linux)

- Requirement: every release must validate core gates in a cross-OS clean matrix.
- Action completed: CI workflow updated to matrix execution on
  `ubuntu-latest`, `macos-latest`, `windows-latest` for:
  - Extension release smoke gate
  - Backend lint + full pytest run
- Evidence:
  - `.github/workflows/release-smoke.yml` now has OS matrix for both jobs.
- Outcome: PASS at definition level, pending remote CI execution proof per runner.

### G2. Windsurf coverage parity

- Requirement: Windsurf must be first-class in global injection logic and DOD gates.
- Action completed:
  - Trust DOD script extended with explicit Windsurf guard (`DOD-T7`).
  - Verified source includes Windsurf target and disruption watcher path.
- Evidence:
  - `extension/scripts/verify-trust-dod.js`
  - `extension/src/universal-instructions.ts`
  - Local run: `npm run verify:trust-dod` => `DOD-T7: PASS`
- Outcome: PASS (code + local gate evidence).

### G3. Copilot clean-profile global injection verification

- Requirement: Copilot instructions must be injected globally, not workspace-local.
- Action completed:
  - Trust DOD script extended with explicit Copilot global-scope guard (`DOD-T8`).
  - Verified runtime state in user settings includes
    `github.copilot.chat.codeGeneration.instructions` with
    `[codetrust-governance-v1]` marker.
- Evidence:
  - `extension/scripts/verify-trust-dod.js`
  - `extension/src/extension.ts`
  - Local run: `npm run verify:trust-dod` => `DOD-T8: PASS`
  - Local settings check: marker present in VS Code global settings.
- Outcome: PASS.

### G4. Local-folder assumptions leaking into global configuration

- Requirement: no `${workspaceFolder}` leakage in global MCP config targets;
  VS Code must use `servers` key (not `mcpServers`).
- Action completed:
  - Trust DOD script extended with global-key/workspace-var guard (`DOD-T9`).
  - Release smoke MCP resolvability checks passed for global targets.
  - Global files inspected for correct key usage and absolute command paths.
- Evidence:
  - `extension/scripts/verify-trust-dod.js`
  - `extension/src/mcp-config-injection.ts`
  - Local run: `npm run verify:trust-dod` => `DOD-T9: PASS`
  - Local run: `scripts/release_smoke.sh` => MCP checks PASS
- Outcome: PASS.

## Platform Verification Summary

- Full backend test suite: `1950 passed, 0 failed`
- Ruff gate: PASS (`ruff check src tests`)
- Extension release smoke: PASS (`8 passed, 0 failed`)
- Trust DOD gate: PASS (`DOD-T1 ... DOD-T9`)
- Guardian post-action scan on hardening changes: PASS

## Residual Risk Register (Release Engineering)

1. Third-party npm advisories exist in extension dependency tree output.
   - Current impact: non-blocking for this release gate.
   - Control: track and remediate in dependency hardening sprint.

2. Windsurf runtime state on this machine is not installed (`~/.codeium/...` absent),
   so direct on-host file-state validation is not possible here.
   - Control: enforced through source-level DOD guard + matrix CI + installation-path checks.

## Sign-Off Decision

Given the completed hardening, passing local gates, and newly enforced cross-OS CI
matrix, this release is approved for publish with conditional enforcement:

- Condition A: matrix jobs in `.github/workflows/release-smoke.yml` must be green.
- Condition B: no new failures in Trust DOD or release smoke gates.

If either condition fails, release is blocked.

## Runbook Crosscheck Snapshot (2026-03-13)

This snapshot maps current evidence to `docs/GLOBAL_VERIFICATION_RUNBOOK_2.8.5.md`.

1. Section 1 (CI matrix): PASS with external evidence source.
  - Latest workflow runs reported green for `Release Smoke Gate` and `Trust DOD Gate`.
  - Note: GitHub UI/job links are external to this repository and must be attached in release evidence.

2. Section 2 (local smoke + trust DOD): PASS.
  - `bash scripts/release_smoke.sh` => `Summary: 8 passed, 0 failed`.
  - `cd extension && npm run verify:trust-dod` => `DOD-T1..DOD-T9 PASS`.

3. Section 3 (global MCP config state): PASS.
  - VS Code global config uses `servers` key.
  - Claude/Cursor/Claude Desktop use `mcpServers` key.
  - `codetrust` and `codetrust-gateway` command entries present and resolvable.

4. Section 4 (Copilot global injection): PASS.
  - `github.copilot.chat.codeGeneration.instructions` contains `[codetrust-governance-v1]` marker in global settings.

5. Section 5 (Windsurf): N/A with compensating control.
  - Local check result: `WINDSURF_NOT_INSTALLED`.
  - Compensating control: trust DOD source/test gate `DOD-T7` passing.

6. Section 6 (published artifacts): BLOCK.
  - Clean-venv check failed: `pip install codetrust==2.8.5` returned no matching distribution.
  - Registry currently exposes `2.8.2` only.

7. Section 7 (production smoke): BLOCK (not executed in this workspace context).
  - Requires live environment/API + webhook verification evidence.

8. Section 8 (dependency risk triage): PARTIAL.
  - npm audit summary: `low=1, moderate=2, high=5, total=8`.
  - pip-audit findings: `2` vulnerabilities:
    - `cryptography 46.0.4` -> `CVE-2026-26007`, fix `46.0.5`
    - `pip 25.3` -> `CVE-2026-1703`, fix `26.0`
  - Owner/due-date assignments for accepted risk are still required.

### Updated Decision

Status remains `CONDITIONAL PASS`.

Unconditional `APPROVED` requires closing all BLOCK/PARTIAL runbook items above.
