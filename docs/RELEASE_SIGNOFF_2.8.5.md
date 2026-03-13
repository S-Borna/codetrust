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
