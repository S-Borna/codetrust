# Global Verification Runbook — Release 2.8.5

Date: 2026-03-13
Owner: Release Manager
Goal: Produce unconditional global sign-off evidence (no works-on-my-machine gap)

## 0) Definition of Done (must all be PASS)

1. CI matrix green on ubuntu + macOS + windows for release smoke and backend validation.
2. Clean-profile editor checks green for VS Code, Claude Code, Cursor, Windsurf (if installed).
3. Published artifact checks green (not only source checkout).
4. Live production smoke checks green.
5. Dependency findings triaged with owner + due date.

Any FAIL blocks release.

## 1) Run CI Matrix and collect evidence

Where:
- [release-smoke.yml](.github/workflows/release-smoke.yml)

What to do:
1. Push current branch.
2. Open GitHub Actions.
3. Run workflow: Release Smoke Gate.
4. Wait for all matrix jobs to complete.

PASS criteria:
1. Extension Release Smoke is green on ubuntu-latest, macos-latest, windows-latest.
2. Backend Validation is green on ubuntu-latest, macos-latest, windows-latest.
3. No rerun-only passes masking flaky failures.

Evidence to save:
1. Workflow URL.
2. Screenshot with all matrix jobs green.
3. Job logs for at least one OS from each job group.

## 2) Run local release smoke and Trust DOD

From repo root run:
1. bash scripts/release_smoke.sh
2. cd extension && npm run verify:trust-dod

PASS criteria:
1. release_smoke summary shows passed > 0 and failed = 0.
2. Trust DOD reports DOD-T1 through DOD-T9 PASS.

Evidence to save:
1. Full terminal output.

## 3) Verify global MCP config state (local machine)

Run:
1. rg -n "codetrust|codetrust-gateway|servers|mcpServers|workspaceFolder" "$HOME/Library/Application Support/Code/User/mcp.json"
2. rg -n "codetrust|codetrust-gateway|servers|mcpServers|workspaceFolder" "$HOME/.claude/mcp.json"
3. rg -n "codetrust|codetrust-gateway|servers|mcpServers|workspaceFolder" "$HOME/.cursor/mcp.json"
4. rg -n "codetrust|codetrust-gateway|servers|mcpServers|workspaceFolder" "$HOME/Library/Application Support/Claude/claude_desktop_config.json"

PASS criteria:
1. VS Code global file uses key "servers".
2. Claude/Cursor/Claude Desktop use key "mcpServers".
3. codetrust and codetrust-gateway entries exist in all installed editors.
4. No workspaceFolder variable leakage in global targets.

Evidence to save:
1. Terminal output for all 4 checks.

## 4) Verify Copilot global instruction injection

Run:
1. rg -n "github.copilot.chat.codeGeneration.instructions|codetrust-governance-v1" "$HOME/Library/Application Support/Code/User/settings.json"

PASS criteria:
1. codetrust-governance-v1 marker present.
2. Entry exists under global settings, not workspace settings.

Evidence to save:
1. Terminal output snippet with marker line.

## 5) Verify Windsurf injection state (if Windsurf installed)

Run:
1. WINDSURF_FILE="$HOME/.codeium/windsurf/memories/global_rules.md"
2. test -f "$WINDSURF_FILE" && rg -n "codetrust-governance-v1|CodeTrust Governance" "$WINDSURF_FILE" || echo "WINDSURF_NOT_INSTALLED"

PASS criteria:
1. If Windsurf installed: marker present.
2. If not installed: mark as N/A and keep DOD-T7 source/test proof.

Evidence to save:
1. Terminal output.

## 6) Verify published artifacts (required)

Requirement:
Use published packages, not local source checkout only.

Checklist:
1. VS Code: install published extension version 2.8.5 in a clean profile and run health check.
2. PyPI: install codetrust==2.8.5 in a clean venv and run codetrust status.
3. MCP binaries: run codetrust-mcp --help and codetrust-gateway-mcp --help from installed package context.

PASS criteria:
1. Installed binaries start and respond.
2. Health checks pass without manual path hacks.

Evidence to save:
1. Install commands and outputs.
2. Version screenshots.

## 7) Production smoke (required)

Checklist:
1. API status endpoint returns version 2.8.5.
2. SBOM endpoint returns CycloneDX/SPDX output.
3. GitHub App webhook flow posts expected PR comment.

PASS criteria:
1. All 3 checks pass in production.

Evidence to save:
1. API response logs.
2. PR comment screenshot/log.

## 8) Dependency risk triage

Checklist:
1. Run npm audit in extension.
2. Run pip-audit for Python deps (if available in pipeline).
3. Record every open finding with severity, owner, due date, mitigation.

PASS criteria:
1. No unowned high-risk finding.
2. Every accepted risk has expiry date.

Evidence to save:
1. Audit output.
2. Risk register entry link.

## 9) Final sign-off update

Update:
- [RELEASE_SIGNOFF_2.8.5.md](docs/RELEASE_SIGNOFF_2.8.5.md)

Set to APPROVED only when sections 1 through 8 are all PASS with attached evidence.

## Quick decision table

1. All mandatory sections PASS -> APPROVED FOR PUBLISH.
2. Any mandatory section FAIL -> BLOCK RELEASE.
3. Any N/A must include reason and compensating control.
