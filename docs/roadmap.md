# CodeTrust — ROI-driven roadmap (implementation plan)

This roadmap is ordered by **ROI** (value delivered / engineering risk) and designed to reach the backlog goal: AI-first, zero-friction, enforceable.

## Phase 1 — Baseline + Zero-friction UX (highest ROI)

✅ 1. Extension: Health Check surface (online/offline, config visibility, last scan)
✅ 2. Extension: Better API failure hints (401/403/429/timeout)
✅ 3. Extension: Fallback scan when no active editor (last saved/scanned file)
✅ 4. Extension: First-run “Always‑On for all workspaces?” global consent
✅ 5. VS Code Profiles support: “Create/Apply CodeTrust Profile” (one click)
✅ 6. Keep extension test suite green (embedded scanner + commands)

## Phase 2 — Repo bootstrap generators (high ROI)

✅ 1. CLI generator: add `.vscode/extensions.json` recommendation (never overwrite)
✅ 2. CLI generator: optional `.vscode/settings.json` presets per stack
✅ 3. CLI generator: add `.devcontainer/devcontainer.json` (auto-install extensions)
✅ 4. CLI generator: add CONTRIBUTING snippet (DoD + how CodeTrust complements verify)

## Phase 3 — Hard gates polish (medium risk, high trust)

✅ 1. Unify warn/block semantics across CLI, pre-commit, Action, API
✅ 2. Deterministic machine outputs (JSON/SARIF) + stable exit codes across surfaces
✅ 3. Improve `codetrust doctor` to pinpoint missing enforcement layers

## Phase 4 — “Per line” assist (medium ROI)

✅ 1. Debounced scan-on-type (opt-in) using embedded scanner (no API spam)
✅ 2. Expand safe Quick Fix coverage (limited, deterministic transforms)

## Phase 5 — Repo-aware intelligence (bigger lift)

✅ 1. Detect common verify gates (`npm run verify`, `pytest`, `ruff`, `tsc`) and pre-warn
✅ 2. Noise control: dedupe/group findings; focus on changed lines

## Phase 6 — Drift / Trust score (bigger lift)

✅ 1. Trust score diff per commit/PR
✅ 2. Trend view + regressions

---

## Definition of done (per item)

- Tests green (Python + extension)
- No overwrites without explicit confirmation
- No secrets written to tracked files
- Clear user-facing messaging for failures
