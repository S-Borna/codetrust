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

---

## Go-to-market add-ons (planned)

✅ 7) Marketplace-first guided onboarding (API URL/key + first scan)
✅ 1) PR-mode default in CI (changed-lines + new findings only)
✅ 3) New-findings-only hard gate (baseline vs HEAD)
✅ 2) GitHub PR summary comment + richer annotations
✅ 6) Doctor as onboarding checklist + auto-fix (`--fix`)
✅ 4) Autofix recipes (safe deterministic subset)
✅ 5) Policy Wizard + schema autocomplete

## Phase 7 — Enterprise Services (competitive parity)

✅ 1) CVE/vulnerability scanning via OSV database (`/v1/vuln/scan`, `codetrust vuln`)
✅ 2) License compliance checking (`/v1/license/scan`, `codetrust license`)
✅ 3) Cross-file import analysis with cycle/orphan/hub detection (`/v1/scan/cross-file`)
✅ 4) Auto-fix PR generation via GitHub API (`/v1/fix/apply`, `codetrust fix --pr`)
✅ 5) Team management & RBAC with org-level policies (`/v1/orgs/*`, 10 endpoints)

---

## Ultimate Governance Program (step-by-step, commit-by-commit)

Target: practical 95%+ operational control in AI-assisted development via policy-as-code, hard enforcement, and attestation.

### Constraints and truth model

- 100% theoretical control is not possible if an agent can execute freely outside enforcement.
- Product target is therefore hard technical gates + verifiable attestations + auditability.
- Delivery model is atomic: each part ships with tests, checkpoint, and one commit.

### Part 1 — Tamper protection for policy artifacts

Scope:
- Sign and hash policy artifacts (`CLAUDE.md`, workspace rules, gateway policy files).
- Fail closed on mismatch in enforced mode.

Implementation:
- Add policy integrity manifest (hash + signature + version + issued_at).
- Verify integrity at gateway startup and before policy-evaluated actions.
- Emit explicit audit event `policy_integrity_failed` on mismatch.

Acceptance criteria:
- Modified policy file without re-signing yields BLOCK in enforce mode.
- Audit log records expected/actual hash and policy source.

### Part 2 — Runtime attestation everywhere

Scope:
- Require `session_id` + `policy_hash` on gateway tool invocations.
- Make attestation fields mandatory in audit payloads.

Implementation:
- Extend gateway request contracts with attestation envelope.
- Reject missing/invalid attestation in enforce mode.
- Add replay protection (`nonce` + short TTL).

Acceptance criteria:
- Requests without attestation are blocked with actionable safe-fix.
- Audit entries always include attestation fields.

### Part 3 — Trusted execution mode (deny native, allow proxy)

Scope:
- Block native execution paths when proxy equivalents are required.
- Enforce in local hook + CI + optional API gate.

Implementation:
- Introduce trusted mode policy flag (`trusted_mode=true`).
- Add denylist for native tools and allowlist for proxy tools.
- Add CI check that fails if prohibited native patterns are detected.

Acceptance criteria:
- Native tool usage in trusted mode gets BLOCK + clear remediation.
- Proxy-path usage passes.

### Part 4 — Interactive approval gate ("always ask allow")

Scope:
- For high-risk actions, require explicit approval before continuation.
- Return mandatory explanation for why approval is needed.

Implementation:
- Add verdict `REQUIRES_APPROVAL` with `risk_reason`, `impact`, `safe_alternative`.
- Support approval token flow (short-lived, signed, single-use, scoped to action hash).
- Persist approval decision with approver identity and expiry.

Acceptance criteria:
- High-risk actions pause and require approval token.
- Reused/expired token is rejected and audited.

### Part 5 — Exception workflow v1 (time-boxed)

Scope:
- Create/approve/revoke temporary policy exceptions.
- Link each exception to explicit reason, owner, scope, and expiry.

Implementation:
- Exception objects: `id`, `rule_id`, `scope`, `reason`, `approved_by`, `expires_at`, `status`.
- Enforce automatic expiry and revocation checks during policy evaluation.
- Add audit events: created, approved, used, expired, revoked.

Acceptance criteria:
- Exception works only within scope + TTL.
- Expired exception no longer bypasses rule.

### Part 6 — Policy simulator (dry-run in PR)

Scope:
- Simulate governance outcome without blocking merge.
- Show exact rules that would block/warn under enforce mode.

Implementation:
- Add simulator endpoint/CLI mode (`--simulate-policy`).
- Emit machine-readable report with diff vs current policy result.

Acceptance criteria:
- PR gets deterministic “would block” summary with rule IDs and fixes.

### Part 7 — Org policy packs (signed defaults)

Scope:
- Deliver startup/team/enterprise packs as signed bundles.
- Ensure deterministic rollout and rollback.

Implementation:
- Versioned bundle schema + signature validation.
- Add rollout guardrails (preview, apply, verify).

Acceptance criteria:
- Pack signature required in enforce mode.
- Rollback restores previous policy snapshot exactly.

### Part 8 — Anti-bypass client hardening

Scope:
- Detect and mitigate attempts to ignore MCP/proxy requirements.
- Enforce “policy-first” behavior at integration boundaries.

Implementation:
- Add bypass detectors (missing proxy call, direct native command patterns, tampered config).
- Add progressive response: WARN → BLOCK based on risk + policy mode.

Acceptance criteria:
- Bypass attempts are detected with explicit root-cause and safe-fix.

### Part 9 — Control plane (realtime posture)

Scope:
- Unified visibility per workspace/agent/session.
- Realtime governance posture, drift, and policy integrity status.

Implementation:
- Dashboard cards: attestation coverage, trusted-mode adoption, exception debt, bypass attempts.
- Realtime stream for critical governance events.

Acceptance criteria:
- Ops can answer “who bypassed what, when, and under which policy hash” in one view.

### Delivery order and release gates

Delivery order:
1. Part 1 + Part 2
2. Part 3 + Part 4
3. Part 5 + Part 6
4. Part 7 + Part 8 + Part 9

For each part (mandatory):
- Tests (happy + failure + abuse-path)
- Lint clean
- Guardian scan with zero BLOCK
- Checkpoint in `SESSION_LOG.md`
- Single atomic commit
