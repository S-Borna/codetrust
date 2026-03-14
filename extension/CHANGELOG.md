# CodeTrust VS Code Extension — Changelog

This changelog covers the **VS Code extension package** published to the Marketplace.
For the full platform history (API/CLI/Action/MCP), see the repo root CHANGELOG.md.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### What's Coming

- Additional governance disruption telemetry for faster root-cause diagnosis in mixed IDE environments.
- Expanded startup checks for first-run IDE profile bootstrap scenarios.

## [2.8.6] - 2026-03-14

### What's New (since 2.8.5)

### Fixed

- Release smoke and trust verification flow hardened for cross-platform CI reliability.
- Additional Windows-specific stability fixes for test and runtime edge cases.
- Claude Desktop MCP startup path hardened for existing users by avoiding workspace-bound global runtime defaults.
- Global MCP auto-resolution now prefers portable command strategies and safer upgrade behavior.
- Runtime fallback startup behavior refined to reduce transport noise during initialization.

### Changed

- Release metadata and public-facing counters synchronized to current measured values.
- Chrome extension release surfaces aligned to 2.8.6 for store/runtime consistency.
- Docs and release guidance now call out safer non-protected workspace locations for stable desktop runtime behavior.

### Added

- Formal bug/feature intake links in extension-facing documentation.
- Public report form workflow for direct submission to CodeTrust intake endpoints.

## [2.8.5] - 2026-03-13

### Added

- IDE quick-fixes expanded to cover `bare except` and hardcoded secrets.
- Governance rollout simulation controls surfaced in extension-driven workflows.

### Changed

- Extension health/release confidence improved with release smoke gate coverage.
- Governance/protection UI signaling refined to capability-based labels and clearer stats behavior.

### Fixed

- MCP recovery and scan stability hardened.
- Auto-injected MCP config handling now self-heals malformed entries and deduplicates repeated prompts.
- MCP health test noise in the output channel reduced to improve signal quality.

## [2.8.2] - 2026-03-12

### Fixed

- Secret Storage migration always overwrites stale API keys instead of skipping when existing value is non-empty.
- Global MCP config excludes `${workspaceFolder}` env for non-workspace targets (prevents crash).
- Obfuscator no longer breaks extension `activate` export.

### Changed

- Version bump across all surfaces for vision-complete milestone.

## [2.8.1] - 2026-03-10

### Fixed

- Corrected injected governance tool references so new sessions use resolvable runtime tools.
- Hardened MCP runtime resolution to reduce cross-workspace availability regressions.
- Improved environment/runtime selection order for more predictable startup behavior.

### Changed

- Global MCP config handling standardized across supported IDE targets for consistent runtime behavior.

### Added

- Governance hardening support in extension flows aligned with gateway additions:
	- trusted-session execution gating support
	- approval/exception lifecycle integration points
	- policy simulation and governance posture consumption paths

### Changed

- Quality remediation across extension runtime and test surfaces:
	- magic-number reductions via named constants
	- regex portability and stability cleanups
	- script hygiene updates in build/release helpers
- Internal release messaging now synchronized with platform-level post-2.8.1 updates.

### Verified

- Repository quality gates after remediation:
	- full test run green
	- Guardian scan green at BLOCK/WARN level

## [2.8.0] - 2026-03-07

### Added

- **MCP Auto-Injection** — extension activation now registers required MCP servers across supported IDE targets.
- **Smart Runtime Detection** — improved command/runtime discovery with safe fallback behavior.
- **Config Resilience** — disruption detection, safe recovery prompts, and malformed-config handling.
- **Clean Uninstall** — deactivation removes only extension-injected MCP entries.

### Fixed

- **Critical:** Governance instructions and runtime registration are now aligned so required tools are available at runtime.
- **IDE config messaging polish:** corrected icon/character rendering in setup output to avoid ambiguous status signals.

## [2.7.0] - 2026-02-20

### Added

- **Signature Validation** — curated function database (33 modules, 209 functions) validates call signatures with min/max argument enforcement, catching AI hallucinations at the function-call level
- **46 API endpoints** (up from 44)
- **280 scan rules** across 10 enforcement layers

### Platform (benefits all surfaces)

- Signature engine hardening with min_args enforcement
- Public-facing materials audit — all claims verified against real implementation
- SOC 2 controls mapping documentation updated
- SECURITY.md updated with v2.7.x support

## [2.6.0] - 2026-02-20

### Added

- **Copyright headers** — all 22 TypeScript source files carry proprietary copyright notice
- **esbuild bundling** — extension now ships as a single minified, identifier-obfuscated file instead of individual compiled `.js` files
- **Source maps disabled** — `tsconfig.json` sets `sourceMap: false`; no `.map` files in package

### Changed

- `vscode:prepublish` now runs `npm run bundle` (esbuild) instead of `npm run compile` (tsc)
- Extension output is a single `out/extension.js` file with copyright banner

### Platform (benefits all surfaces)

- Runtime license validation module (`src/services/license_guard.py`)
- `POST /v1/license/validate` endpoint for license key verification
- Release security gates — 7 automated pre-release IP/security checks
- Terms of Service published at codetrust.ai/tos
- Contributor License Agreement (CLA.md) required for all contributions

## [2.4.0] - 2026-02-20

### Added

- **7 new languages**: Java, C#, C++, Shell/Bash, HTML, Terraform, YAML (up from 6)
- **Ruby, PHP & PowerShell language support** — activation events, AST analysis, import verification (RubyGems, Packagist)
- **16 languages total**: Python, JS, TS, Go, Rust, Java, C#, Ruby, PHP, C++, Shell, PowerShell, Terraform, HTML, SQL, YAML
- Activation events for all 16 languages
- Import verification for Java, C#, C++, Ruby, PHP added (8 registries total)
- Language mapping: `c` → `cpp`, `shellscript` → `shell`, plus all new language IDs
- Embedded scanner routes Terraform/HCL (`.tf`, `.tfvars`, `.hcl`) to DevOps rules
- `enabledLanguages` setting expanded from 6 to 16 entries

### Platform (benefits all surfaces)

- **CVE/vulnerability scanning** via OSV database — `POST /v1/vuln/scan`, `codetrust vuln`
- **License compliance** checking — `POST /v1/license/scan`, `codetrust license`
- **Cross-file import analysis** with cycle/orphan/hub detection — `POST /v1/scan/cross-file`
- **Auto-fix PR generation** via GitHub API — `POST /v1/fix/apply`, `codetrust fix --pr`
- **Team management & RBAC** with org policies — 10 new endpoints under `/v1/orgs/*`
- 14 new API endpoints (42 total, up from 28)
- **11 new philosophy rules** — root-cause enforcement, determinism, configuration, safe data handling, code hygiene
- **110 new IaC/config/language rules** (Batches 1–3) — Ruby, PHP, PowerShell, Terraform, Helm, Ansible, Nginx, CloudFormation, Bicep, Redis, Vault, Monitoring, Systemd, Docker Compose, GitHub Actions, Config Hygiene (275 total rules, up from 154)

### Changed

- Status bar: consistent `$(shield) CodeTrust` branding across all verdict states — no color changes, no "(offline)" suffix
- Silent activation: onboarding/consent prompts removed; `scanOnSave` and governance enabled globally by default
- `onStartupFinished` added — extension activates in every workspace automatically
- Scan-on-open fires unconditionally; active editor + all open docs scanned on activation

### Fixed

- `handleScanOnSave` skips non-file URI schemes (output panels, git diffs)

## [2.3.2] - 2026-02-16

### Fixed

- Marketplace README/action snippets aligned to a single release tag

## [2.3.1] - 2026-02-16

### Added

- Profiles: Create/Apply CodeTrust Profile
- Scan-on-type (opt-in, debounced) using the embedded offline scanner
- Expanded Quick Fix coverage (deterministic transforms)
- Guided onboarding: configure API URL/key + run first scan
- API key stored in VS Code Secret Storage (migrated from settings)
- Onboarding success confirmation message

### Fixed

- Extension tests compile before running to ensure TypeScript tests are executed

## [2.2.4] - 2026-02-13

### Fixed

- Release-sync guard strengthened to keep extension/package version aligned with the platform release
