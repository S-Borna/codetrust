# CodeTrust VS Code Extension — Changelog

This changelog covers the **VS Code extension package** published to the Marketplace.
For the full platform history (API/CLI/Action/MCP), see the repo root CHANGELOG.md.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **7 new languages**: Java, C#, C++, Shell/Bash, HTML, Terraform, YAML — total now **13** (up from 6)
- Activation events for all 13 languages
- Import verification for Java, C#, C++ added
- Language mapping: `c` → `cpp`, `shellscript` → `shell`, plus all new language IDs
- Embedded scanner routes Terraform/HCL (`.tf`, `.tfvars`, `.hcl`) to DevOps rules
- `enabledLanguages` setting expanded from 6 to 13 entries

### Platform (benefits all surfaces)

- **CVE/vulnerability scanning** via OSV database — `POST /v1/vuln/scan`, `codetrust vuln`
- **License compliance** checking — `POST /v1/license/scan`, `codetrust license`
- **Cross-file import analysis** with cycle/orphan/hub detection — `POST /v1/scan/cross-file`
- **Auto-fix PR generation** via GitHub API — `POST /v1/fix/apply`, `codetrust fix --pr`
- **Team management & RBAC** with org policies — 10 new endpoints under `/v1/orgs/*`
- 14 new API endpoints (42 total, up from 28)
- **11 new philosophy rules** — root-cause enforcement, determinism, configuration, safe data handling, code hygiene (165 total rules, up from 154)

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
