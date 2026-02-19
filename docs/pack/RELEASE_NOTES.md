# CodeTrust — Release Notes (Excerpt)

This is a **shareable excerpt** intended for testers and stakeholders.
For the complete history, see the repo root CHANGELOG.md.

## 2.4.0 (2026-02-20)

Highlights:

- **275 total rules** — 199 scan + 76 gateway (up from 239)
- **Batch 1**: Ruby & PHP language support, Maven Central & NuGet registry verification
- **Batch 2**: 51 IaC/config rules (Terraform, Helm, Ansible, Nginx, CloudFormation, Azure ARM/Bicep) + PowerShell 12 rules
- **Batch 3**: 36 config rules — Redis, HashiCorp Vault, Prometheus/Grafana, Systemd, Docker Compose advanced, GitHub Actions advanced, general config hygiene
- **16 languages** supported (added PowerShell)
- **1,665 tests** (up from 1,571)
- New file types: `.service`, `.timer`, `.ini`, `.cfg`

## 2.3.2 (2026-02-16)

Highlights:

- VS Code extension: profiles (create/apply), scan-on-type (opt-in), expanded Quick Fixes, Health Check command
- CLI: deterministic JSON output + unified fail semantics, stack presets, noise controls, repo-aware commands (`pr-risk`, `trust-diff`, `trend`)

Release sync:

- Documentation and Marketplace/PyPI-facing metadata aligned to a single version/tag

## Go-to-market add-ons delivered

- PR-mode default in CI (changed-lines + new findings only)
- GitHub PR summary comment + richer annotations
- New-findings-only hard gate (baseline vs HEAD)
- Autofix recipes (safe deterministic subset)
- Policy Wizard + schema autocomplete
- Doctor as onboarding checklist + auto-fix (`--fix`)
- Marketplace-first guided onboarding (API URL/key + first scan)
