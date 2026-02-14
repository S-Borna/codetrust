# CodeTrust — Enterprise Procurement & Security Overview

## Summary

CodeTrust is designed to support enterprise expectations around:

- Clear enforcement points (developer-time vs CI)
- Auditability of automated actions
- Safe defaults (no secrets in docs, no risky automation without explicit enablement)

## Deployment & integration surfaces

- Developer tooling: VS Code extension + CLI
- CI/CD: GitHub Action (SARIF supported)
- Integrations: REST API and MCP tools for agent workflows

## Data handling (high level)

- Local/offline scanning is supported for many workflows.
- Networked verification features (e.g., registry checks) are explicit and configurable.

For security posture details and reporting guidelines, see SECURITY.md.

## Controls & governance

- Governance features focus on preventing unsafe automated actions and guiding users toward safer patterns.
- Enforcement strength depends on integration point (advisory in editor, enforceable in CI/pre-commit).

## Roadmap alignment

Planned add-ons that matter to enterprise workflows are tracked in docs/roadmap.md and summarized in RELEASE_NOTES.md.
