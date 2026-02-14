# CodeTrust — One‑Pager (Customers / Investors)

## What it is

CodeTrust is an **AI code safety and governance platform** that helps teams ship AI-assisted code with higher confidence.

It focuses on failure modes that become common with AI coding assistants:

- Hallucinated dependencies
- Risky copy/paste security patterns
- Destructive agent actions (governance / guardrails)
- Gradual “trust drift” across a codebase over time

## How teams use it

- VS Code extension for fast feedback during development
- CLI + CI integration for enforceable gates
- GitHub Action for PR checks and SARIF reporting
- REST API and MCP tools for integrations and agent workflows

## Why now

AI accelerates coding, but increases variance and introduces new classes of mistakes. CodeTrust is built to reduce that risk early (developer-time) and enforce it later (pre-commit/CI).

## What’s shipping vs what’s next

### Available today

- Static scanning with clear severities (BLOCK/WARN/INFO)
- Repo-aware workflows (diff-focused scanning, noise controls)
- Trust trend tracking (record/show snapshots)
- VS Code UX: health check, workspace scan, profiles, quick fixes

### Planned next (go-to-market add-ons)

See docs/roadmap.md and the planned list in RELEASE_NOTES.md.

## The pitch in one line

**Trust the code. Ship with proof.**
