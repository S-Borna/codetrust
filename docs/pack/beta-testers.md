# CodeTrust — Beta Tester Guide

## Goal

Help validate CodeTrust in real daily development:

- Catch false positives / false negatives
- Validate UX (VS Code extension + CLI)
- Identify breaking workflows in CI/pre-commit

## What to test (daily)

### VS Code extension

- Scan on save: verify diagnostics appear on supported files
- Scan workspace: run on a medium repo and confirm progress + results
- Scan on type (optional): enable it and confirm it stays responsive while typing
- Quick Fixes: apply suggested fixes where offered and confirm code still runs
- Health Check: confirm API URL/key errors are understandable when misconfigured

### CLI

- `codetrust scan .` for baseline
- Noise-control flags for large repos:
  - `--changed-only` to focus on diffs
  - `--dedupe` to reduce repetitive findings
  - `--suppress-lint-noise` if lint-style warnings overwhelm signal
- Repo-aware summaries:
  - `codetrust pr-risk`
  - `codetrust trust-diff`
  - `codetrust trend record` / `codetrust trend show`

## What to report

When filing an issue/bug report, include:

- Tool + surface: VS Code / CLI / GitHub Action / API
- Version: CodeTrust version and VS Code extension version
- Expected vs actual behavior
- Minimal reproduction (file snippet or steps)
- Output:
  - CLI: JSON output if available (`--json`)
  - VS Code: screenshot of diagnostics + the setting values that matter (apiUrl, scanType, scanOnSave/scanOnType)

## Common categories

- False positive: a finding that is not actually risky in context
- False negative: missing detection for an obviously risky pattern
- Rule severity mismatch: should be WARN vs BLOCK
- Performance regression: lag/CPU spikes during scans
- Bad remediation: Quick Fix changes code incorrectly

## Safety notes

- Do not paste real secrets into issues.
- If a finding involves credentials, redact or replace with placeholders.
