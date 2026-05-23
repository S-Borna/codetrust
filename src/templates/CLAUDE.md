# CLAUDE.md — CodeTrust

> CodeTrust is active in this project as a **warn-first companion**: it shows
> what it finds but does not block your commit unless this project has opted
> into a strict gate (`codetrust enforce`). Treat findings as signal, not as a
> wall. Fix what matters; explain what you're deliberately leaving.

## Scanning Protocol

### While writing or changing code

1. Call `codetrust_static_scan` on files you change to see findings early.
2. Call `codetrust_deep_scan` when you add files or change imports.
3. Treat BLOCK findings as high-priority: fix them, or state plainly why
   they're acceptable here. WARN/INFO are advisory.

### Around commits

1. `codetrust_post_action` summarizes findings for the changed files.
2. In warn-first mode (default) findings never block the commit — surface
   them to the user and let them decide.
3. In enforce mode (`codetrust enforce`) BLOCK findings fail the commit/CI;
   resolve them before committing.

### Imports and Docker

1. When adding a new import → `codetrust_verify_imports`.
2. When changing a Dockerfile → `codetrust_verify_dockerfile`.
3. Don't introduce a package that registry verification reports as NOT_FOUND.

## Good defaults

- Show scan results to the user — visibility is the point.
- Prefer fixing the root cause over suppressing a finding.
- No eval/exec/pickle.load on untrusted data.
- No hardcoded secrets — use environment variables.
- No wildcard imports — import explicitly.
- No bare except — catch specific exceptions.
- If CodeTrust MCP tools are unavailable, say so explicitly rather than guessing.
