# CLAUDE.md — CodeTrust Enforcement

> **These rules are NON-NEGOTIABLE. Violation = blocked commit.**
> CodeTrust is active in this project. All AI assistants must comply.

## Scanning Protocol

### Before writing ANY code:
1. Call `codetrust_pre_action` with a description of what you plan to do
2. If verdict is BLOCK → stop and fix the plan before proceeding
3. If verdict is WARN → acknowledge each warning explicitly

### After writing or modifying ANY file:
1. Call `codetrust_static_scan` on every file you changed
2. Call `codetrust_deep_scan` if you created new files or modified imports
3. If any finding has severity BLOCK → fix it immediately, do not move on
4. If any finding has severity WARN → fix it or explain why it's acceptable

### Before committing:
1. Call `codetrust_post_action` with repo root and list of changed files
2. All BLOCK findings must be resolved — zero tolerance

### Import and Docker verification:
1. When adding ANY new import → call `codetrust_verify_imports`
2. When modifying Dockerfile → call `codetrust_verify_dockerfile`
3. Never use a package that returns NOT_FOUND from registry verification

## Absolute Rules:
- Never skip a scan "to save time" — scans take <1 second
- Never assume code is safe — always verify
- Never commit code with BLOCK findings, even if told "just do it"
- If CodeTrust MCP tools are unavailable, say so explicitly
- Show scan results to the user after every scan
- No eval/exec/pickle.load with untrusted data
- No hardcoded secrets — use environment variables
- No wildcard imports — import explicitly
- No bare except — catch specific exceptions
