# CodeTrust — Release Checklist

**Every version bump MUST complete every item below before commit.** No exceptions.

This checklist exists because stale numbers, missing changelog entries, and unsynced files
have caused unnecessary re-bumps and broken the perception of a professional product.
Follow it sequentially. Check each box. If a step fails, fix it before continuing.

---

## Pre-Release Audit

### 1. Version Sync (all files MUST show the SAME version)

| File | Field | Check |
|------|-------|-------|
| `pyproject.toml` | `version = "X.Y.Z"` | [ ] |
| `extension/package.json` | `"version": "X.Y.Z"` | [ ] |
| `docs/openapi.json` | `"version": "X.Y.Z"` | [ ] |
| `metrics.json` | `"version": "X.Y.Z"` | [ ] |
| `README.md` | `Current: vX.Y.Z` (header badge) | [ ] |
| `README.md` | `uses: S-Borna/codetrust@vX.Y.Z` (Action snippet, x2) | [ ] |
| `extension/CHANGELOG.md` | latest release header is `## [X.Y.Z] - YYYY-MM-DD` | [ ] |
| `docs/index.html` | visible version badge reflects `vX.Y.Z` | [ ] |

**Command:** `TARGET_VERSION="X.Y.Z"; grep -rn "$TARGET_VERSION" pyproject.toml extension/package.json docs/openapi.json metrics.json README.md extension/CHANGELOG.md docs/index.html | head -50`

### 2. Metrics Regeneration (NEVER edit metrics.json manually)

```bash
source .venv/bin/activate
python scripts/generate_metrics.py         # Regenerates metrics.json from source
python scripts/validate_readme_metrics.py  # Validates README matches metrics.json
```

Both commands must succeed with zero errors. The metrics script counts:

- `api_endpoints` — decorators in `src/api.py`
- `tests_collected` — `pytest --collect-only`
- `total_rules` — scan rules + gateway rules
- `mcp_tools` — scanner + gateway tools

### 3. OpenAPI Spec Regeneration

```bash
python scripts/export_openapi.py           # Regenerates docs/openapi.json from FastAPI
```

Verify the endpoint count matches `metrics.json`. If it doesn't, one of them is wrong.

### 4. README Number Audit

Every number in README.md must match `metrics.json`:

| README text | metrics.json field |
|---|---|
| `X tests` (header + Development section) | `tests_collected` |
| `X rules` | `total_rules` |
| `X API endpoints` (description + Five Ways In table) | `api_endpoints` |
| `X MCP tools` | `mcp_tools` |

**Command:** `python scripts/validate_readme_metrics.py` — must pass clean.

### 4b. Website & Public Telemetry Consistency

- [ ] `docs/index.html` static counters (rules/layers/tools/endpoints/tests) match `metrics.json`
- [ ] `docs/index.html` telemetry parser fields match `/v1/stats/public` payload schema
- [ ] `/v1/usage` is documented as authenticated user stats, while global counters use `/v1/stats/public`

**Command:** `grep -n "stats/public\|/v1/usage\|API Endpoints\|MCP Tools\|Tests Passing" docs/index.html src/api.py`

### 5. pyproject.toml Description

The `description` field in `pyproject.toml` contains hardcoded numbers.
Verify these match `metrics.json`:

- API endpoints count
- Test count
- Rule count

### 6. CHANGELOG (root + extension)

- [ ] `CHANGELOG.md` — `[Unreleased]` section moved to `[X.Y.Z] - YYYY-MM-DD`
- [ ] `extension/CHANGELOG.md` — same version header, extension-relevant changes
- [ ] Every new feature, endpoint, command, and fix is listed
- [ ] No feature exists in code that isn't in the changelog
- [ ] Previous `[Unreleased]` section is empty or contains only future work

**Cross-check:** Search code for new files since last release:

```bash
git diff --name-only HEAD~1..HEAD -- src/ tests/
```

### 7. Supported Languages Table (README)

If any new language was added, verify the "Supported Languages" table in README matches:

- `src/models/enums.py` `Language` enum
- `extension/src/types.ts` `Language` type
- Extension `enabledLanguages` default in `package.json`

### 8. CLI Commands

If any new CLI subcommand was added, verify it appears in:

- [ ] README.md "CLI Usage" section
- [ ] CHANGELOG.md

**Command:** `grep -c "add_parser" src/cli.py` — count should match documented commands.

### 9. API Endpoints

If any new endpoint was added, verify:

- [ ] Request model in `src/models/requests.py`
- [ ] Response model in `src/models/responses.py`
- [ ] OpenAPI spec regenerated (`python scripts/export_openapi.py`)
- [ ] Smoke test covers the endpoint (`smoke_test.sh`)
- [ ] CHANGELOG documents the endpoint

### 10. Security & Compliance

- [ ] `SECURITY.md` — supported versions table is current
- [ ] `.env.example` — all env vars used in code are documented
- [ ] No hardcoded secrets in committed files

### 11. Tests

```bash
python -m pytest tests/ -q    # All tests must pass (pre-existing failures documented)
```

- [ ] Test count in metrics.json matches `--collect-only` output
- [ ] No new test file is orphaned (all new services have tests)

### 12. Extension Build

```bash
cd extension
npm run bundle                       # esbuild — produces minified single-file output
npx vsce package --no-dependencies   # Must produce .vsix
```

- [ ] `out/extension.js` is minified (single long line, no readable source)
- [ ] No `.ts` source files in the `.vsix` package

### 12b. Chrome Extension Build (if changed in release scope)

```bash
cd chrome-extension
npm install
npm run build || true
```

- [ ] `chrome-extension/manifest.json` version matches release scope
- [ ] store assets/screenshots reflect current product claims
- [ ] packaged artifact (`codetrust-chrome-extension.zip`) regenerated if published

### 13. Smoke Test

```bash
./smoke_test.sh https://api.codetrust.ai
```

All checks must pass. If a new endpoint was added, verify it's included in the smoke test.

---

## IP & Security Gates (MANDATORY — blocks release)

> **These gates were introduced in v2.6.0 after an IP audit revealed that prior
> releases exposed the full source tree via sdist. NEVER skip them.**

Run the automated gate script: `python scripts/release_security_gate.py`

If ANY gate status is FAIL, the release MUST NOT proceed.

### Gate S1: No sdist in build output

```bash
python -m build --wheel
ls dist/*.tar.gz 2>/dev/null && echo "FAIL: sdist found" || echo "PASS"
```

- [ ] `dist/` contains ONLY `.whl` files — no `.tar.gz`
- [ ] `pyproject.toml` → `[tool.hatch.build.targets.sdist]` → `exclude = ["*"]`

### Gate S2: Copyright headers present

```bash
python scripts/release_security_gate.py --check headers
```

- [ ] Every `.py` file under `src/` has `Copyright (c) 20XX Said Borna` header
- [ ] Every `.ts` file under `extension/src/` has copyright header

### Gate S3: Source maps disabled

- [ ] `extension/tsconfig.json` → `"sourceMap": false`
- [ ] No `.map` files in `extension/out/`

### Gate S4: Extension output is minified

- [ ] `extension/out/extension.js` is minified (< 10 source lines)
- [ ] `extension/package.json` → `vscode:prepublish` runs `npm run bundle`

### Gate S5: License validation module present

- [ ] `src/services/license_guard.py` exists and compiles
- [ ] API lifespan calls `validate_license()`
- [ ] `/v1/license/validate` endpoint exists

### Gate S6: CLA in place

- [ ] `CLA.md` exists
- [ ] `CONTRIBUTING.md` references CLA requirement

### Gate S7: No secrets or API keys in source

```bash
grep -rn "sk_live\|sk_test\|AKIA\|ghp_\|ghs_\|password\s*=\s*['\"]" src/ extension/src/ --include="*.py" --include="*.ts" | grep -v "\.example" | grep -v "test_"
```

- [ ] Zero matches (excluding test fixtures and .example files)

---

## Release Execution

After ALL checks AND security gates pass:

1. **Run security gates**: `python scripts/release_security_gate.py`
2. **Bump version** in all files listed in step 1
3. **Move `[Unreleased]`** to `[X.Y.Z] - YYYY-MM-DD` in both CHANGELOGs
4. **Regenerate**: `python scripts/generate_metrics.py && python scripts/export_openapi.py`
5. **Validate**: `python scripts/validate_readme_metrics.py`
6. **Test**: `python -m pytest tests/ -q`
7. **Build wheel** (NO sdist): `python -m build --wheel`
8. **Build extension** (bundled): `cd extension && npm run bundle && npx vsce package --no-dependencies`
9. **Final gate run**: `python scripts/release_security_gate.py` — must pass clean
10. **Commit**: `git add -A && git commit -m "release: vX.Y.Z"`
11. **Tag**: `git tag vX.Y.Z`
12. **Push**: User pushes manually (NEVER automated)
13. **Publish PyPI**: `twine upload dist/codetrust-*.whl` (NEVER upload .tar.gz)
14. **Publish VS Code Marketplace**: `cd extension && npx vsce publish`
15. **Publish Open VSX**: `cd extension && OVSX_PAT=$(grep -o 'OVSX_PAT=[^ ]*' ../.env | cut -d= -f2) && npx ovsx publish codetrust-X.Y.Z.vsix -p "$OVSX_PAT"` (token is in `.env`)
16. **Publish Chrome extension (optional channel)**: upload updated package/listing assets if release includes browser changes

---

## Trust DOD (Release Blockers)

> These checks are mandatory for enterprise trust readiness. If any item fails,
> the release is blocked.

### DOD-T1: New Workspace Works Without Manual Debugging

- [ ] VS Code workspace MCP target (`.vscode/mcp.json`) is injected by default.
- [ ] No manual file editing is required to register Guardian + Gateway in a new workspace.

### DOD-T2: Governance Is Runtime Enforcement (Not Only Instructions)

- [ ] Gateway tool path is registered and callable at runtime.
- [ ] A governance validation path exists and can return ALLOW/WARN/BLOCK outcomes.

### DOD-T3: Public Claims Match Runtime Capability

- [ ] Any claim of GitHub Copilot support is blocked at release time if workspace MCP injection is missing.
- [ ] Marketplace/release metadata must not advertise unsupported runtime behavior.

### DOD-T4: Same Regression Class Cannot Recur Silently

- [ ] Regression tests fail when workspace MCP target coverage is removed.
- [ ] Release checks fail when claim/implementation parity drifts.

### DOD-T5: Predictable and Verifiable Across IDE/Agent Paths

- [ ] MCP injection paths are explicit and deterministic in code.
- [ ] Verification output clearly reports PASS/FAIL by trust criterion.

### DOD-T6: Failures Are Early and Actionable

- [ ] No vague trust fallback messaging in extension runtime paths.
- [ ] User-facing recovery prompts are concrete (for example, re-inject now).

### DOD-T7: Claude Desktop Runtime Safety

- [ ] Claude Desktop MCP smoke test passes for both `codetrust` and `codetrust-gateway` in a clean session.
- [ ] Documentation examples do not default `CODETRUST_WORKSPACE` to Desktop/Documents/Downloads (TCC-protected paths).
- [ ] MCP startup keeps stdout protocol-clean (no non-JSON bootstrap output before initialize response).

### Trust Verification Command (mandatory)

```bash
cd extension
node ./scripts/verify-trust-dod.js
```

The command must report `PASS` for every DOD-T item and exit with code 0.

---

## Post-Release Verification

After push and deploy:

1. **Smoke test** against production: `./smoke_test.sh https://api.codetrust.ai`
2. **PyPI** — verify version appears: `pip install codetrust==X.Y.Z`
3. **PyPI** — verify NO `.tar.gz` on the release page
4. **VS Code Marketplace** — verify extension version
5. **VS Code Marketplace** — download `.vsix`, unzip, verify no `.ts` source files
6. **GitHub Action** — verify tag works: `uses: S-Borna/codetrust@vX.Y.Z`
7. **Website** — verify any embedded version numbers
8. **Public telemetry** — validate `https://api.codetrust.ai/v1/stats/public` fields render correctly on website dashboard

---

## Common Mistakes This Checklist Prevents

| Mistake | Which step catches it |
|---|---|
| metrics.json says 28 endpoints but code has 42 | Step 2 (generate_metrics) |
| README says "1367 tests" but there are 1454 | Step 4 (validate_readme_metrics) |
| New CLI command added but not in README | Step 8 |
| New API endpoint but OpenAPI spec not updated | Step 3 + Step 9 |
| pyproject.toml description has old numbers | Step 5 |
| SECURITY.md says "2.0.x supported" when we're on 2.3.x | Step 10 |
| .env.example missing OIDC variables | Step 10 |
| Extension CHANGELOG missing platform changes | Step 6 |
| smoke_test.sh doesn't test new endpoints | Step 13 |
