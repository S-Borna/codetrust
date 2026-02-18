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

**Command:** `grep -rn "2\.3\." pyproject.toml extension/package.json docs/openapi.json metrics.json README.md | head -20`

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
npm run compile                  # Must succeed with zero errors
npx vsce package --no-dependencies  # Must produce .vsix
```

### 13. Smoke Test

```bash
./smoke_test.sh https://api.codetrust.ai
```

All checks must pass. If a new endpoint was added, verify it's included in the smoke test.

---

## Release Execution

After all checks pass:

1. **Bump version** in all files listed in step 1
2. **Move `[Unreleased]`** to `[X.Y.Z] - YYYY-MM-DD` in both CHANGELOGs
3. **Regenerate**: `python scripts/generate_metrics.py && python scripts/export_openapi.py`
4. **Validate**: `python scripts/validate_readme_metrics.py`
5. **Test**: `python -m pytest tests/ -q`
6. **Build extension**: `cd extension && npm run compile && npx vsce package --no-dependencies`
7. **Commit**: `git add -A && git commit -m "release: vX.Y.Z"`
8. **Tag**: `git tag vX.Y.Z`
9. **Push**: User pushes manually (NEVER automated)

---

## Post-Release Verification

After push and deploy:

1. **Smoke test** against production: `./smoke_test.sh https://api.codetrust.ai`
2. **PyPI** — verify version appears: `pip install codetrust==X.Y.Z`
3. **VS Code Marketplace** — verify extension version
4. **GitHub Action** — verify tag works: `uses: S-Borna/codetrust@vX.Y.Z`
5. **Website** — verify any embedded version numbers

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
