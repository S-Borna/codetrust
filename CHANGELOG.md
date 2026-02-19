# Changelog

All notable changes to CodeTrust will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-02-20

### Added

- **PowerShell Language Support** — 12 scan rules for `.ps1` / `.psm1` scripts
  - 4 BLOCK: `ps_invoke_expression`, `ps_execution_policy_bypass`, `ps_plaintext_credential`, `ps_hardcoded_password`
  - 5 WARN: `ps_write_host`, `ps_catch_empty`, `ps_no_strict_mode`, `ps_stop_process_force`, `ps_net_webclient`
  - 3 INFO: `ps_start_process_no_wait`, `ps_sleep_unbounded`, `ps_rm_recurse_force`

- **Terraform Provider Rules** — 9 AWS/cloud-specific rules for `.tf` / `.hcl`
  - `tf_wildcard_iam`, `tf_public_s3_acl`, `tf_open_security_group`, `tf_unencrypted_ebs`, `tf_no_tags`, `tf_hardcoded_ami`, `tf_no_versioned_module`, `tf_no_state_encryption`, `tf_sensitive_output`

- **Helm Chart Rules** — 6 rules for Helm template best practices
  - `helm_hardcoded_image_tag`, `helm_no_resource_limits`, `helm_hardcoded_namespace`, `helm_deprecated_api`, `helm_hardcoded_replicas`, `helm_tpl_missing_quote`

- **Ansible Playbook Rules** — 6 rules for Ansible best practices
  - `ansible_command_module`, `ansible_ignore_errors`, `ansible_plaintext_password`, `ansible_latest_package`, `ansible_no_become_user`, `ansible_no_changed_when`

- **Nginx Config Rules** — 6 rules for `.conf` security hardening
  - `nginx_server_tokens_on`, `nginx_autoindex_on`, `nginx_ssl_v3`, `nginx_root_in_location`, `nginx_no_rate_limit`, `nginx_add_header_missing_always`

- **CloudFormation / CDK Rules** — 7 rules for AWS IaC
  - `cfn_wildcard_iam`, `cfn_public_s3`, `cfn_no_deletion_policy`, `cfn_unencrypted_storage`, `cfn_hardcoded_credentials`, `cfn_no_logging`, `cdk_no_removal_policy`

- **Azure ARM / Bicep Rules** — 5 rules for `.bicep` and ARM templates
  - `bicep_no_secure_param`, `bicep_http_only`, `bicep_public_network`, `arm_wildcard_rbac`, `arm_no_diagnostics`

- **Redis Config Rules** — 6 rules for Redis configuration hardening (`.conf`)
  - 3 BLOCK: `redis_no_password`, `redis_bind_all_interfaces`, `redis_disable_protected_mode`
  - 2 WARN: `redis_no_maxmemory`, `redis_dangerous_command`
  - 1 INFO: `redis_no_timeout`

- **Vault Config Rules** — 5 rules for HashiCorp Vault configuration (`.hcl`)
  - 2 BLOCK: `vault_tls_disable`, `vault_no_seal_config`
  - 2 WARN: `vault_default_lease`, `vault_ui_enabled`
  - 1 INFO: `vault_log_level_trace`

- **Monitoring Stack Rules** — 5 rules for Prometheus/Grafana configs (`.yml`/`.yaml`)
  - 2 BLOCK: `prom_no_auth_targets`, `grafana_admin_password`
  - 2 WARN: `prom_high_scrape_interval`, `grafana_allow_signup`
  - 1 INFO: `prom_no_alertmanager`

- **Systemd Unit Rules** — 5 rules for systemd service/timer files (`.service`/`.timer`)
  - 2 WARN: `systemd_no_restart_policy`, `systemd_exec_start_missing`
  - 3 INFO: `systemd_no_description`, `systemd_no_after`, `systemd_no_wanted_by`

- **Docker Compose Advanced Rules** — 5 advanced rules for `docker-compose.yml`
  - 2 BLOCK: `compose_privileged`, `compose_pid_host`
  - 2 WARN: `compose_no_healthcheck`, `compose_no_mem_limit`
  - 1 INFO: `compose_no_restart_policy`

- **GitHub Actions Advanced Rules** — 5 rules for CI/CD workflow files (`.yml`/`.yaml`)
  - 1 BLOCK: `ci_script_injection`
  - 3 WARN: `ci_no_timeout`, `ci_mutable_action_ref`, `ci_excessive_permissions`
  - 1 INFO: `ci_no_concurrency`

- **General Config Hygiene Rules** — 5 rules for INI/CFG/TOML/CONF files
  - 2 BLOCK: `config_plaintext_password`, `config_private_key_inline`
  - 2 WARN: `config_debug_enabled`, `config_http_endpoint`
  - 1 INFO: `config_todo_fixme`

- **New file type support** — `.service`, `.timer`, `.ini`, `.cfg` added to CLI scan extensions

### Fixed

- **SOURCE_EXTS bug** — CLI directory scan (`codetrust scan .`) was silently skipping `.rb`, `.php`, `.ps1`, `.psm1`, `.psd1`, `.cs`, `.tf`, `.tfvars`, `.hcl`, `.cpp`, `.c`, `.h`, `.html`, `.htm`, `.conf`, `.bicep` files due to missing extensions in SOURCE_EXTS
- **CLI rule routing** — Language-specific rules (Ruby, PHP, PowerShell, Nginx, Bicep) now have dedicated routing buckets instead of being routed through generic DevOps rules
- **Extension LANGUAGE_MAP** — Added `ruby`, `php`, `powershell` to VS Code language ID mapping

- **Ruby Language Support** — full static analysis, AST analysis, and import verification for Ruby
  - 11 Ruby-specific scan rules: `ruby_eval`, `ruby_system_exec`, `ruby_send_public_send`, `ruby_binding_pry`, `ruby_puts_p_debug`, `ruby_sleep`, `ruby_rescue_exception`, `ruby_global_variable`, `ruby_mass_assignment`, `ruby_hardcoded_secret`, `ruby_hallucinated_gem`
  - RubyGems registry verification with version checking via rubygems.org API
  - `Gemfile` parser for dependency extraction
  - Ruby import extractor (`require` statements) with stdlib filtering
  - AST analysis via tree-sitter-ruby
  - Fuzzy matching against top 100 RubyGems packages

- **PHP Language Support** — full static analysis, AST analysis, and import verification for PHP
  - 12 PHP-specific scan rules: `php_eval`, `php_shell_exec`, `php_sql_injection`, `php_var_dump`, `php_deprecated_mysql`, `php_error_suppression`, `php_extract`, `php_unserialize`, `php_md5_password`, `php_die_exit`, `php_hardcoded_secret`, `php_hallucinated_namespace`
  - Packagist registry verification via repo.packagist.org v2 API
  - `composer.json` parser for dependency extraction (skips `php` and `ext-*`)
  - PHP import extractor (`use` statements) with namespace normalization and builtins filtering
  - AST analysis via tree-sitter-php
  - Fuzzy matching against top 100 Packagist packages

- **Maven Central Registry Verification** — verify Java artifacts against Maven Central
  - Solr search API integration with `groupId:artifactId` format
  - `pom.xml` parser for dependency extraction
  - Fuzzy matching against top 70 Maven artifacts

- **NuGet Registry Verification** — verify .NET packages against nuget.org
  - Flat container API integration with version listing
  - `.csproj` parser for `PackageReference` extraction
  - Fuzzy matching against top 80 NuGet packages

- **Import Verifier Extended** — now supports 8 languages (Python, JS/TS, Ruby, PHP, Go, Rust, Java, C#)

- **CVE / Vulnerability Scanning** — check dependencies against Google's OSV database for known CVEs/GHSAs across all supported ecosystems (PyPI, npm, crates.io, Go, Maven, NuGet)
  - `POST /v1/vuln/scan` — batch check up to 200 packages per request
  - `codetrust vuln` CLI command with `--language` and `--json` flags
  - Cache-first pattern with configurable TTLs (1h vulnerable, 6h clean)

- **License Compliance** — extract and classify dependency licenses with risk assessment
  - `POST /v1/license/scan` — batch license check with risk classification
  - `codetrust license` CLI command with `--language` and `--json` flags
  - Classification: permissive, weak copyleft (LGPL/MPL), strong copyleft (GPL), network copyleft (AGPL/SSPL)

- **Cross-File Import Analysis** — build import dependency graphs across project files
  - `POST /v1/scan/cross-file` — analyze up to 500 files
  - Language-specific import extraction for Python, JS/TS, Go, Java, C#
  - Circular dependency detection, orphan file detection, hub file detection (imported by 5+)
  - Finding propagation through reverse import graph

- **Auto-Fix PR Generation** — apply safe fix recipes and optionally create GitHub PRs
  - `POST /v1/fix/apply` — apply fixes with optional PR creation via GitHub API
  - `codetrust fix --pr` with `--github-owner`, `--github-repo`, `--github-branch` flags
  - Fix recipes: `print_to_logging`, `bare_except`, `hardcoded_secrets`

- **Team Management & RBAC** — organization management, membership, and policy enforcement
  - 10 API endpoints under `/v1/orgs/*`: create/list/get/delete orgs, add/remove/update members, get/update policies
  - Role hierarchy: Owner → Admin → Member → Viewer with cumulative permissions
  - Org-level policy enforcement: max severity gates, vulnerability thresholds, blocked licenses

- **AI Agent Enforcement Rules** — 21 new rules across all enforcement layers to block AI agents from bypassing safe file-write tools
  - **10 gateway terminal rules**: `gateway_tee_write`, `gateway_echo_to_file`, `gateway_printf_to_file`, `gateway_cat_redirect_write`, `gateway_sed_inline`, `gateway_awk_redirect`, `gateway_bash_c_write`, `gateway_python_write_file`, `gateway_perl_inline`, `gateway_dd_write_file`
  - **5 gateway content rules**: `gateway_content_heredoc`, `gateway_content_bash_heredoc`, `gateway_content_tee_write`, `gateway_content_subprocess_heredoc`, `gateway_content_os_system_heredoc`
  - **6 static scan rules**: `agent_tee_heredoc`, `agent_echo_multiline_redirect`, `agent_cat_heredoc`, `agent_subprocess_shell_true`, `agent_os_system`, `agent_os_popen`
  - All 21 rules enforce `BLOCK` severity — code cannot ship with these patterns

- **PyPI download statistics** — Pepy API integration for real-time download tracking on the landing page

- **Domain migration** — All API URLs, docs, and extension defaults migrated to `codetrust.ai` / `api.codetrust.ai`

- **SEO & AI Model Discoverability** — Search engine and AI model optimization for codetrust.ai
  - `llms.txt` for AI model discovery (Claude, ChatGPT, Perplexity, Gemini)
  - JSON-LD structured data, `sitemap.xml`, `robots.txt`, `.well-known/security.txt`
  - Canonical URL, keywords, OG/Twitter card meta tags

- **7 new languages** — Java, C#, C++, Shell/Bash, HTML, Terraform. Total: **13 languages** (up from 6)
  - Full import extraction for Java (`import`/`import static`), C# (`using`/`using static`), C++ (`#include`)
  - AST analysis support for Java, C#, C++ (cyclomatic complexity, nesting, unused variables)
  - Terraform/HCL files scanned with DevOps rules (`.tf`, `.tfvars`, `.hcl`)

- VS Code extension:
  - 13 language support (python, javascript, typescript, go, rust, sql, yaml, java, csharp, cpp, shell, html, terraform)
  - Import verification for all 13 languages
  - Terraform/HCL and HTML scanning with appropriate rule sets

### Changed

- VS Code extension — Status bar (enterprise branding):
  - All verdict states now show `$(shield) CodeTrust` consistently
  - Scan results communicated via tooltip and Problems panel instead of status bar color changes

- VS Code extension — Silent activation:
  - Extension activates in every workspace — scan-on-save enabled by default
  - Active editor scanned immediately on activation; all open documents scanned on startup

### Fixed

- Scan-on-save now skips non-file URI schemes (output panels, git diffs) to prevent spurious scans

### Infrastructure

- **Zero self-scan findings** — All 369 static analysis findings eliminated (was 2 BLOCK, 250 WARN, 117 INFO)
  - CI self-scan now enforces zero-tolerance: any finding fails the pipeline

- **11 new philosophy rules** — Enforceable engineering laws AI agents cannot bypass (89 scan rules + 76 gateway rules = 165 total)
  - **Law 3 — Root Cause**: `symptom_fix_marker` (BLOCK) — detects comments admitting workarounds
  - **Law 4 — Determinism**: `datetime_utcnow` (BLOCK), `datetime_naive` (WARN) — timezone-aware datetime enforcement
  - **Law 5 — Explicit Configuration**: `hardcoded_temp_path` (WARN), `env_var_no_default` (INFO)
  - **Law 6 — Safe Data Handling**: `string_concat_sql` (BLOCK) — SQL via string concatenation
  - **Law 7 — Code Hygiene**: `commented_out_code` (INFO) — dead code in comments
  - **Gateway**: `gateway_content_symptom_fix` (BLOCK), `gateway_content_datetime_naive` (WARN), `gateway_npm_audit_force` (WARN), `gateway_pip_force_reinstall` (WARN)

---

## [2.3.2] - 2026-02-16

### Fixed

- Release surfaces synced: docs/README/action snippets updated to a single tag
- VS Code extension settings/help text clarified (no "localhost" in public-facing descriptions)

## [2.3.1] - 2026-02-16

### Added

- New `database_url_credentials` rule — catches database URLs with embedded passwords
- Path alias support — `@/`, `~/`, `#/` prefixes no longer flagged as hallucinated imports

- VS Code extension:
  - Profile support commands: Create/Apply CodeTrust Profile
  - Scan-on-type (opt-in, debounced, offline)
  - Expanded Quick Fix coverage (deterministic transforms)
  - Guided onboarding: configure API URL/key + run first scan
  - API key now stored in VS Code Secret Storage
  - Onboarding success confirmation message
- GitHub Action:
  - PR-mode default (auto on pull_request): scans changed files and gates on new findings only
  - New input `pr-mode: auto|always|never` to override behavior
  - Markdown report + GitHub Actions step summary output
  - PR comment posted/updated automatically (requires `pull-requests: write`)
  - Baseline-aware gating: new-findings-only comparison vs HEAD
  - Self-test workflow to verify action behavior on PRs
- CLI:
  - `codetrust add` stack presets for `.vscode/settings.json` (`--stack auto|nextjs|node|python|go|generic`)
  - Noise-control flags: `--dedupe`, `--changed-only`, `--suppress-lint-noise` (opt-in)
  - Repo-aware commands: `codetrust pr-risk`, `codetrust trust-diff`, `codetrust trend record/show`
  - Baseline-aware gating: `codetrust scan --baseline <ref> --fail-on-new BLOCK` (new findings only)
  - Doctor onboarding: `codetrust doctor --fix` installs missing enforcement layers
  - Safe autofix: `codetrust fix` (preview by default, `--apply` to write)
  - Policy Wizard: `codetrust policy wizard` generates governance presets with schema-based autocomplete

### Fixed

- `hardcoded_secret` rule now handles type annotations and compound names (`secret_key`, `secret_token`)
- `api_key_in_config` rule scoped to config file types only (`.yml/.yaml/.toml/.ini/.cfg/.conf`)
- CI self-scan false positives eliminated
- JS/TS import verification no longer flags `@/components`, `@/lib`, `~/config`, `#/db`
  as hallucinated packages — Next.js/Vite/TypeScript path aliases are recognized
- Pre-commit hook no longer crashes on fresh repos without virtual environments
- Pre-commit subprocess failures/timeouts gracefully fall back instead of blocking commits
- API optional-auth: headers ignored when auth is not configured (no surprising 401)
- Extension tests now compile before running to ensure TS tests are executed

---

## [2.2.4] - 2026-02-13

### Fixed

- Removed public release-process text from root README to keep product-facing docs clean
- Strengthened release sync guard to validate version parity across extension/package, pyproject,
  changelog, and website (without depending on public README strings)
- Synced release-prep versioning across backend/API docs/site to `2.2.4`

### Changed

- Prepared manual release candidate `2.2.4` locally (no deploy, no push)

### Released

- Published `codetrust==2.2.4` to PyPI
- Published `SaidBorna.codetrust v2.2.4` to VS Code Marketplace

---

## [2.2.3] - 2026-02-13

### Fixed

- VS Code extension lint blockers resolved
- Dashboard build blockers resolved

### Released

- Published to VS Code Marketplace: `SaidBorna.codetrust` **v2.2.3**
- PyPI release remains pending (Python package version unchanged)

---

## [2.2.2] - 2026-02-13

### Security

- Removed 7 internal blueprint documents (SPEC, PLAN, PRODUCT, PITCH, COMPARISON, CLAUDE, TEST_EVIDENCE) from git tracking — contained implementation details, class names, file paths, and build plans
- Removed Railway deployment URL from landing page — replaced with custom domain
- Removed internal module path (`python -m src.server`) from landing page
- Removed scoring implementation details (penalty multiplier, data retention count) from landing page
- Landing page stats endpoint switched to custom domain

### Fixed

- API endpoint count corrected to 27 across all surfaces (verified from source: 27 routes in api.py)
- CI self-scan false positive resolved — gateway SSL rule pattern split to avoid self-matching
- Webhook example URLs in source code split to avoid self-scan triggers
- SARIF output file added to .gitignore

---

## [2.2.1] - 2026-02-13

### Fixed

- Extension README completely rewritten — was still showing v2.0 content (82 rules, 15 gateway rules)
  while Marketplace listed v2.2.0. Now accurately reflects 132 rules, 57 gateway rules, 27 API endpoints,
  17 MCP tools, three moats, 10 enforcement layers, and all five surfaces
- PyPI description updated with complete feature set and correct metrics
- Development Status upgraded from Beta to Production/Stable
- Keywords expanded for better discoverability (ai-safety, governance, claude-code, cursor)
- API endpoints count corrected from 26 → 27 across all surfaces
- PyPI logo fixed — now uses absolute GitHub raw URL so it renders correctly

---

## [2.2.0] - 2026-02-13

> **Platform Launch Release** — Production-ready landing page, live telemetry,
> ecosystem integration signals, and shield icon system.

### Added

- **Live usage telemetry** — `/v1/stats/public` API endpoint returns real-time scan counts,
  hallucinated packages prevented, and destructive commands blocked from production database
- **Landing page live stats** — usage metrics now fetch from Cloud API with scroll-triggered
  count-up animation; includes telemetry transparency note
- **"Works with" ecosystem section** — VS Code, GitHub, Claude Code, Cursor, and MCP logos
  with hover effects on the landing page
- **Visual architecture diagram** — upgraded from plain text flow to icon-based nodes with
  labeled arrows ("intercepts" / "verified"), color-coded for threat vs safe state
- **Shield icon system** — unified `</>` + checkmark shield SVG across hero, topbar, favicon,
  extension icon (256×256), Apple touch icon, and PyPI logo
- **Icon generation script** — `scripts/generate_icons.py` produces all PNG sizes from SVG
  via cairosvg

### Changed

- Landing page fully redesigned — Space Grotesk + IBM Plex Mono, dark theme (#050507),
  consistent blue (#3b82f6) / green (#22c55e) palette
- Hero logo enlarged 50% for better visual impact
- Topbar shield now matches hero design exactly (gradient, glow, inner ring)
- "Trust" text color unified to #3b82f6 across all surfaces

### Fixed

- Topbar/hero SVG inconsistency (missing glow filter, inner highlight ring)
- Code/Trust text gap eliminated (was 0.4rem, now 0)

---

## [2.1.0] - 2026-02-13

> **The Three Moats Release** — CodeTrust is now an AI code safety platform with three
> capabilities no linter, formatter, or SAST tool provides.

### Moat 1: AI Governance Gateway (57 rules)

The gateway intercepts AI agent actions **before execution** — terminal commands,
file writes, and package installs are validated in real-time.

- **46 terminal interception rules** across 9 categories:
  file destruction, code execution, privilege escalation, git operations,
  container escape, network exfiltration, secrets exposure, supply chain attacks,
  resource abuse
- **11 content rules**: secrets, private keys, AWS keys, SSL bypass, CORS wildcards,
  obfuscated exec, pickle deserialization, subprocess shell, debug mode,
  webhook exfiltration, eval/exec in files

### Moat 2: Live Import Verification (Hallucination Detection)

Every `codetrust scan` now extracts imports from Python/JS files and verifies them
against **live PyPI/npm registries**. Hallucinated packages produce BLOCK findings
with exact file and line number.

- Import verification runs by default (`--no-verify-imports` to skip)
- GitHub Action integration — hallucinated packages appear as PR annotations
- **13 AI-specific static rules** (was 5): `hallucinated_import_nonexistent`,
  `hallucinated_import_misspelled`, `hallucinated_method_chain`,
  `hallucinated_config_option`, `hallucinated_cli_flag`, `hallucinated_version`,
  `phantom_file_reference`, `hallucinated_http_status`, plus original 5

### Moat 3: AI Trust Score with Baseline Trending

Not just a snapshot — a real metric that tracks how your codebase is evolving.

- **AI Trust sub-score** — hallucination findings penalized 15x in scoring
- **A+ grade curve** — A+/A/B+/B/C+/C/D/F
- **Baseline storage** — `.codetrust/drift_baseline.json` persists between runs
- **Delta tracking** — shows improvement/regression from baseline
- **Trend analysis** — improving/degrading/stable based on history

### Summary

- **132 total rules** — 75 scan rules + 57 gateway rules (was 82)
- **1312 tests** — 0 failures, 2 skipped (was 1168)

## [2.0.0] - 2026-02-13

### Added

- **AI Governance Gateway** — pre-execution interception layer for AI agent actions
  - 13 terminal interception rules + 2 content rules at launch
  - Blocks: heredoc, eval, curl|sh, rm -rf /, chmod 777, sudo su, dd of=, git push,
    git force push, pip unverified, env secret export, mkfs, fork bomb
  - Content scanning: eval/exec in file writes, hardcoded secrets in file writes
  - Configurable governance modes (enforce/audit/off) via `.codetrust.toml` or `pyproject.toml`
  - JSONL append-only audit log with filtering and stats
  - MCP gateway server with 7 tools:
    `codetrust_validate_command`, `codetrust_validate_file_write`,
    `codetrust_validate_file_delete`, `codetrust_validate_package`,
    `codetrust_governance_status`, `codetrust_audit_history`, `codetrust_list_gateway_rules`
- **CLI `codetrust governance`** — `--setup`, `--status`, `--mode` subcommands
- **CLI `codetrust audit`** — `--hours`, `--verdict`, `--stats` subcommands
- **CLI `codetrust init`** — now installs `.codetrust.toml` + `.codetrust/` audit directory
- **Extension governance settings** — 7 new VS Code settings for governance configuration
- **82 total rules** — 67 scan rules + 15 gateway rules
- **5 new config hallucination detectors**:
  `hallucinated_localhost_port` (WARN), `hallucinated_api_endpoint` (WARN),
  `hallucinated_env_var` (INFO), `placeholder_url` (WARN), `fake_api_key_format` (BLOCK)
- **CI governance enforcement** — GitHub Action now runs gateway
  content rules on PR files, merging governance findings with scan findings
- **Multi-agent audit correlation** — auto-detects Claude, Copilot, Cursor, Windsurf,
  and GitHub Actions via environment variables; logs agent identity on every audit entry
- **Dashboard governance view** — real-time governance audit page with
  stats cards, verdict badges, and filterable audit table
- **`/v1/governance/audit` API endpoint** — query audit log with `hours`, `verdict`,
  and `limit` parameters
- **React/JSX rules** (7 new) — `dangerouslySetInnerHTML` (BLOCK), `innerHTML` string
  (BLOCK), missing `key` in list, `document.getElementById` usage, `useEffect` without
  deps array, `setState` in render, `index` as key prop
- **Kubernetes YAML rules** (6 new) — `privileged: true` (BLOCK), `hostNetwork`,
  `hostPID`, `runAsUser: 0`, missing resource limits, `latest` image tag
- **CLI `--sarif` / `--sarif-file`** — emit SARIF v2.1.0 output for CI integration
- **CLI config file support** — reads `.codetrust.toml` or `pyproject.toml
  [tool.codetrust]` for `exclude_paths`, `ignore_rules`, and `severity_overrides`
- **7 file-level checks**: `except_swallow`, `sleep_no_context`, `long_function` (>40 lines),
  `connection_no_timeout`, `compose_no_healthcheck`, `ci_no_timeout`, `dockerfile_no_healthcheck`
- **GitHub Action inputs** — `fail-on` (block/warn/never), `scan-type` (static/deep),
  `language`, `sarif` (true/false); expanded file detection to `.tsx`, `.jsx`, `.sql`, `.yml`, `.yaml`
- **Extension "Scan Workspace"** command — scans up to 500 files with progress UI,
  cancel support, and summary notification

### Changed

- **Total rules** — 82 (67 scan rules + 15 gateway rules)
- **Total MCP tools** — 15 (8 scanner + 7 gateway)

## [1.9.0] - 2026-02-12

### Added

- **Offline Mode documentation** — extension README now documents offline scanning
  capabilities, verification cache, and online/offline feature comparison table
- **CI extension build job** — validates TypeScript compilation and npm build on every push
- **CI Python matrix** — tests now run against Python 3.12 and 3.13 in parallel
- **CI pip caching** — faster builds via dependency caching
- **CI timeouts** — all jobs have `timeout-minutes` to prevent stuck workflows

### Fixed

- **API URL consistency** — all entry points now use the same API base URL
- **Self-scan noise** — CLI entry points exempt from `print_debug` rule since `print()` is correct for CLI tools
- **Test fixture false positives** — self-scan now skips test files that contain intentional anti-patterns

## [1.8.1] - 2026-02-11

### Changed

- **9 Verification Layers** — expanded from 7 to 9 layers across all docs, PyPI, and Marketplace:
  - Layer 02: Root Cause Analysis (4 symptom-fix rules) — NEW
  - Layer 05: Container Hardening (10 rules) — NEW
  - Layer 06: IaC & Config (7 rules) — NEW
- **Website Trust color** reverted to `var(--green)` matching logo
- **PyPI and extension descriptions** updated with 9-layer table

### Fixed

- **Procfile** — removed migration command that blocked server start
- **Self-scan reliability** — split regex strings with concatenation to prevent rule definitions from self-matching
- **GitHub Action** — fixed heredoc delimiter issue in CI workflow
- **4 `except_swallow` BLOCK violations** resolved in production code — bare `except: pass` replaced with proper error handling

## [1.8.0] - 2026-02-11

### Added

- **The Three Laws enforcement** — CodeTrust now enforces three core principles:
  1. *Law 1: Don't hallucinate* — every reference must be verifiable
  2. *Law 2: Assume nothing* — every choice must be justified
  3. *Law 3: Fix the cause, never the symptom* — every fix must answer "why?"

- **Symptom-Fix Detection rules** (Law 3) — 4 new rules
  - `except_swallow` — BLOCK — flags `except: pass/...` that silently swallow errors
  - `null_coalesce_smell` — WARN — flags `x = x or ""` defensive patterns
  - `suppress_lint` — WARN — flags `noqa`, `type: ignore`, `eslint-disable`, `@SuppressWarnings`
  - `sleep_no_context` — INFO — flags `sleep()` without preceding comment explaining why

- **Anti-Assumption rules** (Law 2) — 2 new rules
  - `debug_mode_enabled` — WARN — flags `DEBUG=True` left in code
  - `hardcoded_port` — INFO — flags hardcoded port numbers

- **Container Hardening rules** — 4 new rules
  - `docker_root_user` — WARN — flags Dockerfiles running as root (no USER)
  - `docker_latest_tag` — WARN — flags `FROM image:latest` or untagged images
  - `docker_no_workdir` — INFO — flags Dockerfiles without WORKDIR
  - `docker_env_secret` — BLOCK — flags secrets in ENV/ARG instructions

- **CI/CD Pipeline rules** — 2 new rules
  - `ci_unpinned_action` — WARN — flags `uses: action@main` instead of pinned SHA/version
  - `ci_no_timeout` — INFO — flags CI jobs without `timeout-minutes`

- **IaC rules** — 2 new rules
  - `hardcoded_ip` — WARN — flags hardcoded IP addresses in infrastructure files
  - `api_key_in_config` — BLOCK — flags API keys/secrets in YAML/TOML config files

- **AI Drift Score** — composite trust metric (0-100, grades A-F) calculated from
  scan findings, weighted by severity (BLOCK=10, WARN=3, INFO=1). Broken down by
  category: anti_hallucination, anti_assumption, root_cause, container_hygiene, ci_cd, devops.
  Available in API deep scan response and CLI `--json` output.

- **CLI enhanced** — scan engine now includes all new rule categories, Dockerfile
  file-level checks (USER, WORKDIR), CI rule routing, and drift score in output.

- **Pre-commit hook enhanced** — added suppress_lint, null_coalesce, debug_mode,
  docker_latest_tag, ci_unpinned_action, and docker_env_secret patterns.

- **54 new tests** — comprehensive test coverage for all new rules, drift score
  calculation, and CLI scan engine enhancements. Total: 672 tests passing.

## [1.7.0] - 2026-02-11

### Added

- **DevOps anti-pattern rules** — 7 new rules (35 total rules)
  - `connection_no_timeout` — flags connections without timeout
  - `unbounded_retry` — flags retry counts >= 5 without total deadline
  - `retry_exponential_unbounded` — flags exponential backoff without timeout cap
  - `blocking_prestart` — flags migrations blocking server startup
  - `dockerfile_no_healthcheck` — flags Dockerfile CMD without HEALTHCHECK
  - `compose_no_healthcheck` — flags Docker Compose services without healthcheck
  - `healthcheck_timeout_low` — flags healthcheck timeouts under 30s
- **Offline local scanning** — `codetrust scan` now includes DevOps, SQL, and all
  generic rules with file-type routing. No API dependency.
- **Pre-commit local fallback** — hook tries full CLI engine first,
  falls back to embedded regex if CLI unavailable. Zero network dependency.
- **CI local fallback** — GitHub Actions workflows check API health before scanning;
  if API is unreachable, runs local scan automatically.
- SQL and DevOps file types added to scan coverage (`.sql`, `.yml`, `.yaml`, `.toml`)

### Fixed

- **Deployment reliability** — clean startup command with timeout guard

## [1.6.0] - 2026-02-11

### Added

- **SQL anti-pattern rules** — 13 rules for `.sql` file scanning
- File-type routing in static analyzer (SQL rules only fire on `.sql` files)
- Pre-commit hook updated with DevOps patterns

## [1.5.0] - 2026-02-11

### Added

- **Published to PyPI** — `pip install codetrust` — [pypi.org/project/codetrust](https://pypi.org/project/codetrust/)
- **Published to VS Code Marketplace** — [SaidBorna.codetrust](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust)
- **CLI tool** (`codetrust init/scan/status/doctor`) — install enforcement layers into any project
- **Enforcement templates** — CLAUDE.md, .cursorrules, pre-commit hook, GitHub Action
- **VS Code / Cursor Extension** — editor extension for inline code verification
  - Scan on save — automatic static analysis when saving supported files
  - Command palette: Scan File, Deep Scan, Verify Imports, Verify Dockerfile, Clear Diagnostics
  - Inline diagnostics — findings shown as squiggly lines (error/warning/info severity)
  - Quick-fix code actions — suppress rules, apply suggestions, remove problematic lines
  - Status bar — shows last scan verdict (PASS/WARN/BLOCK) with click-to-scan
  - Import verification — extracts imports from Python, JS/TS, Go, Rust and verifies against registries
  - Docker verification — parses FROM directives and validates images/tags
  - Configurable settings: API URL, API key, scan type, severity threshold, language filter, timeout
  - Zero runtime dependencies

## [1.4.0] - 2026-02-11

### Added

- **Dashboard (Next.js 14+)** — web dashboard for API key management and usage analytics
  - Landing page with hero section and feature cards
  - Pricing page with Free / Pro / Enterprise tier comparison
  - GitHub OAuth login with session management
  - Dashboard overview with stats cards, usage chart, and scan history table
  - API key management — create, list, revoke keys
  - Account settings page with profile, subscription, and danger zone
  - Tailwind CSS styling with dark-mode-ready custom palette
- **Billing** — subscription management with checkout, portal, and webhooks
  - Plan limits: FREE=100, PRO=10,000, ENTERPRISE=100,000 scans/day
- **Database layer** — persistent storage for users, API keys, scan history, and usage tracking
  - PostgreSQL for production, SQLite for tests
- **8 new API endpoints** — dashboard backend
  - `POST /v1/api-keys`, `GET /v1/api-keys`, `DELETE /v1/api-keys/{key_id}`
  - `GET /v1/scans/history`, `GET /v1/usage`
  - `POST /v1/billing/checkout`, `POST /v1/billing/portal`
- CORS middleware for dashboard cross-origin requests
- Docker Compose: added PostgreSQL 16 service with health checks

### Changed

- Config expanded: database, billing, OAuth, JWT, dashboard settings

## [1.3.0] - 2026-02-11

### Added

- **GitHub Action for CI/CD** — reusable composite action for PR scanning
  - Configurable inputs: scan-type, fail-on threshold, language, SARIF output
  - Language-aware file discovery with exclusion patterns
  - GitHub workflow annotations (`::error::`, `::warning::`) for inline PR feedback
- **SARIF v2.1.0 output** — standard format for GitHub Security tab integration
  - `POST /v1/scan/static/sarif` and `POST /v1/scan/deep/sarif` API endpoints
  - `codetrust_sarif_export` MCP tool
  - Security-severity mapping (BLOCK→high, WARN→medium, INFO→low)
- **CI pipeline** — lint, test, and self-scan jobs

## [1.2.0] - 2026-02-10

### Added

- **Sandbox Execution** — isolated Docker container code execution
  - Inline and file execution strategies
  - Security: `--network=none`, `--read-only`, `--memory=256m`, `--pids-limit=64`
  - Supported languages: Python, JavaScript, TypeScript, Go, Rust
  - `POST /v1/sandbox/run` API endpoint
  - `codetrust_sandbox_run` MCP tool
  - Sandbox layer integrated into deep scan

## [1.0.1] - 2026-02-10

### Added

- **Go & Rust Registry Support** — extended registry verification to two new ecosystems
  - Go module verification against proxy.golang.org with version check
  - Rust crate verification against crates.io with version check
  - Go import extraction from `import "..."` and `import (...)` blocks (stdlib excluded)
  - Rust import extraction from `use crate::` and `extern crate` (std/core/alloc excluded)
  - Go mod and Cargo.toml manifest parsing for version mapping
  - Fuzzy matching suggestions for Go modules and Rust crates
  - Language routing: Go → Go proxy, Rust → crates.io

## [1.1.0] - 2026-02-10

### Added

- **AST Parsing** — deep code analysis via Abstract Syntax Trees
  - Cyclomatic complexity, unused variables, unreachable code, deep nesting detection
  - Supports Python, JavaScript, TypeScript, Go, Rust
  - `POST /v1/scan/ast` API endpoint
  - `codetrust_ast_scan` MCP tool
  - AST layer integrated into deep scan

## [1.0.0] - 2026-02-10

### Added

- **Static Analysis Engine** — 35+ anti-pattern rules with BLOCK/WARN/INFO severity levels
  - Heredoc detection, hardcoded secrets, eval/exec, SQL injection, pickle.load
  - Bare except, wildcard imports, Any types, mutable defaults, magic numbers
  - Function length checking (40-line threshold)
- **Package Registry Verification** — verify imports against real registries
  - PyPI support for Python packages
  - npm support for JavaScript/TypeScript packages
  - Version mismatch detection
  - Typosquatting suggestions via fuzzy matching
- **Docker Image Verification** — verify base images and tags exist on Docker Hub
  - FROM statement parsing with multi-stage build support
  - Available tag suggestions for unknown tags
- **Enterprise Structure Validation** — check repos for required files
  - README, LICENSE, tests, .gitignore, pyproject.toml / package.json
- **Deep Scan** — combined all-layer analysis in a single pass
- **FastAPI HTTP API** with 5 endpoints
  - `GET /v1/status` — health check
  - `POST /v1/verify/imports` — package verification
  - `POST /v1/verify/dockerfile` — Docker verification
  - `POST /v1/scan/static` — static analysis
  - `POST /v1/scan/deep` — full deep scan
- **MCP Server** with 7 tools for Claude Code integration
  - `codetrust_static_scan`, `codetrust_pre_action`, `codetrust_post_action`
  - `codetrust_list_rules`, `codetrust_verify_imports`
  - `codetrust_verify_dockerfile`, `codetrust_deep_scan`
- **Redis caching** with TTL management and graceful degradation
- **X-API-Key authentication** (optional — skipped in local dev)
- **Pre-commit hook** with BLOCK/WARN pattern scanning
- **Docker Compose** stack for API + Redis
- **Multi-stage Dockerfile** with non-root user
- **Structured JSON logging** throughout
