# OWASP Agentic Security Initiative (ASI) Top 10 — 2026

## CodeTrust Compliance Mapping

**Framework:** OWASP Agentic Security Initiative Top 10 (2026)
**Mapped by:** CodeTrust AI Governance Platform
**Last verified:** 2026-04-04 (all evidence checked against source code)

---

## Coverage Summary

| Risk ID | Risk Name | Coverage |
|---------|-----------|----------|
| OWASP-ASI-01 | Prompt Injection | full |
| OWASP-ASI-02 | Insecure Tool Use | full |
| OWASP-ASI-03 | Excessive Agency | full |
| OWASP-ASI-04 | Unauthorized Actions | full |
| OWASP-ASI-05 | Improper Error Handling | full |
| OWASP-ASI-06 | Supply Chain Vulnerabilities | full |
| OWASP-ASI-07 | Sensitive Information Disclosure | full |
| OWASP-ASI-08 | Sandboxing Failures | full |
| OWASP-ASI-09 | Excessive Permissions | full |
| OWASP-ASI-10 | Logging & Monitoring Gaps | full |

**10/10 full coverage**

---

## OWASP-ASI-01: Prompt Injection

**Description:** Malicious input manipulates agent behavior, bypasses instructions, or exfiltrates data.

**Coverage:** full

**CodeTrust capabilities:**
- Gateway interceptor — 44 BLOCK patterns for terminal commands
- BASH_ENV guard — universal real-time enforcement for shell commands
- PreToolUse gateway hook — 44 blocked patterns before execution
- Interpreter inner-string validation — blocks python3 -c / node -e injection
- Governance file protection — 14 protected paths prevent rule tampering

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/interceptor.py` | `_TERMINAL_RULES` | 62 total rules, 44 BLOCK severity |
| `src/templates/bash_env_guard.sh` | `codetrust_guard()` | 5 rules — heredoc, git push, rm -rf, force push, curl pipe sh |
| `src/templates/pretooluse_gateway_hook.py` | blocked patterns | 44 unique gateway_ rule IDs across 12 categories |
| `src/gateway/interceptor.py` | `_check_interpreter_inner_string()` | validates python/node/ruby/perl -c/-e inner commands |
| `src/templates/pretooluse_file_write_hook.py` | `PROTECTED_PATH_PATTERNS` | 14 compiled patterns for governance files |

---

## OWASP-ASI-02: Insecure Tool Use

**Description:** Agent invokes tools without validation, enabling command injection or unauthorized operations.

**Coverage:** full

**CodeTrust capabilities:**
- MCP Gateway proxy — 21 validated tool functions
- `validate_command` — checks terminal commands against 44 BLOCK patterns
- `validate_file_write` — checks file writes for secrets and protected paths
- `validate_package` — validates package names before installation
- `validate_file_delete` — validates file deletion requests
- Delta-only validation — validates new content, not entire file

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/server.py` | `validate_command()` | 44 BLOCK patterns via interceptor |
| `src/gateway/server.py` | `validate_file_write()` | secret detection + protected paths |
| `src/gateway/server.py` | `validate_package()` | registry verification |
| `src/gateway/server.py` | `validate_file_delete()` | path validation |
| `src/gateway/server.py` | `proxy_replace_string_in_file()` | delta-only validation |

---

## OWASP-ASI-03: Excessive Agency

**Description:** Agent takes actions beyond intended scope without human oversight or approval.

**Coverage:** full

**CodeTrust capabilities:**
- Session action limiter — configurable per-session action count cap (default 500)
- Commit Policy Engine — allowed_models, models_blocked, max_ai_ratio enforcement
- `codetrust doctor` — verifies all 9 enforcement layers are active
- Trusted Session mechanism — explicit human approval for elevated actions
- Pre-action validation — checks plans before code is written

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/server.py` | `_check_session_action_limit()` | configurable via CODETRUST_SESSION_ACTION_LIMIT env var |
| `src/services/commit_policy.py` | `PolicyConfig` | model/editor allowlist and blocklist |
| `src/cli.py` | `cmd_doctor()` | verifies 9 enforcement layers |
| `src/gateway/server.py` | `begin_trusted_session()` | human approval gate |

---

## OWASP-ASI-04: Unauthorized Actions

**Description:** Agent performs operations it should not be permitted to execute.

**Coverage:** full

**CodeTrust capabilities:**
- PreToolUse hooks — intercept EVERY Bash command before execution
- Allow-list audit — detects 9 dangerous bypass patterns in settings
- Protected file paths — 14 governance files cannot be modified by agents
- Gateway interceptor — blocks git push, rm -rf, eval, privilege escalation

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/templates/pretooluse_gateway_hook.py` | blocked patterns | 44 unique gateway_ rule IDs |
| `src/cli.py` | `audit_allow_list()` | 9 bypass patterns |
| `src/templates/pretooluse_file_write_hook.py` | `PROTECTED_PATH_PATTERNS` | 14 patterns |
| `src/gateway/interceptor.py` | `_TERMINAL_RULES` | 44 BLOCK patterns |

---

## OWASP-ASI-05: Improper Error Handling

**Description:** Agent errors expose internal state, crash governance, or degrade to unprotected mode.

**Coverage:** full

**CodeTrust capabilities:**
- Fail-open design — hooks return 0 on exception (documented trade-off)
- Hook health-check — `codetrust doctor` tests BLOCK and ALLOW behavior
- Append-only audit trail — all actions logged regardless of outcome
- Non-blocking audit I/O — audit write failures buffered, never crash

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/templates/pretooluse_gateway_hook.py` | `main()` | fail-open with exit 0 on exception |
| `src/templates/pretooluse_file_write_hook.py` | `main()` | fail-open with exit 0 on exception |
| `src/cli.py` | `cmd_doctor()` | tests git push BLOCKED + ls -la ALLOWED (detects broken hooks) |
| `src/gateway/audit.py` | `AuditLogger.log()` | non-blocking audit writes |

---

## OWASP-ASI-06: Supply Chain Vulnerabilities

**Description:** Agent installs malicious or vulnerable packages via hallucinated or compromised dependencies.

**Coverage:** full

**CodeTrust capabilities:**
- Import verification — detects hallucinated packages across 8 languages
- Registry verification — PyPI, npm, Go Proxy, RubyGems, Maven, NuGet, Packagist
- Vulnerability scanning — OSV database with NVD severity enrichment
- License compliance checking — permissive/copyleft classification
- Package validation — BLOCK on NOT_FOUND registry status

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/services/import_verifier.py` | `async_verify_file_imports()` | 8-language import detection |
| `src/services/registry.py` | `RegistryService` | 7 registries |
| `src/services/vulnerability.py` | `VulnerabilityService` | OSV + NVD |
| `src/services/license_checker.py` | `LicenseService` | 4 classifications |
| `src/gateway/server.py` | `validate_package()` | BLOCK on NOT_FOUND |

---

## OWASP-ASI-07: Sensitive Information Disclosure

**Description:** Agent leaks secrets, credentials, or PII through code, logs, or tool outputs.

**Coverage:** full

**CodeTrust capabilities:**
- File-write hook — 6 secret patterns detected before file is written
- Hardcoded secret scan rules — BLOCK severity in static analysis
- URL credential redaction — strips passwords from log output
- Protected credential paths — .env.production, .ssh/, .aws/, .kube/ blocked

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/templates/pretooluse_file_write_hook.py` | `SECRET_PATTERNS` | 6 secret detection patterns |
| `src/rules/anti_patterns.py` | `hardcoded_secret` | BLOCK severity |
| `src/services/cache.py` | `_redact_url()` | credential redaction |
| `src/templates/pretooluse_file_write_hook.py` | `PROTECTED_PATH_PATTERNS` | credential path protection |

---

## OWASP-ASI-08: Sandboxing Failures

**Description:** Agent-generated code executes without isolation, risking host system compromise.

**Coverage:** full

**CodeTrust capabilities:**
- Docker sandbox — isolated execution with resource limits
- Network isolation — `--network=none` blocks all outbound connections
- Resource caps — `--memory`, `--cpus=1`, `--pids-limit=64`
- Security hardening — `--read-only`, `--security-opt=no-new-privileges`, `--user=sandbox`
- Language support — Python, JavaScript, TypeScript, Go, Rust

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/services/sandbox.py` | `_build_docker_command()` | `--network=none`, `--read-only`, `--memory`, `--cpus=1`, `--pids-limit=64`, `--security-opt=no-new-privileges`, `--user=sandbox` |
| `src/services/sandbox.py` | `SUPPORTED_LANGUAGES` | 5 languages |
| `src/api.py` | `/v1/sandbox/run` | sandbox API endpoint |

---

## OWASP-ASI-09: Excessive Permissions

**Description:** Agent operates with broader permissions than necessary for its task.

**Coverage:** full

**CodeTrust capabilities:**
- Allow-list audit — detects 9 dangerous permission bypass patterns
- Preventive exit — `codetrust init` returns exit 1 when dangerous allow-list entries found
- Policy integrity verification — SHA-256 HMAC of governance files
- Governance integrity MCP tool — runtime hash verification
- Protected path enforcement — credential directories blocked

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/cli.py` | `audit_allow_list()` | 9 patterns |
| `src/cli.py` | `cmd_init()` | exits 1 on dangerous allow-list entries (GOVERNANCE INCOMPLETE) |
| `src/gateway/policy_integrity.py` | `verify_policy_integrity()` | SHA-256 HMAC verification |
| `src/gateway/server.py` | `governance_integrity()` | runtime hash check |

---

## OWASP-ASI-10: Logging & Monitoring Gaps

**Description:** Insufficient audit trail makes it impossible to detect or investigate agent misbehavior.

**Coverage:** full

**CodeTrust capabilities:**
- Append-only JSONL audit trail — every action logged with verdict and rule_id
- Audit history MCP tool — query logs by time range, verdict, format
- Telemetry system — privacy-preserving anonymous aggregation
- Completion Hallucination Detection — verifies agent claims against evidence
- Agent Integrity Verification — detects sycophancy, contradictions, unsubstantiated claims
- CLI audit command — export in table/CEF/LEEF/syslog/JSON formats

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/audit.py` | `AuditLogger` | append-only JSONL |
| `src/gateway/server.py` | `audit_history()` | time/verdict/format query |
| `src/services/telemetry.py` | `TelemetryIngestEvent` | anonymous aggregation |
| `src/services/completion_hallucination.py` | `verify_claims()` | claim vs evidence analysis |
| `src/services/agent_integrity.py` | `analyze_session()` | 4 behavioral patterns |
| `src/cli.py` | `cmd_audit()` | multi-format export |

---

## How to Generate This Report Programmatically

```bash
# Markdown
codetrust compliance --framework owasp-asi-2026

# JSON
codetrust compliance --framework owasp-asi-2026 --json

# List all frameworks
codetrust compliance --list

# Via API
curl -H "X-API-Key: $KEY" https://api.codetrust.ai/v1/compliance/owasp-asi-2026

# Via MCP
# Use codetrust_compliance_report tool with framework="owasp-asi-2026"
```
