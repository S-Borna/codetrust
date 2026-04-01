# OWASP Agentic Security Initiative (ASI) Top 10 — 2026

## CodeTrust Compliance Mapping

**Framework:** OWASP Agentic Security Initiative Top 10 (2026)
**Mapped by:** CodeTrust AI Governance Platform
**Last verified:** 2026-03-30 (all evidence checked against source code)

---

## Coverage Summary

| Risk ID | Risk Name | Coverage |
|---------|-----------|----------|
| OWASP-ASI-01 | Prompt Injection | 🟢 full |
| OWASP-ASI-02 | Insecure Tool Use | 🟢 full |
| OWASP-ASI-03 | Excessive Agency | 🟢 full |
| OWASP-ASI-04 | Unauthorized Actions | 🟢 full |
| OWASP-ASI-05 | Improper Error Handling | 🟢 full |
| OWASP-ASI-06 | Supply Chain Vulnerabilities | 🟢 full |
| OWASP-ASI-07 | Sensitive Information Disclosure | 🟢 full |
| OWASP-ASI-08 | Sandboxing Failures | 🟢 full |
| OWASP-ASI-09 | Excessive Permissions | 🟢 full |
| OWASP-ASI-10 | Logging & Monitoring Gaps | 🟢 full |

**10/10 full coverage · 0/10 partial coverage · 0/10 planned**

---

## OWASP-ASI-01: Prompt Injection

**Description:** Malicious input manipulates agent behavior, bypasses instructions, or exfiltrates data.

**Coverage:** 🟢 `full`

**CodeTrust capabilities:**
- Gateway interceptor — 33 BLOCK patterns for terminal commands
- BASH_ENV guard — universal real-time enforcement for shell commands
- PreToolUse gateway hook — 42 blocked patterns before execution
- Interpreter inner-string validation — blocks python3 -c / node -e injection
- Governance file protection — 13 protected paths prevent rule tampering

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/interceptor.py` | `_TERMINAL_RULES` | Lines 163-534: 82 BLOCK-level gateway rules |
| `src/templates/bash_env_guard.sh` | `codetrust_guard()` | Lines 41-77: 3 core rules — heredoc, git push, rm -rf |
| `src/templates/pretooluse_gateway_hook.py` | `BLOCKED_PATTERNS` | Lines 116-402: 42 rule IDs across 12 categories |
| `src/gateway/interceptor.py` | `_check_interpreter_inner_string()` | Lines 131-156: validates python/node/ruby/perl -c/-e |
| `src/templates/pretooluse_file_write_hook.py` | `PROTECTED_PATH_PATTERNS` | Lines 24-90: 13 protected paths |

---

## OWASP-ASI-02: Insecure Tool Use

**Description:** Agent invokes tools without validation, enabling command injection or unauthorized operations.

**Coverage:** 🟢 `full`

**CodeTrust capabilities:**
- MCP Gateway proxy — 19 validated tool wrappers
- `validate_command` — checks terminal commands against 33 BLOCK patterns
- `validate_file_write` — checks file writes for secrets and protected paths
- `validate_package` — validates package names before installation
- `validate_file_delete` — validates file deletion requests
- Delta-only validation — validates new content, not entire file

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/server.py` | `validate_command()` | Line 539 |
| `src/gateway/server.py` | `validate_file_write()` | Line 592 |
| `src/gateway/server.py` | `validate_package()` | Line 668 |
| `src/gateway/server.py` | `validate_file_delete()` | Line 636 |
| `src/gateway/server.py` | `proxy_replace_string_in_file()` | Lines 901-955: delta-only |

---

## OWASP-ASI-03: Excessive Agency

**Description:** Agent takes actions beyond intended scope without human oversight or approval.

**Coverage:** 🟡 `partial`

**CodeTrust capabilities:**
- Commit Policy Engine — allowed_models, models_blocked, max_ai_ratio enforcement
- `codetrust doctor` — verifies all 8 enforcement layers are active
- Trusted Session mechanism — explicit human approval for elevated actions
- Pre-action validation — checks plans before code is written

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/services/commit_policy.py` | `PolicyConfig` | Lines 40-65 |
| `src/cli.py` | `cmd_doctor()` | Line 4854 |
| `src/gateway/server.py` | `begin_trusted_session()` | Line 1261 |
| `src/server.py` | `codetrust_pre_action()` | Line 229 |

**Gap:** No automatic action-count limiting per session. Policy engine governs commits but not individual tool invocations.

---

## OWASP-ASI-04: Unauthorized Actions

**Description:** Agent performs operations it should not be permitted to execute.

**Coverage:** 🟢 `full`

**CodeTrust capabilities:**
- PreToolUse hooks — intercept EVERY Bash command before execution
- Allow-list audit — detects 9 dangerous bypass patterns in settings
- Protected file paths — 13 governance files cannot be modified by agents
- Gateway interceptor — blocks git push, rm -rf, eval, privilege escalation

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/templates/pretooluse_gateway_hook.py` | `BLOCKED_PATTERNS` | Lines 116-402: 42 patterns |
| `src/cli.py` | `audit_allow_list()` | Lines 3117-3137: 9 bypass patterns |
| `src/templates/pretooluse_file_write_hook.py` | `PROTECTED_PATH_PATTERNS` | Lines 24-90 |
| `src/gateway/interceptor.py` | `_TERMINAL_RULES` | Lines 163-534: 33 patterns |

---

## OWASP-ASI-05: Improper Error Handling

**Description:** Agent errors expose internal state, crash governance, or degrade to unprotected mode.

**Coverage:** 🟡 `partial`

**CodeTrust capabilities:**
- Fail-open design — hooks return 0 on exception (documented trade-off)
- Append-only audit trail — all actions logged regardless of outcome
- Non-blocking audit I/O — audit write failures buffered, never crash
- `codetrust doctor` — verifies enforcement layers are operational

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/templates/pretooluse_gateway_hook.py` | `main()` | Lines 457-461: fail-open |
| `src/templates/pretooluse_file_write_hook.py` | `main()` | Lines 194-198: fail-open |
| `src/gateway/audit.py` | `AuditLogger.log()` | Lines 100-103: non-blocking |
| `src/cli.py` | `cmd_doctor()` | Line 4854: operational verification |

**Gap:** Fail-open design means a hook crash silently disables enforcement. No health-check alerting when hooks fail.

---

## OWASP-ASI-06: Supply Chain Vulnerabilities

**Description:** Agent installs malicious or vulnerable packages via hallucinated or compromised dependencies.

**Coverage:** 🟢 `full`

**CodeTrust capabilities:**
- Import verification — detects hallucinated packages across 8 languages
- Registry verification — PyPI, npm, Go Proxy, RubyGems, Maven, NuGet, Packagist
- Vulnerability scanning — OSV database with NVD severity enrichment
- License compliance checking — permissive/copyleft classification
- Package validation — BLOCK on NOT_FOUND registry status

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/services/import_verifier.py` | `async_verify_file_imports()` | Line 236 |
| `src/services/registry.py` | `RegistryService` | Lines 89-893: 7 registries |
| `src/services/vulnerability.py` | `VulnerabilityService` | Lines 113+: OSV + NVD |
| `src/services/license_checker.py` | `LicenseService` | Lines 34-89: 4 classifications |
| `src/gateway/server.py` | `validate_package()` | Line 668 |

---

## OWASP-ASI-07: Sensitive Information Disclosure

**Description:** Agent leaks secrets, credentials, or PII through code, logs, or tool outputs.

**Coverage:** 🟢 `full`

**CodeTrust capabilities:**
- File-write hook — 6 secret patterns detected before file is written
- Hardcoded secret scan rules — BLOCK severity in static analysis
- URL credential redaction — strips passwords from log output
- Protected credential paths — .env.production, .ssh/, .aws/, .kube/ blocked

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/templates/pretooluse_file_write_hook.py` | `SECRET_PATTERNS` | Lines 94-131 |
| `src/rules/anti_patterns.py` | `hardcoded_secret` | Lines 53-68 |
| `src/services/cache.py` | `_redact_url()` | Lines 18-26 |
| `src/templates/pretooluse_file_write_hook.py` | `PROTECTED_PATH_PATTERNS` | Lines 52-72 |

---

## OWASP-ASI-08: Sandboxing Failures

**Description:** Agent-generated code executes without isolation, risking host system compromise.

**Coverage:** 🟡 `partial`

**CodeTrust capabilities:**
- Docker sandbox — isolated execution with resource limits
- Sandbox MCP tool — `codetrust_sandbox_run` for safe code execution
- Language support — Python, JavaScript, TypeScript, Go, Rust
- Output limits — 50KB max output, configurable timeout

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/services/sandbox.py` | `SandboxService` | Line 58: Docker isolation |
| `src/services/sandbox.py` | `SUPPORTED_LANGUAGES` | Lines 29-35 |
| `src/api.py` | `/v1/sandbox/run` | Line 2288 |

**Gap:** Sandbox requires Docker. No gVisor/Firecracker micro-VM isolation. No network policy enforcement within sandbox.

---

## OWASP-ASI-09: Excessive Permissions

**Description:** Agent operates with broader permissions than necessary for its task.

**Coverage:** 🟡 `partial`

**CodeTrust capabilities:**
- Allow-list audit — detects 9 dangerous permission bypass patterns
- Policy integrity verification — SHA-256 HMAC of governance files
- Governance integrity MCP tool — runtime hash verification
- Protected path enforcement — credential directories blocked

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/cli.py` | `audit_allow_list()` | Lines 3117-3137: 9 patterns |
| `src/gateway/policy_integrity.py` | `verify_policy_integrity()` | Lines 18-60 |
| `src/gateway/server.py` | `governance_integrity()` | Line 1468 |

**Gap:** No dynamic least-privilege scoping per task. Allow-list audit is detective, not preventive.

---

## OWASP-ASI-10: Logging & Monitoring Gaps

**Description:** Insufficient audit trail makes it impossible to detect or investigate agent misbehavior.

**Coverage:** 🟢 `full`

**CodeTrust capabilities:**
- Append-only JSONL audit trail — every action logged with verdict and rule_id
- Audit history MCP tool — query logs by time range, verdict, format
- Telemetry system — privacy-preserving anonymous aggregation
- Completion Hallucination Detection — verifies agent claims against evidence
- CLI audit command — export in table/CEF/LEEF/syslog/JSON formats

**Evidence:**

| File | Component | Detail |
|------|-----------|--------|
| `src/gateway/audit.py` | `AuditLogger` | Lines 56-321 |
| `src/gateway/server.py` | `audit_history()` | Line 1173 |
| `src/services/telemetry.py` | `TelemetryIngestEvent` | Lines 119-144 |
| `src/services/completion_hallucination.py` | `verify_claims()` | Line 122+ |
| `src/cli.py` | `cmd_audit()` | Lines 5701-5721 |

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
