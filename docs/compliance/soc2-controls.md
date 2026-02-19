# SOC 2 Controls Mapping — CodeTrust

> Maps CodeTrust platform capabilities to AICPA SOC 2 Trust Service Criteria.
> Version: 2.0 | Last updated: 2025-01-20

## Overview

This document maps CodeTrust's security, availability, processing integrity, confidentiality, and privacy controls to the [AICPA Trust Service Criteria (TSC)](https://us.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf) used in SOC 2 Type I/II audits.

**Legend:** ✅ Implemented  |  🔧 Configurable  |  📋 Documented

---

## CC1 — Control Environment

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC1.1 | COSO — Management oversight | Governance policy engine with TOML config | ✅ |
| CC1.2 | Board oversight | Audit log with full trail, SIEM export | ✅ |
| CC1.3 | Authority and responsibility | Role-based access (admin/viewer) via OIDC role mapping | ✅ |
| CC1.4 | Competence & accountability | CONTRIBUTING.md, architecture documentation | ✅ |
| CC1.5 | Enforcement | Policy enforcement (BLOCK/WARN verdicts), webhook alerts | ✅ |

## CC2 — Communication and Information

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC2.1 | Internal information quality | Structured logging (structlog), audit entries | ✅ |
| CC2.2 | Internal communication | Webhook notifications (Slack/Teams/PagerDuty) | ✅ |
| CC2.3 | External communication | SECURITY.md, responsible disclosure, status API | ✅ |

## CC3 — Risk Assessment

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC3.1 | Risk identification | 199 scan rules covering anti-patterns, hallucinations | ✅ |
| CC3.2 | Fraud risk | Config hallucination detection (5 rules), phantom import detection | ✅ |
| CC3.3 | Change impact assessment | AST analysis, deep scan combining 5 verification layers | ✅ |
| CC3.4 | Risk from changes | Dependabot automated dependency updates, SBOM generation | ✅ |

## CC4 — Monitoring Activities

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC4.1 | Ongoing monitoring | Prometheus /metrics endpoint (requests, latency, uptime) | ✅ |
| CC4.2 | Evaluate deficiencies | Governance audit log — time-series analysis, violation stats | ✅ |

## CC5 — Control Activities

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC5.1 | Risk mitigation controls | IP-based rate limiting, API key auth, JWT sessions | ✅ |
| CC5.2 | Technology general controls | Docker sandbox isolation, non-root Dockerfile | ✅ |
| CC5.3 | Security policies | `.codetrust.toml` policy config with per-rule overrides | ✅ |

## CC6 — Logical and Physical Access Controls

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC6.1 | Logical access security | API key authentication (X-API-Key header) | ✅ |
| CC6.2 | Credential management | API keys hashed (SHA-256), revocable, trackable | ✅ |
| CC6.3 | New access provisioning | GitHub OAuth, OIDC/SSO with domain restrictions | ✅ |
| CC6.4 | Access changes on termination | API key revocation, token expiration (24h) | ✅ |
| CC6.5 | Authentication mechanisms | JWT (HS256), SSO/OIDC, per-key tracking | ✅ |
| CC6.6 | Restrictions on system access | Per-plan rate limits (free: 100/day, pro: 10k/day) | ✅ |
| CC6.7 | Restrict data access | User-scoped scan history, usage stats | ✅ |
| CC6.8 | Prevent/detect unauthorized access | Rate limiting (IP + user), Prometheus alerts | ✅ |

## CC7 — System Operations

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC7.1 | Detect and monitor anomalies | Prometheus metrics, SIEM integration (CEF/LEEF/ECS) | ✅ |
| CC7.2 | Event evaluation | Webhook notifications on BLOCK/WARN events | ✅ |
| CC7.3 | Incident response | SECURITY.md — vulnerability disclosure policy | ✅ |
| CC7.4 | Business continuity | K8s Helm charts with HPA, health endpoints | ✅ |
| CC7.5 | Restore operations | Database migration support (Alembic), stateless API | ✅ |

## CC8 — Change Management

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC8.1 | Infrastructure/software changes | CI/CD pipeline (GitHub Actions), 1,665 tests | ✅ |
| CC8.2 | Assessment before deployment | 76% code coverage threshold, automated lint checks | ✅ |

## CC9 — Risk Mitigation

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| CC9.1 | Risk mitigation activities | 5-layer deep scan, sandbox execution for runtime verification | ✅ |
| CC9.2 | Vendor/partner risk | Registry verification (PyPI, npm, crates.io, Go proxy, Docker Hub) | ✅ |

---

## Availability (A1)

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| A1.1 | Processing capacity | K8s HPA auto-scaling, configurable pool sizes | ✅ |
| A1.2 | Environmental protections | Docker container isolation, memory limits | ✅ |
| A1.3 | Recovery | Helm charts, Railway/Docker deployment options | ✅ |

## Processing Integrity (PI1)

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| PI1.1 | Processing completeness | SARIF output with full finding metadata | ✅ |
| PI1.2 | Input validation | Pydantic request models with type checking | ✅ |
| PI1.3 | Error handling | Structured error responses, graceful degradation | ✅ |
| PI1.4 | Output accuracy | Finding severity (BLOCK/WARN/INFO), verdict computation | ✅ |

## Confidentiality (C1)

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| C1.1 | Identify confidential info | Scan rules detect hardcoded secrets, API keys, tokens | ✅ |
| C1.2 | Dispose of confidential info | Data retention policy with `purge(older_than_days=)` | ✅ |

## Privacy (P1)

| Criteria | Control | CodeTrust Feature | Status |
|----------|---------|-------------------|--------|
| P1.1 | Privacy notice | GDPR data export API (`/v1/user/export`) | ✅ |
| P1.2 | Choice and consent | User-initiated account deletion (`/v1/user/delete`) | ✅ |
| P1.3 | Personal info collection | Minimal PII: GitHub ID, email, name, avatar | 📋 |
| P1.4 | Use and retention | Configurable retention (`retention_days` in TOML) | ✅ |
| P1.5 | Access to personal data | GDPR data export with full user data in JSON | ✅ |
| P1.6 | Disclosure to third parties | No third-party data sharing by default | 📋 |
| P1.7 | Quality of personal info | User profile sourced from verified OAuth providers | ✅ |
| P1.8 | Monitoring and enforcement | Audit logging of all access operations | ✅ |

---

## Implementation References

| Feature | Component | Notes |
|---------|-----------|-------|
| Policy Engine | Gateway module | TOML-based governance config |
| Audit Logger | Gateway module | JSONL audit trail with purge |
| Command Interceptor | Gateway module | 58 terminal + 18 content rules |
| SIEM Export | Gateway module | CEF, LEEF, Syslog, ECS JSON |
| Webhooks | Gateway module | Slack, Teams, PagerDuty |
| Metrics | Middleware | Prometheus /metrics endpoint |
| Rate Limiting | Middleware | IP-based ASGI middleware |
| SSO/OIDC | Auth service | OIDC Authorization Code Flow |
| GDPR | Privacy service | Data export/delete service |
| Auth | Auth service | GitHub OAuth + JWT |
| Database | Data service | User/key/scan CRUD |
| Static Analysis | Scan service | 188 regex + 11 special rules |
| AST Analysis | Scan service | tree-sitter based |
| Sandbox | Execution service | Docker-isolated execution |
| Custom Rules | Gateway module | YAML/TOML user rules |
| Helm Charts | Deploy config | K8s deployment |

---

## Audit Evidence

For SOC 2 Type II evidence, the following artifacts are available:

1. **Test Suite**: 1,665 Python tests + dashboard tests → `pytest --tb=short`
2. **Coverage Report**: Code coverage → `pytest --cov=src`
3. **CI Pipeline**: `.github/workflows/ci.yml` — automated on every push
4. **SBOM**: CycloneDX SBOM generated in CI and attached to releases
5. **Dependency Scanning**: Dependabot configured for Python and npm
6. **Security Policy**: `SECURITY.md` — responsible disclosure process
7. **Architecture**: README.md with Mermaid architecture diagrams
8. **Audit Logs**: `.codetrust/audit.jsonl` — structured JSON Lines format
9. **SIEM Integration**: Export in CEF, LEEF, Syslog RFC 5424, ECS JSON
10. **Retention Config**: `retention_days` in `.codetrust.toml`
