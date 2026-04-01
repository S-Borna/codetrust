# CodeTrust Compliance Documentation

CodeTrust maps its AI governance capabilities to recognized security and AI safety frameworks. Each mapping includes verified evidence — exact file paths, function names, and line numbers — not marketing claims.

## Supported Frameworks

| Framework | ID | Risks Mapped | Full | Partial |
|-----------|-----|-------------|------|---------|
| [OWASP ASI 2026](owasp-asi-2026.md) | `owasp-asi-2026` | 10 | 6 | 4 |
| EU AI Act | `eu-ai-act` | 7 | 2 | 5 |
| NIST AI RMF | `nist-ai-rmf` | 4 | 0 | 4 |

## Generating Reports

```bash
# CLI
codetrust compliance --framework owasp-asi-2026
codetrust compliance --framework owasp-asi-2026 --json
codetrust compliance --list

# API
GET /v1/compliance/owasp-asi-2026

# MCP
codetrust_compliance_report(framework="owasp-asi-2026")
```

## Methodology

1. Each framework risk is mapped to specific CodeTrust capabilities
2. Every capability claim is verified against actual source code with file:line references
3. Coverage is rated honestly: `full`, `partial`, or `planned`
4. Gaps are documented explicitly for partial/planned coverage
5. Reports are regenerated from code — not maintained as static documents
