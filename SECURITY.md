# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.6.x   | :white_check_mark: |
| 2.5.x   | :white_check_mark: |
| 2.4.x   | :x:                |
| 2.3.x   | :x:                |
| < 2.3   | :x:                |

## Reporting a Vulnerability

We take the security of CodeTrust seriously. If you discover a security
vulnerability, please report it responsibly.

**DO NOT** file a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email:** Send a detailed report to **<security@codetrust.ai>**
2. **Subject line:** `[SECURITY] CodeTrust — <brief description>`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Response Timeline

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix release (critical) | Within 7 days |
| Fix release (high) | Within 30 days |
| Fix release (medium/low) | Next scheduled release |

### Scope

The following are in scope:

- **CodeTrust CLI** (`pip install codetrust`)
- **CodeTrust API** (api.codetrust.ai)
- **CodeTrust VS Code Extension** (SaidBorna.codetrust)
- **CodeTrust MCP Server** (codetrust-mcp)
- **AI Governance Gateway** (real-time command interception)
- **GitHub Action** (S-Borna/codetrust)

### Out of Scope

- Third-party dependencies (report upstream)
- Social engineering attacks
- DoS/DDoS attacks on production infrastructure

### Recognition

We appreciate responsible disclosure. Security researchers who report valid
vulnerabilities will be:

- Credited in the release notes (unless they prefer anonymity)
