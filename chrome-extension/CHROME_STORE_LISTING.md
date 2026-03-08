# Chrome Web Store Listing — CodeTrust

## Listing Metadata (enter in Chrome Web Store Developer Dashboard)

### Extension Name

CodeTrust — AI Code Governance

### Short Description (132 chars max)

Scan code for AI hallucinations, security issues & unsafe patterns. 286 rules, 10 layers, live registry verification. Trust Score.

### Detailed Description (16,000 chars max — optimized for Chrome Web Store SEO)

**CodeTrust** is the AI governance enforcement platform that scans code for security vulnerabilities, AI-generated hallucinations, and dangerous anti-patterns — directly in your browser.

**WHAT IT DOES**

CodeTrust scans code blocks on GitHub, GitLab, Stack Overflow, and any code page to detect:

- **AI Hallucinations** — Fabricated package imports, invented API endpoints, non-existent modules, placeholder URLs, fake credentials
- **Security Vulnerabilities** — SQL injection, XSS, command injection, path traversal, insecure deserialization, hardcoded secrets
- **Anti-Patterns** — eval/exec usage, wildcard imports, mutable defaults, bare except handlers, nested ternaries, console.log in production
- **Supply Chain Risks** — Typosquatted packages, deprecated dependencies, known-vulnerable versions
- **DevOps Issues** — Insecure Dockerfiles, overly permissive Kubernetes configs, unsafe CI/CD patterns

**KEY FEATURES**

- **286 Security Rules** across 10 enforcement layers
- **16 Languages** — Python, JavaScript, TypeScript, Go, Rust, Java, C#, Ruby, PHP, C++, Shell, PowerShell, Terraform, HTML, SQL, YAML
- **Live Registry Verification** — Checks imports against PyPI, npm, crates.io, Go proxy, Maven, NuGet, RubyGems, Packagist
- **Trust Score** — Quantified code safety score with drift tracking
- **Inline Results** — See findings directly on the page
- **Right-Click Scan** — Select code, right-click, scan instantly
- **GitHub Integration** — Scans PRs, code reviews, and gists
- **Privacy-First** — Code is sent to the CodeTrust API for analysis only; no data is stored

**WHO IT'S FOR**

- Developers reviewing code on GitHub
- Security engineers auditing pull requests
- Teams adopting AI coding assistants (Claude Code, Cursor, GitHub Copilot)
- Engineering managers enforcing code quality standards
- DevOps engineers reviewing infrastructure-as-code

**ALSO AVAILABLE AS**

- CLI: pip install codetrust
- VS Code Extension: Search "CodeTrust" in VS Code Marketplace
- GitHub Action: CI/CD gate for pull requests
- MCP Server: Direct AI assistant integration

**LINKS**

- Website: <https://codetrust.ai>
- API Docs: <https://codetrust.ai/openapi.json>
- GitHub: <https://github.com/S-Borna/codetrust>
- PyPI: <https://pypi.org/project/codetrust/>

Built by Said Borna. Enterprise-grade code safety for AI-assisted development.

---

### Category

Developer Tools

### Language

English

### Keywords / Tags (for discoverability)

- code security
- AI code scanner
- code safety
- hallucination detection
- code review
- security scanner
- code quality
- AI governance
- code analysis
- developer tools
- GitHub code scanner
- vulnerability scanner
- anti-pattern detection
- supply chain security
- trust score
- code linter
- static analysis
- SAST
- DevSecOps
- AI coding assistant

---

## Chrome Web Store SEO Strategy

### Primary Keywords (target for #1 ranking)

1. "code security scanner"
2. "AI code scanner"
3. "code safety extension"
4. "hallucination detection"
5. "AI governance"
6. "code review extension"
7. "GitHub code scanner"

### Secondary Keywords

1. "code quality checker"
2. "vulnerability scanner chrome"
3. "developer security tools"
4. "unsafe code detector"
5. "import verification"
6. "supply chain security"
7. "CodeTrust"

### Long-tail Keywords

1. "scan code for security issues on GitHub"
2. "detect AI hallucinated packages"
3. "code review security extension"
4. "AI generated code safety checker"
5. "developer tools code analysis Chrome"

---

## Required Store Assets

### Screenshots (1280x800 or 640x400)

1. **Hero**: Popup UI showing scan results with Trust Score
2. **GitHub Scan**: Content script scanning code on a GitHub PR
3. **Right-Click Menu**: Context menu "Scan with CodeTrust" on selected code
4. **Findings Detail**: Detailed findings with severity levels and suggestions
5. **Settings Page**: Options page with API key configuration

### Promotional Images

- **Small tile**: 440x280 — Logo + "AI Code Governance" tagline
- **Large tile**: 920x680 — Full feature showcase
- **Marquee**: 1400x560 — Featured banner

### Icon

- **Store icon**: 128x128 PNG — Use existing CodeTrust logo

---

## Publishing Checklist

1. [ ] Generate icon sizes (16, 32, 48, 128) — run `node scripts/generate-icons.js`
2. [ ] Create 5 screenshots (1280x800)
3. [ ] Create promotional images (440x280, 920x680, 1400x560)
4. [ ] Write privacy policy page at <https://codetrust.ai/privacy>
5. [ ] Login to Chrome Web Store Developer Dashboard
6. [ ] Upload extension ZIP (exclude scripts/, node_modules/)
7. [ ] Fill in all listing metadata above
8. [ ] Set pricing: Free
9. [ ] Set regions: All regions
10. [ ] Submit for review (takes 1-3 business days)
11. [ ] After approval: add Chrome Web Store link to website, README, etc.

---

## Privacy Policy Requirements (for Store submission)

Chrome Web Store requires a privacy policy URL. Key points to cover:

- What data is collected: Code snippets are sent to api.codetrust.ai for analysis
- What data is stored: API keys in chrome.storage.sync; no code is stored server-side
- Third-party services: CodeTrust API (api.codetrust.ai)
- Data retention: Code is processed in real-time and not persisted
- User control: Users can clear data via Chrome extension settings
- Contact: <said@saidborna.com>
