# CodeTrust vs. Marknaden — Ärlig Jämförelse (v3.0.0)

> **Uppdaterad: 13 mars 2026 · CodeTrust v3.0.0**

---

## Positionering

CodeTrust **ersätter inte** SonarQube, Snyk eller Semgrep i deras kärndomäner. Det **kompletterar** dem med ett saknat lager: **AI governance + verklighetsverifiering av AI-genererad kod**.

Praktiskt innebär det: behåll dina nuvarande verktyg för djup SAST/CVE, och lägg CodeTrust ovanpå som ett governance control-plane för AI-agentflöden.

---

## Kärnkapabilitet — Feature-matris

| Kapabilitet | CodeTrust | SonarQube | Semgrep | Snyk | Ruff/ESLint |
|---|:---:|:---:|:---:|:---:|:---:|
| **AI Governance Gateway** | **✅ 82 regler** | ❌ | ❌ | ❌ | ❌ |
| **Paketexistens-verifiering** | **✅ 8 registries** | ❌ | ❌ | ❌ | ❌ |
| **Typosquatting-skydd** | **✅** | ❌ | ❌ | ❌ | ❌ |
| **Docker image/tag-verifiering** | **✅** | ❌ | ❌ | Delvis¹ | ❌ |
| **Signaturvalidering** | **✅ 50 moduler, 405 fn** | ❌ | ❌ | ❌ | ❌ |
| **MCP Server (AI-integration)** | **✅ 27 tools** | ✅ (2025) | ❌ | ❌ | ❌ |
| **Sandbox-exekvering** | **✅** | ❌ | ❌ | ❌ | ❌ |
| **Trust Score & Drift** | **✅** | Quality Gate | ❌ | ❌ | ❌ |
| **Universal IDE Injection** | **✅ 4 IDEs** | ❌ | ❌ | ❌ | ❌ |
| **10-stegs enforcement** | **✅** | Delvis² | ❌ | ❌ | ❌ |
| **Noll-konfiguration setup** | **✅** 2s | ❌ Timmar | ✅ | ❌ | ✅ |
| **Offline-scanning** | **✅** | ❌ Server | ✅ CLI | ❌ API | ✅ |
| **CVE/Vulnerability** | **✅ OSV** | Tillägg | ✅ | **✅** | ❌ |
| **Licens-compliance** | **✅** | ❌ | ❌ | **✅** | ❌ |
| **Cross-file analys** | **✅** | ✅ | ✅ | ❌ | ❌ |
| **Auto-fix PRs** | **✅ 17 recipes** | ✅ | ✅ | ✅ | ✅ |
| Statisk kodanalys | 402 regler | 5,000+ | 3,000+ | SAST | 800+ |
| Språkstöd | 14 | 35+ | 30+ | 20+ | 1–2 |
| AST-analys | ✅ 11 språk | ✅ | ✅ | ✅ | ✅ |
| Taint analysis | **✅ Intra-proc** | ✅ | ✅ | ✅ | ❌ |
| SARIF-output | ✅ | ✅ | ✅ | ✅ | ❌ |

¹ Snyk gör container scanning för kända CVE:er, men verifierar inte att images/taggar existerar.
² SonarQube har Quality Gates men inte 10-stegs advisory→blocking enforcement stack.

---

## Analys per verktyg

### vs. SonarQube

| | CodeTrust | SonarQube |
|---|---|---|
| **Styrka** | AI Governance Gateway (82 regler), signaturvalidering, paket/Docker-verifiering | Djupaste regelbiblioteket (5,000+), 35+ språk, taint analysis |
| **Svaghet** | 402 regler, intra-procedural taint (ej inter-proc) | Ingen AI governance, ingen paket/Docker-verifiering, kräver server |
| **MCP** | 27 tools (10 scan + 17 gateway) | Tillagt 2025 |
| **Pris** | $0 | $32/mån (10 dev, 100K LOC) |
| **Bäst för** | AI-kodverifiering + governance | Traditionell kodkvalitet |

**Kombination:** SonarQube för djup SAST + CodeTrust för AI governance och verifiering.

### vs. Semgrep

| | CodeTrust | Semgrep |
|---|---|---|
| **Styrka** | Gateway, signatur, paket, Docker, MCP, sandbox, drift score | Cross-file taint analysis, custom rules, 3,000+ regler |
| **Svaghet** | Intra-procedural taint (ej cross-file) | Ingen AI governance, ingen paket/Docker-verifiering |
| **Pris** | $0 | $40–100/dev/mån |
| **Bäst för** | Fånga AI-hallucinationer + styra AI-agenter | Avancerad SAST + SCA |

**Kombination:** Semgrep för taint analysis + CodeTrust för AI-specifik enforcement.

### vs. Snyk

| | CodeTrust | Snyk |
|---|---|---|
| **Styrka** | Verifierar att paket existerar, AI governance gateway, licens-compliance | Bästa SCA — mappar dependencies mot CVE-databaser |
| **Svaghet** | OSV-baserad CVE (inte Snyk-djupet) | Verifierar ej att hallucinerade paket existerar, ingen AI governance |
| **Pris** | $0 | $25/dev/mån (Team) |
| **Bäst för** | AI-paketverifiering + governance | Vulnerability management |

**Kombination:** Snyk för CVE-scanning + CodeTrust för existens-verifiering och AI governance.

### vs. Ruff / ESLint

| | CodeTrust | Ruff/ESLint |
|---|---|---|
| **Styrka** | Verifiering mot verkligheten + AI governance + auto-fix | Snabbaste lintern, full stil-kontroll, 800+ regler |
| **Svaghet** | Inte en linter | Ingen verifiering mot registries, ingen AI governance |
| **Pris** | $0 | $0 |
| **Bäst för** | Kodverifiering + governance | Kodformatering + stil |

**Kombination:** Ruff för stil + CodeTrust för verifiering. Båda bör köras.

---

## Det unika gapet CodeTrust fyller

```
Traditional SAST/SCA workflow:
  Code → Lint → SAST → SCA → Deploy

  "Is the code well-written?"        ✅ SonarQube, Semgrep
  "Does it have known CVEs?"         ✅ Snyk, Semgrep SCA
  "Does it actually WORK?"           ❌ Nobody checks this
    - Do the imports exist?          ❌
    - Is the Docker image real?      ❌
    - Will it crash at runtime?      ❌
  "Is the AI agent safe?"            ❌ Nobody governs this
    - What commands does it run?     ❌
    - What files does it write?      ❌
    - What packages does it install? ❌

With CodeTrust added:
  AI Agent → Gateway → Code → Lint → SAST → SCA → CodeTrust → Deploy

  "Does it actually WORK?"           ✅ CodeTrust
    - Do the imports exist?          ✅ Registry verification (8 registries)
    - Is the Docker image real?      ✅ Docker Hub + GHCR verification
    - Are function signatures real?  ✅ Signature validation (209 functions)
    - Will it crash at runtime?      ✅ Sandbox execution
  "Is the AI agent safe?"            ✅ CodeTrust Gateway
    - What commands does it run?     ✅ 82 interception rules
    - What files does it write?      ✅ Content + path validation
    - What packages does it install? ✅ Package registry check
```

---

## Priser (februari 2026)

| Verktyg | Pris per 10 devs | AI Governance | Paketverifiering | Docker-verif. | MCP | Offline |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **CodeTrust** | **$0** | **✅ 82 regler** | ✅ | ✅ | **✅ 27** | ✅ |
| SonarQube Cloud Team | ~$32/mån | ❌ | ❌ | ❌ | ✅ | ❌ |
| Semgrep SAST | $400/mån | ❌ | ❌ | ❌ | ❌ | ✅ |
| Semgrep Full | $1,000/mån | ❌ | ❌ | ❌ | ❌ | ✅ |
| Snyk Team | $250/mån | ❌ | ❌ | CVE | ❌ | ❌ |
| Snyk Ignite | ~$1,050/mån | ❌ | ❌ | ✅ | ❌ | ❌ |

---

## Sammanfattning

### Strategisk slutsats

- Om du redan betalar för Sonar/Snyk/Semgrep: CodeTrust ökar täckningen där de fortfarande saknar AI-governance.
- Om du startar från noll: CodeTrust ger en snabb, gratis governance-bas med tydlig enforcement i IDE + commit + CI.
- Om du vill vinna internt: positionera CodeTrust som riskreduktion + kontrollbarhet, inte bara ännu en scanner.

| Fråga | Svar |
|---|---|
| Behöver jag CodeTrust om jag har SonarQube? | **Ja.** SonarQube verifierar inte paket/Docker, har ingen AI governance gateway. |
| Behöver jag CodeTrust om jag har Snyk? | **Ja.** Snyk hittar CVE:er i kända paket. CodeTrust fångar paket som inte existerar och styr AI-agenter. |
| Behöver jag SonarQube om jag har CodeTrust? | **Ja, om du behöver djup SAST.** CodeTrust har 402 scan-regler, SonarQube 5,000+. |
| Behöver jag Snyk om jag har CodeTrust? | **Kanske.** CodeTrust har OSV-baserad CVE-scanning. Snyk har djupare CVE-databas. |
| Kan jag använda alla tillsammans? | **Absolut.** De fyller olika delar av säkerhetspipeline. SARIF-format fungerar med samma GitHub Security tab. |

---

*CodeTrust v3.0.0 — AI Governance Enforcement Platform. 402 rules + taint analysis, 27 MCP tools, 60 API endpoints, 2,058 tests.*
