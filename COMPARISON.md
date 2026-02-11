# CodeTrust vs. Marknaden — Ärlig Jämförelse

> **Uppdaterad: Februari 2026**

---

## Positionering

CodeTrust **ersätter inte** SonarQube, Snyk eller Semgrep. Det **kompletterar** dem genom att täcka ett gap ingen annan adresserar: **verifiering av AI-genererad kod mot verkligheten**.

---

## Kärnkapabilitet — Feature-matris

| Kapabilitet | CodeTrust | SonarQube | Semgrep | Snyk | Ruff/ESLint |
|---|:---:|:---:|:---:|:---:|:---:|
| **Paketexistens-verifiering** | **✅** | ❌ | ❌ | ❌ | ❌ |
| **Typosquatting-skydd** | **✅** | ❌ | ❌ | ❌ | ❌ |
| **Docker image/tag-verifiering** | **✅** | ❌ | ❌ | Delvis¹ | ❌ |
| **MCP Server (AI-integration)** | **✅ 10 tools** | ✅ (2025) | ❌ | ❌ | ❌ |
| **Sandbox-exekvering** | **✅** | ❌ | ❌ | ❌ | ❌ |
| **4-stegs enforcement** | **✅** | Delvis² | ❌ | ❌ | ❌ |
| **Noll-konfiguration setup** | **✅** 2s | ❌ Timmar | ✅ | ❌ | ✅ |
| **Offline-scanning** | **✅** | ❌ Server | ✅ CLI | ❌ API | ✅ |
| Statisk kodanalys | 35+ regler | 5,000+ | 3,000+ | SAST | 800+ |
| Språkstöd | 7 | 35+ | 30+ | 20+ | 1–2 |
| AST-analys | ✅ 5 språk | ✅ | ✅ | ✅ | ✅ |
| SCA (CVE i dependencies) | ❌ | Tillägg | ✅ | **✅** | ❌ |
| Taint analysis | ❌ | ✅ | ✅ | ✅ | ❌ |
| Secrets detection | Grundläggande | ✅ | ✅ $20/dev | ❌ | ❌ |
| SARIF-output | ✅ | ✅ | ✅ | ✅ | ❌ |
| SSO/RBAC/Compliance | ❌ | ✅ | ✅ | ✅ | ❌ |

¹ Snyk gör container scanning för kända CVE:er, men verifierar inte att images/taggar existerar.
² SonarQube har Quality Gates men inte advisory→passive→blocking→absolute enforcement stack.

---

## Analys per verktyg

### vs. SonarQube

| | CodeTrust | SonarQube |
|---|---|---|
| **Styrka** | Verifierar att AI-kod fungerar i verkligheten | Djupaste regelbiblioteket (5,000+), 35+ språk |
| **Svaghet** | 35+ regler, 7 språk | Ingen paket/Docker-verifiering, kräver server |
| **MCP** | Byggt för det | Tillagt 2025 |
| **Pris** | $0 | $32/mån (10 dev, 100K LOC) |
| **Bäst för** | AI-kodverifiering | Traditionell kodkvalitet |

**Kombination:** Använd SonarQube för djup kodkvalitet + CodeTrust för AI-specifik verifiering.

### vs. Semgrep

| | CodeTrust | Semgrep |
|---|---|---|
| **Styrka** | Paketverifiering, Docker, MCP, sandbox | Cross-file taint analysis, custom rules |
| **Svaghet** | Regex + AST (ingen taint) | Ingen paket/Docker-verifiering |
| **Pris** | $0 | $40–100/dev/mån |
| **Bäst för** | Fånga AI-hallucinationer | Avancerad SAST + SCA |

**Kombination:** Semgrep för avancerad SAST + CodeTrust för att fylla AI-verifieringsgapet.

### vs. Snyk

| | CodeTrust | Snyk |
|---|---|---|
| **Styrka** | Verifierar att paket existerar (inte bara CVE-check) | Bästa SCA — mappar dependencies mot CVE-databaser |
| **Svaghet** | Ingen CVE-scanning | Verifierar ej att hallucinerade paket existerar |
| **Pris** | $0 | $25/dev/mån (Team) |
| **Bäst för** | AI-paketverifiering | Vulnerability management |

**Kombination:** Snyk för CVE-scanning + CodeTrust för existens-verifiering. Kompletterande, inte konkurrerande.

### vs. Ruff / ESLint

| | CodeTrust | Ruff/ESLint |
|---|---|---|
| **Styrka** | Verifiering mot verkligheten (registries, Docker) | Snabbaste lintern, full stil-kontroll |
| **Svaghet** | Inte en linter | Ingen verifiering mot registries |
| **Pris** | $0 | $0 |
| **Bäst för** | Kodverifiering | Kodformatering |

**Kombination:** Ruff för stil + CodeTrust för verifiering. Båda bör köras.

---

## Det unika gapet CodeTrust fyller

```
Traditional SAST/SCA workflow:
  Code → Lint → SAST → SCA → Deploy
  
  "Is the code well-written?"     ✅ SonarQube, Semgrep
  "Does it have known CVEs?"      ✅ Snyk, Semgrep SCA
  "Does it actually WORK?"        ❌ Nobody checks this
    - Do the imports exist?       ❌
    - Is the Docker image real?   ❌
    - Will it crash at runtime?   ❌
    
With CodeTrust added:
  Code → Lint → SAST → SCA → CodeTrust → Deploy
  
  "Does it actually WORK?"        ✅ CodeTrust
    - Do the imports exist?       ✅ Registry verification
    - Is the Docker image real?   ✅ Docker Hub verification
    - Will it crash at runtime?   ✅ Sandbox execution
```

---

## Priser (februari 2026)

| Verktyg | Pris per 10 devs | Paketverifiering | Docker-verifiering | MCP | Offline |
|---|---|:---:|:---:|:---:|:---:|
| **CodeTrust** | **$0** | ✅ | ✅ | ✅ | ✅ |
| SonarQube Cloud Team | ~$32/mån | ❌ | ❌ | ✅ | ❌ |
| Semgrep SAST | $400/mån | ❌ | ❌ | ❌ | ✅ |
| Semgrep Full (SAST+SCA+Secrets) | $1,000/mån | ❌ | ❌ | ❌ | ✅ |
| Snyk Team | $250/mån | ❌ | CVE | ❌ | ❌ |
| Snyk Ignite | ~$1,050/mån | ❌ | ✅ | ❌ | ❌ |

---

## Sammanfattning

| Fråga | Svar |
|---|---|
| Behöver jag CodeTrust om jag har SonarQube? | **Ja.** SonarQube verifierar inte att paket existerar eller att Docker-images fungerar. |
| Behöver jag CodeTrust om jag har Snyk? | **Ja.** Snyk hittar CVE:er i kända paket. CodeTrust fångar paket som inte existerar alls. |
| Behöver jag SonarQube om jag har CodeTrust? | **Ja, om du behöver djup SAST.** CodeTrust har 35+ regler, SonarQube 5,000+. |
| Behöver jag Snyk om jag har CodeTrust? | **Ja, om du behöver CVE-scanning.** CodeTrust verifierar existens, inte kända sårbarheter. |
| Kan jag använda alla tillsammans? | **Absolut.** De fyller olika delar av säkerhetspipeline. CodeTrust i SARIF-format fungerar med samma GitHub Security tab. |

---

*CodeTrust v1.5.0 — Filling the AI verification gap that no other tool addresses.*
