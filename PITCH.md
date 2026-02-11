# CodeTrust — Pitch & Säljdokumentation

> **Version 1.5.0 | Februari 2026 | Live på PyPI, VS Code Marketplace & Railway**

---

## Elevator Pitch (10 sekunder)

> **"CodeTrust verifierar att det AI:n skriver faktiskt fungerar — innan det når produktion. Inga hallucinerade paket, inga läckta hemligheter, inga trasiga Docker-builds."**

---

## Problemet ($47 miljarder marknadsanledning)

### AI skriver din kod nu. Men ingen verifierar att den fungerar.

2025–2026 har AI-kodningsverktyg (GitHub Copilot, Claude Code, Cursor, GPT) blivit standard. **78% av utvecklare** använder AI-assistenter dagligen. Men AI-genererad kod har nya felklasser som befintliga verktyg inte fångar:

| Ny felklass | Konsekvens | Frekvens |
|---|---|---|
| **Hallucinerade paket** — AI föreslår `import fast-utils` som inte finns | `pip install` kraschar, projektet körs ej | 5–15% av AI-paketförslag (Stanford/Cornell forskning 2024) |
| **Typosquatting** — AI skriver `requets` istf `requests` | Skadligt paket installeras (supply chain attack) | 10,000+ maliciösa paket borttagna från PyPI/npm 2024 |
| **Trasiga Docker-images** — AI anger `FROM python:3.12-alpine-slim` som ej existerar | CI-bygget kraschar, deployment fördröjs timmar | Varje Docker-användande team drabbas |
| **Inbäddade hemligheter** — AI klistrar in `api_key = "sk-live-abc..."` | Pushas till GitHub, exponeras inom sekunder av bots | #1 orsak till credential leaks |
| **Osäkra mönster** — AI skriver `eval(user_input)` | Remote Code Execution-sårbarhet | Standard i AI-genererad glue code |

### Befintliga verktyg missar det helt

| Verktyg | Vad det gör | Vad det INTE gör |
|---|---|---|
| **SonarQube** | 5,000+ kodkvalitetsregler | Verifierar ej att paket existerar |
| **Snyk** | Hittar CVE:er i kända paket | Verifierar ej att okända paket existerar |
| **Semgrep** | Cross-file dataflödesanalys | Ingen MCP-integration, ingen Docker-verifiering |
| **Ruff/ESLint** | Kodstil, formatering | Verifierar ej imports mot registries |

**Ingen av dem verifierar att det AI:n genererar överhuvudtaget fungerar i verkligheten.**

---

## Lösningen: CodeTrust

### 7 verifieringslager — från advisory till absolut blockering

```
┌──────────────────────────────────────────────────────────────────┐
│  LAYER 7 — ENFORCEMENT                                          │
│  GitHub Action blockerar PR. Pre-commit blockerar commit.        │
│  Ingen kan kringgå. Infrastrukturnivå.                           │
├──────────────────────────────────────────────────────────────────┤
│  LAYER 6 — ENTERPRISE STRUCTURE                                  │
│  Verifierar README, LICENSE, tester, .gitignore, config.         │
│  SARIF v2.1.0 output för GitHub Security-tabben.                 │
├──────────────────────────────────────────────────────────────────┤
│  LAYER 5 — SANDBOX EXEKVERING                                    │
│  Kör koden i isolerad Docker-container. Fångar runtime-krascher. │
│  --network=none, --read-only, 256MB, 10s timeout.                │
├──────────────────────────────────────────────────────────────────┤
│  LAYER 4 — DOCKER VERIFIERING                                    │
│  Verifierar base images+taggar mot Docker Hub live API.           │
│  Föreslår tillgängliga taggar om den angivna saknas.              │
├──────────────────────────────────────────────────────────────────┤
│  LAYER 3 — AST-ANALYS (tree-sitter)                              │
│  Cyklomatisk komplexitet, oanvända variabler, oåtkomlig kod,     │
│  djup nesting. Python, JS, TS, Go, Rust.                         │
├──────────────────────────────────────────────────────────────────┤
│  LAYER 2 — PAKETVERIFIERING                                      │
│  Verifierar varje import mot PyPI, npm, crates.io, Go proxy.     │
│  Typosquatting-skydd via fuzzy matching mot 2,000+ paket.         │
├──────────────────────────────────────────────────────────────────┤
│  LAYER 1 — STATISK ANALYS                                        │
│  35+ regex-regler. Hemligheter, eval/exec, SQL injection,        │
│  pickle, bare except, mutable defaults. 7 språk.                 │
└──────────────────────────────────────────────────────────────────┘
```

### Det som gör CodeTrust unikt

| Kapabilitet | CodeTrust | Alla andra |
|---|---|---|
| Verifierar att paket existerar i registries | **Ja** — PyPI, npm, crates.io, Go proxy | **Nej** — ingen |
| Typosquatting-skydd | **Ja** — fuzzy matching, "Did you mean requests?" | **Nej** |
| Docker image/tag-verifiering | **Ja** — live Docker Hub API | **Nej** |
| MCP-native (realtid till AI-assistenter) | **Ja** — 10 MCP-verktyg | SonarQube (nytt 2025), resten nej |
| Offline-scanning i editor | **Ja** — VS Code extension med embedded scanner | Semgrep CLI (delvis) |
| Sandbox-exekvering | **Ja** — isolerad Docker | **Nej** — ingen |
| 4-stegs enforcement (advisory → blockering) | **Ja** — CLAUDE.md → Extension → Hook → Action | Befintliga verktyg: manuell setup |
| Noll konfiguration | **Ja** — `codetrust init` (2 sekunder) | SonarQube: timmar. Snyk: konto + config |

---

## Leveransbevis

### 558 automatiserade tester — 100% gröna

CodeTrust testas med 558 tester fördelade över 19 testsviter:

| Testfil | Antal | Vad den testar |
|---|---|---|
| `test_sandbox.py` | 63 | Sandbox-exekvering, säkerhetslimiter, timeout-hantering |
| `test_registry.py` | 52 | PyPI/npm-verifiering, cache, batch, version mismatch |
| `test_ast.py` | 47 | AST-analys, komplexitet, oanvända variabler, deep nesting |
| `test_go_rust_registry.py` | 44 | Go proxy + crates.io-verifiering, import-extraktion |
| `test_github_action.py` | 44 | GitHub Action, SARIF-output, PR-blockering |
| `test_models.py` | 34 | Pydantic-modellvalidering, enum-serialisering |
| `test_sarif.py` | 33 | SARIF v2.1.0-format, severity-mappning |
| `test_static.py` | 32 | Statisk analys, 35+ regler, alla severity-nivåer |
| `test_parsers.py` | 29 | Import-extraktion Python/JS/TS/Go/Rust, requirements parsing |
| `test_database.py` | 29 | SQLAlchemy async CRUD, användare, API-nycklar, scan-loggar |
| `test_deep_scan.py` | 26 | Cross-layer orkestrering, combined verdict |
| `test_billing.py` | 22 | Stripe-integration, checkout, webhook, subscription |
| `test_api_endpoints.py` | 22 | FastAPI-endpoints, auth, request validation |
| `test_dashboard_api.py` | 15 | Dashboard-API, profilhantering |
| `test_auth_service.py` | 15 | GitHub OAuth, JWT, session-hantering |
| `test_similarity.py` | 14 | Fuzzy matching, typosquatting-upptäckt |
| `test_rate_limit.py` | 14 | Rate limiting, free/pro-tier, dagsgränser |
| `test_docker.py` | 13 | Docker Hub-verifiering, image/tag-check |
| `test_cache.py` | 10 | Redis-cache, TTL, graceful degradation |

```
$ pytest tests/ -q
558 passed in 1.64s
```

**Alla tester körs utan nätverksåtkomst** — Redis mockas med `fakeredis`, HTTP med `pytest-httpx`, databas med SQLite in-memory. Zero external dependencies.

### CodeTrust verifierar sig själv (dogfooding)

Under byggandet av CodeTrust användes CodeTrust aktivt för att verifiera sin egen kod. Dokumenterade fall:

| Vad hände | Hur CodeTrust fångade det | Fas |
|---|---|---|
| `build_scan_response()` anropades med fel signatur | `codetrust_static_scan` flaggade trasig API-integration | Phase 1 |
| Pre-commit hook matchade `.format()` i URL-byggning som SQL injection | Hook blockerade commit, regex förfinades | Phase 1 |
| `eval()` i testkod triggade BLOCK | test_-filer exkluderades korrekt från hook-scanning | Phase 1 |
| Pydantic `strict=True` bröt FastAPI enum-coercion (422-errors) | `codetrust_post_action` flaggade strukturproblem | Phase 3 |
| `json` importerades men användes aldrig i testfil | Ruff + CodeTrust scan fångade unused import | Phase 5 |
| Nested if-satser triggade SIM102 (ruff) och deep nesting (AST) | Dubbelt fångad — statisk + AST-analys | Phase 6 |
| TOML-ordning i pyproject.toml bröt `classifiers` (hamnade under `[project.urls]`) | Bygget kraschar → fångades under paketerings-steg | Phase 11 |
| Duplicate `force-include` i pyproject.toml genererade wheel-warnings | Varningen fångades under `python -m build` | Phase 11 |

**CodeTrust catchar sina egna missar. Det är den starkaste möjliga validering.**

---

## Tekniska metrics

| Metric | Värde |
|---|---|
| **Tester** | 558 (alla gröna) |
| **Testkörningstid** | 1.64 sekunder |
| **Analysregler** | 35+ (BLOCK/WARN/INFO) |
| **Språkstöd** | Python, JavaScript, TypeScript, Go, Rust, Java, Shell |
| **AST-parsning** | 5 språk (tree-sitter) |
| **Registry-stöd** | 4 (PyPI, npm, crates.io, Go proxy) |
| **Docker Hub-verifiering** | Live API med tag-suggestions |
| **API-endpoints** | 19 REST endpoints |
| **MCP-verktyg** | 10 tools |
| **SARIF v2.1.0** | GitHub Security tab-kompatibel |
| **Lint-status** | ruff clean — noll fel |
| **Build-faser** | 11 (alla avslutade) |

---

## Distribution — allt är LIVE

| Kanal | Status | URL |
|---|---|---|
| **PyPI** | **LIVE** | [`pip install codetrust`](https://pypi.org/project/codetrust/) |
| **VS Code Marketplace** | **LIVE** | [`ext install SaidBorna.codetrust`](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust) |
| **Cloud API (Railway)** | **LIVE** | [`codetrust-api-production.up.railway.app`](https://codetrust-api-production.up.railway.app) |
| **GitHub** | **LIVE** | [`github.com/S-Borna/codetrust`](https://github.com/S-Borna/codetrust) |

### Installation (30 sekunder)

```bash
pip install codetrust
cd ditt-projekt
codetrust init        # installerar 4 enforcement-lager
codetrust scan .      # skannar hela projektet
codetrust doctor      # verifierar installationen
```

---

## Prisjämförelse

| Verktyg | Kostnad (10 utvecklare) | Paketverifiering | Docker-verifiering | MCP | Offline |
|---|---|---|---|---|---|
| **CodeTrust** | **$0** | **Ja** | **Ja** | **Ja** | **Ja** |
| SonarQube Cloud | ~$32/mån | Nej | Nej | Nytt (2025) | Nej |
| Semgrep Teams | $400/mån | Nej | Nej | Nej | Ja (CLI) |
| Semgrep + SCA + Secrets | $1,000/mån | Nej | Nej | Nej | Ja |
| Snyk Team | $250/mån | Nej | Container CVEs | Nej | Nej |
| Snyk Ignite | ~$1,050/mån | Nej | Ja | Nej | Nej |

**CodeTrust kostar $0 för kapabiliteter som konkurrenterna saknar helt** — oavsett vad de kostar.

---

## Ärlig positionering

### Där CodeTrust vinner

1. **Enda verktyget** som verifierar att imports faktiskt existerar i registries
2. **Enda verktyget** med typosquatting-skydd via fuzzy matching
3. **Enda verktyget** med Docker image/tag-verifiering mot live API
4. **MCP-native** — byggt för AI-assistenter från grunden
5. **4-stegs enforcement** — från advisory till absolut blockering
6. **Sandbox-exekvering** — kör koden isolerat, fångar runtime-krascher
7. **Noll konfiguration** — `codetrust init` ger fullständig setup
8. **558 tester** — battle-tested, dogfooded under hela utvecklingen

### Där konkurrenterna vinner (ärligt)

1. **Regeldjup** — SonarQube har 5,000+ regler vs våra 35+
2. **Språkbredd** — SonarQube 35+ språk, Semgrep 30+. Vi stöder 7
3. **SCA/CVE-scanning** — Snyk mappar dependencies mot kända sårbarheter. Vi gör det inte
4. **Enterprise features** — SSO, RBAC, compliance i SonarQube/Snyk
5. **Taint analysis** — Semgrep gör cross-file dataflödesanalys. Vi gör regex + AST
6. **Community** — SonarQube har 7M+ användare. Vi är nya

### Slutsats

CodeTrust **ersätter inte** SonarQube/Snyk/Semgrep. Det **kompletterar** dem. Det täcker ett gap som ingen annan adresserar: **verifiering av AI-genererad kod mot verkligheten**.

---

## Arkitektur — 5 interfaces, en service-kärna

```
┌──────────────────────────────────────────────────────────┐
│              Utvecklare / AI-assistent                     │
│         (Claude Code, Cursor, Copilot, VS Code)           │
└────┬──────────┬──────────┬──────────┬──────────┬─────────┘
     │          │          │          │          │
     │ MCP      │ HTTP API │ CLI      │ VS Code  │ GitHub
     │ Protocol │ REST     │ codetrust│ Extension│ Action
     │          │          │          │          │
┌────▼───┐ ┌───▼────┐ ┌───▼───┐ ┌───▼──────┐ ┌─▼────────┐
│MCP Srv │ │FastAPI │ │CLI 4  │ │Extension │ │GH Action │
│10 tools│ │19 endp.│ │komman.│ │Offline   │ │PR-block  │
└────┬───┘ └───┬────┘ └───┬───┘ └───┬──────┘ └─┬────────┘
     │         │          │         │           │
     └─────────┼──────────┼─────────┘           │
               │          │                     │
     ┌─────────▼──────────▼─────────────────────┘
     │           SERVICE LAYER
     │  ┌───────────────────────────────────┐
     │  │ Static Analyzer    (Layer 1)      │
     │  │ Registry Verifier  (Layer 2)      │
     │  │ AST Analyzer       (Layer 3)      │
     │  │ Docker Verifier    (Layer 4)      │
     │  │ Sandbox Service    (Layer 5)      │
     │  │ Enterprise Checks  (Layer 6)      │
     │  │ Enforcement Stack  (Layer 7)      │
     │  └───────────────────────────────────┘
     │               │
     │  ┌────────────▼──────────────────┐
     │  │ PostgreSQL     │    Redis     │
     │  │ Users/Keys     │    Cache     │
     │  │ Scan logs      │    TTL       │
     │  │ Usage data     │              │
     │  └────────────────┴──────────────┘
     │
┌────▼─────────────────────────────────┐
│       Externa registries              │
│  PyPI │ npm │ crates.io │ Go proxy   │
│  Docker Hub                           │
└───────────────────────────────────────┘
```

---

## Tidslinje

| Datum | Milstolpe |
|---|---|
| 10 feb 2026 | Dag 1 — Phase 1–4 (core engine, registry, Docker, deep scan) |
| 10 feb 2026 | Phase 5–6 (Go/Rust-stöd, AST-analys) |
| 10 feb 2026 | Phase 7 (Sandbox-exekvering) |
| 11 feb 2026 | Phase 8–9 (GitHub Action, Dashboard, Stripe) |
| 11 feb 2026 | Phase 10 (VS Code Extension) |
| 11 feb 2026 | Phase 11 (Production Hardening) |
| 11 feb 2026 | **Published to PyPI + VS Code Marketplace** |
| 11 feb 2026 | **Live Cloud API on Railway** |

**Hela produkten byggdes och publicerades på 2 dagar.**

---

## Use Cases

### 1. Solo-utvecklare med AI-assistent

```bash
pip install codetrust
codetrust init
# Klart. Alla 4 enforcement-lager aktiva.
# AI:n kan nu inte pusha trasig kod.
```

### 2. Startup-team (5–20 personer)

```yaml
# .github/workflows/codetrust-scan.yml
name: CodeTrust
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install codetrust
      - run: codetrust scan .
```
**Resultat:** Ingen PR mergas med BLOCK-findings. Hallucinerade paket, hemligheter och osäkra mönster stoppas automatiskt.

### 3. Enterprise

- Self-hostad API (Railway/Docker)
- SARIF-output för GitHub Security tab
- Branch protection + required status checks
- Scan-loggning och usage analytics
- API key management med SHA-256 hashing

---

## FAQ för investerare/partners

**Q: Varför behövs detta?**
AI skriver 30–80% av koden i moderna team. Befintliga verktyg (SonarQube, Snyk) är byggda för människoskriven kod. De verifierar inte att AI:ns imports, Docker-images och konfigurationer existerar i verkligheten.

**Q: Vad är moat?**
First-mover i AI-kodverifiering med MCP-integration. 7 verifieringslager, 558 tester, 4 distributionskanaler live. Teknisk skuld för konkurrenter att replikera.

**Q: Revenue model?**
Freemium. Free tier (100 scans/dag), Pro ($X/mån, 10,000 scans/dag), Enterprise (dedicated, SLA). Alla offline-verktyg förblir gratis.

**Q: Kan det skalas?**
Ja. Stateless API, Redis-cache, PostgreSQL-backend. Railway auto-scales. Majoriteten av scans körs lokalt (CLI, extension, hook) — gratis för oss.

**Q: Hur många användare?**
Nyss publicerat (februari 2026). PyPI + VS Code Marketplace + Cloud API live. Fokus nu: adoption och feedback.

**Q: Är det open source?**
Nej. CodeTrust är proprietärt. Verktygen (CLI, extension, MCP-server) är gratis att använda, men källkoden är inte öppen.

---

## Kontakt

**Said Borna** — Creator & Developer
- GitHub: [github.com/S-Borna](https://github.com/S-Borna)
- Email: said@saidborna.com
- PyPI: [pypi.org/project/codetrust](https://pypi.org/project/codetrust/)
- VS Code: [marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust)

---

*CodeTrust v1.5.0 — Built for the AI coding era. Live on PyPI, VS Code Marketplace & Railway.*
