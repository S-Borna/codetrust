# CodeTrust — Product Specification

> **Version 1.8.0 | February 2026 | Proprietary License**

---

## Innehåll

1. [Vad är CodeTrust?](#1-vad-är-codetrust)
2. [Problemet vi löser](#2-problemet-vi-löser)
3. [Vad CodeTrust gör — teknisk kapabilitet](#3-vad-codetrust-gör--teknisk-kapabilitet)
4. [Varför du ska ha CodeTrust](#4-varför-du-ska-ha-codetrust)
5. [Jämförelse mot marknaden](#5-jämförelse-mot-marknaden)
6. [Paketering & priser](#6-paketering--priser)
7. [Installation & aktivering](#7-installation--aktivering)
8. [Arkitektur & integrationspunkter](#8-arkitektur--integrationspunkter)
9. [Lansering & distribution](#9-lansering--distribution)
10. [Vanliga frågor (FAQ)](#10-vanliga-frågor-faq)

---

## 1. Vad är CodeTrust?

CodeTrust är en **AI-kodverifieringsplattform** som upptäcker hallucinerade paket, trasiga konfigurationer, säkerhetsproblem och kodantipatterns — innan de når produktion.

Den är byggd specifikt för den nya verkligheten där AI (Claude, GPT, Copilot, Cursor) skriver stora delar av koden. Befintliga kod-kvalitetsverktyg utgår från att en människa skriver koden. CodeTrust utgår från att **du inte kan lita på koden förrän den är verifierad**.

**En mening:**
> CodeTrust verifierar att det AI skriver faktiskt fungerar, är säkert, och inte innehåller påhittade paket.

---

## 2. Problemet vi löser

### AI-genererad kod har nya felklasser

| Fel | Vad händer | Hur vanligt |
|-----|-----------|-------------|
| **Hallucinerade paket** | AI föreslår `import fast-utils` — paketet finns inte på npm/PyPI | Dokumenterat i forskning (2024–2025): 5–15% av AI-föreslagna paket existerar ej |
| **Typosquatting-fällor** | AI skriver `requets` istället för `requests` — ett skadligt paket existerar under det namnet | Aktivt exploaterat; 10,000+ skadliga paket borttagna från PyPI/npm 2024 |
| **Trasiga Docker-images** | AI anger `FROM python:3.12-alpine-slim` — taggen existerar inte | Bygget kraschar i CI, fördröjer deployment |
| **Inbäddade hemligheter** | AI lägger in `api_key = "sk-live-abc..."` direkt i koden | Pushas till GitHub, exponeras inom sekunder |
| **Osäkra mönster** | AI använder `eval()`, `pickle.load()`, SQL-formatting med f-strings | Öppnar för RCE, injection-attacker |
| **Trasig struktur** | AI glömmer README, LICENSE, tester, .gitignore | Repo klarar inte enterprise-granskning |

### Befintliga verktyg missar detta

- **SonarQube/Semgrep/Snyk** — fokuserar på statisk analys och SCA (kända CVE:er i kända paket). De *verifierar inte att paketen existerar alls*.
- **Ruff/ESLint** — linters för kodstil, inte för att verifiera att imports fungerar mot verkliga registries.
- **Ingen av dem** erbjuder MCP-integration (Model Context Protocol) som ger realtidsfeedback *medan AI skriver koden*.

---

## 3. Vad CodeTrust gör — teknisk kapabilitet

### Layer 1: Statisk analys (regex + regler)

- 49 regler i tre svårighetsgrader: **BLOCK** (måste fixas), **WARN** (bör fixas), **INFO** (förslag)
- Upptäcker: heredocs, hårdkodade hemligheter, `eval`/`exec`, SQL-injection via strängformattering, `pickle.load`, console.log, wildcard-imports, bare except, mutable defaults, magiska tal
- **Symptom-Fix Detection**: except-swallow, suppress-lint, sleep_no_context, debug_mode_enabled
- **Container Hardening**: docker_root_user, docker_latest_tag, docker_no_workdir, docker_env_secret
- **CI/CD-regler**: ci_unpinned_action, ci_no_timeout
- **IaC-regler**: hardcoded_ip, api_key_in_config
- **AI Drift Score**: Komposit 0–100 trustpoäng med betyg A–F
- Språkstöd: Python, JavaScript, TypeScript, Go, Rust, Java, Shell, Dockerfile, YAML

### Layer 2: Paketverifiering mot verkliga registries

- **PyPI** — verifierar Python-paket mot pypi.org (live API)
- **npm** — verifierar JavaScript/TypeScript-paket mot registry.npmjs.org
- **crates.io** — verifierar Rust-crates mot crates.io API
- **Go Proxy** — verifierar Go-moduler mot proxy.golang.org
- **Versionscheck** — flaggar om angiven version inte existerar (VERSION_MISMATCH)
- **Typosquatting-skydd** — fuzzy matching mot 500+ populära paket per ekosystem. Om `import reqeusts` inte hittas, föreslås `requests`

### Layer 3: AST-analys (tree-sitter)

- Parsning till abstrakt syntaxträd för Python, JavaScript, TypeScript, Go, Rust
- Cyklomatisk komplexitet per funktion (flaggar >10)
- Oanvända variabler
- Oåtkomlig kod (efter return/raise/break)
- Djup nesting (>4 nivåer)

### Layer 4: Docker-verifiering

- Verifierar att base images existerar på Docker Hub (live API)
- Verifierar att angivna taggar existerar
- Föreslår tillgängliga taggar om den angivna saknas
- Parsning av multi-stage builds (alla FROM-direktiv)

### Layer 5: Sandbox-exekvering

- Kör kod i isolerade Docker-containrar
- Säkerhetslimiter: 256MB minne, 10s timeout, ingen nätåtkomst, read-only filesystem
- Fångar import-errors, syntax-errors, runtime-crashes
- Stöd för Python, JavaScript, Go, Rust

### Layer 6: Enterprise-strukturvalidering

- Verifierar att repot har: README, LICENSE, tester, .gitignore, pyproject.toml/package.json
- Pre-action-kontroll (innan kod skrivs): validerar planen
- Post-action-kontroll (efter kod skrivits): validerar slutresultatet
- Genererar SARIF v2.1.0-output för GitHub Security-tabben

### Layer 7: Enforcement (blockering)

- **CLAUDE.md / .cursorrules** — advisory rules direkt i projektets rot som AI läser
- **VS Code-extension** — diagnostik i editorn (squiggly lines), scan-on-save, offline-fallback
- **Pre-commit hook** — blockerar commits med BLOCK-findings. Versionskontrollerad via `core.hooksPath`
- **GitHub Action** — blockerar pull requests. Enbart PASS-resultat tillåter merge

---

## 4. Varför du ska ha CodeTrust

### Om du använder AI för kodning (Claude, GPT, Copilot, Cursor)

| Utan CodeTrust | Med CodeTrust |
|---------------|---------------|
| AI föreslår paket som inte finns — du märker det i deployment | Paketet verifieras mot registret *innan koden sparas* |
| AI lägger in API-nycklar i koden — de pushas till GitHub | Hemligheten fångas i pre-commit hook |
| AI skriver `eval(user_input)` — RCE-sårbarhet | BLOCK-finding stoppar committen |
| AI anger Docker-image som inte existerar — bygget kraschar | Image verifieras mot Docker Hub innan push |
| Ingen vet om AI-koden följer er standard | Varje scan loggas, usage trackas, rapporter genereras |

### Om du ansvarar för kodkvalitet i ett team

- **Enforced standards** — reglerna blockerar, inte bara varnar
- **Audit trail** — varje scan loggas i databasen med user ID, findings, latency
- **Ingen konfiguration** — `codetrust init` installerar alla 4 enforcement-lager på 2 sekunder
- **Offline-kapabilitet** — VS Code-extensionen och pre-commit hook fungerar utan internet

### Om du utvärderar Enterprise-verktyg

- **Self-hostbart** — kör på din egen infrastruktur
- **Free tier** — 100 scans/dag utan kostnad via cloud API
- **5 minuters setup** — `pip install codetrust && codetrust init`
- **MCP-native** — enda verktyget som byggt för att ge realtidsfeedback till AI-assistenter

---

## 5. Jämförelse mot marknaden

### Ärlig positionering

CodeTrust är **inte** ett alternativ till SonarQube eller Snyk. Det är ett **komplement** som täcker ett gap de inte adresserar. Här är en ärlig jämförelse:

### Kärnkapabilitet

| Kapabilitet | CodeTrust | SonarQube | Semgrep | Snyk |
|---|---|---|---|---|
| **Statisk kodanalys** | 49 regler, 9 språk | 5,000+ regler, 35+ språk | 3,000+ regler, 30+ språk | SAST med DeepCode AI |
| **Paketexistens-verifiering** | **Ja** (PyPI, npm, crates, Go) | Nej | Nej | Nej* |
| **Typosquatting-skydd** | **Ja** (fuzzy matching, 500+ paket/ekosystem) | Nej | Nej | Nej |
| **Docker image/tag-verifiering** | **Ja** (live Docker Hub API) | Nej | Nej | Container scanning (CVEs) |
| **MCP Server (AI-integration)** | **Ja** (10 verktyg) | Ja (nytt, 2025) | Nej | Nej |
| **AST-analys** | Ja (tree-sitter, 5 språk) | Ja (alla språk) | Ja (cross-file) | Ja |
| **SCA (kända CVE:er)** | Nej | Nej (tillägg) | Ja ($40/mån/dev) | **Ja** (kärnprodukt) |
| **Sandbox-exekvering** | Ja (isolerad Docker) | Nej | Nej | Nej |
| **SARIF-output** | Ja | Ja | Ja | Ja |
| **Offline-scanning** | **Ja** (embedded scanner) | Nej (kräver server) | **Ja** (CLI) | Nej (kräver API) |
| **Secrets detection** | Grundläggande (regex) | Ja | Ja ($20/mån/dev) | Nej |

*\* Snyk verifierar kända paket mot CVE-databaser, men verifierar inte att okända/hallucinerade paket existerar alls.*

### Där CodeTrust vinner

1. **Hallucinerade paket** — ingen annan verifierar att imports faktiskt existerar i registries
2. **Docker image-verifiering** — ingen annan kontrollerar att base images och taggar existerar
3. **MCP-native** — byggt från grunden för AI-assistenter (Claude Code, Cursor)
4. **Offline-embedded** — VS Code-extension och pre-commit hook kräver ej internet
5. **Noll konfiguration** — `codetrust init` ger 4 enforcement-lager direkt
6. **Sandbox-exekvering** — kan faktiskt köra koden isolerat för att verifiera runtime
7. **Free tier** — 100 scans/dag gratis, ingen per-seat-kostnad

### Där konkurrenterna vinner

1. **Regeldjup** — SonarQube har 5,000+ regler vs våra 49. De fångar fler kodkvalitetsproblem
2. **Språkbredd** — SonarQube stöder 35+ språk, Semgrep 30+. Vi stöder 9
3. **SCA/CVE-scanning** — Snyk och Semgrep Supply Chain mappar dependencies mot kända sårbarheter. Vi gör det inte
4. **Enterprise features** — SSO, RBAC, compliance-rapporter, portfolio management hos SonarQube/Snyk
5. **Taint analysis** — Semgrep och SonarQube gör cross-function/cross-file dataflödesanalys. Vi gör regex + AST
6. **Community & ekosystem** — SonarQube har 7M+ användare, Snyk likaså. Vi är nya

### Prisens roll

| Verktyg | Kostnad vid 10 utvecklare |
|---------|--------------------------|
| **CodeTrust** | **$0** (Free-tier, 100 scans/dag) |
| **SonarQube Cloud** Team | ~$32/mån (100K LOC) |
| **Semgrep** Teams SAST | $400/mån ($40/dev × 10) |
| **Semgrep** + SCA + Secrets | $1,000/mån ($100/dev × 10) |
| **Snyk** Team | $250/mån ($25/dev × 10) |
| **Snyk** Ignite | $12,600/år (~$1,050/mån) |

**CodeTrust kostar noll för det som konkurrenterna inte ens erbjuder** (paketexistens-verifiering, Docker tag-verifiering, MCP-integration, offline enforcement).

---

## 6. Paketering & priser

### Tiers

| | Free | Pro | Enterprise |
|---|---|---|---|
| **Pris** | $0 | Planerad | Planerad |
| **Scans/dag** | 100 | 10,000 | 100,000 |
| **Statisk analys** | Alla regler | Alla regler | Alla regler |
| **Paketverifiering** | PyPI, npm, Go, crates | + prioriterad queue | + SLA |
| **Docker-verifiering** | Ja | Ja | Ja |
| **AST-analys** | Ja | Ja | Ja |
| **Sandbox** | Ja (self-hosted) | Ja | Ja |
| **MCP Server** | Ja | Ja | Ja |
| **CLI** | Ja | Ja | Ja |
| **VS Code Extension** | Ja | Ja | Ja |
| **GitHub Action** | Ja | Ja | Ja |
| **SARIF output** | Ja | Ja | Ja |
| **API-access** | Cloud API | Cloud API | Dedicated |
| **Support** | Community | Email | Dedicated |
| **SLA** | — | — | 99.9% |

### Vad ingår alltid gratis (Free tier)

- CLI (`codetrust scan`, `codetrust init`)
- Pre-commit hook (offline)
- VS Code extension med embedded scanner (offline)
- CLAUDE.md / .cursorrules installation
- GitHub Action template
- MCP Server (self-hosted)
- Samtliga 49 analysregler
- AST-analys (tree-sitter)

### Vad kräver cloud/API

- Paketverifiering mot registries (kräver HTTP till PyPI/npm/etc.)
- Docker-verifiering (kräver HTTP till Docker Hub)
- Scan-loggning och usage tracking
- API key management
- Usage analytics

---

## 7. Installation & aktivering

### Metod 1: CLI (rekommenderat)

```bash
# Installera CodeTrust
pip install codetrust

# Installera alla enforcement-lager i ditt projekt
cd mitt-projekt
codetrust init
```

`codetrust init` installerar automatiskt:

1. `CLAUDE.md` — regler som AI-assistenter följer
2. `.cursorrules` — regler för Cursor AI
3. `hooks/pre-commit` — blockerar commits med anti-patterns
4. `.github/workflows/codetrust-scan.yml` — GitHub Action för PR-scanning
5. `git config core.hooksPath hooks` — aktiverar hooks

### Metod 2: MCP Server (för Claude Code / Claude Desktop)

```json
{
  "mcpServers": {
    "codetrust": {
      "command": "python",
      "args": ["-m", "src.server"],
      "cwd": "/path/to/codetrust"
    }
  }
}
```

Ger AI-assistenten tillgång till 10 verifieringsverktyg som körs i realtid.

### Metod 3: VS Code Extension

```bash
# Installera extension
code --install-extension codetrust.codetrust
```

- Scan-on-save
- Diagnostik som squiggly lines
- Quick-fix-förslag
- Offline-fallback (kräver ej API)

### Metod 4: Cloud API

```bash
curl -X POST https://codetrust-api-production.up.railway.app/v1/scan/static \
  -H "Content-Type: application/json" \
  -H "X-API-Key: din-nyckel" \
  -d '{"code": "import os\neval(input())", "filename": "app.py"}'
```

19 REST-endpoints. Full OpenAPI-dokumentation.

### Metod 5: GitHub Action (CI/CD)

```yaml
# .github/workflows/codetrust-scan.yml
name: CodeTrust
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: '3.12' }
      - run: pip install codetrust
      - run: codetrust scan .
```

---

## 8. Arkitektur & integrationspunkter

```
┌─────────────────────────────────────────────────┐
│        Developer / AI Assistant                  │
│  (Claude Code, Cursor, Copilot, VS Code)         │
└──────┬──────────┬──────────┬──────────┬──────────┘
       │          │          │          │
       │ MCP      │ HTTP     │ CLI      │ Extension
       │          │          │          │
┌──────▼──┐  ┌────▼───┐  ┌──▼───┐  ┌───▼────────┐
│MCP Server│  │FastAPI │  │ CLI  │  │VS Code Ext │
│10 tools  │  │19 endp.│  │4 cmd │  │Offline scan│
└──────┬───┘  └───┬────┘  └──┬───┘  └───┬────────┘
       │          │          │          │
       └──────────┼──────────┘          │
                  │                     │
        ┌─────────▼─────────────────────┘
        │       Service Layer
        │  ┌─────────────────────────┐
        │  │ Static Analyzer (regex) │
        │  │ AST Analyzer (treesit.) │
        │  │ Registry Verifier       │
        │  │ Docker Verifier         │
        │  │ Sandbox Service         │
        │  │ Auth + Rate Limiter     │
        │  │ Billing (Stripe)        │
        │  └─────────────────────────┘
        │               │
        │  ┌─────────────▼───────────┐
        │  │ PostgreSQL  │  Redis    │
        │  │ Users/Keys  │  Cache    │
        │  │ Scan logs   │  TTL      │
        │  │ Usage       │          │
        │  └─────────────┴───────────┘
        │
   ┌────▼──────────────────────────┐
   │   External Registries         │
   │  PyPI │ npm │ crates │ Go    │
   │  Docker Hub                   │
   └───────────────────────────────┘
```

### Enforcement-stack (4 lager)

```
Layer 1 — Advisory        CLAUDE.md / .cursorrules
                          AI läser reglerna, men kan ignorera dem
                          ↓
Layer 2 — Passive         VS Code Extension
                          Visar diagnostik, föreslår fixar
                          Blockerar inte
                          ↓
Layer 3 — Blocking        Pre-commit hook (core.hooksPath)
                          BLOCK-findings = commit avvisas
                          Människa/AI kan inte kringgå
                          ↓
Layer 4 — Absolute        GitHub Action + branch protection
                          BLOCK-findings = PR kan ej mergas
                          Kräver grön status check
```

---

## 9. Lansering & distribution

### Distributionskanaler

| Kanal | Status | URL/Command |
|-------|--------|-------------|
| **PyPI** | **Live** | `pip install codetrust` — [pypi.org/project/codetrust](https://pypi.org/project/codetrust/) |
| **VS Code Marketplace** | **Live** | `ext install SaidBorna.codetrust` — [marketplace.visualstudio.com](https://marketplace.visualstudio.com/items?itemName=SaidBorna.codetrust) |
| **Website** | **Live** | [codetrust.saidborna.com](https://codetrust.saidborna.com) |
| **GitHub** | **Live** | [github.com/S-Borna/codetrust](https://github.com/S-Borna/codetrust) |
| **Docker Hub** | Planerad | `docker pull codetrust/codetrust` |
| **Railway (cloud)** | **Live** | [codetrust-api-production.up.railway.app](https://codetrust-api-production.up.railway.app) |

### Installera via PyPI

```bash
pip install codetrust
codetrust scan .             # skanna aktuellt projekt
codetrust init               # installera enforcement-lager
codetrust doctor             # verifiera installation
```

### Installera VS Code Extension

```bash
# Från Marketplace (i VS Code)
# Sök "CodeTrust" i Extensions-panelen

# Eller via CLI
code --install-extension SaidBorna.codetrust
```

### Self-hosting (Docker)

```bash
docker compose up -d         # API + Redis + PostgreSQL
```

### Self-hosting (Railway)

```bash
railway up                   # deployar till Railway
```

---

## 10. Vanliga frågor (FAQ)

### Generellt

**Q: Är CodeTrust gratis?**
CodeTrust har en generös free tier. CLI, pre-commit hook, VS Code extension och MCP server är gratis att använda. Cloud API har en free tier (100 scans/dag).

**Q: Varför behöver jag CodeTrust om jag redan har SonarQube/Snyk/Semgrep?**
De verktygen hittar kodkvalitetsproblem och kända CVE:er i kända paket. CodeTrust löser ett annat problem: att verifiera att det AI föreslår *överhuvudtaget existerar och fungerar*. Ett paket utan CVE:er men som inte existerar kraschar din applikation. Använd CodeTrust *tillsammans med* befintliga verktyg.

**Q: Fungerar CodeTrust offline?**
Delvis. Statisk analys (49 regler), AST-analys, pre-commit hook och VS Code-extensionens embedded scanner fungerar fullt offline. Paketverifiering och Docker-verifiering kräver internet (de kontaktar registries).

**Q: Vilka språk stöds?**
Python, JavaScript, TypeScript, Go, Rust, Java, Shell, Dockerfile, YAML. AST-analys via tree-sitter stöder de fem första.

**Q: Hur snabbt är det?**
Statisk analys: <100ms. Paketverifiering: ~500ms (med cache: <50ms). Full deep scan: ~1–2 sekunder. GitHub Action scan: ~10 sekunder.

### Teknik

**Q: Vad är MCP?**
Model Context Protocol — ett öppet protokoll från Anthropic som ger AI-assistenter (Claude Code, Cursor) tillgång till externa verktyg. CodeTrust exponerar 10 MCP-verktyg som AI:n anropar automatiskt medan den skriver kod.

**Q: Kan AI tvingas följa reglerna?**
Layer 1 (CLAUDE.md) och Layer 2 (VS Code extension) är advisory — AI kan ignorera dem. Men Layer 3 (pre-commit hook) och Layer 4 (GitHub Action + branch protection) är infrastrukturnivå. Varken AI eller människa kan kringgå dem.

**Q: Vad händer om Redis inte är tillgängligt?**
CodeTrust degraderar graciöst. Caching inaktiveras, allt fungerar utan Redis. Svarstiden för paketverifiering ökar (varje request går till registret direkt).

**Q: Kan jag skriva egna regler?**
Reglerna definieras som regex-mönster i `src/rules/anti_patterns.py`. Du kan lägga till egna regler direkt i kodbasen. Regex-format med BLOCK/WARN/INFO-severity.

### Säkerhet

**Q: Är sandbox-exekveringen säker?**
Ja. Containrar körs med `--network=none`, `--read-only`, `--memory=256m`, `--pids-limit=64`, och 10 sekunders timeout. Ingen nätåtkomst, ingen persistent lagring, inga privilegier.

**Q: Skickas min kod till tredjeparter?**
Aldrig. MCP-servern körs lokalt. CLI:n körs lokalt. Pre-commit hook körs lokalt. Cloud API:n (om du använder den) körs på din Railway-instans som du kontrollerar. Ingen kod skickas till Anthropic, OpenAI, eller någon annan.

**Q: Hur hanteras API-nycklar?**
API-nycklar lagras som SHA-256-hashar i databasen (aldrig i klartext). De har formatet `ct_live_*` för identifiering. Nycklar kan skapas, listas och revokeras via API.

### Affär

**Q: Finns det vendor lock-in?**
Nej. CodeTrust körs lokalt via CLI, extension och MCP-server. Cloud API finns som option men krävs inte.

**Q: Vilka kunder passar CodeTrust för?**

- **Solo-utvecklare** som använder AI för kodning → gratis CLI
- **Startup-team** (2–20 utvecklare) → CLI + GitHub Action + VS Code extension
- **Enterprise** → Self-hostad API + SARIF + branch protection + scan logging

**Q: Hur skiljer sig CodeTrust från en linter?**
En linter (ruff, ESLint) kontrollerar stil och syntax. CodeTrust verifierar att koden *fungerar i verkligheten*: att importerade paket existerar, att Docker-images existerar, att hemligheter inte läcker, att mönster är säkra. Det är verifiering, inte formatering.

---

## Bilagor

### A. Alla 19 API-endpoints

| Method | Endpoint | Beskrivning |
|--------|----------|-------------|
| GET | `/v1/status` | Hälsokontroll |
| POST | `/v1/scan/static` | Statisk analys |
| POST | `/v1/scan/static/sarif` | Statisk analys (SARIF) |
| POST | `/v1/scan/ast` | AST-analys |
| POST | `/v1/scan/deep` | Full deep scan |
| POST | `/v1/scan/deep/sarif` | Deep scan (SARIF) |
| POST | `/v1/verify/imports` | Paketverifiering |
| POST | `/v1/verify/dockerfile` | Docker-verifiering |
| POST | `/v1/sandbox/run` | Sandbox-exekvering |
| POST | `/v1/api-keys` | Skapa API-nyckel |
| GET | `/v1/api-keys` | Lista API-nycklar |
| DELETE | `/v1/api-keys/{id}` | Radera API-nyckel |
| GET | `/v1/scans/history` | Scan-historik |
| GET | `/v1/usage` | Användningsstatistik |
| POST | `/v1/billing/checkout` | Stripe checkout |
| POST | `/v1/billing/portal` | Stripe-portal |
| POST | `/v1/webhooks/stripe` | Stripe-webhook |
| POST | `/v1/auth/github` | GitHub OAuth |
| GET | `/v1/profile` | Användarprofil |

### B. Alla 10 MCP-verktyg

| Verktyg | Beskrivning |
|---------|-------------|
| `codetrust_static_scan` | Skanna kod för antipatterns |
| `codetrust_ast_scan` | AST-baserad analys |
| `codetrust_pre_action` | Validera plan innan kodning |
| `codetrust_post_action` | Validera slutresultat |
| `codetrust_list_rules` | Lista alla regler |
| `codetrust_verify_imports` | Verifiera paket mot registries |
| `codetrust_verify_dockerfile` | Verifiera Docker-images |
| `codetrust_deep_scan` | Full verifiering (alla lager) |
| `codetrust_sandbox_run` | Kör kod i isolerad sandbox |
| `codetrust_sarif_export` | Exportera resultat som SARIF |

### C. Alla analysregler (BLOCK)

| Regel | Mönster | Beskrivning |
|-------|---------|-------------|
| `heredoc` | `<<[-']?\w+` | Heredoc-syntax. Använd template files |
| `hardcoded_secret` | API-nycklar/lösenord i strängar | Möjlig hårdkodad hemlighet |
| `eval_exec` | `eval()`/`exec()` | Säkerhetsrisk — remote code execution |
| `sql_injection` | f-string/format i execute() | SQL-injection via strängformattering |
| `pickle_load` | `pickle.load()` | Osäkert med otillförlitlig data |

### D. Alla analysregler (WARN)

| Regel | Beskrivning |
|-------|-------------|
| `todo_hack` | TODO/HACK/FIXME-markör |
| `console_log` | console.log istället för logger |
| `print_debug` | print() istället för logging |
| `wildcard_import` | `from x import *` |
| `bare_except` | `except:` utan specifikt undantag |
| `any_type` | `: Any` typning |
| `nested_ternary` | Nästlad ternary-operator |
| `mutable_default` | Mutable default-argument |
| `magic_number` | Magiskt nummer utan namngivning |
| `long_function` | Funktion >40 rader |

---

*CodeTrust v1.8.0 — Proprietary License — Built for the AI coding era.*
