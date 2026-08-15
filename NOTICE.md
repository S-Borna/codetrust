# Third-Party Notices

CodeTrust is proprietary software (see [LICENSE](LICENSE)) that depends on
open-source components. This file lists direct runtime dependencies and their
licenses, as required for attribution under their respective terms.

## Python (CLI, API, MCP servers)

| Package | License | Project |
|---|---|---|
| mcp | MIT | https://modelcontextprotocol.io |
| pydantic, pydantic-settings | MIT | https://github.com/pydantic/pydantic |
| fastapi | MIT | https://github.com/fastapi/fastapi |
| uvicorn | BSD-3-Clause | https://uvicorn.dev |
| httpx, httpx-sse | BSD License / MIT | https://github.com/encode/httpx |
| redis | MIT | https://github.com/redis/redis-py |
| structlog | MIT OR Apache-2.0 | https://github.com/hynek/structlog |
| tree-sitter, tree-sitter-python/javascript/typescript/go/rust/java/c-sharp/cpp/ruby/php | MIT | https://tree-sitter.github.io/tree-sitter/ |
| sqlalchemy | MIT | https://www.sqlalchemy.org |
| alembic | MIT | https://alembic.sqlalchemy.org |
| asyncpg | Apache-2.0 | https://github.com/MagicStack/asyncpg |
| stripe | MIT | https://stripe.com |
| PyJWT | MIT | https://github.com/jpadilla/pyjwt |
| psycopg2-binary | LGPL | https://psycopg.org — used unmodified as a dynamic dependency; not statically linked or redistributed as source |

Full transitive dependency list with licenses: run `pip-licenses` in a project
virtualenv, or `codetrust license` to check a target project's own dependency
licenses for compliance.

## VS Code Extension

The extension has no runtime dependencies (`extension/package.json` has an
empty `dependencies` field) — the published `.vsix` ships a minified,
obfuscated bundle of first-party CodeTrust code only, no third-party runtime
code. `extension/package.json` and its `package-lock.json` list build-time
tooling only (esbuild, TypeScript, vsce, mocha, and similar), used to produce
the bundle but never shipped in it.

## Dashboard

Bundled JavaScript dependencies (Next.js, React, and others) and their
licenses are listed in `dashboard/package.json` and its `package-lock.json`.

## No warranty from upstream projects

Use of these third-party components does not imply endorsement by their
authors. Each remains licensed under its own terms; this notice does not
modify or supersede those terms.
