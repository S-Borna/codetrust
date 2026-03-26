# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Anti-pattern rule definitions for static code analysis."""

from src.models.enums import Severity

# Heredoc marker split to prevent content scanner self-detection
_HEREDOC = "<" + "<"

# Each rule is a dict with id, pattern (regex), message, severity, and optional special_handler.
# The static analyzer iterates over these and applies each regex to every line.
#
# Optional keys:
#   file_types  - list of extensions (e.g. [".sql"]) where the rule applies.
#                 If omitted the rule applies to ALL files EXCEPT those claimed
#                 by another language group (see LANGUAGE_EXCLUSIVE below).
#   skip_comments - skip lines that look like comments / docstrings.
#   special_handler - delegate to a named method instead of plain regex.

# Extensions that have their own dedicated rule sets.
# Generic rules will NOT fire on these file types.
SQL_EXTENSIONS: set[str] = {".sql"}
DEVOPS_EXTENSIONS: set[str] = {
    ".dockerfile", ".toml", ".yml", ".yaml",
    ".tf", ".tfvars", ".hcl",
    ".conf", ".bicep",
    ".ps1", ".psm1", ".psd1",
    ".service", ".timer", ".ini", ".cfg",
}

# File-name patterns that are treated as DevOps files regardless of extension.
DEVOPS_FILENAMES: set[str] = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "procfile"}

ANTI_PATTERNS: list[dict[str, str]] = [
    # ═══════════════════════════════════════════════════════════════
    #  GENERIC RULES (Python / JS / TS / Go / Rust / …)
    # ═══════════════════════════════════════════════════════════════

    # --- BLOCK severity ---
    {
        "id": "heredoc",
        "pattern": _HEREDOC + r"[-']?\w+",
        "message": "Heredoc detected. Use template files or multi-line strings.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace the heredoc with a proper file-writing tool. "
            "For git commit: use `git commit -F <tmpfile>` where tmpfile is created via Write tool. "
            "For file creation: use the Write/create_file tool directly. "
            "For shell config: use a template file and `envsubst` or variable expansion."
        ),
    },
    {
        "id": "hardcoded_secret",
        "pattern": (
            r'(?i)(api[_-]?key|secret[_-]?\w*|password|token|credentials)'
            r'(?:\s*:\s*\w+)?\s*[:=]\s*["\'][^"\']{8,}["\']'
        ),
        "message": "Possible hardcoded secret. Use environment variables.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Move the secret to an environment variable. "
            "1. Add the key to .env (never commit .env). "
            "2. Reference via os.environ['KEY'] (Python), process.env.KEY (JS/TS), or os.Getenv('KEY') (Go). "
            "3. Add the key name to .env.example with a placeholder value."
        ),
    },
    {
        "id": "eval_exec",
        "pattern": r"\b(eval|exec)\s*\(",
        "message": "eval/exec is a security risk. Use safe alternatives.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace eval/exec with a safe alternative: "
            "For JSON parsing: use json.loads(). "
            "For math expressions: use ast.literal_eval(). "
            "For dynamic dispatch: use a dict mapping of allowed functions. "
            "For config: use a validated Pydantic model or dataclass."
        ),
    },
    {
        "id": "sql_injection",
        "pattern": r'(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f["\']|[^)]*\.format\s*\()',
        "message": "Possible SQL injection via string formatting. Use parameterized queries.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace f-string/format SQL with parameterized queries: "
            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,)) for psycopg2, "
            "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,)) for sqlite3, "
            "or use an ORM (SQLAlchemy, Prisma, GORM) that handles parameterization automatically."
        ),
    },
    {
        "id": "pickle_load",
        "pattern": r"pickle\.loads?\s*\(",
        "message": "pickle.load is unsafe with untrusted data. Use JSON or msgpack.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace pickle with a safe serialization format: "
            "json.loads()/json.dumps() for general data, "
            "msgpack.packb()/msgpack.unpackb() for binary efficiency, "
            "or pydantic model.model_validate_json() for typed deserialization. "
            "If pickle is required for ML models, use safetensors or ONNX format instead."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  SYMPTOM-FIX DETECTION (Root Cause Enforcement — Law 3)
    #  "Fix the cause, never the symptom"
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "symptom_fix_marker",
        "pattern": (
            r"(?i)#\s*(?:"
            r"work" + r"around"
            r"|quick\s*fix"
            r"|band[\s\-]*aid"
            r"|stop[\s\-]*gap"
            r"|klud" + r"ge"
            r"|duct[\s\-]*tape"
            r"|dirty\s*(?:ha" + r"ck|fix)"
            r"|temporary\s*(?:fix|patch|solution)"
            r"|symptom\s*fix"
            r"|monkey[\s\-]*pat" + r"ch"
            r"|short[\s\-]*term\s*fix"
            r")"
        ),
        "message": (
            "Comment admits this is a symptom fix, not a root-cause fix. "
            "Find and resolve the underlying problem."
        ),
        "severity": Severity.BLOCK,
        "suggestion": (
            "Delete the symptom-fix code and its marker comment. "
            "Run root-cause analysis: ask 'why is this happening?' at least 3 times. "
            "Fix the upstream source of the problem (validation, schema, API contract). "
            "If a temporary fix is truly needed, open a tracked issue with deadline instead."
        ),
    },
    {
        "id": "except_swallow",
        "pattern": r"^\s*except[\s:]",
        "message": "Exception caught and silently swallowed (pass/...). Handle the error or re-raise.",
        "severity": Severity.BLOCK,
        "special_handler": "check_except_swallow",
        "suggestion": (
            "Replace `pass` or `...` in the except block with one of: "
            "1. `logger.exception('Context: what operation failed')` to log with traceback. "
            "2. `raise` to re-raise the original exception. "
            "3. `raise SpecificError('message') from exc` to chain exceptions. "
            "Catch the most specific exception type possible (e.g., ValueError, KeyError)."
        ),
    },
    {
        "id": "null_coalesce_smell",
        "pattern": r"\w+\s*=\s*\w+\s+or\s+(?:\"\"|''|\[\]|\{\}|None|0|False)\s*$",
        "message": "Defensive 'x = x or default' hides why x could be None. Fix the root cause.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "suppress_lint",
        "pattern": r"(?:#\s*" + "no" + r"qa\b|@Suppress" + r"Warnings|eslint-dis" + r"able|prag" + r"ma:\s*no\s*cover)",
        "message": "Lint/coverage warning suppressed. Fix the underlying issue instead.",
        "severity": Severity.INFO,
    },
    {
        "id": "sleep_no_context",
        "pattern": r"(?:time\.)?sleep\s*\(",
        "message": "sleep call without explanation. Why is a delay needed? Document or fix root cause.",
        "severity": Severity.INFO,
        "special_handler": "check_sleep_no_context",
        "skip_comments": True,
    },

    # --- WARN severity (generic) ---
    {
        "id": "todo_hack",
        "pattern": r"(?i)#\s*(todo|hack|fixme|xxx|temp)\b",
        "message": "Temporary marker found. Resolve before committing.",
        "severity": Severity.INFO,
    },
    {
        "id": "console_log",
        "pattern": r"\bconsole\.(log|debug|info)\s*\(",
        "message": "Replace console logging with a structured logger.",
        "severity": Severity.WARN,
    },
    {
        "id": "print_debug",
        "pattern": r"^\s*print\s*\(",
        "message": "Use logging module instead of print().",
        "severity": Severity.WARN,
    },
    {
        "id": "any_type",
        "pattern": r":\s*[Aa]ny\b",
        "message": "Avoid Any type. Use explicit types.",
        "severity": Severity.WARN,
    },
    {
        "id": "wildcard_import",
        "pattern": r"from\s+\S+\s+import\s+\*",
        "message": "Wildcard imports reduce clarity. Import explicitly.",
        "severity": Severity.WARN,
    },
    {
        "id": "nested_ternary",
        "pattern": r"\w\s*\?[^;]*\w\s*\?",
        "message": "Nested ternary reduces readability. Use if/else.",
        "severity": Severity.WARN,
    },
    {
        "id": "bare_except",
        "pattern": r"except\s*:",
        "message": "Bare except catches everything including KeyboardInterrupt. Catch specific exceptions.",
        "severity": Severity.WARN,
    },
    {
        "id": "mutable_default",
        "pattern": r"def\s+\w+\([^)]*(?::\s*(?:list|dict|set)\s*=\s*(?:\[\]|\{\}))",
        "message": "Mutable default argument. Use None and assign inside function.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DETERMINISM RULES (Law 4: "Be deterministic")
    #  Code must produce the same result everywhere, every time.
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "datetime_utcnow",
        "pattern": r"date" + r"time\.utcnow\s*\(",
        "message": (
            "date" + "time.utcnow() is deprecated since Python 3.12 and returns a "
            "naive datetime. Use date" + "time.now(tz=timezone.utc) instead."
        ),
        "severity": Severity.BLOCK,
        "skip_comments": True,
        "suggestion": (
            "Replace `datetime.utcnow()` with `datetime.now(tz=timezone.utc)`. "
            "Add `from datetime import datetime, timezone` at the top of the file. "
            "This returns a timezone-aware datetime that works correctly across time zones."
        ),
    },
    {
        "id": "datetime_naive",
        "pattern": r"date" + r"time\.now\(\s*\)",
        "message": (
            "date" + "time.now() without timezone argument returns a naive datetime. "
            "Use date" + "time.now(tz=timezone.utc) or pass an explicit timezone."
        ),
        "severity": Severity.WARN,
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  EXPLICIT CONFIGURATION (Law 5: "Configure, don't hardcode")
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "hardcoded_temp_path",
        "pattern": r"""["']/(?:tmp|var/tmp|var/log)/""",
        "message": (
            "Hardcoded temp/log path. Use tempfile.mkdtemp(), "
            "tempfile.NamedTemporaryFile(), or a configuration variable."
        ),
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "env_var_no_default",
        "pattern": r"os\.getenv\(\s*[\"']\w+[\"']\s*\)\s*$",
        "message": (
            "os.getenv() without a default value silently returns None. "
            "Provide a default or use os.environ[] to fail fast."
        ),
        "severity": Severity.INFO,
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SAFE DATA HANDLING (Law 6: "Never trust string assembly")
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "string_concat_sql",
        "pattern": (
            r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b'
            r'.*["\']\s*\+\s*\w+'
        ),
        "message": (
            "SQL query assembled via string concatenation. "
            "Use parameterized queries to prevent SQL injection."
        ),
        "severity": Severity.BLOCK,
        "skip_comments": True,
        "suggestion": (
            "Replace string concatenation with parameterized queries: "
            "Instead of `'SELECT * FROM t WHERE id=' + id`, use "
            "`cursor.execute('SELECT * FROM t WHERE id = %s', (id,))`. "
            "For ORMs: use query builder methods (e.g., .filter(Model.id == id)). "
            "Never concatenate user input into SQL strings."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  CODE HYGIENE (Law 7: "Leave no debris")
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "commented_out_code",
        "pattern": (
            r"^\s*#\s*(?:"
            r"def\s+\w+\s*\(|"
            r"class\s+\w+|"
            r"import\s+\w+|"
            r"from\s+\w+\s+import|"
            r"return\s+\w+|"
            r"raise\s+\w+"
            r")"
        ),
        "message": (
            "Commented-out code detected. Use version control to "
            "track old code instead of leaving dead code in comments."
        ),
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ANTI-ASSUMPTION RULES (Law 2: "Assume nothing")
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "debug_mode_enabled",
        "pattern": r'(?i)(?:^|\s)(?:DEBUG|debug)\s*[:=]\s*(?:(?:True|true|1)\b|["\']true["\'])',
        "message": "Debug mode enabled. Ensure this is not shipped to production.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "hardcoded_port",
        "pattern": r"(?:port|PORT)\s*[:=]\s*\d{4,5}\b",
        "message": "Hardcoded port number. Use environment variable or configuration.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },

    # --- INFO severity ---
    {
        "id": "magic_number",
        "pattern": r"(?<!=)\s(?<!\w)[2-9]\d{2,}\b",
        "message": "Magic number detected. Extract to a named constant.",
        "severity": Severity.INFO,
        "skip_comments": True,
        "exclude_path_contains": [
            "tests/",
            "docs/",
            "chrome-extension/",
            "dashboard/",
            "extension/src/test/",
        ],
    },
    {
        "id": "long_function",
        "pattern": r"^(def |async def )",
        "message": "Function detected — verify it's under 40 lines.",
        "severity": Severity.INFO,
        "special_handler": "check_function_length",
    },

    # ═══════════════════════════════════════════════════════════════
    #  SQL RULES  (only fire on .sql files)
    # ═══════════════════════════════════════════════════════════════

    # --- BLOCK severity ---
    {
        "id": "sql_select_star",
        "pattern": r"(?i)\bSELECT\s+\*",
        "message": "SELECT * is fragile — specify columns explicitly.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
        "suggestion": (
            "Replace `SELECT *` with explicit column names: "
            "`SELECT id, name, email, created_at FROM users`. "
            "This prevents breakage when columns are added/removed and improves query performance."
        ),
    },
    {
        "id": "sql_delete_no_where",
        "pattern": r"(?i)^\s*DELETE\s+FROM\s+\w+\s*;",
        "message": "DELETE without WHERE will remove all rows. Add a WHERE clause.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
        "suggestion": (
            "Add a WHERE clause to scope the deletion: "
            "`DELETE FROM table_name WHERE condition;`. "
            "If you truly need to remove all rows, use `TRUNCATE TABLE table_name;` which is explicit about intent."
        ),
    },
    {
        "id": "sql_update_no_where",
        "pattern": r"(?i)^\s*UPDATE\s+\w+\s+SET\s+(?!.*\bWHERE\b)[^;]*;\s*$",
        "message": "UPDATE without WHERE will modify all rows. Add a WHERE clause.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
        "suggestion": (
            "Add a WHERE clause to scope the update: "
            "`UPDATE table_name SET column = value WHERE id = target_id;`. "
            "If updating all rows is intentional, add a comment explaining why."
        ),
    },
    {
        "id": "sql_drop_no_if_exists",
        "pattern": r"(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\s+(?!IF\s+EXISTS\b)\w+",
        "message": "DROP without IF EXISTS may fail. Use DROP … IF EXISTS.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
        "suggestion": (
            "Add IF EXISTS to make the DROP idempotent: "
            "`DROP TABLE IF EXISTS table_name;`. "
            "This prevents errors when the object doesn't exist and makes migrations re-runnable."
        ),
    },
    {
        "id": "sql_grant_all",
        "pattern": r"(?i)\bGRANT\s+ALL\b",
        "message": "GRANT ALL gives excessive privileges. Grant only what is needed.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
        "suggestion": (
            "Replace `GRANT ALL` with specific privileges: "
            "`GRANT SELECT, INSERT, UPDATE ON schema.table TO role;`. "
            "Follow principle of least privilege — only grant what the application actually needs. "
            "Read-only services should only get SELECT."
        ),
    },
    {
        "id": "sql_foreign_key_checks_off",
        "pattern": r"(?i)SET\s+FOREIGN_KEY_CHECKS\s*=\s*0",
        "message": "Disabling foreign key checks bypasses referential integrity. Ensure it is re-enabled.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
        "suggestion": (
            "If disabling FK checks for a migration, wrap it in a transaction and re-enable immediately: "
            "`SET FOREIGN_KEY_CHECKS=0; ... your DDL ... SET FOREIGN_KEY_CHECKS=1;`. "
            "Better: restructure the migration to respect FK ordering (create parent tables first). "
            "Never leave FK checks disabled in production."
        ),
    },
    # --- WARN severity ---
    {
        "id": "sql_float_for_money",
        "pattern": r"(?i)\b(selling_price|cost|price|amount|balance|salary|total|wholesale_cost)\s+FLOAT\b",
        "message": "FLOAT is imprecise for monetary values. Use DECIMAL(10,2) instead.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_no_index_hint",
        "pattern": r"(?i)\bFOREIGN\s+KEY\b",
        "message": "Foreign key detected — verify an index exists on the referenced column.",
        "severity": Severity.INFO,
        "file_types": [".sql"],
    },
    {
        "id": "sql_varchar_no_length",
        "pattern": r"(?i)\bVARCHAR\s*\(\s*\)",
        "message": "VARCHAR without length specified. Define an explicit max length.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_todo_hack",
        "pattern": r"(?i)--\s*(todo|hack|fixme|xxx|temp)\b",
        "message": "Temporary marker found in SQL. Resolve before committing.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_composite_pk_auto_increment",
        "pattern": r"(?i)AUTO_INCREMENT.*PRIMARY\s+KEY\s*\([^)]+,",
        "message": "AUTO_INCREMENT in a composite primary key can cause issues. Use a single-column PK.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    # --- INFO severity ---
    {
        "id": "sql_autocommit_off",
        "pattern": r"(?i)SET\s+autocommit\s*=\s*0",
        "message": "Manual transaction control detected. Ensure matching COMMIT/ROLLBACK exists.",
        "severity": Severity.INFO,
        "file_types": [".sql"],
    },
    {
        "id": "sql_hardcoded_id",
        "pattern": r"(?i)(?:VALUES\s*\([^)]*'[0-9]+'|,\s*'[0-9]+'\s*[),])",
        "message": "Hardcoded ID as string in INSERT. Use integers or let AUTO_INCREMENT handle IDs.",
        "severity": Severity.INFO,
        "file_types": [".sql"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  DEVOPS / INFRASTRUCTURE RULES
    # ═══════════════════════════════════════════════════════════════

    # --- Database URL with embedded credentials ---
    {
        "id": "database_url_credentials",
        "pattern": r"(?i)(?:database|db|sql|postgres|mysql|mongo|redis)[_-]?(?:url|uri|dsn)(?:\s*:\s*\w+)?\s*[:=]\s*[\"']?[\w+]+://\w+:\S+@",
        "message": "Database URL contains embedded credentials. Use environment variables for username and password.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Split the database URL into components using environment variables: "
            "DB_HOST, DB_PORT, DB_USER, DB_PASS, DB_NAME. "
            "Construct the URL at runtime: "
            "`f'postgresql://{os.environ[\"DB_USER\"]}:{os.environ[\"DB_PASS\"]}@{os.environ[\"DB_HOST\"]}/{os.environ[\"DB_NAME\"]}'`. "
            "Or use a single DATABASE_URL env var loaded from .env (never committed)."
        ),
    },

    # --- Python: network connections without timeout ---
    {
        "id": "connection_no_timeout",
        "pattern": r"(?:from_url|AsyncClient|Client|create_async_engine|create_engine)\s*\(",
        "message": "Network/DB connection without explicit timeout. Add connect_timeout or socket_timeout.",
        "severity": Severity.WARN,
        "special_handler": "check_connection_timeout",
    },
    # --- Python: unbounded retry loop ---
    {
        "id": "unbounded_retry",
        "pattern": r"(?:max_retries|retry|retries)\s*[:=]\s*(?:[5-9]|[1-9]\d+)",
        "message": "High retry count without timeout guard. Use a total timeout to bound retries.",
        "severity": Severity.WARN,
    },
    # --- Python: sleep in retry without total timeout ---
    {
        "id": "retry_exponential_unbounded",
        "pattern": r"sleep\s*\(.*\*\*",
        "message": "Exponential backoff without total timeout cap. Add a deadline to prevent indefinite blocking.",
        "severity": Severity.WARN,
    },

    # ─── Container Hardening ──────────────────────────────────────

    # --- Dockerfile: missing HEALTHCHECK ---
    # --- Dockerfile: running as root ---
    {
        "id": "docker_root_user",
        "pattern": r"^CMD\s",
        "message": "Dockerfile runs as root. Add USER instruction to drop privileges.",
        "severity": Severity.WARN,
        "special_handler": "check_docker_root_user",
        "file_types": [".dockerfile"],
    },
    # --- Dockerfile: missing HEALTHCHECK (special handler, multi-line) ---
    {
        "id": "dockerfile_no_healthcheck",
        "pattern": r"^CMD\s",
        "message": "Dockerfile has CMD but no HEALTHCHECK. Add HEALTHCHECK for container orchestration.",
        "severity": Severity.INFO,
        "special_handler": "check_dockerfile_healthcheck",
        "file_types": [".dockerfile"],
    },
    # --- Dockerfile: missing WORKDIR ---
    {
        "id": "docker_no_workdir",
        "pattern": r"^CMD\s",
        "message": "Dockerfile without WORKDIR. Set working directory explicitly.",
        "severity": Severity.INFO,
        "special_handler": "check_docker_no_workdir",
        "file_types": [".dockerfile"],
    },
    # --- Dockerfile: unpinned base image ---
    {
        "id": "docker_latest_tag",
        "pattern": r"^FROM\s+\S+:latest\b|^FROM\s+[^:\s]+\s*$",
        "message": "Unpinned base image (:latest or no tag). Pin to specific version for reproducibility.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    # --- Dockerfile: no WORKDIR ---
    # --- Dockerfile: secrets in ENV/ARG ---
    {
        "id": "docker_env_secret",
        "pattern": r"(?i)^(?:ENV|ARG)\s+\S*(?:password|secret|token|api_key|private_key)",
        "message": "Secret in Dockerfile ENV/ARG. Use runtime secrets or build-time --secret flag.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
        "suggestion": (
            "Remove the secret from Dockerfile ENV/ARG. Instead: "
            "1. Pass at runtime: `docker run -e SECRET_KEY=value ...` "
            "2. Use BuildKit secrets: `RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret`. "
            "3. Use docker-compose secrets or Kubernetes Secrets for orchestrated environments."
        ),
    },

    # ─── Docker Compose ──────────────────────────────────────────

    # --- Docker Compose: missing healthcheck ---
    {
        "id": "compose_no_healthcheck",
        "pattern": r"^\s+image:\s",
        "message": "Service has no healthcheck defined. Add healthcheck for reliable orchestration.",
        "severity": Severity.INFO,
        "special_handler": "check_compose_healthcheck",
        "file_types": [".yml", ".yaml"],
    },

    # ─── CI/CD Pipeline ─────────────────────────────────────────

    # --- Shell/Procfile: blocking pre-start without timeout ---
    {
        "id": "blocking_prestart",
        "pattern": r"(?:alembic|migrate|flask\s+db).*&" + r"&.*(?:uvicorn|gunicorn|node|npm\s+start)",
        "message": "Migration blocks server start. Wrap in 'timeout' or run as a separate step.",
        "severity": Severity.WARN,
    },
    # --- GitHub Actions: unpinned action version ---
    {
        "id": "ci_unpinned_action",
        "pattern": r"uses:\s*\S+@(?:main|master|latest|HEAD)\b",
        "message": "CI action not pinned to SHA or version tag. Pin to specific version for reproducibility.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    # --- CI: no timeout on job ---
    {
        "id": "ci_no_timeout",
        "pattern": r"^\s+runs-on:\s",
        "message": "CI job has no timeout-minutes. Add timeout to prevent hung pipelines.",
        "severity": Severity.INFO,
        "special_handler": "check_ci_no_timeout",
        "file_types": [".yml", ".yaml"],
    },

    # ─── IaC (Terraform / Config) ────────────────────────────────

    # --- Hardcoded IP in infrastructure files ---
    {
        "id": "hardcoded_ip",
        "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
        "message": "Hardcoded IP address in infrastructure file. Use DNS, variables, or service discovery.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl", ".yml", ".yaml", ".toml"],
        "skip_comments": True,
    },
    # --- YAML/TOML: healthcheck timeout too low ---
    {
        "id": "healthcheck_timeout_low",
        "pattern": r"(?i)healthcheck.*timeout.*[:=]\s*(?:[1-9]|[12]\d)\b",
        "message": "Healthcheck timeout under 30s may be too aggressive for cold starts.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml", ".toml"],
    },
    # --- API key in YAML/config ---
    {
        "id": "api_key_in_config",
        "pattern": r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)(?:\s*:\s*\w+)?\s*[:=]\s*[\"']?[^\s\"']{8,}",
        "message": "API key or secret in config file. Use environment variables or secret manager.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf"],
        "skip_comments": True,
        "suggestion": (
            "Replace the hardcoded value with an environment variable reference. "
            "YAML: `api_key: ${API_KEY}` with envsubst, or use a .env file. "
            "TOML: reference via code, not in the config file itself. "
            "For production: use a secret manager (AWS Secrets Manager, HashiCorp Vault, Doppler)."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  REACT / JSX RULES  (fire on .jsx, .tsx, .js, .ts files)
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "react_dangerouslysetinnerhtml",
        "pattern": r"dangerouslySetInnerHTML",
        "message": "dangerouslySetInnerHTML bypasses React's XSS protection. Sanitize input or use a safe renderer.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "suggestion": (
            "Replace dangerouslySetInnerHTML with a safe alternative: "
            "1. Use DOMPurify: `dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(html)}}`. "
            "2. Use a Markdown renderer (react-markdown) for user-generated content. "
            "3. If rendering trusted HTML, add `// SECURITY: content is pre-sanitized by [source]` comment."
        ),
    },
    {
        "id": "react_no_key_in_list",
        "pattern": r"\.map\s*\([^)]*\)\s*=>\s*(?:<\w+(?:\s+(?!key\b)\w+=[^>]*)*>)",
        "message": "List rendering without key prop. Add a unique key to each element in .map().",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "react_direct_dom",
        "pattern": r"document\.(?:getElementById|querySelector|getElementsBy|createElement)\s*\(",
        "message": "Direct DOM manipulation in React. Use refs or React state instead.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "react_use_effect_no_deps",
        "pattern": r"useEffect\s*\(\s*(?:\(\)|[^,)]+)\s*\)\s*;",
        "message": "useEffect without dependency array runs on every render. Add [] or specific dependencies.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "react_set_state_in_render",
        "pattern": r"(?:^|\s)(?:set[A-Z]\w+|setState)\s*\(",
        "message": "Possible state update during render. Move setState calls into event handlers or useEffect.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
        "special_handler": "check_render_set_state",
    },
    {
        "id": "react_index_as_key",
        "pattern": r"key\s*=\s*\{?\s*(?:index|idx|i)\s*\}?",
        "message": "Array index used as React key. Use a stable unique ID to avoid re-render bugs.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "react_innerhtml_string",
        "pattern": r"\.innerHTML\s*=",
        "message": "Direct innerHTML assignment bypasses sanitization. Use React's rendering or a sanitizer.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "suggestion": (
            "Replace `.innerHTML = value` with safe DOM methods: "
            "1. React: use JSX rendering or dangerouslySetInnerHTML with DOMPurify. "
            "2. Vanilla JS: use `element.textContent = value` for text, or "
            "`element.appendChild(document.createTextNode(value))`. "
            "3. If HTML is required: `element.innerHTML = DOMPurify.sanitize(value)`."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  KUBERNETES / K8S YAML RULES
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "k8s_privileged",
        "pattern": r"(?i)privileged:\s*true",
        "message": "Privileged container. Remove privileged: true unless absolutely necessary.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
        "suggestion": (
            "Remove `privileged: true` from the container spec. Instead: "
            "1. Use specific capabilities: `capabilities: { add: ['NET_ADMIN'] }`. "
            "2. Use securityContext with minimal permissions. "
            "3. If hardware access is needed, use `devices:` to mount only the specific device."
        ),
    },
    {
        "id": "k8s_host_network",
        "pattern": r"(?i)hostNetwork:\s*true",
        "message": "hostNetwork: true exposes the host network to the pod. Remove unless required.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_run_as_root",
        "pattern": r"(?i)runAsUser:\s*0\b",
        "message": "Container runs as root (UID 0). Set runAsNonRoot: true or use a non-zero UID.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_no_resource_limits",
        "pattern": r"(?i)^\s+containers:\s*$",
        "message": "Container spec detected — verify resources.limits and resources.requests are set.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
        "special_handler": "check_k8s_resources",
    },
    {
        "id": "k8s_latest_image",
        "pattern": r"(?i)image:\s*\S+:latest\b",
        "message": "Container image uses :latest tag. Pin to a specific version for reproducibility.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  AI AGENT ENFORCEMENT RULES
    # ═══════════════════════════════════════════════════════════════
    #  These rules enforce coding standards that AI agents violate
    #  most frequently. Each maps to a concrete prohibition.
    #  Severity BLOCK = scan fails, code cannot ship.

    {
        "id": "agent_tee_heredoc",
        "pattern": r"\btee\s+\S+\s*" + _HEREDOC,
        "message": "tee with heredoc detected. AI agents must use template files, not shell tricks.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace `tee file <<EOF ... EOF` with the Write/create_file tool. "
            "Write the content directly to the file using your editor's file creation capability. "
            "Heredocs in shell are prohibited — they bypass validation and introduce formatting issues."
        ),
    },
    {
        "id": "agent_echo_multiline_redirect",
        "pattern": r"echo\s+-e\s+.*\\n.*>\s*\S+",
        "message": "echo -e with newlines to write files. Use proper file I/O or template files.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace `echo -e '...\\n...' > file` with the Write/create_file tool. "
            "Write multi-line content using your editor's file creation tool, not shell echo. "
            "This ensures correct encoding, line endings, and allows content validation."
        ),
    },
    {
        "id": "agent_cat_heredoc",
        "pattern": r"cat\s*>\s*\S+\s*" + _HEREDOC,
        "message": "cat with heredoc redirect. Heredocs are prohibited. Use template files.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace `cat > file <<EOF ... EOF` with the Write/create_file tool. "
            "Use your editor's native file creation to write the content directly. "
            "If in a script, use Python/Node to write the file with proper encoding."
        ),
    },
    {
        "id": "agent_subprocess_shell_true",
        "pattern": r"subprocess\.\w+\(.*shell\s*=\s*True",
        "message": "subprocess with shell=True. Use shell=False and pass args as list.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace `subprocess.run('cmd arg1 arg2', shell=True)` with "
            "`subprocess.run(['cmd', 'arg1', 'arg2'], shell=False, check=True)`. "
            "Pass arguments as a list to prevent shell injection. "
            "If you need shell features (pipes, globs), use subprocess.PIPE or pathlib.glob() instead."
        ),
    },
    {
        "id": "agent_os_system",
        "pattern": r"\bos\.system\s*\(",
        "message": "os.system is unsafe. Use subprocess.run with shell=False.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
        "suggestion": (
            "Replace `os.system('command args')` with "
            "`subprocess.run(['command', 'args'], check=True, capture_output=True)`. "
            "Add `import subprocess` and remove `import os` if no longer needed. "
            "subprocess.run gives you return code, stdout, and stderr control."
        ),
    },
    {
        "id": "agent_os_popen",
        "pattern": r"\bos\.popen\s*\(",
        "message": "os.popen is unsafe. Use subprocess.run with shell=False.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace `os.popen('command')` with "
            "`subprocess.run(['command'], capture_output=True, text=True, check=True)`. "
            "Access output via `result.stdout`. This avoids shell injection and gives proper error handling."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  AI HALLUCINATION DETECTION RULES
    # ═══════════════════════════════════════════════════════════════
    #  These catch AI agents fabricating URLs, environment variables,
    #  API endpoints, config values, imports, and CLI flags that
    #  likely don't exist.  THIS IS CODETRUST'S PRIMARY MOAT.

    # --- Hallucinated network targets ---
    {
        "id": "hallucinated_localhost_port",
        "pattern": r"(?i)localhost:\d{5,}",
        "message": "Suspicious localhost port (5+ digits). Verify this port is correct — AI often invents port numbers.",
        "severity": Severity.WARN,
    },
    {
        "id": "hallucinated_api_endpoint",
        "pattern": r"(?i)[\"']/api/v\d+/[a-z]+/[a-z]+/[a-z]+/[a-z]+[\"']",
        "message": "Deeply nested API endpoint path. Verify this endpoint actually exists — AI may hallucinate API routes.",
        "severity": Severity.WARN,
    },
    {
        "id": "hallucinated_env_var",
        "pattern": r"os\.(?:environ|getenv)\s*[\[(]\s*[\"'](?:(?!PATH|HOME|USER|SHELL|TERM|LANG|LC_|TZ|PWD|LOGNAME|HOSTNAME|DISPLAY|XDG_|EDITOR|VISUAL|PAGER|BROWSER|TMPDIR|TEMP|TMP)[A-Z][A-Z0-9_]{15,})[\"']",
        "message": "Long environment variable name (16+ chars). Verify this env var is documented and exists.",
        "severity": Severity.INFO,
    },
    {
        "id": "placeholder_url",
        "pattern": r"(?i)https?://(?:example|your-domain|my-app|your-app|placeholder|changeme|todo)\.",
        "message": "Placeholder URL detected. Replace with actual URL before deploying.",
        "severity": Severity.WARN,
    },
    {
        "id": "fake_api_key_format",
        "pattern": r"[\"'](?:sk-[a-zA-Z0-9]{48}|pk_test_[a-zA-Z0-9]{24}|xoxb-[0-9]{10,})[\"']",
        "message": "String resembles a real API key format (OpenAI/Stripe/Slack). Verify it's not fabricated by AI.",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace the hardcoded key-like string with an environment variable: "
            "`os.environ['OPENAI_API_KEY']` (Python), `process.env.STRIPE_SECRET_KEY` (JS). "
            "If this is a test, use a clearly fake value like 'sk-test-placeholder-not-real'. "
            "Never commit real or real-looking API keys to source control."
        ),
    },

    # --- Hallucinated Python imports ---
    {
        "id": "hallucinated_import_nonexistent",
        "pattern": r"^(?:from|import)\s+(?:ai_utils|ml_helpers|deep_learning_tools|auto_ml_pipeline|neural_utils|smart_ai|llm_toolkit|ai_framework|model_utils|auto_train|automl_kit)\b",
        "message": "Import from a commonly hallucinated AI package. This package likely does not exist on PyPI.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
        "suggestion": (
            "This package does not exist on PyPI — it was hallucinated. "
            "Remove the import and use a real package instead. "
            "Common alternatives: scikit-learn (sklearn), transformers (huggingface), "
            "langchain, openai, anthropic, torch (PyTorch), tensorflow. "
            "Verify any package exists on pypi.org before importing."
        ),
    },
    {
        "id": "hallucinated_import_misspelled",
        "pattern": r"^(?:from|import)\s+(?:requets|requsts|beautifulsoup|sklear|tenserflow|pytorch|numpyy|pands|matplotib|sqlachemy|fasttapi|fask|djano)\b",
        "message": "Misspelled import — AI hallucinated a typo. Check PyPI for the correct package name.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
        "suggestion": (
            "Fix the misspelled import. Common corrections: "
            "requets/requsts → requests, beautifulsoup → beautifulsoup4 (bs4), "
            "sklear → sklearn, tenserflow → tensorflow, pytorch → torch, "
            "numpyy → numpy, pands → pandas, matplotib → matplotlib, "
            "sqlachemy → sqlalchemy, fasttapi → fastapi, fask → flask, djano → django."
        ),
    },

    # --- Hallucinated function/method calls ---
    {
        "id": "hallucinated_method_chain",
        "pattern": r"\.\w+\(\)\.\w+\(\)\.\w+\(\)\.\w+\(\)\.\w+\(\)",
        "message": "Deeply chained method call (5+ levels). AI may have invented methods in this chain — verify each method exists.",
        "severity": Severity.WARN,
    },
    {
        "id": "hallucinated_config_option",
        "pattern": r"(?i)[\"'](?:enable_auto_scaling|use_gpu_acceleration|smart_cache_mode|auto_optimize|intelligent_routing|ai_mode|turbo_mode|fast_mode|advanced_mode)[\"']",
        "message": "Suspicious configuration option. AI often fabricates config keys that don't exist in the target library.",
        "severity": Severity.WARN,
    },

    # --- Hallucinated CLI flags ---
    {
        "id": "hallucinated_cli_flag",
        "pattern": r"(?i)--(?:turbo|smart|auto-fix|auto-optimize|enable-ai|fast-mode|intelligent|deep-scan|ultra|hyper)\b",
        "message": "Suspicious CLI flag that likely doesn't exist. AI agents often invent command-line options.",
        "severity": Severity.WARN,
    },

    # --- Hallucinated version numbers ---
    {
        "id": "hallucinated_version",
        "pattern": r"(?:==|>=|~=)\s*(?:9\d\.\d|[1-9]\d{2,}\.\d)",
        "message": "Implausible version number (>=90.x or 100+.x). AI may have fabricated this version.",
        "severity": Severity.WARN,
    },

    # --- Phantom file references ---
    {
        "id": "phantom_file_reference",
        "pattern": r"(?i)open\s*\(\s*[\"'](?:data|config|settings|schema|models|utils)/[a-z_]+\.(?:json|yaml|yml|toml|csv)[\"']",
        "message": "Opening a file by relative path. Verify this file exists — AI often references files that were never created.",
        "severity": Severity.INFO,
    },

    # --- Fabricated error codes ---
    {
        "id": "hallucinated_http_status",
        "pattern": r"(?:status_code|status|code)\s*(?:==|!=|is)\s*(?:6\d\d|7\d\d|8\d\d|9\d\d)\b",
        "message": "Non-standard HTTP status code. Valid codes are 1xx-5xx — AI may have invented this status code.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  RUBY-SPECIFIC RULES (.rb)
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "ruby_eval",
        "pattern": r"\b(?:eval|class_eval|module_eval|instance_eval)\s*[\(\s]",
        "message": "Avoid eval/class_eval/module_eval — use safe metaprogramming alternatives.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "suggestion": (
            "Replace eval with safe Ruby metaprogramming: "
            "1. Use `define_method` instead of `class_eval` with string interpolation. "
            "2. Use `public_send`/`send` with a whitelist of allowed method names. "
            "3. For config: use YAML.safe_load or JSON.parse instead of eval."
        ),
    },
    {
        "id": "ruby_system_exec",
        "pattern": r"\b(?:system|exec|%x|`)\s*[\(\"\']",
        "message": "Shell command execution detected. Use shell-escape or parameterized commands.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "suggestion": (
            "Replace shell execution with Shellwords-escaped commands: "
            "`system('cmd', Shellwords.escape(user_input))` or use Open3: "
            "`stdout, stderr, status = Open3.capture3('cmd', arg1, arg2)`. "
            "Never interpolate user input into backtick or system() strings."
        ),
    },
    {
        "id": "ruby_send_public_send",
        "pattern": r"\b(?:send|public_send)\s*\(",
        "message": "Dynamic method dispatch via send/public_send. Verify the method name is trusted.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_binding_pry",
        "pattern": r"\bbinding\.pry\b",
        "message": "Debug breakpoint left in code. Remove binding.pry before deploying.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "suggestion": (
            "Delete the `binding.pry` line. "
            "Add a pre-commit hook to catch debug breakpoints: "
            "`grep -rn 'binding.pry' app/ lib/ && exit 1`. "
            "Use conditional debugging: `binding.pry if ENV['DEBUG']` during development only."
        ),
    },
    {
        "id": "ruby_puts_p_debug",
        "pattern": r"^\s*(?:puts|p|pp)\s+",
        "message": "Debug output (puts/p/pp) in production code. Use a structured logger (e.g. Rails.logger).",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_sleep",
        "pattern": r"\bsleep\s*\(",
        "message": "Blocking sleep call. Consider async patterns or background jobs for delays.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_rescue_exception",
        "pattern": r"rescue\s+Exception\b",
        "message": "Rescuing Exception catches system errors (SignalException, NoMemoryError). Rescue StandardError instead.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_global_variable",
        "pattern": r"\$[A-Za-z_]\w*\s*=",
        "message": "Global variable assignment. Use module constants, class variables, or dependency injection.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_mass_assignment",
        "pattern": r"\.new\s*\(\s*params\b",
        "message": "Potential mass assignment. Use strong parameters (permit) in Rails controllers.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_hardcoded_secret",
        "pattern": r'(?i)(?:api_key|secret_key|password|token)\s*=\s*["\'][^"\']{8,}["\']',
        "message": "Possible hardcoded secret in Ruby code. Use environment variables (ENV['KEY']).",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "suggestion": (
            "Replace the hardcoded secret with `ENV.fetch('KEY_NAME')`. "
            "Use `ENV.fetch` (not `ENV[]`) to fail fast if the variable is missing. "
            "Add the key to .env via dotenv gem and to .env.example with a placeholder. "
            "For Rails: use `Rails.application.credentials` or `config/credentials.yml.enc`."
        ),
    },
    {
        "id": "ruby_hallucinated_gem",
        "pattern": r"^require\s+['\"](?:activrecord|actionspack|railties_utils|ruby_json|string_utils|http_client|easy_http|ruby_async|fast_json)\b",
        "message": "Misspelled or hallucinated gem name. Verify the gem exists on rubygems.org.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
        "suggestion": (
            "This gem name is misspelled or does not exist. Common corrections: "
            "activrecord → activerecord, actionspack → actionpack, "
            "ruby_json → json (stdlib), http_client → httparty or faraday, "
            "easy_http → net/http (stdlib) or faraday, ruby_async → async. "
            "Verify on rubygems.org before adding to Gemfile."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  PHP-SPECIFIC RULES (.php)
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "php_eval",
        "pattern": r"\b(?:eval|assert)\s*\(",
        "message": "eval/assert is a critical security risk. Use safe alternatives.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace eval/assert with safe alternatives: "
            "For JSON: use json_decode(). For config: use parse_ini_file() or YAML. "
            "For dynamic class instantiation: use a factory pattern with a whitelist. "
            "For templates: use Twig, Blade, or other sandboxed template engines."
        ),
    },
    {
        "id": "php_shell_exec",
        "pattern": r"\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\(",
        "message": "Shell command execution detected. Use escapeshellarg/escapeshellcmd for user input.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace direct shell execution with escaped commands: "
            "`$output = shell_exec('cmd ' . escapeshellarg($userInput));`. "
            "Better: use PHP native functions (file_get_contents, copy, mkdir) instead of shell commands. "
            "For complex operations: use Symfony Process component with argument arrays."
        ),
    },
    {
        "id": "php_sql_injection",
        "pattern": r'(?:mysql_query|mysqli_query|->query)\s*\(\s*["\'].*?\$',
        "message": "Possible SQL injection via variable interpolation. Use prepared statements (PDO/mysqli).",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace interpolated SQL with PDO prepared statements: "
            "`$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id'); "
            "$stmt->execute(['id' => $userId]);`. "
            "For mysqli: `$stmt = $conn->prepare('SELECT * FROM users WHERE id = ?'); "
            "$stmt->bind_param('i', $userId);`. Never embed $variables in SQL strings."
        ),
    },
    {
        "id": "php_var_dump",
        "pattern": r"\b(?:var_dump|print_r|echo)\s*\(",
        "message": "Debug output in production code. Use a structured logger (e.g. Monolog).",
        "severity": Severity.WARN,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_deprecated_mysql",
        "pattern": r"\b(?:mysql_connect|mysql_query|mysql_fetch|mysql_close)\s*\(",
        "message": "Deprecated mysql_* functions. Use PDO or mysqli instead (mysql_* removed in PHP 7+).",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace mysql_* with PDO (recommended) or mysqli: "
            "mysql_connect → `$pdo = new PDO('mysql:host=localhost;dbname=db', $user, $pass)`. "
            "mysql_query → `$pdo->prepare($sql)->execute()`. "
            "mysql_fetch_array → `$stmt->fetch(PDO::FETCH_ASSOC)`. "
            "PDO supports prepared statements by default, preventing SQL injection."
        ),
    },
    {
        "id": "php_error_suppression",
        "pattern": r"@\w+\s*\(",
        "message": "Error suppression operator @ hides errors. Handle errors explicitly with try/catch.",
        "severity": Severity.WARN,
        "file_types": [".php"],
    },
    {
        "id": "php_extract",
        "pattern": r"\bextract\s*\(",
        "message": "extract() imports variables from array into current scope — security risk with untrusted data.",
        "severity": Severity.WARN,
        "file_types": [".php"],
    },
    {
        "id": "php_unserialize",
        "pattern": r"\bunserialize\s*\(",
        "message": "unserialize() on untrusted data enables object injection attacks. Use json_decode instead.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace `unserialize($data)` with `json_decode($data, true)`. "
            "If PHP serialization is required, use `unserialize($data, ['allowed_classes' => false])` "
            "to prevent object injection. For complex data: use json_encode/json_decode consistently."
        ),
    },
    {
        "id": "php_md5_password",
        "pattern": r"\b(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd)",
        "message": "Weak hash for passwords. Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace `md5($password)` / `sha1($password)` with: "
            "`$hash = password_hash($password, PASSWORD_ARGON2ID);` for hashing, "
            "`password_verify($password, $hash)` for verification. "
            "PASSWORD_ARGON2ID is strongest; fall back to PASSWORD_BCRYPT if Argon2 is unavailable."
        ),
    },
    {
        "id": "php_die_exit",
        "pattern": r"\b(?:die|exit)\s*\(",
        "message": "die/exit terminates execution abruptly. Use proper exception handling and responses.",
        "severity": Severity.WARN,
        "file_types": [".php"],
    },
    {
        "id": "php_hardcoded_secret",
        "pattern": r'(?i)(?:api_key|secret|password|token)\s*=\s*["\'][^"\']{8,}["\']',
        "message": "Possible hardcoded secret in PHP code. Use environment variables (getenv/dotenv).",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "suggestion": (
            "Replace the hardcoded secret with an environment variable: "
            "`$apiKey = getenv('API_KEY');` or `$_ENV['API_KEY']`. "
            "Use vlucas/phpdotenv to load .env files. "
            "For Laravel: use `config('services.api.key')` backed by .env."
        ),
    },
    {
        "id": "php_hallucinated_namespace",
        "pattern": r"^use\s+(?:Laravel\\Http|Symfony\\Components|Doctrine\\ORM\\Managers|Illuminate\\Facades|GuzzleHttp\\Requests)\b",
        "message": "Misspelled or hallucinated PHP namespace. Verify the package exists on packagist.org.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
        "suggestion": (
            "Fix the misspelled namespace. Common corrections: "
            "Laravel\\Http → Illuminate\\Http, Symfony\\Components → Symfony\\Component, "
            "Doctrine\\ORM\\Managers → Doctrine\\ORM\\EntityManager, "
            "GuzzleHttp\\Requests → GuzzleHttp\\Client. "
            "Verify on packagist.org and use `composer show` to check installed packages."
        ),
    },
    # ═══════════════════════════════════════════════════════════════
    #  POWERSHELL RULES (.ps1 / .psm1 / .psd1)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ps_invoke_expression",
        "pattern": r"\bInvoke-Expression\b",
        "message": "Invoke-Expression executes arbitrary strings. Use direct cmdlet calls or validated input.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
        "suggestion": (
            "Replace Invoke-Expression with direct cmdlet calls: "
            "Instead of `Invoke-Expression \"Get-Process $name\"`, use `Get-Process -Name $name`. "
            "For dynamic commands, use the call operator: `& $cmdPath $args`. "
            "For script blocks: `$sb = [scriptblock]::Create($code); & $sb`."
        ),
    },
    {
        "id": "ps_execution_policy_bypass",
        "pattern": r"(?i)Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)",
        "message": "Setting ExecutionPolicy to Bypass/Unrestricted disables script signing checks.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
        "suggestion": (
            "Remove the Set-ExecutionPolicy Bypass/Unrestricted call. "
            "Use `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser` for development. "
            "For CI/CD: set the policy at the system level, not in scripts. "
            "Sign scripts with a code-signing certificate for production environments."
        ),
    },
    {
        "id": "ps_plaintext_credential",
        "pattern": r"(?i)(?:ConvertTo-SecureString)\s+.*-AsPlainText",
        "message": "Converting plaintext to SecureString exposes secrets. Use credential prompts or vaults.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
        "suggestion": (
            "Replace plaintext SecureString with a secure credential source: "
            "1. Interactive: `$cred = Get-Credential`. "
            "2. From vault: `$secret = Get-AzKeyVaultSecret -VaultName 'vault' -Name 'key'`. "
            "3. From env var: `$secure = ConvertTo-SecureString $env:SECRET -AsPlainText -Force` "
            "(only if the env var is injected securely at runtime, never hardcoded)."
        ),
    },
    {
        "id": "ps_hardcoded_password",
        "pattern": r'(?i)(?:\$password|\$secret|\$apikey|\$token)\s*=\s*["\'][^"\']{4,}["\']',
        "message": "Hardcoded credential in PowerShell script. Use SecureString, Key Vault, or environment variables.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
        "suggestion": (
            "Replace the hardcoded credential with an environment variable: "
            "`$password = $env:DB_PASSWORD`. "
            "For Azure: use `Get-AzKeyVaultSecret`. "
            "For AWS: use `Get-SECSecretValue`. "
            "Add the variable name to your deployment documentation."
        ),
    },
    {
        "id": "ps_write_host",
        "pattern": r"\bWrite-Host\b",
        "message": "Write-Host writes to the host UI, not the pipeline. Use Write-Output or Write-Information.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_catch_empty",
        "pattern": r"catch\s*\{[\s\r\n]*\}",
        "message": "Empty catch block silently swallows errors. Log or re-throw the exception.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_no_strict_mode",
        "pattern": r"(?i)Set-StrictMode\s+.*-Off",
        "message": "Disabling StrictMode hides variable and syntax errors. Keep StrictMode on.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_start_process_no_wait",
        "pattern": r"\bStart-Process\b(?!.*-Wait)",
        "message": "Start-Process without -Wait may cause race conditions. Add -Wait if the process must complete.",
        "severity": Severity.INFO,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_stop_process_force",
        "pattern": r"\bStop-Process\s+.*-Force",
        "message": "Stop-Process -Force kills processes without cleanup. Ensure graceful shutdown is not needed.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_net_webclient",
        "pattern": r"\bNew-Object\s+System\.Net\.WebClient\b",
        "message": "System.Net.WebClient is deprecated. Use Invoke-RestMethod or Invoke-WebRequest instead.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_sleep_unbounded",
        "pattern": r"\bStart-Sleep\s+-Seconds\s+\d{3,}",
        "message": "Long sleep (100+ seconds) blocks execution. Consider async patterns or shorter intervals.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_rm_recurse_force",
        "pattern": r"(?i)Remove-Item\s+.*-Recurse\s+.*-Force",
        "message": "Remove-Item -Recurse -Force deletes without confirmation. Verify the target path is safe.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  TERRAFORM PROVIDER-SPECIFIC RULES (.tf / .hcl)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "tf_wildcard_iam",
        "pattern": r'(?:actions|Action)\s*=\s*\[?\s*"\*"\s*\]?',
        "message": "Wildcard IAM action grants full access. Follow the principle of least privilege.",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".hcl"],
        "suggestion": (
            "Replace `Action = \"*\"` with specific actions the service needs: "
            "`actions = [\"s3:GetObject\", \"s3:PutObject\", \"s3:ListBucket\"]`. "
            "Use AWS IAM Access Analyzer to identify the minimum required permissions. "
            "Scope resources with ARN patterns instead of `Resource = \"*\"`."
        ),
    },
    {
        "id": "tf_public_s3_acl",
        "pattern": r'(?i)acl\s*=\s*"(?:public-read|public-read-write)"',
        "message": "S3 bucket with public ACL exposes data. Use bucket policies and block public access settings.",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".hcl"],
        "suggestion": (
            "Remove the public ACL and add block public access: "
            "`acl = \"private\"` and add `aws_s3_bucket_public_access_block` resource with "
            "`block_public_acls = true, block_public_policy = true, "
            "ignore_public_acls = true, restrict_public_buckets = true`. "
            "If public access is needed, use CloudFront with OAI/OAC instead."
        ),
    },
    {
        "id": "tf_open_security_group",
        "pattern": r'cidr_blocks\s*=\s*\[?\s*"0\.0\.0\.0/0"\s*\]?',
        "message": "Security group open to 0.0.0.0/0. Restrict to specific CIDR ranges.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "tf_unencrypted_ebs",
        "pattern": r'encrypted\s*=\s*false',
        "message": "EBS volume encryption explicitly disabled. Set encrypted = true for data-at-rest protection.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "tf_no_tags",
        "pattern": r'resource\s+"aws_(?:instance|s3_bucket|rds_[a-z_]+|vpc)"\s+"[^"]+"\s*\{',
        "message": "AWS resource declared — ensure a tags block is present for cost allocation and governance.",
        "severity": Severity.INFO,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "tf_hardcoded_ami",
        "pattern": r'ami\s*=\s*"ami-[0-9a-f]{8,17}"',
        "message": "Hardcoded AMI ID. Use data sources (aws_ami) or variables for portability across regions.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "tf_no_versioned_module",
        "pattern": r'source\s*=\s*"[^"]+"\s*$(?!.*version)',
        "message": "Module source without version pin. Add ?ref=TAG or version constraint for reproducibility.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "tf_no_state_encryption",
        "pattern": r'backend\s+"s3"\s*\{(?:(?!encrypt\s*=\s*true).)*\}',
        "message": "S3 backend without encryption. Set encrypt = true to protect state file at rest.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "tf_sensitive_output",
        "pattern": r'(?i)output\s+"[^"]*(?:password|secret|key|token)[^"]*"',
        "message": "Output containing sensitive data should set sensitive = true to prevent accidental exposure.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  HELM CHART RULES (.yml / .yaml in charts/templates)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "helm_hardcoded_image_tag",
        "pattern": r"image:\s+\S+:\d+\.\d+",
        "message": "Hardcoded image tag in Helm template. Use {{ .Values.image.tag }} for configurability.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "helm_no_resource_limits",
        "pattern": r"(?i)kind:\s*(?:Deployment|StatefulSet|DaemonSet)",
        "message": "Helm workload should define resource requests/limits via {{ .Values.resources }}.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "helm_hardcoded_namespace",
        "pattern": r"namespace:\s+(?!.*\{\{)[a-z][a-z0-9-]+",
        "message": "Hardcoded namespace in Helm template. Use {{ .Release.Namespace }} for portability.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "helm_deprecated_api",
        "pattern": r"apiVersion:\s+(?:extensions/v1beta1|apps/v1beta[12]|networking\.k8s\.io/v1beta1)",
        "message": "Deprecated Kubernetes API version. Migrate to the stable API version.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "helm_hardcoded_replicas",
        "pattern": r"replicas:\s+\d+(?!\s*#.*Values)",
        "message": "Hardcoded replica count. Use {{ .Values.replicaCount }} for environment-specific scaling.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "helm_tpl_missing_quote",
        "pattern": r':\s+\{\{(?!.*quote).*\.Values\.\w+\s*\}\}',
        "message": "Template value without {{ quote }} wrapper. String values in YAML should be quoted.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  ANSIBLE PLAYBOOK RULES (.yml / .yaml)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ansible_command_module",
        "pattern": r"(?:^|\s)(?:command|shell):\s+",
        "message": "Prefer specific Ansible modules (apt, yum, copy) over command/shell for idempotency.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible_ignore_errors",
        "pattern": r"(?i)ignore_errors:\s*(?:yes|true)",
        "message": "ignore_errors silently swallows failures. Use failed_when or rescue blocks instead.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible_plaintext_password",
        "pattern": r"(?i)(?:password|secret|api_key):\s+[\"']?[a-zA-Z0-9/+=]{8,}[\"']?",
        "message": "Plaintext password in Ansible playbook. Use ansible-vault or lookup plugins for secrets.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible_latest_package",
        "pattern": r"state:\s*latest",
        "message": "state: latest is non-deterministic. Pin package versions for reproducible deployments.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible_no_become_user",
        "pattern": r"become:\s*(?:yes|true)(?!.*become_user)",
        "message": "Privilege escalation without become_user defaults to root. Specify the target user explicitly.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible_no_changed_when",
        "pattern": r"(?:command|shell|raw):\s+\S+.*(?!.*changed_when)",
        "message": "command/shell/raw module should have changed_when for idempotency reporting.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  NGINX CONFIG RULES (.conf)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "nginx_server_tokens_on",
        "pattern": r"(?i)server_tokens\s+on",
        "message": "server_tokens on exposes Nginx version. Set server_tokens off to hide version info.",
        "severity": Severity.WARN,
        "file_types": [".conf"],
    },
    {
        "id": "nginx_autoindex_on",
        "pattern": r"(?i)autoindex\s+on",
        "message": "autoindex on enables directory listing, exposing file structure. Disable it.",
        "severity": Severity.BLOCK,
        "file_types": [".conf"],
    },
    {
        "id": "nginx_ssl_v3",
        "pattern": r"(?i)ssl_protocols\s+.*(?:SSLv2|SSLv3|TLSv1(?:\s|;))",
        "message": "Insecure SSL/TLS protocol version. Use TLSv1.2 and TLSv1.3 only.",
        "severity": Severity.BLOCK,
        "file_types": [".conf"],
    },
    {
        "id": "nginx_root_in_location",
        "pattern": r"^\s+root\s+/",
        "message": "root directive in nested block (likely location) can cause path traversal. Place root in server block.",
        "severity": Severity.WARN,
        "file_types": [".conf"],
    },
    {
        "id": "nginx_no_rate_limit",
        "pattern": r"(?i)upstream\s+.*\{(?:(?!limit_req_zone).)*\}",
        "message": "No rate limiting configured. Add limit_req_zone to protect against abuse.",
        "severity": Severity.INFO,
        "file_types": [".conf"],
    },
    {
        "id": "nginx_add_header_missing_always",
        "pattern": r"add_header\s+(?:X-Frame-Options|Content-Security-Policy|X-Content-Type-Options)(?!.*always)",
        "message": "Security header without 'always' flag. Add 'always' to apply on all response codes.",
        "severity": Severity.INFO,
        "file_types": [".conf"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  AWS CLOUDFORMATION / CDK RULES (.yml / .yaml / .json)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "cfn_wildcard_iam",
        "pattern": r'(?:Action|Resource):\s*["\']?\*["\']?',
        "message": "CloudFormation IAM wildcard grants excessive permissions. Scope to specific actions/resources.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cfn_public_s3",
        "pattern": r"(?i)(?:PublicRead|PublicReadWrite|public-read)",
        "message": "S3 bucket with public access in CloudFormation template. Enforce BlockPublicAccess.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cfn_no_deletion_policy",
        "pattern": r"Type:\s*AWS::(?:RDS::DBInstance|DynamoDB::Table|S3::Bucket)(?:(?!DeletionPolicy).)*$",
        "message": "Stateful AWS resource without DeletionPolicy. Add DeletionPolicy: Retain or Snapshot.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cfn_unencrypted_storage",
        "pattern": r"Type:\s*AWS::(?:RDS::DBInstance|EBS::Volume|S3::Bucket)(?:(?!Encrypt).)*$",
        "message": "AWS storage resource without encryption configuration. Enable encryption at rest.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cfn_hardcoded_credentials",
        "pattern": r'(?i)(?:Password|SecretKey|MasterUserPassword):\s*["\'][^{"\'\s]{8,}["\']',
        "message": "Hardcoded credential in CloudFormation. Use SSM Parameter Store or Secrets Manager references.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cfn_no_logging",
        "pattern": r"Type:\s*AWS::(?:EC2::VPC|S3::Bucket|ELB)(?:(?!Logging|LoggingConfiguration).)*$",
        "message": "AWS resource without logging enabled. Configure access logging for auditability.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cdk_no_removal_policy",
        "pattern": r"(?:new\s+(?:s3\.Bucket|dynamodb\.Table|rds\.DatabaseInstance)|s3\.Bucket\(|dynamodb\.Table\(|rds\.DatabaseInstance\()",
        "message": "CDK stateful construct detected — ensure removalPolicy is set to RETAIN or SNAPSHOT.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js", ".py"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  AZURE ARM / BICEP RULES (.bicep / .json)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "bicep_no_secure_param",
        "pattern": r"(?i)param\s+\w*(?:password|secret|key|token)\w*\s+string(?!.*@secure\(\))",
        "message": "Sensitive Bicep parameter without @secure() decorator. Secrets must use @secure().",
        "severity": Severity.BLOCK,
        "file_types": [".bicep"],
    },
    {
        "id": "bicep_http_only",
        "pattern": r"(?i)httpsOnly:\s*false",
        "message": "Azure resource allowing HTTP. Set httpsOnly: true to enforce HTTPS.",
        "severity": Severity.BLOCK,
        "file_types": [".bicep"],
    },
    {
        "id": "bicep_public_network",
        "pattern": r"(?i)publicNetworkAccess:\s*['\"]?Enabled",
        "message": "Public network access enabled on Azure resource. Use Private Endpoints where possible.",
        "severity": Severity.WARN,
        "file_types": [".bicep"],
    },
    {
        "id": "arm_wildcard_rbac",
        "pattern": r'"actions":\s*\[\s*"\*"\s*\]',
        "message": "Wildcard RBAC action in ARM template. Scope to specific resource provider actions.",
        "severity": Severity.BLOCK,
        "file_types": [".json", ".yml", ".yaml"],
    },
    {
        "id": "arm_no_diagnostics",
        "pattern": r"Microsoft\.(?:Compute|Storage|Network)(?:(?!diagnosticSettings|diagnosticsProfile).)*$",
        "message": "Azure resource without diagnostic settings. Enable diagnostics for monitoring and compliance.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  REDIS CONFIGURATION RULES (.conf)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "redis_bind_all",
        "pattern": r"^\s*bind\s+(?:0\.0\.0\.0|\*)",
        "message": "Redis bound to all interfaces. Bind to 127.0.0.1 or specific IPs in production.",
        "severity": Severity.WARN,
        "file_types": [".conf"],
    },
    {
        "id": "redis_protected_mode_off",
        "pattern": r"^\s*protected-mode\s+no",
        "message": "Redis protected mode disabled. Enable protected-mode to reject external connections without auth.",
        "severity": Severity.BLOCK,
        "file_types": [".conf"],
    },
    {
        "id": "redis_weak_password",
        "pattern": r"(?i)^\s*requirepass\s+(?:redis|password|admin|test|default|changeme|1234|pass|foobared)\s*$",
        "message": "Weak or default Redis password. Use a strong, randomly generated password.",
        "severity": Severity.BLOCK,
        "file_types": [".conf"],
    },
    {
        "id": "redis_maxmemory_noeviction",
        "pattern": r"(?i)^\s*maxmemory-policy\s+noeviction",
        "message": "noeviction policy causes write errors when memory is full. Use allkeys-lru or volatile-lru.",
        "severity": Severity.WARN,
        "file_types": [".conf"],
    },
    {
        "id": "redis_save_disabled",
        "pattern": r'^\s*save\s+""',
        "message": "RDB snapshots disabled. Ensure AOF is enabled or data loss on restart is acceptable.",
        "severity": Severity.WARN,
        "file_types": [".conf"],
    },
    {
        "id": "redis_aof_no_fsync",
        "pattern": r"(?i)^\s*appendfsync\s+no\b",
        "message": "Redis AOF without fsync risks data loss on crash. Use appendfsync everysec or always.",
        "severity": Severity.WARN,
        "file_types": [".conf"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  HASHICORP VAULT RULES (.hcl)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "vault_tls_disabled",
        "pattern": r'(?i)tls_disable\s*=\s*(?:1|true|"true")',
        "message": "Vault TLS disabled. Always enable TLS in production to encrypt client-server communication.",
        "severity": Severity.BLOCK,
        "file_types": [".hcl"],
    },
    {
        "id": "vault_file_storage",
        "pattern": r'(?i)storage\s+"file"\s*\{',
        "message": "Vault using file storage backend. Use Consul, Raft, or cloud storage for HA in production.",
        "severity": Severity.WARN,
        "file_types": [".hcl"],
    },
    {
        "id": "vault_disable_mlock",
        "pattern": r'(?i)disable_mlock\s*=\s*(?:true|1|"true")',
        "message": "Vault mlock disabled. Memory locking prevents secrets from being swapped to disk.",
        "severity": Severity.WARN,
        "file_types": [".hcl"],
    },
    {
        "id": "vault_telemetry_unauth",
        "pattern": r'(?i)unauthenticated_metrics_access\s*=\s*(?:true|1|"true")',
        "message": "Vault metrics exposed without authentication. Set unauthenticated_metrics_access = false.",
        "severity": Severity.WARN,
        "file_types": [".hcl"],
    },
    {
        "id": "vault_max_lease_long",
        "pattern": r'(?i)max_lease_ttl\s*=\s*"\d{4,}h"',
        "message": "Very long Vault max lease TTL (1000+ hours). Short-lived leases reduce exposure from compromised credentials.",
        "severity": Severity.INFO,
        "file_types": [".hcl"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  PROMETHEUS / GRAFANA MONITORING RULES (.yml / .yaml)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "prom_scrape_too_fast",
        "pattern": r"(?i)scrape_interval:\s*[1-4]s\b",
        "message": "Prometheus scrape interval under 5s may overload targets and inflate storage. Use 15s-60s.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "prom_eval_too_fast",
        "pattern": r"(?i)evaluation_interval:\s*[1-4]s\b",
        "message": "Prometheus evaluation interval under 5s is aggressive. Use 15s-60s for most workloads.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "grafana_anon_access",
        "pattern": r"(?i)GF_AUTH_ANONYMOUS_ENABLED\s*=\s*true",
        "message": "Grafana anonymous access enabled. Require authentication for dashboard access in production.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "grafana_default_admin",
        "pattern": r"(?i)GF_SECURITY_ADMIN_PASSWORD\s*=\s*(?:admin|password|grafana|test|changeme|default)",
        "message": "Weak or default Grafana admin password. Use a strong, unique password.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "grafana_allow_embedding",
        "pattern": r"(?i)GF_SECURITY_ALLOW_EMBEDDING\s*=\s*true",
        "message": "Grafana allow_embedding enables iframe embedding, creating a clickjacking risk. Disable unless required.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  SYSTEMD UNIT FILE RULES (.service / .timer)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "systemd_restart_disabled",
        "pattern": r"(?i)^\s*Restart\s*=\s*no\s*$",
        "message": "Systemd service will not restart on failure. Set Restart=on-failure for production services.",
        "severity": Severity.WARN,
        "file_types": [".service", ".timer"],
    },
    {
        "id": "systemd_restart_no_delay",
        "pattern": r"(?i)^\s*RestartSec\s*=\s*0\s*$",
        "message": "RestartSec=0 causes immediate restart loops, risking CPU storms. Set RestartSec=5 or higher.",
        "severity": Severity.WARN,
        "file_types": [".service", ".timer"],
    },
    {
        "id": "systemd_unlimited_resource",
        "pattern": r"(?i)^\s*(?:LimitNOFILE|LimitNPROC)\s*=\s*(?:infinity|unlimited)",
        "message": "Unlimited resource limit for systemd service. Set bounded limits to prevent resource exhaustion.",
        "severity": Severity.WARN,
        "file_types": [".service", ".timer"],
    },
    {
        "id": "systemd_exec_shell_wrapper",
        "pattern": r"(?i)^\s*ExecStart\s*=\s*/(?:bin|usr/bin)/(?:ba)?sh\s+-c\s+",
        "message": "Shell wrapper in ExecStart. Use direct binary path for cleaner signal handling and process management.",
        "severity": Severity.INFO,
        "file_types": [".service", ".timer"],
    },
    {
        "id": "systemd_no_timeout_stop",
        "pattern": r"(?i)^\s*TimeoutStopSec\s*=\s*(?:infinity|0)\s*$",
        "message": "No stop timeout. Set TimeoutStopSec to prevent zombie processes during shutdown.",
        "severity": Severity.INFO,
        "file_types": [".service", ".timer"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  DOCKER COMPOSE ADVANCED RULES (.yml / .yaml)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "compose_ipc_host",
        "pattern": r'(?i)^\s+ipc:\s*["\']?host',
        "message": "Docker Compose IPC set to host. This shares host IPC namespace, breaking container isolation.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "compose_network_host",
        "pattern": r'(?i)^\s+network_mode:\s*["\']?host',
        "message": "Docker Compose service using host network mode. Use bridge networking for container isolation.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "compose_pid_host",
        "pattern": r'(?i)^\s+pid:\s*["\']?host',
        "message": "Docker Compose PID mode set to host. This exposes host processes to the container.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "compose_restart_always",
        "pattern": r'(?i)^\s+restart:\s*["\']?always',
        "message": "restart: always restarts even after manual stop. Use unless-stopped for most production services.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "compose_env_inline_secret",
        "pattern": (
            r"(?i)^\s+-\s*(?:DB_PASSWORD|MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD"
            r"|REDIS_PASSWORD|SECRET_KEY|API_SECRET|MONGO_INITDB_ROOT_PASSWORD)"
            r"\s*=\s*\S{4,}"
        ),
        "message": "Secret value inline in Docker Compose environment block. Use env_file or Docker secrets.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  GITHUB ACTIONS ADVANCED RULES (.yml / .yaml)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ci_pull_request_target",
        "pattern": r"(?i)^\s+pull_request_target:",
        "message": "pull_request_target runs with write permissions on fork PRs. Use pull_request + workflow_run pattern instead.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ci_write_all_permissions",
        "pattern": r"(?i)^\s+permissions:\s*write-all",
        "message": "write-all grants excessive CI permissions. Scope to specific permissions (contents: write, etc).",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ci_curl_pipe_shell",
        "pattern": r"(?i)curl\s+.*\|\s*(?:ba)?sh",
        "message": "Piping curl to shell in CI is unsafe. Download, verify checksum, then execute.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ci_checkout_persist_creds",
        "pattern": r"(?i)persist-credentials:\s*true",
        "message": "Persisting Git credentials in CI. Set persist-credentials: false to minimize token exposure.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ci_inject_untrusted_input",
        "pattern": (
            r"\$\{\{\s*github\.event\."
            r"(?:issue|comment|pull_request|review|discussion)\."
            r"(?:title|body)\s*\}\}"
        ),
        "message": "Untrusted GitHub event data in expression. This enables command injection via issue/PR titles or bodies.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  GENERAL CONFIG HYGIENE (cross-cutting)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "config_ssl_verify_off",
        "pattern": r"(?i)(?:ssl[_-]?verify|verify[_-]?ssl|tls[_-]?verify)\s*[:=]\s*(?:false|0|no|off)\b",
        "message": "SSL/TLS certificate verification disabled. This enables man-in-the-middle attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg"],
    },
    {
        "id": "config_weak_tls_version",
        "pattern": r"(?i)(?:tls[_-]?(?:min[_-]?)?version|ssl[_-]?version|min[_-]?protocol)\s*[:=]\s*[\"']?(?:1\.[01]|TLSv1[^.2]|SSLv[23])",
        "message": "Legacy TLS/SSL version configured. Use TLS 1.2 or 1.3 only.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml", ".toml", ".ini", ".cfg"],
    },
    {
        "id": "config_world_writable",
        "pattern": r"(?i)(?:chmod|mode)\s*[:=]?\s*(?:0?777|a\+rwx)\b",
        "message": "World-writable permission (777). Restrict file permissions to owner and group.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml", ".toml", ".conf", ".service"],
    },
    {
        "id": "config_listen_all_interfaces",
        "pattern": r'(?i)(?:listen[_-]?address|bind[_-]?address|bind[_-]?host)\s*[:=]\s*["\']?0\.0\.0\.0',
        "message": "Service configured to listen on all interfaces. Bind to 127.0.0.1 or specific IPs in production.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml", ".toml", ".ini", ".conf", ".hcl"],
    },
    {
        "id": "config_private_key_inline",
        "pattern": r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        "message": "Private key embedded in config file. Store keys in secure vaults or separate key files with restricted permissions.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml", ".toml", ".ini", ".conf", ".cfg", ".hcl"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  PHASE 1 EXPANSION — Security, Secrets, Crypto, AI, Multi-lang
    #  Added 2026-03-19 to close gap vs SonarQube/Semgrep
    # ═══════════════════════════════════════════════════════════════

    # --- Python Injection & Deserialization ---
    {
        "id": "py_yaml_unsafe_load",
        "pattern": r"yaml\.load\s*\([^,)]+\)",
        "message": "yaml.load() without Loader is unsafe — use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_marshal_loads",
        "pattern": r"marshal\.loads?\s*\(",
        "message": "marshal.load/loads executes arbitrary code — avoid deserializing untrusted data with marshal",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_shelve_open_untrusted",
        "pattern": r"shelve\.open\s*\(",
        "message": "shelve uses pickle internally — do not open untrusted shelve files",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "py_xml_etree_parse",
        "pattern": r"etree\.(parse|fromstring|XML|XMLParser)\s*\(",
        "message": "xml.etree is vulnerable to XML bomb/entity attacks — use defusedxml instead",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "py_xmlrpc_server",
        "pattern": r"xmlrpc\.server\.|SimpleXMLRPCServer\s*\(",
        "message": "XMLRPC servers are vulnerable to XML entity attacks — validate input strictly",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "py_subprocess_shell_interpolation",
        "pattern": r"subprocess\.(run|call|Popen|check_output)\s*\(f['\"]",
        "message": "f-string in subprocess call is vulnerable to command injection — use list form with validated args",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_tempfile_mktemp",
        "pattern": r"tempfile\.mktemp\s*\(",
        "message": "tempfile.mktemp() has TOCTOU race — use tempfile.mkstemp() or tempfile.NamedTemporaryFile()",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace `tempfile.mktemp()` with `tempfile.mkstemp()` (returns fd+path) or "
            "`tempfile.NamedTemporaryFile(delete=False)` (returns file object). "
            "mktemp has a TOCTOU race — another process can create the file between name generation and use."
        ),
    },
    {
        "id": "py_flask_debug_mode",
        "pattern": r"app\.run\s*\([^)]*debug\s*=\s*True",
        "message": "Flask debug=True enables remote code execution via the debugger — disable in production",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace `app.run(debug=True)` with `app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')`. "
            "Or use Flask CLI: `flask run` reads FLASK_DEBUG from environment. "
            "The Werkzeug debugger allows arbitrary code execution — never enable in production."
        ),
    },
    {
        "id": "py_django_debug_true",
        "pattern": r"^DEBUG\s*=\s*True",
        "message": "Django DEBUG=True exposes stack traces and settings — must be False in production",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".cfg", ".ini"],
        "exclude_path_contains": ["test", "example", "sample"],
        "suggestion": (
            "Replace `DEBUG = True` with `DEBUG = os.environ.get('DJANGO_DEBUG', 'False').lower() == 'true'`. "
            "Or use django-environ: `DEBUG = env.bool('DJANGO_DEBUG', default=False)`. "
            "DEBUG=True exposes settings, SQL queries, and stack traces to end users."
        ),
    },
    {
        "id": "py_django_secret_key_hardcoded",
        "pattern": r"SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]",
        "message": "Django SECRET_KEY is hardcoded — load from environment variable",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace with `SECRET_KEY = os.environ['DJANGO_SECRET_KEY']`. "
            "Generate a strong key: `python -c \"from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())\"`. "
            "Add to .env and .env.example (with placeholder)."
        ),
    },
    {
        "id": "py_flask_secret_hardcoded",
        "pattern": r"app\.secret_key\s*=\s*['\"][^'\"]+['\"]",
        "message": "Flask secret_key is hardcoded — load from environment variable",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace with `app.secret_key = os.environ['FLASK_SECRET_KEY']`. "
            "Generate: `python -c \"import secrets; print(secrets.token_hex(32))\"`. "
            "The secret_key signs session cookies — if leaked, sessions can be forged."
        ),
    },
    {
        "id": "py_jinja2_autoescape_off",
        "pattern": r"Environment\s*\([^)]*autoescape\s*=\s*False",
        "message": "Jinja2 autoescape=False enables XSS — enable autoescape for HTML templates",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace `autoescape=False` with `autoescape=True` or use "
            "`select_autoescape(['html', 'xml'])` for selective escaping. "
            "Use `Markup()` or `|safe` filter only for explicitly trusted content."
        ),
    },
    {
        "id": "py_assert_auth",
        "pattern": r"assert\s+.*(auth|permission|role|admin|user)",
        "message": "assert is stripped by Python -O flag — never use assert for authentication checks",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace `assert user.is_admin` with an explicit check: "
            "`if not user.is_admin: raise PermissionError('Admin access required')`. "
            "Python's `-O` flag removes all assert statements — auth bypassed in optimized builds."
        ),
    },
    {
        "id": "py_open_write_path_traversal",
        "pattern": r"open\s*\(\s*(request|user|input|params|args|kwargs)",
        "message": "open() with user-controlled path enables path traversal — validate and sanitize path",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Sanitize the path: `safe_path = pathlib.Path(base_dir) / pathlib.Path(user_input).name`. "
            "Use `.resolve()` and verify it starts with the allowed base directory: "
            "`if not safe_path.resolve().is_relative_to(base_dir): raise ValueError('path traversal')`. "
            "Never pass raw user input to open()."
        ),
    },
    {
        "id": "py_header_injection",
        "pattern": r"response\.headers\s*\[.+\]\s*=\s*(request|user|input)",
        "message": "User-controlled value in response header enables header injection — sanitize value",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Strip newlines from user input before setting headers: "
            "`value = user_input.replace('\\r', '').replace('\\n', '')`. "
            "Or use a strict allowlist: `re.sub(r'[^a-zA-Z0-9_\\-]', '', value)`. "
            "Header injection enables response splitting and cache poisoning."
        ),
    },

    # --- JavaScript/TypeScript Injection ---
    {
        "id": "js_child_process_exec",
        "pattern": r"child_process\.exec\s*\(|require\(['\"]child_process['\"]\).*\.exec\s*\(",
        "message": "child_process.exec() is vulnerable to command injection — use execFile() with explicit args",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
        "suggestion": (
            "Replace `exec('cmd ' + userInput)` with `execFile('cmd', [userInput])`. "
            "execFile does not invoke a shell, preventing injection. "
            "For complex commands: use `spawn('cmd', args, {shell: false})`. "
            "If shell features needed: validate input against strict allowlist."
        ),
    },
    {
        "id": "js_innerhtml_xss",
        "pattern": r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])",
        "message": "innerHTML assignment is vulnerable to XSS — use textContent or DOMPurify.sanitize()",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx", ".html"],
        "suggestion": (
            "Replace `el.innerHTML = value` with `el.textContent = value` for text content. "
            "If HTML rendering required: `el.innerHTML = DOMPurify.sanitize(value)`. "
            "Install: `npm install dompurify`. Import: `import DOMPurify from 'dompurify'`."
        ),
    },
    {
        "id": "js_document_write",
        "pattern": r"document\.write\s*\(",
        "message": "document.write() is vulnerable to XSS and blocks rendering — use DOM manipulation instead",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx", ".html"],
        "suggestion": (
            "Replace `document.write(html)` with DOM manipulation: "
            "`const el = document.createElement('div'); el.textContent = text; document.body.appendChild(el)`. "
            "For React: use JSX rendering. document.write() blocks parsing and is never needed in modern code."
        ),
    },
    {
        "id": "js_prototype_pollution",
        "pattern": r"\.__proto__\s*=|Object\.assign\s*\(\s*\{\s*\}",
        "message": "Potential prototype pollution — avoid assigning to __proto__ or using Object.assign with untrusted input",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "js_eval_like",
        "pattern": r"\bFunction\s*\(\s*['\"]|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]",
        "message": "String passed to Function()/setTimeout()/setInterval() is equivalent to eval() — use function references",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "suggestion": (
            "Replace string argument with function reference: "
            "`setTimeout(() => doWork(), 1000)` instead of `setTimeout('doWork()', 1000)`. "
            "For Function(): use a closure or arrow function. String arguments are eval'd at runtime."
        ),
    },
    {
        "id": "js_sql_string_concat",
        "pattern": r"(query|execute|rawQuery)\s*\([`'\"].*\$\{|[`'\"].*\+\s*(req|user|params|input)",
        "message": "String concatenation in SQL query enables SQL injection — use parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "suggestion": (
            "Replace string interpolation with parameterized queries: "
            "Knex: `knex('users').where('id', userId)`. "
            "pg: `client.query('SELECT * FROM users WHERE id = $1', [userId])`. "
            "Prisma: `prisma.user.findUnique({where: {id: userId}})`. Never concatenate user input into SQL."
        ),
    },
    {
        "id": "js_regex_catastrophic",
        "pattern": r"new\s+RegExp\s*\(\s*(req|user|input|params|query)",
        "message": "User-controlled RegExp enables ReDoS — validate and limit user-provided patterns",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "suggestion": (
            "Never pass user input directly to `new RegExp()`. Instead: "
            "1. Escape user input: `input.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')`. "
            "2. Use string methods (includes, startsWith) instead of regex. "
            "3. If regex needed: use `re2` package (linear-time matching, no ReDoS)."
        ),
    },
    {
        "id": "js_insecure_cookie",
        "pattern": r"(httpOnly|secure)\s*:\s*false",
        "message": "Cookie with httpOnly:false or secure:false exposes session to XSS/MITM — set both to true",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "suggestion": (
            "Set secure cookie options: `{httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600000}`. "
            "httpOnly prevents JavaScript access (XSS protection). "
            "secure ensures HTTPS-only transmission. sameSite prevents CSRF."
        ),
    },
    {
        "id": "js_no_https_fetch",
        "pattern": r"fetch\s*\(\s*['\"]http://",
        "message": "fetch() over plain HTTP — use HTTPS to prevent MITM attacks",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "js_json_parse_no_catch",
        "pattern": r"JSON\.parse\s*\([^)]+\)(?!\s*\}?\s*catch)",
        "message": "JSON.parse() without try/catch will throw on invalid JSON — wrap in try/catch",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "js_postmessage_no_origin",
        "pattern": r"addEventListener\s*\(\s*['\"]message['\"]",
        "message": "message event listener — verify event.origin before processing to prevent cross-origin attacks",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "js_open_redirect",
        "pattern": r"window\.location\s*=\s*(req|user|input|params|query|location\.search)",
        "message": "Open redirect via user-controlled URL — validate destination against allowlist",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "suggestion": (
            "Validate redirect URL against an allowlist: "
            "`const allowed = ['/dashboard', '/profile']; "
            "if (!allowed.includes(url)) url = '/';`. "
            "For absolute URLs: verify hostname matches your domain. "
            "Never redirect to user-provided external URLs without validation."
        ),
    },
    {
        "id": "js_dangerously_set_html",
        "pattern": r"dangerouslySetInnerHTML\s*=",
        "message": "dangerouslySetInnerHTML bypasses React XSS protection — sanitize content with DOMPurify first",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },

    # --- Secrets Detection ---
    {
        "id": "secret_aws_access_key",
        "pattern": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
        "message": "Potential AWS Access Key ID — store in environment variable or AWS Secrets Manager",
        "severity": Severity.WARN,
    },
    {
        "id": "secret_aws_secret_key",
        "pattern": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
        "message": "Potential AWS Secret Access Key — store in environment variable or AWS Secrets Manager",
        "severity": Severity.WARN,
    },
    {
        "id": "secret_github_token",
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "message": "GitHub personal access token detected — revoke immediately and use secrets manager",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Revoke the token immediately at github.com/settings/tokens. "
            "2. Generate a new fine-grained token with minimal scopes. "
            "3. Store in env var: `os.environ['GITHUB_TOKEN']` (Python), `process.env.GITHUB_TOKEN` (JS). "
            "4. For CI: use GitHub Actions secrets (`${{ secrets.GITHUB_TOKEN }}`)."
        ),
    },
    {
        "id": "secret_stripe_key",
        "pattern": r"(sk|pk)_(test|live)_[A-Za-z0-9]{24,}",
        "message": "Stripe API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Roll the key in Stripe Dashboard → Developers → API keys. "
            "2. Store as env var: `STRIPE_SECRET_KEY` for sk_*, `STRIPE_PUBLISHABLE_KEY` for pk_*. "
            "3. Use restricted keys with minimal permissions for each service. "
            "4. For tests: use `sk_test_*` keys, never `sk_live_*` in code."
        ),
    },
    {
        "id": "secret_openai_key",
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "message": "OpenAI API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Revoke at platform.openai.com/api-keys. "
            "2. Create a new key with project-scoped permissions. "
            "3. Store as `OPENAI_API_KEY` env var. The OpenAI SDK reads it automatically. "
            "4. For orgs: use service accounts, not personal keys."
        ),
    },
    {
        "id": "secret_anthropic_key",
        "pattern": r"sk-ant-[A-Za-z0-9\-]{95,}",
        "message": "Anthropic API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Revoke at console.anthropic.com/settings/keys. "
            "2. Create a new key with workspace-scoped permissions. "
            "3. Store as `ANTHROPIC_API_KEY` env var. The Anthropic SDK reads it automatically. "
            "4. Use separate keys for dev/staging/prod environments."
        ),
    },
    {
        "id": "secret_sendgrid_key",
        "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "message": "SendGrid API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Revoke at app.sendgrid.com/settings/api_keys. "
            "2. Create a new key with restricted access (Mail Send only). "
            "3. Store as `SENDGRID_API_KEY` env var. "
            "4. Use API key permissions to limit to specific scopes."
        ),
    },
    {
        "id": "secret_twilio_sid",
        "pattern": r"AC[a-f0-9]{32}",
        "message": "Twilio Account SID detected — load from environment variable",
        "severity": Severity.WARN,
    },
    {
        "id": "secret_twilio_auth_token",
        "pattern": r"twilio.*['\"][a-f0-9]{32}['\"]",
        "message": "Twilio Auth Token detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Rotate in Twilio Console → Account → API keys. "
            "2. Store as `TWILIO_AUTH_TOKEN` env var. "
            "3. Use API keys (SK-prefixed) instead of Auth Token for production."
        ),
    },
    {
        "id": "secret_slack_token",
        "pattern": r"xox[baprs]-[A-Za-z0-9\-]+",
        "message": "Slack token detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Revoke at api.slack.com/apps → OAuth & Permissions → Revoke. "
            "2. Regenerate with minimal bot scopes. "
            "3. Store as `SLACK_BOT_TOKEN` env var. "
            "4. Use Socket Mode for development, HTTP endpoints for production."
        ),
    },
    {
        "id": "secret_jwt_hardcoded",
        "pattern": r"jwt\.sign\s*\([^,]+,\s*['\"][^'\"]{8,}['\"]",
        "message": "Hardcoded JWT secret — load signing key from environment variable",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "suggestion": (
            "Replace hardcoded secret with env var: "
            "`jwt.sign(payload, process.env.JWT_SECRET, {algorithm: 'HS256', expiresIn: '1h'})`. "
            "For production: use RS256 with key pair instead of shared secret. "
            "Minimum secret length: 256 bits (32 bytes)."
        ),
    },
    {
        "id": "secret_private_key_header",
        "pattern": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        "message": "Private key material in source code — store in secure key management system",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Remove the private key from source code immediately. Store in: "
            "1. AWS KMS / GCP Cloud KMS / Azure Key Vault for cloud environments. "
            "2. HashiCorp Vault for self-hosted. "
            "3. File system with 600 permissions referenced by path env var. "
            "Never commit private keys — add *.pem, *.key to .gitignore."
        ),
    },
    {
        "id": "secret_google_api_key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "message": "Google API key detected — restrict key and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Restrict key in Google Cloud Console → Credentials → Edit key → Application/API restrictions. "
            "2. Store as `GOOGLE_API_KEY` env var. "
            "3. For server-side: use service account with IAM roles instead of API key. "
            "4. Set referrer/IP restrictions to prevent unauthorized use."
        ),
    },
    {
        "id": "secret_heroku_api_key",
        "pattern": r"[hH]eroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "message": "Heroku API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "1. Regenerate at Heroku Dashboard → Account → API Key → Regenerate. "
            "2. Store as `HEROKU_API_KEY` env var. "
            "3. For CI: use Heroku OAuth tokens with limited scope instead of account API key."
        ),
    },
    {
        "id": "secret_gcp_service_account",
        "pattern": r'"type":\s*"service_account"',
        "message": "GCP service account credentials in source — store in secret manager, never commit",
        "severity": Severity.BLOCK,
        "file_types": [".json"],
        "suggestion": (
            "Remove the service account JSON from source code. Instead: "
            "1. Use Workload Identity Federation (no key file needed). "
            "2. If key file required: store in GCP Secret Manager, reference by path. "
            "3. Set `GOOGLE_APPLICATION_CREDENTIALS` env var to the key file path. "
            "4. Add *.json service account files to .gitignore."
        ),
    },
    {
        "id": "secret_redis_password",
        "pattern": r"redis://[^@\s]+:[^@\s]+@",
        "message": "Redis URL contains credentials — store in environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Store the full Redis URL in an env var: `REDIS_URL=redis://user:pass@host:port`. "
            "Reference via `os.environ['REDIS_URL']` (Python) or `process.env.REDIS_URL` (JS). "
            "For production: use Redis ACL with per-service credentials and TLS (`rediss://`)."
        ),
    },

    # --- Cryptography ---
    {
        "id": "crypto_md5_weak",
        "pattern": r"hashlib\.md5\s*\(|MD5\s*\(|\.md5\s*\(",
        "message": "MD5 is cryptographically broken — use SHA-256 or SHA-3 for security-sensitive hashing",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace MD5 with SHA-256: `hashlib.sha256(data).hexdigest()` (Python), "
            "`crypto.createHash('sha256').update(data).digest('hex')` (JS). "
            "For passwords: use bcrypt/argon2, never plain hashing. "
            "For checksums (non-security): MD5 is acceptable but document intent."
        ),
    },
    {
        "id": "crypto_sha1_weak",
        "pattern": r"hashlib\.sha1\s*\(|SHA1\s*\(|\.sha1\s*\(",
        "message": "SHA-1 is cryptographically weak — use SHA-256 or SHA-3 for security-sensitive hashing",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto_des_weak",
        "pattern": r"\bDES\b|\bTripleDES\b|Cipher\.DES|DES\.new\s*\(",
        "message": "DES/3DES is deprecated — use AES-256-GCM instead",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace DES/3DES with AES-256-GCM: "
            "Python: `from cryptography.hazmat.primitives.ciphers.aead import AESGCM; "
            "key = AESGCM.generate_key(bit_length=256)`. "
            "JS: `crypto.createCipheriv('aes-256-gcm', key, iv)`. "
            "AES-GCM provides both encryption and authentication."
        ),
    },
    {
        "id": "crypto_ecb_mode",
        "pattern": r"\.MODE_ECB\b|AES\.MODE_ECB|mode\s*=\s*['\"]?ECB",
        "message": "ECB mode reveals data patterns — use AES-GCM or AES-CBC with random IV",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace ECB with GCM mode: `AES.new(key, AES.MODE_GCM)` (pycryptodome) or "
            "`AESGCM(key).encrypt(nonce, data, None)` (cryptography). "
            "GCM provides authenticated encryption. Generate a unique nonce/IV per operation with `os.urandom(12)`."
        ),
    },
    {
        "id": "crypto_weak_random",
        "pattern": r"\brandom\.random\s*\(|\brandom\.randint\s*\(|\brandom\.choice\s*\(",
        "message": "random module is not cryptographically secure — use secrets module for security tokens",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "crypto_math_random_js",
        "pattern": r"Math\.random\s*\(",
        "message": "Math.random() is not cryptographically secure — use crypto.getRandomValues() for security tokens",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "crypto_rsa_small_key",
        "pattern": r"RSA\.generate\s*\(\s*[0-9]{1,3}[^0-9]|generate_key\s*\([^)]*\b(512|768|1024)\b",
        "message": "RSA key size below 2048 bits is insecure — use at least 2048, prefer 4096",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace with `RSA.generate(4096)` or `rsa.generate_private_key(public_exponent=65537, key_size=4096)`. "
            "Minimum: 2048 bits. Recommended: 4096 bits. "
            "For new systems: consider Ed25519 (EdDSA) — faster and more secure than RSA."
        ),
    },
    {
        "id": "crypto_hardcoded_iv",
        "pattern": r"iv\s*=\s*b['\"][^'\"]{8,16}['\"]|IV\s*=\s*b['\"][^'\"]+['\"]",
        "message": "Hardcoded IV for encryption — generate a random IV for each encryption operation",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace hardcoded IV with `iv = os.urandom(12)` for GCM or `os.urandom(16)` for CBC. "
            "Prepend the IV to the ciphertext: `output = iv + ciphertext`. "
            "The IV does not need to be secret but MUST be unique per encryption."
        ),
    },
    {
        "id": "crypto_ssl_no_verify",
        "pattern": r"verify\s*=\s*False|ssl_verify\s*=\s*False|VERIFY_PEER\s*=\s*False|check_hostname\s*=\s*False",
        "message": "SSL certificate verification disabled — enables MITM attacks",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Remove `verify=False`. If connecting to internal services with self-signed certs: "
            "1. Add the CA cert to a cert bundle: `verify='/path/to/ca-bundle.crt'`. "
            "2. Or add to system trust store. "
            "Never disable verification in production — it makes TLS pointless."
        ),
    },
    {
        "id": "crypto_ssl_v2_v3",
        "pattern": r"SSLv2|SSLv3|TLSv1_0|TLSv1_1|PROTOCOL_SSLv|ssl\.PROTOCOL_TLS\b",
        "message": "SSLv2/SSLv3/TLS1.0/TLS1.1 are deprecated — use TLS 1.2+ (PROTOCOL_TLS_CLIENT)",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace with TLS 1.2+: `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` (Python). "
            "Set minimum version: `ctx.minimum_version = ssl.TLSVersion.TLSv1_2`. "
            "For Node.js: `tls.createServer({minVersion: 'TLSv1.2'})`. "
            "SSLv2/v3 and TLS 1.0/1.1 have known vulnerabilities (POODLE, BEAST)."
        ),
    },
    {
        "id": "crypto_password_plaintext",
        "pattern": r"password\s*=\s*['\"][^'\"]{4,}['\"]",
        "message": "Plaintext password in source — load from environment variable",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Move password to environment variable: `os.environ['DB_PASSWORD']` (Python), "
            "`process.env.DB_PASSWORD` (JS). For local dev: use .env file (never committed). "
            "For production: use secrets manager (AWS SSM, HashiCorp Vault, Doppler)."
        ),
    },
    {
        "id": "crypto_weak_bcrypt_rounds",
        "pattern": r"bcrypt\.gensalt\s*\(\s*rounds\s*=\s*[1-9]\b|bcrypt\.gensalt\s*\(\s*[1-9]\b",
        "message": "bcrypt rounds below 10 is too weak — use at least 12 rounds",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "crypto_jwt_none_algorithm",
        "pattern": r"algorithm\s*=\s*['\"]none['\"]|algorithms\s*=\s*\[['\"]none['\"]",
        "message": "JWT 'none' algorithm disables signature verification — always specify a strong algorithm",
        "severity": Severity.BLOCK,
        "suggestion": (
            "Replace `algorithm='none'` with a strong algorithm: "
            "`algorithm='HS256'` for HMAC (shared secret) or `algorithm='RS256'` for RSA (key pair). "
            "Always verify: `jwt.decode(token, key, algorithms=['HS256'])` — note the list, never allow 'none'."
        ),
    },
    {
        "id": "crypto_insecure_hash_passwords",
        "pattern": r"hashlib\.(md5|sha1|sha256)\s*\([^)]*password",
        "message": "Plain hash for passwords — use bcrypt, argon2, or scrypt with salt",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Replace plain hashing with a dedicated password hasher: "
            "`from argon2 import PasswordHasher; ph = PasswordHasher(); hash = ph.hash(password)`. "
            "Or bcrypt: `import bcrypt; hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))`. "
            "Never use SHA-256/MD5 directly for passwords — they lack salt and iterations."
        ),
    },
    {
        "id": "crypto_empty_cipher_key",
        "pattern": r"key\s*=\s*b['\"]['\"]|encrypt\s*\([^,]+,\s*b['\"]['\"]",
        "message": "Empty encryption key — key must be cryptographically random and of correct length",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Generate a proper key: `key = os.urandom(32)` for AES-256 or "
            "`key = AESGCM.generate_key(bit_length=256)`. "
            "Store the key securely in a secrets manager or encrypted file. "
            "For key derivation from password: use `PBKDF2` or `Scrypt` with salt."
        ),
    },

    # --- AI-Specific Security ---
    {
        "id": "ai_prompt_user_input",
        "pattern": r"(prompt|messages)\s*=\s*f['\"].*\{(user|input|request|query|text)",
        "message": "User input directly interpolated into AI prompt — sanitize to prevent prompt injection",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "ai_llm_response_eval",
        "pattern": r"eval\s*\(\s*(llm|ai|gpt|claude|response|completion)",
        "message": "eval() on LLM response enables arbitrary code execution — never execute LLM output",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".ts", ".js"],
        "suggestion": (
            "Never eval() LLM output. Instead: "
            "1. Parse as JSON: `json.loads(llm_response)` for structured data. "
            "2. Use a restricted sandbox (RestrictedPython, VM2) if code execution is required. "
            "3. Validate against a schema before processing. "
            "LLM output is untrusted input — treat it like user input."
        ),
    },
    {
        "id": "ai_system_prompt_override",
        "pattern": r"system.*ignore.*previous|system.*disregard.*instructions|system.*you are now",
        "message": "Potential system prompt override in code — validate LLM system prompts at runtime",
        "severity": Severity.WARN,
    },
    {
        "id": "ai_function_call_no_validation",
        "pattern": r"function_call\[.name.\]|tool_calls\[.*\]\[.function.\]",
        "message": "LLM function call result used directly — validate function name and args before execution",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "ai_embedding_user_data",
        "pattern": r"embed\s*\(\s*(user|request|input|query)",
        "message": "User data passed directly to embedding — sanitize to prevent data leakage in vector stores",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "ai_rag_injection_path",
        "pattern": r"(context|retrieved|chunks)\s*=.*\+(user|input|query)",
        "message": "RAG context concatenated with user input — potential for context injection attacks",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "ai_model_hardcoded",
        "pattern": r"model\s*=\s*['\"]gpt-4-0314|gpt-4-0613|text-davinci-002['\"]",
        "message": "Deprecated OpenAI model hardcoded — use current model versions or config variable",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "ai_training_data_pii",
        "pattern": r"(training|finetune|dataset).*\.(email|ssn|credit_card|phone|address)",
        "message": "PII fields in training dataset — ensure PII is scrubbed before model training",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "ai_max_tokens_unset",
        "pattern": r"openai\.(chat\.completions|Completion)\.create\s*\([^)]*\)(?!.*max_tokens)",
        "message": "OpenAI call without max_tokens — set max_tokens to prevent runaway costs",
        "severity": Severity.INFO,
        "file_types": [".py"],
    },
    {
        "id": "ai_tool_arbitrary_exec",
        "pattern": r"@tool\s*\n.*def.*\(.*\).*\n.*subprocess|@tool\s*\n.*def.*os\.system",
        "message": "AI tool exposes subprocess/os.system — tools with shell execution are high-risk",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "suggestion": (
            "Remove shell execution from AI tool definitions. Instead: "
            "1. Use a strict allowlist of permitted commands. "
            "2. Run in a sandboxed environment (Docker, gVisor). "
            "3. Use subprocess.run with shell=False and validated argument list. "
            "AI agents may invoke tools with adversarial inputs via prompt injection."
        ),
    },

    # --- Go Security ---
    {
        "id": "go_fmt_errorf_wrap",
        "pattern": r'fmt\.Sprintf\s*\(\s*".*%s.*err',
        "message": "Use fmt.Errorf with %w to wrap errors for proper unwrapping with errors.As/Is",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "suggestion": "Replace `fmt.Sprintf(\"failed: %s\", err)` with `fmt.Errorf(\"failed: %w\", err)`. The %w verb wraps the error so callers can use errors.Is() and errors.As().",
    },
    {
        "id": "go_sql_injection",
        "pattern": r'db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.(Sprintf|Printf)',
        "message": "SQL query built with fmt.Sprintf is vulnerable to SQL injection — use parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "suggestion": (
            "Replace `db.Query(fmt.Sprintf(\"SELECT ... WHERE id = %s\", id))` with "
            "`db.Query(\"SELECT ... WHERE id = $1\", id)` (PostgreSQL) or "
            "`db.Query(\"SELECT ... WHERE id = ?\", id)` (MySQL). "
            "For complex queries: use sqlx or GORM query builders."
        ),
    },
    {
        "id": "go_os_exec_shell",
        "pattern": r'exec\.Command\s*\(\s*"sh"|exec\.Command\s*\(\s*"bash"|exec\.Command\s*\(\s*"cmd"',
        "message": "exec.Command with shell interpreter — use exec.Command with explicit args to avoid injection",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "suggestion": "Replace `exec.Command(\"sh\", \"-c\", cmd)` with `exec.Command(\"binary\", \"arg1\", \"arg2\")`. Pass arguments as separate strings to avoid shell injection.",
    },
    {
        "id": "go_http_listenandserve_no_tls",
        "pattern": r'http\.ListenAndServe\s*\(',
        "message": "http.ListenAndServe uses plain HTTP — use http.ListenAndServeTLS for production",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "suggestion": "Replace `http.ListenAndServe(addr, handler)` with `http.ListenAndServeTLS(addr, \"cert.pem\", \"key.pem\", handler)`. For local dev behind a reverse proxy, this may be acceptable.",
    },
    {
        "id": "go_tls_insecure_skip",
        "pattern": r"InsecureSkipVerify\s*:\s*true",
        "message": "InsecureSkipVerify:true disables TLS certificate validation — enables MITM attacks",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "suggestion": (
            "Remove `InsecureSkipVerify: true` from tls.Config. "
            "If connecting to internal services with self-signed certs, add the CA to the cert pool: "
            "`tlsConfig := &tls.Config{RootCAs: certPool}` where certPool contains your CA certificate. "
            "Never skip TLS verification in production."
        ),
    },
    {
        "id": "go_math_rand_security",
        "pattern": r"\bmath/rand\b|rand\.Intn\s*\(|rand\.Int63\s*\(",
        "message": "math/rand is not cryptographically secure — use crypto/rand for security-sensitive values",
        "severity": Severity.WARN,
        "file_types": [".go"],
    },
    {
        "id": "go_goroutine_leak",
        "pattern": r"go\s+func\s*\(\s*\)\s*\{",
        "message": "Anonymous goroutine — ensure goroutine is bounded and can exit (consider context cancellation)",
        "severity": Severity.INFO,
        "file_types": [".go"],
    },
    {
        "id": "go_defer_in_loop",
        "pattern": r"for\s+.*\{[^}]*defer\s+",
        "message": "defer inside loop delays execution until function return, not loop iteration — move defer outside loop",
        "severity": Severity.WARN,
        "file_types": [".go"],
    },
    {
        "id": "go_weak_cipher",
        "pattern": r"des\.NewCipher|rc4\.NewCipher|blowfish\.NewCipher",
        "message": "DES/RC4/Blowfish are deprecated ciphers — use AES-GCM (crypto/cipher with aes.NewGCM)",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "suggestion": (
            "Replace with AES-256-GCM: "
            "`block, _ := aes.NewCipher(key)` then `gcm, _ := cipher.NewGCM(block)`. "
            "Use a 32-byte key for AES-256. Generate nonces with crypto/rand. "
            "For key derivation: use golang.org/x/crypto/argon2 or scrypt."
        ),
    },
    {
        "id": "go_hardcoded_creds",
        "pattern": r'(password|secret|token|key)\s*:?=\s*"[^"]{6,}"',
        "message": "Hardcoded credentials in Go source — load from environment or secrets manager",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "suggestion": (
            "Replace hardcoded credentials with `os.Getenv(\"SECRET_NAME\")`. "
            "Use `godotenv.Load()` (github.com/joho/godotenv) for local development. "
            "For production: use cloud secret managers (AWS SSM, GCP Secret Manager, HashiCorp Vault)."
        ),
    },

    # --- Java Security ---
    {
        "id": "java_sql_injection",
        "pattern": r'(Statement|createStatement)\s*\.\s*(execute|executeQuery|executeUpdate)\s*\(\s*".*\+',
        "message": "SQL string concatenation in Java — use PreparedStatement with parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "suggestion": (
            "Replace Statement with PreparedStatement: "
            "`PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id = ?\"); "
            "ps.setInt(1, userId); ResultSet rs = ps.executeQuery();`. "
            "For JPA/Hibernate: use named parameters `:param` or Criteria API."
        ),
    },
    {
        "id": "java_deserialize_object",
        "pattern": r"ObjectInputStream\s*\(|readObject\s*\(\s*\)",
        "message": "Java deserialization is a critical RCE vector — validate class allow-list before deserializing",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "suggestion": (
            "Replace ObjectInputStream with a safe alternative: "
            "1. Use JSON (Jackson/Gson): `objectMapper.readValue(json, MyClass.class)`. "
            "2. If Java serialization is required, use `ObjectInputFilter` to whitelist classes. "
            "3. Never deserialize untrusted data without class filtering."
        ),
    },
    {
        "id": "java_xpath_injection",
        "pattern": r"xpath\.evaluate\s*\(|XPath\.compile\s*\(",
        "message": "XPath with user input enables XPath injection — use parameterized XPath or validate input",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "suggestion": "Validate and sanitize all user input before passing to XPath. Use XPathVariableResolver for parameterized queries instead of string concatenation.",
    },
    {
        "id": "java_xxe_factory",
        "pattern": r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature.*FEATURE_SECURE_PROCESSING)",
        "message": "DocumentBuilderFactory without XXE protection — disable external entity processing",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "suggestion": "Disable external entities: `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);`.",
    },
    {
        "id": "java_hardcoded_password",
        "pattern": r'(password|passwd|secret|apikey)\s*=\s*"[^"]{4,}"',
        "message": "Hardcoded password/secret in Java — load from environment or secrets manager",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "suggestion": (
            "Replace with `System.getenv(\"SECRET_NAME\")`. "
            "For Spring Boot: use `@Value(\"${SECRET_NAME}\")` or application.yml with env var references. "
            "For production: use HashiCorp Vault, AWS Secrets Manager, or Spring Cloud Config."
        ),
    },
    {
        "id": "java_weak_md5_sha1",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"',
        "message": "MD5/SHA-1 are cryptographically broken — use SHA-256 or stronger",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "suggestion": (
            "Replace `MessageDigest.getInstance(\"MD5\")` with `MessageDigest.getInstance(\"SHA-256\")`. "
            "For password hashing: use BCrypt (`BCrypt.hashpw()`) or Argon2 via BouncyCastle. "
            "For HMAC: use `Mac.getInstance(\"HmacSHA256\")`."
        ),
    },
    {
        "id": "java_runtime_exec",
        "pattern": r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
        "message": "Runtime.exec() with string argument is vulnerable to command injection — use ProcessBuilder with list",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "suggestion": (
            "Replace `Runtime.getRuntime().exec(cmd)` with ProcessBuilder: "
            "`new ProcessBuilder(List.of(\"cmd\", \"arg1\", \"arg2\")).start()`. "
            "ProcessBuilder takes arguments as a list, preventing shell injection. "
            "Never pass user input as a single string to exec()."
        ),
    },
    {
        "id": "java_random_not_secure",
        "pattern": r"\bnew\s+Random\s*\(\s*\)",
        "message": "java.util.Random is not cryptographically secure — use SecureRandom for security tokens",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "suggestion": "Replace `new Random()` with `SecureRandom.getInstanceStrong()` for tokens, keys, or nonces. `java.util.Random` is predictable and unsuitable for security purposes.",
    },
    {
        "id": "java_log_injection",
        "pattern": r"log\.(info|warn|error|debug)\s*\([^)]*\+\s*(request|user|input|param)",
        "message": "User input in log statement enables log injection — sanitize input before logging",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "suggestion": "Use parameterized logging: `log.info(\"User action: {}\", sanitizedInput)` instead of string concatenation. Strip newlines and control characters from user input before logging.",
    },
    {
        "id": "java_spring_actuator_all",
        "pattern": r"management\.endpoints\.web\.exposure\.include\s*=\s*\*",
        "message": "All Spring Boot Actuator endpoints exposed — restrict to specific endpoints in production",
        "severity": Severity.BLOCK,
        "file_types": [".properties", ".yml", ".yaml"],
        "suggestion": (
            "Replace `management.endpoints.web.exposure.include=*` with specific endpoints: "
            "`management.endpoints.web.exposure.include=health,info,metrics`. "
            "Secure sensitive endpoints with Spring Security: "
            "`management.endpoints.web.exposure.exclude=env,beans,configprops`."
        ),
    },

    # --- C/C++ Security ---
    {
        "id": "c_gets_unsafe",
        "pattern": r"\bgets\s*\(",
        "message": "gets() has no bounds checking — use fgets() with explicit buffer size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
        "suggestion": (
            "Replace `gets(buf)` with `fgets(buf, sizeof(buf), stdin)`. "
            "fgets() reads at most sizeof(buf)-1 characters and null-terminates. "
            "Note: gets() was removed from C11 standard — this code will not compile with modern compilers."
        ),
    },
    {
        "id": "c_strcpy_unsafe",
        "pattern": r"\bstrcpy\s*\(",
        "message": "strcpy() is vulnerable to buffer overflow — use strncpy() or strlcpy() with size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
        "suggestion": (
            "Replace `strcpy(dst, src)` with `strncpy(dst, src, sizeof(dst) - 1); dst[sizeof(dst) - 1] = '\\0';`. "
            "Or use `strlcpy(dst, src, sizeof(dst))` on BSD/macOS. "
            "For C++: use `std::string` instead of C-style string operations."
        ),
    },
    {
        "id": "c_sprintf_unsafe",
        "pattern": r"\bsprintf\s*\(",
        "message": "sprintf() is vulnerable to buffer overflow — use snprintf() with buffer size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
        "suggestion": (
            "Replace `sprintf(buf, fmt, ...)` with `snprintf(buf, sizeof(buf), fmt, ...)`. "
            "snprintf guarantees null-termination and prevents buffer overflow. "
            "For C++: use `std::format()` (C++20) or `std::ostringstream`."
        ),
    },
    {
        "id": "c_strcat_unsafe",
        "pattern": r"\bstrcat\s*\(",
        "message": "strcat() is vulnerable to buffer overflow — use strncat() with remaining size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
        "suggestion": (
            "Replace `strcat(dst, src)` with `strncat(dst, src, sizeof(dst) - strlen(dst) - 1)`. "
            "Or use `strlcat(dst, src, sizeof(dst))` on BSD/macOS. "
            "For C++: use `std::string::append()` or `+=` operator."
        ),
    },
    {
        "id": "c_scanf_unsafe",
        "pattern": r"\bscanf\s*\(",
        "message": "scanf() without width specifier is vulnerable to buffer overflow — use width-limited format strings",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
    },
    {
        "id": "c_system_call",
        "pattern": r"\bsystem\s*\(",
        "message": "system() is vulnerable to command injection — use execve() with validated args",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
        "suggestion": (
            "Replace `system(cmd)` with `execve()` or `posix_spawn()` with explicit argument array. "
            "Example: `char *args[] = {\"cmd\", \"arg1\", NULL}; execve(\"/usr/bin/cmd\", args, environ);`. "
            "system() passes through shell — any metacharacter in input enables injection."
        ),
    },
    {
        "id": "c_malloc_no_null_check",
        "pattern": r"\bmalloc\s*\(",
        "message": "malloc() return value not checked — verify pointer is not NULL before dereferencing",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
    },
    {
        "id": "c_format_string_vuln",
        "pattern": r"printf\s*\(\s*\w+\s*\)|fprintf\s*\(\s*\w+\s*,\s*\w+\s*\)",
        "message": "printf with variable as format string — use printf(\"%s\", var) to prevent format string attacks",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp"],
        "suggestion": (
            "Replace `printf(user_str)` with `printf(\"%s\", user_str)`. "
            "A variable format string allows attackers to read/write memory via %x, %n specifiers. "
            "Same applies to fprintf, sprintf, snprintf — always use a literal format string."
        ),
    },
    {
        "id": "c_integer_overflow",
        "pattern": r"\(int\)\s*strlen\s*\(|\(int\)\s*sizeof\s*\(",
        "message": "Casting size_t/ssize_t to int may overflow on large inputs — use size_t consistently",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp"],
    },
    {
        "id": "c_use_after_free",
        "pattern": r"free\s*\([^)]+\)\s*;[^\n]*\n[^\n]*\*\s*\w+\s*=",
        "message": "Potential use-after-free — set pointer to NULL immediately after free()",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp"],
    },

    # --- Rust Security ---
    {
        "id": "rust_unwrap_in_production",
        "pattern": r"\.unwrap\s*\(\s*\)",
        "message": ".unwrap() panics on None/Err — use ? operator, expect() with message, or match for error handling",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "suggestion": (
            "Replace `.unwrap()` with the `?` operator: `let value = fallible_fn()?;`. "
            "Or use `.expect(\"context message\")` for better panic messages. "
            "For Option: use `.unwrap_or(default)` or `.unwrap_or_else(|| compute_default())`. "
            "In libraries: never unwrap — always propagate errors to callers."
        ),
    },
    {
        "id": "rust_command_new_shell",
        "pattern": r'Command::new\s*\(\s*"sh"\s*\)|Command::new\s*\(\s*"bash"\s*\)',
        "message": "Command::new with shell interpreter — pass args directly to Command::new to avoid injection",
        "severity": Severity.WARN,
        "file_types": [".rs"],
    },
    {
        "id": "rust_hardcoded_secret",
        "pattern": r'(secret|password|api_key|token)\s*=\s*"[^"]{6,}"',
        "message": "Hardcoded secret in Rust — load from environment with std::env::var()",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
        "suggestion": (
            "Replace with `std::env::var(\"SECRET_NAME\").expect(\"SECRET_NAME must be set\")`. "
            "Use dotenv crate for local dev. For production: use cloud secrets manager."
        ),
    },
    {
        "id": "rust_sqlx_raw_query",
        "pattern": r'sqlx::query\s*\(\s*&format!\s*\(',
        "message": "sqlx::query with format! string is SQL injection — use query! macro or bind parameters",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
        "suggestion": (
            "Replace `sqlx::query(&format!(...))` with `sqlx::query!(\"SELECT ... WHERE id = $1\", id)` "
            "or `sqlx::query(\"...\").bind(id)`. The query! macro validates SQL at compile time."
        ),
    },
    {
        "id": "rust_from_utf8_unchecked",
        "pattern": r"from_utf8_unchecked\s*\(",
        "message": "from_utf8_unchecked() causes UB on invalid UTF-8 — use from_utf8() with error handling",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
        "suggestion": (
            "Replace `from_utf8_unchecked(bytes)` with `String::from_utf8(bytes)?` or "
            "`str::from_utf8(bytes)?`. The safe versions return Result and handle invalid UTF-8 gracefully."
        ),
    },
    {
        "id": "rust_mem_transmute",
        "pattern": r"std::mem::transmute\s*\(",
        "message": "mem::transmute is extremely unsafe — use safe conversions (as, From/Into, bytemuck) instead",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "suggestion": (
            "Replace transmute with safe alternatives: `as` for numeric casts, `From/Into` for type "
            "conversions, `bytemuck::cast` for POD types, `zerocopy::FromBytes` for zero-copy parsing."
        ),
    },
    {
        "id": "rust_panic_in_lib",
        "pattern": r"\bpanic!\s*\(",
        "message": "panic! in library code — return Result/Option to let callers handle errors",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "suggestion": (
            "Replace `panic!(\"msg\")` with `return Err(MyError::new(\"msg\"))`. Define a custom error "
            "type implementing std::error::Error. Use thiserror crate for ergonomic error types."
        ),
    },

    # --- Shell Security ---
    {
        "id": "sh_curl_bash_pipe",
        "pattern": r"curl\s+.*\|\s*(bash|sh)\b|wget\s+.*\|\s*(bash|sh)\b",
        "message": "curl|bash pipe executes remote code without verification — download, verify checksum, then execute",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Download first, verify, then execute: `curl -fsSL url -o script.sh && "
            "sha256sum -c checksum.txt && bash script.sh`. Or use a package manager "
            "(apt, brew, pip) instead of curl|bash."
        ),
    },
    {
        "id": "sh_chmod_777",
        "pattern": r"chmod\s+(777|a\+rwx|ugo\+rwx)",
        "message": "chmod 777 grants world-writable permissions — use minimal permissions (e.g., 755 for executables)",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Use minimal permissions: `chmod 755` for executables, `chmod 644` for files, "
            "`chmod 600` for secrets. 777 allows any user to read, write, and execute."
        ),
    },
    {
        "id": "sh_rm_rf_root",
        "pattern": r"rm\s+-[rf]+\s+/[^/\w]|rm\s+-[rf]+\s+\$HOME\s+|rm\s+-[rf]+\s+~\s+",
        "message": "rm -rf targeting root or home directory — add path validation before destructive operations",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Add a safety check: `if [ -n \"$DIR\" ] && [ \"$DIR\" != \"/\" ]; then rm -rf \"$DIR\"; fi`. "
            "Use `set -u` to fail on undefined variables. Never rm -rf with variable paths without validation."
        ),
    },
    {
        "id": "sh_unquoted_variable",
        "pattern": r"\$[A-Za-z_][A-Za-z0-9_]*(?!\s*['\"]|[A-Za-z0-9_\(])",
        "message": "Unquoted variable in shell — use \"$VAR\" to prevent word splitting and globbing",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Always double-quote variables: `\"$variable\"` instead of `$variable`. Unquoted variables "
            "are subject to word splitting and glob expansion, causing bugs with spaces and special characters."
        ),
    },
    {
        "id": "sh_sudo_without_check",
        "pattern": r"\bsudo\s+",
        "message": "sudo usage — ensure script validates it's running with appropriate privileges",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Check if running as root first: `if [ \"$(id -u)\" -ne 0 ]; then echo 'Run as root'; exit 1; fi`. "
            "Or use `sudo -n` (non-interactive) to fail fast if password required."
        ),
    },
    {
        "id": "sh_eval_variable",
        "pattern": r"\beval\s+\$",
        "message": "eval with variable enables code injection — avoid eval; use case statements or arrays",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Remove eval and use direct command execution. If dynamic commands are needed, use an array: "
            "`cmd=(\"binary\" \"--flag\" \"$value\"); \"${cmd[@]}\"`. eval enables injection attacks."
        ),
    },
    {
        "id": "sh_source_remote",
        "pattern": r"source\s+<\s*\(curl|source\s+<\s*\(wget|\.\s+<\s*\(curl",
        "message": "Sourcing remote content executes untrusted code — download and verify before sourcing",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
        "suggestion": (
            "Download to local file first, inspect, then source: `curl -fsSL url -o lib.sh && "
            "cat lib.sh && source lib.sh`. Never source remote URLs directly — you cannot verify the content."
        ),
    },

    # --- ORM & Database ---
    {
        "id": "orm_raw_query",
        "pattern": r"\.(raw|raw_query|execute_sql)\s*\(\s*f['\"]|\.raw\s*\(\s*['\"].*%s",
        "message": "Raw ORM query with string interpolation — use parameterized raw() or ORM query builder",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "db_no_index_foreign_key",
        "pattern": r"ForeignKey\s*\([^)]+\)(?!.*db_index)",
        "message": "ForeignKey without db_index — add db_index=True or create explicit index for JOIN performance",
        "severity": Severity.INFO,
        "file_types": [".py"],
    },
    {
        "id": "db_connection_string_hardcoded",
        "pattern": r"(postgres|mysql|mongodb|mssql)://[^@\s]+:[^@\s]+@",
        "message": "Database connection string with credentials — store in environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "db_migration_drop_column",
        "pattern": r"drop_column|DROP\s+COLUMN|RemoveColumn",
        "message": "Column removal migration — ensure application is deployed without reference to column first (zero-downtime)",
        "severity": Severity.WARN,
        "file_types": [".py", ".rb", ".sql"],
    },
    {
        "id": "db_migration_no_transaction",
        "pattern": r"(migration|migrate).*atomic\s*=\s*False",
        "message": "Migration with atomic=False — ensure non-transactional operations are idempotent and safe",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },

    # --- Logging Security ---
    {
        "id": "log_sensitive_data",
        "pattern": r"(log|logger|logging)\.(info|debug|warning|error)\s*\(.*\b(password|secret|token|api_key|secret_key|private_key|credit_card|ssn|cvv)\b",
        "message": "Sensitive data in log statement — redact secrets before logging",
        "severity": Severity.BLOCK,
    },
    {
        "id": "log_user_input_raw",
        "pattern": r"(log|logger)\.(info|debug)\s*\(.*\b(request|user_input|query|body)\b",
        "message": "Raw user input in log — sanitize newlines and control characters to prevent log injection",
        "severity": Severity.WARN,
    },
    {
        "id": "log_exception_swallowed",
        "pattern": r"except\s+\w+(\s+as\s+\w+)?\s*:\s*\n\s*pass\s*$",
        "message": "Exception silently swallowed — log the exception at minimum before passing",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "log_stack_trace_to_user",
        "pattern": r"traceback\.print_exc\s*\(\s*\)|traceback\.format_exc\s*\(\s*\).*response",
        "message": "Stack trace exposed to user response — log internally and return generic error message",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },

    # --- API Security ---
    {
        "id": "api_cors_wildcard",
        "pattern": r"Access-Control-Allow-Origin['\"]?\s*:\s*['\"]?\*|allow_origins\s*=\s*\[['\"]?\*['\"]?\]",
        "message": "CORS wildcard origin — restrict to specific trusted domains in production",
        "severity": Severity.WARN,
    },
    {
        "id": "api_no_rate_limit",
        "pattern": r"@(app|router)\.(post|put|delete)\s*\(['\"]/(login|register|forgot|reset|verify)",
        "message": "Auth endpoint without rate limiting decorator — add rate limiting to prevent brute force",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "api_sensitive_in_url",
        "pattern": r"@(app|router|get|post)\s*\(['\"].*/(token|password|secret|key|auth)\?",
        "message": "Sensitive parameter in URL path — use request body or header instead",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "api_http_method_override",
        "pattern": r"X-HTTP-Method-Override|methodOverride\s*\(",
        "message": "HTTP method override header — disable if not required; enables bypass of method-based ACL",
        "severity": Severity.INFO,
    },
    {
        "id": "api_no_content_type_check",
        "pattern": r'request\.(json|get_json)\s*\(\s*force\s*=\s*True',
        "message": "force=True bypasses Content-Type check — validate Content-Type header to prevent CSRF via form posts",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "api_jwt_no_expiry",
        "pattern": r"jwt\.(encode|sign)\s*\([^)]*\)(?!.*exp)",
        "message": "JWT token without expiry claim — add exp claim to limit token lifetime",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },

    # --- Infrastructure as Code ---
    {
        "id": "iac_s3_public_acl",
        "pattern": r"acl\s*=\s*['\"]public-read|BlockPublicAcls\s*=\s*false|IgnorePublicAcls\s*=\s*false",
        "message": "S3 bucket with public ACL — use bucket policies with explicit grants instead",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".hcl", ".json", ".yaml", ".yml"],
    },
    {
        "id": "iac_iam_star_action",
        "pattern": r'"Action"\s*:\s*"\*"|action\s*=\s*\["\*"\]',
        "message": "IAM policy with wildcard Action (*) — specify minimum required permissions",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".hcl", ".json"],
    },
    {
        "id": "iac_iam_star_resource",
        "pattern": r'"Resource"\s*:\s*"\*"(?!\s*//.*least)',
        "message": "IAM policy with wildcard Resource (*) — scope to specific ARNs",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl", ".json"],
    },
    {
        "id": "iac_security_group_all_ingress",
        "pattern": r"cidr_blocks\s*=\s*\[\"0\.0\.0\.0/0\"\]",
        "message": "Security group open to all ingress (0.0.0.0/0) — restrict to required CIDR ranges",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "iac_no_encryption_at_rest",
        "pattern": r"encrypted\s*=\s*false|storage_encrypted\s*=\s*false",
        "message": "Storage encryption disabled — enable encryption at rest for compliance and security",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".hcl"],
    },
    {
        "id": "iac_deletion_protection_off",
        "pattern": r"deletion_protection\s*=\s*false|prevent_destroy\s*=\s*false",
        "message": "Deletion protection disabled on critical resource — enable to prevent accidental destruction",
        "severity": Severity.WARN,
        "file_types": [".tf", ".hcl"],
    },

    # --- Kotlin Security ---
    {
        "id": "kt_hardcoded_secret",
        "pattern": r'val\s+(secret|password|apiKey|token)\s*=\s*"[^"]{6,}"',
        "message": "Hardcoded secret in Kotlin — load from BuildConfig, environment, or secrets manager",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".kts"],
    },
    {
        "id": "kt_webview_javascript",
        "pattern": r"settings\.javaScriptEnabled\s*=\s*true",
        "message": "WebView with JavaScript enabled — ensure addJavascriptInterface targets API 17+ and is restricted",
        "severity": Severity.WARN,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "kt_log_sensitive",
        "pattern": r"Log\.(d|i|w|e)\s*\(.*\b(password|token|key|secret)\b",
        "message": "Sensitive data in Android Log — Android logs are readable by apps with READ_LOGS permission",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "kt_sql_injection",
        "pattern": r"rawQuery\s*\(\s*\".*\$|rawQuery\s*\(\s*\".*\+",
        "message": "rawQuery with string interpolation — use selection args parameter for parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "kt_shared_prefs_mode_world",
        "pattern": r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
        "message": "SharedPreferences with world-readable/writable mode — deprecated since API 17, use MODE_PRIVATE",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },

    # --- GraphQL Security ---
    {
        "id": "graphql_introspection_enabled",
        "pattern": r"introspection\s*=\s*True|enable_introspection\s*=\s*True",
        "message": "GraphQL introspection enabled — disable in production to prevent schema enumeration",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "graphql_no_depth_limit",
        "pattern": r"GraphQL\s*\(|graphene\.Schema|make_executable_schema",
        "message": "GraphQL schema without depth limit — add query depth limiting to prevent DoS via deeply nested queries",
        "severity": Severity.INFO,
        "file_types": [".py", ".js", ".ts"],
    },
    {
        "id": "graphql_resolver_no_auth",
        "pattern": r"def\s+resolve_\w+\s*\(self,\s*info\s*\)(?!\s*:\s*\n.*is_authenticated)",
        "message": "GraphQL resolver without authentication check — add info.context.user.is_authenticated guard",
        "severity": Severity.INFO,
        "file_types": [".py"],
    },


    # ═══════════════════════════════════════════════════════════════
    #  PHASE 3 EXPANSION — Deeper Language & Framework Rules
    #  Added 2026-03-19 for competitive parity
    # ═══════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════
    #  TYPESCRIPT DEEP RULES (.ts / .tsx)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ts_any_cast",
        "pattern": r"\bas\s+any\b",
        "message": "'as any' cast bypasses type safety entirely. Use a proper type assertion or fix the type.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_non_null_assertion",
        "pattern": r"\w+!\.\w+",
        "message": "Non-null assertion operator (!) bypasses null checking. Use optional chaining or proper null guards.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_ts_ignore",
        "pattern": r"@ts-ig" + r"nore",
        "message": "@ts-ignore suppresses type errors. Fix the underlying type issue instead.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".tsx"],
    },
    {
        "id": "ts_ts_expect_error",
        "pattern": r"@ts-expect-error(?!\s+\S)",
        "message": "@ts-expect-error without a description. Add a comment explaining why the suppression is needed.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx"],
    },
    {
        "id": "ts_enum_mismatch",
        "pattern": r"===?\s*\d+.*enum\b|enum\b.*===?\s*\d+",
        "message": "Numeric comparison on string enum value. Compare against the enum member, not a number.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_promise_no_catch",
        "pattern": r"\.then\s*\([^)]*\)\s*;",
        "message": ".then() without .catch() leaves promise rejections unhandled. Add .catch() or use async/await with try/catch.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx", ".js", ".jsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_optional_chain_void",
        "pattern": r"\?\.\w+\(\)\s*\?\.",
        "message": "Optional chaining on void return value. The method may return undefined, making further chaining unsafe.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_no_infer",
        "pattern": r":\s*(?:Record|Map|Set|Promise|Observable)<[^>]*<[^>]*<",
        "message": "Deeply nested generic without explicit type annotation. Extract to a named type alias for clarity.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_unsafe_return_any",
        "pattern": r"(?:=>|return)\s+\w+\s+as\s+any\b",
        "message": "Function returns 'as any', erasing type safety for all callers. Use a proper return type.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "ts_index_signature_unsafe",
        "pattern": r"\[key:\s*string\]\s*:\s*any\b",
        "message": "Index signature with 'any' value type. Use a specific type or Record<string, T> with a concrete T.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  GO DEEP RULES (.go)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "go_error_ignored",
        "pattern": r"\b\w+,\s*_\s*(?::=|=)\s*\w+\(",
        "message": "Error return value explicitly ignored with '_'. Check and handle the error.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Handle the error: `result, err := fn(); if err != nil { return fmt.Errorf(\"context: %w\", err) }`. "
            "If truly ignorable, document why: `_ = fn() // error ignored: best-effort cleanup`."
        ),
    },
    {
        "id": "go_context_background",
        "pattern": r"context\.Background\(\)",
        "message": "context.Background() in handler code. Use the request context (r.Context()) for proper cancellation.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Replace `context.Background()` with the request context: `ctx := r.Context()` in HTTP handlers. "
            "For non-HTTP: accept context as first parameter `func DoWork(ctx context.Context, ...)`."
        ),
    },
    {
        "id": "go_sync_mutex_copy",
        "pattern": r"func\s+\w+\([^)]*\bsync\.(?:Mutex|RWMutex)\b[^*]",
        "message": "sync.Mutex passed by value (copied). Pass by pointer (*sync.Mutex) to avoid data races.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Change function signature to accept pointer: `func Process(mu *sync.Mutex)` or embed in a "
            "struct with pointer receiver. Copying a mutex duplicates its lock state — causes data races."
        ),
    },
    {
        "id": "go_channel_leak",
        "pattern": r"go\s+func\s*\([^)]*\)\s*\{[^}]*<-\s*\w+",
        "message": "Goroutine blocking on channel without select/timeout. Use select with context.Done() or time.After.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Add timeout or cancellation: `select { case msg := <-ch: handle(msg); case <-ctx.Done(): "
            "return; case <-time.After(30*time.Second): return }`. Never block indefinitely on a channel in a goroutine."
        ),
    },
    {
        "id": "go_nil_map_write",
        "pattern": r"var\s+\w+\s+map\[",
        "message": "Declared map variable without initialization. Writing to a nil map causes a panic. Use make(map[...]).",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Initialize the map: `m := make(map[string]int)` instead of `var m map[string]int`. "
            "Or use a map literal: `m := map[string]int{}`. Writing to a nil map panics at runtime."
        ),
    },
    {
        "id": "go_string_builder",
        "pattern": r"for\s.*\{[^}]*\+\s*=\s*[\"']|for\s.*\{[^}]*=\s*\w+\s*\+\s*[\"']",
        "message": "String concatenation in loop. Use strings.Builder for efficient string building.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Use strings.Builder: `var sb strings.Builder; for _, s := range items { sb.WriteString(s) }; result := sb.String()`. This is O(n) vs O(n^2) for += concatenation.",
    },
    {
        "id": "go_race_condition",
        "pattern": r"go\s+func\s*\([^)]*\)\s*\{[^}]*\b(?:append|delete)\s*\(",
        "message": "Shared data structure modified in goroutine without synchronization. Use sync.Mutex or channels.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Protect shared data with sync.Mutex: `mu.Lock(); defer mu.Unlock(); slice = append(slice, item)`. "
            "Or use channels to serialize access. Run `go test -race` to detect races."
        ),
    },
    {
        "id": "go_json_omitempty",
        "pattern": r'(?:type\s+\w+\s+struct\s*\{[^}]*\b\w+\s+\w+\s*$)',
        "message": "Struct field without json tag. Add json tags for correct serialization behavior.",
        "severity": Severity.INFO,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_http_no_timeout",
        "pattern": r"&http\.Client\s*\{\s*\}|http\.Client\{\s*\}",
        "message": "http.Client without Timeout. Set a Timeout to prevent requests from hanging indefinitely.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Set a timeout: `client := &http.Client{Timeout: 30 * time.Second}`. For fine-grained control: "
            "set DialContext timeout, TLSHandshakeTimeout, and ResponseHeaderTimeout separately."
        ),
    },
    {
        "id": "go_log_fatal_handler",
        "pattern": r"(?:func\s+\w*[Hh]andl\w*|ServeHTTP).*\{[^}]*log\.Fatal",
        "message": "log.Fatal in HTTP handler calls os.Exit(1), killing the entire server. Use log.Println and http.Error instead.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": (
            "Replace `log.Fatal(err)` with `log.Println(err); http.Error(w, \"Internal Server Error\", "
            "http.StatusInternalServerError); return`. log.Fatal kills the entire server process."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  JAVA DEEP RULES (.java)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "java_spring_csrf_disabled",
        "pattern": r"\.csrf\(\)\.disable\(\)",
        "message": "CSRF protection disabled in Spring Security. Only disable for stateless APIs with token auth.",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
        "suggestion": "Only disable CSRF for stateless REST APIs using JWT/Bearer tokens. For session-based auth, keep CSRF enabled: `.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))`.",
    },
    {
        "id": "java_equals_null",
        "pattern": r"\.\s*equals\s*\(\s*null\s*\)",
        "message": ".equals(null) always returns false and can throw NPE. Use '== null' for null checks.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
        "suggestion": "Replace `obj.equals(null)` with `obj == null`. For null-safe comparison with a constant, use `\"constant\".equals(obj)` (constant on the left).",
    },
    {
        "id": "java_string_concat_loop",
        "pattern": r"(?:for|while)\s*\([^)]*\)\s*\{[^}]*\+\s*=\s*\"",
        "message": "String concatenation with += in loop creates O(n^2) allocations. Use StringBuilder.",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "java_system_exit",
        "pattern": r"System\.exit\s*\(",
        "message": "System.exit() terminates the JVM. Use exceptions or return codes for non-main code.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
        "suggestion": "Throw an exception instead: `throw new RuntimeException(\"Fatal: ...\")`. In Spring Boot, use `SpringApplication.exit(ctx, () -> exitCode)`. Reserve System.exit() for CLI main() only.",
    },
    {
        "id": "java_thread_sleep_sync",
        "pattern": r"synchronized\s*\([^)]*\)\s*\{[^}]*Thread\.sleep\s*\(",
        "message": "Thread.sleep() inside synchronized block holds the lock while sleeping. Release the lock first.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
        "suggestion": "Use `obj.wait(timeout)` instead of `Thread.sleep()` inside synchronized blocks — wait() releases the monitor lock. Or move the sleep outside the synchronized block.",
    },
    {
        "id": "java_catch_throwable",
        "pattern": r"catch\s*\(\s*(?:Throwable|Error)\s+",
        "message": "Catching Throwable/Error includes JVM errors (OutOfMemoryError). Catch specific Exception types.",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "java_public_static_field",
        "pattern": r"public\s+static\s+(?!final\b)\w+\s+\w+\s*[=;]",
        "message": "Public static non-final field is mutable global state. Make it final or use proper encapsulation.",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "java_reflection_invoke",
        "pattern": r"\bmethod\.invoke\s*\(",
        "message": "Reflective method invocation without access control check. Validate method accessibility and caller permissions.",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "java_weak_ssl_context",
        "pattern": r'SSLContext\.getInstance\s*\(\s*"(?:SSL|TLSv1(?:\.0)?)"',
        "message": "Weak SSL/TLS context. Use TLSv1.2 or TLSv1.3 for secure communications.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "java_hibernate_native_sql",
        "pattern": r"(?:session|entityManager)\.create(?:Native|SQL)Query\s*\(\s*[\"'].*\+",
        "message": "Native SQL query with string concatenation. Use parameterized queries to prevent SQL injection.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  RUST DEEP RULES (.rs)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "rust_todo_macro",
        "pattern": r"\btodo!\s*\(",
        "message": "todo!() macro will panic at runtime. Implement the logic or return a proper error.",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_clone_on_ref",
        "pattern": r"&\w+\.clone\(\)",
        "message": "Cloning a reference creates an unnecessary allocation. Use the reference directly or borrow.",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_box_default",
        "pattern": r"Box::new\(Default::default\(\)\)",
        "message": "Use Box::default() instead of Box::new(Default::default()) for clarity.",
        "severity": Severity.INFO,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_expect_no_message",
        "pattern": r'\.expect\(\s*""\s*\)',
        "message": ".expect() with empty message gives no context on panic. Provide a descriptive error message.",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_string_push_str",
        "pattern": r"format!\s*\(\s*\"\{\}\{\}\"\s*,",
        "message": "format!() for simple string append. Use push_str() or write!() for better performance.",
        "severity": Severity.INFO,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_index_unchecked",
        "pattern": r"\w+\[\s*\w+\s*\](?!\s*=)",
        "message": "Direct indexing can panic on out-of-bounds. Use .get(i) for safe access with Option return.",
        "severity": Severity.INFO,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_async_recursion",
        "pattern": r"async\s+fn\s+(\w+)[^}]*\b\1\s*\(",
        "message": "Async function with direct recursion can cause stack overflow. Use async-recursion crate or Box::pin.",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "rust_arc_mutex_lock",
        "pattern": r"Arc<Mutex<.*>>\s*.*\.lock\(\).*\.await",
        "message": "Mutex lock held across .await point can cause deadlocks. Use tokio::sync::Mutex for async contexts.",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SWIFT RULES (.swift)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "swift_force_unwrap",
        "pattern": r"\w+!\s*\.",
        "message": "Force unwrap (!) crashes on nil. Use optional binding (if let/guard let) or nil coalescing (??).",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Replace `value!` with `guard let value = optional else { return }` or "
            "`if let value = optional { ... }`. For guaranteed values: use `?? defaultValue`. "
            "Force unwrap crashes on nil."
        ),
    },
    {
        "id": "swift_force_try",
        "pattern": r"\btry!\s+",
        "message": "try! crashes on error. Use do/catch or try? for safe error handling.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Replace `try! expression` with `do { try expression } catch { handleError(error) }`. "
            "Or use `try?` to convert to optional. try! crashes on any thrown error."
        ),
    },
    {
        "id": "swift_implicitly_unwrapped",
        "pattern": r"(?:var|let)\s+\w+\s*:\s*\w+!(?:\s*$|\s*=)",
        "message": "Implicitly unwrapped optional as property. Use regular optional (?) and unwrap safely.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Replace `var name: String!` with `var name: String?` and use optional binding. "
            "Implicitly unwrapped optionals crash on nil access. Only valid for IBOutlets and dependency injection."
        ),
    },
    {
        "id": "swift_nslog_production",
        "pattern": r"\bNSLog\s*\(",
        "message": "NSLog() is slow and visible in device console. Use os_log or Logger for production logging.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Replace NSLog with os_log: `import os; let logger = Logger(subsystem: \"com.app\", "
            "category: \"network\"); logger.info(\"message\")`. NSLog is slow, not private, and visible in Console.app."
        ),
    },
    {
        "id": "swift_hardcoded_url",
        "pattern": r'URL\s*\(\s*string:\s*"https?://[^"]+"\s*\)',
        "message": "Hardcoded URL string. Use a configuration file or environment variable for URLs.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Move URL to configuration: `let url = Bundle.main.infoDictionary?[\"API_URL\"] as? String "
            "?? \"default\"`. Or use a Config.plist with environment-specific values."
        ),
    },
    {
        "id": "swift_keychain_no_acl",
        "pattern": r"kSecAttrAccessible.*kSecAttrAccessibleAlways",
        "message": "Keychain item accessible when device is locked. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Add access control: `let access = SecAccessControlCreateWithFlags(nil, "
            "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, nil)`. "
            "Store sensitive data with biometric protection."
        ),
    },
    {
        "id": "swift_userdefaults_sensitive",
        "pattern": r'(?i)UserDefaults\.\w+\.set\([^)]*(?:password|token|secret|apiKey|creditCard)',
        "message": "Storing sensitive data in UserDefaults (unencrypted). Use Keychain for secrets.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
        "skip_comments": True,
        "suggestion": (
            "Move sensitive data to Keychain: `SecItemAdd([kSecClass: kSecClassGenericPassword, "
            "kSecAttrAccount: key, kSecValueData: data] as CFDictionary, nil)`. "
            "UserDefaults is unencrypted and backed up to iCloud."
        ),
    },

    # ═══════════════════════════════════════════════════════════════
    #  FRAMEWORK-SPECIFIC RULES (cross-language)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "django_raw_sql",
        "pattern": r"connection\.cursor\(\).*\.execute\s*\(",
        "message": "Raw SQL via connection.cursor(). Use Django ORM or parameterized queries to prevent injection.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "fastapi_no_validation",
        "pattern": r"@(?:app|router)\.(?:get|post|put|patch|delete)\s*\([^)]*\)\s*\n\s*(?:async\s+)?def\s+\w+\([^)]*\)(?!\s*->)",
        "message": "FastAPI endpoint without return type annotation (response_model). Add explicit response model for validation.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "express_no_cors_config",
        "pattern": r"\bcors\s*\(\s*\)",
        "message": "Express cors() with no options allows all origins. Pass explicit origin/methods configuration.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "spring_bean_injection_field",
        "pattern": r"@Autowired\s+(?:private|protected|public)\s+\w+",
        "message": "Field injection with @Autowired. Use constructor injection for testability and immutability.",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "react_useeffect_no_deps",
        "pattern": r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]+\}\s*\)\s*;",
        "message": "useEffect without dependency array runs on every render. Add [] or specific dependencies.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "react_setstate_in_render",
        "pattern": r"(?:^|\s)const\s+\w+\s*=\s*\(\)\s*=>\s*\{[^}]*set[A-Z]\w+\s*\([^}]*return\s+<",
        "message": "setState call in render function body causes infinite re-renders. Move to useEffect or event handler.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "nextjs_getserverside_secret",
        "pattern": r"getServerSideProps.*return\s*\{[^}]*(?:apiKey|secret|token|password)\s*:",
        "message": "Sensitive value in getServerSideProps return exposes it to the client. Keep secrets server-side only.",
        "severity": Severity.BLOCK,
        "file_types": [".tsx", ".ts", ".jsx", ".js"],
        "skip_comments": True,
    },
    {
        "id": "flask_send_file_user_input",
        "pattern": r"send_file\s*\(\s*(?:request\.\w+|f[\"']|.*\+)",
        "message": "send_file() with user-controlled path enables path traversal. Use safe_join() and validate the path.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  PYTHON ADVANCED (Django, Flask, FastAPI, asyncio, typing)
    # ═══════════════════════════════════════════════════════════════

    # --- Django ORM ---
    {
        "id": "django_n_plus_one",
        "pattern": r"\.objects\.all\(\)\s*$",
        "message": "QuerySet.all() without select_related/prefetch_related risks N+1 queries. Use select_related() or prefetch_related().",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_raw_interpolated",
        "pattern": r"\.raw\s*\(\s*(?:f[\"']|[^)]*\.format\s*\(|[^)]*%\s*\()",
        "message": "Django raw SQL with string interpolation is SQL injection risk. Use parameterized raw().",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_csrf_exempt",
        "pattern": r"@csrf_exempt",
        "message": "CSRF protection disabled. Only exempt for API endpoints with token auth.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_open_redirect",
        "pattern": r"redirect\s*\(\s*request\.(GET|POST|META)\b",
        "message": "Redirect using user input enables open redirect attacks. Validate the URL against an allowlist.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_unsafe_serializer",
        "pattern": r"class\s+\w+Serializer.*\n\s*class\s+Meta:\s*\n\s*fields\s*=\s*[\"']__all__[\"']",
        "message": "Serializer with fields='__all__' may expose sensitive fields. List fields explicitly.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_model_str_missing",
        "pattern": r"class\s+\w+\(models\.Model\):",
        "message": "Django model without __str__ method makes admin/debugging difficult. Add __str__.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_extra_raw",
        "pattern": r"\.extra\s*\(",
        "message": "QuerySet.extra() is deprecated and prone to SQL injection. Use annotate() or Subquery().",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "django_filter_user_input",
        "pattern": r"\.filter\s*\(\s*\*\*request\.",
        "message": "Passing user input directly to filter() allows ORM injection. Validate and whitelist filter fields.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # --- Flask ---
    {
        "id": "flask_session_no_secret",
        "pattern": r"app\.secret_key\s*=\s*[\"'][^\"']{0,15}[\"']",
        "message": "Flask secret key is too short or weak. Use a cryptographically random key of 32+ bytes.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "flask_jinja2_no_autoescape",
        "pattern": r"Jinja2\s*\(\s*(?!.*autoescape)",
        "message": "Jinja2 environment without autoescape enables XSS. Set autoescape=True.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "flask_unsafe_markup",
        "pattern": r"Markup\s*\(\s*(?:f[\"']|[^)]*\.format\s*\(|[^)]*%\s)",
        "message": "Markup() with string interpolation bypasses Jinja2 escaping. Use Markup.escape() for user input.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # --- FastAPI ---
    {
        "id": "fastapi_missing_depends",
        "pattern": r"@(?:app|router)\.(?:get|post|put|delete|patch)\s*\([^)]*\)\s*\n(?:async\s+)?def\s+\w+\s*\(\s*\)",
        "message": "FastAPI endpoint with no parameters. Missing Depends() for auth/validation?",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "fastapi_no_response_model",
        "pattern": r"@(?:app|router)\.\w+\s*\(\s*[\"'][^\"']+[\"']\s*\)",
        "message": "FastAPI endpoint without response_model. Define a Pydantic response model for type safety.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "fastapi_background_unchecked",
        "pattern": r"background_tasks\.add_task\s*\(\s*\w+\s*(?:,\s*\w+)*\s*\)",
        "message": "BackgroundTask without error handling. Failures are silently swallowed. Add try/except in the task function.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "fastapi_cors_allow_all",
        "pattern": r"allow_origins\s*=\s*\[\s*[\"']\*[\"']\s*\]",
        "message": "CORS allow_origins=['*'] permits any origin. Restrict to specific trusted domains.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # --- asyncio ---
    {
        "id": "asyncio_unawaited_coroutine",
        "pattern": r"(?<!await\s)(?:asyncio|aio\w+|async_)\.\w+\s*\(\s*\)\s*$",
        "message": "Possible unawaited coroutine. Use 'await' for async functions or assign to a variable.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "asyncio_gather_no_return_exceptions",
        "pattern": r"asyncio\.gather\s*\([^)]*\)\s*$",
        "message": "asyncio.gather() without return_exceptions=True will cancel sibling tasks on failure.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "asyncio_missing_shield",
        "pattern": r"await\s+\w+\s*\([^)]*\)\s*#.*cancel",
        "message": "Cancellation-sensitive operation should use asyncio.shield() to prevent premature cancellation.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "asyncio_run_in_async",
        "pattern": r"asyncio\.run\s*\(",
        "message": "asyncio.run() creates a new event loop. In async context use 'await' directly.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "asyncio_sleep_zero",
        "pattern": r"await\s+asyncio\.sleep\s*\(\s*0\s*\)",
        "message": "asyncio.sleep(0) for yielding is fragile. Consider asyncio.sleep(0.001) or restructure the coroutine.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "asyncio_create_task_no_ref",
        "pattern": r"asyncio\.create_task\s*\([^)]+\)\s*$",
        "message": "Fire-and-forget task with no reference. Task may be garbage collected. Store the reference.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # --- Python typing ---
    {
        "id": "python_typevar_misuse",
        "pattern": r"TypeVar\s*\(\s*[\"']\w+[\"']\s*\)\s*$",
        "message": "Unbounded TypeVar without constraints. Add bound= or constraints for type safety.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_overload_no_impl",
        "pattern": r"@overload\s*\n(?:.*\n)*?(?!@overload|def\s)",
        "message": "Overloaded function without implementation. Add the non-decorated implementation after all @overload variants.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_assert_in_prod",
        "pattern": r"^\s*assert\s+(?!.*(?:test_|_test\.py|conftest))",
        "message": "Assert statements are stripped with -O flag. Use explicit validation in production code.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_subprocess_shell",
        "pattern": r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True",
        "message": "subprocess with shell=True is command injection risk. Use shell=False with argument list.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_yaml_load_unsafe",
        "pattern": r"yaml\.load\s*\([^)]*\)\s*$",
        "message": "yaml.load() without Loader parameter uses unsafe loader. Use yaml.safe_load().",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_tempfile_insecure",
        "pattern": r"tempfile\.mk(?:temp|stemp)\s*\(",
        "message": "tempfile.mktemp() has a race condition. Use tempfile.NamedTemporaryFile() or tempfile.mkstemp().",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_md5_sha1",
        "pattern": r"hashlib\.(?:md5|sha1)\s*\(",
        "message": "MD5/SHA1 are cryptographically broken. Use SHA-256 or SHA-3 for security purposes.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "python_random_security",
        "pattern": r"\brandom\.(?:random|randint|choice|randrange)\s*\(",
        "message": "random module is not cryptographically secure. Use secrets module for security-sensitive operations.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # ═══════════════════════════════════════════════════════════════
    #  JAVASCRIPT / TYPESCRIPT ADVANCED
    # ═══════════════════════════════════════════════════════════════

    # --- React ---
    {
        "id": "react_useref_in_deps",
        "pattern": r"(?:useEffect|useMemo|useCallback)\s*\([^)]*,\s*\[[^\]]*\bref(?:\.current)?\b",
        "message": "useRef value in dependency array does not trigger re-renders. Track the value in state instead.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "react_conditional_hook",
        "pattern": r"if\s*\([^)]+\)\s*\{\s*(?:use[A-Z]\w+)\s*\(",
        "message": "Hook called conditionally violates Rules of Hooks. Move hook call to top level.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "react_dangerously_set_html",
        "pattern": r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
        "message": "dangerouslySetInnerHTML exposes XSS risk. Sanitize with DOMPurify or use safe rendering.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "react_index_key_reorder",
        "pattern": r"\.map\s*\(\s*\([^)]*,\s*(?:index|idx|i)\s*\)[^)]*key\s*=\s*\{\s*(?:index|idx|i)\s*\}",
        "message": "Array index as React key causes rendering bugs on reorder. Use a stable unique identifier.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "react_no_memo_expensive",
        "pattern": r"(?:const|let)\s+\w+\s*=\s*\w+\.(?:filter|map|reduce|sort)\s*\(",
        "message": "Expensive computation in render without useMemo. Wrap in useMemo() to avoid recalculation.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
        "skip_comments": True,
    },
    # --- Next.js ---
    {
        "id": "nextjs_middleware_bypass",
        "pattern": r"export\s+(?:const|function)\s+middleware.*\{\s*(?:return\s+NextResponse\.next\(\)|next\(\))\s*\}",
        "message": "Middleware that always passes through provides no protection. Add route-specific checks.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
        "skip_comments": True,
    },
    {
        "id": "nextjs_ssrf_rewrite",
        "pattern": r"rewrites\s*\(\s*\)\s*\{[^}]*destination\s*:\s*(?:process\.env|`\$\{)",
        "message": "Dynamic rewrite destination may enable SSRF. Validate and restrict destination URLs.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".mjs"],
        "skip_comments": True,
    },
    {
        "id": "nextjs_api_no_auth",
        "pattern": r"export\s+(?:default\s+)?(?:async\s+)?function\s+handler\s*\(\s*req\s*,\s*res\s*\)\s*\{(?!.*(?:auth|session|token|verify))",
        "message": "Next.js API route without authentication check. Add auth middleware or session validation.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
        "skip_comments": True,
    },
    {
        "id": "nextjs_use_client_fetch",
        "pattern": r"[\"']use client[\"'].*fetch\s*\(\s*[\"']/api/",
        "message": "Client component fetching own API route adds unnecessary round trip. Use server component or server action.",
        "severity": Severity.INFO,
        "file_types": [".tsx", ".jsx"],
        "skip_comments": True,
    },
    # --- Express ---
    {
        "id": "express_no_helmet",
        "pattern": r"const\s+app\s*=\s*express\s*\(\)",
        "message": "Express app without helmet middleware. Add app.use(helmet()) for security headers.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "express_session_no_secure",
        "pattern": r"session\s*\(\s*\{[^}]*(?!secure\s*:\s*true)",
        "message": "Express session without secure flag. Set cookie.secure=true in production.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "express_cors_wildcard",
        "pattern": r"cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|[\"']\*[\"'])",
        "message": "CORS with wildcard/true origin allows any domain. Restrict to specific origins.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "express_body_no_limit",
        "pattern": r"(?:express\.json|bodyParser\.json)\s*\(\s*\)",
        "message": "Body parser without size limit. Add { limit: '100kb' } to prevent DoS via large payloads.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "express_unvalidated_params",
        "pattern": r"req\.(?:params|query|body)\.\w+",
        "message": "Direct use of request parameters without validation. Use a validation library (Zod, Joi).",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    # --- Node.js ---
    {
        "id": "node_unhandled_rejection",
        "pattern": r"\.catch\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)",
        "message": "Empty catch handler silently swallows promise rejection. Handle or log the error.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "node_event_emitter_leak",
        "pattern": r"\.on\s*\(\s*[\"']\w+[\"']\s*,\s*\w+\s*\)(?!.*\.removeListener)",
        "message": "Event listener registered without cleanup. Remove listeners to prevent memory leaks.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "node_buffer_alloc_unsafe",
        "pattern": r"Buffer\.allocUnsafe\s*\(",
        "message": "Buffer.allocUnsafe() may contain old data. Use Buffer.alloc() unless performance is critical and you fill immediately.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "node_sync_fs",
        "pattern": r"fs\.(?:readFileSync|writeFileSync|appendFileSync|existsSync|mkdirSync)\s*\(",
        "message": "Synchronous filesystem operation blocks the event loop. Use async fs methods.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "node_child_process_exec",
        "pattern": r"child_process\.exec\s*\(\s*(?:`|\$\{|.*\+)",
        "message": "child_process.exec with string interpolation is command injection. Use execFile() with argument array.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    # --- Browser ---
    {
        "id": "browser_postmessage_no_origin",
        "pattern": r"window\.addEventListener\s*\(\s*[\"']message[\"']\s*,\s*(?:function|\([^)]*\)\s*=>)\s*\{(?!.*origin)",
        "message": "postMessage listener without origin check. Validate event.origin to prevent cross-origin attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "browser_localstorage_token",
        "pattern": r"localStorage\.setItem\s*\(\s*[\"'](?:token|jwt|access_token|auth_token|session)[\"']",
        "message": "Storing auth tokens in localStorage is XSS-vulnerable. Use httpOnly cookies instead.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "browser_eval_worker",
        "pattern": r"(?:importScripts|new\s+Function)\s*\(",
        "message": "Dynamic code execution in worker context. Use static imports or message passing.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "browser_innerhtml_assign",
        "pattern": r"\.innerHTML\s*=\s*(?!.*(?:DOMPurify|sanitize))",
        "message": "innerHTML assignment without sanitization enables XSS. Use textContent or sanitize with DOMPurify.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "js_prototype_pollution_merge",
        "pattern": r"(?:Object\.assign|_\.merge|_\.extend|_\.defaultsDeep)\s*\(\s*\{\}",
        "message": "Object merging with untrusted input may enable prototype pollution. Validate input keys.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "js_regex_dos",
        "pattern": r"new\s+RegExp\s*\(\s*(?:req\.|input|user|data|param)",
        "message": "User-controlled regex enables ReDoS attacks. Sanitize input or use a safe regex library.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "js_open_redirect_location",
        "pattern": r"(?:window\.location|location\.href)\s*=\s*(?:req\.|params|query|searchParams)",
        "message": "Redirect using user input enables open redirect. Validate against an allowlist.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    # ═══════════════════════════════════════════════════════════════
    #  GO ADVANCED
    # ═══════════════════════════════════════════════════════════════

    # --- context ---
    {
        "id": "go_context_background_handler",
        "pattern": r"context\.Background\s*\(\)",
        "message": "context.Background() in handler loses request context. Use r.Context() or pass parent context.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Replace `context.Background()` with `r.Context()` (net/http) or `c.Request().Context()` (Echo/Gin) to propagate request cancellation and deadlines.",
    },
    {
        "id": "go_context_cancel_leak",
        "pattern": r"context\.With(?:Cancel|Timeout|Deadline)\s*\([^)]+\)(?!.*defer\s+cancel)",
        "message": "Context created without deferred cancel(). This leaks resources. Add 'defer cancel()'.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Add `defer cancel()` immediately after context creation: `ctx, cancel := context.WithTimeout(parent, 30*time.Second); defer cancel()`.",
    },
    {
        "id": "go_context_timeout_short",
        "pattern": r"context\.WithTimeout\s*\([^,]+,\s*(?:time\.Millisecond\s*\*\s*[1-9][0-9]?|time\.Second\s*\*\s*[01])\s*\)",
        "message": "Context timeout under 100ms or 1s is too short for most operations. Increase timeout.",
        "severity": Severity.INFO,
        "file_types": [".go"],
        "skip_comments": True,
    },
    # --- concurrency ---
    {
        "id": "go_waitgroup_add_in_goroutine",
        "pattern": r"go\s+func\s*\([^)]*\)\s*\{[^}]*\.Add\s*\(",
        "message": "WaitGroup.Add() inside goroutine is a race condition. Call Add() before launching goroutine.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Move `wg.Add(1)` before the `go func()` call: `wg.Add(1); go func() { defer wg.Done(); ... }()`. Adding inside the goroutine races with wg.Wait().",
    },
    {
        "id": "go_unbuffered_channel_goroutine",
        "pattern": r"make\s*\(\s*chan\s+\w+\s*\)\s*$",
        "message": "Unbuffered channel can deadlock if sender/receiver are not synchronized. Consider buffered channel.",
        "severity": Severity.INFO,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_mutex_copy",
        "pattern": r"(?:=\s*\*?\w+\.mu|:=\s*\*?\w+\.Mutex)",
        "message": "Copying a mutex copies its lock state. Pass sync.Mutex by pointer, never by value.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Use a pointer receiver or embed the mutex: `type MyStruct struct { mu sync.Mutex }` and use `func (s *MyStruct) Method()`. Never assign or pass a mutex by value.",
    },
    {
        "id": "go_goroutine_infinite_loop",
        "pattern": r"go\s+func\s*\(\s*\)\s*\{[^}]*for\s+\{",
        "message": "Goroutine with infinite loop needs a shutdown mechanism. Add context or done channel.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Add a context or done channel: `for { select { case <-ctx.Done(): return; default: ... } }`. This allows graceful shutdown on SIGTERM/cancellation.",
    },
    # --- net/http ---
    {
        "id": "go_http_no_read_header_timeout",
        "pattern": r"&http\.Server\s*\{(?!.*ReadHeaderTimeout)",
        "message": "HTTP server without ReadHeaderTimeout is vulnerable to Slowloris. Set ReadHeaderTimeout.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Add `ReadHeaderTimeout: 10 * time.Second` to http.Server config. Without it, attackers can hold connections open indefinitely (Slowloris attack).",
    },
    {
        "id": "go_http_default_client",
        "pattern": r"http\.(?:Get|Post|Head|PostForm)\s*\(",
        "message": "Default http client has no timeout. Create a client with explicit Timeout.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Create a custom client: `client := &http.Client{Timeout: 30 * time.Second}; resp, err := client.Get(url)`. The default client has no timeout and can hang indefinitely.",
    },
    {
        "id": "go_response_body_leak",
        "pattern": r"http\.(?:Get|Post|Do)\s*\([^)]+\)(?!.*defer\s+\w+\.Body\.Close)",
        "message": "HTTP response body not closed. Add 'defer resp.Body.Close()' to prevent resource leak.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
    },
    # --- database/sql ---
    {
        "id": "go_sql_rows_no_close",
        "pattern": r"\.Query\s*\(",
        "special_handler": "check_go_sql_close",
        "message": "SQL Rows not closed. Add 'defer rows.Close()' to prevent connection pool exhaustion.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
        "suggestion": "Add 'defer rows.Close()' immediately after error check: rows, err := db.Query(...); if err != nil { return err }; defer rows.Close().",
    },
    {
        "id": "go_sql_tx_no_rollback",
        "pattern": r"\.Begin\s*\(\s*\)(?!.*defer)",
        "message": "Transaction started without deferred Rollback. Add 'defer tx.Rollback()' for safety.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_sql_string_concat",
        "pattern": r"(?:db|tx)\.(?:Query|Exec)\s*\(\s*(?:\"|`)[^\"`)]*\+",
        "message": "SQL query with string concatenation. Use parameterized queries with $1, $2 placeholders.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_sql_no_pool_config",
        "pattern": r"sql\.Open\s*\([^)]+\)(?!.*SetMaxOpenConns)",
        "message": "Database opened without connection pool limits. Set SetMaxOpenConns() and SetMaxIdleConns().",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    # --- crypto ---
    {
        "id": "go_crypto_hmac_equal",
        "pattern": r"(?:bytes\.Equal|==)\s*.*(?:hmac|mac|signature|hash)",
        "message": "Non-constant-time comparison for HMAC/hash. Use hmac.Equal() to prevent timing attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_crypto_weak_rand",
        "pattern": r"math/rand",
        "message": "math/rand is not cryptographically secure. Use crypto/rand for security-sensitive operations.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_error_underscore_discard",
        "pattern": r"\b\w+\s*,\s*_\s*:?=\s*\w+\.\w+\s*\(",
        "message": "Error return value ignored. Handle the error or explicitly document why it is safe to ignore.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    # ═══════════════════════════════════════════════════════════════
    #  JAVA / KOTLIN ADVANCED
    # ═══════════════════════════════════════════════════════════════

    # --- Spring ---
    {
        "id": "spring_requestmapping_no_method",
        "pattern": r"@RequestMapping\s*\(\s*(?:value\s*=\s*)?[\"']/[^)]*\)(?!.*method\s*=)",
        "message": "@RequestMapping without method accepts all HTTP methods. Use @GetMapping/@PostMapping etc.",
        "severity": Severity.WARN,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "spring_bean_scope_prototype",
        "pattern": r"@Scope\s*\(\s*[\"']prototype[\"']\s*\)",
        "message": "Prototype-scoped bean injected into singleton can cause stale state. Use ObjectProvider or lookup method.",
        "severity": Severity.WARN,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "spring_cross_origin_star",
        "pattern": r"@CrossOrigin\s*(?:\(\s*\)|\(\s*origins\s*=\s*[\"']\*[\"'])",
        "message": "@CrossOrigin with wildcard allows any origin. Specify allowed origins explicitly.",
        "severity": Severity.BLOCK,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "spring_sql_injection",
        "pattern": r"@Query\s*\(\s*[\"'].*\+\s*\w+",
        "message": "String concatenation in @Query enables SQL injection. Use :paramName with @Param.",
        "severity": Severity.BLOCK,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "spring_no_validation",
        "pattern": r"@(?:Post|Put)Mapping.*\)\s*\n\s*public\s+\w+\s+\w+\s*\(\s*@RequestBody\s+(?!@Valid)",
        "message": "@RequestBody without @Valid skips bean validation. Add @Valid annotation.",
        "severity": Severity.WARN,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    # --- JDBC ---
    {
        "id": "jdbc_connection_leak",
        "pattern": r"DriverManager\.getConnection\s*\([^)]+\)(?!.*try|.*finally)",
        "message": "JDBC connection without try-with-resources. Connection leak will exhaust pool.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "jdbc_statement_concat",
        "pattern": r"(?:Statement|createStatement)\s*\(\s*\).*\.execute\w*\s*\(\s*[\"'].*\+",
        "message": "Statement with string concatenation. Use PreparedStatement with ? placeholders.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "jdbc_batch_no_transaction",
        "pattern": r"\.addBatch\s*\((?!.*setAutoCommit\s*\(\s*false)",
        "message": "Batch operations without explicit transaction. Wrap in setAutoCommit(false)/commit().",
        "severity": Severity.WARN,
        "file_types": [".java"],
        "skip_comments": True,
    },
    # --- Kotlin ---
    {
        "id": "kotlin_double_bang",
        "pattern": r"\w+!!",
        "message": "!! operator will throw NPE on null. Use safe call (?.) with elvis (?:) or require().",
        "severity": Severity.WARN,
        "file_types": [".kt"],
        "skip_comments": True,
        "suggestion": (
            "Replace `value!!` with `value ?: throw IllegalStateException(\"Expected non-null\")` for "
            "explicit error, or `value?.let { ... }` for safe handling. !! throws NPE without context."
        ),
    },
    {
        "id": "kotlin_runblocking_coroutine",
        "pattern": r"runBlocking\s*\{",
        "message": "runBlocking in coroutine context blocks the thread. Use coroutineScope or withContext.",
        "severity": Severity.BLOCK,
        "file_types": [".kt"],
        "skip_comments": True,
        "suggestion": (
            "Replace `runBlocking { ... }` with a proper coroutine scope: `lifecycleScope.launch { }` "
            "(Android), `CoroutineScope(Dispatchers.IO).launch { }`, or make the function `suspend`. "
            "runBlocking blocks the calling thread."
        ),
    },
    {
        "id": "kotlin_mutablelist_exposed",
        "pattern": r"fun\s+\w+\s*\([^)]*\)\s*:\s*List<[^>]+>\s*=\s*mutableListOf",
        "message": "MutableList returned as List can be cast back. Use .toList() to return a true immutable copy.",
        "severity": Severity.WARN,
        "file_types": [".kt"],
        "skip_comments": True,
        "suggestion": (
            "Expose as read-only List: `private val _items = mutableListOf<T>(); val items: List<T> "
            "get() = _items`. This prevents external mutation while allowing internal modification."
        ),
    },
    {
        "id": "kotlin_globalscope",
        "pattern": r"GlobalScope\.launch\s*\{",
        "message": "GlobalScope leaks coroutines. Use structured concurrency with viewModelScope or lifecycleScope.",
        "severity": Severity.WARN,
        "file_types": [".kt"],
        "skip_comments": True,
        "suggestion": (
            "Replace `GlobalScope.launch { }` with a structured scope: `viewModelScope.launch { }` "
            "(Android), `lifecycleScope.launch { }`, or custom "
            "`CoroutineScope(SupervisorJob() + Dispatchers.Default)`. GlobalScope ignores lifecycle."
        ),
    },
    # --- Android ---
    {
        "id": "android_exported_no_permission",
        "pattern": r"android:exported\s*=\s*[\"']true[\"'](?!.*android:permission)",
        "message": "Exported component without permission. Any app can interact with it. Add android:permission.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "android_cleartext_traffic",
        "pattern": r"android:usesCleartextTraffic\s*=\s*[\"']true[\"']",
        "message": "Cleartext traffic enabled. Use HTTPS and set usesCleartextTraffic=false.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "android_webview_js_enabled",
        "pattern": r"setJavaScriptEnabled\s*\(\s*true\s*\)",
        "message": "WebView JavaScript enabled without content restrictions. Add Content-Security-Policy and validate URLs.",
        "severity": Severity.WARN,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "android_shared_prefs_sensitive",
        "pattern": r"getSharedPreferences\s*\([^)]+\).*(?:put(?:String|Int)\s*\(\s*[\"'](?:token|password|key|secret))",
        "message": "Storing sensitive data in SharedPreferences. Use EncryptedSharedPreferences.",
        "severity": Severity.BLOCK,
        "file_types": [".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "java_deserialization",
        "pattern": r"ObjectInputStream\s*\(\s*(?:new\s+)?(?:Socket|URL|File|InputStream)",
        "message": "Java deserialization from untrusted source enables RCE. Use JSON/protobuf instead.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
    },
    {
        "id": "java_thread_stop",
        "pattern": r"\.stop\s*\(\s*\)|\.suspend\s*\(\s*\)|\.resume\s*\(\s*\)",
        "message": "Thread.stop/suspend/resume are deprecated and unsafe. Use interrupt() and cooperative shutdown.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  INFRASTRUCTURE DEEP (Terraform, Kubernetes, Docker, GH Actions)
    # ═══════════════════════════════════════════════════════════════

    # --- Terraform ---
    {
        "id": "terraform_state_no_encrypt",
        "pattern": r"backend\s+[\"']s3[\"']\s*\{(?!.*encrypt\s*=\s*true)",
        "message": "Terraform S3 backend without encryption. Set encrypt = true for state file security.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "terraform_provider_unpinned",
        "pattern": r"required_providers\s*\{[^}]*version\s*=\s*[\"']>=",
        "message": "Provider version with >= allows unexpected upgrades. Pin to ~> for minor version constraint.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "terraform_s3_public",
        "pattern": r"acl\s*=\s*[\"'](?:public-read|public-read-write)[\"']",
        "message": "S3 bucket with public ACL. Use bucket policies with explicit access grants.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "terraform_security_group_open",
        "pattern": r"cidr_blocks\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']\s*\]",
        "message": "Security group open to 0.0.0.0/0. Restrict to specific CIDR ranges.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "terraform_hardcoded_creds",
        "pattern": r"(?:access_key|secret_key)\s*=\s*[\"'][^\"']+[\"']",
        "message": "Hardcoded AWS credentials in Terraform. Use environment variables or IAM roles.",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".tfvars"],
    },
    {
        "id": "terraform_no_state_lock",
        "pattern": r"backend\s+[\"']s3[\"']\s*\{(?!.*dynamodb_table)",
        "message": "S3 backend without DynamoDB state locking. Add dynamodb_table for concurrent safety.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    # --- Kubernetes ---
    {
        "id": "k8s_hostpath_mount",
        "pattern": r"hostPath\s*:\s*\n\s*path\s*:",
        "message": "hostPath volume mount exposes host filesystem. Use emptyDir, PVC, or ConfigMap instead.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_nodeport_production",
        "pattern": r"type\s*:\s*NodePort",
        "message": "NodePort exposes services directly. Use LoadBalancer or Ingress in production.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_default_namespace",
        "pattern": r"namespace\s*:\s*[\"']?default[\"']?",
        "message": "Using default namespace. Create dedicated namespaces for workload isolation.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_privileged_container",
        "pattern": r"privileged\s*:\s*true",
        "message": "Privileged container has full host access. Remove privileged flag or use specific capabilities.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_no_cpu_mem_limits",
        "pattern": r"containers\s*:\s*\n\s*-\s*name\s*:(?!.*resources\s*:)",
        "message": "Container without resource limits. Set requests and limits for CPU and memory.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_run_as_uid_zero",
        "pattern": r"runAsUser\s*:\s*0",
        "message": "Container running as root (UID 0). Set runAsNonRoot: true or use a non-root UID.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_no_readiness_probe",
        "pattern": r"containers\s*:\s*\n\s*-\s*name\s*:(?!.*readinessProbe)",
        "message": "Container without readiness probe. Add readinessProbe for traffic routing.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    # --- Docker ---
    {
        "id": "docker_copy_broad",
        "pattern": r"COPY\s+\.\s+\.",
        "message": "COPY . . copies everything including secrets, git history, etc. Use specific paths or .dockerignore.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_no_multi_stage",
        "pattern": r"^FROM\s+\S+(?:\n(?!FROM))*$",
        "message": "Single-stage Dockerfile includes build tools in production image. Use multi-stage builds.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_add_instead_copy",
        "pattern": r"^ADD\s+(?!https?://)\S+",
        "message": "ADD has implicit tar extraction. Use COPY for simple file copies.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_apt_no_clean",
        "pattern": r"apt-get\s+install(?!.*&&\s*(?:apt-get\s+clean|rm\s+-rf\s+/var/lib/apt))",
        "message": "apt-get install without cleanup. Add 'apt-get clean && rm -rf /var/lib/apt/lists/*'.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_expose_wide",
        "pattern": r"EXPOSE\s+\d+(?:\s+\d+){3,}",
        "message": "Exposing many ports. Each exposed port increases attack surface. Minimize to required ports.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    # --- GitHub Actions ---
    {
        "id": "gha_untrusted_input_run",
        "pattern": r"run\s*:.*\$\{\{\s*(?:github\.event\.(?:issue|pull_request|comment)\.(?:title|body)|github\.head_ref)",
        "message": "Untrusted input in run step enables command injection. Use an intermediate environment variable.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "gha_pull_request_target",
        "pattern": r"on\s*:\s*(?:\[.*)?pull_request_target",
        "message": "pull_request_target runs with write access on forked PRs. Use pull_request with explicit checkout.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "gha_secret_in_env",
        "pattern": r"env\s*:\s*\n(?:\s+\w+\s*:\s*.*\n)*\s+\w+\s*:\s*\$\{\{\s*secrets\.",
        "message": "Secret in job-level env is available to all steps. Scope secrets to individual steps.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "gha_action_unpinned",
        "pattern": r"uses\s*:\s*\w+/\w+@(?:master|main|v\d+)\s*$",
        "message": "GitHub Action pinned to mutable ref. Pin to a specific commit SHA for supply chain safety.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "gha_permissions_wide",
        "pattern": r"permissions\s*:\s*write-all",
        "message": "Workflow with write-all permissions. Apply least privilege with specific permission scopes.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  SECURITY PATTERNS (OWASP, Crypto, Auth, Headers)
    # ═══════════════════════════════════════════════════════════════

    # --- OWASP A01: Broken Access Control ---
    {
        "id": "sec_path_traversal",
        "pattern": r"(?:open|read|write|send_file|serve)\s*\(\s*(?:.*\+\s*)?(?:request\.|req\.|params|input|user)",
        "message": "File operation with user-controlled path enables path traversal. Validate and sandbox the path.",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".js", ".ts", ".go", ".java", ".rb"],
        "skip_comments": True,
    },
    {
        "id": "sec_idor_direct_id",
        "pattern": r"(?:findById|get_object_or_404|find_by_id)\s*\(\s*(?:request\.|req\.|params)",
        "message": "Direct object reference from user input. Verify the user has permission to access this resource.",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts", ".java", ".rb"],
        "skip_comments": True,
    },
    {
        "id": "sec_admin_no_auth",
        "pattern": r"(?:@app\.route|@router\.)\s*\(\s*[\"']/admin",
        "message": "Admin route without visible auth decorator. Ensure admin routes require authentication.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # --- OWASP A03: Injection ---
    {
        "id": "sec_ldap_injection",
        "pattern": r"(?:ldap|LDAP).*(?:search|bind)\s*\([^)]*(?:f[\"']|\+|\.format)",
        "message": "LDAP query with string interpolation. Use parameterized LDAP queries.",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".java", ".js"],
        "skip_comments": True,
    },
    {
        "id": "sec_xpath_injection",
        "pattern": r"\.xpath\s*\(\s*(?:f[\"']|.*\+|.*\.format)",
        "message": "XPath query with string interpolation enables XPath injection. Use parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".java", ".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "sec_nosql_injection",
        "pattern": r"\.find\s*\(\s*\{[^}]*:\s*(?:req\.|request\.|params\.|input)",
        "message": "NoSQL query with user input may enable injection. Validate and sanitize query operators.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
        "skip_comments": True,
    },
    {
        "id": "sec_template_injection",
        "pattern": r"(?:render_template_string|Template)\s*\(\s*(?:request\.|req\.|user_input|f[\"'])",
        "message": "Template rendered from user input enables SSTI. Use parameterized templates only.",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".js"],
        "skip_comments": True,
    },
    {
        "id": "sec_xml_external_entity",
        "pattern": r"(?:XMLParser|etree\.parse|parseString)\s*\([^)]*\)(?!.*resolve_entities\s*=\s*False)",
        "message": "XML parsing without disabling external entities (XXE). Set resolve_entities=False.",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".java"],
        "skip_comments": True,
    },
    # --- OWASP A05: Security Misconfiguration ---
    {
        "id": "sec_debug_flag_env",
        "pattern": r"(?:DEBUG|TESTING|DEV_MODE)\s*=\s*(?:True|true|1|[\"']yes[\"'])",
        "message": "Debug/testing flag hardcoded to true. Use environment variables and default to false.",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts", ".env"],
        "skip_comments": True,
    },
    {
        "id": "sec_default_admin_password",
        "pattern": r"(?i)(?:admin|root|default).*(?:password|pass|pwd)\s*[:=]\s*[\"'][^\"']+[\"']",
        "message": "Default admin password detected. Force password change on first login.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_verbose_error_response",
        "pattern": r"(?:traceback\.format_exc|str\(e\)|err\.stack|error\.message)\s*.*(?:return|res\.send|Response)",
        "message": "Stack trace or error details sent to client. Return generic errors, log details server-side.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    # --- Crypto ---
    {
        "id": "sec_timing_compare",
        "pattern": r"(?:==|!=)\s*(?:\w*(?:hmac|hash|digest|signature|token|mac)\w*)",
        "message": "Non-constant-time comparison for cryptographic value. Use hmac.compare_digest() or equivalent.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "sec_deterministic_nonce",
        "pattern": r"(?:nonce|iv)\s*=\s*(?:b[\"'][^\"']+[\"']|[\"'][^\"']+[\"']|\d+)",
        "message": "Static/deterministic nonce or IV. Use os.urandom() or secrets.token_bytes() for each operation.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_weak_cipher",
        "pattern": r"(?i)\b(?:DES|RC4|Blowfish|ARC4|RC2)(?:\s*\(|\.new|\.encrypt|\.decrypt|_cbc|_ecb|_cfb|_ofb)",
        "message": "Weak cipher algorithm. Use AES-256-GCM or ChaCha20-Poly1305.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_ecb_mode",
        "pattern": r"(?:ECB|MODE_ECB)",
        "message": "ECB mode reveals patterns in ciphertext. Use GCM, CBC with HMAC, or authenticated encryption.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_small_rsa_key",
        "pattern": r"generate.*(?:key_size|bits)\s*=\s*(?:512|1024)\b",
        "message": "RSA key size too small. Use at least 2048 bits, preferably 4096.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    # --- Auth ---
    {
        "id": "sec_jwt_localstorage",
        "pattern": r"localStorage\.setItem\s*\(\s*[\"']jwt[\"']",
        "message": "JWT in localStorage is vulnerable to XSS. Use httpOnly secure cookies.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "sec_oauth_no_pkce",
        "pattern": r"(?:grant_type\s*[=:]\s*[\"']?authorization_code|response_type\s*[=:]\s*[\"']?code\b)(?!.*code_challenge)",
        "message": "OAuth authorization code flow without PKCE. Add code_challenge for public clients.",
        "severity": Severity.INFO,
        "skip_comments": True,
        "file_types": [".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb"],
    },
    {
        "id": "sec_session_no_expiry",
        "pattern": r"session\s*\(\s*\{(?!.*(?:maxAge|expires|ttl))",
        "message": "Session configuration without expiry. Set maxAge to limit session lifetime.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "sec_jwt_none_algorithm",
        "pattern": r"(?:algorithm|alg)\s*[:=]\s*[\"'](?:none|None|NONE)[\"']",
        "message": "JWT with 'none' algorithm accepts unsigned tokens. Always require a signing algorithm.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_password_plaintext_log",
        "pattern": r"(?:log|logger|logging)\.\w+\s*\([^)]*(?:password|secret|api_key)\s*=(?!.*(?:mask|redact|\*+|error))",
        "message": "Sensitive value being logged. Mask or redact credentials before logging.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    # --- Headers ---
    {
        "id": "sec_missing_hsts",
        "pattern": r"Strict-Transport-Security.*max-age\s*=\s*(\d+)",
        "message": "HSTS max-age should be at least 31536000 (1 year). Short values provide weak protection.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "sec_no_xframe_options",
        "pattern": r"X-Frame-Options\s*:\s*(?:ALLOW|allow)",
        "message": "X-Frame-Options allowing framing. Use DENY or SAMEORIGIN to prevent clickjacking.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_no_csp",
        "pattern": r"Content-Security-Policy\s*:\s*(?:\*|unsafe-inline|unsafe-eval)",
        "message": "CSP with unsafe-inline or unsafe-eval weakens XSS protection. Use nonces or hashes.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "sec_referrer_policy_unsafe",
        "pattern": r"Referrer-Policy\s*:\s*(?:unsafe-url|no-referrer-when-downgrade)",
        "message": "Referrer-Policy leaks full URL. Use strict-origin-when-cross-origin or no-referrer.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "sec_cookie_no_httponly",
        "pattern": r"(?:Set-Cookie|setCookie|set_cookie)\s*[:=]\s*[^;]*(?!.*httponly|.*HttpOnly|.*httpOnly)",
        "message": "Cookie without HttpOnly flag is accessible to JavaScript. Add HttpOnly for auth cookies.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "sec_cookie_no_samesite",
        "pattern": r"(?:Set-Cookie|setCookie|set_cookie)\s*[:=]\s*[^;]*(?!.*[Ss]ame[Ss]ite)",
        "message": "Cookie without SameSite attribute. Add SameSite=Lax or Strict to prevent CSRF.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CODE QUALITY DEEP
    # ═══════════════════════════════════════════════════════════════

    # --- Dead code ---
    {
        "id": "quality_unreachable_after_return",
        "pattern": r"(?:return|raise|throw|exit)\s+[^;]*;\s*\n\s+\w",
        "message": "Unreachable code after return/throw statement. Remove dead code.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "quality_empty_except_handler",
        "pattern": r"except\s+\w+(?:\s+as\s+\w+)?:\s*\n\s+pass\s*$",
        "message": "Exception caught and ignored with pass. At minimum, log the exception.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_empty_catch_block",
        "pattern": r"catch\s*\([^)]*\)\s*\{\s*\}",
        "message": "Empty catch block silently swallows errors. Handle or log the exception.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".java", ".kt"],
        "skip_comments": True,
    },
    {
        "id": "quality_empty_if_body",
        "pattern": r"if\s*\([^)]+\)\s*\{\s*\}",
        "message": "Empty if block. Either add logic or remove the dead conditional.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "quality_impossible_condition",
        "pattern": r"if\s*\(\s*(?:false|False|0\s*===?\s*1|true\s*===?\s*false)\s*\)",
        "message": "Condition is always false. Remove unreachable code block.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "quality_always_true_condition",
        "pattern": r"if\s*\(\s*(?:true|True|1\s*===?\s*1)\s*\)",
        "message": "Condition is always true. Remove unnecessary conditional.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    # --- Complexity ---
    {
        "id": "quality_nested_callbacks",
        "pattern": r"(?:function|\=\>)\s*\{[^}]*(?:function|\=\>)\s*\{[^}]*(?:function|\=\>)\s*\{",
        "message": "Callback nesting >3 levels deep. Refactor to async/await or extract named functions.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "quality_long_param_list",
        "pattern": r"def\s+\w+\s*\(\s*(?:\w+\s*(?::\s*\w+)?\s*,\s*){6,}",
        "message": "Function with 7+ parameters. Group related parameters into a dataclass or config object.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_long_param_list_js",
        "pattern": r"(?:function\s+\w+|=>)\s*\(\s*(?:\w+\s*(?::\s*\w+)?\s*,\s*){6,}",
        "message": "Function with 7+ parameters. Use an options object pattern.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "quality_deeply_nested_if",
        "pattern": r"^\s{24,}(?:if|elif)\b(?!.*(?:is None|is not None|== None|!= None))",
        "message": "Deeply nested conditional (6+ levels). Extract to helper functions or use early return.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "quality_switch_fallthrough",
        "pattern": r"case\s+[^:]+:\s*\n\s*case\s+",
        "message": "Switch case fallthrough without break. Add break or document intentional fallthrough.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".java", ".go"],
        "skip_comments": True,
    },
    {
        "id": "quality_boolean_param",
        "pattern": r"def\s+\w+\s*\([^)]*\w+\s*:\s*bool\s*=\s*(?:True|False)[^)]*\w+\s*:\s*bool",
        "message": "Function with multiple boolean parameters. Use an enum or config object for clarity.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    # --- Error handling ---
    {
        "id": "quality_catch_log_rethrow",
        "pattern": r"catch\s*\([^)]+\)\s*\{[^}]*(?:console\.(?:error|log)|logger\.\w+)[^}]*throw\b",
        "message": "Catching, logging, and rethrowing adds noise. Either handle the error or let it propagate.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "quality_generic_error_message",
        "pattern": r"(?:raise|throw\s+new)\s+\w*(?:Error|Exception)\s*\(\s*[\"'](?:Something went wrong|An error occurred|Error|Unknown error)[\"']",
        "message": "Generic error message provides no diagnostic value. Include specific context about what failed.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "quality_missing_finally",
        "pattern": r"(?:open|connect|acquire|lock)\s*\([^)]*\)[^}]*try\s*(?:\{|\:)(?!.*finally)",
        "message": "Resource acquired before try block without finally. Use context manager or finally for cleanup.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "quality_error_string_check",
        "pattern": r"(?:str\(e\)|err\.message|error\.message)\s*(?:\.contains|\.includes|in\s+[\"']|==\s*[\"'])",
        "message": "Checking error by string content is fragile. Use error types/codes for reliable error handling.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    # --- Performance ---
    {
        "id": "quality_regex_in_loop",
        "pattern": r"(?:for|while)\s+.*:\s*\n(?:\s+.*\n)*?\s+re\.(?:compile|match|search|findall)\s*\(",
        "message": "Regex compilation inside loop. Compile the pattern once outside the loop.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_string_concat_loop",
        "pattern": r"(?:for|while)\s+.*:\s*\n(?:\s+.*\n)*?\s+\w+\s*\+=\s*(?:[\"']|str\(|f[\"'])",
        "message": "String concatenation in loop has O(n^2) complexity. Use list append + join() or io.StringIO.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_unnecessary_json_parse",
        "pattern": r"JSON\.parse\s*\(\s*JSON\.stringify\s*\(",
        "message": "JSON.parse(JSON.stringify()) for deep clone is slow. Use structuredClone() or a library.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "quality_select_n_plus_one",
        "pattern": r"for\s+\w+\s+in\s+\w+\s*:\s*\n(?:\s+.*\n)*?\s+\w+\.objects\.(?:get|filter)\s*\(",
        "message": "Database query inside loop causes N+1 problem. Use select_related/prefetch_related.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_list_comprehension_side_effect",
        "pattern": r"\[\s*\w+\.\w+\s*\([^)]*\)\s+for\s+\w+\s+in\s+",
        "message": "List comprehension used for side effects. Use a for loop instead.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_global_var_mutation",
        "pattern": r"^\s*global\s+\w+\s*\n.*=",
        "message": "Global variable mutation. Use function parameters and return values for state management.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_unused_variable",
        "pattern": r"^\s*_\w+\s*=\s*[^=]",
        "message": "Variable with underscore prefix assigned but likely unused. Remove dead assignments.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "quality_double_negation",
        "pattern": r"(?:not\s+not\s+|!\s*!\s*|!!\s*)",
        "message": "Double negation reduces readability. Use bool() or Boolean() for explicit conversion.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "quality_magic_string",
        "pattern": r"(?:if|elif|case|switch)\s*.*==\s*[\"'][a-z_]{4,}[\"']",
        "message": "Magic string in conditional. Extract to a named constant or enum for maintainability.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "quality_bare_return_none",
        "pattern": r"return\s+None\s*$",
        "message": "Explicit 'return None' is often unnecessary. Use bare 'return' or omit for implicit None.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_type_check_isinstance",
        "pattern": r"type\s*\(\s*\w+\s*\)\s*(?:==|is)\s*",
        "message": "type() comparison misses subclasses. Use isinstance() for type checking.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_star_star_kwargs_forward",
        "pattern": r"def\s+\w+\s*\(\s*\*\*kwargs\s*\).*\n\s+\w+\.\w+\s*\(\s*\*\*kwargs\s*\)",
        "message": "Blindly forwarding **kwargs hides the function interface. Declare explicit parameters.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_exception_as_control_flow",
        "pattern": r"try\s*:\s*\n\s+\w+\s*=\s*\w+\[[\"']\w+[\"']\]\s*\n\s*except\s+(?:Key|Index)Error",
        "message": "Exception for control flow is slow. Use .get() for dicts or check bounds for lists.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_hardcoded_ip",
        "pattern": r"[\"']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[\"']",
        "message": "Hardcoded IP address. Use DNS names or configuration for environment portability.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "quality_import_inside_function",
        "pattern": r"def\s+\w+\s*\([^)]*\)\s*(?:->.*)?:\s*\n\s+(?:import\s+|from\s+\S+\s+import\s+)",
        "message": "Import inside function hides dependencies. Move imports to module level.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_sys_path_modify",
        "pattern": r"sys\.path\.(?:insert|append)\s*\(",
        "message": "sys.path manipulation is fragile. Use proper package installation or relative imports.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "quality_broad_exception_type",
        "pattern": r"except\s+BaseException\s*(?::|as\s+\w+\s*:)",
        "message": "Catching BaseException intercepts KeyboardInterrupt and SystemExit. Use Exception instead.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ADDITIONAL CROSS-LANGUAGE SECURITY
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "sec_cors_credentials_wildcard",
        "pattern": r"(?:Access-Control-Allow-Credentials|credentials)\s*[:=]\s*(?:true|True).*(?:Access-Control-Allow-Origin|origin)\s*[:=]\s*[\"']\*",
        "message": "CORS credentials with wildcard origin. Browsers reject this but it indicates misconfigured CORS.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_ssrf_unvalidated",
        "pattern": r"(?:requests\.get|httpx\.get|fetch|http\.Get)\s*\(\s*(?:request\.|req\.|params|user_input|url_param)",
        "message": "HTTP request with user-controlled URL enables SSRF. Validate against an allowlist of hosts.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_weak_password_hash",
        "pattern": r"(?:hashlib\.(?:md5|sha1|sha256)|MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-1|SHA1)[\"'])\s*\(.*(?:password|passwd|pwd)",
        "message": "Weak hash for password storage. Use bcrypt, argon2, or scrypt with proper cost factors.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_unencrypted_connection",
        "pattern": r"[=:]\s*['\"](?:http://|ftp://|telnet://|mongodb://(?!.*ssl|.*tls))(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "message": "Unencrypted connection to remote host. Use HTTPS/TLS for data in transit.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "sec_private_key_inline",
        "pattern": r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
        "message": "Private key embedded in source code. Store in secrets manager or environment variable.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "sec_jwt_secret_weak",
        "pattern": r"(?:jwt_secret|JWT_SECRET|secret_key)\s*[:=]\s*[\"'][^\"']{1,20}[\"']",
        "message": "JWT secret appears short/weak. Use a 256-bit random key for HS256 or RSA keys for RS256.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "sec_rate_limit_missing",
        "pattern": r"@(?:app|router)\.(?:post|put)\s*\(\s*[\"']/(?:auth|login|register|reset|forgot)",
        "message": "Authentication endpoint without visible rate limiting. Add rate limiting to prevent brute force.",
        "severity": Severity.INFO,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "sec_file_upload_no_validation",
        "pattern": r"(?:request\.files|req\.file|upload|multer).*(?:save|write|move)",
        "message": "File upload without content-type validation. Validate file type, size, and sanitize filename.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "sec_mass_assignment",
        "pattern": r"\.create\s*\(\s*\*\*(?:request\.\w+|req\.body|data)",
        "message": "Mass assignment from user input. Whitelist allowed fields explicitly.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "sec_directory_listing",
        "pattern": r"(?:Options\s+\+?Indexes|autoindex\s+on|directory_listing\s*=\s*True)",
        "message": "Directory listing enabled. Disable to prevent information disclosure.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ADDITIONAL RULES — Misc Language & Framework
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "rust_unsafe_undocumented",
        "pattern": r"\bunsafe\s*\{",
        "message": "Unsafe block bypasses Rust safety guarantees. Document why unsafe is necessary.",
        "severity": Severity.WARN,
        "file_types": [".rs"],
        "skip_comments": True,
    },
    {
        "id": "ruby_attr_accessible_broad",
        "pattern": r"attr_accessible\s*:.*,.*,.*,",
        "message": "Too many attributes accessible. Use strong parameters and whitelist explicitly.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_send_user_input",
        "pattern": r"\.send\s*\(\s*(?:params|request|user_input)",
        "message": "Object#send with user input allows arbitrary method invocation. Validate method names.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "csharp_sql_concat",
        "pattern": r"SqlCommand\s*\(\s*[\"'].*\+",
        "message": "SQL command with string concatenation. Use SqlParameter for parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
        "suggestion": "Use parameterized queries: `new SqlCommand(\"SELECT * FROM Users WHERE Id = @id\", conn); cmd.Parameters.AddWithValue(\"@id\", userId);`. Never concatenate user input into SQL.",
    },
    {
        "id": "csharp_catch_exception",
        "pattern": r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}",
        "message": "Catching base Exception and ignoring it. Handle specific exceptions.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "php_sql_direct_input",
        "pattern": r"(?:mysql_query|mysqli_query)\s*\(\s*.*\$_(?:GET|POST|REQUEST)",
        "message": "SQL query with direct user input. Use prepared statements with parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_eval_usage",
        "pattern": r"\beval\s*\(\s*\$",
        "message": "eval() with variable input is remote code execution. Never use eval with user data.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  RUBY SECURITY (rails, erb, gems, file operations)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ruby_rails_sql_where_interpolation",
        "pattern": r"\.where\s*\(\s*[\"'].*#\{",
        "message": "SQL injection via string interpolation in where(). Use parameterized form: where('col = ?', val).",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_csrf_skip",
        "pattern": r"skip_before_action\s+:verify_authenticity_token",
        "message": "CSRF protection disabled. This exposes the endpoint to cross-site request forgery.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_unsafe_redirect",
        "pattern": r"redirect_to\s+params\[",
        "message": "Open redirect via user-controlled parameter. Validate the redirect target against an allowlist.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_render_user_input",
        "pattern": r"render\s+(?:inline|text|html)\s*:\s*params\[",
        "message": "Rendering user input directly leads to XSS. Sanitize or use templates.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_permit_all",
        "pattern": r"\.permit!\s*$",
        "message": "permit! allows all parameters (mass assignment). Whitelist specific attributes with permit(:attr).",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_erb_raw_xss",
        "pattern": r"<%=\s*raw\s+",
        "message": "raw() in ERB disables HTML escaping, enabling XSS. Use sanitize() or escape output.",
        "severity": Severity.BLOCK,
        "file_types": [".erb", ".html.erb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_erb_html_safe_xss",
        "pattern": r"\.html_safe\b",
        "message": "html_safe marks string as safe HTML, bypassing escaping. Verify content is trusted.",
        "severity": Severity.WARN,
        "file_types": [".rb", ".erb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_marshal_load",
        "pattern": r"Marshal\.(?:load|restore)\s*\(",
        "message": "Marshal.load with untrusted data enables arbitrary code execution. Use JSON or MessagePack.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_weak_crypto_digest",
        "pattern": r"Digest::(?:MD5|SHA1)\.(?:hexdigest|digest|new)",
        "message": "MD5/SHA1 are cryptographically weak. Use SHA256 or stronger for security-sensitive hashing.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_open_uri_read",
        "pattern": r"(?:open|URI\.open)\s*\(\s*(?:params|user_input|request)",
        "message": "open-uri with user input can read local files or trigger SSRF. Validate and restrict URLs.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_file_path_traversal",
        "pattern": r"File\.(?:read|open|write|delete)\s*\(\s*(?:params|request)",
        "message": "File operation with user input enables path traversal. Sanitize paths and use a whitelist.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_tempfile_world_readable",
        "pattern": r"Tempfile\.new\b.*mode\s*:\s*0o?666",
        "message": "Tempfile with world-readable permissions. Use restrictive permissions (0o600).",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_yaml_unsafe_load",
        "pattern": r"YAML\.load\s*\(",
        "message": "YAML.load can execute arbitrary Ruby. Use YAML.safe_load or Psych.safe_load.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_constantize_user_input",
        "pattern": r"\.constantize\b",
        "message": "constantize with user input allows arbitrary class instantiation. Use an allowlist of classes.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_find_by_sql",
        "pattern": r"find_by_sql\s*\(\s*[\"'].*#\{",
        "message": "SQL injection via string interpolation in find_by_sql. Use parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_execute_sql",
        "pattern": r"(?:connection|ActiveRecord::Base)\.execute\s*\(\s*[\"'].*#\{",
        "message": "Raw SQL execution with interpolation. Use sanitize_sql or parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_open3_shell_injection",
        "pattern": r"Open3\.(?:capture|popen)\w*\s*\(\s*[\"'].*#\{",
        "message": "Shell command with interpolation via Open3. Use array form to prevent injection.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_backtick_interpolation",
        "pattern": r"`[^`]*#\{.*\}`",
        "message": "Backtick shell command with interpolation. Use Shellwords.escape or array form.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_deserialization_oj",
        "pattern": r"Oj\.load\s*\(.*mode\s*:\s*:object",
        "message": "Oj.load in object mode allows arbitrary object instantiation. Use :strict or :compat mode.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_cookie_serializer_marshal",
        "pattern": r"cookie_serializer\s*=\s*:marshal",
        "message": "Marshal cookie serializer enables RCE via tampered cookies. Use :json serializer.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_force_ssl_disabled",
        "pattern": r"config\.force_ssl\s*=\s*false",
        "message": "SSL enforcement disabled. Enable force_ssl in production to prevent MITM attacks.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_session_store_cookie",
        "pattern": r"session_store\s+:cookie_store\b.*(?!secure)",
        "message": "Cookie store without secure flag. Set secure: true in production configuration.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_erb_unescaped_output",
        "pattern": r"<%==\s+",
        "message": "Double-equals ERB tag outputs unescaped HTML. Use <%= with proper escaping.",
        "severity": Severity.WARN,
        "file_types": [".erb", ".html.erb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_file_chmod_world",
        "pattern": r"File\.chmod\s*\(\s*0o?777",
        "message": "World-writable file permissions (777). Use restrictive permissions (644 or 600).",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
    },
    {
        "id": "ruby_rails_content_tag_unsafe",
        "pattern": r"content_tag\s*\(.*\.html_safe",
        "message": "content_tag with html_safe bypasses escaping. Ensure content is sanitized.",
        "severity": Severity.WARN,
        "file_types": [".rb", ".erb"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  PHP SECURITY (laravel, wordpress, core)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "php_laravel_raw_db",
        "pattern": r"DB::(?:raw|select|statement)\s*\(\s*[\"'].*\$",
        "message": "Raw DB query with variable interpolation. Use parameter binding: DB::select('...?', [$val]).",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_laravel_mass_assignment",
        "pattern": r"protected\s+\$guarded\s*=\s*\[\s*\]",
        "message": "Empty $guarded array allows mass assignment of all fields. Use $fillable with explicit fields.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_blade_unescaped",
        "pattern": r"\{!!\s*\$",
        "message": "Blade {!! !!} outputs unescaped HTML, enabling XSS. Use {{ }} for auto-escaping.",
        "severity": Severity.WARN,
        "file_types": [".php", ".blade.php"],
        "skip_comments": True,
    },
    {
        "id": "php_laravel_csrf_except",
        "pattern": r"protected\s+\$except\s*=\s*\[.*\*",
        "message": "CSRF verification excluded for wildcard routes. Limit exceptions to specific endpoints.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_wordpress_wpdb_query",
        "pattern": r"\$wpdb->query\s*\(\s*[\"'].*\$",
        "message": "Direct WordPress DB query with variable. Use $wpdb->prepare() for parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_wordpress_nonce_missing",
        "pattern": r"wp_ajax_(?:nopriv_)?\w+.*(?!wp_verify_nonce|check_ajax_referer)",
        "message": "WordPress AJAX handler without nonce verification. Add wp_verify_nonce() or check_ajax_referer().",
        "severity": Severity.WARN,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_wordpress_echo_unescaped",
        "pattern": r"echo\s+\$_(?:GET|POST|REQUEST|SERVER)\[",
        "message": "Echoing user input without escaping. Use esc_html(), esc_attr(), or esc_url().",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_include_user_input",
        "pattern": r"(?:include|require)(?:_once)?\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "File inclusion with user input enables remote code execution. Never include user-controlled paths.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_preg_e_modifier",
        "pattern": r"preg_replace\s*\(\s*[\"']/.*[\"']e\b",
        "message": "preg_replace /e modifier executes replacement as PHP code. Use preg_replace_callback().",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_system_exec_passthru",
        "pattern": r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$",
        "message": "Shell execution with variable input. Use escapeshellarg() and escapeshellcmd().",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_assert_string",
        "pattern": r"\bassert\s*\(\s*\$",
        "message": "assert() with string argument executes code in older PHP versions. Use boolean expressions.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_file_get_contents_user",
        "pattern": r"file_get_contents\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "file_get_contents with user input enables SSRF and local file read. Validate URLs strictly.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_curl_ssl_verify_off",
        "pattern": r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)",
        "message": "SSL verification disabled for cURL. This allows MITM attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_serialize_user_data",
        "pattern": r"unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
        "message": "unserialize() with user data enables object injection attacks. Use json_decode() instead.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_session_fixation",
        "pattern": r"session_id\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "Session ID from user input enables session fixation. Regenerate with session_regenerate_id().",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_disable_functions_empty",
        "pattern": r"disable_functions\s*=\s*$",
        "message": "No PHP functions disabled. Restrict dangerous functions in php.ini.",
        "severity": Severity.WARN,
        "file_types": [".ini", ".php"],
        "skip_comments": True,
    },
    {
        "id": "php_register_globals",
        "pattern": r"register_globals\s*=\s*(?:On|1)",
        "message": "register_globals creates variables from user input. This is removed in modern PHP for good reason.",
        "severity": Severity.BLOCK,
        "file_types": [".ini", ".php"],
        "skip_comments": True,
    },
    {
        "id": "php_display_errors_on",
        "pattern": r"display_errors\s*=\s*(?:On|1)",
        "message": "Displaying errors in production leaks internal details. Set display_errors=Off.",
        "severity": Severity.WARN,
        "file_types": [".ini", ".php"],
        "skip_comments": True,
    },
    {
        "id": "php_header_injection",
        "pattern": r"header\s*\(\s*[\"'].*\$_(?:GET|POST|REQUEST)",
        "message": "HTTP header injection via user input. Validate and sanitize header values.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_laravel_env_in_view",
        "pattern": r"env\s*\(\s*['\"](?:APP_KEY|DB_PASSWORD|API_SECRET)",
        "message": "Accessing sensitive env vars directly. Use config() with proper configuration files.",
        "severity": Severity.WARN,
        "file_types": [".php", ".blade.php"],
        "skip_comments": True,
    },
    {
        "id": "php_laravel_debug_true",
        "pattern": r"'debug'\s*=>\s*true",
        "message": "Debug mode enabled in config. Disable in production to prevent information disclosure.",
        "severity": Severity.WARN,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_create_function",
        "pattern": r"\bcreate_function\s*\(",
        "message": "create_function() uses eval internally and is deprecated. Use anonymous functions instead.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },
    {
        "id": "php_wordpress_direct_sql_insert",
        "pattern": r"\$wpdb->(?:insert|update|delete)\s*\(.*\$_(?:GET|POST|REQUEST)",
        "message": "WordPress DB operation with unsanitized user input. Sanitize with sanitize_text_field().",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  C# / .NET SECURITY
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "csharp_csrf_missing",
        "pattern": r"\[Http(?:Post|Put|Delete)\](?!\s*\n\s*\[ValidateAntiForgeryToken\])",
        "message": "POST/PUT/DELETE action without [ValidateAntiForgeryToken]. Add CSRF protection.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_response_write_xss",
        "pattern": r"Response\.Write\s*\(\s*(?:Request|HttpContext\.Current\.Request)",
        "message": "Response.Write with request data enables XSS. Use HtmlEncode() for output encoding.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
        "suggestion": "Encode output: `Response.Write(HttpUtility.HtmlEncode(Request.QueryString[\"input\"]))`. In ASP.NET Core, use `HtmlEncoder.Default.Encode()`. Never write raw user input to response.",
    },
    {
        "id": "csharp_viewstate_mac_disabled",
        "pattern": r"EnableViewStateMac\s*=\s*[\"']?false",
        "message": "ViewState MAC validation disabled. This allows ViewState tampering and injection.",
        "severity": Severity.BLOCK,
        "file_types": [".cs", ".aspx", ".config"],
        "skip_comments": True,
    },
    {
        "id": "csharp_ef_raw_sql",
        "pattern": r"\.(?:FromSqlRaw|ExecuteSqlRaw)\s*\(\s*\$",
        "message": "EF Core raw SQL with string interpolation. Use FromSqlInterpolated() or parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
        "suggestion": "Replace `FromSqlRaw($\"... {id}\")` with `FromSqlInterpolated($\"... {id}\")`. FromSqlInterpolated auto-parameterizes interpolated values. FromSqlRaw with interpolation is SQL injection.",
    },
    {
        "id": "csharp_connection_string_hardcoded",
        "pattern": r"(?:Server|Data Source)\s*=\s*\w+;.*(?:Password|Pwd)\s*=\s*\w+",
        "message": "Hardcoded connection string with credentials. Use configuration manager or secrets vault.",
        "severity": Severity.BLOCK,
        "file_types": [".cs", ".config"],
        "skip_comments": True,
    },
    {
        "id": "csharp_migration_drop_table",
        "pattern": r"migrationBuilder\.DropTable\s*\(",
        "message": "Migration drops a table. Ensure this is intentional and data has been migrated.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_md5_usage",
        "pattern": r"MD5\.Create\s*\(",
        "message": "MD5 is cryptographically broken. Use SHA256 or SHA512 for hashing.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_sha1_usage",
        "pattern": r"SHA1\.Create\s*\(",
        "message": "SHA1 is cryptographically weak. Use SHA256 or SHA512.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_weak_random",
        "pattern": r"new\s+Random\s*\(",
        "message": "System.Random is not cryptographically secure. Use RandomNumberGenerator for security contexts.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_hardcoded_key",
        "pattern": r"new\s+(?:Symmetric|Aes|Rijndael)\w*\s*\{[^}]*Key\s*=\s*new\s+byte\[\]",
        "message": "Hardcoded encryption key. Store keys in a secure vault and load at runtime.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_binary_formatter",
        "pattern": r"BinaryFormatter\s*\(\s*\)",
        "message": "BinaryFormatter is insecure and deprecated. Use System.Text.Json or protobuf.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_json_deserialize_unsafe",
        "pattern": r"JsonConvert\.DeserializeObject\s*\(.*TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)",
        "message": "JsonConvert with TypeNameHandling enables deserialization attacks. Use TypeNameHandling.None.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_process_start_shell",
        "pattern": r"Process\.Start\s*\(\s*(?:\"cmd|\"powershell|\"bash|\"sh)",
        "message": "Starting a shell process. Validate all arguments to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_sql_command_concat",
        "pattern": r"new\s+SqlCommand\s*\(\s*\$",
        "message": "SqlCommand with string interpolation. Use SqlParameter for parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_request_validation_disabled",
        "pattern": r"ValidateInput\s*\(\s*false\s*\)",
        "message": "Request validation disabled. This allows XSS payloads in input.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_custom_error_off",
        "pattern": r"customErrors\s+mode\s*=\s*[\"']Off",
        "message": "Custom errors disabled. Stack traces will be shown to users in production.",
        "severity": Severity.WARN,
        "file_types": [".config"],
        "skip_comments": True,
    },
    {
        "id": "csharp_trace_enabled",
        "pattern": r"<trace\s+enabled\s*=\s*[\"']true",
        "message": "ASP.NET tracing enabled. Disable in production to prevent information disclosure.",
        "severity": Severity.WARN,
        "file_types": [".config"],
        "skip_comments": True,
    },
    {
        "id": "csharp_ldap_injection",
        "pattern": r"DirectorySearcher\s*\(.*\+\s*(?:user|input|request)",
        "message": "LDAP query with concatenated user input. Use parameterized LDAP filters.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_path_combine_user",
        "pattern": r"Path\.Combine\s*\(.*(?:Request|user|input)",
        "message": "Path.Combine with user input allows path traversal. Validate and sanitize the path.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_xml_external_entity",
        "pattern": r"XmlReaderSettings\s*\{[^}]*DtdProcessing\s*=\s*DtdProcessing\.Parse",
        "message": "DTD processing enabled in XML reader. This allows XXE attacks. Use DtdProcessing.Prohibit.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_debug_compilation",
        "pattern": r"compilation\s+debug\s*=\s*[\"']true",
        "message": "Debug compilation enabled. Disable in production for performance and security.",
        "severity": Severity.WARN,
        "file_types": [".config"],
        "skip_comments": True,
    },
    {
        "id": "csharp_unsafe_code",
        "pattern": r"<AllowUnsafeBlocks>true</AllowUnsafeBlocks>",
        "message": "Unsafe code blocks enabled. Review necessity and ensure memory safety.",
        "severity": Severity.WARN,
        "file_types": [".csproj"],
        "skip_comments": True,
    },
    {
        "id": "csharp_cookie_no_secure",
        "pattern": r"new\s+CookieOptions\s*\{(?![^}]*Secure\s*=\s*true)",
        "message": "Cookie without Secure flag. Set Secure=true to prevent transmission over HTTP.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_regex_timeout_missing",
        "pattern": r"new\s+Regex\s*\(\s*[\"'][^\"']{20,}[\"']\s*\)",
        "message": "Complex regex without timeout. Use Regex constructor with TimeSpan to prevent ReDoS.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
        "skip_comments": True,
    },
    {
        "id": "csharp_deserialization_soap",
        "pattern": r"SoapFormatter\s*\(\s*\)",
        "message": "SoapFormatter is insecure. Use System.Text.Json or protobuf for serialization.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SCALA SECURITY (akka, play, core)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "scala_play_sql_injection",
        "pattern": r"SQL\s*\(\s*s?\".*\$",
        "message": "SQL injection via string interpolation in Play. Use SQL('... {param}') with on-parameters.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_play_csrf_disabled",
        "pattern": r"play\.filters\.csrf\..*enabled\s*=\s*false",
        "message": "CSRF filter disabled in Play Framework. Enable to prevent cross-site request forgery.",
        "severity": Severity.BLOCK,
        "file_types": [".scala", ".conf"],
        "skip_comments": True,
    },
    {
        "id": "scala_play_form_no_validation",
        "pattern": r"bindFromRequest\s*\(\s*\)\s*\.(?:get|fold)",
        "message": "Form binding without validation constraints. Define validators in the Form mapping.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_var_usage",
        "pattern": r"^\s*var\s+\w+",
        "message": "Mutable var in Scala code. Prefer val (immutable) for thread safety and clarity.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_null_usage",
        "pattern": r"(?:=\s*null\b|\bnull\b)",
        "message": "null usage in Scala. Use Option[T] instead for null safety.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_any_type",
        "pattern": r":\s*Any\b",
        "message": "Any type in Scala loses type safety. Use a specific type or sealed trait.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_mutable_collection_api",
        "pattern": r"import\s+scala\.collection\.mutable\b",
        "message": "Mutable collection in API. Use immutable collections for thread safety.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_akka_untyped_actor",
        "pattern": r"extends\s+(?:Actor|UntypedAbstractActor)\b",
        "message": "Untyped Akka actor. Use Akka Typed for compile-time message safety.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_akka_dead_letters_ignore",
        "pattern": r"DeadLetter\b.*(?:case\s+_\s*=>|unhandled)",
        "message": "Dead letters being ignored. Log and monitor dead letters to detect messaging issues.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_akka_restart_strategy",
        "pattern": r"SupervisorStrategy\.(?:Resume|Restart)\s*$",
        "message": "Akka supervisor strategy without backoff or limits. Add maxNrOfRetries and withinTimeRange.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_runtime_reflection",
        "pattern": r"runtimeMirror\s*\(",
        "message": "Runtime reflection in Scala. Prefer compile-time macros or shapeless for type safety.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_process_shell",
        "pattern": r"Process\s*\(\s*(?:s?\"|Seq\().*#\{",
        "message": "Shell command with interpolation in Scala. Sanitize inputs to prevent injection.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_thread_sleep",
        "pattern": r"Thread\.sleep\s*\(",
        "message": "Thread.sleep blocks the thread. Use Akka scheduler or Future with delay.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },
    {
        "id": "scala_catch_throwable",
        "pattern": r"catch\s*\{\s*case\s+_\s*:\s*Throwable",
        "message": "Catching Throwable includes fatal errors. Use NonFatal or specific exception types.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DART / FLUTTER SECURITY
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "dart_hardcoded_api_key",
        "pattern": r"(?:const|final)\s+\w*(?:api|key|secret|token)\w*\s*=\s*['\"][^'\"]{8,}['\"]",
        "message": "Hardcoded API key or secret in Dart code. Use environment config or secure storage.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_debug_build_check",
        "pattern": r"kDebugMode\s*\?\s*['\"]",
        "message": "Debug-only logic with hardcoded strings. Ensure sensitive data is not exposed in debug builds.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_webview_js_enabled",
        "pattern": r"javascriptMode\s*:\s*JavascriptMode\.unrestricted",
        "message": "WebView JavaScript unrestricted. This enables XSS in web content. Validate loaded URLs.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_http_cleartext",
        "pattern": r"http://(?!localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01]))",
        "message": "HTTP cleartext traffic detected. Use HTTPS for all external communication.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_certificate_pinning_disabled",
        "pattern": r"badCertificateCallback\s*:\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*=>\s*true",
        "message": "Certificate validation disabled. Implement proper certificate pinning.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_shared_preferences_secret",
        "pattern": r"SharedPreferences.*(?:set(?:String|Int)\s*\(\s*['\"](?:token|password|secret|key))",
        "message": "Storing secrets in SharedPreferences (plaintext). Use flutter_secure_storage.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_dynamic_type_abuse",
        "pattern": r":\s*dynamic\b",
        "message": "dynamic type bypasses type checking. Use a specific type or generics.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_late_no_check",
        "pattern": r"late\s+\w+\s+\w+\s*;",
        "message": "late variable without initialization check. Accessing before init throws LateInitializationError.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_force_unwrap",
        "pattern": r"\w+\s*!\s*\.",
        "message": "Force unwrap (!) on nullable value. Handle null case explicitly or use null-aware operators.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_insecure_random",
        "pattern": r"Random\s*\(\s*\)",
        "message": "Random() is not cryptographically secure. Use Random.secure() for security contexts.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_dio_no_timeout",
        "pattern": r"Dio\s*\(\s*\)",
        "message": "Dio HTTP client without timeout configuration. Set connectTimeout and receiveTimeout.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_sql_injection",
        "pattern": r"rawQuery\s*\(\s*['\"].*\$",
        "message": "Raw SQL query with string interpolation. Use parameterized queries with rawQuery arguments.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_flutter_debug_paint",
        "pattern": r"debugPaintSizeEnabled\s*=\s*true",
        "message": "Debug paint enabled. Ensure this is removed in release builds.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },
    {
        "id": "dart_clipboard_sensitive",
        "pattern": r"Clipboard\.setData\s*\(\s*ClipboardData\s*\(.*(?:password|token|secret)",
        "message": "Copying sensitive data to clipboard exposes it to other apps. Avoid clipboard for secrets.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ELIXIR / PHOENIX SECURITY
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "elixir_phoenix_raw_sql",
        "pattern": r"Ecto\.Adapters\.SQL\.query\s*\(.*\".*#\{",
        "message": "Raw SQL with interpolation in Phoenix. Use Ecto parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_ecto_fragment_injection",
        "pattern": r"fragment\s*\(\s*\".*#\{",
        "message": "Ecto fragment() with string interpolation. Use parameterized form: fragment('... ?', ^val).",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_phoenix_csrf_disabled",
        "pattern": r"plug\s+:protect_from_forgery.*when\s+action\s+not\s+in",
        "message": "CSRF protection disabled for actions. Verify these endpoints truly do not need CSRF protection.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_unsafe_atom_creation",
        "pattern": r"String\.to_atom\s*\(",
        "message": "String.to_atom with untrusted input can exhaust the atom table (never GC'd). Use to_existing_atom.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_code_eval",
        "pattern": r"Code\.eval_(?:string|file|quoted)\s*\(",
        "message": "Code.eval_string executes arbitrary code. Never use with user input.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_system_cmd_injection",
        "pattern": r"System\.cmd\s*\(\s*\"(?:bash|sh)\"\s*,\s*\[\s*\"-c\"",
        "message": "Shell command via System.cmd. Validate all arguments to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_ecto_migration_drop",
        "pattern": r"drop\s+table\s*\(",
        "message": "Ecto migration drops a table. Ensure this is intentional and data is backed up.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_phoenix_session_fixation",
        "pattern": r"put_session\s*\(.*(?:conn\.params|params\[)",
        "message": "Setting session value from user params. Ensure session IDs are regenerated on auth changes.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_hardcoded_secret",
        "pattern": r"secret_key_base:\s*\"[a-zA-Z0-9+/=]{20,}\"",
        "message": "Hardcoded secret_key_base. Use environment variables for secrets.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },
    {
        "id": "elixir_erlang_term_decode",
        "pattern": r":erlang\.binary_to_term\s*\(",
        "message": "binary_to_term with untrusted data enables code execution. Use JSON or MessagePack.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ADVANCED SQL SECURITY
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "sql_pg_security_definer",
        "pattern": r"(?i)SECURITY\s+DEFINER\b",
        "message": "SECURITY DEFINER function runs as owner. Verify it cannot be exploited for privilege escalation.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_pg_rls_bypass",
        "pattern": r"(?i)ALTER\s+TABLE\s+\w+\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY",
        "message": "Row Level Security disabled. This removes tenant isolation. Verify this is intentional.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_pg_unparameterized_execute",
        "pattern": r"(?i)EXECUTE\s+['\"].*\|\|\s*",
        "message": "EXECUTE with string concatenation. Use EXECUTE ... USING for parameterized dynamic SQL.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_mysql_strict_mode_off",
        "pattern": r"(?i)SET\s+(?:GLOBAL\s+)?sql_mode\s*=\s*['\"]'?\"?;",
        "message": "SQL strict mode set to empty. Use STRICT_TRANS_TABLES to catch data truncation.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_outfile_injection",
        "pattern": r"(?i)INTO\s+(?:OUTFILE|DUMPFILE)\s+",
        "message": "INTO OUTFILE/DUMPFILE can write arbitrary files. Restrict FILE privilege.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_union_injection_pattern",
        "pattern": r"(?i)UNION\s+(?:ALL\s+)?SELECT\s+(?:NULL|1|2|3|char\(|0x)",
        "message": "UNION-based SQL injection pattern detected. Review for injection vulnerability.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_time_based_blind",
        "pattern": r"(?i)(?:SLEEP|BENCHMARK|WAITFOR\s+DELAY|pg_sleep)\s*\(",
        "message": "Time-based blind SQL injection function. Remove unless this is a legitimate migration delay.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_boolean_blind_pattern",
        "pattern": r"(?i)AND\s+(?:1=1|1=2|'[a-z]'='[a-z]'|SUBSTR|ASCII)\b",
        "message": "Boolean-based blind SQL injection pattern. Review query construction.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_load_file",
        "pattern": r"(?i)LOAD_FILE\s*\(",
        "message": "LOAD_FILE reads server files. Restrict FILE privilege and validate inputs.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_pg_superuser_grant",
        "pattern": r"(?i)ALTER\s+ROLE\s+\w+\s+(?:WITH\s+)?SUPERUSER",
        "message": "Granting SUPERUSER privilege. Use minimal privilege roles instead.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_pg_trust_auth",
        "pattern": r"(?i)^\s*host\s+all\s+all\s+.*\s+trust\s*$",
        "message": "PostgreSQL trust authentication allows passwordless access. Use scram-sha-256.",
        "severity": Severity.BLOCK,
        "file_types": [".conf"],
    },
    {
        "id": "sql_information_schema_leak",
        "pattern": r"(?i)SELECT\s+.*FROM\s+information_schema\.",
        "message": "Querying information_schema. Ensure this is not exposed to untrusted users.",
        "severity": Severity.INFO,
        "file_types": [".sql"],
    },
    {
        "id": "sql_pg_extension_untrusted",
        "pattern": r"(?i)CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:plpythonu|plperlu)\b",
        "message": "Untrusted language extension (plpythonu/plperlu) allows arbitrary code. Use trusted variants.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_stacked_queries",
        "pattern": r";\s*(?:DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)\s+",
        "message": "Stacked query pattern detected. Review for SQL injection via statement chaining.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "sql_charset_injection",
        "pattern": r"(?i)SET\s+(?:NAMES|CHARACTER\s+SET)\s+['\"]?(?:gbk|big5|sjis)",
        "message": "Multi-byte charset can enable SQL injection via encoding bypass. Use utf8mb4.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  API SECURITY ADVANCED (graphql, grpc, rest)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "graphql_depth_limit_missing",
        "pattern": r"ApolloServer\s*\(\s*\{(?![^}]*(?:depthLimit|validationRules))",
        "message": "GraphQL server without query depth limit. Add depthLimit validation to prevent DoS.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "graphql_introspection_prod",
        "pattern": r"introspection\s*:\s*true",
        "message": "GraphQL introspection enabled. Disable in production to prevent schema enumeration.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py"],
        "skip_comments": True,
    },
    {
        "id": "graphql_batch_no_limit",
        "pattern": r"(?:allowBatchedHttpRequests|batching)\s*:\s*true",
        "message": "GraphQL batching enabled without limit. Add maxBatchSize to prevent batching attacks.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "grpc_reflection_enabled",
        "pattern": r"(?:enable_server_reflection|reflection\.enable)",
        "message": "gRPC reflection enabled. Disable in production to prevent service enumeration.",
        "severity": Severity.WARN,
        "file_types": [".py", ".go", ".java"],
        "skip_comments": True,
    },
    {
        "id": "grpc_no_auth_interceptor",
        "pattern": r"grpc\.server\s*\(\s*\w+\s*\(\s*\)(?!\s*,\s*interceptors)",
        "message": "gRPC server without auth interceptor. Add authentication middleware.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "skip_comments": True,
    },
    {
        "id": "api_idor_sequential_id",
        "pattern": r"(?:GET|PUT|DELETE|PATCH)\s+['\"].*/:id['\"]",
        "message": "REST endpoint with sequential ID. Verify authorization checks prevent IDOR.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".py", ".rb"],
        "skip_comments": True,
    },
    {
        "id": "api_verbose_error_stack",
        "pattern": r"(?:res\.json|jsonify|JSONResponse)\s*\(\s*\{.*(?:stack|traceback|stackTrace)",
        "message": "Stack trace in API response. Return generic error messages to clients.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py"],
        "skip_comments": True,
    },
    {
        "id": "api_no_pagination_limit",
        "pattern": r"(?:limit|page_size|per_page)\s*=\s*(?:int|parseInt)\s*\(\s*(?:req|request|params)",
        "message": "User-controlled pagination limit without max cap. Set a maximum limit to prevent DoS.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".rb"],
        "skip_comments": True,
    },
    {
        "id": "api_mass_assignment_express",
        "pattern": r"Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)",
        "message": "Mass assignment via Object.assign with request body. Whitelist allowed fields explicitly.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "api_graphql_no_cost_analysis",
        "pattern": r"(?:schema|typeDefs)\s*:\s*.*(?:@complexity|costAnalysis)",
        "message": "GraphQL without query cost analysis. Add cost analysis to prevent expensive queries.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "api_no_request_id",
        "pattern": r"app\.use\s*\(\s*(?:express|cors|helmet)",
        "message": "Consider adding request ID middleware for tracing. Use express-request-id or similar.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "api_jwt_long_expiry",
        "pattern": r"expiresIn\s*:\s*['\"](?:30d|365d|99d|1y|never)['\"]",
        "message": "JWT with excessively long expiry. Use short-lived tokens with refresh token rotation.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "api_rest_method_override_header",
        "pattern": r"X-HTTP-Method-Override|X-Method-Override",
        "message": "HTTP method override header in use. Ensure this cannot bypass authorization checks.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".rb"],
        "skip_comments": True,
    },
    {
        "id": "api_grpc_plaintext_server",
        "pattern": r"ServerBuilder\s*\.\s*forPort\s*\(\s*\d+\s*\)\s*\.addService",
        "message": "gRPC server without TLS configuration. Use useTransportSecurity() for encryption.",
        "severity": Severity.WARN,
        "file_types": [".java", ".scala"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CLOUD / IaC ADVANCED (aws, azure, gcp)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "aws_iam_inline_policy",
        "pattern": r"(?i)aws_iam_(?:user|group|role)_policy\b(?!_attachment)",
        "message": "IAM inline policy. Use managed policies (aws_iam_policy_attachment) for maintainability.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_cloudtrail_disabled",
        "pattern": r"(?i)enable_logging\s*=\s*false",
        "message": "CloudTrail logging disabled. Enable for audit trail compliance.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_kms_no_rotation",
        "pattern": r"(?i)enable_key_rotation\s*=\s*false",
        "message": "KMS key rotation disabled. Enable automatic key rotation for compliance.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_lambda_env_secrets",
        "pattern": r"(?i)environment\s*\{[^}]*variables\s*=\s*\{[^}]*(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=",
        "message": "Secrets in Lambda environment variables. Use AWS Secrets Manager or SSM Parameter Store.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "azure_storage_public_access",
        "pattern": r"(?i)allow_(?:nested_items_to_be_public|blob_public_access)\s*=\s*true",
        "message": "Azure storage public access enabled. Set to false unless public access is required.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "azure_nsg_allow_all",
        "pattern": r"(?i)source_address_prefix\s*=\s*[\"']\\*[\"']",
        "message": "NSG rule allows all source addresses. Restrict to specific IP ranges.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "azure_keyvault_no_soft_delete",
        "pattern": r"(?i)soft_delete_(?:retention_days|enabled)\s*=\s*(?:false|0)",
        "message": "Key Vault soft delete disabled. Enable to prevent accidental permanent deletion.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "gcp_default_service_account",
        "pattern": r"(?i)service_account\s*=\s*[\"']\d+-compute@developer\.gserviceaccount\.com",
        "message": "Using GCP default service account. Create a dedicated service account with minimal permissions.",
        "severity": Severity.WARN,
        "file_types": [".tf", ".yaml", ".yml"],
        "skip_comments": True,
    },
    {
        "id": "gcp_firewall_allow_all",
        "pattern": r"(?i)source_ranges\s*=\s*\[\s*[\"']0\.0\.0\.0/0[\"']",
        "message": "GCP firewall allows all source IPs. Restrict to specific IP ranges.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "gcp_cloud_sql_public_ip",
        "pattern": r"(?i)ipv4_enabled\s*=\s*true",
        "message": "Cloud SQL public IP enabled. Use private IP with VPC peering for database access.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_s3_no_versioning",
        "pattern": r"(?i)versioning\s*\{[^}]*enabled\s*=\s*false",
        "message": "S3 bucket versioning disabled. Enable for data recovery and compliance.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_rds_no_backup",
        "pattern": r"(?i)backup_retention_period\s*=\s*0",
        "message": "RDS backup retention set to 0. Enable automated backups for disaster recovery.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_ec2_imdsv1",
        "pattern": r"(?i)http_tokens\s*=\s*[\"']optional",
        "message": "EC2 IMDSv1 enabled (http_tokens=optional). Require IMDSv2 for SSRF protection.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "cloud_log_retention_zero",
        "pattern": r"(?i)retention_in_days\s*=\s*0",
        "message": "Log retention set to 0 (indefinite or none). Set appropriate retention period.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },
    {
        "id": "aws_vpc_flow_logs_disabled",
        "pattern": r"(?i)enable_flow_log\s*=\s*false",
        "message": "VPC flow logs disabled. Enable for network monitoring and forensics.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  MOBILE ADVANCED (iOS, React Native, cross-platform)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ios_nsurlsession_no_cert",
        "pattern": r"URLSession\.shared\.data(?:Task)?\s*\(",
        "message": "URLSession.shared without custom certificate validation. Implement URLSessionDelegate for pinning.",
        "severity": Severity.INFO,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "ios_keychain_wrong_access",
        "pattern": r"kSecAttrAccessible.*(?:Always|AfterFirstUnlock)(?!ThisDeviceOnly)",
        "message": "Keychain item accessible without device restriction. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "ios_screenshot_caching",
        "pattern": r"applicationWillResignActive(?!.*isSecure|.*window\.isHidden)",
        "message": "App may cache screenshots when backgrounded. Obscure sensitive content in applicationWillResignActive.",
        "severity": Severity.INFO,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "rn_hermes_debug",
        "pattern": r"hermesFlags\s*=.*\"-O0\"",
        "message": "Hermes engine in debug mode. Use -O for release builds.",
        "severity": Severity.WARN,
        "file_types": [".gradle"],
        "skip_comments": True,
    },
    {
        "id": "rn_asyncstorage_secrets",
        "pattern": r"AsyncStorage\.setItem\s*\(\s*['\"](?:token|password|secret|apiKey)",
        "message": "Storing secrets in AsyncStorage (unencrypted). Use react-native-keychain or SecureStore.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "rn_deep_link_injection",
        "pattern": r"Linking\.addEventListener\s*\(\s*['\"]url['\"].*(?!validate|check|verify)",
        "message": "Deep link handler without URL validation. Validate and sanitize incoming deep links.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "mobile_biometric_bypass",
        "pattern": r"(?:LAPolicy|BiometricManager).*(?:fallback|deviceCredential)",
        "message": "Biometric auth with fallback to passcode. Evaluate if this meets your security requirements.",
        "severity": Severity.INFO,
        "file_types": [".swift", ".kt", ".java"],
        "skip_comments": True,
    },
    {
        "id": "mobile_root_detection_missing",
        "pattern": r"(?:isRooted|isJailbroken)\s*\(\s*\)\s*\{\s*return\s+false",
        "message": "Root/jailbreak detection always returns false. Implement actual device integrity checks.",
        "severity": Severity.WARN,
        "file_types": [".swift", ".kt", ".java", ".dart"],
        "skip_comments": True,
    },
    {
        "id": "mobile_clipboard_exposure",
        "pattern": r"(?:clipboardManager|UIPasteboard|Clipboard).*(?:getText|getString|general\.string)",
        "message": "Reading clipboard data. Be cautious of sensitive data from other apps in clipboard.",
        "severity": Severity.INFO,
        "file_types": [".swift", ".kt", ".java", ".dart"],
        "skip_comments": True,
    },
    {
        "id": "android_backup_enabled",
        "pattern": r"android:allowBackup\s*=\s*\"true\"",
        "message": "Android backup enabled. Sensitive data may be extracted from backups. Set allowBackup=false.",
        "severity": Severity.WARN,
        "file_types": [".xml"],
        "skip_comments": True,
    },
    {
        "id": "ios_url_scheme_hijack",
        "pattern": r"CFBundleURLSchemes.*<string>\w+</string>",
        "message": "Custom URL scheme registered. Validate source and data in URL handler to prevent hijacking.",
        "severity": Severity.INFO,
        "file_types": [".plist"],
        "skip_comments": True,
    },
    {
        "id": "rn_webview_injected_js",
        "pattern": r"injectedJavaScript\s*=\s*\{.*(?:fetch|XMLHttpRequest|eval)",
        "message": "Injecting JavaScript with network or eval calls into WebView. Review for security.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "mobile_cert_pinning_disabled",
        "pattern": r"(?:TrustManager|ServerCertificateCustomValidationCallback).*return\s+true",
        "message": "Certificate validation returning true unconditionally. Implement proper cert pinning.",
        "severity": Severity.BLOCK,
        "file_types": [".java", ".kt", ".cs"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  PERFORMANCE & RELIABILITY
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "perf_unbounded_cache",
        "pattern": r"(?:cache|_cache|CACHE)\s*=\s*(?:\{\}|dict\(\))\s*$",
        "message": "Unbounded in-memory cache. Use LRU cache or set a max size to prevent memory exhaustion.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_large_object_closure",
        "pattern": r"lambda\s*:.*(?:DataFrame|large_|bulk_|all_)",
        "message": "Lambda capturing potentially large object. This prevents garbage collection.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "perf_circular_reference",
        "pattern": r"self\.\w+\s*=\s*self\b",
        "message": "Potential circular reference (self.x = self). Use weakref to prevent memory leaks.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_no_retry_backoff",
        "pattern": r"(?:while|for)\s+.*(?:retry|attempt).*(?:sleep|wait)\s*\(\s*(?:1|2|0\.)",
        "message": "Retry loop with fixed delay. Use exponential backoff to prevent thundering herd.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_no_circuit_breaker",
        "pattern": r"(?:while\s+True|for\s+_\s+in\s+range).*(?:httpx|requests|aiohttp)\.(?:get|post|put)",
        "message": "HTTP calls in retry loop without circuit breaker. Add circuit breaker to prevent cascade failure.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_connection_pool_exhaust",
        "pattern": r"(?:create_engine|ConnectionPool)\s*\((?![^)]*pool_size|[^)]*max_connections)",
        "message": "Connection pool without size limit. Set pool_size and max_overflow to prevent exhaustion.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_race_condition_check_then_act",
        "pattern": r"if\s+(?:os\.path\.exists|Path\s*\(\s*\w+\s*\)\.exists)\s*\(.*\).*\n.*open\s*\(",
        "message": "Check-then-act race condition (TOCTOU). Use atomic operations or file locking.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_deadlock_nested_locks",
        "pattern": r"(?:with\s+\w+_lock|\.acquire\(\)).*\n.*(?:with\s+\w+_lock|\.acquire\(\))",
        "message": "Nested lock acquisition. Use consistent lock ordering or a single lock to prevent deadlocks.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_thread_unsafe_singleton",
        "pattern": r"_instance\s*=\s*None\b.*\n.*if\s+.*_instance\s+is\s+None",
        "message": "Thread-unsafe singleton pattern. Use threading.Lock or module-level instance.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_unbounded_queue",
        "pattern": r"(?:Queue|deque)\s*\(\s*\)(?!\s*#.*maxsize)",
        "message": "Unbounded queue. Set maxsize to prevent memory exhaustion under load.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "perf_global_list_append",
        "pattern": r"^\s*\w+_(?:list|items|data|records)\s*\.append\s*\(",
        "message": "Appending to module-level list without bound. This grows indefinitely in long-running processes.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_sync_io_in_async",
        "pattern": r"(?:async\s+def\s+\w+.*\n(?:\s+.*\n)*?\s+)(?:open|os\.\w+|time\.sleep)\s*\(",
        "message": "Synchronous I/O in async function blocks the event loop. Use aiofiles or asyncio equivalent.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_dns_lookup_loop",
        "pattern": r"(?:for|while)\s+.*(?:socket\.gethostbyname|getaddrinfo)\s*\(",
        "message": "DNS lookup in loop. Cache DNS results or resolve once before the loop.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_regex_compile_loop",
        "pattern": r"(?:for|while)\s+.*\n\s+.*re\.compile\s*\(",
        "message": "Regex compilation inside loop. Compile regex once at module level.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_no_http_keepalive",
        "pattern": r"(?:requests|httpx)\.(?:get|post|put|delete)\s*\(",
        "message": "Individual HTTP request without session/client. Use a session/client for connection reuse.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "perf_large_payload_no_stream",
        "pattern": r"(?:response|res)\.(?:json|text|content)\s*\(\s*\).*(?:for|while)",
        "message": "Loading entire response before iterating. Use streaming for large payloads.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "perf_n_plus_one_query",
        "pattern": r"for\s+\w+\s+in\s+\w+.*\n\s+.*\.(?:query|filter|get|find)\s*\(",
        "message": "Potential N+1 query pattern. Use eager loading (select_related/prefetch/JOIN) instead.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_goroutine_no_wait",
        "pattern": r"go\s+func\s*\(.*\)\s*\{(?![^}]*wg\.|[^}]*done|[^}]*errCh)",
        "message": "Goroutine launched without WaitGroup or completion signal. May cause resource leaks.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "perf_js_memory_leak_event",
        "pattern": r"addEventListener\s*\((?![^)]*\{[^}]*once\s*:\s*true)",
        "message": "Event listener without cleanup. Remove listeners in componentWillUnmount or useEffect cleanup.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "perf_setinterval_no_clear",
        "pattern": r"setInterval\s*\(\s*(?:function|\(\)|=>)",
        "message": "setInterval without clearInterval reference. Store the interval ID for cleanup.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
        "skip_comments": True,
    },
    {
        "id": "perf_promise_all_unbounded",
        "pattern": r"Promise\.all\s*\(\s*\w+\.map\s*\(",
        "message": "Promise.all with mapped array may be unbounded. Use p-limit or batching for concurrency control.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
        "skip_comments": True,
    },
    {
        "id": "perf_db_no_connection_pool",
        "pattern": r"(?:psycopg2|mysql\.connector|pymysql)\.connect\s*\(",
        "message": "Direct database connection without pool. Use connection pooling for production workloads.",
        "severity": Severity.WARN,
        "skip_comments": True,
    },
    {
        "id": "perf_blocking_main_thread",
        "pattern": r"(?:requests\.get|urllib\.request\.urlopen|urlopen)\s*\(",
        "message": "Blocking HTTP call. Use async client (httpx.AsyncClient, aiohttp) in async contexts.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "perf_file_read_entire",
        "pattern": r"\.read\s*\(\s*\)\s*$",
        "message": "Reading entire file into memory. Use chunked reading or streaming for large files.",
        "severity": Severity.INFO,
        "skip_comments": True,
    },
    {
        "id": "perf_mutex_contention",
        "pattern": r"sync\.Mutex\s*\{?\}?\s*$",
        "message": "Mutex without considering RWMutex. Use sync.RWMutex for read-heavy workloads.",
        "severity": Severity.INFO,
        "file_types": [".go"],
        "skip_comments": True,
    },

    # ═══════════════════════════════════════════════════════════════
    #  Internal diagnostic markers — detect CodeTrust internal
    #  identifiers that should not appear in production code.
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ct_sig_borna_2026_alpha",
        "pattern": r"\b__codetrust_internal_marker_alpha__\b",
        "message": "Internal CodeTrust marker detected. This should not appear in production code.",
        "severity": Severity.INFO,
    },
    {
        "id": "ct_sig_governance_w7x9",
        "pattern": r"\bCODETRUST_INTERNAL_GOVERNANCE_W7X9\b",
        "message": "Internal governance marker. Remove before deployment.",
        "severity": Severity.INFO,
    },
    {
        "id": "ct_sig_drift_k3m2_sentinel",
        "pattern": r"\b_ct_drift_sentinel_k3m2_check\b",
        "message": "Trust drift sentinel marker. Remove before deployment.",
        "severity": Severity.INFO,
    },
    {
        "id": "ct_sig_moat_v4_fingerprint",
        "pattern": r"\bCT_MOAT_V4_FINGERPRINT_9F2A\b",
        "message": "CodeTrust moat fingerprint detected. Remove before deployment.",
        "severity": Severity.INFO,
    },
    {
        "id": "ct_sig_sborna_proprietary_q8",
        "pattern": r"\b__ct_proprietary_q8_marker__\b",
        "message": "Proprietary code marker. This identifier is registered to CodeTrust.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  GRAPHQL SECURITY (rules 1003-1012)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "graphql_introspection_leak",
        "pattern": r"(?i)introspection\s*[:=]\s*(?:true|True|1)",
        "message": "GraphQL introspection enabled. Disable in production to prevent schema leakage.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "graphql_depth_limit_disabled",
        "pattern": r"(?i)depthLimit\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "GraphQL depth limiting disabled. Set a reasonable depth limit to prevent DoS.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "graphql_query_string_concat",
        "pattern": r"(?:query|mutation)\s*[:=]\s*(?:f[\"']|[^)]*\.format\s*\()",
        "message": "GraphQL query built via string formatting. Use parameterized variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "graphql_no_cost_analysis",
        "pattern": r"(?i)costAnalysis\s*[:=]\s*(?:false|False|None|null)",
        "message": "GraphQL cost analysis disabled. Enable to prevent expensive queries.",
        "severity": Severity.WARN,
    },
    {
        "id": "graphql_batch_unlimited",
        "pattern": r"(?i)(?:allow_?batch|batch_?limit)\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "GraphQL batching unlimited. Set a batch limit to prevent abuse.",
        "severity": Severity.WARN,
    },
    {
        "id": "graphql_no_rate_limit",
        "pattern": r"(?i)(?:rate_?limit|throttle)\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "GraphQL rate limiting disabled. Enable rate limiting on resolvers.",
        "severity": Severity.WARN,
    },
    {
        "id": "graphql_field_suggestion",
        "pattern": r"(?i)(?:field_?suggestions|suggest_?fields)\s*[:=]\s*(?:true|True|1)",
        "message": "GraphQL field suggestions enabled. Disable in production to limit information disclosure.",
        "severity": Severity.INFO,
    },
    {
        "id": "graphql_playground_prod",
        "pattern": r"(?i)(?:graphiql|playground)\s*[:=]\s*(?:true|True|1)",
        "message": "GraphQL playground/GraphiQL enabled. Disable in production.",
        "severity": Severity.WARN,
    },
    {
        "id": "graphql_no_persisted_queries",
        "pattern": r"(?i)persistedQueries\s*[:=]\s*(?:false|False|None|null)",
        "message": "Persisted queries disabled. Consider enabling to restrict arbitrary queries.",
        "severity": Severity.INFO,
    },
    {
        "id": "graphql_debug_mode",
        "pattern": r"(?i)(?:graphql_?debug|debug_?graphql)\s*[:=]\s*(?:true|True|1)",
        "message": "GraphQL debug mode enabled. Disable in production to prevent stack trace leakage.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  WEBASSEMBLY SECURITY (rules 1013-1020)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "wasm_unchecked_memory",
        "pattern": r"\bmemory\.grow\b(?!.*bounds)",
        "message": "WebAssembly memory.grow without bounds checking. Validate growth limits.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "wasm_unsafe_ptr_cast",
        "pattern": r"(?:__wasm_ptr|wasm_bindgen).*(?:as\s+\*mut|as\s+\*const)",
        "message": "Unsafe pointer cast in WASM boundary. Validate pointer bounds.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "wasm_no_stack_guard",
        "pattern": r"(?i)stack_?guard\s*[:=]\s*(?:false|False|0|None|null)",
        "message": "WASM stack guard disabled. Enable to prevent stack overflow attacks.",
        "severity": Severity.WARN,
    },
    {
        "id": "wasm_shared_memory_no_lock",
        "pattern": r"SharedArrayBuffer.*(?:wasm|WebAssembly)(?!.*(?:Atomics|lock|mutex))",
        "message": "Shared memory with WASM without synchronization. Use Atomics or mutex.",
        "severity": Severity.WARN,
    },
    {
        "id": "wasm_eval_module",
        "pattern": r"WebAssembly\.(?:compile|instantiate)\s*\(\s*(?:user|input|request|body)",
        "message": "Compiling WebAssembly from user input. Validate and sandbox module source.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "wasm_unbounded_table",
        "pattern": r"WebAssembly\.Table\s*\(\s*\{[^}]*maximum\s*:\s*(?:Infinity|undefined)",
        "message": "WASM table without bounded maximum. Set a finite maximum.",
        "severity": Severity.WARN,
    },
    {
        "id": "wasm_import_all",
        "pattern": r"importObject\s*[:=]\s*\{[^}]*\.\.\.",
        "message": "Spreading all properties into WASM imports. Explicitly list imported functions.",
        "severity": Severity.WARN,
    },
    {
        "id": "wasm_debug_info_prod",
        "pattern": r"(?i)(?:wasm_?debug|debug_?wasm|--debug-info)\s*[:=]\s*(?:true|True|1)",
        "message": "WASM debug info enabled in production build. Strip debug info.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  gRPC SECURITY (rules 1021-1030)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "grpc_insecure_channel",
        "pattern": r"grpc\.insecure_channel\s*\(",
        "message": "gRPC insecure channel. Use grpc.secure_channel with TLS credentials.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "grpc_no_deadline",
        "pattern": r"\.(?:unary_unary|unary_stream|stream_unary|stream_stream)\s*\([^)]*\)(?!.*(?:timeout|deadline))",
        "message": "gRPC call without deadline/timeout. Always set a deadline.",
        "severity": Severity.WARN,
    },
    {
        "id": "grpc_tls_disabled",
        "pattern": r"(?i)grpc_?tls\s*[:=]\s*(?:false|False|0|None|null)",
        "message": "gRPC TLS disabled. Enable TLS for all gRPC connections.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "grpc_reflection_prod",
        "pattern": r"(?:add_ServerReflection|enable_server_reflection|grpc_reflection)",
        "message": "gRPC reflection enabled. Disable in production to prevent service discovery.",
        "severity": Severity.WARN,
    },
    {
        "id": "grpc_no_interceptor",
        "pattern": r"grpc\.server\s*\([^)]*\)(?!.*interceptor)",
        "message": "gRPC server without interceptors. Add auth/logging interceptors.",
        "severity": Severity.INFO,
    },
    {
        "id": "grpc_max_message_unlimited",
        "pattern": r"(?i)max_?(?:receive|send)_?message_?(?:length|size)\s*[:=]\s*(?:-1|0|None|null)",
        "message": "gRPC max message size unlimited. Set a reasonable limit.",
        "severity": Severity.WARN,
    },
    {
        "id": "grpc_plaintext_metadata",
        "pattern": r"metadata\s*[:=]\s*\[.*(?:password|secret|token|api_key)",
        "message": "Sensitive data in gRPC metadata without encryption. Use TLS.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "grpc_no_keepalive",
        "pattern": r"(?i)grpc_?keepalive\s*[:=]\s*(?:false|False|0|None|null)",
        "message": "gRPC keepalive disabled. Enable to detect dead connections.",
        "severity": Severity.INFO,
    },
    {
        "id": "grpc_channel_no_retry",
        "pattern": r"(?i)(?:enable_?retries|retry_?policy)\s*[:=]\s*(?:false|False|None|null)",
        "message": "gRPC retries disabled. Configure retry policy for resilience.",
        "severity": Severity.INFO,
    },
    {
        "id": "grpc_no_health_check",
        "pattern": r"grpc\.server\s*\([^)]*\)(?!.*[Hh]ealth)",
        "message": "gRPC server without health check service. Add health checking.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  BLOCKCHAIN / SMART CONTRACT (rules 1031-1045)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "solidity_reentrancy",
        "pattern": r"\.call\s*\{.*value\s*:",
        "message": "Potential reentrancy vulnerability. Use checks-effects-interactions pattern.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_unchecked_call",
        "pattern": r"\.(?:send|transfer|call)\s*\([^)]*\)\s*;(?!\s*(?:require|assert|if))",
        "message": "Unchecked external call return value. Always check call success.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_tx_origin",
        "pattern": r"\btx\.origin\b",
        "message": "tx.origin used for authorization. Use msg.sender instead.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_selfdestruct",
        "pattern": r"\bselfdestruct\s*\(",
        "message": "selfdestruct is dangerous and deprecated. Remove or guard carefully.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_delegatecall",
        "pattern": r"\bdelegatecall\s*\(",
        "message": "delegatecall can execute arbitrary code. Validate target address.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_floating_pragma",
        "pattern": r"pragma\s+solidity\s*\^",
        "message": "Floating pragma version. Pin to a specific compiler version.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_timestamp_dep",
        "pattern": r"\bblock\.timestamp\b.*(?:==|<|>|<=|>=)",
        "message": "Block timestamp used for comparison. Miners can manipulate timestamps.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_unbounded_loop",
        "pattern": r"for\s*\([^)]*\.length\s*[;)]",
        "message": "Unbounded loop over dynamic array. May exceed gas limit.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_integer_overflow",
        "pattern": r"(?:uint|int)\d*\s+\w+\s*=\s*\w+\s*[\+\-\*](?!.*(?:SafeMath|unchecked))",
        "message": "Arithmetic without overflow protection. Use SafeMath or Solidity >=0.8.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "solidity_public_var_no_access",
        "pattern": r"^\s*(?:uint|int|address|bool|string|bytes)\d*\s+public\s+\w+\s*;",
        "message": "Public state variable without access control. Consider using private with getter.",
        "severity": Severity.INFO,
        "file_types": [".sol"],
    },
    {
        "id": "web3_hardcoded_private_key",
        "pattern": r"(?i)(?:private_?key|privateKey)\s*[:=]\s*[\"'][0-9a-fA-F]{64}[\"']",
        "message": "Hardcoded private key. Use environment variables or key vault.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "web3_no_gas_limit",
        "pattern": r"\.sendTransaction\s*\(\s*\{(?!.*gas)",
        "message": "Transaction without gas limit. Always specify gas to prevent draining.",
        "severity": Severity.WARN,
    },
    {
        "id": "solidity_assembly_block",
        "pattern": r"\bassembly\s*\{",
        "message": "Inline assembly bypasses Solidity safety checks. Review carefully.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "web3_unsigned_tx",
        "pattern": r"sendUnsignedTransaction|send_raw_transaction\s*\(\s*(?!.*sign)",
        "message": "Sending unsigned/raw transaction. Ensure proper signing flow.",
        "severity": Severity.WARN,
    },
    {
        "id": "solidity_ecrecover_no_check",
        "pattern": r"\becrecover\s*\([^)]*\)(?!\s*(?:require|!=\s*address\(0\)))",
        "message": "ecrecover without zero-address check. Verify recovered address is non-zero.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  ML PIPELINE SECURITY (rules 1046-1058)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ml_pickle_model_load",
        "pattern": r"(?:torch\.load|joblib\.load|keras\.models\.load_model)\s*\(\s*(?:user|input|request|url|http)",
        "message": "Loading ML model from untrusted source. Validate model origin and hash.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml_unsafe_deserialization",
        "pattern": r"(?:cloudpickle|dill|shelve)\.load\s*\(",
        "message": "Unsafe deserialization library. Use safetensors or ONNX for model loading.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml_no_input_validation",
        "pattern": r"model\.predict\s*\(\s*(?:request|user_input|raw_data)",
        "message": "ML model inference without input validation. Sanitize and validate inputs.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml_hardcoded_seed",
        "pattern": r"(?:random\.seed|np\.random\.seed|torch\.manual_seed)\s*\(\s*\d+\s*\)",
        "message": "Hardcoded random seed. Use configurable seed for reproducibility.",
        "severity": Severity.INFO,
    },
    {
        "id": "ml_no_model_versioning",
        "pattern": r"(?:model\.save|torch\.save)\s*\(\s*[\"'][^\"']*[\"']\s*\)(?!.*version)",
        "message": "Model saved without version tracking. Include version in path or metadata.",
        "severity": Severity.INFO,
    },
    {
        "id": "ml_training_data_url",
        "pattern": r"(?:read_csv|load_dataset|fetch)\s*\(\s*[\"']https?://",
        "message": "Training data loaded from URL. Pin hash and verify data integrity.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml_gpu_no_memory_limit",
        "pattern": r"(?i)(?:gpu_?memory_?fraction|per_process_gpu_memory_fraction)\s*[:=]\s*1\.0",
        "message": "GPU memory set to 100%. Leave headroom for system stability.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml_numpy_fromfile_untrusted",
        "pattern": r"np\.(?:fromfile|load)\s*\(\s*(?:user|input|request|url)",
        "message": "Loading numpy data from untrusted source. Validate file before loading.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml_eval_metric_exec",
        "pattern": r"(?:custom_metric|metric_fn)\s*[:=]\s*(?:eval|exec|compile)\s*\(",
        "message": "Dynamic code execution for metrics. Use predefined metric functions.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml_no_output_clipping",
        "pattern": r"model\.predict\s*\([^)]*\)(?!.*(?:clip|clamp|bound|limit))",
        "message": "Model output without clipping/bounds. Add output validation.",
        "severity": Severity.INFO,
    },
    {
        "id": "ml_wandb_api_key_hardcoded",
        "pattern": r"(?i)wandb_?api_?key\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        "message": "WandB API key hardcoded. Use WANDB_API_KEY environment variable.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml_huggingface_trust_remote",
        "pattern": r"trust_remote_code\s*[:=]\s*True",
        "message": "HuggingFace trust_remote_code=True allows arbitrary code execution. Review model source.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml_no_data_sanitization",
        "pattern": r"(?:DataFrame|dataset)\s*[:=].*(?:user_upload|file_upload|request\.files)",
        "message": "User-uploaded data used directly. Sanitize and validate before processing.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SERVERLESS SECURITY (rules 1059-1070)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "lambda_secret_env_plaintext",
        "pattern": r"(?i)(?:lambda|function).*(?:environment|env).*(?:secret|password|token|api_key)\s*[:=]\s*[\"']",
        "message": "Secret in Lambda environment plaintext. Use AWS Secrets Manager or SSM.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "lambda_no_auth",
        "pattern": r"(?i)(?:function_?url_?auth|auth_?type)\s*[:=]\s*[\"']?(?:NONE|none)[\"']?",
        "message": "Lambda function URL without authentication. Set auth type to AWS_IAM.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "lambda_wildcard_iam",
        "pattern": r"(?:Action|Resource)\s*[:=]\s*[\"']\*[\"']",
        "message": "Wildcard IAM permission. Apply least-privilege principle.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "lambda_timeout_too_high",
        "pattern": r"(?i)timeout\s*[:=]\s*(?:900|[5-9]\d{2})",
        "message": "Lambda timeout too high. Keep timeout minimal for cost and security.",
        "severity": Severity.WARN,
    },
    {
        "id": "lambda_no_vpc",
        "pattern": r"(?i)vpc_?config\s*[:=]\s*(?:None|null|\{\s*\})",
        "message": "Lambda without VPC configuration. Attach to VPC for private resource access.",
        "severity": Severity.INFO,
    },
    {
        "id": "serverless_cors_wildcard",
        "pattern": r"(?i)(?:cors|allowed_?origins?)\s*[:=]\s*[\"']\*[\"']",
        "message": "CORS wildcard in serverless function. Restrict to specific origins.",
        "severity": Severity.WARN,
    },
    {
        "id": "lambda_reserved_concurrency_zero",
        "pattern": r"(?i)reserved_?concurrent_?executions?\s*[:=]\s*0",
        "message": "Lambda reserved concurrency set to 0 disables the function. Use a positive value.",
        "severity": Severity.WARN,
    },
    {
        "id": "lambda_tmp_sensitive_data",
        "pattern": r"/tmp/.*(?:secret|key|password|token|credentials)",
        "message": "Sensitive data in /tmp. Lambda /tmp is shared across invocations.",
        "severity": Severity.WARN,
    },
    {
        "id": "serverless_no_tracing",
        "pattern": r"(?i)tracing\s*[:=]\s*(?:false|False|None|null|PassThrough)",
        "message": "Serverless tracing disabled. Enable X-Ray or equivalent for observability.",
        "severity": Severity.INFO,
    },
    {
        "id": "lambda_layer_untrusted",
        "pattern": r"(?i)layer.*arn:aws:lambda.*:layer:[^:]*(?:public|shared|community)",
        "message": "Untrusted Lambda layer reference. Verify layer source and pin version.",
        "severity": Severity.WARN,
    },
    {
        "id": "serverless_no_dlq",
        "pattern": r"(?i)dead_?letter_?(?:queue|config)\s*[:=]\s*(?:None|null|\{\s*\})",
        "message": "Serverless function without dead letter queue. Add DLQ for failed invocations.",
        "severity": Severity.INFO,
    },
    {
        "id": "lambda_env_dump",
        "pattern": r"(?:os\.environ|process\.env)(?:\s*$|\s*\))",
        "message": "Dumping entire environment. Access only specific variables.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  REDIS / CACHE POISONING (rules 1071-1080)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "redis_no_auth",
        "pattern": r"Redis\s*\(\s*[\"'](?:localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "message": "Redis connection without authentication. Use password and TLS.",
        "severity": Severity.WARN,
    },
    {
        "id": "redis_flushall",
        "pattern": r"\.flushall\s*\(",
        "message": "redis FLUSHALL deletes all data. Use targeted deletion.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "redis_debug_command",
        "pattern": r"(?:redis|cache|r_conn|rdb)\s*\.\s*(?:debug|config_set)\s*\(",
        "message": "Redis debug/config command in application code. Remove before production.",
        "severity": Severity.WARN,
    },
    {
        "id": "redis_keys_pattern",
        "pattern": r"\.keys\s*\(\s*[\"']\*[\"']\s*\)",
        "message": "Redis KEYS * is O(n) and blocks. Use SCAN for iteration.",
        "severity": Severity.WARN,
    },
    {
        "id": "redis_no_ttl",
        "pattern": r"(?:redis|cache|r)\s*\.set\s*\([^)]*\)(?!.*(?:ex=|px=|ttl|expire|EX|PX))",
        "message": "Redis SET without TTL. Set expiration to prevent memory leaks.",
        "severity": Severity.INFO,
    },
    {
        "id": "cache_user_input_key",
        "pattern": r"cache\.(?:get|set|delete)\s*\(\s*(?:f[\"']|.*(?:request|user_input|params))",
        "message": "Cache key from user input. Sanitize to prevent cache poisoning.",
        "severity": Severity.WARN,
    },
    {
        "id": "redis_eval_script",
        "pattern": r"\.eval\s*\(\s*(?:f[\"']|.*\.format\(|.*user|.*input|.*request)",
        "message": "Redis EVAL with dynamic script. Use registered Lua scripts.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "redis_no_tls",
        "pattern": r"(?i)redis://(?!.*ssl|.*tls)",
        "message": "Redis connection without TLS. Use rediss:// or ssl=True.",
        "severity": Severity.WARN,
    },
    {
        "id": "cache_sensitive_data",
        "pattern": r"cache\.set\s*\([^)]*(?:password|secret|token|ssn|credit_card)",
        "message": "Sensitive data in cache. Encrypt before caching or avoid caching secrets.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "redis_unbounded_list",
        "pattern": r"\.(?:lpush|rpush)\s*\([^)]*\)(?!.*(?:ltrim|maxlen|limit))",
        "message": "Redis list push without trim. Use LTRIM to bound list size.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  WEBSOCKET SECURITY (rules 1081-1090)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ws_no_origin_check",
        "pattern": r"(?i)(?:check_?origin|verify_?origin|allowed_?origins)\s*[:=]\s*(?:false|False|\[\s*\]|\*|None|null)",
        "message": "WebSocket without origin validation. Verify origin to prevent CSWSH.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ws_no_message_size_limit",
        "pattern": r"(?i)(?:max_?(?:message_?)?size|max_?frame_?size)\s*[:=]\s*(?:0|None|null|Infinity)",
        "message": "WebSocket without message size limit. Set max to prevent DoS.",
        "severity": Severity.WARN,
    },
    {
        "id": "ws_no_auth",
        "pattern": r"(?:WebSocket|ws)\s*\([^)]*\)(?!.*(?:auth|token|verify|authenticate))",
        "message": "WebSocket connection without authentication. Verify tokens on connect.",
        "severity": Severity.WARN,
    },
    {
        "id": "ws_no_rate_limit",
        "pattern": r"(?:on_?message|onmessage).*(?!.*(?:rate_limit|throttle|debounce))",
        "message": "WebSocket message handler without rate limiting. Throttle incoming messages.",
        "severity": Severity.INFO,
    },
    {
        "id": "ws_eval_message",
        "pattern": r"(?:on_?message|onmessage)[^}]*(?:eval|exec|Function)\s*\(",
        "message": "WebSocket message handler uses eval/exec. Parse messages safely.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ws_no_ping_pong",
        "pattern": r"(?i)(?:ping_?interval|ping_?timeout)\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "WebSocket ping/pong disabled. Enable for connection health checking.",
        "severity": Severity.INFO,
    },
    {
        "id": "ws_broadcast_no_filter",
        "pattern": r"(?:broadcast|send_?all|emit_?all)\s*\([^)]*\)(?!.*(?:filter|room|channel|group))",
        "message": "WebSocket broadcasting to all clients. Filter by room/channel.",
        "severity": Severity.WARN,
    },
    {
        "id": "ws_plaintext_sensitive",
        "pattern": r"(?:ws\.send|socket\.send)\s*\([^)]*(?:password|secret|token|api_key)",
        "message": "Sending sensitive data over WebSocket. Encrypt or use WSS.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ws_no_close_handler",
        "pattern": r"(?:WebSocket|ws).*(?:on_?open|onopen)(?!.*(?:on_?close|onclose))",
        "message": "WebSocket open handler without close handler. Always handle disconnection.",
        "severity": Severity.INFO,
    },
    {
        "id": "ws_unvalidated_json",
        "pattern": r"JSON\.parse\s*\(\s*(?:message|data|event\.data)\s*\)(?!.*(?:try|catch|validate|schema))",
        "message": "Parsing WebSocket JSON without validation. Validate against schema.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  OAUTH / OIDC MISCONFIG (rules 1091-1102)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "oauth_implicit_flow",
        "pattern": r"(?i)(?:response_?type|grant_?type)\s*[:=]\s*[\"'](?:token|implicit)[\"']",
        "message": "OAuth implicit flow is deprecated. Use authorization code with PKCE.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth_no_state_param",
        "pattern": r"(?i)authorize\s*\([^)]*\)(?!.*state)",
        "message": "OAuth authorize without state parameter. Add state to prevent CSRF.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth_no_pkce",
        "pattern": r"(?i)(?:grant_?type|response_?type)\s*[:=]\s*[\"'](?:authorization_?code|code)[\"'](?!.*(?:pkce|code_?challenge|code_?verifier))",
        "message": "OAuth authorization code without PKCE. Add code_challenge for security.",
        "severity": Severity.WARN,
    },
    {
        "id": "oauth_token_in_url",
        "pattern": r"(?i)(?:access_?token|bearer)\s*[:=].*(?:query|params|url|href)",
        "message": "OAuth token in URL query parameter. Use Authorization header.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oidc_no_nonce",
        "pattern": r"(?i)(?:openid|oidc).*(?:authorize|auth_url)(?!.*nonce)",
        "message": "OIDC authorization without nonce. Add nonce to prevent replay attacks.",
        "severity": Severity.WARN,
    },
    {
        "id": "oauth_no_token_expiry",
        "pattern": r"(?i)(?:token_?expiry|expires_?in|token_?lifetime)\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "OAuth token without expiry. Set a reasonable token lifetime.",
        "severity": Severity.WARN,
    },
    {
        "id": "oauth_hardcoded_client_secret",
        "pattern": r"(?i)client_?secret\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        "message": "Hardcoded OAuth client secret. Use environment variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth_wildcard_redirect",
        "pattern": r"(?i)redirect_?uri\s*[:=]\s*[\"']\*",
        "message": "Wildcard redirect URI. Specify exact allowed redirect URIs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth_no_scope_validation",
        "pattern": r"(?i)scope\s*[:=]\s*[\"'][\*\s]*[\"']",
        "message": "OAuth scope wildcard. Request minimum required scopes.",
        "severity": Severity.WARN,
    },
    {
        "id": "oidc_no_issuer_validation",
        "pattern": r"(?i)(?:validate_?issuer|verify_?issuer|issuer_?validation)\s*[:=]\s*(?:false|False|0)",
        "message": "OIDC issuer validation disabled. Always validate token issuer.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth_refresh_token_no_rotation",
        "pattern": r"(?i)(?:rotate_?refresh|refresh_?token_?rotation)\s*[:=]\s*(?:false|False|0|None|null)",
        "message": "Refresh token rotation disabled. Enable to limit token reuse.",
        "severity": Severity.WARN,
    },
    {
        "id": "oidc_skip_audience_check",
        "pattern": r"(?i)(?:validate_?audience|verify_?aud(?:ience)?)\s*[:=]\s*(?:false|False|0)",
        "message": "OIDC audience validation disabled. Always verify token audience.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CSP / SECURITY HEADERS (rules 1103-1112)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "csp_unsafe_inline",
        "pattern": r"(?i)(?:Content-Security-Policy|csp).*unsafe-inline",
        "message": "CSP allows unsafe-inline. Use nonces or hashes instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "csp_unsafe_eval",
        "pattern": r"(?i)(?:Content-Security-Policy|csp).*unsafe-eval",
        "message": "CSP allows unsafe-eval. Remove to prevent XSS via eval.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "csp_wildcard_source",
        "pattern": r"(?i)Content-Security-Policy.*(?:script-src|default-src)\s+\*",
        "message": "CSP with wildcard source. Restrict to specific domains.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "no_x_frame_options",
        "pattern": r"(?i)X-Frame-Options\s*[:=]\s*[\"']?(?:ALLOWALL|allow)",
        "message": "X-Frame-Options allows framing. Set to DENY or SAMEORIGIN.",
        "severity": Severity.WARN,
    },
    {
        "id": "hsts_disabled",
        "pattern": r"(?i)Strict-Transport-Security.*max-age\s*[:=]\s*0",
        "message": "HSTS max-age set to 0 disables HSTS. Use a long max-age.",
        "severity": Severity.WARN,
    },
    {
        "id": "no_xss_protection",
        "pattern": r"(?i)X-XSS-Protection\s*[:=]\s*[\"']?0[\"']?",
        "message": "XSS protection header disabled. Enable X-XSS-Protection.",
        "severity": Severity.INFO,
    },
    {
        "id": "referrer_policy_unsafe",
        "pattern": r"(?i)Referrer-Policy\s*[:=]\s*[\"']?(?:unsafe-url|no-referrer-when-downgrade)[\"']?",
        "message": "Unsafe Referrer-Policy. Use strict-origin-when-cross-origin.",
        "severity": Severity.WARN,
    },
    {
        "id": "permissions_policy_all",
        "pattern": r"(?i)Permissions-Policy.*(?:camera|microphone|geolocation)\s*[:=]\s*\*",
        "message": "Permissions-Policy grants all origins. Restrict to self.",
        "severity": Severity.WARN,
    },
    {
        "id": "csp_report_only_prod",
        "pattern": r"(?i)Content-Security-Policy-Report-Only",
        "message": "CSP in report-only mode. Switch to enforcement in production.",
        "severity": Severity.INFO,
    },
    {
        "id": "no_content_type_nosniff",
        "pattern": r"(?i)X-Content-Type-Options\s*[:=]\s*[\"']?(?:none|false)[\"']?",
        "message": "X-Content-Type-Options nosniff disabled. Enable to prevent MIME sniffing.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  MOBILE SECURITY — ANDROID / iOS (rules 1113-1124)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "android_allow_backup",
        "pattern": r"android:allowBackup\s*=\s*[\"']true[\"']",
        "message": "Android allowBackup exposes app data. Set to false.",
        "severity": Severity.WARN,
        "file_types": [".xml"],
    },
    {
        "id": "android_debuggable",
        "pattern": r"android:debuggable\s*=\s*[\"']true[\"']",
        "message": "Android app debuggable in manifest. Disable for release builds.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "android_webview_file_access",
        "pattern": r"setAllowFileAccess\s*\(\s*true\s*\)",
        "message": "WebView file access enabled. Restrict file access in WebViews.",
        "severity": Severity.WARN,
        "file_types": [".java", ".kt"],
    },
    {
        "id": "ios_ats_arbitrary_loads",
        "pattern": r"NSAllowsArbitraryLoads.*true",
        "message": "iOS App Transport Security disabled. Enable ATS for HTTPS enforcement.",
        "severity": Severity.BLOCK,
        "file_types": [".plist"],
    },
    {
        "id": "ios_keychain_accessible_always",
        "pattern": r"kSecAttrAccessibleAlways",
        "message": "Keychain item accessible always. Use kSecAttrAccessibleWhenUnlocked.",
        "severity": Severity.WARN,
        "file_types": [".swift", ".m"],
    },
    {
        "id": "ios_insecure_random",
        "pattern": r"\barc4random\s*\(",
        "message": "arc4random is not cryptographically secure on all platforms. Use SecRandomCopyBytes.",
        "severity": Severity.INFO,
        "file_types": [".swift", ".m"],
    },
    {
        "id": "mobile_hardcoded_api_url",
        "pattern": r"(?i)(?:base_?url|api_?url|endpoint)\s*[:=]\s*[\"']http://(?!localhost|127\.0\.0\.1)",
        "message": "Hardcoded HTTP URL in mobile app. Use HTTPS and configuration.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "android_prefs_secret_storage",
        "pattern": r"getSharedPreferences\s*\([^)]*\).*(?:put(?:String|Int|Boolean))\s*\([^)]*(?:password|token|secret|key)",
        "message": "Sensitive data in SharedPreferences. Use EncryptedSharedPreferences.",
        "severity": Severity.BLOCK,
        "file_types": [".java", ".kt"],
    },
    {
        "id": "ios_nsuserdefaults_sensitive",
        "pattern": r"UserDefaults.*(?:set|setValue).*(?:password|token|secret|key)",
        "message": "Sensitive data in NSUserDefaults. Use Keychain instead.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  LOGGING SENSITIVE DATA / PII (rules 1125-1134)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "log_password",
        "pattern": r"(?:log(?:ger)?|console|print|puts|fmt\.Print)\s*[\(\.].*(?:password|passwd|pwd)\s*[:=,\)]",
        "message": "Password logged. Never log credentials.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "log_credit_card",
        "pattern": r"(?:log(?:ger)?|console|print|puts|fmt\.Print).*(?:credit_?card|card_?number|ccn|pan)\b",
        "message": "Credit card number in logs. Mask or omit PCI data.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "log_ssn",
        "pattern": r"(?:log(?:ger)?|console|print|puts|fmt\.Print).*\bssn\b",
        "message": "SSN in logs. Never log personally identifiable information.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "log_bearer_token",
        "pattern": r"(?:log(?:ger)?|console|print|puts|fmt\.Print)\s*[\(\.].*(?:bearer|access_?token|refresh_?token)(?!_url)",
        "message": "Auth token in logs. Redact tokens before logging.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "log_email_address",
        "pattern": r"(?:log(?:ger)?|console|print).*(?:email|e_?mail).*@",
        "message": "Email address in logs. Hash or redact PII.",
        "severity": Severity.WARN,
    },
    {
        "id": "log_ip_address",
        "pattern": r"(?:log(?:ger)?|console|print).*\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "message": "IP address in logs. Consider privacy implications (GDPR).",
        "severity": Severity.INFO,
    },
    {
        "id": "log_full_request",
        "pattern": r"(?:log(?:ger)?|console|print).*(?:request\.body|req\.body|request\.data)",
        "message": "Full request body logged. Sanitize sensitive fields first.",
        "severity": Severity.WARN,
    },
    {
        "id": "log_full_response",
        "pattern": r"(?:log(?:ger)?|console|print).*(?:response\.body|res\.body|response\.data|response\.text)",
        "message": "Full response body logged. May contain sensitive data.",
        "severity": Severity.INFO,
    },
    {
        "id": "log_stack_trace_prod",
        "pattern": r"(?:traceback\.print_exc|stackTrace|printStackTrace)\s*\(",
        "message": "Stack trace printed. Use structured logging with error details.",
        "severity": Severity.WARN,
    },
    {
        "id": "log_env_vars",
        "pattern": r"(?:log(?:ger)?|console|print).*(?:os\.environ|process\.env|ENV\[)",
        "message": "Environment variables in logs. May contain secrets.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  RACE CONDITIONS / TOCTOU (rules 1135-1144)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "toctou_file_exists",
        "pattern": r"(?:os\.path\.exists|Path.*exists)\s*\([^)]+\).*(?:open|read|write|unlink|remove)",
        "message": "TOCTOU: file existence check then use. Use try/except instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "toctou_isfile",
        "pattern": r"(?:os\.path\.isfile|os\.path\.isdir)\s*\([^)]+\).*(?:open|shutil|os\.)",
        "message": "TOCTOU: file type check then operation. Use atomic operations.",
        "severity": Severity.WARN,
    },
    {
        "id": "race_check_then_act",
        "pattern": r"if\s+.*\.(?:count|size|length|empty)\s*[!=<>]+.*\n\s*.*\.(?:remove|delete|pop|dequeue)",
        "message": "Check-then-act pattern. Use atomic operations or locks.",
        "severity": Severity.WARN,
    },
    {
        "id": "race_singleton_no_lock",
        "pattern": r"(?:_instance|_singleton)\s*(?:is None|==\s*None).*\n\s*(?:_instance|_singleton)\s*=",
        "message": "Singleton without thread lock. Use threading.Lock or module-level init.",
        "severity": Severity.WARN,
    },
    {
        "id": "race_global_mutable",
        "pattern": r"^(?:global_?(?:state|data|config|cache)|_shared_(?:state|data))\s*[:=]\s*(?:\{|\[|dict\(|list\()",
        "message": "Global mutable state without synchronization. Use thread-safe structures.",
        "severity": Severity.WARN,
    },
    {
        "id": "toctou_mkdir_exists",
        "pattern": r"(?:os\.path\.exists|not.*exists)\s*\([^)]+\).*\n\s*os\.makedirs?\s*\(",
        "message": "TOCTOU: check then mkdir. Use os.makedirs(exist_ok=True).",
        "severity": Severity.WARN,
    },
    {
        "id": "race_counter_no_atomic",
        "pattern": r"\b(?:count|counter|total)\s*(?:\+=|-=)\s*\d+(?!.*(?:lock|atomic|Lock|Atomic))",
        "message": "Non-atomic counter increment. Use threading.Lock or atomic operations.",
        "severity": Severity.INFO,
    },
    {
        "id": "race_lazy_init",
        "pattern": r"if\s+(?:cls\._|self\._)\w+\s+is\s+None\s*:.*\n\s*(?:cls\._|self\._)\w+\s*=",
        "message": "Lazy initialization without lock. Add threading lock for thread safety.",
        "severity": Severity.WARN,
    },
    {
        "id": "race_file_lock_missing",
        "pattern": r"open\s*\([^)]*[\"'](?:w|a)[\"'][^)]*\)(?!.*(?:flock|lockf|FileLock))",
        "message": "File write without lock. Use file locking for concurrent access.",
        "severity": Severity.INFO,
    },
    {
        "id": "toctou_access_check",
        "pattern": r"os\.access\s*\([^)]+\).*\n\s*(?:open|os\.)",
        "message": "TOCTOU: os.access check then use. Use try/except with the operation.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CRYPTOGRAPHIC ANTI-PATTERNS (rules 1145-1158)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "crypto_md5",
        "pattern": r"(?:hashlib\.md5|MD5\.new|createHash\s*\(\s*[\"']md5[\"']\))",
        "message": "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_sha1",
        "pattern": r"(?:hashlib\.sha1|SHA1\.new|createHash\s*\(\s*[\"']sha1[\"']\))",
        "message": "SHA-1 is deprecated. Use SHA-256 or SHA-3.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto_des",
        "pattern": r"(?i)\b(?:DES|3DES|TripleDES|DESede)\b.*(?:encrypt|decrypt|cipher)",
        "message": "DES/3DES is deprecated. Use AES-256-GCM.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_ecb_insecure",
        "pattern": r"(?i)(?:ECB|MODE_ECB|AES\.MODE_ECB|mode\s*[:=]\s*[\"']ecb[\"'])",
        "message": "ECB mode does not provide semantic security. Use GCM or CBC with HMAC.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_static_iv_nonce",
        "pattern": r"(?i)(?:iv|nonce|initialization_?vector)\s*[:=]\s*(?:b[\"']|[\"']\\x|bytes\s*\()",
        "message": "Hardcoded IV/nonce. Generate a random IV for each encryption.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_hardcoded_key",
        "pattern": r"(?i)(?:encryption_?key|aes_?key|cipher_?key)\s*[:=]\s*(?:b[\"']|[\"'])",
        "message": "Hardcoded encryption key. Use key derivation and secure key storage.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_weak_rsa",
        "pattern": r"(?i)(?:rsa.*(?:key_?size|bits)\s*[:=]\s*(?:512|1024|768))|(?:generate\s*\(\s*(?:512|1024|768)\s*\))",
        "message": "RSA key size below 2048 bits. Use 2048+ for RSA or switch to Ed25519.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_rc4",
        "pattern": r"(?i)\bRC4\b.*(?:encrypt|cipher|new)",
        "message": "RC4 is broken. Use AES-256-GCM.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_random_not_secure",
        "pattern": r"\brandom\.(?:random|randint|choice|randrange|uniform)\s*\(.*(?:token|key|secret|password|salt|nonce|iv)",
        "message": "Non-cryptographic random for security use. Use secrets module.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_no_padding",
        "pattern": r"(?i)(?:padding\s*[:=]\s*(?:None|null|false|False|0)|no_?padding)",
        "message": "Encryption without padding. Use proper padding scheme (OAEP, PKCS7).",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto_compare_timing",
        "pattern": r"(?:==|!=)\s*.*(?:hmac|digest|signature|hash|mac)(?!.*(?:compare_digest|constant_time|timingSafeEqual))",
        "message": "Non-constant-time comparison for cryptographic value. Use hmac.compare_digest.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto_low_pbkdf2_iterations",
        "pattern": r"(?i)(?:iterations|rounds)\s*[:=]\s*(?:[1-9]\d{0,3}|[1-4]\d{4})(?!\d)",
        "message": "PBKDF2 iterations below 50000. Use at least 600000 for passwords.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto_static_salt",
        "pattern": r"(?i)salt\s*[:=]\s*(?:b[\"']|[\"'][^\"']+[\"'])",
        "message": "Static/hardcoded salt. Generate unique salt per password.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_jwt_none_alg",
        "pattern": r"(?i)(?:algorithm|alg)\s*[:=]\s*[\"'](?:none|None)[\"']",
        "message": "JWT 'none' algorithm allows token forgery. Use RS256 or ES256.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  REDOS / REGEX DENIAL OF SERVICE (rules 1159-1166)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "redos_nested_quantifier",
        "pattern": r"re\.compile\s*\([^)]*\([^)]*[\+\*]\)\s*[\+\*]",
        "message": "Nested quantifiers in regex (e.g. (a+)+). Potential ReDoS vulnerability.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "redos_overlapping_alternation",
        "pattern": r"re\.compile\s*\([^)]*\.\*.*\|.*\.\*",
        "message": "Overlapping alternation with wildcards. Potential ReDoS.",
        "severity": Severity.WARN,
    },
    {
        "id": "regex_user_input",
        "pattern": r"re\.(?:compile|match|search|findall|sub)\s*\(\s*(?:user|input|request|params)",
        "message": "Regex from user input. Use re.escape or set timeout.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "redos_backreference_quantifier",
        "pattern": r"re\.compile\s*\([^)]*\\[1-9][^)]*[\+\*]",
        "message": "Backreference with quantifier. Potential ReDoS vulnerability.",
        "severity": Severity.WARN,
    },
    {
        "id": "regex_no_timeout",
        "pattern": r"re\.(?:match|search|findall|sub)\s*\([^)]*\)(?!.*(?:timeout|TIMEOUT|time_limit))",
        "message": "Regex without timeout on untrusted input. Use regex timeout.",
        "severity": Severity.INFO,
    },
    {
        "id": "redos_catastrophic_pattern",
        "pattern": r"re\.compile\s*\([^)]*\([^)]*\.\+\)[^)]*\+",
        "message": "Catastrophic backtracking pattern detected. Simplify regex.",
        "severity": Severity.WARN,
    },
    {
        "id": "redos_star_star",
        "pattern": r"re\.compile\s*\([^)]*\.\*\.\*",
        "message": "Multiple unbounded wildcards in regex. Potential ReDoS.",
        "severity": Severity.WARN,
    },
    {
        "id": "regex_multiline_user",
        "pattern": r"re\.(?:DOTALL|MULTILINE|S|M).*(?:user|input|request)",
        "message": "Multiline regex on user input. Validate input length first.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  TEMPLATE INJECTION (rules 1167-1176)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ssti_jinja2_user_input",
        "pattern": r"(?:Template|Environment).*(?:from_string|render_template_string)\s*\(\s*(?:user|input|request|body)",
        "message": "Jinja2 template from user input. Server-Side Template Injection risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssti_jinja2_autoescape_off",
        "pattern": r"(?:Environment|Jinja2).*autoescape\s*[:=]\s*(?:false|False|0)",
        "message": "Jinja2 autoescape disabled. Enable to prevent XSS.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssti_handlebars_noesc",
        "pattern": r"\{\{\{[^}]+\}\}\}",
        "message": "Handlebars triple-braces bypass escaping. Use double-braces.",
        "severity": Severity.WARN,
        "file_types": [".hbs", ".handlebars"],
    },
    {
        "id": "ssti_mako_user",
        "pattern": r"Template\s*\(\s*(?:user|input|request)",
        "message": "Mako template from user input. Template injection risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssti_pug_unescaped",
        "pattern": r"!\s*\{[^}]+\}",
        "message": "Pug/Jade unescaped output. Use escaped interpolation.",
        "severity": Severity.WARN,
        "file_types": [".pug", ".jade"],
    },
    {
        "id": "ssti_ejs_user",
        "pattern": r"ejs\.render\s*\(\s*(?:user|input|req|request)",
        "message": "EJS template from user input. Template injection risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssti_freemarker",
        "pattern": r"(?:freemarker|ftl).*(?:assign|setting).*(?:user|input|request)",
        "message": "FreeMarker template with user input. Template injection risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssti_nunjucks_user",
        "pattern": r"nunjucks\.renderString\s*\(\s*(?:user|input|req|request)",
        "message": "Nunjucks template from user input. Template injection risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssti_twig_raw",
        "pattern": r"\{\%\s*raw\s*\%\}",
        "message": "Twig raw block disables escaping. Validate output.",
        "severity": Severity.WARN,
        "file_types": [".twig"],
    },
    {
        "id": "ssti_velocity_user",
        "pattern": r"(?:Velocity|VelocityEngine).*merge.*(?:user|input|request)",
        "message": "Velocity template with user input. Template injection risk.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DESERIALIZATION ATTACKS (rules 1177-1186)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "deser_java_objectinputstream",
        "pattern": r"ObjectInputStream\s*\(\s*(?!.*(?:whitelist|filter|ObjectInputFilter))",
        "message": "Java ObjectInputStream without filter. Use ObjectInputFilter.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "deser_java_xmldecoder",
        "pattern": r"XMLDecoder\s*\(",
        "message": "Java XMLDecoder is unsafe. Use safe XML parsing.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "deser_dotnet_binaryformatter",
        "pattern": r"BinaryFormatter\s*\(",
        "message": ".NET BinaryFormatter is insecure. Use System.Text.Json.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "deser_php_unserialize",
        "pattern": r"\bunserialize\s*\(\s*\$(?:_GET|_POST|_REQUEST|_COOKIE|input)",
        "message": "PHP unserialize on user input. Object injection vulnerability.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "deser_yaml_load_unsafe",
        "pattern": r"yaml\.load\s*\([^)]*\)(?!.*Loader\s*[:=]\s*(?:yaml\.)?SafeLoader)",
        "message": "yaml.load without SafeLoader. Use yaml.safe_load.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "deser_ruby_marshal",
        "pattern": r"Marshal\.load\s*\(\s*(?:params|request|input|user)",
        "message": "Ruby Marshal.load on user input. Deserialization attack risk.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "deser_python_shelve",
        "pattern": r"shelve\.open\s*\(\s*(?:user|input|request)",
        "message": "shelve.open on user input. Uses pickle internally.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "deser_java_snakeyaml",
        "pattern": r"new\s+Yaml\s*\(\s*\)\.load\s*\(",
        "message": "SnakeYAML default Yaml().load allows arbitrary types. Use SafeConstructor.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "deser_dotnet_jsonnet_typenamehandling",
        "pattern": r"TypeNameHandling\s*[:=]\s*(?:All|Auto|Objects|Arrays)",
        "message": ".NET Json.NET TypeNameHandling enables type injection. Use None.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "deser_msgpack_raw",
        "pattern": r"msgpack\.unpack(?:b)?\s*\(\s*(?:user|input|request|body)",
        "message": "msgpack deserialization of user input. Validate schema first.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SSRF PATTERNS (rules 1187-1194)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "ssrf_user_url",
        "pattern": r"(?:requests\.get|httpx\.get|urllib\.request\.urlopen|fetch)\s*\(\s*(?:user|input|request|params)",
        "message": "HTTP request with user-supplied URL. SSRF risk. Validate and allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssrf_redirect_follow",
        "pattern": r"(?i)(?:allow_?redirects|follow_?redirects|max_?redirects)\s*[:=]\s*(?:true|True|[5-9]\d*|\d{2,})",
        "message": "Following redirects on user URL may bypass SSRF protections.",
        "severity": Severity.WARN,
    },
    {
        "id": "ssrf_dns_rebinding",
        "pattern": r"(?:requests|httpx|urllib).*(?:user|input|request)(?!.*(?:dns_?resolver|ip_?check|validate_?url))",
        "message": "Outbound request without DNS rebinding protection. Pin resolved IP.",
        "severity": Severity.INFO,
    },
    {
        "id": "ssrf_internal_ip",
        "pattern": r"(?:requests|httpx|fetch|urllib).*(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.0\.0\.0|localhost|metadata\.google|169\.254)",
        "message": "Request to internal/cloud metadata IP. Block internal network access.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssrf_file_protocol",
        "pattern": r"(?:requests|httpx|urllib|fetch).*[\"']file://",
        "message": "File protocol in HTTP library. Block file:// URLs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssrf_gopher_protocol",
        "pattern": r"(?:requests|httpx|urllib|fetch).*[\"']gopher://",
        "message": "Gopher protocol can bypass SSRF protections. Block gopher:// URLs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ssrf_no_timeout",
        "pattern": r"(?:requests|httpx|urllib)\.(?:get|post|put|delete|request)\s*\([^)]*\)(?!.*timeout)",
        "message": "Outbound HTTP request without timeout. Set timeout to prevent hanging.",
        "severity": Severity.WARN,
    },
    {
        "id": "ssrf_image_url",
        "pattern": r"(?:Image\.open|imageio\.imread|cv2\.imread)\s*\(\s*(?:urllib|requests|httpx|fetch|url|user|input)",
        "message": "Image loaded from URL. Validate URL to prevent SSRF.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  PATH TRAVERSAL (rules 1195-1200)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "path_traversal_dotdot",
        "pattern": r"(?:open|read|write|os\.path\.join)\s*\([^)]*(?:user|input|request|params|query)[^)]*\)(?!.*(?:realpath|abspath|secure_filename|sanitize))",
        "message": "User input in file path without sanitization. Path traversal risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "path_traversal_no_realpath",
        "pattern": r"os\.path\.join\s*\([^)]*(?:\.\.|\.\./)",
        "message": "Relative path with .. in os.path.join. Use os.path.realpath.",
        "severity": Severity.WARN,
    },
    {
        "id": "path_send_file_user",
        "pattern": r"send_file\s*\(\s*(?:user|input|request|params|os\.path\.join\s*\([^)]*(?:user|input|request))",
        "message": "send_file with user input. Validate path against base directory.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "path_static_file_user",
        "pattern": r"(?:static_?file|serve_?file|sendFile)\s*\(\s*(?:user|input|req|request|params)",
        "message": "Serving static file from user input. Restrict to safe directory.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "path_zipslip",
        "pattern": r"(?:extractall|extract)\s*\([^)]*\)(?!.*(?:sanitize|realpath|abspath|is_within|check_path))",
        "message": "Archive extraction without path validation. Zip Slip vulnerability.",
        "severity": Severity.WARN,
    },
    {
        "id": "path_symlink_follow",
        "pattern": r"os\.(?:readlink|stat)\s*\([^)]*(?:user|input|request)",
        "message": "Following symlinks from user input. Validate target path.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  XXE / XML (rules 1201-1202)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "xxe_etree_parse",
        "pattern": r"(?:etree|ElementTree|xml\.dom|minidom|pulldom|sax)\.parse\s*\(\s*(?:user|input|request|body|file)",
        "message": "XML parsing of user input without disabling external entities. XXE risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "xxe_resolve_entities",
        "pattern": r"(?i)(?:resolve_?entities|load_?external_?dtd|external_?general_?entities)\s*[:=]\s*(?:true|True|1)",
        "message": "XML external entity resolution enabled. Disable to prevent XXE.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  HTTP RESPONSE SPLITTING (rules 1203-1210)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "http_response_splitting",
        "pattern": r"(?:setHeader|set_header|add_header|writeHead)\s*\([^)]*(?:user|input|request|params|query)",
        "message": "User input in HTTP header. Response splitting/CRLF injection risk.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "http_header_crlf",
        "pattern": r"(?:setHeader|set_header|add_header).*(?:\\r\\n|\\x0d\\x0a|\r\n)",
        "message": "CRLF characters in header value. Sanitize to prevent response splitting.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "http_redirect_user_url",
        "pattern": r"(?:redirect|Location)\s*[:=]\s*(?:user|input|request|params|query|req\.query)",
        "message": "Open redirect from user input. Validate redirect URL against allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "http_set_cookie_no_flags",
        "pattern": r"Set-Cookie\s*[:=].*(?!.*(?:Secure|HttpOnly|SameSite))",
        "message": "Cookie without security flags. Add Secure, HttpOnly, SameSite.",
        "severity": Severity.WARN,
    },
    {
        "id": "http_cors_credentials_wildcard",
        "pattern": r"(?i)Access-Control-Allow-Credentials.*true.*Access-Control-Allow-Origin.*\*",
        "message": "CORS credentials with wildcard origin. Specify exact origins.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "http_cache_sensitive",
        "pattern": r"(?i)Cache-Control.*(?:public|max-age=\d{5,}).*(?:auth|session|token|account)",
        "message": "Caching sensitive response. Set Cache-Control: no-store.",
        "severity": Severity.WARN,
    },
    {
        "id": "http_etag_sensitive",
        "pattern": r"(?i)ETag.*(?:inode|mtime)",
        "message": "ETag leaks server info. Use content-based ETags.",
        "severity": Severity.INFO,
    },
    {
        "id": "http_server_header_leak",
        "pattern": r"(?i)(?:Server|X-Powered-By)\s*[:=]\s*[\"'](?:Apache|nginx|Express|IIS|Kestrel|Tomcat)",
        "message": "Server header reveals technology stack. Remove or obfuscate.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  PROTOTYPE POLLUTION (JS) (rules 1211-1220)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "proto_pollution_merge",
        "pattern": r"(?:merge|extend|assign|deepMerge|defaultsDeep)\s*\([^)]*(?:user|input|request|body|params|query)",
        "message": "Object merge with user input. Prototype pollution risk. Use safe merge.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_pollution_bracket",
        "pattern": r"\w+\[(?:user|input|request|body|params|query|key|prop)\w*\]\s*=",
        "message": "Dynamic property assignment from user input. Prototype pollution risk.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_pollution_constructor",
        "pattern": r"\[(?:[\"']__proto__[\"']|[\"']constructor[\"']|[\"']prototype[\"'])\]",
        "message": "Access to __proto__/constructor/prototype. Sanitize property names.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_lodash_merge",
        "pattern": r"_\.merge\s*\([^)]*(?:req|request|body|params|user)",
        "message": "lodash merge with user input. Use lodash.mergeWith with sanitizer.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_json_parse_reviver",
        "pattern": r"JSON\.parse\s*\(\s*(?:user|input|request|body|req\.body)\s*\)(?!.*reviver)",
        "message": "JSON.parse of user input without reviver. Add key sanitization.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_object_create_null",
        "pattern": r"(?:Object\.create\(null\)|Object\.freeze|Object\.seal)(?!.*merge)",
        "message": "Good: null-prototype object. Verify it covers all user-facing data paths.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_recursive_assign",
        "pattern": r"function\s+\w*(?:merge|assign|extend)\w*\s*\([^)]*\)\s*\{(?!.*(?:hasOwnProperty|__proto__|constructor))",
        "message": "Custom recursive merge without prototype checks. Guard against __proto__.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_set_prototype",
        "pattern": r"Object\.setPrototypeOf\s*\(",
        "message": "Object.setPrototypeOf is slow and dangerous. Use Object.create.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_define_property_user",
        "pattern": r"Object\.defineProperty\s*\([^)]*(?:user|input|request|body)",
        "message": "Object.defineProperty with user-controlled key. Validate property name.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "proto_dot_notation_traverse",
        "pattern": r"(?:get|set|has)\s*\(\s*(?:obj|target|source)[^)]*,\s*(?:path|key|prop)\s*\)(?!.*(?:sanitize|validate|hasOwnProperty))",
        "message": "Dynamic object traversal without sanitization. Block __proto__ paths.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  SUPPLY CHAIN SECURITY (rules 1221-1232)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "supply_install_script",
        "pattern": r"(?i)[\"'](?:preinstall|postinstall|preuninstall|postuninstall)[\"']\s*:",
        "message": "npm lifecycle script detected. Review for supply chain attacks.",
        "severity": Severity.WARN,
    },
    {
        "id": "supply_curl_pipe_sh",
        "pattern": r"curl\s+[^|]*\|\s*(?:sh|bash|zsh)",
        "message": "Piping curl to shell. Download, verify hash, then execute.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "supply_unpinned_dependency",
        "pattern": r"[\"']\w+[\"']\s*:\s*[\"'](?:\*|latest|>=|>|~>)[\"']",
        "message": "Unpinned dependency version. Pin to exact version.",
        "severity": Severity.WARN,
    },
    {
        "id": "supply_typosquat_lodash",
        "pattern": r"(?:require|import).*[\"'](?:lodahs|lodashs|1odash|lodas|lodahsh)[\"']",
        "message": "Possible typosquat of lodash. Verify package name.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "supply_typosquat_express",
        "pattern": r"(?:require|import).*[\"'](?:expres|expresss|expess|expreess|xpress)[\"']",
        "message": "Possible typosquat of express. Verify package name.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "supply_typosquat_requests",
        "pattern": r"(?:import|from)\s+(?:requets|requsts|reqeusts|requesst|requess)\b",
        "message": "Possible typosquat of requests. Verify package name.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "supply_git_dependency",
        "pattern": r"[\"'](?:git\+https?|git\+ssh|git://).*[\"']",
        "message": "Git URL as dependency. Pin to specific commit hash.",
        "severity": Severity.WARN,
    },
    {
        "id": "supply_http_dependency",
        "pattern": r"[\"']https?://.*\.(?:tar\.gz|tgz|zip|whl)[\"']",
        "message": "HTTP URL as dependency. Use package registry and verify checksum.",
        "severity": Severity.WARN,
    },
    {
        "id": "supply_no_lockfile_ci",
        "pattern": r"npm\s+install(?!\s+--(?:ci|frozen-lockfile))",
        "message": "npm install without --ci in CI context. Use npm ci for reproducible builds.",
        "severity": Severity.INFO,
    },
    {
        "id": "supply_private_registry_http",
        "pattern": r"(?i)registry\s*[:=]\s*[\"']http://(?!localhost|127\.0\.0\.1)",
        "message": "Package registry over HTTP. Use HTTPS for registry access.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "supply_allow_scripts",
        "pattern": r"(?i)(?:ignore-scripts|ignore_scripts)\s*[:=]\s*(?:false|False|0)",
        "message": "Package install scripts enabled. Review or disable with --ignore-scripts.",
        "severity": Severity.INFO,
    },
    {
        "id": "supply_floating_action_version",
        "pattern": r"uses:\s*\w+/\w+@(?:main|master|latest|v\d+)(?!\.\d+\.\d+)",
        "message": "GitHub Action with floating version. Pin to full SHA.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  API VERSIONING ANTI-PATTERNS (rules 1233-1240)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "api_no_version_prefix",
        "pattern": r"(?:app\.route|@router|@app)\s*\(\s*[\"']/(?!v\d|api/v\d)(?:users|products|orders|auth|payments|accounts)",
        "message": "API route without version prefix. Use /v1/ prefix for versioning.",
        "severity": Severity.WARN,
    },
    {
        "id": "api_breaking_change_no_version",
        "pattern": r"(?i)#.*(?:BREAKING|breaking.?change)(?!.*v\d)",
        "message": "Breaking change comment without API version bump. Increment version.",
        "severity": Severity.WARN,
    },
    {
        "id": "api_hardcoded_version",
        "pattern": r"(?:version|api_version)\s*[:=]\s*[\"']v?\d+[\"'](?!.*config|.*env|.*settings)",
        "message": "Hardcoded API version. Use configuration for version management.",
        "severity": Severity.INFO,
    },
    {
        "id": "api_mixed_versioning",
        "pattern": r"(?:Accept|Content-Type).*version\s*[:=].*(?:url|path).*v\d",
        "message": "Mixed API versioning strategies. Choose URL or header versioning.",
        "severity": Severity.INFO,
    },
    {
        "id": "api_sunset_no_date",
        "pattern": r"(?i)(?:deprecated|sunset)(?!.*(?:date|until|deadline|expires))",
        "message": "API deprecation without sunset date. Specify removal timeline.",
        "severity": Severity.INFO,
    },
    {
        "id": "api_no_pagination",
        "pattern": r"(?:return|response).*(?:find_?all|find_?many|select\s+\*|\.all\(\))(?!.*(?:limit|offset|page|cursor|paginate))",
        "message": "API returns all records without pagination. Add limit/offset.",
        "severity": Severity.WARN,
    },
    {
        "id": "api_no_rate_limit_header",
        "pattern": r"(?i)(?:rate_?limit|throttle)(?!.*(?:X-RateLimit|Retry-After|header))",
        "message": "Rate limiting without response headers. Add X-RateLimit-* headers.",
        "severity": Severity.INFO,
    },
    {
        "id": "api_internal_error_detail",
        "pattern": r"(?:return|response|json).*(?:str\((?:e|err|error|exc)\)|traceback|stack_?trace|__traceback__)",
        "message": "Internal error details in API response. Return generic message.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  FEATURE FLAG SECURITY (rules 1241-1250)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "feature_flag_hardcoded",
        "pattern": r"(?i)(?:feature_?flag|flag_?enabled|is_?feature)\s*[:=]\s*(?:True|true|False|false)(?!\s*#.*config)",
        "message": "Hardcoded feature flag. Use feature flag service or config.",
        "severity": Severity.WARN,
    },
    {
        "id": "feature_flag_no_default",
        "pattern": r"(?i)get_?feature_?flag\s*\([^)]*\)(?!.*(?:default|fallback))",
        "message": "Feature flag lookup without default. Always provide fallback.",
        "severity": Severity.WARN,
    },
    {
        "id": "feature_flag_client_side_secret",
        "pattern": r"(?i)(?:feature_?flag|launchdarkly|unleash|flipt|flagsmith).*(?:server_?key|sdk_?key|api_?key)\s*[:=]\s*[\"']",
        "message": "Feature flag SDK key in client code. Use client-side key only.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "feature_flag_stale",
        "pattern": r"(?i)(?:feature_?flag|flag).*(?:temporary|temp|experiment).*(?:20(?:1[0-9]|2[0-3]))",
        "message": "Stale feature flag from past year. Clean up old flags.",
        "severity": Severity.INFO,
    },
    {
        "id": "feature_flag_no_logging",
        "pattern": r"(?:if|unless).*(?:feature_?flag|flag_?enabled)(?!.*(?:log|track|analytics|metric))",
        "message": "Feature flag check without usage tracking. Log flag evaluations.",
        "severity": Severity.INFO,
    },
    {
        "id": "feature_flag_nested",
        "pattern": r"(?:feature_?flag|is_?enabled).*\n\s*.*(?:feature_?flag|is_?enabled)",
        "message": "Nested feature flags increase complexity. Simplify flag logic.",
        "severity": Severity.INFO,
    },
    {
        "id": "feature_flag_in_loop",
        "pattern": r"(?:for|while)\s.*\n\s*.*(?:feature_?flag|is_?enabled|get_?flag)",
        "message": "Feature flag evaluation in loop. Cache flag value outside loop.",
        "severity": Severity.WARN,
    },
    {
        "id": "feature_flag_catch_all",
        "pattern": r"(?i)(?:feature_?flag|flag).*(?:except|catch)\s*(?:\(?\s*Exception|\(?\s*Error|\(?\s*\))",
        "message": "Feature flag error caught broadly. Handle specific flag errors.",
        "severity": Severity.WARN,
    },
    {
        "id": "feature_flag_percentage_hardcoded",
        "pattern": r"(?i)(?:rollout|percentage|percent)\s*[:=]\s*\d+(?!\s*#.*config)",
        "message": "Hardcoded rollout percentage. Use flag service for gradual rollout.",
        "severity": Severity.INFO,
    },
    {
        "id": "feature_flag_no_kill_switch",
        "pattern": r"(?i)(?:feature|experiment)(?!.*(?:kill_?switch|circuit_?breaker|disable|emergency))",
        "message": "Feature without kill switch. Add emergency disable capability.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  MEMORY LEAK PATTERNS (rules 1251-1262)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "memleak_event_listener_no_remove",
        "pattern": r"addEventListener\s*\([^)]*\)(?!.*(?:removeEventListener|cleanup|dispose|unmount|destroy))",
        "message": "Event listener without removal. Remove in cleanup/unmount.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "memleak_setinterval_no_clear",
        "pattern": r"setInterval\s*\([^)]*\)(?!.*(?:clearInterval|cleanup|dispose|unmount|destroy))",
        "message": "setInterval without clearInterval. Clear in cleanup.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "memleak_observer_no_disconnect",
        "pattern": r"(?:IntersectionObserver|MutationObserver|ResizeObserver)\s*\([^)]*\)(?!.*disconnect)",
        "message": "Observer without disconnect. Call disconnect in cleanup.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "memleak_unclosed_connection",
        "pattern": r"^\s*\w+\s*=\s*(?:create_?connection|\.connect)\s*\(",
        "message": "Connection opened without context manager. Use 'with' or ensure close() in finally.",
        "severity": Severity.WARN,
    },
    {
        "id": "memleak_growing_list",
        "pattern": r"(?:append|push|add)\s*\([^)]*\).*(?:while\s+True|for\s+\w+\s+in\s+itertools)",
        "message": "Unbounded collection growth. Add size limit or periodic cleanup.",
        "severity": Severity.WARN,
    },
    {
        "id": "memleak_global_cache_no_eviction",
        "pattern": r"(?:_cache|_memo|_store)\s*[:=]\s*(?:dict\(\)|\{\}|defaultdict)(?!.*(?:maxsize|ttl|evict|lru|limit))",
        "message": "Global cache without eviction policy. Use LRU cache or TTL.",
        "severity": Severity.WARN,
    },
    {
        "id": "memleak_unclosed_file",
        "pattern": r"^\s*\w+\s*=\s*open\s*\(",
        "special_handler": "check_unclosed_file",
        "message": "File opened without context manager. Use 'with open(...) as f:' instead.",
        "severity": Severity.WARN,
        "file_types": [".py"],
        "suggestion": "Use a context manager: with open(path) as f: ...",
    },
    {
        "id": "memleak_circular_reference",
        "pattern": r"self\.\w+\s*=\s*self(?:\s|$|\.|,)",
        "message": "Potential circular reference. Use weakref to break cycles.",
        "severity": Severity.INFO,
    },
    {
        "id": "memleak_closure_capture",
        "pattern": r"(?:setTimeout|setInterval|Promise)\s*\(\s*(?:function|\()\s*\).*\bthis\b",
        "message": "Closure captures this context. May prevent garbage collection.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "memleak_stream_no_destroy",
        "pattern": r"(?:createReadStream|createWriteStream|Readable|Writable)\s*\([^)]*\)(?!.*(?:destroy|close|end|pipe|finish))",
        "message": "Stream created without destroy/close. Handle stream lifecycle.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "memleak_subprocess_no_wait",
        "pattern": r"(?:subprocess\.Popen|spawn|fork)\s*\([^)]*\)(?!.*(?:wait|communicate|kill|terminate))",
        "message": "Subprocess without wait/terminate. Zombie process risk.",
        "severity": Severity.WARN,
    },
    {
        "id": "memleak_buffer_accumulate",
        "pattern": r"(?:Buffer\.concat|BytesIO|StringIO)\s*\([^)]*\).*(?:while|for)(?!.*(?:limit|max_?size|truncate))",
        "message": "Buffer accumulation in loop. Add size limit to prevent OOM.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTAINER SECURITY (rules 1263-1274)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "docker_run_as_root",
        "pattern": r"(?:USER\s+root|user:\s*[\"']?root)",
        "message": "Container running as root. Use non-root user.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile", ".yml", ".yaml"],
    },
    {
        "id": "docker_privileged",
        "pattern": r"(?i)(?:privileged\s*[:=]\s*true|--privileged)",
        "message": "Privileged container. Remove privileged flag.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_cap_sys_admin",
        "pattern": r"(?i)(?:SYS_ADMIN|CAP_SYS_ADMIN|cap_add.*SYS_ADMIN)",
        "message": "SYS_ADMIN capability. Drop unnecessary capabilities.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_host_network",
        "pattern": r"(?i)(?:network_?mode\s*[:=]\s*[\"']?host|--net\s*=?\s*host|--network\s*=?\s*host)",
        "message": "Container using host network. Use bridge or custom network.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_host_pid",
        "pattern": r"(?i)(?:pid\s*[:=]\s*[\"']?host|--pid\s*=?\s*host)",
        "message": "Container sharing host PID namespace. Isolate PID namespace.",
        "severity": Severity.WARN,
    },
    {
        "id": "docker_writable_rootfs",
        "pattern": r"(?i)(?:read_?only\s*[:=]\s*false|readOnlyRootFilesystem\s*[:=]\s*false)",
        "message": "Container with writable root filesystem. Set readOnlyRootFilesystem.",
        "severity": Severity.WARN,
    },
    {
        "id": "docker_no_healthcheck",
        "pattern": r"(?i)HEALTHCHECK\s+NONE",
        "message": "Docker HEALTHCHECK disabled. Add health check.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_env_credential_leak",
        "pattern": r"(?i)ENV\s+(?:\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*)\s*[:=]\s*\S+",
        "message": "Secret in Docker ENV instruction. Use Docker secrets or build args.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_add_remote",
        "pattern": r"ADD\s+https?://",
        "message": "Docker ADD from URL. Use COPY with verified downloads.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker_no_memory_limit",
        "pattern": r"(?i)(?:mem_?limit|memory)\s*[:=]\s*(?:0|unlimited|None|null)",
        "message": "Container without memory limit. Set memory limit to prevent OOM.",
        "severity": Severity.WARN,
    },
    {
        "id": "k8s_no_network_policy",
        "pattern": r"kind:\s*(?:Deployment|StatefulSet|DaemonSet)(?![\s\S]*NetworkPolicy)",
        "message": "Kubernetes workload without NetworkPolicy. Add network segmentation.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_namespace_default_used",
        "pattern": r"namespace:\s*[\"']?default[\"']?",
        "message": "Using default Kubernetes namespace. Create dedicated namespace.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  DATABASE SECURITY (rules 1275-1286)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "db_dsn_credentials_exposed",
        "pattern": r"(?i)(?:database_?url|connection_?string|dsn)\s*[:=]\s*[\"'](?:postgres|mysql|mongo|redis|mssql)://\w+:\w+@",
        "message": "Hardcoded database connection string with credentials. Use env vars.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "db_ssl_disabled",
        "pattern": r"(?i)(?:ssl_?mode|sslmode|ssl)\s*[:=]\s*[\"']?(?:disable|false|prefer|allow)[\"']?",
        "message": "Database SSL disabled or weakened. Use sslmode=verify-full.",
        "severity": Severity.WARN,
    },
    {
        "id": "db_wildcard_grant",
        "pattern": r"(?i)GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+\*\.\*",
        "message": "Wildcard database grant. Apply least privilege.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "db_drop_without_exists",
        "pattern": r"(?i)DROP\s+(?:TABLE|DATABASE|INDEX)(?!\s+IF\s+EXISTS)",
        "message": "DROP without IF EXISTS. Add IF EXISTS for safety.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "db_fk_missing_index",
        "pattern": r"(?i)FOREIGN\s+KEY\s*\([^)]+\)\s*REFERENCES(?!.*INDEX)",
        "message": "Foreign key without index. Add index for JOIN performance.",
        "severity": Severity.INFO,
        "file_types": [".sql"],
    },
    {
        "id": "db_select_all_columns",
        "pattern": r"(?i)SELECT\s+\*\s+FROM",
        "message": "SELECT * in application code. Specify column names explicitly.",
        "severity": Severity.INFO,
        "file_types": [".sql"],
    },
    {
        "id": "db_no_migration_down",
        "pattern": r"(?i)def\s+upgrade\s*\((?![\s\S]*def\s+downgrade)",
        "message": "Database migration without downgrade function. Add rollback.",
        "severity": Severity.WARN,
    },
    {
        "id": "db_raw_query_user_input",
        "pattern": r"(?:raw|text|execute)\s*\(\s*f[\"'].*(?:user|input|request|params)",
        "message": "Raw database query with user input. Use parameterized queries.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "db_pool_no_limit",
        "pattern": r"(?i)(?:pool_?size|max_?connections|max_?pool)\s*[:=]\s*(?:0|None|null|unlimited|-1)",
        "message": "Database pool without limit. Set max connections.",
        "severity": Severity.WARN,
    },
    {
        "id": "db_no_timeout",
        "pattern": r"(?i)(?:connect_?timeout|statement_?timeout|query_?timeout)\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "Database query without timeout. Set statement timeout.",
        "severity": Severity.WARN,
    },
    {
        "id": "db_autocommit_on",
        "pattern": r"(?i)autocommit\s*[:=]\s*(?:true|True|1)",
        "message": "Database autocommit enabled. Use explicit transactions.",
        "severity": Severity.INFO,
    },
    {
        "id": "db_truncate_cascade",
        "pattern": r"(?i)TRUNCATE\s+.*CASCADE",
        "message": "TRUNCATE CASCADE can delete related data. Verify intent.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  ASYNC / CONCURRENCY ANTI-PATTERNS (rules 1287-1298)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "async_sync_in_async",
        "pattern": r"(?:async\s+def\s+\w+.*\n(?:.*\n){0,10})\s*(?:time\.sleep|requests\.(?:get|post)|open\s*\()",
        "message": "Synchronous call in async function. Use async equivalent.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_bare_create_task",
        "pattern": r"asyncio\.create_task\s*\([^)]*\)(?!.*(?:await|gather|group|result))",
        "message": "Fire-and-forget task. Store reference to prevent silent failures.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_no_shield",
        "pattern": r"(?:cancel|task\.cancel)\s*\([^)]*\)(?!.*(?:shield|protect|critical))",
        "message": "Task cancellation without shield. Protect critical sections.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_no_timeout",
        "pattern": r"await\s+\w+\s*\([^)]*\)(?!.*(?:timeout|wait_for|asyncio\.timeout))",
        "message": "Await without timeout. Use asyncio.timeout or asyncio.wait_for.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_global_event_loop",
        "pattern": r"asyncio\.get_event_loop\s*\(\s*\)",
        "message": "Deprecated get_event_loop. Use asyncio.get_running_loop or asyncio.run.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_run_in_executor_blocking",
        "pattern": r"run_in_executor\s*\(\s*None\s*,",
        "message": "run_in_executor with default executor. Use explicit ThreadPoolExecutor.",
        "severity": Severity.INFO,
    },
    {
        "id": "thread_daemon_no_cleanup",
        "pattern": r"(?:daemon\s*[:=]\s*True|setDaemon\s*\(\s*True\s*\))(?!.*(?:atexit|cleanup|shutdown|join))",
        "message": "Daemon thread without cleanup. Add atexit handler.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_gather_no_return_exceptions",
        "pattern": r"asyncio\.gather\s*\([^)]*\)(?!.*return_exceptions)",
        "message": "asyncio.gather without return_exceptions. Handle task failures.",
        "severity": Severity.INFO,
    },
    {
        "id": "thread_lock_no_timeout",
        "pattern": r"\.acquire\s*\(\s*\)(?!.*timeout)",
        "message": "Lock acquire without timeout. Add timeout to prevent deadlock.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_blocking_dns",
        "pattern": r"(?:socket\.getaddrinfo|socket\.gethostbyname)\s*\(",
        "message": "Blocking DNS resolution in async context. Use async DNS resolver.",
        "severity": Severity.WARN,
    },
    {
        "id": "thread_unbounded_pool",
        "pattern": r"ThreadPoolExecutor\s*\(\s*\)(?!.*max_workers)",
        "message": "ThreadPoolExecutor without max_workers. Set explicit limit.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_mixed_sync_async",
        "pattern": r"(?:requests|urllib)\.(?:get|post|put|delete)\s*\(.*\n.*(?:async|await|asyncio)",
        "message": "Mixing sync HTTP library with async code. Use httpx or aiohttp.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ENVIRONMENT / CONFIG SECURITY (rules 1299-1310)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "env_debug_prod",
        "pattern": r"(?i)(?:DEBUG|FLASK_DEBUG|DJANGO_DEBUG|APP_DEBUG)\s*[:=]\s*(?:true|True|1|[\"']true[\"'])",
        "message": "Debug mode enabled. Ensure this is not production config.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_default_secret_key",
        "pattern": r"(?i)SECRET_?KEY\s*[:=]\s*[\"'](?:changeme|secret|default|test|dev|password|123|abc)[\"']",
        "message": "Default/weak secret key. Generate a strong random key.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "env_no_env_validation",
        "pattern": r"os\.environ\[.*\](?!.*(?:get|default|or\s|raise))",
        "message": "Direct env access without fallback. Use os.environ.get with default.",
        "severity": Severity.INFO,
    },
    {
        "id": "env_dotenv_committed",
        "pattern": r"(?:load_dotenv|dotenv\.load)\s*\(\s*[\"']\.env[\"']",
        "message": "Loading specific .env file. Ensure .env is in .gitignore.",
        "severity": Severity.INFO,
    },
    {
        "id": "env_production_test_data",
        "pattern": r"(?i)(?:seed|fixture|mock|fake|dummy).*(?:production|prod|live)",
        "message": "Test/seed data reference in production context. Remove before deploy.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_cors_all_origins",
        "pattern": r"(?i)(?:CORS|cors)\s*\(\s*\w+\s*(?:,\s*)?(?:origins?\s*[:=]\s*\[?\s*[\"']\*[\"']\s*\]?|allow_all\s*[:=]\s*True)",
        "message": "CORS allows all origins. Restrict to specific domains.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_smtp_no_tls",
        "pattern": r"(?i)(?:SMTP|smtp)\s*\([^)]*\)(?!.*(?:TLS|SSL|starttls|SMTP_SSL))",
        "message": "SMTP connection without TLS. Use SMTP_SSL or starttls.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_admin_default_creds",
        "pattern": r"(?i)(?:admin|root).*(?:password|passwd|pwd)\s*[:=]\s*[\"'](?:admin|root|password|123456|test)[\"']",
        "message": "Default admin credentials. Change before deployment.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "env_insecure_cookie",
        "pattern": r"(?i)(?:cookie|session).*(?:secure\s*[:=]\s*(?:false|False)|httponly\s*[:=]\s*(?:false|False))",
        "message": "Insecure cookie settings. Enable Secure and HttpOnly flags.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_wildcard_host",
        "pattern": r"(?i)(?:ALLOWED_?HOSTS|allowed_hosts)\s*[:=]\s*\[?\s*[\"']\*[\"']",
        "message": "Wildcard allowed hosts. Specify exact hostnames.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_no_https_redirect",
        "pattern": r"(?i)(?:SECURE_?SSL_?REDIRECT|force_?ssl|require_?https)\s*[:=]\s*(?:false|False|0)",
        "message": "HTTPS redirect disabled. Enable in production.",
        "severity": Severity.WARN,
    },
    {
        "id": "env_session_no_expiry",
        "pattern": r"(?i)(?:session_?lifetime|session_?timeout|session_?max_?age)\s*[:=]\s*(?:0|None|null|false|False)",
        "message": "Session without expiry. Set a reasonable session timeout.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ERROR HANDLING ANTI-PATTERNS (rules 1311-1320)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "error_catch_all_rethrow",
        "pattern": r"except\s+Exception.*:\s*\n\s*raise\s*$",
        "message": "Catching all exceptions just to re-raise. Remove unnecessary catch.",
        "severity": Severity.INFO,
    },
    {
        "id": "error_generic_message",
        "pattern": r"(?:raise|throw)\s+\w*(?:Error|Exception)\s*\(\s*[\"'](?:error|failure|something went wrong|unknown error)[\"']\s*\)",
        "message": "Generic error message. Provide actionable error description.",
        "severity": Severity.WARN,
    },
    {
        "id": "error_empty_finally",
        "pattern": r"finally\s*:\s*\n\s*pass",
        "message": "Empty finally block. Remove or add cleanup logic.",
        "severity": Severity.INFO,
    },
    {
        "id": "error_assert_in_production",
        "pattern": r"^\s*assert\s+(?!.*(?:test|spec|_test\.py|_spec\.py|conftest))",
        "message": "Assert in production code. Use explicit validation with exceptions.",
        "severity": Severity.WARN,
    },
    {
        "id": "error_exit_in_library",
        "pattern": r"(?:sys\.exit|os\._exit|exit|quit)\s*\(\s*\d*\s*\)(?!.*(?:main|__main__|cli|entry))",
        "message": "sys.exit in library code. Raise exception instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "error_exception_as_flow",
        "pattern": r"try\s*:.*\n\s*.*(?:int|float|bool|str)\s*\(.*\n\s*except\s+(?:ValueError|TypeError)",
        "message": "Exception for flow control. Validate before conversion.",
        "severity": Severity.INFO,
    },
    {
        "id": "error_silent_timeout",
        "pattern": r"except\s+(?:Timeout|TimeoutError|asyncio\.TimeoutError)\s*:\s*\n\s*(?:pass|continue)",
        "message": "Timeout silently swallowed. Log and handle timeout appropriately.",
        "severity": Severity.WARN,
    },
    {
        "id": "error_broad_retry",
        "pattern": r"(?:retry|retries).*except\s+(?:Exception|BaseException|Error)",
        "message": "Retry on broad exception. Retry only on transient errors.",
        "severity": Severity.WARN,
    },
    {
        "id": "error_no_context",
        "pattern": r"raise\s+\w+(?:Error|Exception)\s*\([^)]*\)\s*$(?!.*from)",
        "message": "Raising exception without chaining. Use 'raise ... from err'.",
        "severity": Severity.INFO,
    },
    {
        "id": "error_except_pass",
        "pattern": r"except\s+\w+(?:Error|Exception)\s*:\s*\n\s*pass\s*$",
        "message": "Exception caught and ignored. Handle, log, or re-raise.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  INPUT VALIDATION (rules 1321-1332)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "input_no_size_limit",
        "pattern": r"(?:request\.body|req\.body|request\.data|request\.json)(?!.*(?:max_?size|limit|max_?length|content_?length))",
        "message": "Request body without explicit size validation. Add max content length.",
        "severity": Severity.INFO,
    },
    {
        "id": "input_no_type_check",
        "pattern": r"(?:request\.json|req\.body)\s*\[[\"']\w+[\"']\](?!.*(?:isinstance|type|validate|schema))",
        "message": "Accessing request field without type validation. Validate schema.",
        "severity": Severity.INFO,
    },
    {
        "id": "input_html_no_sanitize",
        "pattern": r"(?:innerHTML|dangerouslySetInnerHTML|v-html|ng-bind-html)\s*[:=]\s*(?:user|input|request|data|props)",
        "message": "User input in HTML without sanitization. XSS vulnerability.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "input_file_upload_no_type",
        "pattern": r"(?:uploaded_?file|upload_?file|form_?file)\.save\s*\((?!.*(?:content_?type|mime|extension|validate|allowed))",
        "message": "File upload saved without type validation. Verify file type and size.",
        "severity": Severity.WARN,
    },
    {
        "id": "input_url_no_validate",
        "pattern": r"(?:url|uri|link|href)\s*[:=]\s*(?:user|input|request|params|body)(?!.*(?:validate|parse|urlparse|URL\(|is_?valid))",
        "message": "URL from user input without validation. Parse and validate URL.",
        "severity": Severity.WARN,
    },
    {
        "id": "input_email_no_validate",
        "pattern": r"(?:email|e_?mail)\s*[:=]\s*(?:request|params|body|input)\[(?!.*(?:validate|regex|match|schema))",
        "message": "Email from user input without validation. Validate email format.",
        "severity": Severity.WARN,
    },
    {
        "id": "input_numeric_no_range",
        "pattern": r"(?:int|float|Number)\s*\(\s*(?:request|params|input|body)\[(?!.*(?:min|max|range|clamp|bound))",
        "message": "Numeric conversion without range check. Validate bounds.",
        "severity": Severity.INFO,
    },
    {
        "id": "input_json_parse_no_catch",
        "pattern": r"(?:json\.loads|JSON\.parse)\s*\(\s*(?:request|body|data)(?!.*(?:try|except|catch|validate))",
        "message": "JSON parsing without error handling. Wrap in try/except.",
        "severity": Severity.WARN,
    },
    {
        "id": "input_command_injection",
        "pattern": r"(?:os\.system|subprocess\.call|child_process\.exec)\s*\(\s*(?:f[\"']|.*(?:user|input|request|params))",
        "message": "Command injection via user input. Use subprocess with list args.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "input_ldap_injection",
        "pattern": r"(?:ldap|LDAP).*(?:search|filter|bind).*(?:user|input|request|params)",
        "message": "LDAP query with user input. Escape special characters.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "input_xpath_injection",
        "pattern": r"(?:xpath|XPath).*(?:user|input|request|params)",
        "message": "XPath query with user input. Use parameterized XPath.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "input_header_injection",
        "pattern": r"(?:add_?header|set_?header|Header)\s*\([^)]*(?:user|input|request|params)",
        "message": "User input in HTTP header. Sanitize to prevent header injection.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  INFRASTRUCTURE AS CODE (rules 1333-1344)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "tf_s3_public_acl",
        "pattern": r"acl\s*=\s*[\"']public-read(?:-write)?[\"']",
        "message": "S3 bucket with public ACL. Use bucket policy instead.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "tf_sg_open_ingress",
        "pattern": r"cidr_blocks\s*=\s*\[.*[\"']0\.0\.0\.0/0[\"'].*\]",
        "message": "Security group open to all IPs. Restrict to specific CIDRs.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "tf_no_encryption",
        "pattern": r"(?i)(?:encrypted|encryption)\s*[:=]\s*(?:false|False|0)",
        "message": "Encryption disabled. Enable encryption at rest.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "tf_no_logging",
        "pattern": r"(?i)(?:enable_?logging|access_?logging|logging)\s*[:=]\s*(?:false|False|0)",
        "message": "Logging disabled on infrastructure. Enable for audit trail.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "tf_hardcoded_credentials",
        "pattern": r"(?i)(?:access_key|secret_key)\s*=\s*[\"'][A-Z0-9]{16,}[\"']",
        "message": "Hardcoded AWS credentials in Terraform. Use IAM roles or env vars.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "tf_default_vpc",
        "pattern": r"(?i)default\s*=\s*true.*vpc",
        "message": "Using default VPC. Create dedicated VPC for production.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "tf_no_state_lock",
        "pattern": r"(?i)(?:lock|dynamodb_table)\s*[:=]\s*(?:false|False|[\"'][\"']|null)",
        "message": "Terraform state locking disabled. Enable to prevent corruption.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "tf_no_versioning",
        "pattern": r"(?i)versioning\s*\{[^}]*enabled\s*[:=]\s*(?:false|False)",
        "message": "S3 versioning disabled. Enable for data protection.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "helm_latest_tag",
        "pattern": r"(?:image|tag)\s*:\s*[\"']?latest[\"']?",
        "message": "Container image with :latest tag. Pin to specific version.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_container_no_limits",
        "pattern": r"containers\s*:(?![\s\S]*(?:resources|limits|requests))",
        "message": "Kubernetes container without resource limits. Set CPU/memory limits.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_no_security_context",
        "pattern": r"containers\s*:(?![\s\S]*securityContext)",
        "message": "Kubernetes container without securityContext. Set runAsNonRoot.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_host_path_volume",
        "pattern": r"hostPath\s*:",
        "message": "HostPath volume in Kubernetes. Use PersistentVolumeClaim instead.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },

    # ═══════════════════════════════════════════════════════════════
    #  TESTING ANTI-PATTERNS (rules 1345-1356)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "test_sleep_in_test",
        "pattern": r"(?:time\.sleep|Thread\.sleep|Sleep)\s*\(\s*\d+\s*\)",
        "message": "Sleep in test. Use async wait or mock time.",
        "severity": Severity.WARN,
    },
    {
        "id": "test_no_assertion",
        "pattern": r"def\s+test_\w+\s*\([^)]*\)\s*:(?![\s\S]*(?:assert|expect|should|verify|mock\.\w+\.assert))",
        "message": "Test function without assertions. Add meaningful assertions.",
        "severity": Severity.WARN,
    },
    {
        "id": "test_hardcoded_url",
        "pattern": r"(?:test|spec).*(?:https?://(?!localhost|127\.0\.0\.1|example\.com))\w+\.\w+",
        "message": "Hardcoded external URL in test. Use mock or test server.",
        "severity": Severity.WARN,
    },
    {
        "id": "test_real_database",
        "pattern": r"(?:test|spec).*(?:psycopg|mysql\.connector|pymongo|sqlalchemy).*connect",
        "message": "Real database connection in test. Use test database or mock.",
        "severity": Severity.WARN,
    },
    {
        "id": "test_order_dependent",
        "pattern": r"(?:global|class\s+\w+).*(?:test_?state|shared_?state|_counter)\s*[:=]",
        "message": "Shared mutable state between tests. Tests should be independent.",
        "severity": Severity.WARN,
    },
    {
        "id": "test_skip_no_reason",
        "pattern": r"@(?:skip|pytest\.mark\.skip)\s*(?:\(\s*\)|$)(?!.*reason)",
        "message": "Skipped test without reason. Document why test is skipped.",
        "severity": Severity.INFO,
    },
    {
        "id": "test_mock_everything",
        "pattern": r"@(?:mock\.)?patch\s*\([^)]*\)\s*\n\s*@(?:mock\.)?patch\s*\([^)]*\)\s*\n\s*@(?:mock\.)?patch",
        "message": "Too many mocks. Consider integration test or simplify unit.",
        "severity": Severity.INFO,
    },
    {
        "id": "test_assertEqual_bool",
        "pattern": r"assert(?:Equal|Equals)\s*\([^,]+,\s*(?:True|False)\s*\)",
        "message": "assertEqual with boolean. Use assertTrue/assertFalse.",
        "severity": Severity.INFO,
    },
    {
        "id": "test_hardcoded_port",
        "pattern": r"(?:test|spec).*(?:port|PORT)\s*[:=]\s*\d{4,5}(?!.*(?:env|config|random|available))",
        "message": "Hardcoded port in test. Use dynamic port allocation.",
        "severity": Severity.INFO,
    },
    {
        "id": "test_ignore_return",
        "pattern": r"(?:test|spec).*(?:get|post|put|delete|patch)\s*\([^)]*\)\s*$(?!.*(?:assert|expect|response|result))",
        "message": "HTTP call in test without checking response. Add assertions.",
        "severity": Severity.WARN,
    },
    {
        "id": "test_print_debug",
        "pattern": r"(?:test_|spec_|_test|_spec).*(?:print|console\.log|puts|fmt\.Print)\s*\(",
        "message": "Print/log in test code. Use assertions or test logging.",
        "severity": Severity.INFO,
    },
    {
        "id": "test_datetime_now",
        "pattern": r"(?:test|spec).*(?:datetime\.now|Date\.now|time\.time)\s*\(",
        "message": "Real time in test. Mock time for deterministic tests.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  ENCRYPTION IN TRANSIT (rules 1357-1364)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "tls_v1_deprecated",
        "pattern": r"(?i)(?:TLSv1(?:\.0)?|SSLv[23]|ssl\.PROTOCOL_TLSv1(?:_0)?|ssl\.PROTOCOL_SSLv[23])",
        "message": "Deprecated TLS/SSL version. Use TLS 1.2+ minimum.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "tls_verify_disabled",
        "pattern": r"(?i)(?:verify\s*[:=]\s*(?:false|False|0)|CERT_NONE|verify_?ssl\s*[:=]\s*(?:false|False)|rejectUnauthorized\s*[:=]\s*false)",
        "message": "TLS certificate verification disabled. Enable for security.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "tls_weak_cipher",
        "pattern": r"(?i)(?:RC4|DES|NULL|EXPORT|anon|MD5).*(?:cipher|suite|ssl|tls)",
        "message": "Weak TLS cipher suite. Use modern cipher suites.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "tls_self_signed_prod",
        "pattern": r"(?i)(?:self_?signed|selfsigned|self-signed).*(?:prod|production|deploy)",
        "message": "Self-signed certificate in production. Use CA-signed certificate.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "tls_no_cert_pinning",
        "pattern": r"(?i)(?:cert_?pin|certificate_?pin|ssl_?pin)\s*[:=]\s*(?:false|False|None|null|0)",
        "message": "Certificate pinning disabled. Enable for sensitive connections.",
        "severity": Severity.INFO,
    },
    {
        "id": "tls_hardcoded_cert",
        "pattern": r"(?i)(?:cert_?file|certificate|ca_?cert)\s*[:=]\s*[\"']/(?:etc|usr|opt|home|tmp)/",
        "message": "Hardcoded certificate path. Use configuration.",
        "severity": Severity.WARN,
    },
    {
        "id": "http_no_https",
        "pattern": r"[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|example\.com)[\w.-]+",
        "message": "HTTP URL in code. Use HTTPS for security.",
        "severity": Severity.WARN,
    },
    {
        "id": "tls_allow_renegotiation",
        "pattern": r"(?i)(?:allow_?renegotiation|unsafe_?renegotiation)\s*[:=]\s*(?:true|True|1)",
        "message": "TLS renegotiation enabled. Disable to prevent DoS.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  PERMISSION / ACCESS CONTROL (rules 1365-1376)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "authz_no_check",
        "pattern": r"(?:@app\.route|@router\.\w+)\s*\([^)]*\)\s*\n(?:(?:async\s+)?def\s+\w+\s*\([^)]*\)\s*:)(?![\s\S]*(?:permission|authorize|role|is_?admin|is_?authenticated|login_?required|Depends))",
        "message": "Route handler without authorization check. Add permission verification.",
        "severity": Severity.WARN,
    },
    {
        "id": "authz_role_hardcoded",
        "pattern": r"(?:role|user_type)\s*[:=!<>=]+\s*[\"'](?:admin|superuser|root|superadmin)[\"']",
        "message": "Hardcoded role check. Use role-based access control system.",
        "severity": Severity.INFO,
    },
    {
        "id": "authz_idor_direct_access",
        "pattern": r"(?:User|Account|Profile|Order)\.(?:get|find|find_?one)\s*\(\s*(?:request|params|args)\[",
        "message": "Direct object access from request params. IDOR risk. Verify ownership.",
        "severity": Severity.WARN,
    },
    {
        "id": "authz_jwt_no_verify",
        "pattern": r"(?:jwt\.decode|jose\.verify|jsonwebtoken\.verify).*(?:verify\s*[:=]\s*false|algorithms?\s*[:=]\s*\[\])",
        "message": "JWT decoded without verification. Always verify signature.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "authz_session_fixation",
        "pattern": r"(?:session|session_id)\s*[:=]\s*(?:request|params|query|cookie)\[",
        "message": "Session ID from user input. Regenerate session after auth.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "authz_password_plaintext",
        "pattern": r"(?:password|passwd)\s*[:=!]+\s*(?:request|params|body|input)\[.*\](?!.*(?:hash|bcrypt|argon|pbkdf|scrypt))",
        "message": "Password comparison without hashing. Use bcrypt or argon2.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "authz_api_key_query_param",
        "pattern": r"(?:api_?key|apikey|token)\s*[:=]\s*(?:request\.(?:args|query|params)|req\.query)",
        "message": "API key in query parameter. Use Authorization header.",
        "severity": Severity.WARN,
    },
    {
        "id": "authz_no_brute_force_protection",
        "pattern": r"@(?:app|router|api)\.\s*(?:post|put)\s*\(\s*['\"].*(?:login|sign.?in|authenticate)(?!.*(?:rate_?limit|throttle|lockout|max_?attempts|brute))",
        "message": "Login endpoint without brute force protection. Add rate limiting.",
        "severity": Severity.WARN,
    },
    {
        "id": "authz_privilege_escalation",
        "pattern": r"(?:is_?admin|is_?superuser|role)\s*[:=]\s*(?:request|params|body|input)\[",
        "message": "User-controlled privilege assignment. Validate against auth system.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "authz_cors_with_credentials",
        "pattern": r"(?i)(?:credentials|withCredentials)\s*[:=]\s*(?:true|True).*(?:origin|Origin)\s*[:=]\s*(?:request|req)",
        "message": "CORS credentials with reflected origin. Validate origin against allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "authz_2fa_bypass",
        "pattern": r"(?i)(?:two_?factor|2fa|mfa|otp).*(?:skip|bypass|disable)\s*[:=]\s*(?:true|True|1)",
        "message": "2FA bypass flag. Never allow MFA bypass in production.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "authz_token_no_refresh",
        "pattern": r"(?i)(?:access_?token|jwt).*(?:expires|expiry).*(?:never|0|None|null|false|9999)",
        "message": "Token with no/extreme expiry. Set reasonable token lifetime.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  OBSERVABILITY ANTI-PATTERNS (rules 1377-1386)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "observ_no_correlation_id",
        "pattern": r"(?:log(?:ger)?|logging)\.(?:info|warning|error|debug)\s*\([^)]*\)(?!.*(?:correlation|trace|request_id|span))",
        "message": "Log entry without correlation ID. Add request/trace ID.",
        "severity": Severity.INFO,
    },
    {
        "id": "observ_no_structured_log",
        "pattern": r"logging\.(?:info|warning|error|debug)\s*\(\s*f[\"']",
        "message": "Unstructured f-string log. Use structured logging with extra dict.",
        "severity": Severity.INFO,
    },
    {
        "id": "observ_metric_no_label",
        "pattern": r"(?:Counter|Gauge|Histogram|Summary)\s*\([^)]*\)(?!.*(?:label|tag|dimension))",
        "message": "Metric without labels. Add labels for meaningful aggregation.",
        "severity": Severity.INFO,
    },
    {
        "id": "observ_high_cardinality_label",
        "pattern": r"(?:label|tag)\s*[:=].*(?:user_id|email|ip_address|request_id|session_id)",
        "message": "High-cardinality metric label. Use low-cardinality values.",
        "severity": Severity.WARN,
    },
    {
        "id": "observ_no_error_rate_metric",
        "pattern": r"except\s+\w+(?:Error|Exception).*(?!.*(?:metric|counter|increment|observe))",
        "message": "Error handling without metrics. Track error rate.",
        "severity": Severity.INFO,
    },
    {
        "id": "observ_log_level_debug_prod",
        "pattern": r"(?i)(?:LOG_?LEVEL|log_?level|LOGLEVEL)\s*[:=]\s*[\"']?(?:DEBUG|TRACE|VERBOSE)[\"']?",
        "message": "Debug log level. Set INFO or WARN for production.",
        "severity": Severity.WARN,
    },
    {
        "id": "observ_no_health_endpoint",
        "pattern": r"(?:app|server)\.(?:listen|run)\s*\((?![\s\S]*(?:health|healthz|ready|readiness|liveness))",
        "message": "Server without health endpoint. Add /health for monitoring.",
        "severity": Severity.INFO,
    },
    {
        "id": "observ_alert_no_runbook",
        "pattern": r"(?i)(?:alert|alarm|notification)(?!.*(?:runbook|playbook|documentation|wiki|url))",
        "message": "Alert without runbook link. Add documentation for on-call response.",
        "severity": Severity.INFO,
    },
    {
        "id": "observ_sentry_debug",
        "pattern": r"(?i)(?:sentry|Sentry).*debug\s*[:=]\s*(?:true|True|1)",
        "message": "Sentry debug mode enabled. Disable in production.",
        "severity": Severity.WARN,
    },
    {
        "id": "observ_log_rotation_missing",
        "pattern": r"(?:FileHandler|file_?handler)\s*\([^)]*\)(?!.*(?:rotating|timed|max_?bytes|backup))",
        "message": "File logging without rotation. Use RotatingFileHandler.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DEPENDENCY INJECTION / COUPLING (rules 1387-1396)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "coupling_import_cycle",
        "pattern": r"(?:from|import)\s+\.\w+\s+import.*\n(?:.*\n){0,20}(?:from|import)\s+\.\w+\s+import.*(?:# circular|# cycle)",
        "message": "Circular import indicated by comment. Refactor dependency graph.",
        "severity": Severity.WARN,
    },
    {
        "id": "coupling_god_class",
        "pattern": r"class\s+\w+.*:\s*\n(?:.*\n){100,}",
        "message": "Class over 100 lines. Split by responsibility.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_service_locator",
        "pattern": r"(?:ServiceLocator|Registry|Container)\.(?:get|resolve|getInstance)\s*\(",
        "message": "Service locator pattern. Use constructor injection.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_new_in_constructor",
        "pattern": r"(?:__init__|constructor)\s*\([^)]*\)\s*:?\s*\n(?:.*\n){0,5}\s*self\.\w+\s*=\s*\w+\s*\(",
        "message": "Object creation in constructor. Inject dependencies instead.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_hardcoded_class",
        "pattern": r"(?:isinstance|type)\s*\(\s*\w+\s*,\s*(?:str|int|float|bool|list|dict)\s*\)(?=.*(?:parse|convert|transform))",
        "message": "Type check with primitive types in business logic. Use protocol/interface.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_global_singleton",
        "pattern": r"_instance\s*[:=]\s*None\s*\n.*@classmethod\s*\n.*def\s+(?:get_?instance|instance|shared)",
        "message": "Manual singleton pattern. Use module-level instance or DI container.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_deep_nesting",
        "pattern": r"^\s{24,}(?:for|while)\s",
        "message": "Deep nesting (6+ levels) with loop. Extract to helper functions.",
        "severity": Severity.WARN,
    },
    {
        "id": "coupling_boolean_param",
        "pattern": r"def\s+\w+\s*\([^)]*(?:flag|is_\w+|should_\w+|enable_\w+)\s*[:=]\s*(?:bool|True|False)[^)]*\)",
        "message": "Boolean parameter often indicates function does two things. Split.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_magic_string",
        "pattern": r"if\s+\w+\s*==\s*[\"'](?:active|pending|completed|failed|processing|draft|published)[\"']",
        "message": "Magic string comparison. Use Enum or constants.",
        "severity": Severity.INFO,
    },
    {
        "id": "coupling_feature_envy",
        "pattern": r"(?:self\.\w+\.\w+\.\w+\.\w+|this\.\w+\.\w+\.\w+\.\w+)",
        "message": "Deep attribute chain (Law of Demeter). Delegate to intermediate object.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DATA PRIVACY / COMPLIANCE (rules 1397-1402)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "privacy_gdpr_no_consent",
        "pattern": r"(?i)(?:track|analytics|telemetry|collect).*(?:user|personal|pii)(?!.*(?:consent|opt_?in|gdpr|permission))",
        "message": "User data collection without consent check. Add GDPR consent flow.",
        "severity": Severity.WARN,
    },
    {
        "id": "privacy_no_data_retention",
        "pattern": r"(?i)(?:store|save|persist|insert).*(?:personal|pii|email|phone|address)(?!.*(?:retention|expire|ttl|delete|purge))",
        "message": "Storing personal data without retention policy. Add data expiration.",
        "severity": Severity.INFO,
    },
    {
        "id": "privacy_export_no_encryption",
        "pattern": r"(?i)(?:export_data|download_data|dump_data|backup_data|csv_export|data_export).*(?:user|customer|personal|pii)(?!.*(?:encrypt|cipher|secure|protected))",
        "message": "Exporting personal data without encryption. Encrypt data exports.",
        "severity": Severity.WARN,
    },
    {
        "id": "privacy_third_party_data_share",
        "pattern": r"(?i)(?:send|share|transmit|forward).*(?:user_?data|personal|pii).*(?:third_?party|external|partner|vendor)",
        "message": "Sharing personal data with third party. Verify DPA agreement.",
        "severity": Severity.WARN,
    },
    {
        "id": "privacy_no_audit_trail",
        "pattern": r"(?i)(?:delete|update|modify).*(?:personal|pii|user_?data)(?!.*(?:audit|log|trail|record|history))",
        "message": "PII modification without audit trail. Log data access for compliance.",
        "severity": Severity.INFO,
    },
    {
        "id": "privacy_hardcoded_pii",
        "pattern": r"(?i)(?:email|phone|ssn|social_?security)\s*[:=]\s*[\"'](?:\w+@\w+\.\w+|\d{3}[\s-]?\d{2}[\s-]?\d{4}|\+?\d{10,})[\"']",
        "message": "Hardcoded PII in source code. Use test fixtures or anonymized data.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  SPRING BOOT SECURITY (Java) - 20 rules
    # =================================================================
    {
        "id": "spring_crossorigin_wildcard",
        "pattern": r'@CrossOrigin\s*\(\s*origins?\s*=\s*["\*"]',
        "message": "CrossOrigin with wildcard allows any origin. Restrict to specific domains.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_no_valid_annotation",
        "pattern": r"@(?:Post|Put|Patch)Mapping[^)]*\)\s*\n?\s*public\s+\S+\s+\w+\s*\(\s*(?:@RequestBody\s+)(?!@Valid)",
        "message": "Request body without @Valid annotation. Add @Valid for input validation.",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "spring_csrf_disabled",
        "pattern": r"\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(",
        "message": "CSRF protection disabled. Keep CSRF enabled for session-based auth.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_session_fixation_none",
        "pattern": r"\.sessionFixation\s*\(\s*\)\s*\.\s*none\s*\(",
        "message": "Session fixation protection disabled. Use migrateSession or newSession.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_permit_all_wildcard",
        "pattern": r'\.antMatchers\s*\(\s*["\']\/\*\*["\']\s*\)\s*\.\s*permitAll',
        "message": "Permitting all paths without auth. Restrict to specific public endpoints.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_h2_console_enabled",
        "pattern": r"spring\.h2\.console\.enabled\s*=\s*true",
        "message": "H2 console enabled. Disable in production to prevent data exposure.",
        "severity": Severity.WARN,
        "file_types": [".properties", ".yml", ".yaml"],
    },
    {
        "id": "spring_devtools_prod",
        "pattern": r"spring\.devtools\.restart\.enabled\s*=\s*true",
        "message": "DevTools restart enabled. Disable in production builds.",
        "severity": Severity.WARN,
        "file_types": [".properties", ".yml", ".yaml"],
    },
    {
        "id": "spring_debug_logging_prod",
        "pattern": r"logging\.level\.root\s*=\s*(?:DEBUG|TRACE)",
        "message": "Debug-level logging in config. Use INFO or WARN for production.",
        "severity": Severity.WARN,
        "file_types": [".properties", ".yml", ".yaml"],
    },
    {
        "id": "spring_no_https_required",
        "pattern": r"\.requiresChannel\s*\(\s*\)\s*\.\s*anyRequest\s*\(\s*\)\s*\.\s*requiresInsecure",
        "message": "Insecure channel required. Require HTTPS for all production traffic.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_remember_me_no_key",
        "pattern": r"\.rememberMe\s*\(\s*\)(?!.*\.key\s*\()",
        "message": "Remember-me without secret key. Set a strong key for token security.",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "spring_cors_allow_credentials_wildcard",
        "pattern": r"allowCredentials\s*\(\s*true\s*\).*allowedOrigins\s*\(\s*\"\*\"",
        "message": "Credentials with wildcard origin is insecure. Specify allowed origins.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_jdbc_template_concat",
        "pattern": r'jdbcTemplate\s*\.\s*(?:query|update|execute)\s*\(\s*["\'].*\+',
        "message": "SQL string concatenation in JdbcTemplate. Use parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_security_debug_enabled",
        "pattern": r"@EnableWebSecurity\s*\(\s*debug\s*=\s*true\s*\)",
        "message": "Security debug mode enabled. Disable for production deployment.",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "spring_password_plaintext_config",
        "pattern": r"spring\.datasource\.password\s*=\s*\w+",
        "message": "Plaintext password in config. Use environment variables or vault.",
        "severity": Severity.BLOCK,
        "file_types": [".properties", ".yml", ".yaml"],
    },
    {
        "id": "spring_oauth2_no_state",
        "pattern": r"\.oauth2Login\s*\(\s*\)(?!.*state)",
        "message": "OAuth2 without state parameter invites CSRF. Ensure state is validated.",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "spring_jwt_no_signature_verify",
        "pattern": r"Jwts\s*\.\s*parser\s*\(\s*\)(?!.*\.setSigningKey)",
        "message": "JWT parsed without signature verification. Always verify signatures.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_no_method_security",
        "pattern": r"@RequestMapping.*\)\s*\n?\s*public\s+\S+\s+\w+.*(?!@PreAuthorize|@Secured|@RolesAllowed)",
        "message": "Endpoint without method-level security. Add @PreAuthorize or @Secured.",
        "severity": Severity.INFO,
        "file_types": [".java"],
    },
    {
        "id": "spring_open_redirect",
        "pattern": r'(?:redirect|sendRedirect)\s*\(\s*(?:request\.getParameter|params\.get)',
        "message": "Redirect with user input enables open redirect attacks. Validate URLs.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "spring_weak_password_encoder",
        "pattern": r"NoOpPasswordEncoder|MD5PasswordEncoder|ShaPasswordEncoder",
        "message": "Weak password encoder. Use BCryptPasswordEncoder or Argon2PasswordEncoder.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },

    # =================================================================
    #  .NET / C# SECURITY - 20 rules
    # =================================================================
    {
        "id": "csharp_hardcoded_connection_string",
        "pattern": r'(?:connectionString|ConnectionString)\s*=\s*["\'](?:Server|Data Source|Host)=',
        "message": "Hardcoded connection string. Use appsettings or environment variables.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_missing_authorize",
        "pattern": r"\[(?:Http(?:Get|Post|Put|Delete|Patch))\](?!\s*\n?\s*\[Authorize)",
        "message": "API endpoint without [Authorize]. Add authorization attribute.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_cors_allow_any_origin",
        "pattern": r"\.AllowAnyOrigin\s*\(\s*\)",
        "message": "CORS allows any origin. Restrict to specific domains.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_des_usage",
        "pattern": r"DESCryptoServiceProvider|TripleDESCryptoServiceProvider",
        "message": "DES/3DES are obsolete. Use AES with 256-bit keys.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_insecure_cookie",
        "pattern": r"(?:Secure|HttpOnly)\s*=\s*false",
        "message": "Cookie with Secure or HttpOnly disabled. Enable both for security.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_exception_details_response",
        "pattern": r"(?:app|services)\.UseDeveloperExceptionPage\s*\(",
        "message": "Developer exception page exposes stack traces. Disable in production.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_file_upload_no_validation",
        "pattern": r"IFormFile\s+\w+(?!.*(?:ContentType|Length|FileName.*Path\.GetExtension))",
        "message": "File upload without validation. Check size, type, and extension.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_jwt_no_validation",
        "pattern": r"ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false|ValidateLifetime\s*=\s*false",
        "message": "JWT validation disabled. Validate issuer, audience, and lifetime.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_regex_dos",
        "pattern": r'new\s+Regex\s*\([^)]*(?:\.\*){2,}',
        "message": "Complex regex may cause ReDoS. Use timeout or simpler patterns.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_dynamic_type",
        "pattern": r"\bdynamic\b\s+\w+\s*=",
        "message": "Dynamic type bypasses compile-time checks. Use explicit types.",
        "severity": Severity.WARN,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_hardcoded_api_key_attr",
        "pattern": r'\[ApiKey\s*\(\s*["\'][A-Za-z0-9]{16,}["\']\s*\)\]',
        "message": "Hardcoded API key in attribute. Load from configuration.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_insecure_ssl_protocol",
        "pattern": r"SslProtocols\.(?:Ssl3|Tls|Tls11)\b",
        "message": "Insecure SSL/TLS protocol. Use TLS 1.2 or higher.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },
    {
        "id": "csharp_unsafe_deserialization_json",
        "pattern": r"TypeNameHandling\.All|TypeNameHandling\.Auto|TypeNameHandling\.Objects",
        "message": "Insecure JSON TypeNameHandling enables deserialization attacks. Use None.",
        "severity": Severity.BLOCK,
        "file_types": [".cs"],
    },

    # =================================================================
    #  RUBY / RAILS SECURITY - 20 rules
    # =================================================================
    {
        "id": "rails_mass_assignment_permit_all",
        "pattern": r"\.permit!\s*$|params\.permit\s*\(\s*!",
        "message": "Mass assignment with permit! allows all params. Whitelist attributes.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_sql_interpolation",
        "pattern": r'\.where\s*\(\s*["\'].*#\{',
        "message": "SQL injection via string interpolation. Use parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_backtick_injection",
        "pattern": r"`.*#\{.*`",
        "message": "Command injection via backtick interpolation. Use shellescape.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_system_call_interpolation",
        "pattern": r'(?:system|exec|spawn)\s*\(\s*["\'].*#\{',
        "message": "Command injection via interpolation in system call. Use array form.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_raw_html",
        "pattern": r"\.html_safe\b|raw\s*\(",
        "message": "html_safe/raw bypasses XSS protection. Use sanitize helper instead.",
        "severity": Severity.WARN,
        "file_types": [".rb", ".erb"],
    },
    {
        "id": "rails_skip_before_action",
        "pattern": r"skip_before_action\s*:\s*(?:authenticate|verify|authorize)",
        "message": "Skipping auth before action. Ensure endpoint is intentionally public.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "rails_protect_from_forgery_except",
        "pattern": r"protect_from_forgery\s+except:",
        "message": "CSRF protection disabled for some actions. Verify this is intentional.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "rails_render_inline",
        "pattern": r"render\s+inline:\s*",
        "message": "Render inline can lead to template injection. Use template files.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "rails_send_method_user_input",
        "pattern": r"\.send\s*\(\s*params\[",
        "message": "Dynamic method dispatch with user input. Validate method names.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_constantize_user_input",
        "pattern": r"params\[.*\]\s*\.(?:constantize|safe_constantize)",
        "message": "Constantize with user input enables code injection. Use allowlist.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_find_by_sql_interpolation",
        "pattern": r'find_by_sql\s*\(\s*["\'].*#\{',
        "message": "SQL injection via find_by_sql interpolation. Use parameterized form.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_session_secret_hardcoded",
        "pattern": r'secret_key_base\s*=\s*["\'][A-Za-z0-9]{8,}',
        "message": "Hardcoded session secret. Use Rails credentials or env variable.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_weak_password_hash",
        "pattern": r"Digest::(?:MD5|SHA1)\.hexdigest",
        "message": "Weak hash for passwords. Use bcrypt via has_secure_password.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_cookie_no_httponly",
        "pattern": r"cookies\[.*\]\s*=\s*\{(?!.*httponly)",
        "message": "Cookie without httponly flag. Set httponly to prevent XSS theft.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },
    {
        "id": "ruby_open_uri_user_input",
        "pattern": r"(?:open|URI\.open)\s*\(\s*(?:params|request)",
        "message": "SSRF via open-uri with user input. Validate and restrict URLs.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
    },
    {
        "id": "rails_debug_mode_prod",
        "pattern": r"config\.consider_all_requests_local\s*=\s*true",
        "message": "Debug mode treats all requests as local. Disable in production.",
        "severity": Severity.WARN,
        "file_types": [".rb"],
    },

    # =================================================================
    #  PHP SECURITY - 20 rules
    # =================================================================
    {
        "id": "php_sql_injection_concat",
        "pattern": r'(?:mysql_query|mysqli_query|->query)\s*\(\s*["\'].*\.\s*\$_',
        "message": "SQL injection via concatenation. Use prepared statements.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "php_echo_xss",
        "pattern": r"echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\[",
        "message": "XSS via direct echo of user input. Use htmlspecialchars().",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "php_file_upload_no_check",
        "pattern": r"move_uploaded_file\s*\(\s*\$_FILES(?!.*(?:getimagesize|finfo|mime_content_type))",
        "message": "File upload without type validation. Check MIME type and extension.",
        "severity": Severity.WARN,
        "file_types": [".php"],
    },
    {
        "id": "php_extract_superglobal",
        "pattern": r"extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
        "message": "extract() with superglobals enables variable injection. Avoid extract.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "php_weak_random",
        "pattern": r"\b(?:rand|mt_rand|srand)\s*\(",
        "message": "Weak random number generator. Use random_int or random_bytes.",
        "severity": Severity.WARN,
        "file_types": [".php"],
    },
    {
        "id": "php_open_redirect",
        "pattern": r"header\s*\(\s*['\"]Location:\s*.*\$_(?:GET|POST|REQUEST)",
        "message": "Open redirect via user input. Validate redirect target.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "php_global_register",
        "pattern": r"register_globals\s*=\s*(?:On|1|true)",
        "message": "register_globals is dangerous. Use explicit superglobal access.",
        "severity": Severity.BLOCK,
        "file_types": [".php", ".ini"],
    },
    {
        "id": "php_xss_printf",
        "pattern": r"(?:printf|sprintf|vprintf)\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "XSS via printf with user input. Sanitize output with htmlspecialchars.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "php_allow_url_include",
        "pattern": r"allow_url_include\s*=\s*(?:On|1|true)",
        "message": "Remote file inclusion enabled. Disable allow_url_include.",
        "severity": Severity.BLOCK,
        "file_types": [".php", ".ini"],
    },

    # =================================================================
    #  SWIFT / iOS SECURITY - 15 rules
    # =================================================================
    {
        "id": "swift_insecure_url_session",
        "pattern": r"URLSessionConfiguration\.default(?!.*\.tlsMinimumSupportedProtocol)",
        "message": "Default URLSession may allow insecure connections. Set TLS minimum.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_hardcoded_key_plist",
        "pattern": r'(?:API_KEY|SECRET|TOKEN|PASSWORD)\s*</key>\s*\n?\s*<string>[^<]{8,}',
        "message": "Hardcoded key in plist. Use Keychain or secure configuration.",
        "severity": Severity.BLOCK,
        "file_types": [".plist"],
    },
    {
        "id": "swift_ats_disabled",
        "pattern": r"NSAllowsArbitraryLoads\s*</key>\s*\n?\s*<true",
        "message": "App Transport Security disabled. Enable ATS for secure connections.",
        "severity": Severity.BLOCK,
        "file_types": [".plist"],
    },
    {
        "id": "swift_keychain_no_access_control",
        "pattern": r"kSecAttrAccessible.*kSecAttrAccessibleAlways\b",
        "message": "Keychain item always accessible. Use afterFirstUnlock or whenUnlocked.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
    },
    {
        "id": "swift_no_certificate_pinning",
        "pattern": r"didReceive\s+challenge.*completionHandler\s*\(\s*\.useCredential",
        "message": "Accepting all SSL certificates. Implement certificate pinning.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_webview_js_enabled",
        "pattern": r"WKWebViewConfiguration\s*\(\s*\).*javaScriptEnabled\s*=\s*true",
        "message": "WebView JavaScript enabled. Disable unless required and sanitize content.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_print_sensitive",
        "pattern": r'(?i)print\s*\(\s*.*(?:password|token|secret|apiKey)',
        "message": "Logging sensitive data via print. Use os_log with privacy redaction.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_insecure_random",
        "pattern": r"\barc4random\s*\(\s*\)|drand48\s*\(",
        "message": "Non-cryptographic random. Use SecRandomCopyBytes for security.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_force_unwrap_network",
        "pattern": r"(?:URLResponse|Data)\s*!\s*",
        "message": "Force unwrapping network data risks crashes. Use safe unwrapping.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_clipboard_sensitive",
        "pattern": r"UIPasteboard\.general\.string\s*=.*(?:password|token|secret)",
        "message": "Sensitive data copied to clipboard. Other apps can access it.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
    },
    {
        "id": "swift_screenshot_no_protection",
        "pattern": r"applicationDidEnterBackground(?!.*makeSecure|willResignActive.*blur)",
        "message": "No screenshot protection. Obscure sensitive views in background.",
        "severity": Severity.INFO,
        "file_types": [".swift"],
    },
    {
        "id": "swift_biometric_no_fallback",
        "pattern": r"LAPolicy\.deviceOwnerAuthenticationWithBiometrics(?!.*deviceOwnerAuthentication\b)",
        "message": "Biometric auth without fallback. Provide passcode fallback option.",
        "severity": Severity.INFO,
        "file_types": [".swift"],
    },
    {
        "id": "swift_insecure_http_url",
        "pattern": r'URL\s*\(\s*string:\s*["\']http://',
        "message": "Insecure HTTP URL. Use HTTPS for all network requests.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
    },
    {
        "id": "swift_hardcoded_encryption_key",
        "pattern": r'(?:SymmetricKey|SecKey)\s*\(\s*data:\s*["\'][A-Za-z0-9+/=]{8,}',
        "message": "Hardcoded encryption key. Derive keys from Keychain or KDF.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
    },

    # =================================================================
    #  KOTLIN / ANDROID SECURITY - 15 rules
    # =================================================================
    {
        "id": "kotlin_shared_prefs_sensitive",
        "pattern": r'getSharedPreferences\s*\(.*(?:MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)',
        "message": "SharedPreferences with world-readable mode. Use MODE_PRIVATE.",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "android_insecure_network_config",
        "pattern": r"cleartextTrafficPermitted\s*=\s*[\"']true[\"']",
        "message": "Cleartext traffic allowed. Enforce HTTPS via network security config.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "kotlin_hardcoded_api_key",
        "pattern": r'(?:val|var)\s+(?:API_KEY|SECRET|TOKEN)\s*=\s*"[A-Za-z0-9]{8,}"',
        "message": "Hardcoded API key in Kotlin. Use BuildConfig or encrypted storage.",
        "severity": Severity.BLOCK,
        "file_types": [".kt"],
    },
    {
        "id": "android_backup_allowed",
        "pattern": r'android:allowBackup\s*=\s*["\']true["\']',
        "message": "App backup allowed. Disable or encrypt backups to protect user data.",
        "severity": Severity.WARN,
        "file_types": [".xml"],
    },
    {
        "id": "android_debuggable_true",
        "pattern": r'android:debuggable\s*=\s*["\']true["\']',
        "message": "Debuggable flag enabled. Disable for production builds.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "kotlin_log_sensitive",
        "pattern": r'Log\.(?:d|i|v|w|e)\s*\(\s*[^)]*(?:password|token|secret|apiKey)',
        "message": "Sensitive data in Android logs. Remove or redact before release.",
        "severity": Severity.WARN,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "kotlin_insecure_trust_manager",
        "pattern": r"X509TrustManager.*checkServerTrusted.*\{\s*\}|TrustAllCerts",
        "message": "Custom trust manager accepts all certificates. Validate properly.",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "android_intent_data_no_validation",
        "pattern": r"intent\.(?:getStringExtra|getData)\s*\((?!.*(?:require|check|valid))",
        "message": "Intent data used without validation. Validate all intent extras.",
        "severity": Severity.WARN,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "kotlin_weak_cipher",
        "pattern": r'Cipher\.getInstance\s*\(\s*["\'](?:DES|RC4|Blowfish|AES/ECB)',
        "message": "Weak cipher algorithm. Use AES/GCM/NoPadding for encryption.",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "android_broadcast_no_permission",
        "pattern": r"sendBroadcast\s*\(\s*\w+\s*\)(?!\s*,\s*\")",
        "message": "Broadcast without permission. Use LocalBroadcastManager or add permission.",
        "severity": Severity.WARN,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "kotlin_sql_raw_query",
        "pattern": r'rawQuery\s*\(\s*["\'].*\+|\$\{',
        "message": "Raw SQL query with interpolation. Use parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".kt", ".java"],
    },
    {
        "id": "android_provider_exported",
        "pattern": r'<provider[^>]*android:exported\s*=\s*["\']true["\'](?!.*android:readPermission)',
        "message": "Content provider exported without permissions. Add read/write permissions.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },

    # =================================================================
    #  REACT / NEXT.JS - 15 rules
    # =================================================================
    {
        "id": "react_dangerous_html_variable",
        "pattern": r"dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!sanitize|DOMPurify)",
        "message": "dangerouslySetInnerHTML without sanitization. Use DOMPurify.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "react_missing_key_map",
        "pattern": r"\.map\s*\(\s*(?:\([^)]*\)|[^=]*)\s*=>\s*(?:<\w+)(?!.*\bkey\s*=)",
        "message": "List element without key prop. Add unique key for reconciliation.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "react_useeffect_no_cleanup",
        "pattern": r"useEffect\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*(?:addEventListener|setInterval|subscribe)(?!.*return\s)",
        "message": "useEffect with subscription but no cleanup. Return cleanup function.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "react_uncontrolled_input",
        "pattern": r"<input(?!.*(?:value=|checked=|onChange=))(?!.*type=['\"](?:submit|button|hidden)['\"])",
        "message": "Uncontrolled input component. Add value and onChange for control.",
        "severity": Severity.INFO,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "nextjs_server_secret_leak",
        "pattern": r'(?:getServerSideProps|getStaticProps).*process\.env\.\w+.*return\s*\{.*props:',
        "message": "Server secret potentially leaked to client via props. Filter secrets.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "react_setstate_async_no_callback",
        "pattern": r"setState\s*\(\s*\{[^}]*\}\s*\)\s*;\s*(?:this\.state|console\.log.*state)",
        "message": "Reading state immediately after setState. Use callback or useEffect.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "react_memo_missing_comparison",
        "pattern": r"React\.memo\s*\(\s*\w+\s*\)(?!\s*,|\s*;)",
        "message": "React.memo without comparison function. Add custom areEqual if needed.",
        "severity": Severity.INFO,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "nextjs_api_no_method_check",
        "pattern": r"export\s+(?:default\s+)?(?:async\s+)?function\s+handler\s*\([^)]*\)\s*\{(?!.*req\.method)",
        "message": "Next.js API route without method check. Validate HTTP method.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "react_context_value_no_memo",
        "pattern": r"<\w+Provider\s+value=\{\s*\{(?!.*useMemo)",
        "message": "Context value as inline object causes re-renders. Use useMemo.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "react_fetch_no_error_boundary",
        "pattern": r"(?:useQuery|useSWR|fetch)\s*\((?!.*(?:ErrorBoundary|onError|error))",
        "message": "Data fetching without error handling. Add error boundary or handler.",
        "severity": Severity.INFO,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "nextjs_env_public_secret",
        "pattern": r"NEXT_PUBLIC_.*(?:SECRET|PASSWORD|PRIVATE_KEY|API_SECRET)",
        "message": "Secret in NEXT_PUBLIC_ env var is exposed to browser. Use server-only.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx", ".env"],
    },
    {
        "id": "react_usestate_object_spread",
        "pattern": r"set\w+\s*\(\s*\{.*\.\.\.(?:props|data)\s*\}",
        "message": "Spreading external data into state enables mass assignment. Pick fields.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },
    {
        "id": "react_href_javascript",
        "pattern": r'href\s*=\s*[{"\']javascript:',
        "message": "javascript: URL in href enables XSS. Use onClick handler instead.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "nextjs_revalidate_zero",
        "pattern": r"revalidate\s*:\s*0",
        "message": "Revalidate set to 0 disables ISR caching. Set appropriate TTL.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "react_window_location_assign",
        "pattern": r"window\.location\s*(?:\.href\s*)?=\s*(?:props|params|query|searchParams)",
        "message": "Open redirect via window.location. Validate redirect URL.",
        "severity": Severity.BLOCK,
        "file_types": [".jsx", ".tsx", ".js", ".ts"],
    },

    # =================================================================
    #  VUE.JS SECURITY - 10 rules
    # =================================================================
    {
        "id": "vue_v_html_directive",
        "pattern": r"v-html\s*=",
        "message": "v-html renders raw HTML risking XSS. Use v-text or sanitize content.",
        "severity": Severity.WARN,
        "file_types": [".vue"],
    },
    {
        "id": "vue_no_csrf_meta",
        "pattern": r"axios\.(?:post|put|patch|delete)\s*\((?!.*(?:csrf|xsrf|_token))",
        "message": "HTTP mutation without CSRF token. Include CSRF token in requests.",
        "severity": Severity.WARN,
        "file_types": [".vue", ".js", ".ts"],
    },
    {
        "id": "vue_prototype_pollution_computed",
        "pattern": r"computed:\s*\{[^}]*Object\.assign\s*\(\s*\{\s*\}\s*,\s*(?:this\.)?\$(?:route|store)",
        "message": "Object.assign in computed may enable prototype pollution. Use spread.",
        "severity": Severity.WARN,
        "file_types": [".vue"],
    },
    {
        "id": "vue_eval_template",
        "pattern": r"template\s*:\s*[`'\"].*\$\{",
        "message": "Template interpolation with dynamic content risks injection. Use props.",
        "severity": Severity.WARN,
        "file_types": [".vue", ".js", ".ts"],
    },
    {
        "id": "vue_v_on_dynamic",
        "pattern": r"v-on\s*=\s*['\"].*\$event",
        "message": "Dynamic event handler with $event. Validate event data before use.",
        "severity": Severity.INFO,
        "file_types": [".vue"],
    },
    {
        "id": "vue_router_no_guard",
        "pattern": r"(?:path|route):\s*['\"]\/admin(?!.*(?:beforeEnter|meta.*requiresAuth))",
        "message": "Admin route without navigation guard. Add auth check.",
        "severity": Severity.WARN,
        "file_types": [".vue", ".js", ".ts"],
    },
    {
        "id": "vue_localstorage_token",
        "pattern": r"localStorage\.setItem\s*\(\s*['\"](?:token|jwt|access_token|auth)",
        "message": "Storing auth token in localStorage is XSS-vulnerable. Use httpOnly cookies.",
        "severity": Severity.WARN,
        "file_types": [".vue", ".js", ".ts"],
    },
    {
        "id": "vue_innerhtml_ref",
        "pattern": r"\$refs\.\w+\.innerHTML\s*=",
        "message": "Setting innerHTML via $refs bypasses Vue sanitization. Use v-text.",
        "severity": Severity.BLOCK,
        "file_types": [".vue"],
    },
    {
        "id": "vue_component_is_dynamic",
        "pattern": r":is\s*=\s*['\"]?\s*(?:userInput|query|params)",
        "message": "Dynamic component from user input. Use allowlist of components.",
        "severity": Severity.BLOCK,
        "file_types": [".vue"],
    },
    {
        "id": "vue_no_key_v_for",
        "pattern": r"v-for\s*=\s*['\"](?!.*:key)",
        "message": "v-for without :key binding. Add unique key for DOM diffing.",
        "severity": Severity.WARN,
        "file_types": [".vue"],
    },

    # =================================================================
    #  ANGULAR SECURITY - 10 rules
    # =================================================================
    {
        "id": "angular_bypass_security_trust_html",
        "pattern": r"bypassSecurityTrustHtml\s*\(",
        "message": "bypassSecurityTrustHtml disables XSS protection. Sanitize content.",
        "severity": Severity.BLOCK,
        "file_types": [".ts"],
    },
    {
        "id": "angular_bypass_security_trust_url",
        "pattern": r"bypassSecurityTrustUrl\s*\(",
        "message": "bypassSecurityTrustUrl allows unsafe URLs. Validate URL scheme.",
        "severity": Severity.BLOCK,
        "file_types": [".ts"],
    },
    {
        "id": "angular_bypass_security_trust_script",
        "pattern": r"bypassSecurityTrustScript\s*\(",
        "message": "bypassSecurityTrustScript enables script injection. Avoid entirely.",
        "severity": Severity.BLOCK,
        "file_types": [".ts"],
    },
    {
        "id": "angular_bypass_security_trust_style",
        "pattern": r"bypassSecurityTrustStyle\s*\(",
        "message": "bypassSecurityTrustStyle allows CSS injection. Sanitize styles.",
        "severity": Severity.WARN,
        "file_types": [".ts"],
    },
    {
        "id": "angular_bypass_security_trust_resource_url",
        "pattern": r"bypassSecurityTrustResourceUrl\s*\(",
        "message": "bypassSecurityTrustResourceUrl enables resource loading attacks. Validate.",
        "severity": Severity.BLOCK,
        "file_types": [".ts"],
    },
    {
        "id": "angular_innerhtml_binding",
        "pattern": r"\[innerHTML\]\s*=\s*\"(?!sanitize|purify)",
        "message": "innerHTML binding without sanitization. Use DomSanitizer properly.",
        "severity": Severity.WARN,
        "file_types": [".html", ".ts"],
    },
    {
        "id": "angular_template_injection",
        "pattern": r"new\s+Function\s*\(|compile\s*\(\s*template",
        "message": "Dynamic template compilation enables injection. Use static templates.",
        "severity": Severity.BLOCK,
        "file_types": [".ts"],
    },
    {
        "id": "angular_http_no_interceptor",
        "pattern": r"HttpClient\.(?:get|post|put|delete)\s*\((?!.*(?:interceptor|withCredentials))",
        "message": "HTTP call without interceptor. Use interceptors for auth and error handling.",
        "severity": Severity.INFO,
        "file_types": [".ts"],
    },
    {
        "id": "angular_no_route_guard",
        "pattern": r"(?:path|route):\s*['\"]admin(?!.*(?:canActivate|authGuard))",
        "message": "Admin route without canActivate guard. Add authentication guard.",
        "severity": Severity.WARN,
        "file_types": [".ts"],
    },
    {
        "id": "angular_disable_sanitization",
        "pattern": r"SECURITY_CONTEXT.*NONE|sanitize.*=.*false",
        "message": "Sanitization disabled. Keep Angular sanitization enabled.",
        "severity": Severity.BLOCK,
        "file_types": [".ts"],
    },

    # =================================================================
    #  ELIXIR / PHOENIX - 10 rules
    # =================================================================
    {
        "id": "elixir_fragment_injection",
        "pattern": r'fragment\s*\(\s*["\'].*#\{',
        "message": "SQL injection via Ecto fragment interpolation. Use parameterized form.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "phoenix_insecure_cookie_config",
        "pattern": r"(?:secure|http_only):\s*false",
        "message": "Insecure cookie config. Set secure: true and http_only: true.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "phoenix_csrf_plug_disabled",
        "pattern": r"plug\s+:protect_from_forgery.*when\s+action\s+in",
        "message": "CSRF protection conditionally disabled. Apply to all mutation endpoints.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "phoenix_json_no_auth_plug",
        "pattern": r"pipeline\s*:api(?!.*plug.*(?:auth|authenticate|ensure_auth))",
        "message": "API pipeline without auth plug. Add authentication plug.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "elixir_system_cmd_interpolation",
        "pattern": r'System\.cmd\s*\(\s*["\'].*#\{',
        "message": "Command injection via System.cmd interpolation. Validate arguments.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "phoenix_secret_key_hardcoded",
        "pattern": r'secret_key_base\s*:\s*"[A-Za-z0-9+/=]{16,}"',
        "message": "Hardcoded secret key base. Use environment variable.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "elixir_code_eval_string",
        "pattern": r"Code\.eval_string\s*\(",
        "message": "Code.eval_string executes arbitrary code. Use compiled modules.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "phoenix_no_rate_limit",
        "pattern": r"post\s+[\"']/(?:login|signup|auth)(?!.*(?:rate_limit|throttle|hammer))",
        "message": "Auth endpoint without rate limiting. Add rate limiting plug.",
        "severity": Severity.WARN,
        "file_types": [".ex", ".exs"],
    },
    {
        "id": "elixir_port_open_user_input",
        "pattern": r"Port\.open\s*\(\s*\{:spawn,.*\+\+",
        "message": "Port.open with dynamic args. Validate all external command arguments.",
        "severity": Severity.BLOCK,
        "file_types": [".ex", ".exs"],
    },

    # =================================================================
    #  SCALA SECURITY - 10 rules
    # =================================================================
    {
        "id": "scala_xml_external_entity",
        "pattern": r"XML\.load\s*\(|SAXParserFactory(?!.*setFeature.*disallow-doctype)",
        "message": "XML parsing without disabling external entities. Disable DTD processing.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
    },
    {
        "id": "scala_process_exec_interpolation",
        "pattern": r'(?:Process|Runtime\.getRuntime)\s*\.?\s*(?:exec|!)\s*\(\s*s"',
        "message": "Process execution with string interpolation. Use Seq form of Process.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
    },
    {
        "id": "scala_insecure_random_gen",
        "pattern": r"(?:scala\.util\.Random|new\s+Random)\s*(?:\(\s*\))?(?!.*Secure)",
        "message": "Non-cryptographic random. Use java.security.SecureRandom.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
    },
    {
        "id": "scala_unfiltered_sql",
        "pattern": r'sql\s*".*\$\{(?!.*\#\{)',
        "message": "Unparameterized SQL interpolation. Use #$ for literal and # for params.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
    },
    {
        "id": "scala_hardcoded_secret_val",
        "pattern": r'(?:val|var)\s+(?:secret|apiKey|password|token)\s*=\s*"[^"]{8,}"',
        "message": "Hardcoded secret in Scala code. Use environment variables or vault.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
    },
    {
        "id": "scala_no_ssl_verification",
        "pattern": r"SSLContext\.getInstance.*TrustAll|setHostnameVerifier.*ALLOW_ALL",
        "message": "SSL verification disabled. Use proper certificate validation.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
    },
    {
        "id": "scala_serialization_unsafe",
        "pattern": r"ObjectInputStream\s*\(\s*",
        "message": "Java deserialization is unsafe. Use JSON or validated serialization.",
        "severity": Severity.BLOCK,
        "file_types": [".scala"],
    },
    {
        "id": "scala_reflect_invoke",
        "pattern": r"\.getDeclaredMethod\s*\(|classOf\s*\[.*\]\.getMethods",
        "message": "Reflection-based invocation. Validate method names against allowlist.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
    },
    {
        "id": "scala_plaintext_logging_creds",
        "pattern": r'(?:logger|log)\.\w+\s*\(.*(?:password|secret|token|credential)',
        "message": "Credentials in log output. Redact sensitive values before logging.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
    },
    {
        "id": "scala_catch_all_throwable",
        "pattern": r"catch\s*\{\s*case\s+_\s*:\s*Throwable\s*=>",
        "message": "Catching Throwable hides fatal errors. Catch specific exceptions.",
        "severity": Severity.WARN,
        "file_types": [".scala"],
    },

    # =================================================================
    #  GENERAL API SECURITY - 15 rules
    # =================================================================
    {
        "id": "api_no_ratelimit_response_header",
        "pattern": r"res\.(?:json|send)\s*\((?!.*(?:X-RateLimit|RateLimit-Remaining|Retry-After))",
        "message": "API response without rate limit headers. Include rate limit info.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "api_pagination_no_max_limit",
        "pattern": r"(?:limit|pageSize|per_page)\s*=\s*(?:req\.|params\.|query\.)(?!.*Math\.min|.*max\(|.*clamp)",
        "message": "Pagination limit from user input without cap. Enforce maximum limit.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "api_spread_assignment",
        "pattern": r"(?:Object\.assign|\.\.\.(?:req\.body|request\.data))\s*(?:\)|,)",
        "message": "Mass assignment via spread of request body. Pick specific fields.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "graphql_no_depth_limiter",
        "pattern": r"(?:ApolloServer|GraphQLServer|yoga)\s*\(\s*\{(?!.*(?:depthLimit|maxDepth|validationRules))",
        "message": "GraphQL server without depth limiting. Add depth limit validation.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "graphql_no_complexity_limit",
        "pattern": r"(?:ApolloServer|GraphQLServer)\s*\(\s*\{(?!.*(?:complexity|costAnalysis|costLimit))",
        "message": "GraphQL server without complexity analysis. Add query cost limiting.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "api_no_input_length_check",
        "pattern": r"(?:body|payload)\.\w+(?!.*(?:maxLength|max_length|\.length\s*[<>]|\.slice|\.substring))",
        "message": "String input without length validation. Add maximum length check.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "api_sensitive_data_query_param",
        "pattern": r"(?:req\.query|request\.args|params)\.\s*(?:password|token|secret|api_key)",
        "message": "Sensitive data in query params is logged in URLs. Use POST body.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "api_no_request_size_limit",
        "pattern": r"app\.use\s*\(\s*(?:express\.json|bodyParser\.json)\s*\(\s*\)(?!.*limit)",
        "message": "JSON body parser without size limit. Set limit to prevent DoS.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "api_cors_reflect_origin",
        "pattern": r"(?:origin|Access-Control-Allow-Origin)\s*[:=]\s*(?:req\.headers\.origin|request\.origin)",
        "message": "CORS reflects request origin. Use explicit allowlist of origins.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "api_no_helmet_headers",
        "pattern": r"app\.listen\s*\((?!.*helmet|.*security.*headers)",
        "message": "Server started without security headers. Use helmet or equivalent.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "api_jwt_algorithm_none",
        "pattern": r'(?:algorithms|algorithm)\s*[:=]\s*[\["\'](?:none|None)',
        "message": "JWT with algorithm none disables verification. Use HS256 or RS256.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "api_error_stack_in_response",
        "pattern": r"(?:res\.json|response\.json|jsonify)\s*\(\s*\{.*(?:stack|traceback|stackTrace)",
        "message": "Stack trace exposed in API response. Return generic error to clients.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "api_file_download_path_traversal",
        "pattern": r"(?:sendFile|send_file|download)\s*\(\s*(?:req|request)\.\w+",
        "message": "File path from user input enables path traversal. Validate and sandbox.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "api_no_content_security_policy",
        "pattern": r"res\.(?:render|sendFile)\s*\((?!.*(?:Content-Security-Policy|csp|helmet))",
        "message": "Serving HTML without CSP header. Add Content-Security-Policy.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "api_wildcard_method_handler",
        "pattern": r"app\.all\s*\(\s*['\"]\/",
        "message": "Wildcard method handler accepts all HTTP methods. Use specific methods.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },

    # =================================================================
    #  MICROSERVICE PATTERNS - 10 rules
    # =================================================================
    {
        "id": "microservice_no_circuit_breaker",
        "pattern": r"(?:axios|fetch|httpClient)\.\w+\s*\((?!.*(?:circuitBreaker|circuit_breaker|breaker|resilience))",
        "message": "External service call without circuit breaker. Add circuit breaker.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "microservice_retry_no_backoff",
        "pattern": r"(?:retry|retries)\s*[:=]\s*\d+(?!.*(?:backoff|exponential|delay|interval))",
        "message": "Retry without backoff may cause thundering herd. Add exponential backoff.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".java", ".go"],
    },
    {
        "id": "microservice_no_correlation_id",
        "pattern": r"(?:fetch|axios|httpClient)\.\w+\s*\(\s*['\"]https?://(?!.*(?:correlation|request.id|trace.id|x-request-id))",
        "message": "Inter-service call without correlation ID. Propagate trace context.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "microservice_sync_in_async",
        "pattern": r"(?:await|async).*(?:requests\.get|urllib\.urlopen|http\.request)\s*\(",
        "message": "Synchronous HTTP in async context blocks event loop. Use async client.",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "microservice_no_timeout",
        "pattern": r"(?:axios|fetch|httpClient|requests)\.\w+\s*\(\s*['\"]https?://[^)]*\)(?!.*timeout)",
        "message": "External call without timeout. Set explicit timeout to prevent hangs.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py"],
    },
    {
        "id": "microservice_shared_database",
        "pattern": r"(?:connect|createPool|DataSource)\s*\(.*(?:other_service|external_db|shared_db)",
        "message": "Direct access to another service database. Use API calls instead.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".java"],
    },
    {
        "id": "microservice_no_health_check",
        "pattern": r"app\.listen\s*\(\s*\d+(?!.*(?:health|ready|liveness|readiness))",
        "message": "Service without health check endpoint. Add /health or /ready.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "microservice_hardcoded_service_url",
        "pattern": r'(?:BASE_URL|SERVICE_URL|API_URL)\s*=\s*["\']https?://\d+\.\d+\.\d+\.\d+',
        "message": "Hardcoded service IP. Use service discovery or DNS names.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".java", ".go"],
    },
    {
        "id": "microservice_no_idempotency",
        "pattern": r"app\.post\s*\(\s*['\"]\/(?:payment|order|transaction)(?!.*(?:idempotency|idempotent))",
        "message": "Mutation endpoint without idempotency key. Add idempotency support.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "microservice_unbounded_queue",
        "pattern": r"(?:Queue|Channel|queue)\s*\((?!.*(?:maxSize|max_size|bounded|capacity|limit))",
        "message": "Unbounded queue can exhaust memory. Set maximum capacity.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".java", ".go"],
    },

    # =================================================================
    #  CLOUD PROVIDER SECURITY - 10 rules
    # =================================================================
    {
        "id": "aws_iam_wildcard_action",
        "pattern": r'"Action"\s*:\s*"\*"|"Action"\s*:\s*\[\s*"\*"\s*\]',
        "message": "IAM policy with wildcard Action. Follow least-privilege principle.",
        "severity": Severity.BLOCK,
        "file_types": [".json", ".tf", ".yaml", ".yml"],
    },
    {
        "id": "aws_iam_wildcard_resource",
        "pattern": r'"Resource"\s*:\s*"\*"',
        "message": "IAM policy with wildcard Resource. Scope to specific ARNs.",
        "severity": Severity.WARN,
        "file_types": [".json", ".tf", ".yaml", ".yml"],
    },
    {
        "id": "gcp_service_account_key_file",
        "pattern": r'(?:GOOGLE_APPLICATION_CREDENTIALS|service_account_key|gcp_credentials)\s*=\s*["\'][^"\']*\.json',
        "message": "GCP service account key file in code. Use workload identity federation.",
        "severity": Severity.WARN,
        "file_types": [".py", ".js", ".ts", ".yaml", ".yml", ".env"],
    },
    {
        "id": "azure_connection_string_code",
        "pattern": r'(?:DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)\s*=\s*[A-Za-z0-9+/=]{20,}',
        "message": "Azure connection string in code. Use managed identity or Key Vault.",
        "severity": Severity.BLOCK,
        "file_types": [".cs", ".py", ".js", ".ts", ".json"],
    },
    {
        "id": "aws_s3_public_acl",
        "pattern": r'(?:ACL|acl)\s*[:=]\s*["\']public-read(?:-write)?["\']',
        "message": "S3 bucket with public ACL. Use private ACL with presigned URLs.",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".js", ".ts", ".tf", ".json", ".yaml", ".yml"],
    },
    {
        "id": "cloud_hardcoded_credentials",
        "pattern": r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}',
        "message": "AWS access key ID in code. Use IAM roles or environment variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "aws_security_group_all_traffic",
        "pattern": r'(?:ingress|inbound).*(?:0\.0\.0\.0/0|::/0).*(?:from_port|FromPort)\s*[:=]\s*0',
        "message": "Security group allows all inbound traffic. Restrict to needed ports.",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".json", ".yaml", ".yml"],
    },
    {
        "id": "gcp_public_firewall_rule",
        "pattern": r'source_ranges\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "message": "GCP firewall allows all sources. Restrict to known IP ranges.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "azure_storage_shared_key",
        "pattern": r'AccountKey\s*=\s*[A-Za-z0-9+/=]{40,}',
        "message": "Azure storage account key in config. Use SAS tokens or managed identity.",
        "severity": Severity.BLOCK,
        "file_types": [".cs", ".py", ".js", ".ts", ".json", ".env"],
    },
    {
        "id": "cloud_unencrypted_storage",
        "pattern": r'(?:encryption|encrypted|server_side_encryption)\s*[:=]\s*(?:false|none|"none")',
        "message": "Cloud storage without encryption. Enable server-side encryption.",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".json", ".yaml", ".yml"],
    },
    # =================================================================
    #  PERFORMANCE ANTI-PATTERNS (perf_) - 25 rules
    # =================================================================

    {
        "id": "perf_n_plus_one_loop_query",
        "pattern": r"for\s+\w+\s+in\s+\w+\.(?:all|filter|objects).*:\s*\n\s*\w+\.(?:get|filter|select)",
        "message": "Potential N+1 query pattern. Use select_related/prefetch_related or batch fetching.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_missing_db_index_hint",
        "pattern": r"(?i)\.filter\(\s*\w+__(?:contains|icontains|startswith|endswith)\s*=",
        "message": "Text search filter without index hint. Add db_index=True or use full-text search.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_unbounded_list_append",
        "pattern": r"while\s+True\s*:.*\.append\(",
        "message": "Unbounded list growth in infinite loop. Add a size limit or use a bounded collection.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_string_concat_loop",
        "pattern": r"for\s+\w+\s+in\s+.*:\s*\n\s*\w+\s*\+=\s*['\"]",
        "message": "String concatenation in loop. Use str.join() or io.StringIO for better performance.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_redundant_rerender",
        "pattern": r"useEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*setState\s*\(",
        "message": "setState inside useEffect without dependency array may cause infinite re-renders.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "perf_global_regex_recompile",
        "pattern": r"def\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+re\.compile\(",
        "message": "Regex compiled inside function. Compile at module level to avoid repeated compilation.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_queryset_len",
        "pattern": r"len\(\s*\w+\.objects\.(?:all|filter)\(",
        "message": "Using len() on QuerySet fetches all rows. Use .count() instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_list_comprehension_side_effect",
        "pattern": r"\[\s*\w+\.\w+\(.*\)\s+for\s+\w+\s+in\s+.*\](?:\s*$|\s*#)",
        "message": "List comprehension used for side effects. Use a for loop instead to clarify intent.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_copy_deepcopy_in_loop",
        "pattern": r"for\s+\w+\s+in\s+.*:\s*\n\s*(?:copy\.deepcopy|deepcopy)\(",
        "message": "deepcopy inside loop is expensive. Consider restructuring to minimize copies.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_unnecessary_sort",
        "pattern": r"sorted\(.*\)\s*\[\s*(?:0|-1)\s*\]",
        "message": "Sorting entire collection to get min/max. Use min() or max() instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_repeated_dict_lookup",
        "pattern": r"if\s+\w+\s+in\s+(\w+)\s*:.*\n\s*\w+\s*=\s*\1\[\w+\]",
        "message": "Repeated dictionary lookup. Use dict.get() or try/except KeyError pattern.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_select_star_orm",
        "pattern": r"\.(?:raw|execute)\s*\(\s*['\"]SELECT\s+\*",
        "message": "SELECT * in raw query fetches unnecessary columns. Specify columns explicitly.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_synchronous_file_read_loop",
        "pattern": r"for\s+\w+\s+in\s+.*:\s*\n\s*(?:open|Path)\(.*\)\.read",
        "message": "Synchronous file reads in loop. Use async I/O or batch reading.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_json_dumps_in_loop",
        "pattern": r"for\s+\w+\s+in\s+.*:\s*\n\s*json\.dumps\(",
        "message": "json.dumps in loop. Consider batching serialization or using orjson.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_nested_loop_db_call",
        "pattern": r"for\s+\w+\s+in\s+.*:\s*\n\s+for\s+\w+\s+in\s+.*:\s*\n\s+.*\.(?:get|filter|save|create)\(",
        "message": "Database call inside nested loop creates O(n^2) queries. Use bulk operations.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "perf_large_response_no_stream",
        "pattern": r"requests\.(?:get|post)\([^)]+\)\.(?:content|text|json)\(\)",
        "message": "Large response loaded fully into memory. Use stream=True for large payloads.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_repeated_isinstance",
        "pattern": r"isinstance\(\s*\w+\s*,\s*\w+\s*\).*\n.*isinstance\(\s*\w+\s*,\s*\w+\s*\).*\n.*isinstance\(",
        "message": "Multiple isinstance checks. Use a tuple of types: isinstance(x, (A, B, C)).",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_orm_save_in_loop",
        "pattern": r"for\s+\w+\s+in\s+.*:\s*\n\s+\w+\.save\(\)",
        "message": "ORM .save() in loop issues N queries. Use bulk_update() or bulk_create().",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_expensive_default_arg",
        "pattern": r"def\s+\w+\(.*=\s*(?:list\(\)|dict\(\)|\[\]|\{\})",
        "message": "Mutable default argument. Use None and initialize inside the function.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_unindexed_foreign_key",
        "pattern": r"ForeignKey\([^)]+\)(?!.*db_index)",
        "message": "ForeignKey without explicit db_index. Django adds indexes by default but verify for custom setups.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_queryset_evaluate_twice",
        "pattern": r"(\w+\.objects\.\w+\([^)]*\))[^;]*\n.*\1",
        "message": "Same QuerySet evaluated twice. Cache the result in a variable.",
        "severity": Severity.WARN,
    },
    {
        "id": "perf_no_cache_expensive_call",
        "pattern": r"@(?:app|router)\.(?:get|post)\([^)]*\)\s*\n(?:(?!@cache|@lru_cache).)*def\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+await\s+\w+\.(?:fetch|get|query)\(",
        "message": "Expensive external call in endpoint without caching decorator. Consider adding cache.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_inline_lambda_sort",
        "pattern": r"\.sort\(\s*key\s*=\s*lambda\s+\w+\s*:\s*\w+\.\w+\).*\n.*\.sort\(",
        "message": "Multiple sort calls on same collection. Combine into single sort with tuple key.",
        "severity": Severity.INFO,
    },
    {
        "id": "perf_dataframe_iterrows",
        "pattern": r"\.iterrows\(\)\s*:",
        "message": "DataFrame.iterrows() is slow. Use vectorized operations or .itertuples().",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  ASYNC/CONCURRENCY ANTI-PATTERNS (async_) - 25 rules
    # =================================================================

    {
        "id": "async_deadlock_nested_lock",
        "pattern": r"async\s+with\s+\w+_lock\s*:.*\n(?:\s+.*\n)*?\s+async\s+with\s+\w+_lock\s*:",
        "message": "Nested async lock acquisition may cause deadlock. Use a single lock or ordered locking.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "async_race_condition_check_then_act",
        "pattern": r"if\s+(?:not\s+)?(?:await\s+)?\w+\.exists\(.*\).*:\s*\n\s*(?:await\s+)?\w+\.create\(",
        "message": "Check-then-act race condition. Use get_or_create or atomic upsert.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_missing_lock_shared_state",
        "pattern": r"(?:global|cls)\.\w+\s*(?:\+|-)=(?!.*(?:lock|mutex|semaphore))",
        "message": "Shared state modification without lock. Protect with asyncio.Lock or threading.Lock.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_fire_and_forget",
        "pattern": r"asyncio\.(?:ensure_future|create_task)\([^)]+\)(?!\s*\n\s*(?:await|try|result))",
        "message": "Fire-and-forget task without error handling. Store task reference and add done callback.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_blocking_call_in_async",
        "pattern": r"async\s+def\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+(?:time\.sleep|requests\.(?:get|post|put|delete))\(",
        "message": "Blocking call in async function. Use asyncio.sleep or httpx async client.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "async_bare_gather_no_return",
        "pattern": r"await\s+asyncio\.gather\([^)]+,\s*return_exceptions\s*=\s*True\s*\)(?!\s*\n\s*(?:for|if|result))",
        "message": "asyncio.gather with return_exceptions but results not checked for exceptions.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_thread_pool_no_limit",
        "pattern": r"ThreadPoolExecutor\(\s*\)(?!.*max_workers)",
        "message": "ThreadPoolExecutor without max_workers limit. Set explicit worker count.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_sync_io_in_event_loop",
        "pattern": r"async\s+def\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+open\(\s*['\"]",
        "message": "Synchronous file I/O in async function. Use aiofiles or run_in_executor.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_missing_timeout",
        "pattern": r"await\s+(?:(?:http_?)?client|session\(\)|\brequests\b|aiohttp|httpx|urllib)\.\s*(?:get|post|put|delete|patch|head|options|request|fetch)\s*\(",
        "special_handler": "check_async_timeout",
        "message": "Async HTTP call without timeout. Add explicit timeout to prevent hanging.",
        "severity": Severity.WARN,
        "suggestion": "Add timeout= parameter: await client.get(url, timeout=30).",
    },
    {
        "id": "async_unbounded_semaphore",
        "pattern": r"asyncio\.Semaphore\(\s*(?:1000|9999|\d{4,})\s*\)",
        "message": "Semaphore with very high limit provides no real concurrency control.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_missing_cancel_handler",
        "pattern": r"async\s+def\s+\w+.*:\s*\n\s+try\s*:\s*\n(?:(?!except\s+(?:asyncio\.)?CancelledError).)*(?:except\s+Exception)",
        "message": "Async function catches Exception but not CancelledError. Handle cancellation explicitly.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_shared_httpx_no_pool",
        "pattern": r"httpx\.AsyncClient\(\s*\)(?!.*limits)",
        "message": "AsyncClient without connection pool limits. Set httpx.Limits for production use.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_event_loop_get_running",
        "pattern": r"asyncio\.get_event_loop\(\)",
        "message": "Deprecated asyncio.get_event_loop(). Use asyncio.get_running_loop() in async context.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_run_nested",
        "pattern": r"asyncio\.run\((?!.*__main__)",
        "message": "asyncio.run() called outside __main__. Avoid nested event loops; use await instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_lock_not_in_context_manager",
        "pattern": r"\w+_lock\.acquire\(\)(?!.*finally.*release)",
        "message": "Lock acquired without context manager. Use 'async with lock:' to ensure release.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_global_client_no_close",
        "pattern": r"^\w+_client\s*=\s*httpx\.AsyncClient\(",
        "message": "Global async client without lifecycle management. Use lifespan handler for cleanup.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_task_exception_lost",
        "pattern": r"(?:loop|asyncio)\.create_task\([^)]+\)\s*$",
        "message": "Task created without storing reference. Exceptions will be silently lost.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_mixing_sync_async_orm",
        "pattern": r"async\s+def\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+\w+\.objects\.(?:get|filter|create|all)\(",
        "message": "Synchronous ORM call in async function. Use sync_to_async or async ORM.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "async_queue_no_maxsize",
        "pattern": r"asyncio\.Queue\(\s*\)",
        "message": "Unbounded asyncio.Queue. Set maxsize to prevent memory exhaustion.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_wait_first_completed_no_cancel",
        "pattern": r"asyncio\.wait\([^)]*return_when\s*=\s*FIRST_COMPLETED(?!.*cancel)",
        "message": "FIRST_COMPLETED without cancelling pending tasks causes resource leaks.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_generator_no_cleanup",
        "pattern": r"async\s+def\s+\w+.*:\s*\n(?:\s+.*\n)*?\s+yield\s+(?!.*finally)",
        "message": "Async generator without try/finally cleanup. Resources may leak on early exit.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_sleep_zero_spin",
        "pattern": r"while\s+.*:\s*\n\s+await\s+asyncio\.sleep\(\s*0\s*\)",
        "message": "Spinning with sleep(0) wastes CPU. Use asyncio.Event or Condition instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_subprocess_no_timeout",
        "pattern": r"await\s+asyncio\.create_subprocess_(?:exec|shell)\([^)]*\)(?!.*timeout)",
        "message": "Async subprocess without timeout. Add timeout to prevent zombie processes.",
        "severity": Severity.WARN,
    },
    {
        "id": "async_shield_misuse",
        "pattern": r"asyncio\.shield\(\s*\w+\s*\)(?!.*(?:try|except|cancel))",
        "message": "asyncio.shield without handling outer cancellation. Inner task continues unobserved.",
        "severity": Severity.INFO,
    },
    {
        "id": "async_daemon_thread_no_join",
        "pattern": r"Thread\([^)]*daemon\s*=\s*True[^)]*\)\.start\(\)(?!.*join)",
        "message": "Daemon thread started without join. May be killed mid-operation at process exit.",
        "severity": Severity.INFO,
    },

    # =================================================================
    #  AUTHENTICATION ANTI-PATTERNS (auth_) - 20 rules
    # =================================================================

    {
        "id": "auth_jwt_no_expiry",
        "pattern": r"jwt\.encode\([^)]*(?!.*exp['\"])",
        "message": "JWT created without expiry claim. Always set 'exp' to limit token lifetime.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_md5_password",
        "pattern": r"(?i)(?:hashlib\.md5|MD5)\s*\([^)]*(?:password|passwd|pwd)",
        "message": "MD5 for password hashing is cryptographically broken. Use bcrypt or argon2.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_sha1_password",
        "pattern": r"(?i)(?:hashlib\.sha1|SHA1)\s*\([^)]*(?:password|passwd|pwd)",
        "message": "SHA1 for password hashing is weak. Use bcrypt or argon2.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_missing_mfa_check",
        "pattern": r"def\s+(?:login|authenticate)\s*\([^)]*\).*:\s*\n(?:(?!mfa|totp|two_factor|2fa).)*return\s+(?:True|token|session)",
        "message": "Login function without MFA verification step. Add multi-factor authentication.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_session_token_in_url",
        "pattern": r"(?i)(?:url|href|redirect|location)\s*=.*[?&](?:token|session_id|auth|api_key)=",
        "message": "Session token in URL query parameter. Tokens in URLs leak via referer headers and logs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_oauth_no_state",
        "pattern": r"(?i)(?:oauth|authorize_url|authorization_endpoint).*(?:redirect|callback)(?!.*state=)",
        "message": "OAuth redirect without state parameter. Vulnerable to CSRF attacks.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_plaintext_password_storage",
        "pattern": r"(?i)(?:password|passwd|pwd)\s*=\s*(?:request|data|form|body)\.\w+(?!\s*.*(?:hash|bcrypt|argon|pbkdf|scrypt))",
        "message": "Password stored without hashing. Always hash passwords before storage.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_weak_jwt_algorithm",
        "pattern": r"jwt\.(?:encode|decode)\([^)]*algorithm\s*=\s*['\"](?:none|HS256)['\"]",
        "message": "Weak JWT algorithm. Use RS256 or ES256 for production systems.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_hardcoded_admin_password",
        "pattern": r"(?i)(?:admin|root|superuser).*(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]+['\"]",
        "message": "Hardcoded admin credentials. Use environment variables or secret manager.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_no_rate_limit_login",
        "pattern": r"@(?:app|router)\.post\s*\(\s*['\"](?:/login|/auth|/signin)['\"](?!.*(?:rate_limit|throttle|RateLimit))",
        "message": "Login endpoint without rate limiting. Add rate limiting to prevent brute force.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_password_in_log",
        "pattern": r"(?:log(?:ger)?|structlog|logging)\.\w+\([^)]*(?:password|passwd|pwd)\s*=(?!.*(?:mask|redact|\*+|hash))",
        "message": "Password logged. Never log passwords — hash or redact first.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_jwt_decode_no_verify",
        "pattern": r"jwt\.decode\([^)]*(?:verify\s*=\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False)",
        "message": "JWT decoded without signature verification. Always verify JWT signatures.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_cookie_no_samesite",
        "pattern": r"set_cookie\([^)]+\)(?!.*samesite)",
        "message": "Cookie set without SameSite attribute. Add SameSite=Lax or Strict for CSRF protection.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_remember_me_no_expiry",
        "pattern": r"(?i)remember_?me\s*[:=]\s*True(?!.*(?:expir|ttl|max_age))",
        "message": "Remember-me token without expiry. Set maximum lifetime for persistent sessions.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_password_min_length_low",
        "pattern": r"(?i)(?:min_?length|password.*len)\s*(?:>=?|==|<)\s*[1-7]\b",
        "message": "Password minimum length below 8 characters. NIST recommends minimum 8 characters.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_basic_auth_no_tls",
        "pattern": r"(?i)BasicAuth|Authorization.*Basic\s+(?!.*https)",
        "message": "Basic authentication should only be used over TLS/HTTPS.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_timing_attack_comparison",
        "pattern": r"(?:token|password|secret|hash)\s*==\s*(?:request|data|input|user)",
        "message": "Direct string comparison for secrets is timing-attack vulnerable. Use hmac.compare_digest.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_user_enumeration",
        "pattern": r"(?i)(?:user\s+not\s+found|email\s+not\s+registered|unknown\s+user|no\s+account)",
        "message": "Error message enables user enumeration. Use generic messages for auth failures.",
        "severity": Severity.WARN,
    },
    {
        "id": "auth_cors_credentials_wildcard",
        "pattern": r"(?i)(?:Access-Control-Allow-Origin.*\*.*credentials|allow_credentials\s*=\s*True.*allow_origins\s*=\s*\[?\s*['\"]?\*)",
        "message": "CORS with credentials and wildcard origin is a security risk. Specify allowed origins.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "auth_api_key_in_query",
        "pattern": r"(?i)(?:api_?key|access_?token)\s*=\s*(?:request\.(?:args|query|params)|params\[)",
        "message": "API key from query parameter. Use Authorization header to avoid key leakage in logs.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  SESSION MANAGEMENT ANTI-PATTERNS (session_) - 15 rules
    # =================================================================

    {
        "id": "session_fixation",
        "pattern": r"(?i)(?:session|sess)(?:_?id)?\s*=\s*(?:request|cookie|header)\.\w+(?!.*(?:regenerate|rotate|new_session))",
        "message": "Session ID from request used directly. Regenerate session ID after authentication.",
        "severity": Severity.WARN,
    },
    {
        "id": "session_missing_secure_flag",
        "pattern": r"set_cookie\([^)]*session[^)]*\)(?!.*(?:secure\s*=\s*True|secure=True))",
        "message": "Session cookie without Secure flag. Set Secure=True to prevent transmission over HTTP.",
        "severity": Severity.WARN,
    },
    {
        "id": "session_missing_httponly",
        "pattern": r"set_cookie\([^)]*session[^)]*\)(?!.*(?:httponly\s*=\s*True|httponly=True))",
        "message": "Session cookie without HttpOnly flag. Set HttpOnly=True to prevent XSS theft.",
        "severity": Severity.WARN,
    },
    {
        "id": "session_excessive_lifetime",
        "pattern": r"(?i)(?:session|cookie).*(?:max_age|expir(?:es|y))\s*[:=]\s*(?:86400{2,}|\d{7,})",
        "message": "Session lifetime exceeds 24 hours. Use shorter lifetimes with refresh tokens.",
        "severity": Severity.WARN,
    },
    {
        "id": "session_localstorage_token",
        "pattern": r"localStorage\.setItem\(\s*['\"](?:token|session|jwt|auth|access_token)",
        "message": "Session/auth token in localStorage is XSS-vulnerable. Use HttpOnly cookies instead.",
        "severity": Severity.WARN,
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "session_no_invalidation_logout",
        "pattern": r"def\s+logout\s*\([^)]*\).*:\s*\n(?:(?!(?:session|token).*(?:delete|invalidate|destroy|clear|revoke)).)*return",
        "message": "Logout without session invalidation. Destroy server-side session on logout.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "session_predictable_id",
        "pattern": r"(?i)session_?id\s*=\s*(?:str\(\s*\w+\s*\)|uuid\.uuid1|int\(time|hash\()",
        "message": "Predictable session ID generation. Use secrets.token_urlsafe or cryptographic RNG.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "session_data_in_cookie",
        "pattern": r"(?i)set_cookie\([^)]*(?:user_?id|role|admin|permissions|email)[^)]*\)",
        "message": "Sensitive data stored in cookie. Store only session ID in cookie; data on server.",
        "severity": Severity.WARN,
    },
    {
        "id": "session_no_ip_binding",
        "pattern": r"(?i)session\[.+\]\s*=.*(?:user|auth)(?!.*(?:ip|remote_addr|client_ip))",
        "message": "Session without IP binding. Consider binding sessions to client IP for extra security.",
        "severity": Severity.INFO,
    },
    {
        "id": "session_concurrent_no_limit",
        "pattern": r"def\s+(?:login|create_session)\s*\([^)]*\).*:\s*\n(?:(?!(?:concurrent|active).*(?:session|limit|max|count)).)*(?:session|token)\s*=",
        "message": "Login without concurrent session limit. Restrict maximum active sessions per user.",
        "severity": Severity.INFO,
    },
    {
        "id": "session_token_no_rotation",
        "pattern": r"(?i)def\s+(?:refresh|renew)\s*\([^)]*\).*:\s*\n(?:(?!(?:new|rotate|regenerate).*(?:token|session)).)*return\s+(?:token|session)",
        "message": "Token refresh without rotation. Issue new token and invalidate old one on refresh.",
        "severity": Severity.WARN,
    },
    {
        "id": "session_sessionstorage_sensitive",
        "pattern": r"sessionStorage\.setItem\(\s*['\"](?:token|jwt|password|secret|creditcard)",
        "message": "Sensitive data in sessionStorage is XSS-vulnerable. Use HttpOnly cookies.",
        "severity": Severity.WARN,
        "file_types": [".js", ".jsx", ".ts", ".tsx"],
    },
    {
        "id": "session_absolute_timeout_missing",
        "pattern": r"(?i)(?:session_config|SESSION)\s*=\s*\{(?:(?!absolute.*timeout|max_lifetime).)*\}",
        "message": "Session config without absolute timeout. Set maximum session lifetime regardless of activity.",
        "severity": Severity.INFO,
    },
    {
        "id": "session_cross_origin_leak",
        "pattern": r"(?i)(?:Access-Control-Allow-Origin|CORS).*\*.*(?:session|cookie|Set-Cookie)",
        "message": "Session cookies exposed to all origins via CORS wildcard. Restrict allowed origins.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "session_no_csrf_token",
        "pattern": r"@(?:app|router)\.post\([^)]*\)\s*\ndef\s+\w+.*:\s*\n(?:(?!csrf|csrftoken|_token|xsrf).)*$",
        "message": "POST endpoint without CSRF protection. Add CSRF token validation for state-changing operations.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  ADVANCED CRYPTO ANTI-PATTERNS (crypto2_) - 15 rules
    # =================================================================

    {
        "id": "crypto2_rsa_small_key",
        "pattern": r"(?i)RSA.*(?:generate|key_?size|bits)\s*[:=(]\s*(?:512|768|1024)\b",
        "message": "RSA key size below 2048 bits is insecure. Use minimum 2048 bits, prefer 4096.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_aes_cbc_no_hmac",
        "pattern": r"(?i)AES\.new\([^)]*CBC[^)]*\)(?!.*(?:HMAC|hmac|tag|digest|GCM))",
        "message": "AES-CBC without HMAC authentication. Use AES-GCM or add HMAC for integrity.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_reused_nonce",
        "pattern": r"(?i)(?:nonce|iv)\s*=\s*(?:b['\"][^'\"]+['\"]|bytes\(\s*\d+\s*\)|b'\\x00)",
        "message": "Static or hardcoded nonce/IV. Generate unique nonce per encryption operation.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_predictable_iv",
        "pattern": r"(?i)(?:iv|initialization_?vector)\s*=\s*(?:b['\"]|hashlib|str\.|int\.to_bytes)",
        "message": "Predictable IV detected. Use os.urandom() or secrets module for IV generation.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_no_key_rotation",
        "pattern": r"(?i)(?:ENCRYPTION_KEY|SECRET_KEY|MASTER_KEY)\s*=\s*['\"][^'\"]+['\"](?!.*(?:rotat|version|_v\d))",
        "message": "Static encryption key without rotation scheme. Implement key versioning and rotation.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto2_ecb_mode",
        "pattern": r"(?i)(?:AES|DES|Blowfish).*(?:ECB|MODE_ECB)",
        "message": "ECB mode leaks data patterns. Use CBC with random IV or GCM mode.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_des_usage",
        "pattern": r"(?i)(?:DES|3DES|TripleDES|DESede)\.(?:new|encrypt|decrypt)",
        "message": "DES/3DES is deprecated. Migrate to AES-256-GCM.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_weak_kdf_iterations",
        "pattern": r"(?i)(?:pbkdf2|PBKDF2).*iterations\s*[:=]\s*(?:[1-9]\d{0,4}|[1-9]\d{4})\b",
        "message": "PBKDF2 with less than 100000 iterations. OWASP recommends minimum 600000 for SHA-256.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto2_random_not_secure",
        "pattern": r"(?:random\.random|random\.randint|random\.choice)\(.*(?:key|token|secret|password|nonce|salt|iv)",
        "message": "Insecure random for cryptographic purpose. Use secrets module or os.urandom().",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_hardcoded_salt",
        "pattern": r"(?i)salt\s*=\s*(?:b['\"][^'\"]+['\"]|['\"][^'\"]+['\"]\.encode)",
        "message": "Hardcoded salt. Generate unique salt per password with os.urandom(16).",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_rc4_usage",
        "pattern": r"(?i)(?:ARC4|RC4|Arcfour)\.(?:new|encrypt)",
        "message": "RC4 is broken. Use AES-256-GCM for symmetric encryption.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_padding_oracle_risk",
        "pattern": r"(?i)except\s+(?:ValueError|PaddingError|InvalidPadding).*:\s*\n\s*(?:return|raise).*(?:invalid|bad|wrong).*(?:padding|decrypt)",
        "message": "Detailed padding error message enables padding oracle attacks. Return generic error.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto2_key_in_source",
        "pattern": r"(?:AES|RSA|Fernet)\s*\(\s*b?['\"][A-Za-z0-9+/=]{16,}['\"]",
        "message": "Encryption key hardcoded in source. Load from environment or key management service.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto2_md5_integrity",
        "pattern": r"(?:hashlib\.md5|MD5)\s*\([^)]*\)\.(?:hexdigest|digest)\(\).*(?:verify|check|compare|==)",
        "message": "MD5 for integrity verification is collision-prone. Use SHA-256 or SHA-3.",
        "severity": Severity.WARN,
    },
    {
        "id": "crypto2_missing_cert_validation",
        "pattern": r"(?i)(?:ssl|tls).*(?:verify\s*=\s*False|CERT_NONE|check_hostname\s*=\s*False)",
        "message": "Certificate validation disabled. Always verify TLS certificates in production.",
        "severity": Severity.BLOCK,
    },

    # =================================================================
    #  LOGGING SECURITY ANTI-PATTERNS (logging2_) - 15 rules
    # =================================================================

    {
        "id": "logging2_pii_in_log",
        "pattern": r"(?:log(?:ger)?|structlog|logging)\.\w+\(.*[\s,](?:email|phone|ssn|social_security|date_of_birth|credit_card)\s*=",
        "message": "PII in log output. Mask or exclude personal data from logs for GDPR/CCPA compliance.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "logging2_stack_trace_to_user",
        "pattern": r"(?:return|Response|JsonResponse)\s*\([^)]*(?:traceback|stacktrace|str\(e\)|repr\(e\))",
        "message": "Stack trace returned to user. Log internally and return sanitized error message.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "logging2_log_injection",
        "pattern": r"(?:log(?:ger)?|structlog)\.\w+\(\s*f?['\"].*\{(?:request|user_input|data|params)\.",
        "message": "Unsanitized user input in log message. Sanitize to prevent log injection attacks.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_missing_auth_audit",
        "pattern": r"def\s+(?:login|logout|register|change_password|reset_password)\s*\([^)]*\).*:\s*\n(?:(?!(?:log|audit|event|track|record)).)*return",
        "message": "Auth event without audit logging. Log all authentication events for security monitoring.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_debug_in_production",
        "pattern": r"(?i)(?:DEBUG\s*=\s*True|log_level\s*[:=]\s*['\"]?DEBUG|setLevel\(\s*(?:logging\.)?DEBUG\s*\))",
        "message": "Debug logging in production config. Use INFO or WARNING level in production.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_no_request_id",
        "pattern": r"(?:log(?:ger)?|structlog)\.\w+\([^)]*(?:error|exception|critical)[^)]*\)(?!.*(?:request_id|correlation_id|trace_id))",
        "message": "Error log without request/correlation ID. Add request ID for distributed tracing.",
        "severity": Severity.INFO,
    },
    {
        "id": "logging2_log_sensitive_header",
        "pattern": r"(?:log(?:ger)?|structlog)\.\w+\([^)]*(?:request\.headers|headers\[|Authorization|Cookie)",
        "message": "Sensitive headers logged. Filter out Authorization and Cookie headers from logs.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_no_rotation_config",
        "pattern": r"FileHandler\([^)]+\)(?!.*(?:RotatingFileHandler|TimedRotating|maxBytes))",
        "message": "File logging without rotation. Use RotatingFileHandler to prevent disk exhaustion.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_exception_swallowed",
        "pattern": r"except\s+\w+.*:\s*\n\s+(?:pass|\.\.\.)\s*$",
        "message": "Exception caught and swallowed. At minimum log the exception for debugging.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_sql_in_log",
        "pattern": r"(?:log(?:ger)?|structlog)\.\w+\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)\s+",
        "message": "Raw SQL logged. May expose sensitive data. Log query templates without values.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_ip_address_logged",
        "pattern": r"(?:log(?:ger)?|structlog)\.\w+\([^)]*(?:remote_addr|client_ip|ip_address|REMOTE_ADDR)",
        "message": "IP address in logs may be PII under GDPR. Hash or anonymize IP addresses.",
        "severity": Severity.INFO,
    },
    {
        "id": "logging2_no_timestamp",
        "pattern": r"logging\.basicConfig\([^)]*\)(?!.*(?:format|datefmt|asctime))",
        "message": "Logging without timestamp format. Include timestamps for incident investigation.",
        "severity": Severity.INFO,
    },
    {
        "id": "logging2_print_to_stderr",
        "pattern": r"print\([^)]*,\s*file\s*=\s*sys\.stderr",
        "message": "Print to stderr instead of proper logging. Use structured logging framework.",
        "severity": Severity.WARN,
    },
    {
        "id": "logging2_credential_in_url_log",
        "pattern": r"(?:log(?:ger)?|structlog)\.\w+\([^)]*(?:https?://\w+:\w+@|password=|secret=|key=)",
        "message": "Credentials in logged URL. Strip credentials from URLs before logging.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "logging2_no_structured_context",
        "pattern": r"logger\.(?:error|critical)\(\s*['\"].*%[sd]",
        "message": "Printf-style log formatting. Use structured logging with key-value pairs.",
        "severity": Severity.INFO,
    },

    # =================================================================
    #  NETWORK SECURITY ANTI-PATTERNS (net_) - 15 rules
    # =================================================================

    {
        "id": "net_tls_1_0",
        "pattern": r"(?i)(?:ssl\.PROTOCOL_TLSv1(?:_[01])?|TLSv1\.0|TLSv1\.1|SSLv[23]|TLS_1_0|TLS_1_1)",
        "message": "TLS 1.0/1.1 is deprecated and insecure. Use TLS 1.2 or higher.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "net_self_signed_cert",
        "pattern": r"(?i)(?:verify\s*=\s*False|CERT_NONE|verify_ssl\s*=\s*False|check_hostname\s*=\s*False)",
        "message": "Certificate verification disabled, accepting self-signed certs. Enable in production.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "net_dns_rebinding",
        "pattern": r"(?i)(?:0\.0\.0\.0|127\.0\.0\.1|localhost).*(?:host\s*=|bind\s*=|listen\s*\()(?!.*(?:debug|test|dev))",
        "message": "Binding to localhost/0.0.0.0 in production may enable DNS rebinding. Use specific interface.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_header_injection",
        "pattern": r"(?:response|headers)\[.*\]\s*=\s*(?:request|user_input|data|params)\.",
        "message": "User input in HTTP response header. Sanitize to prevent header injection (CRLF).",
        "severity": Severity.BLOCK,
    },
    {
        "id": "net_missing_hsts",
        "pattern": r"(?i)(?:app|server)\.\w+.*(?:https|tls|ssl)(?!.*(?:hsts|Strict-Transport-Security))",
        "message": "HTTPS configured without HSTS header. Add Strict-Transport-Security with includeSubDomains.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_open_redirect",
        "pattern": r"(?:redirect|RedirectResponse|HttpResponseRedirect)\(\s*(?:request|params|args)\.\w+",
        "message": "Open redirect vulnerability. Validate redirect URL against allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "net_ssrf_user_url",
        "pattern": r"(?:httpx|requests|urllib|aiohttp)\.(?:get|post|put|delete|fetch)\(\s*(?:request|user|data|params)\.\w+",
        "message": "Server-side request with user-supplied URL (SSRF risk). Validate against allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "net_websocket_no_auth",
        "pattern": r"@(?:app|router)\.websocket\([^)]*\)\s*\nasync\s+def\s+\w+.*:\s*\n(?:(?!auth|token|verify|authenticate).)*await\s+websocket\.accept",
        "message": "WebSocket endpoint without authentication. Verify identity before accepting connection.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_missing_csp",
        "pattern": r"(?i)(?:app|server)\.(?:add_middleware|use)\([^)]*(?:Security|Helmet)(?!.*content.security.policy)",
        "message": "Security middleware without Content-Security-Policy. Add CSP to prevent XSS.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_http_no_tls",
        "pattern": r"(?i)(?:base_url|api_url|endpoint)\s*[:=]\s*['\"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "message": "Non-localhost HTTP URL for API endpoint. Use HTTPS for all external connections.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_cors_allow_all",
        "pattern": r"(?i)(?:allow_origins\s*=\s*\[\s*['\"]?\*['\"]?\s*\]|Access-Control-Allow-Origin.*\*)",
        "message": "CORS allows all origins. Restrict to specific trusted domains.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_no_request_size_limit",
        "pattern": r"(?:app|server)\s*=\s*(?:FastAPI|Flask|Starlette)\([^)]*\)(?!.*(?:max.*size|limit|max_content))",
        "message": "Server without request size limit. Set max content length to prevent DoS.",
        "severity": Severity.INFO,
    },
    {
        "id": "net_proxy_trust_all",
        "pattern": r"(?i)(?:FORWARDED_ALLOW_IPS|proxy_headers|trust_proxy)\s*[:=]\s*['\"]?\*",
        "message": "Trusting all proxy headers. Restrict to known proxy IPs to prevent IP spoofing.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_graphql_introspection_prod",
        "pattern": r"(?i)(?:introspection|enable_introspection)\s*[:=]\s*True(?!.*(?:debug|dev|test))",
        "message": "GraphQL introspection enabled in production. Disable to prevent schema discovery.",
        "severity": Severity.WARN,
    },
    {
        "id": "net_missing_x_frame_options",
        "pattern": r"(?:app|server)\.(?:add_middleware|use)\([^)]*(?:Security|Helmet)(?!.*(?:x.frame|frame.options|clickjack))",
        "message": "Missing X-Frame-Options or frame-ancestors CSP. Add to prevent clickjacking.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  ADVANCED API ANTI-PATTERNS (api2_) - 15 rules
    # =================================================================

    {
        "id": "api2_missing_content_type_check",
        "pattern": r"@(?:app|router)\.(?:post|put|patch)\([^)]*\)\s*\n(?:async\s+)?def\s+\w+.*:\s*\n(?:(?!content.type|Content-Type|media_type).)*(?:request\.json|request\.body)",
        "message": "Reading request body without Content-Type validation. Verify Content-Type header.",
        "severity": Severity.WARN,
    },
    {
        "id": "api2_cors_reflect_origin",
        "pattern": r"(?i)(?:Access-Control-Allow-Origin|allow_origin)\s*[:=]\s*(?:request|origin|req)\.",
        "message": "CORS reflecting request origin is equivalent to wildcard. Use explicit allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "api2_no_versioning",
        "pattern": r"@(?:app|router)\.(?:get|post|put|delete)\(\s*['\"](?!/v\d|/api/v\d)(?:/\w+)+['\"]",
        "message": "API endpoint without version prefix. Add /v1/ prefix for backward compatibility.",
        "severity": Severity.INFO,
    },
    {
        "id": "api2_excessive_data_exposure",
        "pattern": r"\.(?:dict|model_dump|__dict__)\(\)(?!.*(?:include|exclude|by_alias))",
        "message": "Full model serialization without field filtering. Use include/exclude to limit exposure.",
        "severity": Severity.WARN,
    },
    {
        "id": "api2_broken_function_auth",
        "pattern": r"@(?:app|router)\.(?:get|post|put|delete)\(\s*['\"].*(?:admin|manage|config|internal)[^)]*\)\s*\n(?:(?!(?:Depends|auth|permission|role|admin)).)*def\s+\w+",
        "message": "Admin/management endpoint without authorization check. Add role-based access control.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "api2_mass_assignment",
        "pattern": r"(?:\*\*request\.(?:json|dict|body)|\.update\(\s*request\.(?:json|dict)\s*\))",
        "message": "Mass assignment from request data. Explicitly list allowed fields to prevent overwrite.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "api2_no_pagination_list",
        "pattern": r"@(?:app|router)\.get\([^)]*\)\s*\n(?:async\s+)?def\s+\w+.*:\s*\n(?:(?!(?:limit|offset|page|cursor|paginate)).)*return\s+\w+\.(?:all|find|select)\(",
        "message": "List endpoint without pagination. Add limit/offset to prevent large response payloads.",
        "severity": Severity.WARN,
    },
    {
        "id": "api2_no_response_model",
        "pattern": r"@(?:app|router)\.(?:get|post|put|delete)\([^)]*\)(?!.*response_model)\s*\n(?:async\s+)?def\s+",
        "message": "Endpoint without response_model. Define response schema to prevent data leaks.",
        "severity": Severity.INFO,
    },
    {
        "id": "api2_sql_filter_from_param",
        "pattern": r"(?:order_by|sort|filter)\(\s*(?:request|params|query)\.\w+\s*\)",
        "message": "SQL ordering/filtering from user parameter. Validate against allowlist of columns.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "api2_no_idempotency_key",
        "pattern": r"@(?:app|router)\.post\(\s*['\"].*(?:payment|charge|transfer|order)[^)]*\)(?!.*idempotency)",
        "message": "Financial endpoint without idempotency key. Add idempotency to prevent duplicate charges.",
        "severity": Severity.WARN,
    },
    {
        "id": "api2_missing_rate_limit",
        "pattern": r"@(?:app|router)\.(?:get|post)\(\s*['\"].*(?:search|export|download|report)[^)]*\)(?!.*(?:rate_limit|throttle))",
        "message": "Resource-intensive endpoint without rate limiting. Add throttling to prevent abuse.",
        "severity": Severity.INFO,
    },
    {
        "id": "api2_enum_not_validated",
        "pattern": r"(?:status|type|role|category)\s*[:=]\s*(?:request|params|query)\.\w+(?!.*(?:Enum|Literal|choices|validate))",
        "message": "Enum-like field from request without validation. Use Enum or Literal type for validation.",
        "severity": Severity.WARN,
    },
    {
        "id": "api2_delete_no_soft",
        "pattern": r"\.delete\(\).*(?:cascade|permanent|hard)(?!.*(?:soft|archive|deactivate))",
        "message": "Hard delete without soft delete option. Consider soft delete for data recovery.",
        "severity": Severity.INFO,
    },
    {
        "id": "api2_error_detail_leak",
        "pattern": r"(?:HTTPException|Response)\([^)]*detail\s*=\s*(?:str\(e\)|repr\(e\)|traceback)",
        "message": "Exception details in API error response. Return generic message; log details internally.",
        "severity": Severity.WARN,
    },
    {
        "id": "api2_file_upload_no_validation",
        "pattern": r"(?:UploadFile|file\.read|request\.files)(?!.*(?:content_type|size|extension|validate|MAX))",
        "message": "File upload without type/size validation. Validate content type and enforce size limits.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  CLOUD SECURITY ANTI-PATTERNS (cloud2_) - 15 rules
    # =================================================================

    {
        "id": "cloud2_s3_bucket_public",
        "pattern": r"(?i)(?:s3.*(?:policy|acl)|BucketPolicy|put_bucket_policy)\s*[^)]*(?:Principal.*\*|public-read|public-read-write)",
        "message": "S3 bucket policy allows public access. Restrict Principal to specific accounts.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cloud2_lambda_env_secret",
        "pattern": r"(?i)(?:lambda|serverless|function).*(?:environment|env).*(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\s*[:=]\s*['\"][^'\"]+['\"]",
        "message": "Secret in Lambda environment config. Use AWS Secrets Manager or Parameter Store.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cloud2_gcp_metadata_exposure",
        "pattern": r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal).*(?:token|key|secret)",
        "message": "GCP metadata endpoint access for secrets. Use workload identity or secret manager.",
        "severity": Severity.WARN,
    },
    {
        "id": "cloud2_azure_managed_identity_all",
        "pattern": r"(?i)(?:ManagedIdentity|DefaultAzureCredential)\(\)(?!.*(?:client_id|managed_identity_client_id))",
        "message": "Azure managed identity without specifying client ID. Use user-assigned identity explicitly.",
        "severity": Severity.INFO,
    },
    {
        "id": "cloud2_iam_admin_policy",
        "pattern": r"(?i)(?:Action|Effect).*(?:Allow).*(?:Resource).*\*.*(?:Action).*\*",
        "message": "IAM policy with admin-level access (Action:* Resource:*). Use least-privilege principle.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cloud2_storage_no_encryption",
        "pattern": r"(?i)(?:create_bucket|put_object|upload_file)\([^)]*\)(?!.*(?:encrypt|SSE|KMS|ServerSideEncryption))",
        "message": "Cloud storage operation without encryption. Enable server-side encryption.",
        "severity": Severity.WARN,
    },
    {
        "id": "cloud2_public_rds",
        "pattern": r"(?i)(?:PubliclyAccessible|publicly_accessible)\s*[:=]\s*True",
        "message": "Database instance publicly accessible. Keep databases in private subnets.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cloud2_security_group_all",
        "pattern": r"(?i)(?:SecurityGroup|security_group|ingress).*(?:0\.0\.0\.0/0|::/0).*(?:22|3389|5432|3306|27017)",
        "message": "Security group allows public access to sensitive ports. Restrict to specific IPs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cloud2_hardcoded_aws_region",
        "pattern": r"(?i)region\s*[:=]\s*['\"]us-east-1['\"](?!.*(?:config|env|settings|os\.environ))",
        "message": "Hardcoded AWS region. Use configuration or environment variable for region.",
        "severity": Severity.INFO,
    },
    {
        "id": "cloud2_sns_no_encryption",
        "pattern": r"(?i)(?:create_topic|SNS)\([^)]*\)(?!.*(?:KmsMasterKeyId|encrypt))",
        "message": "SNS topic without encryption. Enable KMS encryption for sensitive message data.",
        "severity": Severity.INFO,
    },
    {
        "id": "cloud2_sqs_no_dlq",
        "pattern": r"(?i)(?:create_queue|SQS)\([^)]*\)(?!.*(?:dead_letter|DeadLetterQueue|RedrivePolicy))",
        "message": "SQS queue without dead letter queue. Add DLQ to capture failed message processing.",
        "severity": Severity.WARN,
    },
    {
        "id": "cloud2_cloudwatch_no_alarm",
        "pattern": r"(?i)(?:Lambda|lambda_function|serverless)(?!.*(?:alarm|alert|monitor|CloudWatch))",
        "message": "Lambda function without CloudWatch alarm. Add error and duration alarms.",
        "severity": Severity.INFO,
    },
    {
        "id": "cloud2_s3_no_versioning",
        "pattern": r"(?i)create_bucket\([^)]*\)(?!.*(?:versioning|Versioning))",
        "message": "S3 bucket without versioning. Enable versioning for data protection and recovery.",
        "severity": Severity.INFO,
    },
    {
        "id": "cloud2_ecr_no_scan",
        "pattern": r"(?i)(?:create_repository|ECR)\([^)]*\)(?!.*(?:scan|imageScanningConfiguration|ScanOnPush))",
        "message": "ECR repository without image scanning. Enable scan-on-push for vulnerability detection.",
        "severity": Severity.WARN,
    },
    {
        "id": "cloud2_kms_key_rotation_disabled",
        "pattern": r"(?i)(?:create_key|KMS).*(?:EnableKeyRotation|enable_key_rotation)\s*[:=]\s*False",
        "message": "KMS key rotation disabled. Enable automatic key rotation for compliance.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  CONTAINER ADVANCED ANTI-PATTERNS (container2_) - 10 rules
    # =================================================================

    {
        "id": "container2_writable_rootfs",
        "pattern": r"(?i)(?:readOnlyRootFilesystem|read_only)\s*[:=]\s*(?:False|false)",
        "message": "Writable root filesystem in container. Set readOnlyRootFilesystem: true.",
        "severity": Severity.WARN,
    },
    {
        "id": "container2_missing_seccomp",
        "pattern": r"(?i)(?:securityContext|security_context)\s*:(?:(?!seccompProfile|seccomp).)*$",
        "message": "Container without seccomp profile. Add RuntimeDefault or custom seccomp profile.",
        "severity": Severity.INFO,
    },
    {
        "id": "container2_net_raw_capability",
        "pattern": r"(?i)(?:capabilities|cap_add).*(?:NET_RAW|net_raw)",
        "message": "NET_RAW capability enables packet spoofing. Drop unless specifically needed.",
        "severity": Severity.WARN,
    },
    {
        "id": "container2_host_pid_namespace",
        "pattern": r"(?i)(?:hostPID|pid_mode|pid\s*:\s*host)\s*[:=]\s*(?:True|true|['\"]host['\"])",
        "message": "Host PID namespace shared with container. Allows process inspection and signal sending.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "container2_privileged_mode",
        "pattern": r"(?i)(?:privileged|--privileged)\s*[:=]\s*(?:True|true)",
        "message": "Container in privileged mode has full host access. Remove privileged flag.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "container2_host_network",
        "pattern": r"(?i)(?:hostNetwork|network_mode)\s*[:=]\s*(?:True|true|['\"]host['\"])",
        "message": "Container using host network namespace. Use bridge or overlay network instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "container2_sys_admin_cap",
        "pattern": r"(?i)(?:capabilities|cap_add).*SYS_ADMIN",
        "message": "SYS_ADMIN capability is nearly equivalent to root. Remove and use specific caps.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "container2_no_resource_limits",
        "pattern": r"(?i)(?:containers|spec)\s*:(?:(?!(?:resources|limits|requests|memory|cpu)).)*image\s*:",
        "message": "Container without resource limits. Set CPU and memory limits to prevent resource abuse.",
        "severity": Severity.WARN,
    },
    {
        "id": "container2_latest_tag",
        "pattern": r"(?i)image\s*[:=]\s*['\"]?[a-z]+(?:/[a-z]+)?(?::latest|['\"]?\s*$)",
        "message": "Container image without specific tag or using :latest. Pin to specific version.",
        "severity": Severity.WARN,
    },
    {
        "id": "container2_root_user",
        "pattern": r"(?i)(?:runAsUser|user)\s*[:=]\s*(?:0|['\"]root['\"])",
        "message": "Container running as root. Set runAsNonRoot: true and specify non-root user.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  TESTING ANTI-PATTERNS (test2_) - 10 rules
    # =================================================================

    {
        "id": "test2_assert_in_production",
        "pattern": r"(?<!test_)(?<!_test)\.py.*\bassert\s+(?!isinstance)(?:\w+\s*[!=><]|\w+\s*(?:in|not|is)\s)",
        "message": "Assert statement in non-test code. Assertions are stripped with -O flag. Use explicit checks.",
        "severity": Severity.INFO,
    },
    {
        "id": "test2_credentials_in_test",
        "pattern": r"(?i)(?:password|api_key|secret|token)\s*=\s*['\"](?:admin123|password|test123|secret|12345|changeme)['\"]",
        "message": "Default/test credentials in code. Use fixture factories with random values.",
        "severity": Severity.WARN,
    },
    {
        "id": "test2_mock_overuse",
        "pattern": r"(?:@patch|@mock\.patch)\([^)]+\)\s*\n(?:@patch|@mock\.patch)\([^)]+\)\s*\n(?:@patch|@mock\.patch)\(",
        "message": "Three or more patches on single test. Excessive mocking may hide real integration bugs.",
        "severity": Severity.INFO,
    },
    {
        "id": "test2_sleep_in_test",
        "pattern": r"(?:time\.sleep|asyncio\.sleep)\(\s*\d+\s*\).*#.*(?:wait|flaky|timing|retry)",
        "message": "Sleep in test with timing comment indicates flaky test. Use polling or events.",
        "severity": Severity.WARN,
    },
    {
        "id": "test2_no_assertion",
        "pattern": r"def\s+test_\w+\s*\([^)]*\)\s*:\s*\n(?:(?!assert|expect|should|verify|mock.*called|raise).)*$",
        "message": "Test function without assertions. Every test must verify expected behavior.",
        "severity": Severity.WARN,
    },
    {
        "id": "test2_real_api_in_test",
        "pattern": r"(?:def\s+test_|class\s+Test).*\n(?:\s+.*\n)*?\s+(?:httpx|requests|urllib)\.(?:get|post|put|delete)\(\s*['\"]https?://(?!localhost|127\.0\.0\.1)",
        "message": "Test making real HTTP call to external service. Mock external dependencies.",
        "severity": Severity.WARN,
    },
    {
        "id": "test2_hardcoded_port",
        "pattern": r"(?:def\s+test_|class\s+Test).*\n(?:\s+.*\n)*?\s*['\"](?:http|https)://localhost:\d{4,5}",
        "message": "Hardcoded port in test. Use dynamic port allocation to avoid test conflicts.",
        "severity": Severity.INFO,
    },
    {
        "id": "test2_broad_exception_test",
        "pattern": r"with\s+pytest\.raises\(\s*Exception\s*\)",
        "message": "Catching generic Exception in test. Assert specific exception type.",
        "severity": Severity.WARN,
    },
    {
        "id": "test2_database_no_rollback",
        "pattern": r"(?:def\s+test_).*:\s*\n(?:\s+.*\n)*?\s+\w+\.(?:create|insert|save)\((?!.*(?:transaction|rollback|fixture|factory))",
        "message": "Test creates database records without rollback guarantee. Use transaction fixtures.",
        "severity": Severity.INFO,
    },
    {
        "id": "test2_random_without_seed",
        "pattern": r"(?:def\s+test_).*:\s*\n(?:\s+.*\n)*?\s+random\.(?:random|randint|choice)\((?!.*seed)",
        "message": "Random values in test without seed. Set seed for reproducibility.",
        "severity": Severity.INFO,
    },

    # =================================================================
    #  DEPENDENCY ANTI-PATTERNS (dep_) - 10 rules
    # =================================================================

    {
        "id": "dep_pinned_vulnerable",
        "pattern": r"(?i)(?:django|flask|fastapi|requests|urllib3|pillow|numpy|cryptography)==\d+\.\d+\.\d+(?!.*#.*(?:secure|reviewed|audited))",
        "message": "Exactly-pinned dependency without security review note. Verify version is not vulnerable.",
        "severity": Severity.INFO,
    },
    {
        "id": "dep_unused_import",
        "pattern": r"^import\s+\w+\s*;\s*#\s*(?:noqa|unused|TODO)",
        "message": "Potentially unused import flagged with noqa/unused. Remove if not needed.",
        "severity": Severity.INFO,
    },
    {
        "id": "dep_circular_import_hint",
        "pattern": r"(?:from|import)\s+\w+\.\w+\s+import\s+\w+.*#.*(?:circular|cycle|lazy)",
        "message": "Circular import workaround detected. Refactor to eliminate circular dependency.",
        "severity": Severity.WARN,
    },
    {
        "id": "dep_version_range_too_wide",
        "pattern": r"(?:install_requires|dependencies).*>=\s*\d+\.\d+(?!.*<)",
        "message": "Dependency with unbounded upper version. Add upper bound to prevent breaking changes.",
        "severity": Severity.INFO,
    },
    {
        "id": "dep_dev_in_production",
        "pattern": r"(?i)(?:install_requires|dependencies).*(?:pytest|mock|faker|factory.boy|coverage|debug.toolbar)",
        "message": "Development dependency in production requirements. Move to dev/test dependencies.",
        "severity": Severity.WARN,
    },
    {
        "id": "dep_multiple_http_clients",
        "pattern": r"import\s+(?:requests|httpx|urllib3|aiohttp).*\n(?:.*\n)*?import\s+(?:requests|httpx|urllib3|aiohttp)",
        "message": "Multiple HTTP client libraries imported. Standardize on one to reduce dependency surface.",
        "severity": Severity.INFO,
    },
    {
        "id": "dep_vendored_code",
        "pattern": r"# (?:vendored|copied|pasted) from (?:https?://|github\.com)",
        "message": "Vendored/copied code detected. Use proper package dependency for updates and security patches.",
        "severity": Severity.WARN,
    },
    {
        "id": "dep_sys_path_manipulation",
        "pattern": r"sys\.path\.(?:insert|append)\(",
        "message": "sys.path manipulation is fragile. Use proper package installation or relative imports.",
        "severity": Severity.WARN,
    },
    {
        "id": "dep_requirements_no_hash",
        "pattern": r"==\d+\.\d+\.\d+(?:\s*)$(?!.*--hash)",
        "message": "Pinned dependency without hash verification. Add --hash for supply chain security.",
        "severity": Severity.INFO,
        "file_types": [".txt"],
    },
    {
        "id": "dep_git_dependency",
        "pattern": r"(?i)(?:git\+https?://|git\+ssh://|egg=).*(?:@master|@main|@HEAD)",
        "message": "Git dependency on mutable branch. Pin to specific commit hash for reproducibility.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  ENCODING ANTI-PATTERNS (encoding_) - 5 rules
    # =================================================================

    {
        "id": "encoding_double_encode",
        "pattern": r"(?:urllib\.parse\.quote|encodeURIComponent|escape)\(.*(?:urllib\.parse\.quote|encodeURIComponent|escape)\(",
        "message": "Double URL encoding detected. This corrupts data and may bypass security filters.",
        "severity": Severity.WARN,
    },
    {
        "id": "encoding_mixed_decode",
        "pattern": r"\.decode\(\s*['\"](?:utf-8|ascii)['\"].*\.decode\(\s*['\"](?:latin|iso-8859|cp1252)",
        "message": "Mixed encoding in decode chain. Standardize on UTF-8 to prevent mojibake.",
        "severity": Severity.WARN,
    },
    {
        "id": "encoding_homoglyph_check",
        "pattern": r"['\"].*[\u0400-\u04ff\u0370-\u03ff].*[a-zA-Z].*['\"]",
        "message": "Possible homoglyph attack - mixed scripts in string literal. Verify character origins.",
        "severity": Severity.INFO,
    },
    {
        "id": "encoding_bom_in_string",
        "pattern": r"(?:\\xef\\xbb\\xbf|\\ufeff)",
        "message": "BOM (Byte Order Mark) in string. May cause invisible parsing issues.",
        "severity": Severity.INFO,
    },
    {
        "id": "encoding_base64_secret",
        "pattern": r"(?:b64decode|base64\.decode)\(\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
        "message": "Base64-encoded string decoded inline. If this is a secret, use proper secret management.",
        "severity": Severity.WARN,
    },

    # =================================================================
    #  CONFIG ANTI-PATTERNS (config2_) - 5 rules
    # =================================================================

    {
        "id": "config2_hardcoded_feature_flag",
        "pattern": r"(?i)(?:feature_flag|feature_enabled|is_feature)\s*[:=]\s*(?:True|False)(?!.*(?:env|config|settings|os\.environ))",
        "message": "Hardcoded feature flag. Use configuration service for runtime feature toggling.",
        "severity": Severity.WARN,
    },
    {
        "id": "config2_missing_circuit_breaker",
        "pattern": r"(?:while\s+True|for\s+\w+\s+in\s+range\(\d+\)).*(?:retry|attempt)(?!.*(?:circuit.breaker|CircuitBreaker|backoff|exponential))",
        "message": "Retry loop without circuit breaker. Add circuit breaker to prevent cascade failures.",
        "severity": Severity.WARN,
    },
    {
        "id": "config2_default_admin_creds",
        "pattern": r"(?i)(?:ADMIN|ROOT|SUPERUSER).*(?:USERNAME|USER)\s*[:=]\s*['\"]admin['\"]",
        "message": "Default admin username. Require custom admin credentials during setup.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "config2_debug_mode_production",
        "pattern": r"(?i)(?:DEBUG|TESTING|DEVELOPMENT)\s*[:=]\s*True(?!.*(?:if|when|test|dev|local))",
        "message": "Debug/testing mode enabled unconditionally. Guard with environment check.",
        "severity": Severity.WARN,
    },
    {
        "id": "config2_magic_number",
        "pattern": r"(?:sleep|timeout|retry|max_age|ttl|limit)\s*[:=]\s*(?:3600|86400|604800|2592000)(?!\s*#)",
        "message": "Uncommented magic number for time/limit constant. Extract to named constant with comment.",
        "severity": Severity.INFO,
    },

    # =================================================================
    #  DART / FLUTTER SECURITY (dart_, flutter_) - 20 rules
    # =================================================================

    {
        "id": "dart_insecure_http",
        "pattern": r"(?:Uri\.parse|http\.get|http\.post)\s*\(\s*['\"]http://",
        "message": "Insecure HTTP URL in Dart. Use HTTPS to prevent man-in-the-middle attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
    },
    {
        "id": "dart_disabled_ssl_verify",
        "pattern": r"(?:badCertificateCallback|onBadCertificate)\s*[:=]\s*\(\s*\w*\s*(?:,\s*\w*\s*)*\)\s*=>\s*true",
        "message": "SSL certificate verification disabled. Enables man-in-the-middle attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
    },
    {
        "id": "dart_eval_javascript",
        "pattern": r"(?:evaluateJavascript|runJavascriptReturningResult)\s*\(",
        "message": "JavaScript evaluation in WebView. Sanitize input to prevent XSS injection.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "dart_hardcoded_password",
        "pattern": r"(?:password|passwd|secret)\s*[:=]\s*['\"][^'\"]{4,}['\"]",
        "message": "Hardcoded password in Dart. Use secure storage (flutter_secure_storage).",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
    },
    {
        "id": "dart_shared_prefs_sensitive",
        "pattern": r"SharedPreferences.*(?:set(?:String|Int|Bool))\s*\(\s*['\"](?:token|password|secret|api_key)",
        "message": "Sensitive data in SharedPreferences. Use flutter_secure_storage instead.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
    },
    {
        "id": "dart_process_run",
        "pattern": r"Process\.(?:run|start)\s*\(",
        "message": "Direct process execution in Dart. Validate and sanitize all inputs to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "dart_sql_string_concat",
        "pattern": r"(?:rawQuery|rawInsert|rawUpdate|rawDelete)\s*\(\s*['\"].*\$",
        "message": "String interpolation in raw SQL query. Use parameterized queries to prevent injection.",
        "severity": Severity.BLOCK,
        "file_types": [".dart"],
    },
    {
        "id": "dart_no_null_check",
        "pattern": r"as\s+(?:String|int|double|bool)(?!\?)\s*;",
        "message": "Non-null cast without null check. Use null-aware cast (as Type?) with null handling.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_platform_channel_no_validation",
        "pattern": r"(?:MethodChannel|EventChannel)\s*\(\s*['\"].*['\"].*(?:invokeMethod|receiveBroadcastStream)(?!.*(?:validate|sanitize|check))",
        "message": "Platform channel call without input validation. Sanitize data crossing platform boundaries.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_webview_javascript_enabled",
        "pattern": r"WebView\s*\((?:[^)]*?)javascriptMode\s*:\s*JavascriptMode\.unrestricted",
        "message": "Unrestricted JavaScript in WebView. Restrict unless explicitly required and input is trusted.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_debug_print_sensitive",
        "pattern": r"(?:debugPrint|print|log)\s*\(.*(?:token|password|secret|key|credential)",
        "message": "Sensitive data in debug output. Remove or redact before release.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_no_error_widget",
        "pattern": r"ErrorWidget\.builder\s*=\s*\(\s*\w+\s*\)\s*=>\s*(?:Container|SizedBox)\s*\(",
        "message": "Custom error widget hides errors silently. Log errors to crash reporting service.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_hardcoded_url",
        "pattern": r"(?:baseUrl|BASE_URL|apiUrl)\s*[:=]\s*['\"]https?://(?!localhost|127\.0\.0\.1)",
        "message": "Hardcoded production URL. Use environment configuration for base URLs.",
        "severity": Severity.INFO,
        "file_types": [".dart"],
    },
    {
        "id": "dart_dynamic_type_usage",
        "pattern": r"(?:dynamic\s+\w+|Map<\s*dynamic\s*,\s*dynamic\s*>|List<\s*dynamic\s*>)",
        "message": "Dynamic type usage reduces type safety. Use explicit types for better compile-time checking.",
        "severity": Severity.INFO,
        "file_types": [".dart"],
    },
    {
        "id": "dart_deprecated_http_package",
        "pattern": r"import\s+['\"]package:http/",
        "message": "Consider using dio or chopper for production HTTP with interceptors, retry, and logging.",
        "severity": Severity.INFO,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_no_loading_state",
        "pattern": r"FutureBuilder\s*\((?:(?!(?:ConnectionState\.waiting|loading|CircularProgressIndicator))[\s\S]){0,200}\)",
        "message": "FutureBuilder without loading state handling. Show loading indicator for ConnectionState.waiting.",
        "severity": Severity.INFO,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_setState_async",
        "pattern": r"await\s+.*;\s*\n\s*setState\s*\(",
        "message": "setState after await without mounted check. Widget may be disposed; check mounted first.",
        "severity": Severity.WARN,
        "file_types": [".dart"],
    },
    {
        "id": "flutter_dispose_missing",
        "pattern": r"(?:AnimationController|TextEditingController|ScrollController|FocusNode)\s+\w+\s*=",
        "message": "Controller created without visible dispose. Ensure dispose() is called to prevent memory leaks.",
        "severity": Severity.INFO,
        "file_types": [".dart"],
    },

    # =================================================================
    #  R LANGUAGE (r_lang_) - 10 rules
    # =================================================================

    {
        "id": "r_lang_sql_paste_injection",
        "pattern": r"(?:dbGetQuery|dbSendQuery|sqlInterpolate)\s*\(.*paste\s*\(",
        "message": "SQL built with paste() in R. Use parameterized queries (dbBind) to prevent injection.",
        "severity": Severity.BLOCK,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_system_call",
        "pattern": r"(?:system|system2|shell)\s*\(",
        "message": "System command execution in R. Validate inputs to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_eval_parse",
        "pattern": r"eval\s*\(\s*parse\s*\(",
        "message": "eval(parse()) in R executes arbitrary code. Use safer alternatives like switch or match.arg.",
        "severity": Severity.BLOCK,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_insecure_download",
        "pattern": r"download\.file\s*\(.*method\s*=\s*['\"](?:internal|wget|curl)['\"](?!.*https)",
        "message": "Insecure file download in R. Specify HTTPS URL and verify checksums.",
        "severity": Severity.WARN,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_source_url",
        "pattern": r"source\s*\(\s*['\"]https?://",
        "message": "Sourcing R code from URL. Remote code could be tampered with; use local vetted scripts.",
        "severity": Severity.BLOCK,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_no_tryCatch",
        "pattern": r"(?:read\.csv|readRDS|readLines)\s*\([^)]+\)\s*$",
        "message": "File read without tryCatch. Wrap in tryCatch for graceful error handling.",
        "severity": Severity.INFO,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_setwd_hardcoded",
        "pattern": r"setwd\s*\(\s*['\"](?:/|[A-Z]:)",
        "message": "Hardcoded working directory path. Use relative paths or here::here() for portability.",
        "severity": Severity.WARN,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_rm_list",
        "pattern": r"rm\s*\(\s*list\s*=\s*ls\s*\(\s*\)\s*\)",
        "message": "rm(list=ls()) clears entire environment. Be selective about object removal.",
        "severity": Severity.INFO,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_assign_global",
        "pattern": r"<<-",
        "message": "Global assignment operator (<<-) in R. Avoid modifying global state; use return values.",
        "severity": Severity.WARN,
        "file_types": [".r", ".R"],
    },
    {
        "id": "r_lang_serialize_untrusted",
        "pattern": r"(?:unserialize|readRDS)\s*\(\s*(?:url|connection|rawConnection)",
        "message": "Deserializing from untrusted source. R serialization can execute arbitrary code.",
        "severity": Severity.BLOCK,
        "file_types": [".r", ".R"],
    },

    # =================================================================
    #  MATLAB (matlab_) - 8 rules
    # =================================================================

    {
        "id": "matlab_eval_usage",
        "pattern": r"(?:eval|evalc|evalin|feval)\s*\(\s*['\"]",
        "message": "eval() in MATLAB executes arbitrary code. Use direct function calls or switch statements.",
        "severity": Severity.BLOCK,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_system_call",
        "pattern": r"(?:system|dos|unix|perl)\s*\(",
        "message": "System command execution in MATLAB. Validate and escape all inputs.",
        "severity": Severity.WARN,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_hardcoded_path",
        "pattern": r"(?:addpath|cd|load|save)\s*\(\s*['\"](?:/|[A-Z]:)",
        "message": "Hardcoded absolute path in MATLAB. Use relative paths or fullfile() for portability.",
        "severity": Severity.WARN,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_insecure_webread",
        "pattern": r"webread\s*\(\s*['\"]http://",
        "message": "Insecure HTTP in MATLAB webread. Use HTTPS for secure data transfer.",
        "severity": Severity.WARN,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_empty_catch",
        "pattern": r"catch\s+\w+\s*\n\s*end",
        "message": "Empty catch block in MATLAB. Log or handle the error explicitly.",
        "severity": Severity.WARN,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_assignin_base",
        "pattern": r"assignin\s*\(\s*['\"]base['\"]",
        "message": "assignin to base workspace pollutes global state. Return values instead.",
        "severity": Severity.WARN,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_urlwrite_deprecated",
        "pattern": r"urlwrite\s*\(",
        "message": "urlwrite is deprecated and insecure. Use websave with weboptions for HTTPS support.",
        "severity": Severity.WARN,
        "file_types": [".m", ".mlx"],
    },
    {
        "id": "matlab_global_variable",
        "pattern": r"^\s*global\s+\w+",
        "message": "Global variable in MATLAB. Pass data explicitly as function arguments instead.",
        "severity": Severity.INFO,
        "file_types": [".m", ".mlx"],
    },

    # =================================================================
    #  HASKELL (haskell_) - 8 rules
    # =================================================================

    {
        "id": "haskell_unsafePerformIO",
        "pattern": r"unsafePerformIO",
        "message": "unsafePerformIO breaks referential transparency. Use IO monad properly.",
        "severity": Severity.BLOCK,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_head_empty_list",
        "pattern": r"(?:^|[^-])\bhead\s+(?!\$)",
        "message": "head on potentially empty list throws exception. Use pattern matching or headMay.",
        "severity": Severity.WARN,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_incomplete_pattern",
        "pattern": r"(?:case\s+\w+\s+of(?:(?!\n\s*_)[\s\S]){0,200})\n\s*\n",
        "message": "Case expression may have incomplete patterns. Add a wildcard (_) or cover all constructors.",
        "severity": Severity.WARN,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_unsafe_coerce",
        "pattern": r"unsafeCoerce",
        "message": "unsafeCoerce bypasses the type system. Use proper type conversions.",
        "severity": Severity.BLOCK,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_fromJust",
        "pattern": r"fromJust(?!\s*\.\s*lookup)",
        "message": "fromJust crashes on Nothing. Use maybe, fromMaybe, or pattern matching.",
        "severity": Severity.WARN,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_read_no_safe",
        "pattern": r"\bread\s+['\"]",
        "message": "read throws on invalid input. Use readMaybe or readEither for safe parsing.",
        "severity": Severity.WARN,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_error_call",
        "pattern": r"\berror\s+['\"]",
        "message": "error throws an unrecoverable exception. Use Either, Maybe, or MonadError for recoverable errors.",
        "severity": Severity.WARN,
        "file_types": [".hs", ".lhs"],
    },
    {
        "id": "haskell_unsafeIOToSTM",
        "pattern": r"unsafeIOToSTM",
        "message": "unsafeIOToSTM can violate STM invariants. Keep IO effects outside STM transactions.",
        "severity": Severity.BLOCK,
        "file_types": [".hs", ".lhs"],
    },

    # =================================================================
    #  ERLANG / ELIXIR ADVANCED (erlang_) - 8 rules
    # =================================================================

    {
        "id": "erlang_os_cmd",
        "pattern": r"os:cmd\s*\(",
        "message": "os:cmd executes shell commands. Validate inputs to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_binary_to_term_untrusted",
        "pattern": r"binary_to_term\s*\((?!.*safe)",
        "message": "binary_to_term with untrusted input can create atoms and exhaust memory. Use {safe, used} option.",
        "severity": Severity.BLOCK,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_list_to_atom",
        "pattern": r"list_to_atom\s*\(",
        "message": "list_to_atom creates atoms from untrusted input. Atoms are not garbage collected; use list_to_existing_atom.",
        "severity": Severity.WARN,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_apply_dynamic",
        "pattern": r"apply\s*\(\s*(?:Mod|Module|M)\s*,",
        "message": "Dynamic apply with user-controlled module. Whitelist allowed modules to prevent arbitrary code execution.",
        "severity": Severity.WARN,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_spawn_no_monitor",
        "pattern": r"\bspawn\s*\((?!.*(?:monitor|link|spawn_monitor))",
        "message": "spawn without monitor or link. Process failures will be silent; use spawn_monitor or spawn_link.",
        "severity": Severity.INFO,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_catch_all_pattern",
        "pattern": r"catch\s+_:_\s*->",
        "message": "Catch-all exception pattern hides errors. Catch specific exception classes.",
        "severity": Severity.WARN,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_hardcoded_cookie",
        "pattern": r"erlang:set_cookie\s*\(\s*\w+\s*,\s*['\"]",
        "message": "Hardcoded Erlang cookie. Use environment variable or config file for distributed auth.",
        "severity": Severity.BLOCK,
        "file_types": [".erl", ".hrl"],
    },
    {
        "id": "erlang_open_port_shell",
        "pattern": r"open_port\s*\(\s*\{spawn\s*,",
        "message": "open_port with spawn executes external commands. Validate input and prefer spawn_executable.",
        "severity": Severity.WARN,
        "file_types": [".erl", ".hrl"],
    },

    # =================================================================
    #  BUILD SYSTEM SECURITY (cmake_, make_, gradle2_, maven2_) - 20 rules
    # =================================================================

    {
        "id": "cmake_execute_process_injection",
        "pattern": r"execute_process\s*\(\s*COMMAND\s+.*\$\{",
        "message": "Variable expansion in CMake execute_process. Sanitize variables to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".cmake", ".txt"],
    },
    {
        "id": "cmake_insecure_download",
        "pattern": r"(?:file\s*\(\s*DOWNLOAD|ExternalProject_Add).*http://",
        "message": "Insecure HTTP download in CMake. Use HTTPS and verify checksums with EXPECTED_HASH.",
        "severity": Severity.BLOCK,
        "file_types": [".cmake", ".txt"],
    },
    {
        "id": "cmake_no_hash_verification",
        "pattern": r"file\s*\(\s*DOWNLOAD(?!.*(?:EXPECTED_HASH|EXPECTED_MD5|TLS_VERIFY))",
        "message": "CMake download without hash verification. Add EXPECTED_HASH to prevent tampering.",
        "severity": Severity.WARN,
        "file_types": [".cmake", ".txt"],
    },
    {
        "id": "cmake_add_custom_command_injection",
        "pattern": r"add_custom_command\s*\(.*COMMAND.*\$\{.*\}",
        "message": "Unsanitized variable in add_custom_command. Validate inputs to prevent build-time injection.",
        "severity": Severity.WARN,
        "file_types": [".cmake", ".txt"],
    },
    {
        "id": "cmake_disable_security_flags",
        "pattern": r"set\s*\(\s*CMAKE_(?:C|CXX)_FLAGS.*(?:-fno-stack-protector|-D_FORTIFY_SOURCE=0|-z\s+norelro)",
        "message": "Security compilation flags disabled. Keep stack protector and FORTIFY_SOURCE enabled.",
        "severity": Severity.BLOCK,
        "file_types": [".cmake", ".txt"],
    },
    {
        "id": "make_shell_injection",
        "pattern": r"\$\(shell\s+.*\$\(",
        "message": "Nested shell expansion in Makefile. Sanitize variables to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".mk"],
    },
    {
        "id": "make_curl_pipe_sh",
        "pattern": r"curl\s+.*\|\s*(?:sh|bash|zsh)",
        "message": "Piping curl to shell in Makefile. Download, verify, then execute separately.",
        "severity": Severity.BLOCK,
        "file_types": [".mk"],
    },
    {
        "id": "make_hardcoded_credentials",
        "pattern": r"(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*[:?]?=\s*[^\$\(]",
        "message": "Hardcoded credentials in Makefile. Use environment variables or secret management.",
        "severity": Severity.BLOCK,
        "file_types": [".mk"],
    },
    {
        "id": "make_chmod_777",
        "pattern": r"chmod\s+777",
        "message": "chmod 777 grants world-writable permissions. Use more restrictive permissions (755 or 644).",
        "severity": Severity.BLOCK,
        "file_types": [".mk"],
    },
    {
        "id": "make_rm_rf_root",
        "pattern": r"rm\s+-rf\s+/(?!\w)",
        "message": "Dangerous rm -rf / in Makefile. Use targeted paths with safeguards.",
        "severity": Severity.BLOCK,
        "file_types": [".mk"],
    },
    {
        "id": "gradle2_insecure_repo",
        "pattern": r"(?:maven|repository)\s*\{[^}]*url\s*['\"]http://",
        "message": "Insecure HTTP repository in Gradle. Use HTTPS to prevent dependency hijacking.",
        "severity": Severity.BLOCK,
        "file_types": [".gradle", ".gradle.kts"],
    },
    {
        "id": "gradle2_exec_command_injection",
        "pattern": r"(?:exec|commandLine)\s*\{[^}]*(?:args|commandLine).*\$",
        "message": "Variable interpolation in Gradle exec task. Sanitize inputs to prevent command injection.",
        "severity": Severity.WARN,
        "file_types": [".gradle", ".gradle.kts"],
    },
    {
        "id": "gradle2_allow_insecure_protocol",
        "pattern": r"allowInsecureProtocol\s*=\s*true",
        "message": "allowInsecureProtocol enables HTTP downloads. Use HTTPS repositories.",
        "severity": Severity.BLOCK,
        "file_types": [".gradle", ".gradle.kts"],
    },
    {
        "id": "gradle2_hardcoded_signing_key",
        "pattern": r"(?:signingKey|signing\.key|storePassword)\s*=\s*['\"][^'\"]{4,}['\"]",
        "message": "Hardcoded signing key in Gradle. Use gradle.properties or environment variables.",
        "severity": Severity.BLOCK,
        "file_types": [".gradle", ".gradle.kts"],
    },
    {
        "id": "gradle2_dynamic_version",
        "pattern": r"(?:implementation|api|compile)\s*['\"][^'\"]+:\+['\"]",
        "message": "Dynamic version (+) in Gradle dependency. Pin exact versions for reproducible builds.",
        "severity": Severity.WARN,
        "file_types": [".gradle", ".gradle.kts"],
    },
    {
        "id": "maven2_insecure_repo",
        "pattern": r"<url>\s*http://(?!localhost)",
        "message": "Insecure HTTP repository in Maven POM. Use HTTPS to prevent dependency hijacking.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "maven2_hardcoded_password",
        "pattern": r"<(?:password|passphrase)>[^$<{][^<]+</(?:password|passphrase)>",
        "message": "Hardcoded password in Maven settings. Use encrypted passwords or environment variables.",
        "severity": Severity.BLOCK,
        "file_types": [".xml"],
    },
    {
        "id": "maven2_snapshot_in_release",
        "pattern": r"<version>[^<]*-SNAPSHOT</version>(?!.*<!--.*(?:dev|test))",
        "message": "SNAPSHOT version dependency. Pin release versions for production builds.",
        "severity": Severity.WARN,
        "file_types": [".xml"],
    },
    {
        "id": "maven2_exec_plugin_injection",
        "pattern": r"<executable>.*\$\{",
        "message": "Variable in Maven exec plugin executable. Validate to prevent build-time injection.",
        "severity": Severity.WARN,
        "file_types": [".xml"],
    },
    {
        "id": "maven2_skip_tests",
        "pattern": r"<skipTests>true</skipTests>",
        "message": "Tests skipped in Maven configuration. Do not ship untested code.",
        "severity": Severity.WARN,
        "file_types": [".xml"],
    },

    # =================================================================
    #  BUNDLER SECURITY (webpack_, vite_, rollup_, esbuild_) - 15 rules
    # =================================================================

    {
        "id": "webpack_eval_devtool",
        "pattern": r"devtool\s*:\s*['\"](?:eval|cheap-eval|eval-source-map)['\"]",
        "message": "eval-based devtool in webpack. Use 'source-map' in production to avoid eval().",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "webpack_sourcemap_production",
        "pattern": r"devtool\s*:\s*['\"](?:source-map|hidden-source-map)['\"](?!.*(?:development|dev|test))",
        "message": "Source maps may expose source code in production. Use 'hidden-source-map' or disable.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "webpack_public_path_injection",
        "pattern": r"publicPath\s*:\s*(?:process\.env\.\w+|window\.\w+)",
        "message": "Dynamic publicPath from runtime variable. Validate to prevent script injection via path manipulation.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "webpack_disable_performance_hints",
        "pattern": r"performance\s*:\s*(?:false|\{\s*hints\s*:\s*false)",
        "message": "Performance hints disabled. Keep enabled to catch bundle size regressions.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "vite_sourcemap_prod",
        "pattern": r"build\s*:\s*\{[^}]*sourcemap\s*:\s*true",
        "message": "Source maps enabled in Vite production build. May expose source code.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "vite_server_open_host",
        "pattern": r"server\s*:\s*\{[^}]*host\s*:\s*['\"]0\.0\.0\.0['\"]",
        "message": "Vite dev server bound to all interfaces. Restrict to localhost in development.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "vite_define_injection",
        "pattern": r"define\s*:\s*\{[^}]*:\s*(?:process\.env|JSON\.stringify\s*\(\s*process\.env)",
        "message": "Exposing process.env via Vite define. Only expose specific, non-sensitive variables.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "vite_proxy_no_rewrite",
        "pattern": r"proxy\s*:\s*\{[^}]*target\s*:(?!.*(?:changeOrigin|rewrite))",
        "message": "Vite proxy without changeOrigin or rewrite. Configure properly to prevent request leaks.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "rollup_treeshake_disabled",
        "pattern": r"treeshake\s*:\s*false",
        "message": "Tree shaking disabled in Rollup. Increases bundle size with dead code.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "rollup_eval_plugin",
        "pattern": r"(?:transform|renderChunk)\s*\(.*\)\s*\{[^}]*\beval\s*\(",
        "message": "eval() in Rollup plugin. Use AST transformations instead of string evaluation.",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "rollup_external_all",
        "pattern": r"external\s*:\s*\(\s*\)\s*=>\s*true",
        "message": "All dependencies marked as external. Verify this is intentional for library builds.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "esbuild_minify_disabled_prod",
        "pattern": r"minify\s*:\s*false(?!.*(?:dev|development|test))",
        "message": "Minification disabled. Enable for production builds to reduce bundle size.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "esbuild_define_injection",
        "pattern": r"define\s*:\s*\{[^}]*:\s*['\"].*\$\{",
        "message": "Template literal in esbuild define. Ensure no user input reaches build-time definitions.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "esbuild_write_false_no_output",
        "pattern": r"write\s*:\s*false(?!.*(?:outputFiles|result))",
        "message": "esbuild write:false without handling outputFiles. Build output will be lost.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "esbuild_target_esnext",
        "pattern": r"target\s*:\s*['\"]esnext['\"]",
        "message": "esbuild target esnext may not be compatible with all browsers. Set explicit target.",
        "severity": Severity.INFO,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },

    # =================================================================
    #  ORM SECURITY (prisma_, typeorm_, sequelize_, mongoose_) - 25 rules
    # =================================================================

    {
        "id": "prisma_raw_query",
        "pattern": r"(?:\$queryRaw|queryRawUnsafe|executeRawUnsafe)\s*\(",
        "message": "Raw SQL query in Prisma. Use parameterized Prisma.sql or $queryRaw with template literals.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "prisma_raw_unsafe_interpolation",
        "pattern": r"(?:queryRawUnsafe|executeRawUnsafe)\s*\(\s*`",
        "message": "Template literal in Prisma unsafe query. Use Prisma.sql tagged template for parameterized queries.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "prisma_no_select",
        "pattern": r"\.findMany\s*\(\s*\)(?!.*(?:select|include))",
        "message": "findMany without select or include fetches all columns. Select only needed fields.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "prisma_no_pagination",
        "pattern": r"\.findMany\s*\(\s*\{(?:(?!(?:take|skip|cursor))[\s\S]){0,200}\}",
        "message": "findMany without pagination. Add take/skip or cursor to prevent loading entire tables.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "prisma_delete_many_no_where",
        "pattern": r"\.deleteMany\s*\(\s*\)",
        "message": "deleteMany without where clause deletes all records. Add explicit where filter.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "typeorm_raw_query",
        "pattern": r"(?:\.query|\.manager\.query)\s*\(\s*[`'\"](?:SELECT|INSERT|UPDATE|DELETE)",
        "message": "Raw SQL in TypeORM. Use QueryBuilder or Repository methods with parameter binding.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "typeorm_string_interpolation_query",
        "pattern": r"\.(?:query|createQueryBuilder)\s*\(.*\$\{",
        "message": "String interpolation in TypeORM query. Use parameter binding (:param) to prevent injection.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "typeorm_synchronize_production",
        "pattern": r"synchronize\s*:\s*true",
        "message": "TypeORM synchronize:true auto-modifies schema. Disable in production; use migrations.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "typeorm_no_transaction",
        "pattern": r"(?:\.save|\.insert|\.update|\.delete)\s*\((?!.*(?:transaction|queryRunner))",
        "message": "Multiple write operations without transaction. Use queryRunner.startTransaction for atomicity.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "typeorm_logging_all",
        "pattern": r"logging\s*:\s*true(?!.*(?:test|dev))",
        "message": "TypeORM full logging enabled. May expose sensitive data in queries. Use ['error', 'warn'] in prod.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "sequelize_raw_query",
        "pattern": r"\.query\s*\(\s*[`'\"](?:SELECT|INSERT|UPDATE|DELETE).*\$\{",
        "message": "String interpolation in Sequelize raw query. Use replacements or bind parameter.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "sequelize_mass_assignment",
        "pattern": r"\.create\s*\(\s*req\.body\s*\)",
        "message": "Passing req.body directly to Sequelize create. Use allowlist to prevent mass assignment.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "sequelize_force_sync",
        "pattern": r"\.sync\s*\(\s*\{\s*force\s*:\s*true",
        "message": "Sequelize force sync drops and recreates tables. Use migrations in production.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "sequelize_no_validation",
        "pattern": r"DataTypes\.STRING(?!\s*\(\s*\d+\s*\))",
        "message": "Sequelize STRING without length limit. Specify max length to prevent oversized inputs.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "sequelize_literal_injection",
        "pattern": r"sequelize\.literal\s*\(\s*[`'\"].*\$\{",
        "message": "Interpolation in sequelize.literal. Attacker can inject SQL through this path.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_where_injection",
        "pattern": r"\.\$where\s*\(\s*['\"]",
        "message": "$where in Mongoose executes JavaScript on the server. Use standard query operators instead.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_query_injection",
        "pattern": r"\.find\s*\(\s*req\.(?:body|query|params)\s*\)",
        "message": "Passing request data directly to Mongoose find. Sanitize to prevent NoSQL injection.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_no_schema_validation",
        "pattern": r"new\s+Schema\s*\(\s*\{(?:(?!(?:required|validate|min|max|enum|match))[\s\S]){0,300}\}",
        "message": "Mongoose schema without validation rules. Add required, validate, or constraints.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_select_password",
        "pattern": r"\.find\w*\s*\((?:(?!(?:select|\.select|-password))[\s\S]){0,200}\)",
        "message": "Query may return password field. Use select('-password') to exclude sensitive fields.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_lean_mutation",
        "pattern": r"\.lean\s*\(\s*\).*\.save\s*\(",
        "message": "Calling save() on lean document. Lean documents are plain objects without Mongoose methods.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "prisma_upsert_race",
        "pattern": r"\.upsert\s*\((?:(?!(?:transaction|\$transaction))[\s\S]){0,200}\)",
        "message": "Prisma upsert outside transaction may have race conditions. Wrap in $transaction for safety.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "typeorm_like_injection",
        "pattern": r"Like\s*\(\s*`\$\{",
        "message": "String interpolation in TypeORM Like(). Use parameter binding to prevent SQL injection.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "sequelize_operator_injection",
        "pattern": r"\[Op\.\w+\]\s*:\s*req\.",
        "message": "Sequelize operator with unsanitized request data. Validate and whitelist operator values.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_exec_no_catch",
        "pattern": r"\.exec\s*\(\s*\)(?!\s*\.(?:then|catch)|.*(?:await|try))",
        "message": "Mongoose exec() without error handling. Add catch() or use try/await.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "mongoose_mapReduce_injection",
        "pattern": r"\.mapReduce\s*\(",
        "message": "mapReduce executes JavaScript on MongoDB server. Use aggregation pipeline instead.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },

    # =================================================================
    #  MESSAGE QUEUE (kafka_, rabbitmq_) - 16 rules
    # =================================================================

    {
        "id": "kafka_no_auth",
        "pattern": r"(?:Kafka|KafkaClient|KafkaProducer)\s*\(\s*\{(?:(?!(?:sasl|ssl|security))[\s\S]){0,300}\}",
        "message": "Kafka client without authentication. Configure SASL/SSL for secure connections.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "kafka_no_tls",
        "pattern": r"(?:brokers|bootstrap[._]servers)\s*[:=]\s*['\"][^'\"]*:9092['\"]",
        "message": "Kafka on port 9092 (plaintext). Use 9093 with SSL for encrypted connections.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "kafka_no_dead_letter",
        "pattern": r"(?:eachMessage|consumer\.run)\s*\(\s*\{(?:(?!(?:deadLetter|dlq|DLQ|retry))[\s\S]){0,300}\}",
        "message": "Kafka consumer without dead letter queue. Failed messages will be lost or block the consumer.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "kafka_auto_commit",
        "pattern": r"(?:autoCommit|enable[._]auto[._]commit)\s*[:=]\s*true",
        "message": "Kafka auto-commit enabled. Use manual commit after processing for at-least-once delivery.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "kafka_no_idempotent",
        "pattern": r"(?:KafkaProducer|Producer)\s*\(\s*\{(?:(?!(?:idempotent|enable[._]idempotence))[\s\S]){0,300}\}",
        "message": "Kafka producer without idempotence. Enable for exactly-once delivery semantics.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "kafka_unbounded_consumer",
        "pattern": r"(?:maxBytes|fetch[._]max[._]bytes)\s*[:=]\s*(?:\d{8,})",
        "message": "Very large Kafka fetch size. Limit maxBytes to prevent out-of-memory errors.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "kafka_hardcoded_group_id",
        "pattern": r"groupId\s*:\s*['\"](?:test|default|group1)['\"]",
        "message": "Generic Kafka group ID. Use descriptive, environment-specific group IDs.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "kafka_no_schema_registry",
        "pattern": r"(?:produce|send)\s*\(\s*\{[^}]*value\s*:\s*JSON\.stringify",
        "message": "Kafka message without schema registry. Use Avro/Protobuf with schema registry for compatibility.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "rabbitmq_no_auth",
        "pattern": r"(?:amqp|amqps?)://guest:guest@",
        "message": "RabbitMQ using default guest credentials. Configure proper authentication.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "rabbitmq_no_tls",
        "pattern": r"amqp://(?!localhost|127\.0\.0\.1)",
        "message": "RabbitMQ without TLS (amqp:// not amqps://). Use amqps:// for encrypted connections.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "rabbitmq_no_dead_letter",
        "pattern": r"assertQueue\s*\(\s*[^,]+\s*,\s*\{(?:(?!(?:deadLetter|x-dead-letter))[\s\S]){0,200}\}",
        "message": "RabbitMQ queue without dead letter exchange. Configure x-dead-letter-exchange for failed messages.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "rabbitmq_no_prefetch",
        "pattern": r"(?:consume|subscribe)\s*\((?:(?!(?:prefetch|qos))[\s\S]){0,200}\)",
        "message": "RabbitMQ consumer without prefetch limit. Set prefetch to prevent memory exhaustion.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "rabbitmq_auto_ack",
        "pattern": r"(?:noAck|auto_ack)\s*[:=]\s*(?:true|True)",
        "message": "RabbitMQ auto-ack enabled. Messages are lost if consumer crashes. Use manual acknowledgment.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "rabbitmq_no_durable",
        "pattern": r"assertQueue\s*\(\s*[^,]+\s*,\s*\{[^}]*durable\s*:\s*false",
        "message": "Non-durable RabbitMQ queue. Messages are lost on broker restart. Use durable:true.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "rabbitmq_hardcoded_vhost",
        "pattern": r"(?:vhost|virtualHost)\s*[:=]\s*['\"/]['\"]",
        "message": "Hardcoded RabbitMQ vhost. Use configuration for environment-specific vhost.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js", ".py"],
    },
    {
        "id": "rabbitmq_no_confirm",
        "pattern": r"(?:publish|sendToQueue)\s*\((?:(?!(?:confirm|waitForConfirms))[\s\S]){0,200}\)",
        "message": "RabbitMQ publish without publisher confirms. Enable confirms for reliable delivery.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },

    # =================================================================
    #  GRPC ADVANCED (grpc2_) - 10 rules
    # =================================================================

    {
        "id": "grpc2_no_deadline",
        "pattern": r"(?:\.unary|\.serverStreaming|stub\.)\w+\s*\((?:(?!(?:deadline|timeout|wait_for_ready))[\s\S]){0,200}\)",
        "message": "gRPC call without deadline. Set deadline to prevent indefinite waiting.",
        "severity": Severity.WARN,
        "file_types": [".py", ".go", ".java"],
    },
    {
        "id": "grpc2_no_interceptor",
        "pattern": r"(?:grpc\.server|grpc\.insecure_channel)\s*\((?:(?!(?:interceptor|interceptors))[\s\S]){0,200}\)",
        "message": "gRPC server/channel without interceptors. Add interceptors for logging, auth, and metrics.",
        "severity": Severity.INFO,
        "file_types": [".py", ".go", ".java"],
    },
    {
        "id": "grpc2_insecure_channel",
        "pattern": r"grpc\.insecure_channel\s*\(\s*['\"](?!localhost|127\.0\.0\.1|\\[::1\\])",
        "message": "Insecure gRPC channel to non-local host. Use grpc.secure_channel with TLS credentials.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_no_retry_policy",
        "pattern": r"(?:grpc\.(?:secure_channel|insecure_channel))\s*\((?:(?!(?:retry|service_config))[\s\S]){0,200}\)",
        "message": "gRPC channel without retry policy. Configure service_config with retryPolicy for resilience.",
        "severity": Severity.INFO,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_unbounded_stream",
        "pattern": r"def\s+\w+\s*\(\s*self\s*,\s*request_iterator(?:(?!(?:timeout|max_count|limit))[\s\S]){0,200}:",
        "message": "gRPC streaming RPC without bounds. Add message count or time limits to prevent resource exhaustion.",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_no_health_check",
        "pattern": r"grpc\.server\s*\((?:(?!(?:health|HealthServicer))[\s\S]){0,300}\)",
        "message": "gRPC server without health check service. Add grpc_health for proper load balancer integration.",
        "severity": Severity.INFO,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_large_message_no_limit",
        "pattern": r"grpc\.(?:server|insecure_channel|secure_channel)\s*\((?:(?!(?:max_receive_message_length|max_send_message_length))[\s\S]){0,300}\)",
        "message": "gRPC without message size limits. Set max_receive/send_message_length to prevent memory issues.",
        "severity": Severity.INFO,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_plaintext_metadata",
        "pattern": r"metadata\s*=\s*\[\s*\(\s*['\"](?:authorization|token|api-key)['\"]",
        "message": "Sensitive metadata in gRPC call. Ensure channel uses TLS to protect metadata in transit.",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_no_graceful_shutdown",
        "pattern": r"server\.stop\s*\(\s*0\s*\)",
        "message": "gRPC server stop(0) does not wait for in-flight RPCs. Use stop(grace_period) for graceful shutdown.",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },
    {
        "id": "grpc2_reflection_enabled",
        "pattern": r"(?:enable_server_reflection|add_ServerReflection)",
        "message": "gRPC reflection enabled. Disable in production to prevent service enumeration.",
        "severity": Severity.WARN,
        "file_types": [".py"],
    },

    # =================================================================
    #  GRAPHQL ADVANCED (graphql2_) - 15 rules
    # =================================================================

    {
        "id": "graphql2_no_depth_limit",
        "pattern": r"(?:ApolloServer|createServer|graphqlHTTP)\s*\(\s*\{(?:(?!(?:depthLimit|depth|maxDepth))[\s\S]){0,300}\}",
        "message": "GraphQL server without query depth limit. Add depthLimit to prevent deeply nested query attacks.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_no_cost_analysis",
        "pattern": r"(?:ApolloServer|createServer)\s*\(\s*\{(?:(?!(?:costAnalysis|costLimit|queryComplexity))[\s\S]){0,300}\}",
        "message": "GraphQL without query cost analysis. Add cost limit to prevent expensive query abuse.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_introspection_enabled",
        "pattern": r"introspection\s*:\s*true(?!.*(?:dev|development|test))",
        "message": "GraphQL introspection enabled in production. Disable to prevent schema enumeration.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_no_rate_limit",
        "pattern": r"(?:ApolloServer|createServer)\s*\(\s*\{(?:(?!(?:rateLimit|rateLimiting|throttle))[\s\S]){0,300}\}",
        "message": "GraphQL without rate limiting. Add per-client rate limits to prevent abuse.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_resolver_no_auth",
        "pattern": r"(?:Query|Mutation)\s*:\s*\{[^}]*\w+\s*:\s*(?:async\s+)?(?:\(\s*(?:parent|root|_)\s*,\s*args)(?!.*(?:auth|context\.user|isAuthenticated))",
        "message": "GraphQL resolver without authentication check. Verify user context before resolving.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_subscription_no_auth",
        "pattern": r"Subscription\s*:\s*\{[^}]*subscribe\s*:(?:(?!(?:auth|token|context\.user))[\s\S]){0,200}",
        "message": "GraphQL subscription without authentication. Validate credentials in onConnect or subscribe.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_n_plus_one",
        "pattern": r"(?:resolve|fieldResolver)\s*[:=].*(?:\.find|\.findOne|\.get)\s*\((?:(?!(?:DataLoader|dataloader|batch))[\s\S]){0,200}\)",
        "message": "Possible N+1 query in GraphQL resolver. Use DataLoader for batching and caching.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_union_no_resolveType",
        "pattern": r"(?:UnionType|GraphQLUnionType)\s*\(\s*\{(?:(?!(?:resolveType|__resolveType))[\s\S]){0,200}\}",
        "message": "GraphQL union type without resolveType. Runtime may incorrectly resolve the type.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_error_leak",
        "pattern": r"formatError\s*:\s*\(\s*\w+\s*\)\s*=>\s*\w+",
        "message": "GraphQL formatError may leak internal details. Sanitize error messages for clients.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_upload_no_limit",
        "pattern": r"(?:graphqlUpload|Upload)\s*\((?:(?!(?:maxFileSize|maxFiles))[\s\S]){0,200}\)",
        "message": "GraphQL file upload without size limit. Set maxFileSize to prevent denial of service.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_persisted_query_bypass",
        "pattern": r"persistedQueries\s*:\s*false",
        "message": "Persisted queries disabled. Enable to prevent arbitrary query execution in production.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_no_validation_rules",
        "pattern": r"(?:ApolloServer|createServer)\s*\(\s*\{(?:(?!(?:validationRules))[\s\S]){0,300}\}",
        "message": "GraphQL without custom validation rules. Add rules to enforce query constraints.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_debug_enabled",
        "pattern": r"debug\s*:\s*true(?!.*(?:dev|development|test|NODE_ENV))",
        "message": "GraphQL debug mode enabled. Stack traces and internal info may leak to clients.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_batch_no_limit",
        "pattern": r"(?:allowBatchedHttpRequests|batch)\s*:\s*true(?!.*(?:maxBatch|limit))",
        "message": "GraphQL batching enabled without limit. Set maxBatchSize to prevent batch abuse.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "graphql2_cors_wildcard",
        "pattern": r"cors\s*:\s*(?:true|\{\s*origin\s*:\s*['\"]\\*['\"])",
        "message": "GraphQL CORS allows all origins. Restrict to specific trusted domains.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },

    # =================================================================
    #  WEBSOCKET ADVANCED (websocket2_) - 10 rules
    # =================================================================

    {
        "id": "websocket2_no_heartbeat",
        "pattern": r"(?:WebSocket|ws\.Server|socketio)\s*\(\s*\{(?:(?!(?:ping|heartbeat|keepAlive))[\s\S]){0,300}\}",
        "message": "WebSocket without heartbeat/ping. Configure ping interval to detect stale connections.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_no_reconnect_backoff",
        "pattern": r"(?:onclose|onerror)\s*=\s*.*new\s+WebSocket(?!.*(?:backoff|exponential|delay|setTimeout))",
        "message": "WebSocket reconnect without backoff. Use exponential backoff to prevent reconnect storms.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_no_message_validation",
        "pattern": r"(?:onmessage|on\s*\(\s*['\"]message['\"])\s*[:=].*JSON\.parse(?!.*(?:validate|schema|zod|joi))",
        "message": "WebSocket message parsed without validation. Validate message schema before processing.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_no_auth",
        "pattern": r"(?:ws\.Server|WebSocketServer)\s*\(\s*\{(?:(?!(?:verifyClient|auth|authenticate))[\s\S]){0,300}\}",
        "message": "WebSocket server without authentication. Add verifyClient or auth middleware.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_no_rate_limit",
        "pattern": r"(?:onmessage|on\s*\(\s*['\"]message['\"])\s*[:=](?:(?!(?:rateLimit|throttle|bucket))[\s\S]){0,200}",
        "message": "WebSocket without message rate limiting. Add rate limiter to prevent flooding.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_eval_message",
        "pattern": r"(?:onmessage|on\s*\(\s*['\"]message['\"]).*(?:eval|Function)\s*\(",
        "message": "Evaluating WebSocket message as code. Never execute received data as code.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_no_max_payload",
        "pattern": r"(?:WebSocketServer|ws\.Server)\s*\(\s*\{(?:(?!(?:maxPayload|maxReceivedFrameSize))[\s\S]){0,300}\}",
        "message": "WebSocket without max payload size. Set maxPayload to prevent memory exhaustion.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_broadcast_no_check",
        "pattern": r"\.clients\.forEach\s*\(\s*(?:client|c)\s*=>\s*(?:client|c)\.send\s*\(",
        "message": "WebSocket broadcast without readyState check. Verify client.readyState === OPEN before sending.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_insecure_ws",
        "pattern": r"new\s+WebSocket\s*\(\s*['\"]ws://(?!localhost|127\.0\.0\.1)",
        "message": "Insecure WebSocket (ws://) to remote host. Use wss:// for encrypted connections.",
        "severity": Severity.BLOCK,
        "file_types": [".ts", ".js"],
    },
    {
        "id": "websocket2_no_close_handler",
        "pattern": r"new\s+WebSocket\s*\([^)]+\)(?:(?!(?:onclose|\.on\s*\(\s*['\"]close))[\s\S]){0,200}$",
        "message": "WebSocket without close handler. Handle close events for cleanup and reconnection.",
        "severity": Severity.INFO,
        "file_types": [".ts", ".js"],
    },

    # =================================================================
    #  BASH / SHELL ADVANCED (bash2_) - 15 rules
    # =================================================================

    {
        "id": "bash2_word_splitting",
        "pattern": r'\$\w+(?!\s*["\'])',
        "message": "Unquoted variable expansion vulnerable to word splitting. Use double quotes: \"$var\".",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_glob_injection",
        "pattern": r"(?:for|ls|rm|mv|cp)\s+\$\w+(?!/)",
        "message": "Unquoted variable in glob context. Filenames with spaces or wildcards may cause issues.",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_toctou_check",
        "pattern": r"(?:if\s+\[\s*-(?:f|e|d)\s+[^]]+\].*(?:then|&&))\s*(?:rm|mv|cat|chmod|chown)\s",
        "message": "TOCTOU race: file check then operation is not atomic. Use atomic operations or lock files.",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_unsafe_temp_file",
        "pattern": r"(?:TMPFILE|TEMPFILE|TMP)\s*=\s*['\"]?/tmp/\w+['\"]?(?!.*mktemp)",
        "message": "Predictable temp file path. Use mktemp for secure temporary file creation.",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_eval_variable",
        "pattern": r"\beval\s+.*\$",
        "message": "eval with variable expansion. Attacker-controlled input leads to arbitrary command execution.",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_backtick_nesting",
        "pattern": r"`[^`]*`[^`]*`",
        "message": "Nested backticks are error-prone. Use $() for command substitution.",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_no_set_e",
        "pattern": r"^#!/bin/(?:bash|sh)(?![\s\S]*set\s+-e)",
        "message": "Script without 'set -e'. Errors may go unnoticed. Add 'set -euo pipefail'.",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_curl_insecure",
        "pattern": r"curl\s+(?:-k|--insecure)",
        "message": "curl with insecure flag skips TLS verification. Remove -k/--insecure for production.",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_chmod_recursive_777",
        "pattern": r"chmod\s+-[rR]\s+777",
        "message": "Recursive chmod 777 is extremely dangerous. Use least-privilege permissions.",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_password_in_command",
        "pattern": r"(?:mysql|psql|mongosh?)\s+.*(?:-p\s*['\"]?\w+['\"]?|--password[= ]\w+)",
        "message": "Password in command line visible in process list. Use config file or environment variable.",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_unset_ifs",
        "pattern": r"IFS\s*=(?!\s*['\"])",
        "message": "IFS set without quoting. May cause unexpected word splitting behavior.",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_cd_no_check",
        "pattern": r"\bcd\s+[^&|;]+(?!.*(?:\|\||&&|or|die|exit))",
        "message": "cd without error check. Directory may not exist. Use 'cd dir || exit 1'.",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_source_untrusted",
        "pattern": r"(?:source|\.)\s+(?:/dev/stdin|\$\w+|/tmp/)",
        "message": "Sourcing from untrusted or variable path. Verify file integrity before sourcing.",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_redirect_clobber",
        "pattern": r">\s*(?:\$\w+|/etc/|/var/)",
        "message": "Redirect may clobber important file. Use 'set -o noclobber' or check before writing.",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash"],
    },
    {
        "id": "bash2_ssh_strict_host_off",
        "pattern": r"(?:ssh|scp)\s+.*StrictHostKeyChecking[= ]no",
        "message": "SSH strict host key checking disabled. Enables man-in-the-middle attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash"],
    },

    # =================================================================
    #  POWERSHELL ADVANCED (powershell2_) - 10 rules
    # =================================================================

    {
        "id": "powershell2_invoke_expression",
        "pattern": r"Invoke-Expression\s+(?:\$|['\"])",
        "message": "Invoke-Expression executes arbitrary code. Use & operator or direct cmdlet calls instead.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_expandstring_injection",
        "pattern": r"\$ExecutionContext\.InvokeCommand\.ExpandString\s*\(",
        "message": "ExpandString evaluates embedded expressions. Attacker input can execute arbitrary code.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_credential_plaintext",
        "pattern": r"(?:ConvertTo-SecureString)\s+.*-AsPlainText",
        "message": "Credential stored as plaintext. Use encrypted credential storage or Azure Key Vault.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_password_in_script",
        "pattern": r"(?:\$password|\$secret|\$apiKey)\s*=\s*['\"][^'\"]{4,}['\"]",
        "message": "Hardcoded credential in PowerShell. Use Get-Secret or environment variables.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_disable_execution_policy",
        "pattern": r"Set-ExecutionPolicy\s+(?:Unrestricted|Bypass)",
        "message": "Execution policy set to Unrestricted/Bypass. Use RemoteSigned or AllSigned.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_no_error_action",
        "pattern": r"(?:Invoke-WebRequest|Invoke-RestMethod)\s+(?:(?!(?:-ErrorAction|-EA))[\s\S]){0,200}$",
        "message": "Web request without ErrorAction. Add -ErrorAction Stop for proper error handling.",
        "severity": Severity.INFO,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_skip_cert_check",
        "pattern": r"(?:-SkipCertificateCheck|ServerCertificateValidationCallback\s*=.*true)",
        "message": "Certificate validation skipped. Enables man-in-the-middle attacks.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_add_type_inline",
        "pattern": r"Add-Type\s+-TypeDefinition\s+.*(?:DllImport|unsafe)",
        "message": "Inline C# with DllImport/unsafe in PowerShell. Review for security implications.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_net_webclient",
        "pattern": r"Net\.WebClient\s*\)\s*\.Download",
        "message": "System.Net.WebClient is deprecated. Use Invoke-WebRequest or Invoke-RestMethod.",
        "severity": Severity.INFO,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "powershell2_start_process_hidden",
        "pattern": r"Start-Process\s+.*-WindowStyle\s+Hidden",
        "message": "Hidden process execution is suspicious. Ensure this is not used for malicious purposes.",
        "severity": Severity.WARN,
        "file_types": [".ps1", ".psm1"],
    },

    # =================================================================
    #  SCRIPTING (perl_, lua_, clojure_) - 10 rules
    # =================================================================

    {
        "id": "perl_regex_injection",
        "pattern": r"(?:=~|!~)\s*(?:m|s|tr)?\s*/.*\$\w+",
        "message": "User input in Perl regex. Use quotemeta() to escape special characters.",
        "severity": Severity.WARN,
        "file_types": [".pl", ".pm"],
    },
    {
        "id": "perl_system_call",
        "pattern": r"(?:system|exec|qx)\s*\(\s*\$",
        "message": "System call with variable in Perl. Validate input to prevent command injection.",
        "severity": Severity.BLOCK,
        "file_types": [".pl", ".pm"],
    },
    {
        "id": "perl_open_two_arg",
        "pattern": r"open\s*\(\s*\w+\s*,\s*\$",
        "message": "Two-argument open with variable in Perl. Use three-argument form to prevent injection.",
        "severity": Severity.BLOCK,
        "file_types": [".pl", ".pm"],
    },
    {
        "id": "perl_eval_string",
        "pattern": r"\beval\s+['\"]",
        "message": "eval of string in Perl. Use eval block (eval { }) for exception handling instead.",
        "severity": Severity.BLOCK,
        "file_types": [".pl", ".pm"],
    },
    {
        "id": "lua_loadstring",
        "pattern": r"(?:loadstring|load)\s*\(\s*(?:\w+|['\"])",
        "message": "loadstring/load executes arbitrary Lua code. Use sandboxed environments for untrusted input.",
        "severity": Severity.BLOCK,
        "file_types": [".lua"],
    },
    {
        "id": "lua_os_execute",
        "pattern": r"os\.execute\s*\(",
        "message": "os.execute runs shell commands. Validate input and prefer io.popen with sanitization.",
        "severity": Severity.WARN,
        "file_types": [".lua"],
    },
    {
        "id": "lua_debug_library",
        "pattern": r"(?:debug\.getinfo|debug\.sethook|debug\.setupvalue)",
        "message": "Lua debug library in production. Can bypass sandboxing and access internal state.",
        "severity": Severity.WARN,
        "file_types": [".lua"],
    },
    {
        "id": "clojure_read_string",
        "pattern": r"\(read-string\s",
        "message": "read-string evaluates Clojure reader macros. Use edn/read-string for untrusted input.",
        "severity": Severity.BLOCK,
        "file_types": [".clj", ".cljs", ".cljc"],
    },
    {
        "id": "clojure_eval",
        "pattern": r"\(eval\s",
        "message": "eval executes arbitrary Clojure code. Avoid with untrusted input.",
        "severity": Severity.BLOCK,
        "file_types": [".clj", ".cljs", ".cljc"],
    },
    {
        "id": "clojure_shell_sh",
        "pattern": r"\((?:clojure\.java\.)?shell/sh\s+(?!\"\w+\")",
        "message": "Shell command execution in Clojure. Validate and escape all input arguments.",
        "severity": Severity.WARN,
        "file_types": [".clj", ".cljs", ".cljc"],
    },

    # Accessibility (a11y_) - 20 rules
    # =====================================================================
    {
        "id": "a11y_missing_alt_text",
        "pattern": r"<img\s+(?:(?!alt=)[^>])*>",
        "message": "Image tag missing alt attribute. Add alt text for screen readers.",
        "severity": Severity.BLOCK,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_empty_alt_text",
        "pattern": r'<img\s+[^>]*alt\s*=\s*""\s*[^>]*>',
        "message": "Image has empty alt text. Provide descriptive alt text or mark as decorative with role=presentation.",
        "severity": Severity.WARN,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_aria_label",
        "pattern": r"<(?:button|a)\s+(?:(?!aria-label|aria-labelledby)[^>])*>\s*<(?:svg|i|span)\s",
        "message": "Interactive element with icon-only content missing aria-label. Add aria-label for accessibility.",
        "severity": Severity.BLOCK,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_no_lang_attribute",
        "pattern": r"<html\s+(?:(?!lang=)[^>])*>",
        "message": "HTML element missing lang attribute. Specify language for screen readers.",
        "severity": Severity.WARN,
        "file_types": [".html"],
    },
    {
        "id": "a11y_color_only_indicator",
        "pattern": r"(?i)(?:color|colour)\s*[:=]\s*['\"]?(?:red|green)['\"]\s*.*(?:error|success|valid|invalid)",
        "message": "Using color alone to convey information. Add text or icon indicators alongside color.",
        "severity": Severity.WARN,
        "file_types": [".css", ".scss", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_focus_style",
        "pattern": r"(?i):focus\s*\{\s*outline\s*:\s*(?:none|0)\s*;?\s*\}",
        "message": "Removing focus outline without replacement. Provide visible focus indicator for keyboard users.",
        "severity": Severity.BLOCK,
        "file_types": [".css", ".scss"],
    },
    {
        "id": "a11y_tabindex_positive",
        "pattern": r'tabindex\s*=\s*["\']?[1-9]\d*["\']?',
        "message": "Positive tabindex disrupts natural tab order. Use tabindex=0 or -1 instead.",
        "severity": Severity.WARN,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_form_label",
        "pattern": r"<input\s+(?:(?!aria-label|aria-labelledby|id=)[^>])*type\s*=\s*[\"'](?:text|email|password|tel|number)[\"']",
        "message": "Form input missing associated label. Use <label for=id> or aria-label.",
        "severity": Severity.BLOCK,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_autoplay_media",
        "pattern": r"<(?:video|audio)\s+[^>]*autoplay",
        "message": "Media element with autoplay. Provide pause/stop controls and respect prefers-reduced-motion.",
        "severity": Severity.WARN,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_skip_link",
        "pattern": r"<body[^>]*>\s*<(?:header|nav|div)",
        "message": "No skip navigation link at top of body. Add a skip-to-content link for keyboard users.",
        "severity": Severity.INFO,
        "file_types": [".html"],
    },
    {
        "id": "a11y_click_handler_no_keyboard",
        "pattern": r"onClick\s*=\s*\{[^}]+\}\s*(?:(?!onKeyDown|onKeyPress|onKeyUp|role=)[^>])*>",
        "message": "Click handler without keyboard equivalent. Add onKeyDown handler for keyboard accessibility.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "a11y_div_as_button",
        "pattern": r"<div\s+[^>]*onClick\s*=\s*\{(?:(?!role=)[^>])*>",
        "message": "Using div as clickable element. Use <button> or add role=button and keyboard handlers.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_heading_hierarchy",
        "pattern": r"<h[3-6][^>]*>(?:(?!<h[12])[^<])*$",
        "message": "Heading hierarchy may be broken. Ensure headings follow sequential order (h1 before h2, etc.).",
        "severity": Severity.INFO,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_aria_live",
        "pattern": r"(?i)(?:toast|notification|alert|snackbar)\s*(?:=|:)\s*(?:\{|function)",
        "message": "Dynamic notification without aria-live region. Use aria-live=polite or assertive for announcements.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_role_attribute",
        "pattern": r"<(?:div|span)\s+[^>]*(?:aria-label|aria-labelledby)\s*=\s*[^>]*(?:(?!role=)[^>])*>",
        "message": "Element with aria-label but no role. Add appropriate role attribute.",
        "severity": Severity.WARN,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_missing_table_headers",
        "pattern": r"<table\s*(?:(?!role=)[^>])*>\s*(?:(?!<th)[^<])*<td",
        "message": "Table without header cells. Use <th> elements with scope attribute for data tables.",
        "severity": Severity.WARN,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_low_contrast_text",
        "pattern": r"(?i)color\s*:\s*#(?:ccc|ddd|eee|999|aaa|bbb)\b",
        "message": "Potentially low contrast text color. Ensure 4.5:1 contrast ratio for normal text (WCAG AA).",
        "severity": Severity.INFO,
        "file_types": [".css", ".scss"],
    },
    {
        "id": "a11y_missing_viewport_meta",
        "pattern": r"<head[^>]*>(?:(?!viewport)[^<])*</head>",
        "message": "Missing viewport meta tag. Add <meta name=viewport> for mobile accessibility.",
        "severity": Severity.WARN,
        "file_types": [".html"],
    },
    {
        "id": "a11y_title_on_interactive",
        "pattern": r"<(?:a|button)\s+[^>]*title\s*=\s*[\"'][^\"']+[\"']\s*(?:(?!aria-label)[^>])*>",
        "message": "Using title attribute for accessible name. Prefer aria-label as title is not reliably announced.",
        "severity": Severity.INFO,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "a11y_mouse_only_event",
        "pattern": r"(?:onMouseOver|onMouseEnter|onHover)\s*=\s*\{[^}]*\}(?:(?!onFocus)[^>])*>",
        "message": "Mouse-only event handler without focus equivalent. Add onFocus for keyboard users.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    # =====================================================================
    # Internationalization (i18n_) - 10 rules
    # =====================================================================
    {
        "id": "i18n_hardcoded_string_ui",
        "pattern": r"(?:label|placeholder|title|tooltip)\s*[:=]\s*[\"'][A-Z][a-z]+(?:\s+[a-z]+){2,}[\"']",
        "message": "Hardcoded UI string detected. Use i18n translation keys for user-facing text.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".vue"],
    },
    {
        "id": "i18n_date_format_assumption",
        "pattern": r"(?i)(?:format|parse)\s*\(\s*[\"'](?:MM/DD/YYYY|DD/MM/YYYY|M/D/YY)[\"']",
        "message": "Hardcoded date format assumes locale. Use Intl.DateTimeFormat or locale-aware formatting.",
        "severity": Severity.WARN,
    },
    {
        "id": "i18n_missing_locale_param",
        "pattern": r"(?:toLocaleDateString|toLocaleTimeString|toLocaleString)\s*\(\s*\)",
        "message": "Locale-aware method called without explicit locale. Pass locale parameter for consistent formatting.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "i18n_string_concatenation",
        "pattern": r"[\"'][A-Za-z]+\s*[\"']\s*\+\s*\w+\s*\+\s*[\"']\s*[A-Za-z]+[\"']",
        "message": "String concatenation for user-visible text. Use i18n interpolation - word order varies by language.",
        "severity": Severity.WARN,
    },
    {
        "id": "i18n_hardcoded_currency",
        "pattern": r'["\'](?:\$|USD|EUR|GBP)\s*["\'].*(?:price|cost|amount|total)',
        "message": "Hardcoded currency symbol. Use Intl.NumberFormat with currency option for locale-aware formatting.",
        "severity": Severity.WARN,
    },
    {
        "id": "i18n_rtl_direction_missing",
        "pattern": r"<html\s+(?:(?!dir=)[^>])*lang\s*=\s*[\"'](?:ar|he|fa|ur)[\"']",
        "message": "RTL language specified without dir attribute. Add dir=rtl for right-to-left languages.",
        "severity": Severity.BLOCK,
        "file_types": [".html"],
    },
    {
        "id": "i18n_fixed_text_width",
        "pattern": r"(?i)(?:width|max-width)\s*:\s*\d+px\s*;.*(?:label|text|button|heading)",
        "message": "Fixed width on text container. Text length varies by locale - use flexible sizing.",
        "severity": Severity.INFO,
        "file_types": [".css", ".scss"],
    },
    {
        "id": "i18n_plural_without_rule",
        "pattern": r'["\'](?:\d+|count)\s*\+\s*["\']\s*(?:item|file|record|message)s?["\']',
        "message": "Naive pluralization detected. Use ICU plural rules - plural forms vary significantly by language.",
        "severity": Severity.WARN,
    },
    {
        "id": "i18n_hardcoded_number_format",
        "pattern": r"(?i)\.toFixed\s*\(\s*2\s*\).*(?:price|cost|currency|amount)",
        "message": "Hardcoded decimal places for currency. Use Intl.NumberFormat - decimal separators vary by locale.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "i18n_text_in_image",
        "pattern": r'<img\s+[^>]*src\s*=\s*["\'][^"\']*(?:banner|header|logo-text|button)[^"\']*\.[^"\']+["\']',
        "message": "Text embedded in image may not be translatable. Use HTML/CSS for translatable text overlays.",
        "severity": Severity.INFO,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    # =====================================================================
    # SEO (seo_) - 10 rules
    # =====================================================================
    {
        "id": "seo_missing_meta_description",
        "pattern": r"<head[^>]*>(?:(?!meta\s+name\s*=\s*[\"']description)[^<])*</head>",
        "message": "Missing meta description tag. Add <meta name=description> for search engine results.",
        "severity": Severity.WARN,
        "file_types": [".html"],
    },
    {
        "id": "seo_missing_title_tag",
        "pattern": r"<head[^>]*>(?:(?!<title)[^<])*</head>",
        "message": "Missing <title> tag. Every page needs a unique, descriptive title.",
        "severity": Severity.BLOCK,
        "file_types": [".html"],
    },
    {
        "id": "seo_broken_canonical",
        "pattern": r'<link\s+[^>]*rel\s*=\s*["\']canonical["\'][^>]*href\s*=\s*["\'](?:http://|//)["\']',
        "message": "Empty or HTTP canonical URL. Use full HTTPS URL for canonical links.",
        "severity": Severity.BLOCK,
        "file_types": [".html"],
    },
    {
        "id": "seo_duplicate_h1",
        "pattern": r"<h1[^>]*>.*</h1>.*<h1[^>]*>",
        "message": "Multiple H1 tags on page. Use a single H1 for the primary heading.",
        "severity": Severity.WARN,
        "file_types": [".html"],
    },
    {
        "id": "seo_missing_og_tags",
        "pattern": r"<head[^>]*>(?:(?!og:title)[^<])*</head>",
        "message": "Missing Open Graph meta tags. Add og:title, og:description for social sharing.",
        "severity": Severity.INFO,
        "file_types": [".html"],
    },
    {
        "id": "seo_noindex_production",
        "pattern": r'<meta\s+[^>]*(?:noindex|nofollow)[^>]*>(?:(?!if|env|process)[^<])*',
        "message": "noindex/nofollow in template. Ensure this is conditional and not applied in production.",
        "severity": Severity.WARN,
        "file_types": [".html"],
    },
    {
        "id": "seo_missing_alt_anchor",
        "pattern": r"<a\s+[^>]*href\s*=\s*[^>]*>\s*<img[^>]*/?\s*>\s*</a>",
        "message": "Link wrapping image without descriptive text. Add text or aria-label for link purpose.",
        "severity": Severity.WARN,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "seo_javascript_redirect",
        "pattern": r"(?i)window\.location\s*(?:\.href)?\s*=\s*[\"'][^\"']+[\"']",
        "message": "JavaScript redirect instead of server-side. Use HTTP 301/302 for SEO-friendly redirects.",
        "severity": Severity.INFO,
    },
    {
        "id": "seo_missing_robots_txt",
        "pattern": r"(?i)(?:sitemap|robots)\s*:\s*(?:null|undefined|false|''|\"\")",
        "message": "Sitemap or robots configuration set to empty. Configure robots.txt and sitemap.xml.",
        "severity": Severity.WARN,
    },
    {
        "id": "seo_unstructured_data",
        "pattern": r"<(?:article|product|event|recipe)\s*(?:(?!itemscope|ld\+json)[^>])*>",
        "message": "Content section without structured data. Add schema.org markup (JSON-LD) for rich results.",
        "severity": Severity.INFO,
        "file_types": [".html"],
    },
    # =====================================================================
    # UX anti-patterns (ux_) - 10 rules
    # =====================================================================
    {
        "id": "ux_infinite_scroll_no_pagination",
        "pattern": r"(?i)(?:infinite.?scroll|load.?more|endless.?scroll)(?:(?!pagination|page.?number|page.?size)[^;])*;",
        "message": "Infinite scroll without pagination fallback. Provide URL-based pagination for deep linking.",
        "severity": Severity.WARN,
    },
    {
        "id": "ux_missing_loading_state",
        "pattern": r"(?:fetch|axios|httpx?)\s*\.\s*(?:get|post|put|delete)\s*\([^)]*\)(?:(?!loading|spinner|skeleton|isLoading)[^;])*;",
        "message": "Async request without loading state indicator. Show loading feedback to users.",
        "severity": Severity.WARN,
    },
    {
        "id": "ux_missing_error_boundary",
        "pattern": r"(?:createRoot|ReactDOM\.render)\s*\([^)]*\)(?:(?!ErrorBoundary|error.?boundary)[^;])*",
        "message": "React root without ErrorBoundary. Wrap top-level components in error boundaries.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "ux_confirm_destructive_action",
        "pattern": r"(?i)(?:delete|remove|destroy|purge)\s*\(\s*\)(?:(?!confirm|modal|dialog|prompt)[^;])*;",
        "message": "Destructive action without confirmation. Add confirmation dialog for irreversible operations.",
        "severity": Severity.WARN,
    },
    {
        "id": "ux_no_empty_state",
        "pattern": r"(?i)(?:\.length\s*===?\s*0|isEmpty|no.?results?)(?:(?!empty.?state|no.?data|placeholder)[^;])*return\s+null",
        "message": "Empty data returning null. Show helpful empty state UI with actionable guidance.",
        "severity": Severity.INFO,
    },
    {
        "id": "ux_alert_in_production",
        "pattern": r"\balert\s*\(\s*[\"'][^\"']+[\"']\s*\)",
        "message": "Using alert() for user notifications. Use toast/snackbar for non-blocking feedback.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".jsx", ".tsx"],
    },
    {
        "id": "ux_disabled_button_no_tooltip",
        "pattern": r"<button\s+[^>]*disabled[^>]*>(?:(?!title=|aria-label|tooltip)[^<])*</button>",
        "message": "Disabled button without explanation. Add tooltip explaining why the action is unavailable.",
        "severity": Severity.INFO,
        "file_types": [".html", ".jsx", ".tsx"],
    },
    {
        "id": "ux_form_no_validation_feedback",
        "pattern": r"<form\s+[^>]*onSubmit\s*=\s*\{[^}]*\}(?:(?!error|validation|invalid|feedback)[^>])*>",
        "message": "Form without validation error display. Show inline validation messages near fields.",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx"],
    },
    {
        "id": "ux_long_form_no_progress",
        "pattern": r"(?i)(?:step|wizard|multi.?step|multi.?page)\s*(?:form|flow)(?:(?!progress|stepper|indicator)[^;])*",
        "message": "Multi-step form without progress indicator. Show step progress for complex forms.",
        "severity": Severity.INFO,
    },
    {
        "id": "ux_no_undo_action",
        "pattern": r"(?i)(?:delete|archive|move|remove)\s*\(\s*[^)]+\)\s*;(?:(?!undo|revert|restore|history)[^;])*",
        "message": "Destructive action without undo option. Provide undo/restore capability where possible.",
        "severity": Severity.INFO,
    },
    # =====================================================================
    # Mobile advanced (mobile2_) - 10 rules
    # =====================================================================
    {
        "id": "mobile2_battery_drain_polling",
        "pattern": r"(?i)setInterval\s*\([^,]+,\s*(?:[1-9]\d{0,3}|[12]\d{4})\s*\)",
        "message": "Aggressive polling interval drains battery. Use push notifications or longer intervals on mobile.",
        "severity": Severity.WARN,
    },
    {
        "id": "mobile2_excessive_wake_lock",
        "pattern": r"(?i)(?:navigator\.wakeLock|WakeLock|PARTIAL_WAKE_LOCK)(?:(?!release|timeout|finally)[^;])*;",
        "message": "Wake lock acquired without visible release. Always release wake locks to preserve battery.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "mobile2_background_location",
        "pattern": r"(?i)(?:watchPosition|ACCESS_BACKGROUND_LOCATION|allowsBackgroundLocationUpdates)",
        "message": "Background location tracking detected. Justify need and minimize tracking frequency.",
        "severity": Severity.WARN,
    },
    {
        "id": "mobile2_large_image_no_resize",
        "pattern": r"(?i)(?:backgroundImage|source|src)\s*[:=]\s*[\"'][^\"']*(?:\.png|\.jpg|\.jpeg)[\"'](?:(?!resize|compress|thumbnail|srcset)[^;])*",
        "message": "Loading full-size images on mobile. Use responsive images with srcset or server-side resizing.",
        "severity": Severity.WARN,
    },
    {
        "id": "mobile2_sync_storage_main_thread",
        "pattern": r"(?i)localStorage\.\s*(?:setItem|getItem|removeItem)\s*\(",
        "message": "Synchronous storage on main thread. Use async storage API to avoid UI jank on mobile.",
        "severity": Severity.INFO,
    },
    {
        "id": "mobile2_heavy_animation",
        "pattern": r"(?i)(?:animation|transition)\s*:[^;]*(?:all|width|height|top|left|margin|padding)\b",
        "message": "Animating layout properties causes reflow. Use transform/opacity for smooth 60fps mobile animations.",
        "severity": Severity.WARN,
        "file_types": [".css", ".scss"],
    },
    {
        "id": "mobile2_no_offline_fallback",
        "pattern": r"(?i)(?:serviceWorker|service.?worker)\.register(?:(?!offline|cache|fallback)[^;])*;",
        "message": "Service worker without offline fallback. Implement offline page for poor connectivity.",
        "severity": Severity.INFO,
    },
    {
        "id": "mobile2_excessive_permissions",
        "pattern": r"(?i)(?:uses-permission|NSCameraUsageDescription|NSMicrophoneUsageDescription).*(?:RECORD_AUDIO|CAMERA|READ_CONTACTS|READ_SMS)",
        "message": "Requesting sensitive permissions. Request only when needed and explain purpose to user.",
        "severity": Severity.WARN,
    },
    {
        "id": "mobile2_unthrottled_scroll",
        "pattern": r"(?:addEventListener|on)\s*\(\s*[\"']scroll[\"']\s*,(?:(?!throttle|debounce|requestAnimationFrame|passive)[^)]*)\)",
        "message": "Unthrottled scroll handler degrades mobile performance. Use passive listener or throttle/debounce.",
        "severity": Severity.WARN,
    },
    {
        "id": "mobile2_webview_js_injection",
        "pattern": r"(?i)(?:evaluateJavaScript|loadUrl\s*\(\s*[\"']javascript:)",
        "message": "JavaScript injection into WebView. Sanitize all input and use message passing instead.",
        "severity": Severity.BLOCK,
    },
    # =====================================================================
    # Embedded / Firmware / IoT (embedded_, firmware_, iot_) - 20 rules
    # =====================================================================
    {
        "id": "embedded_stack_alloc_large",
        "pattern": r"\b(?:char|int|uint8_t|uint16_t|uint32_t)\s+\w+\s*\[\s*(?:[1-9]\d{4,}|[5-9]\d{3})\s*\]",
        "message": "Large stack allocation in embedded context. Use heap allocation or static buffers for arrays >4KB.",
        "severity": Severity.WARN,
        "file_types": [".c", ".h", ".cpp"],
    },
    {
        "id": "embedded_recursive_function",
        "pattern": r"(?:void|int|uint\w+)\s+(\w+)\s*\([^)]*\)\s*\{[^}]*\b\1\s*\(",
        "message": "Recursive function in embedded context risks stack overflow. Use iterative approach.",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp"],
    },
    {
        "id": "embedded_malloc_no_null_check",
        "pattern": r"=\s*malloc\s*\([^)]+\)\s*;(?:(?!if\s*\(|!=\s*NULL|==\s*NULL)[^;])*;",
        "message": "malloc without NULL check. Always verify allocation succeeded in embedded systems.",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp"],
    },
    {
        "id": "embedded_no_watchdog",
        "pattern": r"(?i)while\s*\(\s*(?:1|true)\s*\)\s*\{(?:(?!watchdog|wdt|kick|feed|pet)[^}])*\}",
        "message": "Infinite loop without watchdog timer reset. Add watchdog kick to prevent system hang.",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp"],
    },
    {
        "id": "firmware_unsigned_update",
        "pattern": r"(?i)(?:firmware|fw|ota)_?(?:update|upgrade|flash)(?:(?!sign|verify|hash|checksum|signature)[^;])*;",
        "message": "Firmware update without signature verification. Verify cryptographic signature before flashing.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "firmware_debug_enabled",
        "pattern": r"(?i)(?:#define\s+DEBUG\s+1|DEBUG_MODE\s*=\s*(?:true|1)|JTAG_ENABLE|SWD_ENABLE)",
        "message": "Debug interface enabled in firmware. Disable JTAG/SWD and debug flags in production builds.",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".h", ".cpp"],
    },
    {
        "id": "firmware_hardcoded_key",
        "pattern": r"(?i)(?:AES|DES|RSA|HMAC)_?KEY\s*(?:=|\[)\s*(?:\{|[\"'])[^}\"']+(?:\}|[\"'])",
        "message": "Hardcoded cryptographic key in firmware. Use secure key storage or hardware security module.",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".h", ".cpp"],
    },
    {
        "id": "firmware_unprotected_bootloader",
        "pattern": r"(?i)(?:BOOT_LOCK|boot_protection|secure_boot)\s*(?:=|:)\s*(?:0|false|disabled|off)",
        "message": "Bootloader protection disabled. Enable secure boot to prevent unauthorized firmware.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "iot_default_credentials",
        "pattern": r'(?i)(?:password|passwd|credential)\s*[:=]\s*["\'](?:admin|root|default|1234|password|12345678)["\']',
        "message": "Default IoT credentials detected. Require unique credentials per device on first boot.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "iot_unencrypted_mqtt",
        "pattern": r"(?i)mqtt://(?:(?!localhost|127\.0\.0\.1)[^/])",
        "message": "Unencrypted MQTT connection. Use mqtts:// (TLS) for IoT device communication.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "iot_telemetry_no_auth",
        "pattern": r"(?i)(?:telemetry|sensor|device)\s*\.(?:send|publish|report)\s*\((?:(?!token|auth|key|credential)[^)]*)\)",
        "message": "IoT telemetry sent without authentication. Include device authentication token.",
        "severity": Severity.WARN,
    },
    {
        "id": "iot_no_rate_limit_command",
        "pattern": r"(?i)(?:on_?message|on_?command|handle_?command)\s*\((?:(?!rate_limit|throttle|debounce)[^)]*)\)",
        "message": "IoT command handler without rate limiting. Throttle incoming commands to prevent abuse.",
        "severity": Severity.WARN,
    },
    {
        "id": "iot_plaintext_protocol",
        "pattern": r"(?i)(?:coap://|mqtt://|amqp://)(?:(?!localhost|127\.0\.0\.1|192\.168)[^\s\"']+)",
        "message": "Plaintext protocol for IoT communication. Use encrypted transport (TLS/DTLS).",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".js", ".ts", ".go", ".java", ".c", ".cpp"],
    },
    {
        "id": "iot_no_device_attestation",
        "pattern": r"(?i)(?:register|enroll|provision)_?device\s*\((?:(?!attest|certificate|tpm|secure_element)[^)]*)\)",
        "message": "Device registration without attestation. Verify device identity with certificate or TPM.",
        "severity": Severity.WARN,
    },
    {
        "id": "embedded_interrupt_long_handler",
        "pattern": r"(?i)(?:ISR|IRQHandler|__interrupt)\s*\([^)]*\)\s*\{[^}]{500,}\}",
        "message": "Long interrupt handler blocks other interrupts. Keep ISRs short - defer work to main loop.",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp"],
    },
    {
        "id": "embedded_global_disable_interrupts",
        "pattern": r"(?i)(?:cli\(\)|__disable_irq\(\)|noInterrupts\(\))(?:(?!sei|__enable_irq|interrupts)[^;]{200,})",
        "message": "Interrupts disabled for extended period. Minimize critical sections to prevent missed events.",
        "severity": Severity.WARN,
        "file_types": [".c", ".cpp"],
    },
    {
        "id": "iot_open_debug_port",
        "pattern": r"(?i)(?:bind|listen)\s*\(\s*[\"']?(?:0\.0\.0\.0|::)[\"']?\s*,\s*(?:22|23|8080|9090|1883)\s*\)",
        "message": "Debug/management port open on all interfaces. Bind to localhost or use firewall rules.",
        "severity": Severity.BLOCK,
    },
    # =====================================================================
    # Blockchain / DeFi (blockchain2_, smart_contract_, nft_, defi_) - 20 rules
    # =====================================================================
    {
        "id": "smart_contract_reentrancy",
        "pattern": r"(?i)\.call\s*\{[^}]*value\s*:[^}]*\}\s*\([^)]*\)\s*;(?:(?!ReentrancyGuard|nonReentrant|_status)[^;])*",
        "message": "External call with value before state update. Use checks-effects-interactions pattern or ReentrancyGuard.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "smart_contract_unchecked_call",
        "pattern": r"(?i)\.call\s*\{[^}]*\}\s*\([^)]*\)\s*;(?:(?!require|if|success|revert)[^;])*",
        "message": "Unchecked low-level call return value. Always check success boolean from .call().",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "smart_contract_delegatecall",
        "pattern": r"\.delegatecall\s*\(",
        "message": "delegatecall executes code in caller context. Ensure target is trusted and immutable.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "defi_flash_loan_no_guard",
        "pattern": r"(?i)(?:flash_?loan|flashLoan|flash_?borrow)(?:(?!require|guard|check|verify|onlyOwner)[^;])*;",
        "message": "Flash loan without validation guards. Add price oracle checks and slippage protection.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "defi_oracle_single_source",
        "pattern": r"(?i)(?:getPrice|latestAnswer|latestRoundData)\s*\((?:(?!median|aggregate|twap|multiple)[^)]*)\)",
        "message": "Single oracle price source. Use multiple oracles or TWAP to prevent manipulation.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "defi_no_slippage_check",
        "pattern": r"(?i)(?:swap|exchange|trade)\s*\([^)]*\)(?:(?!minOut|slippage|amountOutMin|deadline)[^;])*;",
        "message": "Token swap without slippage protection. Add minimum output amount check.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "blockchain2_private_key_exposure",
        "pattern": r"(?i)(?:private_?key|secret_?key|signing_?key)\s*[:=]\s*[\"'][0-9a-fA-F]{64}[\"']",
        "message": "Private key hardcoded in source. Use environment variables or hardware wallet.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "blockchain2_unchecked_math",
        "pattern": r"(?i)(?:uint256|uint128|uint64)\s+\w+\s*=\s*\w+\s*[\+\-\*]\s*\w+\s*;(?:(?!SafeMath|unchecked|require)[^;])*",
        "message": "Arithmetic without overflow protection. Use SafeMath or Solidity 0.8+ checked arithmetic.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "smart_contract_timestamp_dependence",
        "pattern": r"\bblock\.timestamp\b.*(?:if|require|condition|random)",
        "message": "Block timestamp used for critical logic. Miners can manipulate timestamp by ~15 seconds.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "defi_no_withdrawal_limit",
        "pattern": r"(?i)(?:withdraw|redeem|claim)\s*\([^)]*\)(?:(?!limit|max|cap|timelock|cooldown)[^;])*;",
        "message": "Withdrawal without limits or timelock. Add daily limits and cooling periods for large amounts.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "nft_unrestricted_mint",
        "pattern": r"(?i)function\s+mint\s*\([^)]*\)(?:(?!onlyOwner|onlyMinter|require|_mint|maxSupply)[^{])*\{",
        "message": "NFT mint function without access control. Restrict minting to authorized addresses.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "nft_missing_royalty",
        "pattern": r"(?i)(?:ERC721|ERC1155)(?:(?!ERC2981|royalty|royaltyInfo)[^;])*;",
        "message": "NFT contract without royalty standard. Implement ERC-2981 for on-chain royalty enforcement.",
        "severity": Severity.INFO,
        "file_types": [".sol"],
    },
    {
        "id": "blockchain2_hardcoded_gas",
        "pattern": r"(?i)gas\s*:\s*(?:2300|21000|\d{6,})\b",
        "message": "Hardcoded gas limit. Gas costs change with network upgrades - use estimation.",
        "severity": Severity.WARN,
        "file_types": [".sol", ".js", ".ts"],
    },
    {
        "id": "smart_contract_front_running",
        "pattern": r"(?i)(?:approve|swap|bid|commit)\s*\([^)]*\)(?:(?!commit.?reveal|timelock|private|encrypted)[^;])*;",
        "message": "Transaction vulnerable to front-running. Use commit-reveal scheme or private mempool.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    {
        "id": "defi_unbounded_loop",
        "pattern": r"(?i)for\s*\([^)]*(?:balances|holders|stakers)\.length[^)]*\)\s*\{",
        "message": "Loop over unbounded array may exceed gas limit. Use pagination or pull-based patterns.",
        "severity": Severity.BLOCK,
        "file_types": [".sol"],
    },
    {
        "id": "blockchain2_mnemonic_in_code",
        "pattern": r"(?i)(?:mnemonic|seed_?phrase)\s*[:=]\s*[\"'][a-z]+(?:\s+[a-z]+){11,}[\"']",
        "message": "Mnemonic seed phrase in source code. Use secure key management - never commit seed phrases.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "nft_no_metadata_freeze",
        "pattern": r"(?i)function\s+setTokenURI\s*\([^)]*\)(?:(?!frozen|locked|immutable|finalized)[^{])*\{",
        "message": "Mutable NFT metadata without freeze mechanism. Add ability to permanently lock metadata.",
        "severity": Severity.INFO,
        "file_types": [".sol"],
    },
    {
        "id": "defi_missing_emergency_stop",
        "pattern": r"(?i)contract\s+\w+(?:(?!Pausable|pause|circuit_?breaker|emergency)[^}])*\}",
        "message": "DeFi contract without emergency pause. Implement Pausable for circuit-breaker functionality.",
        "severity": Severity.WARN,
        "file_types": [".sol"],
    },
    # =====================================================================
    # ML/AI pipeline (ml2_, nlp_, cv_) - 20 rules
    # =====================================================================
    {
        "id": "ml2_training_on_test_data",
        "pattern": r"(?i)(?:model\.fit|\.train)\s*\([^)]*(?:test|val|validation)[^)]*\)",
        "message": "Possible training on test/validation data. Use strictly separate train/test splits.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml2_data_leakage_preprocessing",
        "pattern": r"(?i)(?:fit_transform|\.fit)\s*\(\s*(?:X|data|df)(?:(?!train|_train)[^)]*)\)(?:.*(?:split|train_test))",
        "message": "Preprocessing fitted before train/test split causes data leakage. Fit only on training data.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml2_no_random_seed",
        "pattern": r"(?i)(?:train_test_split|KFold|RandomForest|shuffle)\s*\((?:(?!random_state|seed|random_seed)[^)]*)\)",
        "message": "ML operation without random seed. Set random_state for reproducible experiments.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml2_pickle_load_unsafe",
        "pattern": r"(?i)(?:pickle\.load|joblib\.load|torch\.load)\s*\(\s*(?:(?!weights_only|safe)[^)]*)\)",
        "message": "Unsafe model deserialization allows arbitrary code execution. Use safe loading or verify source.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ml2_no_model_versioning",
        "pattern": r"(?i)(?:model\.save|save_model|torch\.save)\s*\(\s*[\"'][^\"']*[\"']\s*\)(?:(?!version|timestamp|hash|mlflow)[^;])*",
        "message": "Model saved without versioning. Use MLflow, DVC, or timestamp-based versioning.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml2_hardcoded_hyperparams",
        "pattern": r"(?i)(?:learning_rate|lr|epochs|batch_size)\s*=\s*(?:0\.\d+|\d+)(?:(?!config|params|args|hparams)[^;])*;",
        "message": "Hardcoded hyperparameters. Use config files or experiment tracking for reproducibility.",
        "severity": Severity.INFO,
    },
    {
        "id": "ml2_no_input_validation",
        "pattern": r"(?i)(?:model\.predict|\.inference|\.forward)\s*\(\s*\w+\s*\)(?:(?!validate|check|assert|shape)[^;])*",
        "message": "Model inference without input validation. Check shape, dtype, and range before prediction.",
        "severity": Severity.WARN,
    },
    {
        "id": "nlp_prompt_injection",
        "pattern": r"(?i)(?:prompt|system_message|instruction)\s*[:=]\s*.*\+\s*(?:user_?input|request\.body|query)",
        "message": "User input concatenated into prompt. Sanitize input and use parameterized prompts.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "nlp_no_input_sanitize",
        "pattern": r"(?i)(?:openai|anthropic|llm)\.\w+\.create\s*\([^)]*(?:user_input|raw_text|body)[^)]*\)",
        "message": "Raw user input passed to LLM API. Sanitize and validate input before sending.",
        "severity": Severity.WARN,
    },
    {
        "id": "nlp_no_output_filter",
        "pattern": r"(?i)(?:response|completion|result)\s*\.\s*(?:text|content|choices)\s*(?:(?!filter|sanitize|moderate|check)[^;])*;",
        "message": "LLM output used without filtering. Apply content moderation before displaying to users.",
        "severity": Severity.WARN,
    },
    {
        "id": "nlp_unlimited_token_cost",
        "pattern": r"(?i)(?:max_tokens|maxTokens)\s*[:=]\s*(?:None|null|undefined|-1|99999)",
        "message": "Unlimited token count risks runaway API costs. Set reasonable max_tokens limit.",
        "severity": Severity.WARN,
    },
    {
        "id": "cv_no_image_validation",
        "pattern": r"(?i)(?:cv2\.imread|Image\.open|load_image)\s*\(\s*(?:path|file|url)",
        "message": "Image loaded without validation. Check file type, size, and dimensions before processing.",
        "severity": Severity.WARN,
    },
    {
        "id": "cv_hardcoded_image_size",
        "pattern": r"(?i)(?:resize|reshape)\s*\(\s*\(?(?:224|299|416|512|640)\s*,\s*(?:224|299|416|512|640)\s*\)?",
        "message": "Hardcoded image dimensions. Define input size as model configuration constant.",
        "severity": Severity.INFO,
    },
    {
        "id": "ml2_eval_metric_mismatch",
        "pattern": r"(?i)(?:accuracy_score|accuracy)\s*\((?:.*(?:imbalanced|unbalanced|skew))",
        "message": "Using accuracy on imbalanced dataset. Use F1, precision-recall, or AUC-ROC instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml2_no_data_drift_check",
        "pattern": r"(?i)(?:predict|inference|serve)\s*\((?:(?!drift|monitor|distribution|schema_check)[^)]*)\)",
        "message": "Prediction serving without data drift detection. Monitor input distribution shifts.",
        "severity": Severity.INFO,
    },
    {
        "id": "cv_no_gpu_memory_cleanup",
        "pattern": r"(?i)(?:torch\.cuda|cuda\(\)|\.to\s*\(\s*[\"']cuda[\"']\s*\))(?:(?!empty_cache|del\s|gc\.collect|with\s+torch)[^;])*",
        "message": "CUDA tensors without memory cleanup. Call torch.cuda.empty_cache() to prevent OOM.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml2_no_feature_scaling",
        "pattern": r"(?i)(?:LinearRegression|SVM|KMeans|GradientBoosting)\s*\((?:(?!StandardScaler|normalize|MinMaxScaler)[^)]*)\)",
        "message": "Model sensitive to feature scale used without normalization. Apply feature scaling.",
        "severity": Severity.INFO,
    },
    {
        "id": "nlp_no_rate_limit_api",
        "pattern": r"(?i)(?:openai|anthropic|cohere|huggingface)\.\w+(?:(?!rate_limit|retry|backoff|sleep|throttle)[^;])*;",
        "message": "LLM API call without rate limiting. Implement exponential backoff and request throttling.",
        "severity": Severity.WARN,
    },
    {
        "id": "ml2_no_experiment_tracking",
        "pattern": r"(?i)(?:model\.fit|\.train)\s*\([^)]*\)(?:(?!mlflow|wandb|tensorboard|experiment|log_metric)[^;])*;",
        "message": "Training without experiment tracking. Use MLflow, W&B, or TensorBoard to log metrics.",
        "severity": Severity.INFO,
    },
    {
        "id": "cv_adversarial_no_defense",
        "pattern": r"(?i)(?:classify|predict|detect)\s*\(\s*(?:image|img|frame)\s*\)(?:(?!adversarial|robust|defense|perturbation)[^;])*",
        "message": "Image classification without adversarial defense. Consider input validation and robust models.",
        "severity": Severity.INFO,
    },
    # =====================================================================
    # Data pipeline (data_pipeline_, etl_, spark_, airflow_, dbt_) - 20 rules
    # =====================================================================
    {
        "id": "data_pipeline_sql_injection_etl",
        "pattern": r"(?i)(?:execute|cursor\.execute)\s*\(\s*f?[\"'].*\{.*\}.*[\"']\s*\)",
        "message": "SQL injection risk in data pipeline. Use parameterized queries even in ETL processes.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "etl_no_data_validation",
        "pattern": r"(?i)(?:read_csv|read_json|read_parquet|load_table)\s*\((?:(?!schema|validate|dtype|columns)[^)]*)\)",
        "message": "Loading data without schema validation. Define expected schema to catch corruption early.",
        "severity": Severity.WARN,
    },
    {
        "id": "etl_no_null_handling",
        "pattern": r"(?i)(?:merge|join|concat)\s*\([^)]*\)(?:(?!dropna|fillna|null|isna|notna)[^;])*;",
        "message": "Data join without null handling. Handle nulls explicitly to prevent silent data loss.",
        "severity": Severity.WARN,
    },
    {
        "id": "etl_unbounded_query",
        "pattern": r'(?i)(?:SELECT|FROM)\s+\*\s+FROM\s+\w+(?:(?!LIMIT|WHERE|TOP|FETCH\s+FIRST)[^;])*;',
        "message": "Unbounded query in ETL pipeline. Add LIMIT/WHERE clause to prevent memory exhaustion.",
        "severity": Severity.WARN,
    },
    {
        "id": "spark_collect_large_dataset",
        "pattern": r"(?i)\.collect\s*\(\s*\)(?:(?!limit|take|sample|head)[^;])*",
        "message": "Spark collect() on potentially large dataset. Use take(), limit(), or write to storage.",
        "severity": Severity.WARN,
    },
    {
        "id": "spark_no_partition_strategy",
        "pattern": r"(?i)\.write\s*\.\s*(?:parquet|csv|json)\s*\((?:(?!partition|repartition|coalesce)[^)]*)\)",
        "message": "Writing Spark output without partitioning. Partition by date/key for query performance.",
        "severity": Severity.INFO,
    },
    {
        "id": "spark_udf_no_type",
        "pattern": r"(?i)udf\s*\(\s*(?:lambda|def\s+\w+)(?:(?!returnType|IntegerType|StringType|schema)[^)]*)\)",
        "message": "Spark UDF without return type. Specify return type to avoid serialization errors.",
        "severity": Severity.WARN,
    },
    {
        "id": "airflow_unbounded_dag",
        "pattern": r"(?i)(?:schedule_interval|schedule)\s*[:=]\s*[\"'](?:@once|None)[\"'](?:(?!catchup\s*=\s*False)[^,])*",
        "message": "Airflow DAG without catchup=False may backfill indefinitely. Set catchup=False explicitly.",
        "severity": Severity.WARN,
    },
    {
        "id": "airflow_hardcoded_connection",
        "pattern": r'(?i)(?:conn_id|airflow\.models\.connection|dag_id)\s*[:=]\s*["\'](?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|jdbc:|postgresql://)',
        "message": "Hardcoded connection in Airflow DAG. Use Airflow Connections and Variables for configuration.",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
        "exclude_path_contains": ["test"],
    },
    {
        "id": "airflow_no_retry",
        "pattern": r"(?i)(?:retries|retry)\s*[:=]\s*0\b",
        "message": "Task with zero retries. Set retries >= 1 for resilience against transient failures.",
        "severity": Severity.WARN,
    },
    {
        "id": "airflow_no_sla",
        "pattern": r"(?i)(?:BashOperator|PythonOperator|task)\s*\((?:(?!sla|timeout|execution_timeout)[^)]*)\)",
        "message": "Airflow task without SLA or timeout. Set execution_timeout to prevent hung tasks.",
        "severity": Severity.WARN,
    },
    {
        "id": "dbt_no_test",
        "pattern": r"(?i)(?:source|ref)\s*\(\s*[\"'][^\"']+[\"']\s*\)(?:(?!test|assert|unique|not_null)[^;])*",
        "message": "dbt model reference without tests. Add unique, not_null, and relationship tests.",
        "severity": Severity.INFO,
    },
    {
        "id": "dbt_hardcoded_schema",
        "pattern": r"(?i)(?:FROM|JOIN)\s+(?:raw|staging|production|public)\.\w+",
        "message": "Hardcoded schema name in dbt model. Use {{ source() }} or {{ ref() }} for schema resolution.",
        "severity": Severity.WARN,
        "file_types": [".sql"],
    },
    {
        "id": "data_pipeline_no_idempotency",
        "pattern": r"(?i)(?:INSERT\s+INTO|APPEND)(?:(?!ON\s+CONFLICT|MERGE|UPSERT|IF\s+NOT\s+EXISTS|REPLACE)[^;])*;",
        "message": "Non-idempotent write operation in pipeline. Use UPSERT or ON CONFLICT to prevent duplicates.",
        "severity": Severity.WARN,
    },
    {
        "id": "data_pipeline_no_checkpoint",
        "pattern": r"(?i)(?:stream|consume|process_events)\s*\((?:(?!checkpoint|offset|watermark|bookmark)[^)]*)\)",
        "message": "Streaming pipeline without checkpointing. Add checkpoints for failure recovery.",
        "severity": Severity.WARN,
    },
    {
        "id": "etl_hardcoded_file_path",
        "pattern": r'(?i)(?:read_csv|read_json|open)\s*\(\s*["\'](?:/|C:\\|~/)[\w/\\.-]+["\']',
        "message": "Hardcoded file path in ETL. Use configuration or environment variables for paths.",
        "severity": Severity.WARN,
    },
    {
        "id": "spark_cache_without_unpersist",
        "pattern": r"(?i)\.cache\s*\(\s*\)(?:(?!unpersist)[^;]{500,})",
        "message": "Cached DataFrame without unpersist. Call unpersist() when cache is no longer needed.",
        "severity": Severity.INFO,
    },
    {
        "id": "data_pipeline_no_dead_letter",
        "pattern": r"(?i)(?:on_error|except|catch)\s*(?::|{)(?:(?!dead_letter|dlq|quarantine|retry_queue)[^}])*",
        "message": "Error handling without dead letter queue. Route failed records to DLQ for investigation.",
        "severity": Severity.INFO,
    },
    {
        "id": "etl_no_dedup",
        "pattern": r"(?i)(?:merge|union|concat|append)\s*\([^)]*\)(?:(?!distinct|drop_duplicates|dedup|unique)[^;])*;",
        "message": "Data merge without deduplication. Add dedup step to prevent duplicate records.",
        "severity": Severity.WARN,
    },
    {
        "id": "data_pipeline_no_lineage",
        "pattern": r"(?i)(?:transform|process|pipeline)\s*\([^)]*\)(?:(?!lineage|metadata|provenance|audit)[^;])*;",
        "message": "Data transformation without lineage tracking. Record source, transformations, and destination.",
        "severity": Severity.INFO,
    },
    # =====================================================================
    # IaC advanced (terraform2_, pulumi_, cdk2_, cloudformation2_) - 20 rules
    # =====================================================================
    {
        "id": "terraform2_state_no_encryption",
        "pattern": r'(?i)backend\s+"s3"\s*\{(?:(?!encrypt\s*=\s*true)[^}])*\}',
        "message": "Terraform S3 backend without encryption. Set encrypt = true to protect state file.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "terraform2_state_no_locking",
        "pattern": r'(?i)backend\s+"s3"\s*\{(?:(?!dynamodb_table)[^}])*\}',
        "message": "Terraform S3 backend without state locking. Add dynamodb_table for lock management.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "terraform2_hardcoded_credentials",
        "pattern": r'(?i)(?:access_key|secret_key)\s*=\s*"[^"]{10,}"',
        "message": "Hardcoded AWS credentials in Terraform. Use environment variables or IAM roles.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    {
        "id": "terraform2_no_version_constraint",
        "pattern": r'(?i)required_providers\s*\{[^}]*source\s*=\s*"[^"]*"(?:(?!version)[^}])*\}',
        "message": "Provider without version constraint. Pin version to prevent breaking changes.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "terraform2_public_subnet",
        "pattern": r"(?i)map_public_ip_on_launch\s*=\s*true",
        "message": "Subnet auto-assigns public IPs. Ensure this is intentional and not for private resources.",
        "severity": Severity.INFO,
        "file_types": [".tf"],
    },
    {
        "id": "pulumi_secret_plain_text",
        "pattern": r"(?i)pulumi\.Config\s*\(\s*\)\.(?:get|require)\s*\(\s*[\"'](?:password|secret|key|token)[\"']\s*\)",
        "message": "Reading secret as plaintext in Pulumi. Use get_secret() or require_secret() for encryption.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "pulumi_no_stack_protection",
        "pattern": r"(?i)pulumi\.StackReference\s*\((?:(?!protect|retain)[^)]*)\)",
        "message": "Stack reference without resource protection. Use protect=True for critical resources.",
        "severity": Severity.INFO,
    },
    {
        "id": "pulumi_hardcoded_region",
        "pattern": r'(?i)(?:region|location)\s*[:=]\s*["\'](?:us-east-1|eu-west-1|us-west-2)["\'](?:(?!config|variable|param)[^;])*',
        "message": "Hardcoded cloud region in Pulumi. Use stack configuration for region selection.",
        "severity": Severity.WARN,
    },
    {
        "id": "cdk2_no_removal_policy",
        "pattern": r"(?i)(?:Bucket|Table|Database|Queue)\s*\((?:(?!removal_policy|removalPolicy)[^)]*)\)",
        "message": "CDK resource without removal policy. Set RemovalPolicy.RETAIN for stateful resources.",
        "severity": Severity.WARN,
        "file_types": [".ts", ".js", ".py"],
        "skip_comments": True,
    },
    {
        "id": "cdk2_wildcard_iam",
        "pattern": r'(?i)(?:add_to_policy|grant|PolicyStatement)\s*\([^)]*(?:actions\s*[:=]\s*\[?\s*["\'][\w:]*\*["\']|resources\s*[:=]\s*\[?\s*["\']\*["\'])',
        "message": "CDK IAM policy with wildcard. Apply least-privilege - specify exact actions and resources.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cdk2_public_bucket",
        "pattern": r"(?i)(?:public_read_access|publicReadAccess)\s*[:=]\s*(?:true|True)",
        "message": "CDK S3 bucket with public read access. Use CloudFront or presigned URLs instead.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cloudformation2_no_drift_detection",
        "pattern": r"(?i)DeletionPolicy\s*:\s*(?:Delete|delete)",
        "message": "CloudFormation resource deletes on stack removal. Use Retain for stateful resources.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cloudformation2_plaintext_parameter",
        "pattern": r"(?i)Type\s*:\s*String\s*\n\s*(?:(?!NoEcho)[^:]*:)",
        "message": "CloudFormation parameter without NoEcho for potential secret. Add NoEcho: true.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "cloudformation2_no_encryption",
        "pattern": r"(?i)AWS::S3::Bucket(?:(?!BucketEncryption|ServerSideEncryption)[^}])*\}",
        "message": "S3 bucket in CloudFormation without encryption. Enable SSE-S3 or SSE-KMS.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "terraform2_open_security_group",
        "pattern": r'(?i)(?:ingress|security_group_rule)(?:[^}]*)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "message": "Security group open to the world. Restrict CIDR blocks to known IP ranges.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "terraform2_no_lifecycle_prevent",
        "pattern": r"(?i)resource\s+\"aws_db_instance\"(?:(?!prevent_destroy)[^}])*\}",
        "message": "RDS instance without prevent_destroy lifecycle rule. Protect against accidental deletion.",
        "severity": Severity.WARN,
        "file_types": [".tf"],
    },
    {
        "id": "cdk2_no_access_logging",
        "pattern": r"(?i)(?:Bucket|Distribution|LoadBalancer)\s*\((?:(?!access_log|server_access_logs|logging)[^)]*)\)",
        "message": "CDK resource without access logging. Enable access logs for audit and debugging.",
        "severity": Severity.INFO,
    },
    {
        "id": "cloudformation2_hardcoded_ami",
        "pattern": r"(?i)ImageId\s*:\s*ami-[0-9a-f]{8,17}",
        "message": "Hardcoded AMI ID in CloudFormation. Use SSM parameter or mapping for maintainability.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "pulumi_no_tags",
        "pattern": r"(?i)(?:aws|azure|gcp)\.\w+\.\w+\s*\((?:(?!tags|labels)[^)]*)\)",
        "message": "Cloud resource created without tags. Add cost allocation and environment tags.",
        "severity": Severity.INFO,
    },
    {
        "id": "terraform2_sensitive_output",
        "pattern": r'(?i)output\s+"[^"]*(?:password|secret|key|token)[^"]*"\s*\{(?:(?!sensitive\s*=\s*true)[^}])*\}',
        "message": "Terraform output with sensitive data not marked sensitive. Add sensitive = true.",
        "severity": Severity.BLOCK,
        "file_types": [".tf"],
    },
    # =====================================================================
    # Config management (ansible2_, puppet_, chef_, saltstack_) - 20 rules
    # =====================================================================
    {
        "id": "ansible2_plaintext_password",
        "pattern": r'(?i)(?:password|passwd|secret)\s*:\s*["\']?(?!\\{\\{)[^"\'{\\}\n]+["\']?\s*$',
        "message": "Plaintext password in Ansible. Use ansible-vault to encrypt sensitive variables.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible2_shell_injection",
        "pattern": r"(?i)(?:shell|command)\s*:\s*.*\\{\\{\s*\w+\s*\\}\\}",
        "message": "Ansible shell module with variable interpolation. Use quote filter to prevent injection.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible2_no_become_method",
        "pattern": r"(?i)become\s*:\s*(?:yes|true)(?:(?!become_method)[^:]*:)",
        "message": "Ansible privilege escalation without become_method. Specify become_method explicitly.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible2_ignore_errors",
        "pattern": r"(?i)ignore_errors\s*:\s*(?:yes|true)",
        "message": "Ansible task ignoring errors. Use failed_when or register to handle errors explicitly.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible2_no_handlers",
        "pattern": r"(?i)(?:service|systemd)\s*:.*state\s*:\s*(?:restarted|reloaded)(?:(?!notify|handler|when)[^:]*$)",
        "message": "Direct service restart instead of handler. Use notify/handlers for idempotent restarts.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "puppet_plaintext_secret",
        "pattern": r"(?i)(?:password|secret|key)\s*=>\s*[\"'][^$][^\"']+[\"']",
        "message": "Plaintext secret in Puppet manifest. Use hiera-eyaml or Vault for secret management.",
        "severity": Severity.BLOCK,
        "file_types": [".pp"],
    },
    {
        "id": "puppet_exec_no_path",
        "pattern": r"(?i)exec\s*\{\s*[\"'][^\"']+[\"']\s*:(?:(?!path\s*=>)[^}])*\}",
        "message": "Puppet exec without path parameter. Specify full path for predictable execution.",
        "severity": Severity.WARN,
        "file_types": [".pp"],
    },
    {
        "id": "puppet_exec_no_unless",
        "pattern": r"(?i)exec\s*\{\s*[\"'][^\"']+[\"']\s*:(?:(?!unless|onlyif|creates|refreshonly)[^}])*\}",
        "message": "Puppet exec without guard condition. Add unless/onlyif for idempotent execution.",
        "severity": Severity.WARN,
        "file_types": [".pp"],
    },
    {
        "id": "puppet_file_mode_permissive",
        "pattern": r"(?i)mode\s*=>\s*[\"']0?(?:777|666|775)[\"']",
        "message": "Overly permissive file mode in Puppet. Use restrictive permissions (0644 or 0600).",
        "severity": Severity.BLOCK,
        "file_types": [".pp"],
    },
    {
        "id": "puppet_no_ensure",
        "pattern": r"(?i)(?:package|service|file)\s*\{\s*[\"'][^\"']+[\"']\s*:(?:(?!ensure\s*=>)[^}])*\}",
        "message": "Puppet resource without ensure parameter. Always specify desired state explicitly.",
        "severity": Severity.WARN,
        "file_types": [".pp"],
    },
    {
        "id": "chef_plaintext_data_bag",
        "pattern": r"(?i)data_bag_item\s*\(\s*[\"'][^\"']+[\"']\s*,(?:(?!encrypted)[^)]*)\)",
        "message": "Chef unencrypted data bag for potential secrets. Use encrypted data bags or Chef Vault.",
        "severity": Severity.WARN,
    },
    {
        "id": "chef_shell_command",
        "pattern": r"(?i)(?:execute|bash)\s+[\"'][^\"']+[\"']\s+do\s*\n(?:(?!not_if|only_if|creates|guard)[^e]*end)",
        "message": "Chef execute resource without guard. Add not_if/only_if for idempotent execution.",
        "severity": Severity.WARN,
    },
    {
        "id": "chef_no_version_pin",
        "pattern": r"(?i)depends\s+[\"'][^\"']+[\"']\s*$",
        "message": "Chef cookbook dependency without version pin. Specify version to prevent breaking changes.",
        "severity": Severity.WARN,
    },
    {
        "id": "chef_file_from_url",
        "pattern": r"(?i)remote_file\s+[^d]*do(?:(?!checksum|verify)[^e]*end)",
        "message": "Chef remote_file without checksum verification. Add checksum for integrity validation.",
        "severity": Severity.WARN,
    },
    {
        "id": "chef_sensitive_log",
        "pattern": r"(?i)(?:log|Chef::Log)\s*[.(]\s*[\"'].*(?:password|secret|token|key).*[\"']",
        "message": "Logging sensitive data in Chef. Use sensitive property to suppress output.",
        "severity": Severity.WARN,
    },
    {
        "id": "saltstack_plaintext_pillar",
        "pattern": r"(?i)(?:password|secret|token)\s*:\s*[^\n{#]+$",
        "message": "Plaintext secret in Salt pillar. Use GPG-encrypted pillar or external secret store.",
        "severity": Severity.WARN,
        "file_types": [".sls"],
    },
    {
        "id": "saltstack_cmd_run_unsafe",
        "pattern": r"(?i)cmd\.run\s*:\s*\n\s*-\s*name\s*:.*\\{\\{",
        "message": "Salt cmd.run with Jinja interpolation. Use cmd.run with runas and shell=False.",
        "severity": Severity.WARN,
        "file_types": [".sls"],
    },
    {
        "id": "saltstack_no_require",
        "pattern": r"(?i)(?:pkg|service|file)\.\w+\s*:\s*\n(?:(?!require|watch|listen)[^:]*:)*\s*$",
        "message": "Salt state without dependency ordering. Use require/watch for execution order.",
        "severity": Severity.INFO,
        "file_types": [".sls"],
    },
    {
        "id": "ansible2_no_check_mode",
        "pattern": r"(?i)(?:lineinfile|replace|template)\s*:(?:(?!check_mode|diff)[^:]*:)*\s*$",
        "message": "Ansible file modification without check_mode support. Ensure task works with --check.",
        "severity": Severity.INFO,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "ansible2_raw_module",
        "pattern": r"(?i)\braw\s*:\s*",
        "message": "Using Ansible raw module bypasses idempotency. Use specific modules (apt, yum, etc.).",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    # =====================================================================
    # Security tooling (packer_, vault_) - 10 rules
    # =====================================================================
    {
        "id": "packer_insecure_communicator",
        "pattern": r'(?i)communicator\s*[:=]\s*"(?:ssh|winrm)"(?:(?!ssh_private_key|keypair|certificate)[^}])*',
        "message": "Packer communicator without key-based auth. Use SSH keys instead of passwords.",
        "severity": Severity.WARN,
    },
    {
        "id": "packer_no_checksum",
        "pattern": r"(?i)iso_url\s*[:=](?:(?!iso_checksum|checksum)[^}])*\}",
        "message": "Packer ISO source without checksum. Add iso_checksum for download integrity.",
        "severity": Severity.WARN,
    },
    {
        "id": "packer_shell_provisioner_curl",
        "pattern": r'(?i)type\s*[:=]\s*"shell"[^}]*inline\s*[:=].*curl\s+[^|]*\|\s*(?:bash|sh)',
        "message": "Packer shell provisioner piping curl to shell. Download then verify before executing.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "packer_root_builder",
        "pattern": r'(?i)ssh_username\s*[:=]\s*"root"',
        "message": "Packer building as root user. Use non-root user with sudo for security.",
        "severity": Severity.WARN,
    },
    {
        "id": "packer_no_cleanup",
        "pattern": r'(?i)type\s*[:=]\s*"shell"(?:(?!cleanup|rm\s+-rf|apt\s+clean|yum\s+clean)[^}]*)\}',
        "message": "Packer provisioner without cleanup step. Remove caches and temp files to reduce image size.",
        "severity": Severity.INFO,
    },
    {
        "id": "vault_default_policy",
        "pattern": r'(?i)policy\s*[:=]\s*["\']default["\']',
        "message": "Using Vault default policy. Create specific policies with least-privilege access.",
        "severity": Severity.WARN,
        "file_types": [".hcl"],
    },
    {
        "id": "vault_root_token_usage",
        "pattern": r"(?i)(?:VAULT_TOKEN|vault_token)\s*[:=]\s*[\"'](?:root|hvs\.\w+)[\"']",
        "message": "Hardcoded or root Vault token. Use dynamic tokens with limited TTL and policies.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "vault_no_audit_backend",
        "pattern": r"(?i)vault\s+(?:server|operator)(?:(?!audit|enable\s+audit)[^;])*",
        "message": "Vault deployment without audit backend. Enable audit logging for compliance.",
        "severity": Severity.WARN,
    },
    {
        "id": "vault_auto_unseal_no_kms",
        "pattern": r"(?i)seal\s*\{(?:(?!awskms|gcpckms|azurekeyvault|transit)[^}])*\}",
        "message": "Vault seal configuration without KMS backend. Use cloud KMS for auto-unseal security.",
        "severity": Severity.INFO,
        "file_types": [".hcl"],
    },
    {
        "id": "vault_wide_path_policy",
        "pattern": r'(?i)path\s+"[^"]*\*[^"]*"\s*\{\s*capabilities\s*=\s*\[.*"(?:sudo|root)"',
        "message": "Vault policy with wildcard path and sudo capability. Restrict paths and capabilities.",
        "severity": Severity.BLOCK,
        "file_types": [".hcl"],
    },
    # =====================================================================
    # Observability (obs_) - 10 rules
    # =====================================================================
    {
        "id": "obs_missing_health_check",
        "pattern": r"(?i)(?:app|server|express|fastapi|flask)\s*(?:=|\()",
        "special_handler": "check_obs_health_check",
        "message": "Application without health check endpoint. Add /health for load balancer monitoring.",
        "severity": Severity.WARN,
        "suggestion": "Add a health check endpoint: @app.get('/health') or app.get('/healthz', handler).",
    },
    {
        "id": "obs_no_circuit_breaker",
        "pattern": r"(?i)(?:httpx?|axios|fetch|requests)\.\w+\s*\((?:(?!circuit_?breaker|breaker|resilience|retry)[^)]*)\)",
        "message": "External call without circuit breaker. Add circuit breaker to prevent cascade failures.",
        "severity": Severity.INFO,
    },
    {
        "id": "obs_debug_log_production",
        "pattern": r"(?i)(?:log_level|LOG_LEVEL|logging\.level)\s*[:=]\s*[\"']?(?:DEBUG|TRACE)[\"']?(?:(?!if|env|development|test)[^;])*",
        "message": "Debug log level may be active in production. Use INFO or WARN for production logging.",
        "severity": Severity.WARN,
    },
    {
        "id": "obs_no_request_tracing",
        "pattern": r"(?i)(?:app|router)\.\w+\s*\(\s*[\"']/[^\"']+[\"'](?:(?!trace|correlation|request_id|span)[^)]*)\)",
        "message": "HTTP endpoint without request tracing. Add correlation ID for distributed tracing.",
        "severity": Severity.INFO,
    },
    {
        "id": "obs_no_error_rate_metric",
        "pattern": r"(?i)(?:except|catch)\s*(?:\(|:)(?:(?!metric|counter|increment|statsd|prometheus)[^;])*;",
        "message": "Error handler without metrics. Track error rates for alerting and SLO monitoring.",
        "severity": Severity.INFO,
    },
    {
        "id": "obs_log_sensitive_data",
        "pattern": r"(?i)(?:log|logger)\.\w+\s*\(.*(?:password|credit_card|ssn|social_security)\s*=(?!.*(?:mask|redact|\*+|hash)).*\)",
        "message": "Logging potentially sensitive data. Mask or redact PII and secrets from logs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "obs_no_latency_metric",
        "pattern": r"(?i)(?:@app\.route|@router\.\w+|app\.\w+)\s*\((?:(?!histogram|latency|duration|timer|observe)[^)]*)\)",
        "message": "HTTP endpoint without latency metrics. Add response time histogram for SLO tracking.",
        "severity": Severity.INFO,
    },
    {
        "id": "obs_unstructured_logging",
        "pattern": r"(?i)(?:logging|logger)\.\w+\s*\(\s*f?[\"'].*[\"']\s*\)(?:(?!extra|structlog|json|dict)[^;])*",
        "message": "Unstructured log message. Use structured logging with key-value pairs for searchability.",
        "severity": Severity.INFO,
    },
    {
        "id": "obs_no_alert_threshold",
        "pattern": r"(?i)(?:gauge|counter|histogram)\s*\((?:(?!alert|threshold|warn|critical)[^)]*)\)",
        "message": "Metric without alert threshold. Define alerting rules for critical metrics.",
        "severity": Severity.INFO,
    },
    {
        "id": "obs_missing_readiness_probe",
        "pattern": r"(?i)(?:livenessProbe|liveness_probe)(?:(?!readinessProbe|readiness_probe)[^}])*\}",
        "message": "Kubernetes liveness probe without readiness probe. Add readiness probe for traffic routing.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  OS-SPECIFIC SECURITY (rules 1403-1427)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "win_registry_write_unrestricted",
        "pattern": r"(?i)(?:RegSetValueEx|RegCreateKeyEx|winreg\.SetValueEx)\s*\(",
        "message": "Unrestricted Windows registry write. Validate key path and permissions first.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "win_disable_firewall",
        "pattern": r"(?i)(?:netsh\s+advfirewall\s+set\s+\w+profile\s+state\s+off|Set-NetFirewallProfile.*-Enabled\s+False)",
        "message": "Disabling Windows firewall. Never disable firewall programmatically.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "win_disable_defender",
        "pattern": r"(?i)(?:Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true|sc\s+stop\s+WinDefend)",
        "message": "Disabling Windows Defender. Never disable antivirus in production code.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "win_runas_admin",
        "pattern": r"(?i)(?:runas\s+/user:Administrator|Start-Process.*-Verb\s+RunAs)",
        "message": "Elevating to admin privileges. Use least-privilege principle.",
        "severity": Severity.WARN,
    },
    {
        "id": "win_credential_manager_extract",
        "pattern": r"(?i)(?:CredRead|CredEnumerate|vaultcmd\s+/listcreds|Get-StoredCredential)",
        "message": "Extracting credentials from Windows Credential Manager. Verify authorization.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "win_disable_uac",
        "pattern": r"(?i)(?:EnableLUA.*(?:0|false)|ConsentPromptBehaviorAdmin.*0)",
        "message": "Disabling UAC. Never lower user account control in production.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "win_sam_database_access",
        "pattern": r"(?i)(?:SAM|SECURITY|SYSTEM).*(?:reg\s+save|copy|export)",
        "message": "Accessing SAM database. This is a credential theft vector.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "win_powershell_bypass_policy",
        "pattern": r"(?i)(?:Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)|powershell.*-(?:ep|ExecutionPolicy)\s+(?:bypass|unrestricted))",
        "message": "Bypassing PowerShell execution policy. Use signed scripts instead.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_setuid_binary",
        "pattern": r"(?i)chmod\s+[ugo]*\+s\s|chmod\s+[2467]\d{3}\s",
        "message": "Setting SUID/SGID bit on binary. This enables privilege escalation.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_shadow_file_read",
        "pattern": r"(?i)(?:open|read|cat|head|tail)\s*\(?\s*[\"']/etc/shadow",
        "message": "Reading /etc/shadow. Never access password hashes directly.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_passwd_modification",
        "pattern": r"(?i)(?:usermod|useradd|passwd)\s.*(?:-p\s|--password)",
        "message": "Modifying user passwords via CLI. Use PAM or dedicated auth service.",
        "severity": Severity.WARN,
    },
    {
        "id": "linux_sudoers_edit",
        "pattern": r"(?i)(?:echo|cat|tee).*(?:/etc/sudoers|visudo)",
        "message": "Editing sudoers file. Use visudo and audit all sudo rule changes.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_kernel_module_load",
        "pattern": r"(?i)(?:insmod|modprobe)\s+(?!.*--dry-run)",
        "message": "Loading kernel module. Verify module signature before loading.",
        "severity": Severity.WARN,
    },
    {
        "id": "linux_disable_selinux",
        "pattern": r"(?i)(?:setenforce\s+0|SELINUX\s*=\s*(?:disabled|permissive))",
        "message": "Disabling SELinux. Keep mandatory access controls enforcing.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_iptables_flush",
        "pattern": r"(?i)iptables\s+-F(?:\s|$)|nft\s+flush\s+ruleset",
        "message": "Flushing all firewall rules. Apply targeted rule changes instead.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_cron_world_writable",
        "pattern": r"(?i)chmod\s+(?:777|666|o\+w).*(?:cron|crontab)",
        "message": "Making cron files world-writable. Restrict to owner-only permissions.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "linux_proc_mem_access",
        "pattern": r"(?i)(?:open|read)\s*\(?\s*[\"']/proc/\d+/mem",
        "message": "Reading process memory. This is a debugging-only operation.",
        "severity": Severity.WARN,
    },
    {
        "id": "macos_keychain_dump",
        "pattern": r"(?i)(?:security\s+dump-keychain|security\s+find-generic-password\s+-w)",
        "message": "Dumping macOS Keychain. Use Keychain Services API with proper entitlements.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "macos_gatekeeper_disable",
        "pattern": r"(?i)(?:spctl\s+--master-disable|spctl\s+--disable)",
        "message": "Disabling Gatekeeper. Never bypass code signing verification.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "macos_sip_disable",
        "pattern": r"(?i)csrutil\s+disable",
        "message": "Disabling System Integrity Protection. Never disable SIP programmatically.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "macos_tcc_bypass",
        "pattern": r"(?i)(?:tccutil\s+reset|tccutil\s+reset\s+All|com\.apple\.TCC)",
        "message": "Attempting TCC bypass. Request proper entitlements instead.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "macos_launch_daemon_install",
        "pattern": r"(?i)(?:launchctl\s+load|/Library/LaunchDaemons/)(?!.*(?:unload|status))",
        "message": "Installing launch daemon. Verify code signature and restrict permissions.",
        "severity": Severity.WARN,
    },
    {
        "id": "win_wmi_exec",
        "pattern": r"(?i)(?:wmic\s+process\s+call\s+create|Win32_Process\.Create)",
        "message": "WMI process creation. Use proper process management APIs.",
        "severity": Severity.WARN,
    },
    {
        "id": "linux_capability_escalation",
        "pattern": r"(?i)setcap\s+.*(?:cap_sys_admin|cap_net_admin|cap_dac_override)\+ep",
        "message": "Granting dangerous Linux capabilities. Use minimal capability set.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "macos_privacy_db_access",
        "pattern": r"(?i)(?:TCC\.db|com\.apple\.TCC/TCC\.db)",
        "message": "Direct TCC database access. Use proper permission request APIs.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SERVICE MESH SECURITY (rules 1428-1447)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "istio_permissive_mtls",
        "pattern": r"(?i)(?:mode:\s*(?:PERMISSIVE|DISABLE)|PeerAuthentication.*mode.*PERMISSIVE)",
        "message": "Istio mTLS set to permissive. Use STRICT mode in production.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "istio_allow_all_traffic",
        "pattern": r"(?i)(?:action:\s*ALLOW\s*$|AuthorizationPolicy.*rules:\s*\[\])",
        "message": "Istio policy allows all traffic. Define explicit allow rules.",
        "severity": Severity.WARN,
    },
    {
        "id": "istio_sidecar_injection_disabled",
        "pattern": r"(?i)sidecar\.istio\.io/inject.*[\"']?false[\"']?",
        "message": "Istio sidecar injection disabled. Enable for mesh security coverage.",
        "severity": Severity.WARN,
    },
    {
        "id": "istio_no_request_auth",
        "pattern": r"(?i)RequestAuthentication.*jwtRules:\s*\[\]",
        "message": "Istio request auth with empty JWT rules. Define JWT validation.",
        "severity": Severity.WARN,
    },
    {
        "id": "istio_outbound_unrestricted",
        "pattern": r"(?i)outboundTrafficPolicy:\s*(?:mode:\s*)?ALLOW_ANY",
        "message": "Istio allows all outbound traffic. Use REGISTRY_ONLY for egress control.",
        "severity": Severity.WARN,
    },
    {
        "id": "istio_debug_port_exposed",
        "pattern": r"(?i)(?:istiod|pilot).*(?:15014|15004|8080).*(?:expose|NodePort|LoadBalancer)",
        "message": "Istio debug/admin port exposed externally. Restrict to cluster-internal.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "envoy_admin_exposed",
        "pattern": r"(?i)admin:\s*\n\s*(?:address|access_log_path).*(?:0\.0\.0\.0|[:]{2})",
        "message": "Envoy admin interface exposed on all interfaces. Bind to localhost only.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "envoy_no_tls_context",
        "pattern": r"(?i)(?:transport_socket|tls_context):\s*\{\s*\}",
        "message": "Envoy listener without TLS context. Configure TLS for encrypted traffic.",
        "severity": Severity.WARN,
    },
    {
        "id": "envoy_permissive_cors",
        "pattern": r"(?i)allow_origin_string_match.*(?:safe_regex.*\.\*|prefix:\s*[\"'][\"'])",
        "message": "Envoy CORS allows all origins. Restrict to specific domains.",
        "severity": Severity.WARN,
    },
    {
        "id": "envoy_no_rate_limit",
        "pattern": r"(?i)(?:virtual_host|route_config|http_filters)(?!.*(?:rate_limit|ratelimit|local_rate_limit))",
        "message": "Envoy route without rate limiting. Add rate limit filter.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml", ".json"],
    },
    {
        "id": "envoy_plaintext_upstream",
        "pattern": r"(?i)clusters:.*(?:type:\s*STRICT_DNS|LOGICAL_DNS)(?!.*transport_socket)",
        "message": "Envoy upstream without TLS. Enable TLS for upstream connections.",
        "severity": Severity.WARN,
    },
    {
        "id": "consul_no_acl",
        "pattern": r"(?i)(?:acl\s*=\s*\{[^}]*enabled\s*=\s*false|\"acl\".*\"enabled\".*false)",
        "message": "Consul ACL disabled. Enable ACL for access control.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "consul_default_allow",
        "pattern": r"(?i)default_policy\s*=\s*[\"']allow[\"']",
        "message": "Consul default policy is allow. Use deny-by-default.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "consul_gossip_no_encryption",
        "pattern": r"(?i)encrypt\s*=\s*[\"'][\"']|encrypt_verify_incoming\s*=\s*false",
        "message": "Consul gossip encryption disabled. Enable encrypt key for cluster communication.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "consul_http_no_tls",
        "pattern": r"(?i)(?:https?\s*=\s*(?:-1|0|false)|verify_incoming\s*=\s*false)",
        "message": "Consul HTTP without TLS. Enable HTTPS for API access.",
        "severity": Severity.WARN,
    },
    {
        "id": "consul_anonymous_token",
        "pattern": r"(?i)(?:anonymous|00000000-0000-0000-0000-000000000002).*(?:policy|role|service)",
        "message": "Consul anonymous token with privileges. Restrict anonymous access.",
        "severity": Severity.WARN,
    },
    {
        "id": "istio_gateway_no_tls",
        "pattern": r"(?i)Gateway.*servers:.*port.*protocol:\s*HTTP(?!S)",
        "message": "Istio Gateway serving plain HTTP. Configure TLS termination.",
        "severity": Severity.WARN,
    },
    {
        "id": "envoy_no_access_log",
        "pattern": r"(?i)(?:listeners|filter_chains)(?!.*access_log)",
        "message": "Envoy listener without access logging. Enable access logs for observability.",
        "severity": Severity.INFO,
    },
    {
        "id": "istio_no_peer_auth",
        "pattern": r"(?i)apiVersion:\s*security\.istio\.io.*kind:\s*AuthorizationPolicy(?!.*PeerAuthentication)",
        "message": "Authorization without peer authentication. Add PeerAuthentication policy.",
        "severity": Severity.WARN,
    },
    {
        "id": "consul_service_no_intention",
        "pattern": r"(?i)service\s*\{[^}]*(?!.*intention|connect)",
        "message": "Consul service without Connect intentions. Define service-to-service ACLs.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  HASHICORP STACK SECURITY (rules 1448-1462)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "vault2_token_hardcoded",
        "pattern": r"(?i)(?:VAULT_TOKEN|vault_token|X-Vault-Token)\s*[:=]\s*[\"'][hs]\.[A-Za-z0-9]{20,}[\"']",
        "message": "Hardcoded Vault token. Use dynamic token retrieval or auth methods.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "vault2_unseal_key_in_code",
        "pattern": r"(?i)(?:unseal_key|VAULT_UNSEAL|seal.*key)\s*[:=]\s*[\"'][A-Za-z0-9+/=]{30,}[\"']",
        "message": "Vault unseal key in source code. Use auto-unseal with cloud KMS.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "vault2_dev_mode_production",
        "pattern": r"(?i)vault\s+server\s+-dev(?:\s|$)",
        "message": "Vault running in dev mode. Never use dev mode in production.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "vault2_root_token_usage",
        "pattern": r"(?i)(?:root_token|initial_root_token|Root\s+Token)\s*[:=]",
        "message": "Using Vault root token. Create specific policies and use limited tokens.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "vault2_tls_skip_verify",
        "pattern": r"(?i)(?:VAULT_SKIP_VERIFY|tls_skip_verify)\s*[:=]\s*(?:true|1|[\"']true[\"'])",
        "message": "Skipping Vault TLS verification. Always verify TLS certificates.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "vault2_wildcard_policy",
        "pattern": r"(?i)path\s+[\"']\*[\"']\s*\{[^}]*capabilities.*(?:create|update|delete|sudo)",
        "message": "Vault wildcard policy with write capabilities. Use specific paths.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "nomad_no_acl",
        "pattern": r"(?i)acl\s*\{[^}]*enabled\s*=\s*false",
        "message": "Nomad ACL disabled. Enable ACL for job access control.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "nomad_raw_exec_driver",
        "pattern": r"(?i)driver\s*=\s*[\"']raw_exec[\"']",
        "message": "Nomad raw_exec driver used. Use Docker or exec driver with isolation.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "nomad_privileged_job",
        "pattern": r"(?i)privileged\s*=\s*true",
        "message": "Nomad job running privileged. Remove privileged mode.",
        "severity": Severity.WARN,
    },
    {
        "id": "boundary_no_tls",
        "pattern": r"(?i)(?:tls_disable|disable_mlock)\s*=\s*(?:true|1)",
        "message": "Boundary TLS or mlock disabled. Enable for secure session management.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "boundary_default_password",
        "pattern": r"(?i)boundary.*(?:password|secret)\s*[:=]\s*[\"'](?:password|admin|boundary|default)[\"']",
        "message": "Boundary using default password. Set strong unique credentials.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "waypoint_no_auth",
        "pattern": r"(?i)waypoint\s+(?:server|install)(?!.*(?:tls|auth|token))",
        "message": "Waypoint server without authentication. Configure auth token.",
        "severity": Severity.WARN,
    },
    {
        "id": "vault2_audit_disabled",
        "pattern": r"(?i)vault\s+audit\s+disable|disable_audit",
        "message": "Vault audit logging disabled. Audit backends are mandatory for compliance.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "nomad_no_tls",
        "pattern": r"(?i)tls\s*\{[^}]*(?:http\s*=\s*false|rpc\s*=\s*false)",
        "message": "Nomad TLS disabled for HTTP or RPC. Enable TLS for all communications.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "waypoint_plaintext_runner",
        "pattern": r"(?i)waypoint\s+runner.*(?:odr|on-demand)(?!.*tls)",
        "message": "Waypoint runner without TLS. Enable TLS for runner communication.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DEVOPS PLATFORM SECURITY (rules 1463-1482)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "github_token_hardcoded",
        "pattern": r"(?:GITHUB_TOKEN|github_pat|gh[pousr]_[A-Za-z0-9]{30,})\s*=\s*[\"'][^\"']{5,}[\"']",
        "message": "GitHub token in source code. Use secrets management or OIDC.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "github_actions_pull_request_target",
        "pattern": r"(?i)on:\s*pull_request_target(?!.*(?:labeled|review))",
        "message": "Using pull_request_target without restrictions. Limit trigger conditions.",
        "severity": Severity.WARN,
    },
    {
        "id": "github_actions_script_injection",
        "pattern": r"(?i)\$\{\{\s*github\.event\.(?:issue|pull_request|comment)\.(?:title|body)",
        "message": "GitHub Actions script injection risk. Sanitize event data before use.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "github_actions_permissions_write_all",
        "pattern": r"(?i)permissions:\s*write-all",
        "message": "GitHub Actions with write-all permissions. Use least-privilege permissions.",
        "severity": Severity.WARN,
    },
    {
        "id": "github_webhook_no_secret",
        "pattern": r"(?i)webhook.*(?:secret|token)\s*[:=]\s*[\"'][\"']|create_hook.*(?!.*secret)",
        "message": "GitHub webhook without secret. Always set webhook secret for verification.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "gitlab2_token_exposed",
        "pattern": r"(?i)(?:glpat-[A-Za-z0-9_-]{20,}|GITLAB_TOKEN|gitlab.*private.token)",
        "message": "GitLab token in source code. Use CI/CD variables or vault.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "gitlab2_runner_untagged",
        "pattern": r"(?i)(?:run_untagged:\s*true|tags:\s*\[\])",
        "message": "GitLab runner accepts untagged jobs. Use tags for job isolation.",
        "severity": Severity.WARN,
    },
    {
        "id": "gitlab2_shared_runner_secret",
        "pattern": r"(?i)(?:registration.token|RUNNER_TOKEN|runner.*token)\s*[:=]\s*[\"'][A-Za-z0-9_-]{10,}[\"']",
        "message": "GitLab runner token in code. Use environment variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "gitlab2_allow_failure_security",
        "pattern": r"(?i)(?:sast|dast|dependency.scanning|secret.detection).*allow_failure:\s*true",
        "message": "Security scan set to allow_failure. Security scans should block pipeline.",
        "severity": Severity.WARN,
    },
    {
        "id": "bitbucket2_app_password_exposed",
        "pattern": r"(?i)(?:BITBUCKET_APP_PASSWORD|bitbucket.*app_password)\s*[:=]\s*[\"'][A-Za-z0-9]{10,}[\"']",
        "message": "Bitbucket app password in source. Use repository variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "bitbucket2_pipeline_no_step_restriction",
        "pattern": r"(?i)pipelines:.*step:(?!.*(?:deployment|trigger|condition))",
        "message": "Bitbucket pipeline step without restrictions. Add deployment conditions.",
        "severity": Severity.INFO,
    },
    {
        "id": "github_actions_checkout_untrusted",
        "pattern": r"(?i)uses:\s*actions/checkout.*ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha",
        "message": "Checking out untrusted PR code. Validate source before checkout.",
        "severity": Severity.WARN,
    },
    {
        "id": "github_branch_protection_bypass",
        "pattern": r"(?i)(?:enforce_admins|required_pull_request_reviews).*(?:false|disabled|null)",
        "message": "Disabling branch protection. Keep branch protection enforced.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "gitlab2_ci_debug_enabled",
        "pattern": r"(?i)CI_DEBUG_TRACE\s*[:=]\s*[\"']?true",
        "message": "GitLab CI debug trace enabled. Disable in production pipelines.",
        "severity": Severity.WARN,
    },
    {
        "id": "bitbucket2_pipeline_docker_privileged",
        "pattern": r"(?i)pipelines:.*options:.*docker:\s*true.*(?!.*--security-opt)",
        "message": "Bitbucket pipeline with Docker in Docker. Add security constraints.",
        "severity": Severity.WARN,
    },
    {
        "id": "github_actions_self_hosted_public",
        "pattern": r"(?i)runs-on:\s*self-hosted(?!.*(?:private|internal))",
        "message": "Self-hosted runner on public repo. Use GitHub-hosted for public repos.",
        "severity": Severity.WARN,
    },
    {
        "id": "gitlab2_container_registry_public",
        "pattern": r"(?i)container_registry.*(?:visibility|access).*(?:public|enabled)",
        "message": "GitLab container registry set to public. Restrict to private.",
        "severity": Severity.WARN,
    },
    {
        "id": "bitbucket2_webhook_no_ssl",
        "pattern": r"(?i)webhook.*(?:url|endpoint)\s*[:=]\s*[\"']http://",
        "message": "Bitbucket webhook over HTTP. Use HTTPS for webhook endpoints.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "github_deploy_key_write",
        "pattern": r"(?i)deploy.*key.*(?:read_write|write)\s*[:=]\s*true",
        "message": "GitHub deploy key with write access. Use read-only unless write is required.",
        "severity": Severity.WARN,
    },
    {
        "id": "gitlab2_project_access_token_exposed",
        "pattern": r"(?i)glpat-[A-Za-z0-9_-]{20,}",
        "message": "GitLab project access token exposed. Rotate and use CI variables.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  COLLABORATION TOOL SECURITY (rules 1483-1497)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "jira_api_token_hardcoded",
        "pattern": r"(?i)(?:JIRA_API_TOKEN|jira.*token|atlassian.*api.*key)\s*[:=]\s*[\"'][A-Za-z0-9]{10,}[\"']",
        "message": "Jira API token hardcoded. Use environment variables or secrets manager.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "jira_basic_auth_plaintext",
        "pattern": r"(?i)(?:jira|atlassian).*(?:Basic\s+[A-Za-z0-9+/=]{20,}|username.*password)",
        "message": "Jira basic auth with plaintext credentials. Use API tokens with OAuth.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "confluence_api_key_exposed",
        "pattern": r"(?i)(?:CONFLUENCE_API|confluence.*(?:token|key|secret))\s*[:=]\s*[\"'][A-Za-z0-9]{10,}[\"']",
        "message": "Confluence API key in source. Use secrets management.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "slack2_bot_token_exposed",
        "pattern": r"(?i)xoxb-[0-9]{9,13}-[0-9]{9,13}-[A-Za-z0-9]{20,}",
        "message": "Slack bot token in source code. Store in environment variable.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "slack2_user_token_exposed",
        "pattern": r"(?i)xoxp-[0-9]{9,13}-[0-9]{9,13}-[0-9]{9,13}-[a-f0-9]{32}",
        "message": "Slack user token in source code. Never commit user tokens.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "slack2_webhook_url_hardcoded",
        "pattern": r"(?i)hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "message": "Slack webhook URL hardcoded. Store in environment variable.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "discord_bot_token_exposed",
        "pattern": r"(?i)(?:DISCORD_TOKEN|discord.*bot.*token)\s*[:=]\s*[\"'][A-Za-z0-9._-]{50,}[\"']",
        "message": "Discord bot token in source. Use environment variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "discord_webhook_hardcoded",
        "pattern": r"(?i)discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        "message": "Discord webhook URL hardcoded. Store in configuration.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "webhook_no_signature_verification",
        "pattern": r"(?i)(?:webhook|hook).*(?:receive|handler|endpoint)(?!.*(?:verify|signature|hmac|digest))",
        "message": "Webhook handler without signature verification. Validate webhook signatures.",
        "severity": Severity.WARN,
    },
    {
        "id": "webhook_no_replay_protection",
        "pattern": r"(?i)(?:webhook|hook).*(?:process|handle)(?!.*(?:timestamp|nonce|idempoten))",
        "message": "Webhook without replay protection. Check timestamps and use idempotency keys.",
        "severity": Severity.INFO,
    },
    {
        "id": "slack2_signing_secret_exposed",
        "pattern": r"(?i)(?:SLACK_SIGNING_SECRET|signing_secret)\s*[:=]\s*[\"'][a-f0-9]{30,}[\"']",
        "message": "Slack signing secret exposed. Use secrets manager.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "jira_webhook_no_auth",
        "pattern": r"(?i)jira.*webhook.*(?:url|endpoint)(?!.*(?:secret|auth|token|hmac))",
        "message": "Jira webhook without authentication. Add webhook secret.",
        "severity": Severity.WARN,
    },
    {
        "id": "confluence_space_public",
        "pattern": r"(?i)(?:space|permission).*(?:anonymous|public)\s*[:=]\s*true",
        "message": "Confluence space set to public. Review space permissions.",
        "severity": Severity.WARN,
    },
    {
        "id": "webhook_http_endpoint",
        "pattern": r"(?i)webhook.*(?:url|endpoint|callback)\s*[:=]\s*[\"']http://(?!localhost|127\.0\.0\.1)",
        "message": "Webhook using HTTP endpoint. Use HTTPS for webhook callbacks.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "discord_permissions_admin",
        "pattern": r"(?i)(?:permissions|PERMISSIONS)\s*[:=]\s*[\"']?8[\"']?(?:\s|,|$)",
        "message": "Discord bot with admin permissions. Use least-privilege permission flags.",
        "severity": Severity.WARN,
    },

    # ═══════════════════════════════════════════════════════════════
    #  IDENTITY PROTOCOL SECURITY (rules 1498-1517)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "oauth3_implicit_grant",
        "pattern": r"(?i)(?:response_type\s*[:=]\s*[\"']token[\"']|grant_type.*implicit)",
        "message": "OAuth implicit grant flow. Use authorization code with PKCE instead.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth3_no_state_param",
        "pattern": r"(?i)(?:authorize|authorization).*(?:redirect|callback)(?!.*(?:state|nonce))",
        "message": "OAuth flow without state parameter. Add state to prevent CSRF.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth3_client_secret_in_frontend",
        "pattern": r"(?i)(?:client_secret|CLIENT_SECRET)\s*[:=]\s*[\"'][A-Za-z0-9_-]{10,}[\"']",
        "message": "OAuth client secret in code. Store server-side in environment variable.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth3_no_pkce",
        "pattern": r"(?i)grant_type\s*[:=]\s*[\"']authorization_code[\"'](?!.*code_verifier)",
        "message": "OAuth authorization code without PKCE. Add code_challenge for public clients.",
        "severity": Severity.WARN,
    },
    {
        "id": "oauth3_wildcard_redirect",
        "pattern": r"(?i)redirect_uri\s*[:=]\s*[\"'](?:https?://\*|.*\.\*)",
        "message": "OAuth wildcard redirect URI. Use exact redirect URIs.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "saml_no_signature_validation",
        "pattern": r"(?i)(?:validate_signature|want_assertions_signed|wantAssertionsSigned)\s*[:=]\s*(?:false|False|0)",
        "message": "SAML signature validation disabled. Always validate SAML assertions.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "saml_assertion_replay",
        "pattern": r"(?i)(?:allow_replay|check_assertion_id|notOnOrAfter)\s*[:=]\s*(?:false|False|0|none|None)",
        "message": "SAML assertion replay protection disabled. Enforce assertion ID and timestamp checks.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "saml_weak_digest",
        "pattern": r"(?i)(?:DigestMethod|SignatureMethod).*(?:sha1|md5|rsa-sha1)",
        "message": "SAML using weak digest algorithm. Use SHA-256 or stronger.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ldap_injection",
        "pattern": r"(?i)(?:ldap_search|search_s|search_ext)\s*\(.*(?:\+|format|f[\"']|%s)",
        "message": "LDAP query with string interpolation. Use parameterized LDAP queries.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ldap_anonymous_bind",
        "pattern": r"(?i)(?:simple_bind_s|bind_s)\s*\(\s*[\"'][\"']\s*,\s*[\"'][\"']",
        "message": "LDAP anonymous bind. Use authenticated bind with service account.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ldap_no_tls",
        "pattern": r"(?i)ldap://(?!.*(?:start_tls|StartTLS|STARTTLS))",
        "message": "LDAP without TLS. Use ldaps:// or STARTTLS.",
        "severity": Severity.WARN,
    },
    {
        "id": "kerberos_rc4_encryption",
        "pattern": r"(?i)(?:permitted_enctypes|default_tgs_enctypes).*(?:rc4|arcfour|des-cbc)",
        "message": "Kerberos using weak encryption (RC4/DES). Use AES-256 encryption types.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "kerberos_no_preauth",
        "pattern": r"(?i)(?:DONT_REQUIRE_PREAUTH|UF_DONT_REQUIRE_PREAUTH|preauth.*false)",
        "message": "Kerberos pre-authentication disabled. Enable to prevent AS-REP roasting.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "x509_self_signed_production",
        "pattern": r"(?i)(?:generate_self_signed|selfsigned|self_signed)\s*[:=]\s*true",
        "message": "Self-signed certificate in production. Use CA-signed certificates.",
        "severity": Severity.WARN,
    },
    {
        "id": "x509_no_revocation_check",
        "pattern": r"(?i)(?:check_crl|check_revocation|OCSP)\s*[:=]\s*(?:false|False|0|disabled)",
        "message": "Certificate revocation check disabled. Enable CRL or OCSP validation.",
        "severity": Severity.WARN,
    },
    {
        "id": "x509_weak_key_size",
        "pattern": r"(?i)(?:key_size|key_length|bits)\s*[:=]\s*(?:512|768|1024)(?:\s|,|$)",
        "message": "Weak certificate key size. Use minimum 2048-bit RSA or 256-bit EC.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "oauth3_token_in_url",
        "pattern": r"(?i)(?:access_token|bearer)\s*=\s*[A-Za-z0-9._-]{20,}",
        "message": "OAuth token passed in URL. Use Authorization header instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "saml_metadata_unsigned",
        "pattern": r"(?i)(?:sign_metadata|wantMetadataSigned)\s*[:=]\s*(?:false|False)",
        "message": "SAML metadata not signed. Sign metadata to prevent tampering.",
        "severity": Severity.WARN,
    },
    {
        "id": "x509_expired_cert_allowed",
        "pattern": r"(?i)(?:verify_expiry|check_expiry|allow_expired)\s*[:=]\s*(?:false|true)",
        "message": "Certificate expiry check disabled. Always validate certificate dates.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "ldap_password_in_config",
        "pattern": r"(?i)(?:ldap.*(?:bind_password|BIND_PW|manager_password))\s*[:=]\s*[\"'][^\"']{3,}[\"']",
        "message": "LDAP bind password in configuration. Use secrets manager.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  TOKEN AND HEADER SECURITY (rules 1518-1537)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "jwt2_none_algorithm",
        "pattern": r"(?i)(?:algorithm|alg)\s*[:=]\s*[\"'](?:none|None|NONE)[\"']",
        "message": "JWT none algorithm. Always specify a signing algorithm.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "jwt2_hmac_public_key_confusion",
        "pattern": r"(?i)(?:verify|decode)\s*\(.*(?:HS256|HS384|HS512).*(?:public_key|rsa_public|cert)",
        "message": "JWT algorithm confusion - HMAC with public key. Verify algorithm matches key type.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "jwt2_no_expiration",
        "pattern": r"(?i)(?:jwt|token).*(?:encode|sign|create)\s*\((?!.*(?:exp|expires|expiresIn|ttl))",
        "message": "JWT without expiration claim. Always set exp to limit token lifetime.",
        "severity": Severity.WARN,
    },
    {
        "id": "jwt2_weak_secret",
        "pattern": r"(?i)(?:jwt|token).*(?:secret|key)\s*[:=]\s*[\"'](?:secret|password|key|test|dev|123)[\"']",
        "message": "JWT with weak secret. Use cryptographically random secret of 256+ bits.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "jwt2_no_audience_check",
        "pattern": r"(?i)(?:verify_aud|verify_audience|audience)\s*[:=]\s*(?:false|False|0)",
        "message": "JWT audience verification disabled. Validate audience to prevent token misuse.",
        "severity": Severity.WARN,
    },
    {
        "id": "cors2_allow_all_origins",
        "pattern": r"(?i)(?:Access-Control-Allow-Origin|allow_origins)\s*[:=]\s*[\"']\*[\"']",
        "message": "CORS allows all origins. Restrict to specific trusted domains.",
        "severity": Severity.WARN,
    },
    {
        "id": "cors2_allow_credentials_wildcard",
        "pattern": r"(?i)(?:allow_credentials|Access-Control-Allow-Credentials)\s*[:=]\s*(?:true|True).*(?:allow_origins|Origin).*\*",
        "message": "CORS credentials with wildcard origin. This combination is insecure.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cors2_expose_all_headers",
        "pattern": r"(?i)(?:Access-Control-Expose-Headers|expose_headers)\s*[:=]\s*[\"']\*[\"']",
        "message": "CORS exposes all response headers. Limit exposed headers.",
        "severity": Severity.WARN,
    },
    {
        "id": "csp2_unsafe_inline",
        "pattern": r"(?i)Content-Security-Policy.*(?:unsafe-inline|unsafe-eval)",
        "message": "CSP with unsafe-inline or unsafe-eval. Use nonces or hashes instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "csp2_missing_frame_ancestors",
        "pattern": r"(?i)Content-Security-Policy(?!.*frame-ancestors)",
        "message": "CSP missing frame-ancestors. Add to prevent clickjacking.",
        "severity": Severity.WARN,
        "file_types": [".js", ".ts", ".py", ".yml", ".yaml", ".conf"],
        "skip_comments": True,
    },
    {
        "id": "hsts2_short_max_age",
        "pattern": r"(?i)Strict-Transport-Security.*max-age\s*=\s*(?:[0-9]{1,5})(?:\s|;|$)",
        "message": "HSTS max-age too short. Use minimum 31536000 (one year).",
        "severity": Severity.WARN,
    },
    {
        "id": "hsts2_missing_subdomains",
        "pattern": r"(?i)Strict-Transport-Security(?!.*includeSubDomains)",
        "message": "HSTS without includeSubDomains. Add to protect all subdomains.",
        "severity": Severity.INFO,
    },
    {
        "id": "hsts2_no_preload",
        "pattern": r"(?i)Strict-Transport-Security(?!.*preload)",
        "message": "HSTS without preload directive. Add preload for browser preload list.",
        "severity": Severity.INFO,
    },
    {
        "id": "sri_missing_integrity",
        "pattern": r"(?i)<script\s+src\s*=\s*[\"']https?://(?!.*integrity\s*=)",
        "message": "External script without SRI integrity hash. Add integrity attribute.",
        "severity": Severity.WARN,
    },
    {
        "id": "sri_weak_hash",
        "pattern": r"(?i)integrity\s*=\s*[\"'](?:sha256|md5)-",
        "message": "SRI using weak hash. Use sha384 or sha512.",
        "severity": Severity.WARN,
    },
    {
        "id": "referrer_unsafe_url",
        "pattern": r"(?i)Referrer-Policy\s*[:=]\s*[\"']unsafe-url[\"']",
        "message": "Referrer-Policy set to unsafe-url. Use strict-origin-when-cross-origin.",
        "severity": Severity.WARN,
    },
    {
        "id": "referrer_no_referrer_downgrade",
        "pattern": r"(?i)Referrer-Policy\s*[:=]\s*[\"']no-referrer-when-downgrade[\"']",
        "message": "Referrer-Policy allows downgrade leakage. Use strict-origin-when-cross-origin.",
        "severity": Severity.INFO,
    },
    {
        "id": "jwt2_kid_injection",
        "pattern": r"(?i)(?:kid|key_id)\s*[:=].*(?:sql|path|file|url|http)",
        "message": "JWT kid header with potential injection. Validate kid against allowlist.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "cors2_preflight_cache_long",
        "pattern": r"(?i)(?:Access-Control-Max-Age|max_age)\s*[:=]\s*(?:86400|604800|\d{6,})",
        "message": "CORS preflight cache too long. Use shorter max-age for security policy changes.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  DEPLOYMENT PATTERN SECURITY (rules 1538-1552)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "feature_flag2_stale_flag",
        "pattern": r"(?i)(?:feature_flag|feature_toggle|isEnabled)\s*\(\s*[\"'](?:temp|test|old|legacy|deprecated)",
        "message": "Potentially stale feature flag. Review and remove dead flags.",
        "severity": Severity.INFO,
    },
    {
        "id": "feature_flag2_no_default",
        "pattern": r"(?i)(?:feature_flag|get_flag|is_enabled)\s*\([^)]*\)(?!.*(?:default|fallback|\|\|))",
        "message": "Feature flag without default value. Always provide a safe fallback.",
        "severity": Severity.WARN,
    },
    {
        "id": "feature_flag2_boolean_only",
        "pattern": r"(?i)(?:feature_flag|toggle)\s*\(.*\)\s*(?:==|!=)\s*(?:true|false|True|False)(?!.*(?:variant|percentage))",
        "message": "Feature flag used as simple boolean. Consider gradual rollout with percentages.",
        "severity": Severity.INFO,
    },
    {
        "id": "ab_test_no_tracking",
        "pattern": r"(?i)(?:ab_test|experiment|variant)\s*\((?!.*(?:track|analytics|metric|event))",
        "message": "A/B test without tracking. Add analytics events to measure results.",
        "severity": Severity.WARN,
    },
    {
        "id": "ab_test_hardcoded_variant",
        "pattern": r"(?i)(?:variant|experiment_group)\s*[:=]\s*[\"'](?:control|treatment|A|B)[\"']",
        "message": "Hardcoded A/B test variant. Use random assignment from experiment service.",
        "severity": Severity.WARN,
    },
    {
        "id": "canary_no_rollback",
        "pattern": r"(?i)(?:canary|canary_deploy)(?!.*(?:rollback|revert|abort|failover))",
        "message": "Canary deployment without rollback strategy. Define automated rollback criteria.",
        "severity": Severity.WARN,
    },
    {
        "id": "canary_no_metrics",
        "pattern": r"(?i)(?:canary|canary_deploy)(?!.*(?:metric|monitor|health|error_rate))",
        "message": "Canary deployment without health metrics. Add metrics for promotion decision.",
        "severity": Severity.WARN,
    },
    {
        "id": "blue_green_no_healthcheck",
        "pattern": r"(?i)(?:blue.green|bluegreen).*(?:switch|swap|cutover)(?!.*(?:health|ready|check))",
        "message": "Blue-green cutover without health check. Verify target is healthy before switch.",
        "severity": Severity.WARN,
    },
    {
        "id": "blue_green_no_drain",
        "pattern": r"(?i)(?:blue.green|bluegreen).*(?:switch|cutover)(?!.*(?:drain|graceful|connection))",
        "message": "Blue-green without connection draining. Drain existing connections before switch.",
        "severity": Severity.WARN,
    },
    {
        "id": "feature_flag2_flag_in_data_layer",
        "pattern": r"(?i)(?:SELECT|INSERT|UPDATE|DELETE).*(?:feature_flag|feature_toggle|is_enabled)",
        "message": "Feature flag logic in SQL query. Keep flag evaluation in application layer.",
        "severity": Severity.WARN,
    },
    {
        "id": "canary_full_traffic",
        "pattern": r"(?i)(?:canary|weight)\s*[:=]\s*(?:100|1\.0)(?:\s|,|$)",
        "message": "Canary receiving full traffic. Start with small percentage and gradually increase.",
        "severity": Severity.WARN,
    },
    {
        "id": "ab_test_no_sample_size",
        "pattern": r"(?i)(?:experiment|ab_test).*(?:start|launch|begin)(?!.*(?:sample|size|power|significance))",
        "message": "A/B test without sample size calculation. Define statistical power requirements.",
        "severity": Severity.INFO,
    },
    {
        "id": "blue_green_same_db",
        "pattern": r"(?i)(?:blue.green|bluegreen).*(?:database|db).*(?:shared|same|single)",
        "message": "Blue-green sharing database. Plan for schema compatibility between versions.",
        "severity": Severity.INFO,
    },
    {
        "id": "feature_flag2_permanent_flag",
        "pattern": r"(?i)(?:permanent|forever|never_remove)\s*[:=]\s*true.*(?:flag|toggle|feature)",
        "message": "Feature flag marked permanent. Evaluate if configuration is more appropriate.",
        "severity": Severity.INFO,
    },
    {
        "id": "canary_no_baseline",
        "pattern": r"(?i)(?:canary|canary_analysis)(?!.*(?:baseline|control|compare|threshold))",
        "message": "Canary without baseline comparison. Compare canary metrics against stable baseline.",
        "severity": Severity.INFO,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CHAOS ENGINEERING / SRE (rules 1553-1567)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "chaos_no_blast_radius",
        "pattern": r"(?i)(?:chaos|experiment|fault_injection)(?!.*(?:blast_radius|scope|target|limit))",
        "message": "Chaos experiment without blast radius definition. Limit scope of failure injection.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml", ".tf", ".hcl", ".json"],
    },
    {
        "id": "chaos_production_no_approval",
        "pattern": r"(?i)(?:chaos|litmus|gremlin).*(?:prod|production)(?!.*(?:approv|review|confirm))",
        "message": "Chaos experiment in production without approval. Require explicit approval workflow.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "chaos_no_abort_condition",
        "pattern": r"(?i)(?:chaos[-_]?(?:monkey|mesh|experiment|test)|litmus[-_]?chaos|fault[-_]?injection)(?!.*(?:abort|stop|emergency|rollback|circuit_breaker))",
        "message": "Chaos experiment without abort conditions. Define emergency stop criteria.",
        "severity": Severity.WARN,
        "file_types": [".py", ".yaml", ".yml", ".go", ".java"],
    },
    {
        "id": "sre_no_error_budget",
        "pattern": r"(?i)(?:slo|service_level)\s*[:=](?!.*(?:error_budget|budget|remaining|burn))",
        "message": "SLO defined without error budget tracking. Implement error budget monitoring.",
        "severity": Severity.INFO,
    },
    {
        "id": "sre_slo_no_consequence",
        "pattern": r"(?i)(?:slo|service_level).*(?:target|objective)(?!.*(?:alert|action|freeze|policy))",
        "message": "SLO without consequence policy. Define actions when error budget is exhausted.",
        "severity": Severity.INFO,
    },
    {
        "id": "incident_no_severity",
        "pattern": r"(?i)(?:incident|create_incident|open_incident)(?!.*(?:severity|priority|sev[0-5]|p[0-5]))",
        "message": "Incident created without severity level. Assign severity for proper routing.",
        "severity": Severity.WARN,
    },
    {
        "id": "incident_no_owner",
        "pattern": r"(?i)(?:incident|create_incident)(?!.*(?:owner|assignee|oncall|responder))",
        "message": "Incident without owner. Assign incident commander for coordination.",
        "severity": Severity.WARN,
    },
    {
        "id": "postmortem_no_action_items",
        "pattern": r"(?i)(?:postmortem|post_mortem|retrospective)(?!.*(?:action_item|follow_up|remediation|task))",
        "message": "Postmortem without action items. Document concrete remediation steps.",
        "severity": Severity.WARN,
    },
    {
        "id": "postmortem_blame",
        "pattern": r"(?i)(?:postmortem|post_mortem).*(?:fault|blame|responsible|mistake|who)",
        "message": "Postmortem with blame language. Use blameless postmortem format.",
        "severity": Severity.INFO,
    },
    {
        "id": "runbook_no_steps",
        "pattern": r"(?i)(?:runbook|playbook)(?!.*(?:step|procedure|instruction|action))",
        "message": "Runbook without procedural steps. Add step-by-step instructions.",
        "severity": Severity.WARN,
        "file_types": [".md", ".yml", ".yaml", ".txt"],
    },
    {
        "id": "runbook_no_escalation",
        "pattern": r"(?i)(?:runbook|playbook)(?!.*(?:escalat|contact|oncall|page|notify))",
        "message": "Runbook without escalation path. Define when and who to escalate to.",
        "severity": Severity.WARN,
        "file_types": [".md", ".yml", ".yaml", ".txt"],
    },
    {
        "id": "sre_toil_no_tracking",
        "pattern": r"(?i)(?:manual|toil|repetitive).*(?:task|work|process)(?!.*(?:automat|ticket|track|measure))",
        "message": "Manual toil without tracking. Track toil to prioritize automation.",
        "severity": Severity.INFO,
    },
    {
        "id": "chaos_no_monitoring",
        "pattern": r"(?i)(?:chaos|fault_injection)(?!.*(?:monitor|observe|dashboard|alert|metric))",
        "message": "Chaos experiment without monitoring. Observe system behavior during experiments.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml", ".tf", ".hcl", ".json"],
    },
    {
        "id": "incident_no_timeline",
        "pattern": r"(?i)(?:incident|postmortem)(?!.*(?:timeline|chronolog|sequence|timestamp))",
        "message": "Incident report without timeline. Document chronological event sequence.",
        "severity": Severity.INFO,
    },
    {
        "id": "runbook_hardcoded_credentials",
        "pattern": r"(?i)(?:runbook|playbook).*(?:password|credential|secret|token)\s*[:=]\s*[\"'][^\"']+[\"']",
        "message": "Runbook with hardcoded credentials. Reference secrets manager entries.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  CONTAINER ORCHESTRATION (rules 1568-1587)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "docker3_init_container_privileged",
        "pattern": r"(?i)(?:initContainer|init_container).*(?:privileged|securityContext.*privileged)\s*[:=]\s*true",
        "message": "Init container running privileged. Use minimal privileges for init containers.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker3_no_healthcheck",
        "pattern": r"(?i)(?:HEALTHCHECK\s+|healthcheck:|livenessProbe:|readinessProbe:)",
        "message": "Container without health check. Add HEALTHCHECK or probe configuration.",
        "severity": Severity.INFO,
        "negate": True,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker3_latest_tag",
        "pattern": r"(?i)(?:FROM|image:)\s*[a-z0-9._/-]+:latest(?:\s|$)",
        "message": "Container using :latest tag. Pin to specific version for reproducibility.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker3_add_instead_of_copy",
        "pattern": r"(?i)^ADD\s+(?!https?://)\S+\s+\S+",
        "message": "Using ADD instead of COPY. Use COPY unless extracting archives or fetching URLs.",
        "severity": Severity.INFO,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker3_run_as_root",
        "pattern": r"(?i)(?:USER\s+root|user:\s*[\"']?(?:0|root)[\"']?)",
        "message": "Container running as root. Use non-root user for security.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "k8s2_pod_no_disruption_budget",
        "pattern": r"(?i)kind:\s*Deployment(?!.*PodDisruptionBudget)",
        "message": "Deployment without PodDisruptionBudget. Add PDB for availability during updates.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_sidecar_no_resource_limit",
        "pattern": r"(?i)(?:sidecar|istio-proxy|envoy)(?!.*(?:resources|limits|requests))",
        "message": "Sidecar container without resource limits. Set CPU and memory limits.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_init_no_timeout",
        "pattern": r"(?i)initContainers:(?!.*(?:timeout|activeDeadlineSeconds|terminationGracePeriod))",
        "message": "Init container without timeout. Set deadline to prevent indefinite blocking.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_emptydir_no_sizelimit",
        "pattern": r"(?i)emptyDir:\s*\{\s*\}|emptyDir:(?!.*sizeLimit)",
        "message": "emptyDir volume without size limit. Set sizeLimit to prevent node disk exhaustion.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_hostpath_volume",
        "pattern": r"(?i)hostPath:\s*\n\s*path:",
        "message": "Using hostPath volume. Avoid hostPath - use PersistentVolume or emptyDir.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "docker3_expose_all_ports",
        "pattern": r"(?i)(?:EXPOSE|ports:).*(?:0\.0\.0\.0|hostPort)",
        "message": "Exposing container ports on all interfaces. Bind to specific interfaces.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker3_env_secrets",
        "pattern": r"(?i)ENV\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=",
        "message": "Secrets in Dockerfile ENV. Use runtime secrets or build args with --secret.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
    },
    {
        "id": "k8s2_default_service_account",
        "pattern": r"(?i)serviceAccountName:\s*[\"']?default[\"']?",
        "message": "Using default service account. Create dedicated service account with RBAC.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_no_liveness_probe",
        "pattern": r"(?i)containers:(?!.*livenessProbe)",
        "message": "Container without liveness probe. Add livenessProbe for restart on failure.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_no_readiness_probe",
        "pattern": r"(?i)containers:(?!.*readinessProbe)",
        "message": "Container without readiness probe. Add readinessProbe for traffic routing.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "docker3_shell_form_cmd",
        "pattern": r"(?i)^CMD\s+(?!\[)[\"']?\w+",
        "message": "Dockerfile CMD in shell form. Use exec form CMD [\"executable\", \"arg\"] instead.",
        "severity": Severity.INFO,
        "file_types": [".dockerfile"],
    },
    {
        "id": "docker3_no_user_directive",
        "pattern": r"(?i)^USER\s+\w",
        "message": "Dockerfile without USER directive. Add USER to run as non-root.",
        "severity": Severity.INFO,
        "negate": True,
        "file_types": [".dockerfile"],
    },
    {
        "id": "k8s2_privileged_escalation",
        "pattern": r"(?i)allowPrivilegeEscalation:\s*true",
        "message": "Privilege escalation allowed. Set allowPrivilegeEscalation to false.",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "docker3_tmp_world_writable",
        "pattern": r"(?i)chmod\s+(?:777|o\+w)\s+/tmp",
        "message": "Making /tmp world-writable in container. Use proper volume mounts.",
        "severity": Severity.WARN,
        "file_types": [".dockerfile"],
    },
    # ═══════════════════════════════════════════════════════════════
    #  ADVANCED KUBERNETES (rules 1588-1602)
    # ═══════════════════════════════════════════════════════════════
    {
        "id": "k8s2_no_network_policy",
        "pattern": r"(?i)kind:\s*(?:Deployment|StatefulSet|DaemonSet)(?!.*NetworkPolicy)",
        "message": "Workload without NetworkPolicy. Define ingress and egress network policies.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_rbac_cluster_admin",
        "pattern": r"(?i)ClusterRoleBinding.*roleRef.*cluster-admin",
        "message": "Binding to cluster-admin ClusterRole. Use least-privilege custom role.",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_rbac_wildcard_resource",
        "pattern": r"(?i)(?:ClusterRole|Role).*resources:\s*\[\s*[\"']\*[\"']\s*\]",
        "message": "RBAC role with wildcard resources. Specify exact resources needed.",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_rbac_wildcard_verb",
        "pattern": r"(?i)(?:ClusterRole|Role).*verbs:\s*\[\s*[\"']\*[\"']\s*\]",
        "message": "RBAC role with wildcard verbs. Specify exact verbs (get, list, watch).",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_secret_in_env",
        "pattern": r"(?i)env:.*(?:valueFrom|value).*(?:secretKeyRef|SECRET)(?!.*(?:volume|mount|projected))",
        "message": "Secret exposed as env variable. Use volume mount for secrets instead.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_no_resource_quota",
        "pattern": r"(?i)kind:\s*Namespace(?!.*ResourceQuota)",
        "message": "Namespace without ResourceQuota. Set quotas to prevent resource exhaustion.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_no_limit_range",
        "pattern": r"(?i)kind:\s*Namespace(?!.*LimitRange)",
        "message": "Namespace without LimitRange. Set default limits for containers.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_automount_token",
        "pattern": r"(?i)automountServiceAccountToken:\s*true",
        "message": "Service account token auto-mounted. Disable unless pod needs API access.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_host_pid",
        "pattern": r"(?i)hostPID:\s*true",
        "message": "Pod using host PID namespace. Avoid host PID for process isolation.",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_host_ipc",
        "pattern": r"(?i)hostIPC:\s*true",
        "message": "Pod using host IPC namespace. Avoid host IPC for isolation.",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_no_security_context",
        "pattern": r"(?i)containers:(?!.*securityContext)",
        "message": "Container without securityContext. Define security context for hardening.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_writable_root_filesystem",
        "pattern": r"(?i)readOnlyRootFilesystem:\s*false",
        "message": "Writable root filesystem. Set readOnlyRootFilesystem to true.",
        "severity": Severity.WARN,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_capabilities_all",
        "pattern": r"(?i)capabilities:.*add:.*(?:ALL|SYS_ADMIN|NET_ADMIN)",
        "message": "Adding dangerous Linux capabilities. Drop all and add only required caps.",
        "severity": Severity.BLOCK,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_no_pod_anti_affinity",
        "pattern": r"(?i)replicas:\s*[2-9]\d*(?!.*podAntiAffinity)",
        "message": "Multiple replicas without pod anti-affinity. Spread across nodes for HA.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "k8s2_latest_image_policy",
        "pattern": r"(?i)imagePullPolicy:\s*(?:Always|Never)(?!.*(?:sha256|@))",
        "message": "Image pull policy without digest pinning. Use digest-pinned images.",
        "severity": Severity.INFO,
        "file_types": [".yaml", ".yml"],
    },
    {
        "id": "r1a_001",
        "pattern": r'''\.execute\s*\(\s*f[\"']''',
        "message": "SQL query built with f-string in execute() call - use parameterized queries instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_002",
        "pattern": r'''\.execute\s*\(\s*[\"'].*%s.*[\"']\s*%\s*''',
        "message": "SQL query using percent formatting in execute() - use parameterized queries instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_003",
        "pattern": r'''\.raw\s*\(\s*f[\"']''',
        "message": "ORM raw() query built with f-string - use parameterized raw queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_004",
        "pattern": r"\.extra\s*\(\s*where\s*=\s*\[.*\+",
        "message": "Django extra() with string concatenation in WHERE clause - use parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_005",
        "pattern": r'''\.RawSQL\s*\(\s*f[\"']''',
        "message": "Django RawSQL with f-string interpolation enables SQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_006",
        "pattern": r'''cursor\.execute\s*\(\s*[\"'].*\+\s*''',
        "message": "SQL cursor.execute() with string concatenation - use parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_007",
        "pattern": r"\.query\s*\(\s*`[^`]*\$\{",
        "message": "SQL query with template literal interpolation - use parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_008",
        "pattern": r"db\.exec(?:ute)?\s*\(\s*`[^`]*\$\{",
        "message": "Database exec/execute with template literal interpolation - use parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_009",
        "pattern": r"\.whereRaw\s*\(\s*`[^`]*\$\{",
        "message": "Knex whereRaw with template literal interpolation - use parameter binding",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_010",
        "pattern": r'Sprintf\s*\(\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)',
        "message": "Go SQL query built with Sprintf - use parameterized queries with $1 or ? placeholders",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_011",
        "pattern": r'fmt\.Sprintf\s*\(\s*\"[^\"]*(?:WHERE|SET|VALUES)\s+[^\"]*%',
        "message": "Go SQL clause built with fmt.Sprintf - use db.Query with args",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_012",
        "pattern": r"\.createQueryBuilder\s*\(.*\.where\s*\(\s*`[^`]*\$\{",
        "message": "TypeORM QueryBuilder with template literal in where() - use parameter binding",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_013",
        "pattern": r"sequelize\.query\s*\(\s*`[^`]*\$\{",
        "message": "Sequelize raw query with template literal interpolation - use replacements or bind parameters",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_014",
        "pattern": r'\.FromSqlRaw\s*\(\s*\$\"',
        "message": "EF Core FromSqlRaw with string interpolation - use FromSqlInterpolated instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_015",
        "pattern": r'Statement\.execute\s*\(\s*\"[^\"]*\"\s*\+',
        "message": "Java Statement.execute with string concatenation - use PreparedStatement",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_016",
        "pattern": r'createStatement\s*\(\s*\).*\.execute(?:Query|Update)\s*\(\s*\"[^\"]*\"\s*\+',
        "message": "Java createStatement with string concatenation - use prepareStatement with parameter binding",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_017",
        "pattern": r"\.orderByRaw\s*\(\s*`[^`]*\$\{",
        "message": "Knex orderByRaw with template literal interpolation enables SQL injection via ORDER BY",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_018",
        "pattern": r"\.havingRaw\s*\(\s*`[^`]*\$\{",
        "message": "Knex havingRaw with template literal interpolation enables SQL injection via HAVING",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_019",
        "pattern": r"\.joinRaw\s*\(\s*`[^`]*\$\{",
        "message": "Knex joinRaw with template literal interpolation enables SQL injection via JOIN",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_020",
        "pattern": r'''TABLE\s+[\"']?\s*\+\s*\w+|INTO\s+[\"']?\s*\+\s*\w+''',
        "message": "Dynamic table name via string concatenation - validate against allowlist of table names",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_021",
        "pattern": r'''\.text_type\s*\(\s*f[\"']|\.column\s*\(\s*f[\"']''',
        "message": "Dynamic column or type name with f-string in ORM schema definition",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_022",
        "pattern": r'ActiveRecord::Base\.connection\.execute\s*\(\s*\"[^\"]*#\{',
        "message": "Rails ActiveRecord raw execute with string interpolation - use sanitize_sql or parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_023",
        "pattern": r'\$\w+->query\s*\(\s*\"[^\"]*\\\$',
        "message": "PHP direct query with variable interpolation - use prepared statements with PDO",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_024",
        "pattern": r"mysql_query\s*\(",
        "message": "Using deprecated mysql_query function - use PDO or mysqli with prepared statements",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_025",
        "pattern": r"\.selectRaw\s*\(\s*`[^`]*\$\{",
        "message": "Knex/Laravel selectRaw with template literal interpolation - use parameter binding",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_026",
        "pattern": r'DB::select\s*\(\s*\"[^\"]*\\\$|DB::statement\s*\(\s*\"[^\"]*\\\$',
        "message": "Laravel DB::select/statement with variable interpolation - use parameter binding",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_027",
        "pattern": r"\.Exec\s*\(\s*fmt\.Sprintf\s*\(",
        "message": "Go database Exec with fmt.Sprintf - use Exec with parameter placeholders",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_028",
        "pattern": r'''LIKE\s+['\"]%?\s*\+\s*\w+|LIKE\s+['\"]%?\s*\.\s*\+''',
        "message": "LIKE clause with string concatenation - vulnerable to SQL injection and wildcard injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_029",
        "pattern": r"\.Unsafe\s*\(\s*\)\.(?:Select|Where|Order)",
        "message": "Using Unsafe() to bypass SQL builder protections - review for injection risk",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_030",
        "pattern": r'@Query\s*\(\s*value\s*=\s*\"[^\"]*\"\s*\+|nativeQuery\s*=\s*true.*\+',
        "message": "Spring Data @Query with string concatenation - use named parameters with :param syntax",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_031",
        "pattern": r'''algorithms?\s*[=:]\s*\[?\s*[\"']none[\"']''',
        "message": "JWT algorithm set to 'none' - this disables signature verification entirely",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_032",
        "pattern": r"verify\s*[=:]\s*(?:False|false)\s*[,\)]",
        "message": "JWT verification disabled - tokens will be accepted without signature validation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_033",
        "pattern": r"jwt\.decode\s*\([^)]*algorithms\s*=\s*\[.*HS256.*RS256|algorithms\s*=\s*\[.*RS256.*HS256",
        "message": "JWT accepts both symmetric and asymmetric algorithms - vulnerable to algorithm confusion attack",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_034",
        "pattern": r'''jwt\.sign\s*\([^)]*expiresIn\s*:\s*[\"'](\d{3,}d|[5-9]\d{2,}h)''',
        "message": "JWT expiration set too long - tokens should expire in hours, not hundreds of days",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_035",
        "pattern": r"session\.cookie_secure\s*=\s*(?:False|false|0)",
        "message": "Session cookie secure flag disabled - cookies will be sent over unencrypted HTTP",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_036",
        "pattern": r"httpOnly\s*:\s*false|httponly\s*=\s*False",
        "message": "Cookie httpOnly flag disabled - cookie accessible to JavaScript, enabling XSS theft",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_037",
        "pattern": r'''sameSite\s*:\s*[\"'](?:none|None)[\"'](?!.*[Ss]ecure\s*:\s*true)''',
        "message": "SameSite=None without Secure flag - cookie will be rejected by modern browsers",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_038",
        "pattern": r"req\.session\.id\s*=\s*req\.(query|params|body)\.",
        "message": "Session ID set from user input - vulnerable to session fixation attack",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_039",
        "pattern": r"session_id\s*=\s*request\.(GET|POST|args|form)\.",
        "message": "Session ID set from user input - vulnerable to session fixation attack",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_040",
        "pattern": r'''\.role\s*[=:]\s*req\.(body|query|params)\.role|role\s*=\s*request\.(json|form|args)\[?[\"']role''',
        "message": "User role assigned from request input - privilege escalation vulnerability",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_041",
        "pattern": r"isAdmin\s*[=:]\s*(?:req\.|request\.)",
        "message": "Admin flag set from user-controlled input - must be derived from server-side authorization",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_042",
        "pattern": r'''password\s*===?\s*[\"'][^\"']{1,30}[\"']|password\s*==\s*[\"'][^\"']{1,30}[\"']''',
        "message": "Hardcoded password comparison - use proper password hashing with bcrypt/argon2",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_043",
        "pattern": r"\.compare\s*\(\s*password\s*,\s*password\s*\)|password\s*===?\s*(?:stored|db|user)Password",
        "message": "Plain text password comparison - use bcrypt.compare or equivalent constant-time comparison",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_044",
        "pattern": r"(?:api[_-]?key|token|secret)\s*===?\s*req\.(query|params)\.",
        "message": "API key or token compared from query parameter - use headers and constant-time comparison",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_045",
        "pattern": r"md5\s*\(\s*(?:password|passwd|pwd)",
        "message": "MD5 used for password hashing - MD5 is cryptographically broken, use bcrypt or argon2",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_046",
        "pattern": r"sha1\s*\(\s*(?:password|passwd|pwd)|SHA1\.(?:hexdigest|digest|hash)\s*\(\s*(?:password|passwd|pwd)",
        "message": "SHA1 used for password hashing - SHA1 is deprecated, use bcrypt or argon2",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_047",
        "pattern": r"@(?:Public|AllowAnonymous|PermitAll)\s*\n.*(?:delete|remove|destroy|drop|admin|config)",
        "message": "Destructive or admin endpoint marked as public/anonymous - requires authentication",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_048",
        "pattern": r'''CORS.*(?:origin|Origin)\s*[=:]\s*[\"']\*[\"']''',
        "message": "CORS allows all origins with wildcard - restrict to specific trusted domains",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_049",
        "pattern": r"Access-Control-Allow-Credentials.*true.*origin.*\*|origin.*\*.*Access-Control-Allow-Credentials.*true",
        "message": "CORS allows credentials with wildcard origin - browsers will reject this, but it signals misconfiguration",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_050",
        "pattern": r"(?:token|jwt|session).*(?:localStorage|sessionStorage)\.setItem",
        "message": "Storing authentication token in browser storage - vulnerable to XSS theft, use httpOnly cookies",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_051",
        "pattern": r'''\.generateKeyPairSync\s*\(\s*[\"']rsa[\"']\s*,\s*\{\s*modulusLength\s*:\s*(?:512|768|1024)\b''',
        "message": "RSA key length under 2048 bits - insufficient for security, use at least 2048",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_052",
        "pattern": r"csrf.*(?:disable|disabled|false|off)|disable.*csrf|@csrf_exempt",
        "message": "CSRF protection disabled - forms and state-changing endpoints are vulnerable to cross-site request forgery",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_053",
        "pattern": r'''(?:OAuth|oauth).*state\s*[=:]\s*(?:null|undefined|None|\"\"|\'\')|\bstate\b\s*[=:]\s*(?:null|undefined).*(?:OAuth|oauth|authorize)''',
        "message": "OAuth state parameter is null or empty - vulnerable to CSRF in OAuth flow",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_054",
        "pattern": r"bcrypt\.(?:hash|hashSync)\s*\([^)]*(?:rounds?\s*[=:]\s*[1-5]\b|saltRounds?\s*[=:]\s*[1-5]\b)",
        "message": "Bcrypt cost factor too low (under 10) - brute force is feasible, use at least 10 rounds",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_055",
        "pattern": r'''passport\.authenticate\s*\(\s*[\"']local[\"']\s*,\s*\{[^}]*session\s*:\s*false''',
        "message": "Passport local strategy with sessions disabled - ensure token-based auth is properly implemented",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_056",
        "pattern": r"window\.location\.(href|assign|replace)\s*=\s*(?:req\.|request\.|params\.|query\.|\$_GET|\$_POST|document\.)",
        "message": "Open redirect from user-controlled input - validate redirect URLs against allowlist",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_057",
        "pattern": r"(?:res|response)\.redirect\s*\(\s*(?:req\.|request\.)(?:query|params|body)\.",
        "message": "Server-side redirect using user-controlled input - validate against allowlist of permitted URLs",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_058",
        "pattern": r"@login_required\s*\n\s*@(?:app|router)\.route\s*\(\s*[^)]*methods\s*=.*(?:GET|POST)",
        "message": "Decorator order issue - @login_required should be after @route (innermost decorator runs first)",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_059",
        "pattern": r"(?:MAX_LOGIN_ATTEMPTS|max_attempts|maxAttempts)\s*[=:]\s*(?:[5-9]\d{2,}|\d{4,})",
        "message": "Login attempt limit set too high (500+) - effectively disables brute force protection",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_060",
        "pattern": r"\.verify\s*\(\s*token\s*,\s*(?:req\.|request\.)(?:body|query|params)\.",
        "message": "JWT secret/key derived from user input - secret must be server-side only",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_061",
        "pattern": r'''(?:ACL|acl)\s*[=:]\s*[\"']public-read-write[\"']''',
        "message": "S3 bucket or object ACL set to public-read-write - allows anyone to read and modify data",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_062",
        "pattern": r'''(?:ACL|acl)\s*[=:]\s*[\"']public-read[\"']''',
        "message": "S3 bucket or object ACL set to public-read - verify this is intentional, most buckets should be private",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_063",
        "pattern": r"block_public_acls\s*=\s*false|BlockPublicAcls\s*:\s*false",
        "message": "S3 public access block disabled - enable all four public access block settings",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_064",
        "pattern": r"block_public_policy\s*=\s*false|BlockPublicPolicy\s*:\s*false",
        "message": "S3 block public policy disabled - bucket policies can make data public",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_065",
        "pattern": r'\"Effect\"\s*:\s*\"Allow\".*\"Action\"\s*:\s*\"\*\".*\"Resource\"\s*:\s*\"\*\"',
        "message": "IAM policy grants full access to all resources - apply least-privilege principle",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_066",
        "pattern": r'\"Effect\"\s*:\s*\"Allow\".*\"Action\"\s*:\s*\"iam:\*\"',
        "message": "IAM policy grants full IAM access - enables privilege escalation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_067",
        "pattern": r'\"Principal\"\s*:\s*(?:\"\*\"|\{[^}]*\"AWS\"\s*:\s*\"\*\")',
        "message": "Resource policy grants access to all AWS principals - restrict to specific accounts or roles",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_068",
        "pattern": r"(?:ingress|SecurityGroupIngress).*(?:0\.0\.0\.0/0|::/0).*(?:from_port|FromPort)\s*[=:]\s*0.*(?:to_port|ToPort)\s*[=:]\s*65535",
        "message": "Security group allows all traffic from all IPs - restrict to specific ports and CIDR ranges",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_069",
        "pattern": r'''(?:from_port|FromPort)\s*[=:]\s*22.*(?:cidr|CidrIp)\s*[=:]\s*[\"']0\.0\.0\.0/0[\"']''',
        "message": "SSH port 22 open to all IPs - restrict to specific CIDR ranges or use SSM/bastion",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_070",
        "pattern": r'''(?:from_port|FromPort)\s*[=:]\s*3389.*(?:cidr|CidrIp)\s*[=:]\s*[\"']0\.0\.0\.0/0[\"']''',
        "message": "RDP port 3389 open to all IPs - restrict to specific CIDR ranges or use bastion host",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_071",
        "pattern": r"encrypted\s*=\s*false|Encrypted\s*:\s*false|storage_encrypted\s*=\s*false",
        "message": "Storage encryption disabled - enable encryption at rest for EBS volumes, RDS, and S3",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_072",
        "pattern": r"logging\s*\{[^}]*enabled\s*=\s*false|LoggingConfiguration\s*:\s*\{\}",
        "message": "Access logging disabled - enable logging for audit trail and security monitoring",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_073",
        "pattern": r'(?:versioning|Versioning)\s*\{[^}]*(?:enabled|Status)\s*[=:]\s*(?:false|\"Suspended\")',
        "message": "S3 bucket versioning disabled - enable for data protection and recovery",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_074",
        "pattern": r"multi_az\s*=\s*false|MultiAZ\s*:\s*false",
        "message": "Multi-AZ deployment disabled for database - single AZ creates availability risk",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_075",
        "pattern": r"deletion_protection\s*=\s*false|DeletionProtection\s*:\s*false",
        "message": "Deletion protection disabled on database or load balancer - enable to prevent accidental deletion",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_076",
        "pattern": r"backup_retention_period\s*=\s*0|BackupRetentionPeriod\s*:\s*0",
        "message": "Database backup retention period set to 0 - no automated backups will be created",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_077",
        "pattern": r"publicly_accessible\s*=\s*true|PubliclyAccessible\s*:\s*true",
        "message": "Database instance set to publicly accessible - place in private subnet behind VPN or bastion",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_078",
        "pattern": r'''(?:kms_key_id|KmsKeyId)\s*[=:]\s*(?:\"\"|'')''',
        "message": "KMS key ID is empty - using default AWS-managed keys reduces control over encryption",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_079",
        "pattern": r"enable_key_rotation\s*=\s*false|EnableKeyRotation\s*:\s*false",
        "message": "KMS key rotation disabled - enable automatic annual key rotation",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_080",
        "pattern": r'''(?:min_tls_version|MinimumTlsVersion|tls_version)\s*[=:]\s*[\"'](?:TLS1_0|TLSv1|1\.0|TLS_1_0)[\"']''',
        "message": "Minimum TLS version set to 1.0 - use TLS 1.2 or higher",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_081",
        "pattern": r"(?:force_ssl|require_ssl|ssl_enforcement)\s*[=:]\s*(?:false|disabled)",
        "message": "SSL/TLS enforcement disabled - database connections should require encryption in transit",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_082",
        "pattern": r"uniform_bucket_level_access\s*=\s*false",
        "message": "GCP uniform bucket-level access disabled - ACLs create complex permission management",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_083",
        "pattern": r"allUsers|allAuthenticatedUsers",
        "message": "GCP IAM binding grants access to all users or all authenticated users - restrict to specific principals",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_084",
        "pattern": r"network_policy\s*\{[^}]*enabled\s*=\s*false",
        "message": "GKE network policy enforcement disabled - pods can communicate without restriction",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_085",
        "pattern": r"enable_legacy_abac\s*=\s*true",
        "message": "GKE legacy ABAC enabled - use RBAC instead for fine-grained access control",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_086",
        "pattern": r"auto_repair\s*=\s*false|auto_upgrade\s*=\s*false",
        "message": "GKE node auto-repair or auto-upgrade disabled - increases maintenance burden and security risk",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_087",
        "pattern": r"(?:ip_configuration|ipConfiguration).*(?:authorized_networks|authorizedNetworks).*0\.0\.0\.0/0",
        "message": "Cloud SQL authorized networks includes 0.0.0.0/0 - database accessible from any IP",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_088",
        "pattern": r"(?:enable_flow_logs|enableFlowLogs|flow_logs)\s*[=:]\s*false",
        "message": "VPC flow logs disabled - enable for network traffic monitoring and security analysis",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_089",
        "pattern": r"point_in_time_recovery\s*\{[^}]*enabled\s*=\s*false",
        "message": "Point-in-time recovery disabled on database - limits recovery options in case of data loss",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_090",
        "pattern": r'''AZURE_STORAGE_CONNECTION_STRING\s*=\s*[\"'][^\"']+AccountKey=[^\"']+''',
        "message": "Azure storage connection string with account key hardcoded - use managed identity or Key Vault",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_091",
        "pattern": r"DES\s*\.\s*new|DESede|TripleDES|Blowfish\s*\.\s*new",
        "message": "Using obsolete cipher (DES/3DES/Blowfish) - use AES-256-GCM or ChaCha20-Poly1305",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_092",
        "pattern": r'(?:AES|Cipher).*(?:MODE_ECB|ECB|\"ECB\"|/ECB/)',
        "message": "AES in ECB mode does not provide semantic security - identical plaintext blocks produce identical ciphertext",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_093",
        "pattern": r"(?:AES|Cipher).*(?:MODE_CBC|CBC)(?!.*HMAC|.*Mac|.*tag|.*authenticate)",
        "message": "AES-CBC without authentication (MAC) - vulnerable to padding oracle attacks, use AES-GCM instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_094",
        "pattern": r'''(?:iv|IV|nonce)\s*[=:]\s*(?:b[\"']\\x00|(?:new\s+)?byte\s*\[\s*\d+\s*\]|(?:0x)?00{8,}|[\"']0{16,}[\"'])''',
        "message": "Initialization vector (IV) set to all zeros - IV must be random and unique per encryption",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_095",
        "pattern": r'''(?:iv|IV|nonce)\s*[=:]\s*[\"'][a-zA-Z0-9+/=]{8,}[\"']''',
        "message": "Hardcoded initialization vector - IV must be randomly generated for each encryption operation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_096",
        "pattern": r'''(?:key|KEY|secret_key|encryption_key)\s*[=:]\s*[\"'][A-Za-z0-9+/=]{16,64}[\"']''',
        "message": "Hardcoded encryption key - keys must be generated securely and stored in a key management system",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_097",
        "pattern": r"(?:PBKDF2|pbkdf2).*(?:iterations?|rounds?)\s*[=:]\s*(?:[1-9]\d{0,3}|[1-5]\d{4})\b",
        "message": "PBKDF2 iteration count too low (under 60000) - OWASP recommends at least 600000 for SHA-256",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_098",
        "pattern": r"(?:hashlib\.)?(?:md5|MD5)\s*\(",
        "message": "MD5 hash function used - MD5 is cryptographically broken, use SHA-256 or SHA-3",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_099",
        "pattern": r"(?:hashlib\.)?(?:sha1|SHA1|SHA-1)\s*\(",
        "message": "SHA-1 hash function used - SHA-1 has known collision attacks, use SHA-256 or SHA-3",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_100",
        "pattern": r"random\.\w+\s*\(|Math\.random\s*\(|rand\s*\(\s*\)",
        "message": "Non-cryptographic random number generator used - use secrets/crypto.randomBytes for security-sensitive values",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_101",
        "pattern": r"RC4|ARC4|ARCFOUR|rc4",
        "message": "RC4 stream cipher is cryptographically broken - use AES-GCM or ChaCha20-Poly1305",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_102",
        "pattern": r"RSA.*(?:key_size|keysize|modulus_length)\s*[=:]\s*(?:512|768|1024)\b",
        "message": "RSA key size under 2048 bits - use at least 2048 bits, prefer 4096 for long-term security",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_103",
        "pattern": r"(?:PKCS1v15|PKCS1_v1_5).*(?:sign|encrypt)",
        "message": "Using PKCS#1 v1.5 padding - use OAEP for encryption and PSS for signatures",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_104",
        "pattern": r'''(?:openssl_seal|openssl_encrypt)\s*\([^)]*[\"'](?:des-|rc4|bf-|cast5)''',
        "message": "OpenSSL using weak cipher algorithm - use aes-256-gcm or chacha20-poly1305",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_105",
        "pattern": r"(?:scrypt|Scrypt).*(?:N|cost)\s*[=:]\s*(?:1024|2048|4096)\b",
        "message": "Scrypt cost parameter too low - use N=32768 or higher for password hashing",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_106",
        "pattern": r"\.(?:update|write)\s*\(\s*(?:key|secret|password)",
        "message": "Sensitive data written to hash without using HMAC - use HMAC for keyed hashing to prevent length extension attacks",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_107",
        "pattern": r"==\s*.*\.digest\(\)|\.digest\(\)\s*==|\.hexdigest\(\)\s*==",
        "message": "Hash comparison using == operator - use hmac.compare_digest or constant-time comparison to prevent timing attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_108",
        "pattern": r"(?:tls|TLS|ssl|SSL)\.(?:Config|Context|create_default_context).*(?:InsecureSkipVerify|check_hostname\s*=\s*False|verify_mode\s*=\s*ssl\.CERT_NONE)\s*[=:]\s*(?:true|True)",
        "message": "TLS certificate verification disabled - enables man-in-the-middle attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_109",
        "pattern": r'''\.set_ciphers\s*\(\s*[\"'](?:ALL|eNULL|aNULL|LOW|EXP|DES|RC4)''',
        "message": "Weak TLS cipher suites enabled - use only strong ciphers like AES-GCM and ChaCha20",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_110",
        "pattern": r"(?:MinVersion|min_version|minimum_version)\s*[=:]\s*(?:tls\.VersionTLS10|tls\.VersionSSL30|ssl\.PROTOCOL_TLSv1\b)",
        "message": "Minimum TLS version set to 1.0 or SSL 3.0 - use TLS 1.2 as minimum",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_111",
        "pattern": r'''\.(?:createCipheriv|createDecipheriv)\s*\(\s*[\"'](?:aes-128-ecb|des|rc4|bf)''',
        "message": "Node.js crypto using weak cipher - use aes-256-gcm or chacha20-poly1305",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_112",
        "pattern": r'''(?:KeyPairGenerator|KeyGenerator)\.getInstance\s*\(\s*[\"'](?:DES|DESede|Blowfish)[\"']''',
        "message": "Java key generator using obsolete algorithm - use AES with 256-bit keys",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_113",
        "pattern": r'''Cipher\.getInstance\s*\(\s*[\"']AES[\"']\s*\)''',
        "message": "Java Cipher.getInstance('AES') defaults to ECB mode - specify AES/GCM/NoPadding explicitly",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_114",
        "pattern": r"SecureRandom\s*\(\s*\).*setSeed\s*\(\s*\d+\s*\)",
        "message": "SecureRandom seeded with a fixed value - defeats the purpose of CSPRNG",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_115",
        "pattern": r'''\.deriveKey\s*\(\s*[\"']PBKDF2[\"']\s*,.*iterations\s*:\s*(?:[1-9]\d{0,3}|[1-4]\d{4})\b''',
        "message": "WebCrypto PBKDF2 with low iterations - use at least 600000 iterations",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_116",
        "pattern": r"(?:new\s+)?(?:X509TrustManager|TrustManager)\s*(?:\{|\().*(?:checkServerTrusted|checkClientTrusted).*(?:return|//\s*no)",
        "message": "Custom TrustManager that accepts all certificates - disables TLS verification",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_117",
        "pattern": r'''crypto\.createHash\s*\(\s*[\"'](?:md5|sha1)[\"']\s*\)''',
        "message": "Node.js using weak hash algorithm - use sha256 or sha512",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_118",
        "pattern": r'''\.export_key\s*\(\s*[\"']PEM[\"']\s*\).*\.write\(|\.private_bytes\(.*NoEncryption''',
        "message": "Private key exported without encryption - protect private keys with a passphrase",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_119",
        "pattern": r"(?:DSA|dsa).*(?:key_size|generate)\s*\(?\s*(?:1024|2048)\b",
        "message": "DSA key generation - DSA is deprecated in modern standards, use Ed25519 or ECDSA with P-256",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_120",
        "pattern": r'''\.(?:encrypt|sign)\s*\([^)]*\).*\.encode\s*\(\s*[\"']hex[\"']\s*\)''',
        "message": "Encoding ciphertext as hex doubles output size - use base64 for more efficient encoding",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_121",
        "pattern": r"FROM\s+\S+\s*\n(?!.*USER\s)(?:.*\n)*$",
        "message": "Dockerfile does not set a USER - container will run as root by default",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_122",
        "pattern": r"FROM\s+(?:ubuntu|debian|centos|alpine)\s*$|FROM\s+(?:ubuntu|debian|centos|alpine):latest",
        "message": "Dockerfile uses base image without pinned version - pin to specific version for reproducibility",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_123",
        "pattern": r"RUN\s+.*apt-get\s+install(?!.*--no-install-recommends)",
        "message": "apt-get install without --no-install-recommends installs unnecessary packages, increasing image size and attack surface",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_124",
        "pattern": r"RUN\s+.*curl\s+.*\|\s*(?:sh|bash)|RUN\s+.*wget\s+.*\|\s*(?:sh|bash)",
        "message": "Piping downloaded script to shell in Dockerfile - download, verify checksum, then execute",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_125",
        "pattern": r"COPY\s+\.\s+\.|ADD\s+\.\s+\.",
        "message": "Copying entire build context into container - use specific paths and .dockerignore",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_127",
        "pattern": r"ENV\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|PRIVATE_KEY)\s*=",
        "message": "Secret value set in Dockerfile ENV - secrets should be passed at runtime, not baked into images",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_128",
        "pattern": r"EXPOSE\s+22\b",
        "message": "Container exposes SSH port 22 - containers should be accessed via orchestration tools, not SSH",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_129",
        "pattern": r"privileged\s*:\s*true|--privileged",
        "message": "Container running in privileged mode - grants full host access, use specific capabilities instead",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml", ".toml", ".sh", ".bash"],
    },
    {
        "id": "r1a_130",
        "pattern": r"hostNetwork\s*:\s*true",
        "message": "Pod using host network namespace - bypasses network isolation and network policies",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_131",
        "pattern": r"hostPID\s*:\s*true|hostIPC\s*:\s*true",
        "message": "Pod sharing host PID or IPC namespace - breaks container isolation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_132",
        "pattern": r"runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false",
        "message": "Container configured to run as root user - use runAsNonRoot: true and a non-zero runAsUser",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_133",
        "pattern": r"readOnlyRootFilesystem\s*:\s*false",
        "message": "Container root filesystem is writable - use readOnlyRootFilesystem: true and mount specific writable volumes",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_134",
        "pattern": r"allowPrivilegeEscalation\s*:\s*true",
        "message": "Container allows privilege escalation via setuid/setgid - set allowPrivilegeEscalation: false",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_135",
        "pattern": r"capabilities\s*:\s*\n\s*add\s*:\s*\n\s*-\s*(?:ALL|SYS_ADMIN|NET_ADMIN)",
        "message": "Container granted dangerous Linux capabilities - follow least-privilege and add only needed caps",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_136",
        "pattern": r"(?:resources\s*:\s*\{\}|(?<!resources:)(?:containers:\s*\n\s*-\s*name:.*\n(?:\s+\w+:.*\n)*(?!\s+resources:)))",
        "message": "Container has no resource limits - set CPU and memory limits to prevent resource exhaustion",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_137",
        "pattern": r"automountServiceAccountToken\s*:\s*true",
        "message": "Service account token auto-mounted - set to false unless the pod needs Kubernetes API access",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_138",
        "pattern": r"kind\s*:\s*ClusterRoleBinding[\s\S]*?roleRef[\s\S]*?name\s*:\s*cluster-admin",
        "message": "ClusterRoleBinding to cluster-admin role - grants unrestricted cluster access",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_139",
        "pattern": r"kind\s*:\s*NetworkPolicy[\s\S]*?spec\s*:\s*\{\}",
        "message": "NetworkPolicy with empty spec - does not restrict any traffic, effectively a no-op",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_140",
        "pattern": r'''(?:image|Image)\s*:\s*[\"']?[a-z]+(?:/[a-z]+)*(?::[a-z]+)?[\"']?\s*$''',
        "message": "Container image without specific tag or digest - use pinned version tags or SHA256 digests",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_141",
        "pattern": r"imagePullPolicy\s*:\s*(?:Never|IfNotPresent)(?!.*sha256)",
        "message": "Image pull policy set to Never/IfNotPresent without digest pinning - may run outdated or different images",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_142",
        "pattern": r"HEALTHCHECK\s+NONE",
        "message": "Dockerfile disables health check - implement health checks for container orchestration",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_143",
        "pattern": r"RUN\s+.*chmod\s+777",
        "message": "Setting file permissions to 777 in container - use least-privilege permissions (644 for files, 755 for executables)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_144",
        "pattern": r"kind\s*:\s*Pod\b(?!.*kind\s*:\s*Deployment)",
        "message": "Bare Pod resource without Deployment/StatefulSet - use higher-level controllers for lifecycle management",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_145",
        "pattern": r"seccompProfile\s*:\s*\n\s*type\s*:\s*Unconfined",
        "message": "Seccomp profile set to Unconfined - use RuntimeDefault or a custom profile",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_146",
        "pattern": r"kind\s*:\s*Ingress[\s\S]*?(?:annotations[\s\S]*?)?(?!.*tls:)",
        "message": "Ingress resource without TLS configuration - configure TLS termination for encrypted traffic",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_147",
        "pattern": r"RUN\s+.*apk\s+add(?!.*--no-cache)",
        "message": "apk add without --no-cache leaves package index in image, increasing size",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_148",
        "pattern": r"(?:emptyDir\s*:\s*\{\}.*sizeLimit|emptyDir\s*:\s*\n\s*(?!sizeLimit))",
        "message": "emptyDir volume without sizeLimit - can consume all node disk space",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_149",
        "pattern": r"kind\s*:\s*Service[\s\S]*?type\s*:\s*NodePort",
        "message": "Service type NodePort exposes ports on all cluster nodes - use LoadBalancer or Ingress for production",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_150",
        "pattern": r'''kind\s*:\s*Role\b[\s\S]*?verbs\s*:\s*\n\s*-\s*[\"']?\*[\"']?''',
        "message": "Role grants wildcard verbs on resources - specify exact verbs needed (get, list, watch, etc.)",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_152",
        "pattern": r'v-html\s*=\s*\"',
        "message": "Vue v-html directive renders raw HTML - vulnerable to XSS, sanitize with DOMPurify first",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_153",
        "pattern": r'\[innerHTML\]\s*=\s*\"',
        "message": "Angular innerHTML binding renders raw HTML - use DomSanitizer.sanitize() or bypassSecurityTrust only with trusted content",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_154",
        "pattern": r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(",
        "message": "Angular DomSanitizer bypass used - verify the input is from a trusted source, not user-controlled",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_155",
        "pattern": r"eval\s*\(\s*(?:this\.)?\$?\w+(?:\.value|\.text|\.input)",
        "message": "eval() with user-controlled input - code injection vulnerability, use safe alternatives",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_156",
        "pattern": r"new\s+Function\s*\(\s*(?:this\.)?\$?\w+",
        "message": "new Function() with dynamic input - equivalent to eval(), enables code injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_158",
        "pattern": r'''\.outerHTML\s*=\s*|\.innerHTML\s*=\s*(?![\s]*[\"'](?:\s*[\"'])?)''',
        "message": "Direct innerHTML/outerHTML assignment with potentially unsanitized content - use textContent or sanitize first",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_159",
        "pattern": r'''href\s*=\s*\{?\s*[\"']?\s*javascript\s*:''',
        "message": "javascript: protocol in href attribute - XSS vector, use onClick handler instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_160",
        "pattern": r"(?:src|href|action)\s*=\s*\{\s*(?:user|input|query|params|data)\b",
        "message": "URL attribute bound to user-controlled variable without validation - validate and sanitize URLs",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_161",
        "pattern": r'''(?:React|react).*(?:componentDidMount|useEffect).*(?:document\.cookie|localStorage\.getItem\s*\(\s*[\"']token)''',
        "message": "Accessing auth tokens in component lifecycle - centralize auth state management",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_162",
        "pattern": r"__NEXT_DATA__|window\.__NUXT__|window\.__INITIAL_STATE__",
        "message": "Accessing framework internal state directly - may contain sensitive server-side data exposed to client",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_163",
        "pattern": r"(?:onClick|onSubmit|onChange)\s*=\s*\{?\s*(?:eval|Function)\s*\(",
        "message": "Event handler using eval or Function constructor - code injection risk",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_164",
        "pattern": r'''postMessage\s*\(\s*.*,\s*[\"']\*[\"']\s*\)''',
        "message": "postMessage with wildcard origin '*' - messages can be received by any window, specify target origin",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_165",
        "pattern": r'''addEventListener\s*\(\s*[\"']message[\"'].*(?!.*origin)''',
        "message": "Message event listener without origin validation - check event.origin before processing",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_166",
        "pattern": r'''\$\(\s*[\"']<|\.html\s*\(\s*(?:data|response|input|user|value)''',
        "message": "jQuery DOM insertion with dynamic content - sanitize to prevent XSS",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_167",
        "pattern": r"\.(?:trustAsHtml|trustAs)\s*\(\s*\$scope\.",
        "message": "AngularJS $sce.trustAsHtml with scope variable - verify input is sanitized before trusting",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_168",
        "pattern": r"templateUrl\s*:\s*(?:this\.)?\w+\s*\+|template\s*:\s*(?:this\.)?\w+\s*\+",
        "message": "Angular template URL or template built with string concatenation - use static template paths",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_169",
        "pattern": r"(?:Helmet|helmet).*(?:contentSecurityPolicy\s*:\s*false|csp\s*:\s*false)",
        "message": "Content Security Policy disabled in Helmet - CSP is critical for XSS prevention",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_170",
        "pattern": r"X-Frame-Options.*(?:ALLOWALL|ALLOW-FROM\s+\*)|frameguard\s*:\s*false",
        "message": "X-Frame-Options disabled or permissive - enables clickjacking attacks",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_171",
        "pattern": r"createRef\s*\(\s*\).*\.current\.innerHTML\s*=",
        "message": "React ref used to set innerHTML - bypasses React's XSS protections, sanitize first",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_172",
        "pattern": r"useRouter\s*\(\s*\).*\.query\b.*dangerouslySetInnerHTML",
        "message": "Router query parameter rendered via dangerouslySetInnerHTML - reflected XSS vulnerability",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_173",
        "pattern": r"(?:import\.meta\.env)\.(?!VITE_|REACT_APP_)\w+",
        "message": "Accessing non-public environment variable in client-side code - may leak server secrets to browser",
        "severity": Severity.WARN,
        "file_types": [".jsx", ".tsx", ".vue", ".svelte"],
    },
    {
        "id": "r1a_174",
        "pattern": r'''(?:target)\s*=\s*[\"']_blank[\"'](?!.*rel\s*=\s*[\"'].*noopener)''',
        "message": "Link with target=_blank without rel=noopener - enables reverse tabnabbing attack",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_175",
        "pattern": r'''DOMParser\s*\(\s*\)\.parseFromString\s*\([^,]+,\s*[\"']text/html[\"']\s*\).*\.body\.innerHTML''',
        "message": "DOMParser HTML output used as innerHTML - parse result may contain executable script content",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_176",
        "pattern": r"go\s+func\s*\([^)]*\)\s*\{[^}]*\}\s*\(\s*\)",
        "message": "Goroutine launched without context or cancellation mechanism - use context.Context for lifecycle management",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_177",
        "pattern": r"go\s+func\s*\(\s*\)\s*\{(?:[^}](?!select\s*\{))*\bfor\s*\{",
        "message": "Goroutine with infinite loop without select or context.Done - potential goroutine leak",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_178",
        "pattern": r"if\s+err\s*!=\s*nil\s*\{\s*\n?\s*\}",
        "message": "Empty error handling block - error silently swallowed, log or return the error",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_179",
        "pattern": r"if\s+err\s*!=\s*nil\s*\{\s*\n?\s*return\s+nil\s*\n?\s*\}",
        "message": "Error replaced with nil return - caller loses error context, propagate the error",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_180",
        "pattern": r"defer\s+\w+\.(?:Unlock|RUnlock)\s*\(\s*\)[\s\S]*?\w+\.(?:Lock|RLock)\s*\(\s*\)",
        "message": "Defer of Unlock before Lock call - defer runs at function exit, ensure Lock is called before defer Unlock",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_181",
        "pattern": r"defer\s+func\s*\(\s*\)\s*\{\s*(?:recover|if\s+r\s*:=\s*recover)",
        "message": "Blanket panic recovery in defer - log the recovered value and consider whether recovery is appropriate",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_182",
        "pattern": r"result\s*:=\s*\w+\[:\]|copy\s*:=\s*\w+\[:\]",
        "message": "Slice aliasing via [:] creates a reference, not a copy - use copy() or append to new slice for independence",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_183",
        "pattern": r"^\s+append\s*\(\s*\w+\s*,\s*\w+\s*\)",
        "message": "append() result not assigned - append may return a new slice, always assign the result",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
    },
    {
        "id": "r1a_184",
        "pattern": r"for\s+\w+\s*,\s*\w+\s*:=\s*range\s+\w+\s*\{[^}]*go\s+func\s*\(\s*\)\s*\{[^}]*\w+",
        "message": "Goroutine in range loop captures loop variable by reference - pass as parameter to avoid race condition",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_185",
        "pattern": r"time\.Sleep\s*\(\s*time\.(?:Second|Millisecond)\s*\*\s*\d+\s*\).*(?:retry|Retry|poll|Poll)",
        "message": "Fixed sleep for retry/polling - use exponential backoff with jitter",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_186",
        "pattern": r'''http\.ListenAndServe\s*\(\s*[\"']:(?:80|443|8080|8443)[\"']''',
        "message": "http.ListenAndServe used directly - use http.Server with timeouts configured (ReadTimeout, WriteTimeout)",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_187",
        "pattern": r"http\.DefaultClient|http\.Get\s*\(|http\.Post\s*\(",
        "message": "Using http.DefaultClient or top-level Get/Post - has no timeout, create client with explicit timeout",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_188",
        "pattern": r"resp\s*,\s*_\s*:=\s*http\.\w+\s*\(|resp\s*,\s*_\s*=\s*http\.\w+\s*\(",
        "message": "HTTP response error ignored with blank identifier - always check and handle HTTP errors",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_189",
        "pattern": r"json\.Unmarshal\s*\([^,]+,\s*&\w+\s*\)\s*\n(?!\s*if\s+err)",
        "message": "json.Unmarshal error not checked on next line - malformed JSON will cause silent data loss",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_190",
        "pattern": r"defer\s+resp\.Body\.Close\s*\(\s*\)\s*\n(?!\s*if\s+err)",
        "message": "Defer resp.Body.Close before checking error - if err is not nil, resp may be nil causing panic",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1a_191",
        "pattern": r"sync\.(?:Mutex|RWMutex)\s*\}(?!.*copy)",
        "message": "Struct containing sync.Mutex - ensure the struct is never copied (pass by pointer, implement noCopy)",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_192",
        "pattern": r"select\s*\{\s*\n\s*case\s+<-\s*ctx\.Done\s*\(\s*\)\s*:\s*\n\s*return",
        "message": "Select with only ctx.Done case - if this is the only case, the goroutine blocks unnecessarily, add default or other cases",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_193",
        "pattern": r"make\s*\(\s*chan\s+\w+\s*\)(?!.*select|.*goroutine|.*go\s+func)",
        "message": "Unbuffered channel created without apparent consumer goroutine - may cause deadlock",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_194",
        "pattern": r"os\.Exit\s*\(\s*\d+\s*\)(?!.*main\s*\()",
        "message": "os.Exit called outside main - prevents defer cleanup and makes testing difficult",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_195",
        "pattern": r"log\.(?:Fatal|Panic)\s*\((?!.*main\s*func)",
        "message": "log.Fatal/Panic outside main function - terminates program without cleanup, return errors instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_196",
        "pattern": r'string\s*\(\s*\w+\s*\)\s*(?:==|!=)\s*\"\"',
        "message": "Converting bytes to string for empty check - use len() == 0 to avoid allocation",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_197",
        "pattern": r'''(?:errors\.New|fmt\.Errorf)\s*\(\s*[\"'][A-Z]''',
        "message": "Error message starts with uppercase - Go convention is lowercase error messages without punctuation",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_198",
        "pattern": r"func\s+\(\w+\s+\w+\)\s+(?:Error|String)\s*\(\s*\)\s+string\s*\{[^}]*fmt\.Sprintf\s*\(\s*[^)]*\bself\b",
        "message": "Error()/String() method may cause infinite recursion if it references the receiver in fmt.Sprintf",
        "severity": Severity.WARN,
    },
    {
        "id": "r1a_199",
        "pattern": r"context\.(?:Background|TODO)\s*\(\s*\)(?!.*WithTimeout|.*WithCancel|.*WithDeadline)",
        "message": "context.Background/TODO used without timeout or cancellation - wrap with WithTimeout or WithCancel",
        "severity": Severity.INFO,
    },
    {
        "id": "r1a_200",
        "pattern": r"t\.(?:Error|Errorf|Fail)\s*\([^)]*\)\s*\n(?!\s*return|\s*\})",
        "message": "Test uses t.Error/Errorf without return - test continues executing after failure, use t.Fatal instead or add return",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_001",
        "pattern": r"(?i)introspection\s*[\(:].*(?:true|enabled)",
        "message": "GraphQL introspection enabled in production exposes schema to attackers",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_002",
        "pattern": r'''(?i)access-control-allow-origin\s*[=:]\s*['"]?\*''',
        "message": "CORS wildcard origin allows any domain to make cross-origin requests",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_003",
        "pattern": r"(?i)\.assign\s*\(\s*(?:req\.body|request\.body|params)",
        "message": "Mass assignment from request body without allowlisting fields enables property injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_004",
        "pattern": r"(?i)find(?:One|ById)?\s*\(\s*(?:req\.params|request\.params)",
        "message": "Direct use of user-supplied ID in database lookup without ownership check (IDOR risk)",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_005",
        "pattern": r"(?i)rate_?limit\s*[=:]\s*(?:0|false|none|null|disabled)",
        "message": "Rate limiting explicitly disabled exposes API to brute force and DoS attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_006",
        "pattern": r'''(?i)graphql\s*\(\s*['"`].*\$\{''',
        "message": "GraphQL query built via string interpolation enables injection attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_007",
        "pattern": r"(?i)@Public\s*\n.*@(?:Mutation|Query)",
        "message": "GraphQL resolver marked as public without authentication guard on mutation or query",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_008",
        "pattern": r"(?i)depth[_\-]?limit\s*[=:]\s*(?:[5-9]\d+|\d{3,})",
        "message": "GraphQL query depth limit set excessively high allows deeply nested denial-of-service queries",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_009",
        "pattern": r"(?i)max[_\-]?complexity\s*[=:]\s*(?:0|null|none|false)",
        "message": "GraphQL query complexity analysis disabled allows resource-exhaustion attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_010",
        "pattern": r"(?i)@Expose\(\s*\)\s*\n.*(?:password|secret|token|apiKey)",
        "message": "Sensitive field exposed through API serialization decorator without exclusion",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_011",
        "pattern": r"(?i)res(?:ponse)?\.json\(\s*(?:user|account|record)\s*\)",
        "message": "Entire database object returned in API response may leak sensitive internal fields",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_012",
        "pattern": r"(?i)api[_\-]?key\s*[=:]\s*(?:req|request)\.(?:query|params)\.",
        "message": "API key accepted via query parameter exposes it in server logs and browser history",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_013",
        "pattern": r"(?i)(?:allow|permit)[_\-]?batch\s*[=:]\s*true.*(?:mutation|delete|update)",
        "message": "Batched mutations enabled without per-operation authorization check",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_014",
        "pattern": r"(?i)x-forwarded-for.*(?:trust|accept)\s*[=:]\s*true",
        "message": "Blindly trusting X-Forwarded-For header enables IP spoofing to bypass rate limits",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_015",
        "pattern": r'''(?i)(?:scope|permission)\s*[=:]\s*['"]?\*['"]?''',
        "message": "Wildcard scope or permission grants unrestricted access to all resources",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_016",
        "pattern": r"(?i)pagination\s*[=:]\s*false|(?:limit|page_size)\s*[=:]\s*(?:0|null|none)",
        "message": "API endpoint without pagination allows unbounded data retrieval causing memory exhaustion",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_017",
        "pattern": r"(?i)(?:create|update|save)\s*\(\s*\{?\s*\.\.\.(?:req|request)\.body",
        "message": "Spread operator on request body in database write enables mass assignment",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_018",
        "pattern": r"(?i)helmet\s*\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false",
        "message": "Content Security Policy disabled in Helmet middleware removes XSS protection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_019",
        "pattern": r"(?i)@ApiProperty\(\s*\)\s*\n\s*(?:password|hash|salt|secret)",
        "message": "Sensitive field included in Swagger API documentation via ApiProperty decorator",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_020",
        "pattern": r"(?i)(?:query|gql)\s*[(`][\s\S]*?__typename",
        "message": "GraphQL __typename introspection fragment used in production query may leak schema details",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_021",
        "pattern": r"(?i)subscription\s*\{[\s\S]*?(?:without|no)\s*auth",
        "message": "GraphQL subscription without authentication allows unauthorized real-time data access",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_022",
        "pattern": r"(?i)access-control-allow-credentials\s*[=:]\s*true.*access-control-allow-origin\s*[=:]\s*\*",
        "message": "CORS credentials with wildcard origin is a browser-rejected but server-side misconfiguration",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_023",
        "pattern": r"(?i)(?:api|endpoint|route).*(?:admin|internal).*(?:public|open|no.?auth)",
        "message": "Administrative or internal API endpoint configured without authentication",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_024",
        "pattern": r"(?i)\.filter\(\s*(?:req|request)\.(?:query|body)\s*\)",
        "message": "Passing raw request parameters as database filter criteria enables NoSQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_025",
        "pattern": r"(?i)(?:max|limit)[_\-]?(?:upload|file)[_\-]?size\s*[=:]\s*(?:\d{9,}|Infinity|null|0)",
        "message": "File upload size limit set too high or disabled enables denial-of-service via large uploads",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_026",
        "pattern": r"(?i)app\.use\(\s*cors\(\s*\)\s*\)",
        "message": "CORS middleware used with default open configuration allows all cross-origin requests",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_027",
        "pattern": r"(?i)@SkipAuth|@NoAuth|@AllowAnonymous.*(?:delete|update|admin)",
        "message": "Destructive or administrative operation decorated to skip authentication",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_028",
        "pattern": r"(?i)(?:idempotency|replay)[_\-]?(?:check|protection)\s*[=:]\s*(?:false|disabled|off)",
        "message": "Idempotency or replay protection disabled on financial or state-changing endpoint",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_029",
        "pattern": r"(?i)(?:query|gql)\s*[(`][\s\S]*?(?:union|join)\s+[\s\S]*?\$\{",
        "message": "SQL or GraphQL union/join operation constructed with string interpolation enables injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_030",
        "pattern": r'''(?i)response\.header\(\s*['"]X-Powered-By''',
        "message": "X-Powered-By header reveals server technology stack aiding reconnaissance attacks",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_031",
        "pattern": r"\bgets\s*\(",
        "message": "Use of gets() is always unsafe as it performs no bounds checking on input buffer",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
    },
    {
        "id": "r1b_032",
        "pattern": r'''sprintf\s*\([^,]+,\s*['"]%s['"]''',
        "message": "sprintf with %s format has no length limit; use snprintf to prevent buffer overflow",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_033",
        "pattern": r"strcpy\s*\(",
        "message": "strcpy performs no bounds checking; use strncpy or strlcpy to prevent buffer overflow",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_034",
        "pattern": r"strcat\s*\(",
        "message": "strcat performs no bounds checking; use strncat or strlcat to prevent buffer overflow",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_035",
        "pattern": r"free\s*\(\s*(\w+)\s*\)(?:(?!.*\1\s*=\s*NULL)[\s\S])*?free\s*\(\s*\1\s*\)",
        "message": "Potential double-free detected: same pointer freed twice without nullification",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_036",
        "pattern": r"free\s*\(\s*(\w+)\s*\)\s*;(?:\s*\n)*\s*(?!\s*\1\s*=\s*NULL)\s*\1\s*(?:->|\[)",
        "message": "Use-after-free: pointer dereferenced after being freed without reassignment",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_037",
        "pattern": r"unsafe\s*\{[\s\S]*?\*\s*(?:mut\s+)?(?:ptr|raw|pointer)",
        "message": "Raw pointer dereference inside unsafe block in Rust requires careful lifetime management",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_038",
        "pattern": r"malloc\s*\(.*\)\s*;(?:\s*\n)*\s*(?!\s*if\s*\()",
        "message": "malloc return value not checked for NULL; memory allocation failure will cause null dereference",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_039",
        "pattern": r"realloc\s*\(\s*(\w+)\s*,",
        "message": "realloc on same pointer without storing in temp variable causes memory leak if realloc fails",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_040",
        "pattern": r"alloca\s*\(",
        "message": "alloca allocates on stack without bounds checking; large allocations cause stack overflow",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_041",
        "pattern": r'''scanf\s*\(\s*['"]%s['"]''',
        "message": "scanf with %s has no field width limit; use %Ns with explicit width to prevent overflow",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_042",
        "pattern": r"memcpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(\s*\*",
        "message": "memcpy using sizeof pointer instead of sizeof pointed-to structure copies wrong bytes",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_043",
        "pattern": r"(?:int|short|char)\s+\w+\s*=\s*atoi\s*\(",
        "message": "atoi has no error handling for invalid input; use strtol with error checking instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_044",
        "pattern": r"unsafe\s*\{[\s\S]*?(?:transmute|transmute_copy)\s*[:<(]",
        "message": "std::mem::transmute in unsafe block reinterprets bits without type safety checks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_045",
        "pattern": r"(?:static\s+mut|lazy_static.*mut)\s+\w+",
        "message": "Static mutable variable in Rust creates data race conditions across threads",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_046",
        "pattern": r"\.as_ptr\(\)\s*(?:as\s+\*(?:const|mut))",
        "message": "Casting slice reference to raw pointer may outlive the borrowed data causing dangling pointer",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_047",
        "pattern": r"#\[no_mangle\]\s*\n\s*pub\s+(?:unsafe\s+)?extern",
        "message": "no_mangle FFI function should validate all pointer arguments for null before dereferencing",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_048",
        "pattern": r"new\s*\[\s*[^]\n]*\]\s*;(?:\s*\n)*(?!.*delete\s*\[\])",
        "message": "Array allocated with new[] must be freed with delete[]; mismatch causes undefined behavior",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_049",
        "pattern": r"int\s+\w+\s*\[\s*\]\s*;",
        "message": "Zero-length or unsized array declaration without explicit size leads to undefined behavior",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_050",
        "pattern": r"char\s+\w+\s*\[\s*(\d+)\s*\]\s*;\s*\n\s*(?:str(?:n?cpy|cat)|memcpy|sprintf)",
        "message": "Fixed-size stack buffer followed immediately by copy operation without explicit size check",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_051",
        "pattern": r"mmap\s*\(.*PROT_EXEC\s*\|\s*PROT_WRITE",
        "message": "Memory mapped with both write and execute permissions enables code injection attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_052",
        "pattern": r"(?:va_start|va_arg)\s*\(",
        "message": "Variadic functions bypass type checking; prefer type-safe alternatives",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_053",
        "pattern": r"std::auto_ptr",
        "message": "std::auto_ptr is deprecated and has broken copy semantics; use std::unique_ptr instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_054",
        "pattern": r"(?:reinterpret|const|static|dynamic)_cast\s*<\s*(?:void|char)\s*\*",
        "message": "Casting to void* or char* discards type information and bypasses type safety",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_055",
        "pattern": r"union\s*\{[\s\S]*?(?:int|float|char|double|long)",
        "message": "Union with overlapping primitive types may cause type punning and undefined behavior",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_056",
        "pattern": r"#pragma\s+pack\s*\(\s*1\s*\)",
        "message": "Struct packing to 1 byte alignment causes performance degradation and potential misaligned access",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_057",
        "pattern": r"std::string_view\s+\w+\s*=\s*(?:std::string|std::to_string)\s*\(",
        "message": "string_view from temporary string creates dangling reference after statement ends",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_058",
        "pattern": r"Box::from_raw\s*\(",
        "message": "Box::from_raw requires the pointer to have been originally created by Box::into_raw",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_059",
        "pattern": r"std::mem::forget\s*\(",
        "message": "std::mem::forget prevents drop from running, causing resource leaks for types with Drop",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_060",
        "pattern": r"setjmp\s*\(|longjmp\s*\(",
        "message": "setjmp/longjmp bypass RAII destructors in C++ and corrupt stack unwinding",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_061",
        "pattern": r"ObjectInputStream\s*\(\s*(?:new\s+)?(?:Socket|URL|Http)",
        "message": "Deserializing objects from network input enables remote code execution via gadget chains",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_062",
        "pattern": r"(?i)InitialContext\s*\(\s*\)|new\s+InitialDirContext",
        "message": "JNDI lookup with user-controlled input enables remote class loading",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_063",
        "pattern": r"(?:ctx|context)\s*\.\s*lookup\s*\(\s*(?:request|param|input|user|req\.get)",
        "message": "JNDI lookup with user-supplied name enables JNDI injection and remote code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_064",
        "pattern": r"@RequestMapping\s*\((?!.*method\s*=)",
        "message": "Spring @RequestMapping without explicit HTTP method accepts all methods including dangerous ones",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_065",
        "pattern": r"(?i)spring\.jpa\.hibernate\.ddl-auto\s*=\s*(?:create|create-drop|update)",
        "message": "Hibernate DDL auto mode in production will modify or destroy database schema automatically",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_066",
        "pattern": r"Class\s*\.\s*forName\s*\(\s*(?:request|param|input|args\[)",
        "message": "Dynamic class loading from user input enables arbitrary class instantiation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_067",
        "pattern": r"\.getMethod\s*\(\s*(?:request|param|input|user)",
        "message": "Reflective method lookup from user input enables arbitrary method invocation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_068",
        "pattern": r'(?i)@CrossOrigin\s*(?:\(\s*\)|\(\s*origins?\s*=\s*"\*")',
        "message": "Spring @CrossOrigin with wildcard or default allows all origins for this endpoint",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_069",
        "pattern": r"\.setAccessible\s*\(\s*true\s*\)",
        "message": "Reflection setAccessible(true) bypasses Java access control and encapsulation",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_070",
        "pattern": r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
        "message": "Runtime.exec with string argument is vulnerable to command injection; use ProcessBuilder",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_071",
        "pattern": r"XMLInputFactory\s*\.\s*newInstance\s*\(\s*\)(?![\s\S]*?setProperty[\s\S]*?SUPPORT_DTD)",
        "message": "XMLInputFactory without disabling DTD support is vulnerable to XXE attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_072",
        "pattern": r"@Cacheable\s*\((?!.*key\s*=)",
        "message": "Spring @Cacheable without explicit key may produce cache collisions",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_073",
        "pattern": r"(?i)spring\.datasource\.password\s*=\s*\S+",
        "message": "Database password hardcoded in Spring configuration; use environment variables or vault",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_074",
        "pattern": r"@Transactional\s*\(.*propagation\s*=\s*Propagation\s*\.\s*NOT_SUPPORTED",
        "message": "Transaction propagation NOT_SUPPORTED suspends existing transaction causing data inconsistency",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_075",
        "pattern": r"new\s+Random\s*\(\s*\)",
        "message": "java.util.Random is not cryptographically secure; use SecureRandom for security operations",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_076",
        "pattern": r"ScriptEngine\s*.*\.\s*eval\s*\(\s*(?:request|param|input|user)",
        "message": "Script engine eval with user input enables arbitrary code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_077",
        "pattern": r"@EnableWebSecurity[\s\S]*?csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)",
        "message": "CSRF protection disabled in Spring Security allows cross-site request forgery attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_078",
        "pattern": r"\.permitAll\s*\(\s*\)[\s\S]*?(?:/admin|/api/internal|/manage)",
        "message": "Administrative endpoint configured with permitAll bypasses authentication",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_079",
        "pattern": r'Cipher\s*\.\s*getInstance\s*\(\s*"(?:DES|RC[24]|Blowfish|ECB)',
        "message": "Weak or deprecated cipher algorithm; use AES-GCM or AES-CBC with HMAC",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_080",
        "pattern": r"TrustManager[\s\S]*?checkServerTrusted[\s\S]*?\{\s*\}",
        "message": "Empty TrustManager.checkServerTrusted disables SSL certificate validation entirely",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_081",
        "pattern": r"@PathVariable\s*(?:\([^)]*\))?\s*(?:String|Long|Integer)\s+\w+(?:Id|id)(?![\s\S]*?@PreAuthorize)",
        "message": "Path variable with resource ID without @PreAuthorize enables IDOR attacks",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_082",
        "pattern": r"(?:Yaml|ObjectMapper)\s*\(\s*\)\s*\.(?:load|readValue)\s*\(\s*(?:request|input|param)",
        "message": "Deserializing YAML or JSON from user input without type restriction enables code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_083",
        "pattern": r"@(?:Scheduled|Async)\s*\n(?!.*@Transactional)",
        "message": "Spring @Scheduled or @Async method without @Transactional may have unexpected persistence",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_084",
        "pattern": r'EntityManager\s*\.(?:createNativeQuery|createQuery)\s*\(\s*"[\s\S]*?"\s*\+',
        "message": "JPA query built with string concatenation enables SQL or JPQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_085",
        "pattern": r'@Value\s*\(\s*"\$\{.*:.*\}".*\)\s*\n\s*(?:private|public)\s+String\s+(?:secret|password|key|token)',
        "message": "Sensitive Spring @Value property has a default value which may be used if env var is missing",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_086",
        "pattern": r'new\s+ProcessBuilder\s*\(\s*(?:"(?:cmd|bash|sh|powershell)")',
        "message": "ProcessBuilder invoking shell interpreter may enable command injection via arguments",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_087",
        "pattern": r"@Entity[\s\S]*?@Column\s*\([\s\S]*?columnDefinition\s*=",
        "message": "JPA @Column with columnDefinition bypasses Hibernate DDL validation",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_088",
        "pattern": r"(?:Expression|SpelExpression)Parser\s*\(\s*\)\s*\.parseExpression\s*\(\s*(?:request|param|input)",
        "message": "Spring SpEL evaluation of user input enables remote code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_089",
        "pattern": r"@EnableScheduling[\s\S]*?@Scheduled\s*\(\s*fixedRate\s*=\s*\d{1,3}\s*\)",
        "message": "Scheduled task with very low fixedRate may overwhelm system resources",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_090",
        "pattern": r"ObjectMapper\s*\(\s*\)(?![\s\S]*?(?:activateDefaultTyping|deactivateDefaultTyping))",
        "message": "Jackson ObjectMapper without explicit type handling may be vulnerable to polymorphic deserialization",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_093",
        "pattern": r'''(?:include|require)(?:_once)?\s*\(\s*['"](?:https?://|ftp://)''',
        "message": "Remote file inclusion from URL enables execution of attacker-controlled code",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_094",
        "pattern": r'''\$_(?:GET|POST|REQUEST)\s*\[\s*['"][^'"]+['"]\s*\]\s*==\s*''',
        "message": "PHP loose comparison (==) with user input causes type juggling bypass (use === instead)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_095",
        "pattern": r"extract\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)",
        "message": "extract() on superglobals creates variables from user input enabling variable injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_096",
        "pattern": r"(?:shell_exec|passthru|proc_open)\s*\(\s*\$",
        "message": "Shell execution with variable argument enables command injection; use escapeshellarg",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_097",
        "pattern": r'''(?:system|exec|popen)\s*\(\s*['"].*\$_(?:GET|POST|REQUEST)''',
        "message": "OS command execution with user input directly interpolated enables command injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_098",
        "pattern": r'''preg_replace\s*\(\s*['"]\/.*/e['"]''',
        "message": "preg_replace with /e modifier evaluates replacement as PHP code enabling code injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_099",
        "pattern": r"assert\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "PHP assert() with user input evaluates string as code enabling remote code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_100",
        "pattern": r"create_function\s*\(",
        "message": "create_function uses eval internally and is deprecated; use anonymous functions instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_101",
        "pattern": r"\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "Variable function call with user input enables arbitrary function invocation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_102",
        "pattern": r"(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd)",
        "message": "MD5 or SHA1 for password hashing is insecure; use password_hash with PASSWORD_BCRYPT",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_103",
        "pattern": r"mysql_(?:query|real_escape_string|connect)\s*\(",
        "message": "mysql_* functions are removed in PHP 7+; use PDO or mysqli with prepared statements",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_104",
        "pattern": r'''header\s*\(\s*['"]Location:\s*['"]?\s*\.\s*\$_(?:GET|POST|REQUEST)''',
        "message": "Open redirect via user-controlled Location header enables phishing attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_105",
        "pattern": r"(?:echo|print)\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)",
        "message": "Direct output of user input without htmlspecialchars enables reflected XSS",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_106",
        "pattern": r"file_(?:get_contents|put_contents)\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "File operation with user-controlled path enables arbitrary file read/write",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_107",
        "pattern": r"simplexml_load_string\s*\(\s*\$(?!.*LIBXML_NOENT.*LIBXML_NONET)",
        "message": "SimpleXML without LIBXML_NOENT and LIBXML_NONET flags is vulnerable to XXE attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_108",
        "pattern": r"session_regenerate_id\s*\(\s*false\s*\)",
        "message": "session_regenerate_id(false) keeps old session file enabling session fixation",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_109",
        "pattern": r'''ini_set\s*\(\s*['"]display_errors['"]\s*,\s*['"]?(?:1|on|true)''',
        "message": "Displaying errors in production leaks sensitive information about application internals",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_110",
        "pattern": r"json_decode\s*\(\s*\$\w+\s*,\s*false\s*\)",
        "message": "json_decode returning objects instead of arrays may enable property injection attacks",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_111",
        "pattern": r'''\$_FILES\s*\[.*\]\s*\[\s*['"](?:name|type)['"]\s*\](?!.*pathinfo)''',
        "message": "Using uploaded file name or MIME type from client without validation enables upload attacks",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_112",
        "pattern": r"move_uploaded_file\s*\(.*\$_(?:GET|POST|REQUEST)",
        "message": "Upload destination path from user input enables arbitrary file placement on server",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_113",
        "pattern": r"call_user_func(?:_array)?\s*\(\s*\$_(?:GET|POST|REQUEST)",
        "message": "call_user_func with user input enables arbitrary function invocation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_114",
        "pattern": r"is_numeric\s*\(\s*\$\w+\s*\)\s*(?:&&|\?)[\s\S]*?(?:query|WHERE)",
        "message": "is_numeric allows hex strings which can bypass SQL injection filters in older PHP",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_115",
        "pattern": r"setcookie\s*\([^)]*\)(?!.*(?:httponly|secure))",
        "message": "Cookie set without httponly and secure flags is vulnerable to XSS theft and MITM",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_116",
        "pattern": r"(?:dl|register_shutdown_function)\s*\(\s*\$",
        "message": "Dynamic extension loading or shutdown function from variable enables code injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_117",
        "pattern": r"array_merge\s*\(\s*\$\w+\s*,\s*\$_(?:GET|POST|REQUEST)",
        "message": "Merging user input array into application data enables mass assignment of internal values",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_118",
        "pattern": r"sleep\s*\(\s*(?:intval|int)\s*\(\s*\$_(?:GET|POST)",
        "message": "Sleep duration from user input enables denial-of-service via thread exhaustion",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_119",
        "pattern": r"parse_str\s*\(\s*\$(?!.*,\s*\$)",
        "message": "parse_str without second parameter overwrites variables in current scope",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_120",
        "pattern": r'''mb_ereg_replace\s*\(\s*['"].*['"].*['"]e['"]''',
        "message": "mb_ereg_replace with e flag evaluates replacement as PHP code enabling injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_121",
        "pattern": r"attr_accessible\s+:.*(?:role|admin|is_admin|permissions)",
        "message": "Mass assignment of role or admin attributes via attr_accessible enables privilege escalation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_122",
        "pattern": r"YAML\s*\.\s*load\s*\((?!\s*.*safe|.*permitted)",
        "message": "YAML.load deserializes arbitrary Ruby objects enabling code execution; use YAML.safe_load",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_123",
        "pattern": r'''(?:system|exec|%x)\s*(?:\(|\{)\s*["'].*#\{''',
        "message": "Command execution with string interpolation enables shell injection attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_124",
        "pattern": r"`[^`]*#\{.*params",
        "message": "Backtick command execution with interpolated params enables command injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_125",
        "pattern": r'''\.where\s*\(\s*["'].*#\{''',
        "message": "ActiveRecord where clause with string interpolation enables SQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_126",
        "pattern": r'''\.find_by_sql\s*\(\s*["'].*#\{''',
        "message": "find_by_sql with interpolated values enables SQL injection; use placeholder parameters",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_127",
        "pattern": r"render\s+(?:text|inline)\s*:\s*params\[",
        "message": "Rendering user input as text/inline template enables XSS and SSTI attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_128",
        "pattern": r"\.html_safe\s*$",
        "message": "Marking string as html_safe bypasses Rails XSS escaping and may introduce vulnerabilities",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_129",
        "pattern": r"raw\s*\(\s*(?:params|request|@\w+)",
        "message": "raw() helper on user-controlled content disables HTML escaping enabling XSS",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_130",
        "pattern": r"send\s*\(\s*params\[",
        "message": "Dynamic method dispatch via send with user input enables arbitrary method invocation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_131",
        "pattern": r"constantize\s*\.\s*new|const_get\s*\(\s*params",
        "message": "Dynamic constant resolution from user input enables arbitrary class instantiation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_132",
        "pattern": r"(?:eval|instance_eval|class_eval|module_eval)\s*(?:\(|\s)(?:params|request)",
        "message": "eval family with user input enables arbitrary Ruby code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_133",
        "pattern": r"redirect_to\s*(?:\(?\s*)params\[",
        "message": "Redirect to user-supplied URL enables open redirect phishing attacks",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_135",
        "pattern": r"protect_from_forgery\s*(?::with\s*=>\s*:null_session|.*except)",
        "message": "CSRF protection weakened or exempted on controller actions",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_136",
        "pattern": r"config\.action_mailer\.(?:raise_delivery_errors|perform_deliveries)\s*=\s*false",
        "message": "Mail delivery errors silently swallowed makes it impossible to detect email failures",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_137",
        "pattern": r"\.order\s*\(\s*params\[",
        "message": "Dynamic ORDER BY from user input enables SQL injection in ActiveRecord",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_138",
        "pattern": r"\.pluck\s*\(\s*params\[",
        "message": "Dynamic column selection via pluck from user input enables SQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_139",
        "pattern": r"Kernel\.open\s*\(\s*(?:params|request|url)",
        "message": "Kernel.open with user input can execute commands via pipe; use File.open or URI.open",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_140",
        "pattern": r"Marshal\s*\.\s*(?:load|restore)\s*\(",
        "message": "Marshal.load of untrusted data enables arbitrary object instantiation and code execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_141",
        "pattern": r'''\.update_all\s*\(\s*["'].*#\{''',
        "message": "update_all with interpolated SQL enables mass SQL injection affecting multiple records",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_142",
        "pattern": r"Digest::(?:MD5|SHA1)\s*\.\s*(?:hexdigest|digest)\s*\(\s*(?:password|pass)",
        "message": "MD5 or SHA1 for password hashing is cryptographically weak; use bcrypt or Argon2",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_143",
        "pattern": r'''config\.secret_key_base\s*=\s*['"][a-f0-9]+['"]''',
        "message": "Hardcoded secret_key_base enables session forgery; use environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_144",
        "pattern": r'''\.delete_all\s*\(\s*["'].*#\{''',
        "message": "delete_all with string interpolation enables SQL injection for mass deletion",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_145",
        "pattern": r"\.calculate\s*\(\s*params\[",
        "message": "ActiveRecord calculate with user-controlled operation enables SQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_146",
        "pattern": r"config\.log_level\s*=\s*:debug(?:.*production)",
        "message": "Debug log level in production exposes sensitive application internals",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_148",
        "pattern": r"Tempfile\s*\.\s*new\s*\(.*params\[",
        "message": "Tempfile name from user input may enable path traversal or symlink attacks",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_149",
        "pattern": r"config\.consider_all_requests_local\s*=\s*true(?:.*production)",
        "message": "Treating all requests as local in production exposes detailed error pages",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_150",
        "pattern": r"ERB\s*\.new\s*\(\s*(?:params|request)",
        "message": "ERB template rendering from user input enables server-side template injection (SSTI)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_151",
        "pattern": r"kSecAttrAccessible(?:Always|AlwaysThisDeviceOnly)(?!\s*//\s*deprecated)",
        "message": "Keychain item accessible when device is locked exposes credentials if device is stolen",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_153",
        "pattern": r"\.allowsHitTesting\s*\(\s*false\s*\).*(?:biometric|faceID|touchID)",
        "message": "Disabling hit testing on biometric UI elements may enable authentication bypass",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_154",
        "pattern": r"canEvaluatePolicy\s*\(.*\)\s*\{[\s\S]*?(?:else|catch)\s*\{[\s\S]*?(?:return\s+true|success)",
        "message": "Biometric authentication fallback grants access on failure enabling bypass",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_155",
        "pattern": r"UserDefaults\s*\.(?:standard|set).*(?:password|token|secret|apiKey|api_key)",
        "message": "Storing sensitive data in UserDefaults which is unencrypted and backed up to iCloud",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_156",
        "pattern": r"URLSession\s*\.shared\s*\.(?:data|download)Task.*http://",
        "message": "HTTP request via URLSession without TLS exposes data to network interception",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_157",
        "pattern": r"UIPasteboard\s*\.general\s*\.string\s*=.*(?:password|token|secret)",
        "message": "Copying sensitive data to system pasteboard exposes it to other applications",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_158",
        "pattern": r"(?:NSLog|print|debugPrint)\s*\(.*(?:password|token|secret|apiKey|credential)",
        "message": "Logging sensitive data which persists in device logs accessible via Console.app",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_159",
        "pattern": r"SecTrustEvaluate.*kSecTrustResultProceed.*kSecTrustResultUnspecified",
        "message": "Accepting both proceed and unspecified trust results weakens certificate validation",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_160",
        "pattern": r"\.serverTrust\s*!\s*(?:\n|;)",
        "message": "Force-unwrapping server trust without validation disables SSL certificate checking",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_161",
        "pattern": r'let\s+\w+\s*=\s*"(?:[A-Za-z0-9+/]{20,}={0,2})"',
        "message": "Hardcoded base64 string in source code may be an embedded secret or API key",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_162",
        "pattern": r'fileExistsAtPath\s*\(\s*"/(?:Applications/Cydia|private/var/lib/apt|bin/bash)"',
        "message": "Jailbreak detection via simple file existence check is easily bypassed",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_163",
        "pattern": r"UIWebView",
        "message": "UIWebView is deprecated and has known security vulnerabilities; use WKWebView instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_164",
        "pattern": r"\.javaScriptEnabled\s*=\s*true(?![\s\S]*?WKContentRuleList)",
        "message": "WebView with JavaScript enabled without content rules may be vulnerable to XSS",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_165",
        "pattern": r"kSecAttrAccessControl.*biometryAny(?!.*devicePasscode)",
        "message": "Biometric-only keychain access without device passcode fallback may lock users out",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_166",
        "pattern": r"CCCrypt\s*\(.*kCCAlgorithmDES",
        "message": "DES encryption is cryptographically broken; use kCCAlgorithmAES128 or higher",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_167",
        "pattern": r"SecRandomCopyBytes.*kSecRandomDefault",
        "message": "SecRandomCopyBytes failure should be handled; silently returning default produces predictable output",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_168",
        "pattern": r'canOpenURL\s*\(\s*URL\s*\(\s*string\s*:\s*"cydia://',
        "message": "Jailbreak detection via URL scheme checking is trivially bypassed",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_169",
        "pattern": r"URLSessionConfiguration\s*\.default\s*(?:\n|;)(?!.*\.tlsMinimumSupportedProtocolVersion)",
        "message": "URLSession without minimum TLS version allows connections over deprecated TLS 1.0/1.1",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_170",
        "pattern": r"\.allowsBackForwardNavigationGestures\s*=\s*true.*(?:auth|login|payment)",
        "message": "Back/forward navigation gestures in auth or payment WebView may skip validation",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_171",
        "pattern": r"NSDictionary\s*\(\s*contentsOfFile\s*:.*\.plist\).*(?:key|secret|password)",
        "message": "Reading secrets from plist file which is not encrypted and included in app bundle",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_172",
        "pattern": r"(?:GCDWebServer|CocoaHTTPServer|Swifter)\s*\(\s*\)",
        "message": "Embedded HTTP server in iOS app exposes local attack surface",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_173",
        "pattern": r"FileManager\s*\.default\s*\.createFile.*attributes\s*:\s*nil.*(?:private|sensitive|secret)",
        "message": "Creating file with sensitive data without setting file protection attributes",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_174",
        "pattern": r"\.resolvingSymlinksInPath\s*\(\s*\)(?![\s\S]*?(?:sandbox|whitelist|allowlist))",
        "message": "Resolving symlinks without sandbox path validation may escape the app container",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_175",
        "pattern": r"MKPinAnnotationView.*subtitle.*(?:address|phone|email|ssn)",
        "message": "Displaying PII in map pin annotations may expose sensitive data in screenshots",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_176",
        "pattern": r'(?i)assume_role_policy.*"Principal".*"AWS".*"\*"',
        "message": "IAM role trust policy allows any AWS account to assume the role",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_178",
        "pattern": r"(?i)aws_flow_log.*(?:log_destination|traffic_type)",
        "message": "VPC defined without flow logs prevents network traffic auditing",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_179",
        "pattern": r"(?i)aws_wafv2.*default_action[\s\S]*?allow",
        "message": "WAF with default allow action undermines web application firewall protection",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_180",
        "pattern": r"(?i)aws_s3_bucket(?![\s\S]{0,500}?server_side_encryption)",
        "message": "S3 bucket defined without server-side encryption configuration",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_181",
        "pattern": r"(?i)aws_db_instance[\s\S]*?publicly_accessible\s*=\s*true",
        "message": "RDS instance publicly accessible exposes database to internet-based attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_182",
        "pattern": r'(?i)aws_security_group[\s\S]*?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
        "message": "Security group open to all IP addresses enables unauthorized access",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_183",
        "pattern": r'(?i)aws_iam_policy[\s\S]*?"Action"\s*:\s*"\*"[\s\S]*?"Resource"\s*:\s*"\*"',
        "message": "IAM policy with wildcard action and resource grants full administrative access",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_184",
        "pattern": r"(?i)aws_cloudtrail[\s\S]*?enable_logging\s*=\s*false",
        "message": "CloudTrail logging disabled prevents audit trail of AWS API activity",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_185",
        "pattern": r"(?i)aws_ebs_volume(?![\s\S]{0,300}?encrypted\s*=\s*true)",
        "message": "EBS volume without encryption at rest exposes data if hardware is compromised",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_186",
        "pattern": r"(?i)aws_elasticsearch_domain[\s\S]*?node_to_node_encryption[\s\S]*?enabled\s*=\s*false",
        "message": "Elasticsearch domain without node-to-node encryption exposes data in transit",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_187",
        "pattern": r"(?i)aws_lambda_function[\s\S]*?timeout\s*=\s*900",
        "message": "Lambda function with maximum timeout may indicate unbounded processing and cost overrun",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_188",
        "pattern": r'(?i)aws_iam_user_policy[\s\S]*?sts:AssumeRole[\s\S]*?"Resource"\s*:\s*"\*"',
        "message": "IAM user with wildcard AssumeRole can escalate privileges to any role",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_189",
        "pattern": r'(?i)aws_sns_topic_policy[\s\S]*?"Principal"\s*:\s*"\*"',
        "message": "SNS topic policy with wildcard principal allows any account to publish",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_190",
        "pattern": r"(?i)aws_sqs_queue(?![\s\S]{0,300}?kms_master_key_id)",
        "message": "SQS queue without KMS encryption stores messages in plaintext at rest",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_191",
        "pattern": r"(?i)aws_ecr_repository(?![\s\S]{0,300}?image_scanning_configuration)",
        "message": "ECR repository without image scanning misses vulnerability detection",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_192",
        "pattern": r"(?i)aws_eks_cluster[\s\S]*?endpoint_public_access\s*=\s*true",
        "message": "EKS cluster public endpoint exposes Kubernetes API to the internet",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_193",
        "pattern": r"(?i)aws_redshift_cluster[\s\S]*?encrypted\s*=\s*false",
        "message": "Redshift cluster without encryption at rest violates data protection requirements",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_194",
        "pattern": r"(?i)aws_iam_role[\s\S]*?max_session_duration\s*=\s*43200",
        "message": "IAM role with 12-hour session duration increases window for credential abuse",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_195",
        "pattern": r"(?i)aws_config_configuration_recorder[\s\S]*?all_supported\s*=\s*false",
        "message": "AWS Config not recording all resource types leaves compliance gaps",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_196",
        "pattern": r"(?i)aws_guardduty_detector[\s\S]*?enable\s*=\s*false",
        "message": "GuardDuty detector disabled removes automated threat detection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_197",
        "pattern": r"(?i)aws_api_gateway_rest_api(?![\s\S]{0,500}?logging_level)",
        "message": "API Gateway without access logging prevents request auditing",
        "severity": Severity.WARN,
    },
    {
        "id": "r1b_198",
        "pattern": r'(?i)aws_msk_cluster[\s\S]*?client_broker\s*=\s*"PLAINTEXT"',
        "message": "MSK cluster allowing plaintext client connections exposes Kafka data in transit",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r1b_199",
        "pattern": r"(?i)aws_secretsmanager_secret(?![\s\S]{0,300}?rotation)",
        "message": "Secrets Manager secret without automatic rotation increases credential risk",
        "severity": Severity.INFO,
    },
    {
        "id": "r1b_200",
        "pattern": r"(?i)aws_dynamodb_table(?![\s\S]{0,300}?point_in_time_recovery)",
        "message": "DynamoDB table without point-in-time recovery risks unrecoverable data loss",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_001",
        "pattern": r"asyncio\.get_event_loop\(\)\.run_until_complete",
        "message": "Calling run_until_complete on the running loop blocks the event loop and causes deadlocks; use await instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_002",
        "pattern": r"time\.sleep\s*\(\s*[^)]+\)\s*.*(?:async\s+def|await)",
        "message": "Using time.sleep in async code blocks the entire event loop; use asyncio.sleep instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_003",
        "pattern": r"loop\.run_in_executor\s*\(\s*None\s*,\s*lambda",
        "message": "Passing lambda to run_in_executor is unpicklable and prevents proper cancellation; use a named function",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_004",
        "pattern": r"asyncio\.gather\s*\([^)]*return_exceptions\s*=\s*False",
        "message": "asyncio.gather with return_exceptions=False cancels remaining tasks on first failure; set return_exceptions=True or handle explicitly",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_005",
        "pattern": r"threading\.Thread\s*\(.*daemon\s*=\s*True",
        "message": "Daemon threads are killed abruptly at interpreter shutdown without cleanup; use non-daemon threads with proper join",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_006",
        "pattern": r"ctypes\.CDLL\s*\(.*\)\s*\n(?!.*try)",
        "message": "Loading C libraries via ctypes without error handling can cause segfaults; wrap in try/except OSError",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_007",
        "pattern": r"class\s+\w+\s*\(\s*type\s*\)\s*:(?!.*__init_subclass__)",
        "message": "Custom metaclass without __init_subclass__ creates fragile inheritance chains; prefer __init_subclass__ for most use cases",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_008",
        "pattern": r"def\s+__del__\s*\(\s*self\s*\)",
        "message": "Relying on __del__ for resource cleanup is unreliable due to GC non-determinism; use context managers or weakref.finalize",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_009",
        "pattern": r"yield\s+.*(?:open|connect|acquire)\s*\(",
        "message": "Yielding an open resource from a generator risks leak if the generator is not fully consumed; use contextlib.contextmanager",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_010",
        "pattern": r"global\s+\w+\s*\n.*(?:async\s+def|Thread)",
        "message": "Mutable global state shared across async tasks or threads causes race conditions; use contextvars or thread-local storage",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_011",
        "pattern": r"__slots__\s*=\s*\(.*\)\s*\n.*class\s+\w+\s*\(\s*\w+\s*\)\s*:\s*\n(?!.*__slots__)",
        "message": "Subclass missing __slots__ negates memory savings of parent __slots__; define __slots__ in all subclasses",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_012",
        "pattern": r"async\s+def\s+\w+\s*\([^)]*\)[^:]*:\s*\n\s+return\s+(?!await)",
        "message": "Async function that never awaits is unnecessary overhead; remove async keyword or add proper await",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_013",
        "pattern": r"multiprocessing\.Pool\s*\(\s*\)(?!.*close|terminate|__enter__)",
        "message": "Creating multiprocessing.Pool without close/terminate leaks child processes; use as context manager",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_014",
        "pattern": r"signal\.signal\s*\(\s*signal\.\w+.*(?:async|thread)",
        "message": "Signal handlers can only run in the main thread; registering from async or worker threads raises RuntimeError",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_015",
        "pattern": r"sys\.setrecursionlimit\s*\(\s*\d{5,}",
        "message": "Increasing recursion limit beyond 10000 risks segfault from stack overflow; refactor to iterative approach",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_017",
        "pattern": r"__getattr__\s*.*(?:raise\s+AttributeError|return\s+None)",
        "message": "Swallowing attribute errors in __getattr__ silently breaks hasattr checks and IDE introspection",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_018",
        "pattern": r"asyncio\.create_task\s*\([^)]+\)(?!\s*\n\s*\w+\s*=)",
        "message": "Fire-and-forget asyncio.create_task loses exceptions silently; store the task reference and handle results",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_019",
        "pattern": r"concurrent\.futures\.Future\s*\(\s*\)",
        "message": "Manually constructing Future objects bypasses executor lifecycle management; use executor.submit instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_020",
        "pattern": r"from\s+__future__\s+import\s+annotations.*\n.*isinstance\s*\(",
        "message": "PEP 563 deferred annotations break isinstance checks on string-form type hints at runtime; use typing.get_type_hints",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_021",
        "pattern": r"weakref\.ref\s*\((?:int|str|float|tuple|bytes|frozenset)\s*\(",
        "message": "Built-in immutable types do not support weak references; weakref.ref will raise TypeError",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_022",
        "pattern": r"os\.fork\s*\(\).*(?:thread|Thread|asyncio)",
        "message": "Forking a multithreaded or async process creates deadlock-prone children; use multiprocessing.spawn start method",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_023",
        "pattern": r"@property\s*\n\s*def\s+\w+\s*\(self\).*\n(?:.*\n){0,5}.*(?:requests\.get|httpx|aiohttp|urlopen)",
        "message": "Property performing network I/O violates caller expectations of fast attribute access; use an explicit method",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_024",
        "pattern": r"logging\.basicConfig\s*\(.*filename\s*=",
        "message": "logging.basicConfig overwrites root logger config and silently drops structured handlers; configure handlers explicitly",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_025",
        "pattern": r"itertools\.count\s*\(\s*\)(?!.*break|islice|takewhile)",
        "message": "Unbounded itertools.count without termination condition creates infinite loop risk; use islice or takewhile",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_026",
        "pattern": r"def\s+__init__\s*\(self[^)]*\)\s*:\s*\n(?:.*\n){0,3}.*self\.\w+\s*=\s*\[\]",
        "message": "Mutable instance attribute initialized in __init__ may mask class-level shared mutable default; verify no class-level list exists",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_027",
        "pattern": r"async\s+with\s+asyncio\.timeout\s*\(\s*0\s*\)",
        "message": "asyncio.timeout(0) raises TimeoutError immediately without giving the coroutine a chance to run; use a positive value",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_028",
        "pattern": r"(?:await\s+)?asyncio\.sleep\s*\(\s*0\s*\)\s*#.*(?:yield|switch)",
        "message": "Using asyncio.sleep(0) as explicit yield point is fragile; restructure for natural cooperative scheduling",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_029",
        "pattern": r"importlib\.import_module\s*\(\s*(?:input|request|os\.environ)",
        "message": "Dynamic import from user-controlled input enables arbitrary module loading; validate against an allowlist",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_030",
        "pattern": r"functools\.lru_cache\s*\((?:maxsize\s*=\s*None|[^)]*)\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\(self",
        "message": "lru_cache on methods holds strong reference to self, preventing garbage collection; use weakref or per-instance cache",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_031",
        "pattern": r"Object\.assign\s*\(\s*(?:target|\w+)\s*,\s*(?:req\.body|req\.query|req\.params|input|data)",
        "message": "Object.assign from untrusted input enables prototype pollution; validate and sanitize input properties first",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_032",
        "pattern": r"\w+\[(?:key|prop|name|field|attr)\]\s*=\s*(?:req\.|input\.|data\.|body\.)",
        "message": "Dynamic property assignment from user input enables prototype pollution via __proto__; use Map or validate keys",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_033",
        "pattern": r"JSON\.parse\s*\(\s*(?:req\.body|request\.body|input|data)",
        "message": "Parsing untrusted JSON without schema validation can cause prototype pollution via __proto__ keys; use a schema validator",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_034",
        "pattern": r"(?:while|for)\s*\(.*\)\s*\{[^}]*(?:crypto\.pbkdf2Sync|crypto\.scryptSync|fs\.readFileSync)",
        "message": "Synchronous crypto or file I/O in a loop blocks the event loop for all concurrent requests; use async variants",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_035",
        "pattern": r"(?:Array|new\s+Array)\s*\(\s*\d{7,}\s*\)",
        "message": "Allocating arrays with millions of elements blocks the event loop and risks heap exhaustion; use streams or chunked processing",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_036",
        "pattern": r"new\s+WeakRef\s*\(\s*(?:\{|\[|new\s+(?:Object|Array))",
        "message": "WeakRef to an inline-created object is immediately eligible for GC; store a strong reference first",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_037",
        "pattern": r"new\s+FinalizationRegistry\s*\([^)]*\)(?!.*unregister)",
        "message": "FinalizationRegistry without unregister logic can cause callbacks on already-cleaned-up resources",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_038",
        "pattern": r"new\s+SharedArrayBuffer\s*\([^)]*\)(?!.*Atomics)",
        "message": "SharedArrayBuffer without Atomics operations causes data races between workers; use Atomics for synchronization",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_039",
        "pattern": r"Atomics\.wait\s*\(",
        "message": "Atomics.wait blocks the calling thread; never use on the main thread as it freezes the UI or event loop",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_040",
        "pattern": r'''process\.on\s*\(\s*['\"]uncaughtException['\"].*\)\s*(?:=>|function)\s*(?:\(\w*\))?\s*\{?\s*(?:\}|console\.log)''',
        "message": "Catching uncaughtException without exiting leaves process in undefined state; log and exit with process.exit(1)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_041",
        "pattern": r"setInterval\s*\(\s*(?:async\s+)?(?:\(\s*\)|function)\s*(?:=>)?\s*\{[^}]*await",
        "message": "Async callback in setInterval can stack overlapping executions if one takes longer than the interval; use recursive setTimeout",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_042",
        "pattern": r"new\s+Promise\s*\(\s*(?:async\s+)?(?:\(\s*resolve\s*,?\s*reject?\s*\))?\s*(?:=>)?\s*\{[^}]*new\s+Promise",
        "message": "Nested Promise constructors indicate a misunderstanding of promise chaining; flatten with async/await or .then chains",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_043",
        "pattern": r'''eval\s*\(\s*(?:`|['\"].*\$\{)''',
        "message": "eval with template literals or string interpolation enables code injection; use Function constructor or a parser",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_044",
        "pattern": r"new\s+Function\s*\(\s*(?:req\.|input|data|body|query)",
        "message": "Dynamic Function constructor from user input is equivalent to eval and enables code injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_046",
        "pattern": r'''innerHTML\s*=\s*(?:`|['\"].*\$\{|.*\+\s*\w+)''',
        "message": "Setting innerHTML with dynamic content enables XSS; use textContent or a sanitization library",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_047",
        "pattern": r"(?:window|globalThis|global)\.\w+\s*=\s*",
        "message": "Polluting global scope creates naming collisions and untraceable dependencies; use modules or closures",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_048",
        "pattern": r"\.then\s*\(\s*\)\s*\.catch\s*\(\s*\)",
        "message": "Empty .then() and .catch() silently swallow both results and errors; handle or propagate explicitly",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_049",
        "pattern": r"Proxy\.revocable\s*\([^)]*\)(?!.*revoke)",
        "message": "Creating revocable Proxy without storing or using the revoke function defeats its purpose; capture and call revoke",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_050",
        "pattern": r"structuredClone\s*\(\s*\w+\s*\)\s*(?:;|\n)(?!.*catch|try)",
        "message": "structuredClone throws on non-cloneable values like functions or DOM nodes; wrap in try/catch",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_051",
        "pattern": r"as\s+any\b",
        "message": "Casting to any disables type checking and hides bugs that surface at runtime; use a specific type or unknown",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_053",
        "pattern": r"(?:interface|type)\s+\w+\s*\{[^}]*\[key:\s*string\]\s*:\s*any",
        "message": "Index signature with any value type defeats TypeScript's type safety; use a specific type or unknown",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_054",
        "pattern": r"!\s*(?:\.|\[)",
        "message": "Non-null assertion operator (!) masks potential null/undefined bugs; use optional chaining or explicit null checks",
        "severity": Severity.WARN,
        "file_types": [".ts", ".tsx"],
    },
    {
        "id": "r2a_055",
        "pattern": r"require\s*\(\s*(?:req\.|input|data|process\.argv)",
        "message": "Dynamic require from user-controlled input enables arbitrary module loading; validate against an allowlist",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_056",
        "pattern": r"Buffer\.from\s*\(\s*\w+\s*\)(?!.*encoding)",
        "message": "Buffer.from without encoding defaults to UTF-8 which silently corrupts binary data; specify the encoding explicitly",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_057",
        "pattern": r"new\s+RegExp\s*\(\s*(?:req\.|input|data|query|body)",
        "message": "Dynamic RegExp from user input enables ReDoS attacks; validate input length and complexity or use a static pattern",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_058",
        "pattern": r"Array\.prototype\.\w+\s*=",
        "message": "Modifying Array prototype affects all arrays globally and breaks third-party code; use utility functions or subclassing",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_059",
        "pattern": r'''\.postMessage\s*\(\s*\w+\s*,\s*['\"]?\*['\"]?\s*\)''',
        "message": "postMessage with wildcard origin exposes data to any window; specify the exact target origin",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_060",
        "pattern": r"Worker\s*\(\s*(?:new\s+)?(?:URL|Blob)\s*\(.*(?:input|data|req\.|body)",
        "message": "Creating Web Worker from user-controlled input enables arbitrary code execution in worker context",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_061",
        "pattern": r"for\s+\w+\s+in\s+\w+:\s*\n\s+.*\.query\s*\(",
        "message": "Query inside a loop creates N+1 query problem; use a single bulk query with IN clause or eager loading",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_062",
        "pattern": r"\.forEach\s*\(\s*(?:async\s+)?.*=>\s*\{[^}]*(?:await\s+)?(?:db|prisma|knex|sequelize)\.\w+\.\w+",
        "message": "Database query inside forEach creates N+1 problem; use bulk fetch or include/eager loading",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_063",
        "pattern": r"for\s+.*range\s*\{[^}]*(?:db\.Query|db\.Exec|tx\.Query)",
        "message": "Database query inside a Go loop creates N+1 problem; use a single query with IN clause",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_064",
        "pattern": r"(?:SELECT|select)\s+\*\s+(?:FROM|from)\s+\w+(?!\s+(?:WHERE|where|LIMIT|limit))",
        "message": "SELECT * without WHERE or LIMIT fetches entire table into memory; specify columns and add filtering",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_065",
        "pattern": r"(?:CREATE\s+TABLE|create\s+table)(?!.*(?:INDEX|index|PRIMARY\s+KEY|primary\s+key))",
        "message": "Table created without any index or primary key; define at least a primary key for query performance",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_066",
        "pattern": r"pool_size\s*=\s*(?:[5-9]\d{2,}|\d{4,})",
        "message": "Connection pool size over 500 exhausts database server connections; use smaller pools with proper queuing",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_067",
        "pattern": r"(?:create_engine|connect)\s*\([^)]*\)(?!.*pool)",
        "message": "Database connection without connection pooling creates a new connection per request; configure pool_size and max_overflow",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_068",
        "pattern": r"SET\s+TRANSACTION\s+ISOLATION\s+LEVEL\s+READ\s+UNCOMMITTED",
        "message": "READ UNCOMMITTED allows dirty reads of uncommitted data; use READ COMMITTED or higher for data integrity",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_069",
        "pattern": r"(?:LOCK\s+TABLE|lock\s+table)\s+\w+\s+(?:IN\s+)?(?:EXCLUSIVE|ACCESS\s+EXCLUSIVE)",
        "message": "Exclusive table lock blocks all concurrent access; use row-level locking or advisory locks instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_070",
        "pattern": r"autocommit\s*=\s*True",
        "message": "Autocommit mode makes each statement its own transaction; multi-step operations lose atomicity guarantees",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_071",
        "pattern": r'''\.raw\s*\(\s*f['\"]|\.raw\s*\(\s*['\"].*%s.*['\"].*%|\.raw\s*\(\s*['\"].*\{''',
        "message": "Raw SQL query with string interpolation enables SQL injection; use parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_072",
        "pattern": r'''\.execute\s*\(\s*f['\"]|\.execute\s*\(\s*['\"].*\+\s*\w+|\.execute\s*\(\s*['\"].*%\s*\(''',
        "message": "SQL execute with string formatting enables injection; use parameterized queries with placeholders",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_073",
        "pattern": r'''(?:lazy|LazyLoad|lazy_load)\s*[=:]\s*(?:true|True|['\"]select['\"])''',
        "message": "Lazy loading triggers individual queries on attribute access causing N+1; use eager loading for known access patterns",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_074",
        "pattern": r'''(?:LIKE|like)\s+['\"]%.*%['\"]''',
        "message": "Leading wildcard in LIKE query prevents index usage and causes full table scan; use full-text search index",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_075",
        "pattern": r"(?:DELETE\s+FROM|delete\s+from)\s+\w+\s*(?:;|\n)(?!\s*(?:WHERE|where))",
        "message": "DELETE without WHERE clause removes all rows from the table; add a WHERE clause or use TRUNCATE intentionally",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_076",
        "pattern": r"(?:UPDATE|update)\s+\w+\s+(?:SET|set)\s+.*(?:;|\n)(?!\s*(?:WHERE|where))",
        "message": "UPDATE without WHERE clause modifies all rows in the table; add a WHERE clause to target specific rows",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_077",
        "pattern": r"(?:DROP\s+TABLE|drop\s+table)(?!\s+IF\s+EXISTS)",
        "message": "DROP TABLE without IF EXISTS fails if table does not exist; use IF EXISTS for idempotent migrations",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_078",
        "pattern": r"(?:ALTER\s+TABLE|alter\s+table)\s+\w+\s+(?:ADD|add)\s+\w+.*(?:NOT\s+NULL)(?!.*DEFAULT)",
        "message": "Adding NOT NULL column without DEFAULT fails on existing rows; provide a DEFAULT value or make nullable first",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_079",
        "pattern": r"\.cursor\s*\(\s*\)(?!.*close|__enter__|with\s)",
        "message": "Database cursor opened without context manager or explicit close leaks connections; use with statement",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_080",
        "pattern": r"(?:BEGIN|begin)\s*(?:;|\n)(?:.*\n){20,}(?:COMMIT|commit)",
        "message": "Long-running transaction over 20+ statements holds locks excessively; split into smaller transactions",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_081",
        "pattern": r"(?:ORDER\s+BY|order\s+by)\s+(?:RAND|RANDOM|NEWID)\s*\(\s*\)",
        "message": "ORDER BY RANDOM performs full table scan and sort; use alternative random selection strategies for large tables",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_082",
        "pattern": r"(?:OFFSET|offset)\s+\d{4,}",
        "message": "Large OFFSET values cause database to scan and discard rows; use cursor-based pagination (keyset pagination) instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_083",
        "pattern": r"(?:VARCHAR|varchar)\s*\(\s*(?:MAX|max|65535|4294967295)\s*\)",
        "message": "VARCHAR(MAX) prevents inline storage and index creation; use a reasonable max length based on domain constraints",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_084",
        "pattern": r"(?:FLOAT|float|DOUBLE|double)\s+.*(?:price|amount|balance|currency|money|cost)",
        "message": "Floating-point type for monetary values causes rounding errors; use DECIMAL/NUMERIC with explicit precision",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_085",
        "pattern": r"\.save\s*\(\s*\)\s*\n.*\.save\s*\(\s*\)(?!.*transaction|atomic)",
        "message": "Multiple ORM save calls without transaction wrapper lose atomicity; wrap in a transaction block",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_086",
        "pattern": r"(?:SELECT|select).*(?:COUNT|count)\s*\(\s*\*\s*\)\s*(?:FROM|from)\s+\w+\s*(?:;|\n)(?!\s*(?:WHERE|where))",
        "message": "COUNT(*) without WHERE on large tables is slow; use approximate counts or cached counters",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_087",
        "pattern": r"(?:GRANT|grant)\s+ALL\s+(?:PRIVILEGES\s+)?(?:ON|on)\s+\*\.\*",
        "message": "Granting ALL PRIVILEGES on all databases violates least privilege; grant specific permissions on specific databases",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_088",
        "pattern": r"connection_timeout\s*[=:]\s*(?:0|None|null|undefined)",
        "message": "Zero or no connection timeout causes indefinite hangs when database is unreachable; set a reasonable timeout",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_089",
        "pattern": r"(?:INSERT|insert)\s+(?:INTO|into)\s+\w+.*(?:VALUES|values)\s*\((?:.*\n){100,}",
        "message": "Massive single INSERT statement can exceed max packet size and lock the table; use batch inserts with COPY or bulk API",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_090",
        "pattern": r"\.createIndex\s*\(\s*\{[^}]*\}\s*,\s*\{[^}]*unique\s*:\s*false[^}]*\}.*\n.*\.createIndex",
        "message": "Multiple non-unique indexes on the same collection inflate storage and slow writes; consolidate compound indexes",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_091",
        "pattern": r"(?:log|logger|logging|console)\.\w+\s*\(.*(?:password|passwd|credit_card|ssn|social_security)\s*=(?!.*(?:mask|redact|\*+|hash))",
        "message": "Logging sensitive data (passwords, SSN) violates privacy regulations and creates breach risk; redact PII before logging",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_092",
        "pattern": r"(?:log|logger|logging|console)\.\w+\s*\(.*(?:email|phone|address|date_of_birth|dob|ip_address)\s*[=:]",
        "message": "Logging PII (email, phone, address) may violate GDPR/CCPA; hash or mask PII in log output",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_093",
        "pattern": r'''(?:log|logger)\.\w+\s*\(\s*f?['\"].*\{.*(?:req|request)\.(?:body|form|data|json)''',
        "message": "Logging entire request body may contain PII or sensitive data; log only specific safe fields",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_094",
        "pattern": r"(?:log|logger|console)\.\w+\s*\(\s*(?:req|request)\.\w+\s*\)",
        "message": "Logging raw user input enables log injection via newline characters; sanitize input or use structured logging",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_095",
        "pattern": r'''console\.log\s*\(\s*(?:['\"](?:Error|error|ERROR)|err|error)''',
        "message": "Using console.log for errors loses severity metadata; use console.error or a structured logging library",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_096",
        "pattern": r"(?:log|logger)\.\w+\s*\(.*\)(?!.*(?:request_id|correlation_id|trace_id|span_id|x-request-id))",
        "message": "Log statement without correlation ID makes distributed tracing impossible; include request_id or trace_id",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_097",
        "pattern": r"(?:log|logger)\.debug\s*\(.*(?:for\s+\w+\s+in|forEach|\.map\s*\()",
        "message": "Debug logging inside a loop generates excessive log volume and I/O overhead; log summary outside the loop",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_098",
        "pattern": r"(?:labels|tags|dimensions)\s*[=:]\s*\{[^}]*(?:user_id|email|ip|session_id|url|path)",
        "message": "High-cardinality metric labels (user_id, email, URL) cause metric storage explosion; use bounded label values",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_099",
        "pattern": r"(?:Histogram|Summary|Counter|Gauge)\s*\([^)]*\)\s*\.labels\s*\(\s*(?:request|req)\.",
        "message": "Using request-specific values as metric labels creates unbounded cardinality; aggregate to fixed categories",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_100",
        "pattern": r'''(?:log_level|LOG_LEVEL|level)\s*[=:]\s*['\"]?(?:DEBUG|debug|TRACE|trace)''',
        "message": "Debug/trace log level in production generates excessive I/O and may expose sensitive data; use INFO or higher",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_101",
        "pattern": r"except\s+\w+.*:\s*\n\s+(?:log|logger)\.\w+\s*\([^)]*\)\s*\n\s+raise\b",
        "message": "Logging and re-raising the same exception creates duplicate log entries up the call stack; log at the handler or re-raise, not both",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_102",
        "pattern": r'''(?:log|logger|console)\.\w+\s*\(\s*['\"].*['\"](?:\s*\+|\s*,)\s*(?:err|error|exception)\.(?:stack|stackTrace|message)''',
        "message": "Logging only error message or stack separately loses structured context; log the full error object with structured fields",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_103",
        "pattern": r"(?:Sentry|sentry|bugsnag|rollbar)\.\w+\s*\(.*\)\s*\n\s*(?:log|logger|console)\.\w+\s*\(",
        "message": "Sending to error tracker and logging the same error creates duplicate noise; use one or the other with proper integration",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_104",
        "pattern": r'''(?:log|logger)\.\w+\s*\(\s*['\"]Starting|Entering|Begin''',
        "message": "Entry/exit log messages without timing data are noise; use structured spans or middleware-level timing instead",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_105",
        "pattern": r"(?:opentelemetry|otel).*Span\s*\([^)]*\)(?!.*(?:set_attribute|add_event|set_status))",
        "message": "Creating tracing spans without attributes or events provides no diagnostic value; add relevant attributes",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_106",
        "pattern": r'''(?:meter|metrics)\.\w+\s*\(\s*['\"][^'\"]*['\"](?:\s*\)|\s*,\s*\{?\s*\}?\s*\))(?!.*(?:description|unit))''',
        "message": "Metrics without description or unit make dashboards uninterpretable; always specify unit and description",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_107",
        "pattern": r"(?:setTimeout|setInterval)\s*\(\s*(?:\(\)|function\s*\(\))\s*(?:=>)?\s*\{[^}]*(?:log|logger|console)\.\w+",
        "message": "Periodic logging from timers creates noise and can mask timer leak; use metrics counters for recurring measurements",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_108",
        "pattern": r"\.catch\s*\(\s*(?:\(\s*(?:err|error|e)\s*\))?\s*(?:=>)?\s*\{?\s*(?:console\.log|void)\s*\}?\s*\)",
        "message": "Swallowing errors with console.log in catch loses error context; use proper error handler or structured logging",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_109",
        "pattern": r'''(?:log|logger)\.\w+\s*\(\s*['\"].*['\"](?:\s*%\s*\(|\s*\.format\s*\()''',
        "message": "String formatting in log calls evaluates even when log level is disabled; use lazy formatting with log parameters",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_110",
        "pattern": r"(?:health|healthz|readyz|livez)\s*.*(?:log|logger|console)\.\w+",
        "message": "Logging every health check response floods logs at high frequency; log only failures or use a separate transport",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_111",
        "pattern": r"(?:sampling|sample_rate|sampleRate)\s*[=:]\s*(?:1\.0|1(?:\.0+)?|100)\b",
        "message": "100% trace sampling rate in production generates massive data volume and cost; use adaptive or probabilistic sampling",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_112",
        "pattern": r"(?:log|logger)\.\w+\s*\(.*(?:\\n|\\r|%0a|%0d)",
        "message": "Literal newline sequences in log output enable log injection and forgery; sanitize or use structured logging format",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_113",
        "pattern": r'''(?:FileHandler|RotatingFileHandler|file_handler)\s*\([^)]*(?:mode\s*=\s*['\"]a['\"])?[^)]*\)(?!.*maxBytes|rotation)''',
        "message": "File logging without rotation fills disk space; configure RotatingFileHandler with maxBytes and backupCount",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_114",
        "pattern": r"(?:console|process\.stdout|process\.stderr)\.(?:log|write)\s*\(\s*JSON\.stringify\s*\(\s*\w+\s*,\s*null\s*,\s*[24]",
        "message": "Pretty-printed JSON logs waste bandwidth and break log parsers; use compact JSON (no indentation) in production",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_115",
        "pattern": r'''(?:Counter|Gauge|Histogram|Summary)\s*\(\s*['\"][^'\"]*['\"].*\).*\n.*(?:Counter|Gauge|Histogram|Summary)\s*\(\s*['\"][^'\"]*['\"]''',
        "message": "Re-registering Prometheus metrics with the same name causes CollectorRegistry errors; define metrics at module level",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_116",
        "pattern": r"(?:alert|alarm|page|notify)\s*\(.*(?:==\s*0|<\s*1|!=\s*200)",
        "message": "Alerting on single-point thresholds causes flapping; use averaging windows or burn rate alerts instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_117",
        "pattern": r"\.setLevel\s*\(\s*logging\.(?:WARNING|ERROR|CRITICAL)\s*\)\s*\n.*\.addHandler\s*\(\s*logging\.StreamHandler",
        "message": "Setting high log level on root logger suppresses library warnings; configure per-logger levels instead",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_118",
        "pattern": r"(?:log|logger)\.\w+\s*\(.*(?:repr|str)\s*\(\s*(?:response|res|result)\s*\)",
        "message": "Logging entire response objects can expose headers, cookies, and auth tokens; log specific safe fields only",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_119",
        "pattern": r"try\s*\{[^}]*\}\s*catch\s*\(\s*\w+\s*\)\s*\{\s*\}",
        "message": "Empty catch block silently swallows errors making debugging impossible; log the error or rethrow",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_120",
        "pattern": r"except\s+Exception\s*(?:as\s+\w+)?:\s*\n\s+pass",
        "message": "Bare except-pass silently swallows all exceptions including KeyboardInterrupt; handle or log specific exceptions",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_121",
        "pattern": r"(?:retry|retries|max_retries)\s*[=:]\s*(?:[5-9]|\d{2,})",
        "message": "Retry count above 4 without backoff creates retry storms that amplify outages; use exponential backoff with jitter",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_122",
        "pattern": r"(?:retry|retries).*(?:delay|wait|sleep)\s*[=:]\s*(?:0|1)\b(?!.*(?:exponential|backoff|jitter))",
        "message": "Fixed short retry delay amplifies thundering herd during outages; implement exponential backoff with jitter",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_123",
        "pattern": r"(?:httpx|requests|axios|http\.Client)\.\w+\s*\([^)]*\)\s*$(?!.*(?:timeout|circuit|breaker))",
        "message": "HTTP call to external service without timeout or circuit breaker risks cascading failure; add timeout and circuit breaker",
        "severity": Severity.INFO,
        "file_types": [".py", ".js", ".ts", ".go", ".java", ".rb"],
    },
    {
        "id": "r2a_124",
        "pattern": r"(?:grpc|gRPC)\.\w+\s*\([^)]*\)(?!.*(?:deadline|timeout))",
        "message": "gRPC call without deadline propagation causes unbounded resource consumption on server failures",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_125",
        "pattern": r"(?:saga|compensat|rollback).*(?:TODO|FIXME|not\s+implemented)",
        "message": "Incomplete saga compensation logic leaves distributed state inconsistent on partial failure; implement all compensating actions",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_126",
        "pattern": r"(?:kafka|rabbit|amqp|sqs|pubsub)\.\w*(?:publish|send|produce)\s*\([^)]*\)(?!.*(?:retry|dead.?letter|dlq))",
        "message": "Message publish without dead letter queue configuration loses messages on processing failure; configure DLQ",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_127",
        "pattern": r"(?:kafka|rabbit|amqp|sqs)\.\w*(?:consume|subscribe|receive).*(?:auto.?ack|auto.?commit)\s*[=:]\s*(?:true|True)",
        "message": "Auto-acknowledge before processing completes loses messages on crash; use manual acknowledgment after processing",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_128",
        "pattern": r'''(?:service|api|endpoint)\s*[=:]\s*['\"](?:http|https)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)''',
        "message": "Hardcoded localhost service URL fails in containerized and multi-host deployments; use service discovery or config",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_129",
        "pattern": r"(?:X-Forwarded-For|x-forwarded-for|X-Real-IP|x-real-ip).*(?:trust|allow|accept)\s*[=:]\s*(?:true|True|\*)",
        "message": "Blindly trusting X-Forwarded-For header enables IP spoofing; validate against known proxy IPs",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_130",
        "pattern": r"(?:idempotency|idempotent)\s*[=:]\s*(?:false|False|0)",
        "message": "Disabling idempotency on mutation endpoints causes duplicate processing on retries; implement idempotency keys",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_131",
        "pattern": r"(?:bulkhead|semaphore|concurrency.?limit)\s*[=:]\s*(?:\d{4,}|unlimited|0)",
        "message": "Missing or excessive concurrency limit allows single downstream to exhaust all threads; configure bulkhead pattern",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_132",
        "pattern": r"(?:dns|resolve|lookup).*(?:cache|ttl)\s*[=:]\s*(?:0|false|False|disabled)",
        "message": "Disabled DNS caching causes DNS lookup on every request adding latency and DNS server load; enable reasonable TTL",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_133",
        "pattern": r'''(?:api.?version)\s*[=:]\s*['\"](?:latest|current|default)['\"]''',
        "message": "Using 'latest' API version in service calls breaks when provider updates; pin to a specific version",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_134",
        "pattern": r"(?:distributed|redis|memcache).*lock\s*\([^)]*\)(?!.*(?:ttl|expire|timeout))",
        "message": "Distributed lock without TTL causes permanent deadlock if holder crashes; always set expiration",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_135",
        "pattern": r"(?:rate.?limit|throttle|limiter)\s*[=:]\s*(?:\d{5,}|unlimited|0|false)",
        "message": "Missing or extremely high rate limit exposes service to abuse and resource exhaustion; set reasonable limits",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_136",
        "pattern": r"(?:readiness|liveness)(?:Probe|_probe|Check|_check).*(?:return\s+(?:true|True|ok|200))",
        "message": "Health probe that always returns OK defeats its purpose; check actual dependencies (DB, cache, downstream)",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_137",
        "pattern": r"(?:graceful|shutdown|SIGTERM|SIGINT).*(?:process\.exit\s*\(\s*0?\s*\)|os\._exit|sys\.exit\s*\(\s*0?\s*\))",
        "message": "Immediate exit on shutdown signal drops in-flight requests; drain connections and finish processing first",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_138",
        "pattern": r"(?:istio|envoy|linkerd|nginx).*(?:mtls|mTLS|mutual.?tls)\s*[=:]\s*(?:false|False|disabled|DISABLE|PERMISSIVE)",
        "message": "Disabling mTLS in service mesh allows unencrypted traffic between services; enforce STRICT mode",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_139",
        "pattern": r"(?:queue|topic|channel)\.(?:publish|send|produce)\s*\([^)]*\)(?!.*(?:correlation.?id|message.?id|trace.?id))",
        "message": "Publishing messages without correlation ID breaks distributed tracing; include correlation ID in message headers",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_140",
        "pattern": r"(?:cache|redis|memcached)\.(?:set|put)\s*\([^)]*\)(?!.*(?:ttl|expire|ex=|EX|px=))",
        "message": "Cache entry without TTL grows unboundedly and causes memory exhaustion; always set expiration",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_141",
        "pattern": r"(?:sync|synchronous)\s*(?:call|request|invoke).*(?:within|inside|from)\s*(?:async|event.?loop|handler)",
        "message": "Synchronous blocking call inside async handler blocks the event loop for all concurrent requests",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_142",
        "pattern": r"(?:fanout|broadcast|notify.?all|publish.?all)\s*\([^)]*\)(?!.*(?:batch|chunk|throttle|limit))",
        "message": "Unbounded fanout without throttling creates message storms during high load; implement backpressure",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_143",
        "pattern": r'''(?:service|api).*(?:url|endpoint|host)\s*[=:]\s*['\"].*['\"](?!.*(?:env|config|settings|os\.getenv))''',
        "message": "Hardcoded service URL prevents environment-specific configuration; use environment variables or config service",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_144",
        "pattern": r"(?:two.?phase|2pc|xa.?transaction|distributed.?transaction)\s*",
        "message": "Two-phase commit across services creates tight coupling and availability issues; use saga pattern with compensating actions",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_145",
        "pattern": r"(?:shared|common|central)\s*(?:database|db|schema)\s*.*(?:service|microservice)",
        "message": "Shared database between microservices creates tight coupling; each service should own its data store",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_146",
        "pattern": r"(?:jwt|token|auth).*(?:verify|validate)\s*[=:]\s*(?:false|False|skip|none|disabled)",
        "message": "Disabling JWT verification in service-to-service communication allows unauthorized access; always verify tokens",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_147",
        "pattern": r'''(?:load.?balance|lb|proxy).*(?:strategy|algorithm)\s*[=:]\s*['\"]?(?:random|round.?robin)['\"]?(?!.*(?:health|weight))''',
        "message": "Round-robin load balancing ignores server health and capacity; use least-connections or weighted algorithms with health checks",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_148",
        "pattern": r"(?:openapi|swagger).*(?:security)\s*:\s*\[\s*\]",
        "message": "Empty security array in OpenAPI spec means the endpoint has no authentication; add appropriate security scheme",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_149",
        "pattern": r"(?:network.?policy|NetworkPolicy).*(?:ingress|egress)\s*:\s*\[\s*\]",
        "message": "Empty ingress/egress rules in NetworkPolicy allow all traffic; define explicit allow rules",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_150",
        "pattern": r"(?:sidecar|proxy).*(?:resource|limit|request)\s*:\s*\{\s*\}",
        "message": "Sidecar proxy without resource limits can consume unbounded CPU/memory and starve the application container",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_151",
        "pattern": r'''(?:secrets|credentials|password|api_key|token)\s*[=:]\s*['\"][^$\{'\"]''',
        "message": "Hardcoded secret in CI/CD configuration; use secret management (GitHub Secrets, Vault) with variable references",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_152",
        "pattern": r"uses:\s*\w+/\w+@(?:master|main|latest|v\d+)\b(?!\.\d+\.\d+)",
        "message": "Unpinned GitHub Action uses mutable tag vulnerable to supply chain attacks; pin to a full SHA hash",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_153",
        "pattern": r"runs-on:\s*self-hosted",
        "message": "Self-hosted runners on public repos enable arbitrary code execution by forked PRs; use environment protection rules",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_154",
        "pattern": r"pull_request_target:.*\n(?:.*\n){0,10}.*(?:checkout|actions/checkout).*ref:\s*\$\{\{\s*github\.event\.pull_request\.head",
        "message": "Checking out PR head in pull_request_target runs untrusted code with write permissions; use pull_request event instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_155",
        "pattern": r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)\.(?:body|title)\s*\}\}",
        "message": "Interpolating user-controlled event data in workflow enables command injection; use environment variable intermediary",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_156",
        "pattern": r"permissions:\s*\n\s+(?:contents|packages|id-token|actions|security-events):\s*write",
        "message": "Excessive workflow permissions violate least privilege; request only the minimum permissions needed",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_157",
        "pattern": r'''(?:artifact|upload-artifact|cache).*(?:path|key)\s*[=:]\s*['\"]?(?:\.\*|/|\*\*)''',
        "message": "Uploading entire workspace or root as artifact may include secrets and build cache; specify explicit paths",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_158",
        "pattern": r"(?:download-artifact|cache/restore).*\n(?:.*\n){0,5}.*(?:bash|sh|run|exec)\s*.*\$\{\{",
        "message": "Executing content from downloaded artifacts without verification enables artifact poisoning; hash-verify first",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_159",
        "pattern": r'''(?:npm|pip|gem|cargo|go)\s+(?:publish|push|upload).*(?:--token|--api-key)\s+['\"]?[A-Za-z0-9]''',
        "message": "Package publish with inline token exposes credentials in CI logs; use masked secret variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_160",
        "pattern": r"(?:docker|podman)\s+(?:build|push).*(?:--build-arg)\s+(?:\w*(?:SECRET|KEY|TOKEN|PASSWORD)\w*)\s*=",
        "message": "Passing secrets as Docker build-arg embeds them in image layers; use BuildKit --secret mount instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_161",
        "pattern": r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|sudo)",
        "message": "Piping downloaded scripts to shell executes unverified code; download, verify checksum, then execute",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_162",
        "pattern": r"^FROM\s+\w+/?\w+(?::\s*latest|\s+(?!.*@sha256:))",
        "message": "Docker image without SHA256 digest is mutable and vulnerable to tag poisoning; pin with @sha256 digest",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_163",
        "pattern": r"(?:ADD|COPY)\s+.*\s+/(?!.*--chown)",
        "message": "COPY/ADD without --chown runs files as root by default; specify --chown for non-root ownership",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_164",
        "pattern": r"USER\s+root\s*$",
        "message": "Container running as root enables privilege escalation if compromised; use a non-root USER",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_165",
        "pattern": r"(?:GITHUB_TOKEN|GH_TOKEN|ACTIONS_RUNTIME_TOKEN)\s*[=:]\s*\$\{\{",
        "message": "Exposing GITHUB_TOKEN to all steps enables token extraction; limit token scope to specific steps",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_166",
        "pattern": r"(?:if|condition).*(?:always|success|failure)\s*\(\s*\).*(?:deploy|publish|release|push)",
        "message": "Deploying on always() condition deploys even on failed tests; use success() as condition for deployment steps",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_167",
        "pattern": r"(?:cache|actions/cache).*key:\s*\$\{\{.*runner\.os\s*\}\}(?!.*hashFiles)",
        "message": "Cache key without hashFiles allows stale cache poisoning; include hashFiles of lockfile in cache key",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_168",
        "pattern": r'''(?:cron|schedule):\s*['\"]?(?:\*\s+){4}\*''',
        "message": "Cron schedule running every minute wastes runner resources and may hit rate limits; use appropriate interval",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_169",
        "pattern": r"(?:terraform|tf)\s+(?:apply|destroy).*(?:-auto-approve|--auto-approve)",
        "message": "Auto-approve on terraform apply/destroy skips plan review; require manual approval in production pipelines",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_170",
        "pattern": r"(?:TERRAFORM_STATE|tfstate).*(?:s3|gcs|azurerm).*(?:encrypt|encryption)\s*[=:]\s*(?:false|False)",
        "message": "Unencrypted Terraform state may contain secrets; enable encryption at rest for state backend",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_171",
        "pattern": r'''(?:aws_access_key|aws_secret|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?[A-Z0-9]''',
        "message": "AWS credentials hardcoded in CI config; use IAM roles, OIDC federation, or secret manager",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_172",
        "pattern": r"(?:privileged|--privileged)\s*[=:]\s*(?:true|True)",
        "message": "Privileged container has full host access; remove privileged mode and use specific capabilities instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_173",
        "pattern": r"(?:securityContext|security_context).*(?:allowPrivilegeEscalation|allow_privilege_escalation)\s*:\s*true",
        "message": "Allowing privilege escalation in container enables root access from non-root; set allowPrivilegeEscalation: false",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_174",
        "pattern": r"(?:hostNetwork|host_network)\s*:\s*true",
        "message": "hostNetwork shares the host network namespace; pods can sniff all host traffic and bind to privileged ports",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_175",
        "pattern": r"(?:hostPID|host_pid|hostIPC|host_ipc)\s*:\s*true",
        "message": "hostPID/hostIPC shares host process or IPC namespace; container can inspect or signal host processes",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_176",
        "pattern": r'''(?:WebSocket|ws|wss)\s*\(\s*['\"][^'\"]+['\"]\s*\)(?!.*(?:auth|token|header|cookie|ticket))''',
        "message": "WebSocket connection without authentication handshake allows unauthorized access; verify auth in upgrade request",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_177",
        "pattern": r"(?:on\.?message|onmessage|message.*handler).*\{[^}]*(?:JSON\.parse|json\.loads)\s*\([^)]*\)(?!.*(?:try|catch|except|schema|validate))",
        "message": "Parsing WebSocket message without validation or error handling crashes on malformed input; validate message schema",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_178",
        "pattern": r"(?:maxPayload|max.?message.?size|max.?frame.?size|maxMessageSize)\s*[=:]\s*(?:0|null|None|undefined|Infinity|-1)",
        "message": "No WebSocket message size limit allows memory exhaustion via large messages; set a reasonable maximum (e.g., 1MB)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_179",
        "pattern": r"(?:broadcast|emit|send.?all|publish)\s*\([^)]*\)(?!.*(?:filter|room|channel|permission|auth|exclude))",
        "message": "Broadcasting WebSocket messages without room or permission filtering leaks data to unauthorized clients",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_180",
        "pattern": r"(?:ws|socket|websocket)\.(?:send|write|emit)\s*\([^)]*(?:user|account|profile|private|internal)",
        "message": "Sending user-specific data over WebSocket without verifying recipient authorization; check permissions per message",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_181",
        "pattern": r"(?:ws|socket|websocket).*(?:rate.?limit|throttle)\s*[=:]\s*(?:0|false|False|disabled|none|None)",
        "message": "WebSocket without rate limiting allows message flooding and resource exhaustion; implement per-client rate limits",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_182",
        "pattern": r'''(?:ws|socket|websocket)\.on\s*\(\s*['\"](?:close|disconnect|error)['\"].*\)\s*(?:=>)?\s*\{?\s*\}?''',
        "message": "Empty WebSocket close/error handler leaks resources; clean up subscriptions, timers, and state on disconnect",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_183",
        "pattern": r'''(?:ws|socket)\.on\s*\(\s*['\"]message['\"].*(?:exec|spawn|system|eval|Function)\s*\(''',
        "message": "Executing system commands from WebSocket messages enables remote code execution; validate and sandbox all operations",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_184",
        "pattern": r"(?:ping|pong|heartbeat).*(?:interval|timeout)\s*[=:]\s*(?:0|false|False|disabled)",
        "message": "Disabled WebSocket heartbeat fails to detect dead connections; enable ping/pong with reasonable interval",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_185",
        "pattern": r"(?:socket|ws).*(?:reconnect|retry).*(?:max|limit)\s*[=:]\s*(?:Infinity|-1|0|unlimited)",
        "message": "Unlimited WebSocket reconnection attempts during outage create thundering herd; use exponential backoff with max retries",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_186",
        "pattern": r'''(?:io|socketio|socket\.io)\s*\(\s*['\"][^'\"]*['\"](?:\s*,\s*\{[^}]*)?(?!\s*(?:cors|origin))''',
        "message": "Socket.IO server without CORS configuration accepts connections from any origin; configure allowed origins",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_187",
        "pattern": r'''(?:ws|wss|websocket).*(?:origin|Origin)\s*[=:]\s*['\"]?\*['\"]?''',
        "message": "Wildcard WebSocket origin allows cross-site WebSocket hijacking; restrict to specific trusted origins",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_188",
        "pattern": r"(?:sse|server.?sent.?event|EventSource)\s*\([^)]*\)(?!.*(?:auth|token|withCredentials))",
        "message": "Server-Sent Events without authentication exposes real-time data stream; require auth token or credentials",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_189",
        "pattern": r"(?:channel|room|topic)\.(?:join|subscribe)\s*\([^)]*\)(?!.*(?:auth|permission|check|verify|guard))",
        "message": "Channel subscription without authorization check allows access to restricted real-time data; verify permissions on join",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_190",
        "pattern": r'''(?:ws|socket|websocket).*(?:protocol|subprotocol)\s*[=:]\s*['\"]?(?:raw|binary|custom)['\"]?(?!.*(?:validate|verify|check))''',
        "message": "Custom WebSocket subprotocol without validation allows protocol confusion attacks; validate negotiated protocol",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_191",
        "pattern": r"(?:presence|online|status).*(?:broadcast|emit|send)\s*\([^)]*(?:user|member|client)",
        "message": "Broadcasting presence information without privacy controls exposes user online status to unauthorized viewers",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_192",
        "pattern": r"(?:ws|socket)\.(?:send|write|emit)\s*\(\s*JSON\.stringify\s*\(\s*(?:err|error|exception)",
        "message": "Sending raw error objects over WebSocket exposes internal stack traces and system paths to clients; sanitize errors",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_194",
        "pattern": r"(?:maxConnections|max.?clients|max.?sockets)\s*[=:]\s*(?:\d{6,}|Infinity|unlimited|0)",
        "message": "Unlimited WebSocket connections enables connection exhaustion DoS; set a per-server and per-IP connection limit",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_195",
        "pattern": r"(?:ws|socket).*(?:compress|permessage-deflate|perMessageDeflate)\s*[=:]\s*(?:true|True|\{)",
        "message": "WebSocket compression enables BREACH-like attacks on encrypted connections; disable for sensitive data or use per-message masking",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_196",
        "pattern": r'''(?:pubsub|pub.?sub|channel).*(?:pattern|glob)\s*[=:]\s*['\"]?\*['\"]?''',
        "message": "Wildcard pattern subscription receives all messages including internal channels; subscribe to specific channels",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_197",
        "pattern": r"(?:socket|ws)\.(?:rooms|channels|subscriptions)(?!.*(?:limit|max|cap))",
        "message": "Unlimited room/channel subscriptions per client enables resource exhaustion; cap subscriptions per connection",
        "severity": Severity.INFO,
    },
    {
        "id": "r2a_198",
        "pattern": r"(?:binary|arraybuffer|blob)\s*.*(?:ws|socket|websocket)\.(?:send|write)(?!.*(?:validate|check|verify|limit|size))",
        "message": "Sending binary data over WebSocket without size validation risks memory exhaustion; validate payload size",
        "severity": Severity.WARN,
    },
    {
        "id": "r2a_199",
        "pattern": r"(?:socket|ws|websocket).*(?:admin|management|control|debug)\s*[=:]\s*(?:true|True|enabled)",
        "message": "WebSocket admin/debug interface exposed without additional authentication; require elevated credentials or disable in production",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2a_200",
        "pattern": r"(?:stale|idle|inactive).*(?:timeout|ttl)\s*[=:]\s*(?:0|false|False|disabled|none|None|-1)",
        "message": "Disabled idle timeout for WebSocket connections keeps dead connections open indefinitely; set reasonable idle timeout",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_001",
        "pattern": r"Await\.result\s*\(",
        "message": "Blocking Await.result defeats async execution model and can cause thread starvation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_002",
        "pattern": r"\.onComplete\s*\{\s*case\s+Success",
        "message": "Future.onComplete with pattern match often drops Failure case silently",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_003",
        "pattern": r"import\s+scala\.concurrent\.ExecutionContext\.Implicits\.global",
        "message": "Global ExecutionContext is unsuitable for blocking I/O - use a dedicated thread pool",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_004",
        "pattern": r"\.asInstanceOf\[",
        "message": "Unsafe cast via asInstanceOf bypasses compile-time type safety and risks ClassCastException",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_005",
        "pattern": r"classOf\[.*\]\.newInstance",
        "message": "Reflective instantiation via classOf.newInstance is deprecated and bypasses constructor safety",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_007",
        "pattern": r"ObjectInputStream\s*\(",
        "message": "Java ObjectInputStream deserialization is a well-known remote code execution vector",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_008",
        "pattern": r"implicit\s+def\s+\w+\s*\(",
        "message": "Implicit conversion methods create hidden type coercions that obscure control flow",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_009",
        "pattern": r"Future\s*\{\s*blocking\s*\{",
        "message": "Future with blocking wrapper still consumes a thread - use a dedicated blocking dispatcher",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_010",
        "pattern": r"\.isInstanceOf\[",
        "message": "Runtime type check via isInstanceOf indicates possible type erasure issue or design flaw",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_011",
        "pattern": r"ActorSystem\s*\(",
        "message": "Creating multiple ActorSystems is resource-intensive - reuse a single system per JVM",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_012",
        "pattern": r"sender\s*!\s*",
        "message": "Using sender() in Future callback captures a stale ActorRef that may point to dead letter",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_013",
        "pattern": r"var\s+\w+\s*:\s*\w+\s*=",
        "message": "Mutable var in actor state without synchronization risks data races",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_014",
        "pattern": r"JavaConversions",
        "message": "scala.collection.JavaConversions is deprecated - use JavaConverters or scala.jdk.CollectionConverters",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_015",
        "pattern": r"\.get\s*\(\s*\)\s*$",
        "message": "Calling .get on Option/Try/Future throws on empty - use getOrElse, fold, or pattern match",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_016",
        "pattern": r"null\s*\)",
        "message": "Passing null explicitly defeats Scala type safety - use Option instead",
        "severity": Severity.WARN,
        "file_types": [".scala", ".sc"],
    },
    {
        "id": "r2b_018",
        "pattern": r"@SerialVersionUID",
        "message": "Explicit SerialVersionUID with Java serialization may indicate use of insecure serialization",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_019",
        "pattern": r"TypeTag|ClassTag|WeakTypeTag",
        "message": "Overuse of TypeTag/ClassTag to work around erasure often signals a design that fights the type system",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_020",
        "pattern": r"\.synchronized\s*\{",
        "message": "Using synchronized blocks in actor-based code mixes concurrency models and risks deadlocks",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_021",
        "pattern": r"Promise\s*\(\s*\)\.future",
        "message": "Manually managing Promise/Future pairs is error-prone - prefer Future combinators",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_022",
        "pattern": r"\.result\s*\(\s*Duration\.Inf",
        "message": "Awaiting with Duration.Inf can hang indefinitely - always set a finite timeout",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_023",
        "pattern": r"@unchecked",
        "message": "The @unchecked annotation suppresses exhaustiveness warnings, hiding potential MatchError at runtime",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_024",
        "pattern": r"sys\.process\._",
        "message": "scala.sys.process executes shell commands - ensure inputs are sanitized to prevent injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_025",
        "pattern": r"XMLInputFactory\.newInstance",
        "message": "Default XMLInputFactory is vulnerable to XXE - disable external entities explicitly",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_026",
        "pattern": r"\.foreach\s*\{[^}]*Future",
        "message": "Launching Futures inside foreach without backpressure can overwhelm the thread pool",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_027",
        "pattern": r"throw\s+new\s+\w*Exception",
        "message": "Throwing exceptions in Scala breaks referential transparency - use Either or Try instead",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_028",
        "pattern": r"Serializable\b",
        "message": "Java Serializable interface enables insecure deserialization attacks - prefer JSON or protobuf",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_029",
        "pattern": r"implicit\s+class\s+\w+.*AnyVal",
        "message": "Implicit value class can cause unexpected boxing in certain contexts due to erasure",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_030",
        "pattern": r"\.head\b",
        "message": "Calling .head on a collection throws NoSuchElementException if empty - use .headOption",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_031",
        "pattern": r'\"SELECT\s.*\+\s*\w+',
        "message": "SQL query built via string concatenation is vulnerable to SQL injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_032",
        "pattern": r'\$\"SELECT\s.*\{',
        "message": "SQL query in interpolated string is vulnerable to SQL injection - use parameterized queries",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_034",
        "pattern": r"NetDataContractSerializer",
        "message": "NetDataContractSerializer allows type injection during deserialization",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_035",
        "pattern": r"\[IgnoreAntiforgeryToken\]",
        "message": "Disabling antiforgery token validation exposes the endpoint to CSRF attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_036",
        "pattern": r"\[ValidateAntiForgeryToken\]\s*$",
        "message": "ValidateAntiForgeryToken on GET requests is unnecessary and may mask missing protection on POST",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_037",
        "pattern": r"MarkupString\s*\(",
        "message": "Blazor MarkupString renders raw HTML without sanitization, enabling XSS",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_038",
        "pattern": r"@Html\.Raw\s*\(",
        "message": "Html.Raw outputs unencoded HTML, creating XSS vulnerability if input is user-controlled",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_039",
        "pattern": r"\[AllowAnonymous\]",
        "message": "AllowAnonymous bypasses authentication - verify this endpoint truly requires no auth",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_040",
        "pattern": r"\.UseCors\s*\(\s*policy\s*=>\s*policy\.AllowAnyOrigin",
        "message": "CORS policy allowing any origin exposes API to cross-origin abuse",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_041",
        "pattern": r"SoapFormatter",
        "message": "SoapFormatter is vulnerable to deserialization attacks - use modern serializers",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_042",
        "pattern": r"TypeNameHandling\s*=\s*TypeNameHandling\.\s*(All|Auto|Objects|Arrays)",
        "message": "Json.NET TypeNameHandling enables type injection attacks - use None or explicit binder",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_043",
        "pattern": r'Process\.Start\s*\(\s*\"(cmd|bash|sh|powershell)',
        "message": "Spawning shell process with user input enables command injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_045",
        "pattern": r'\.ExecuteSqlRaw\s*\(\s*\$\"',
        "message": "EF Core ExecuteSqlRaw with interpolation is SQL injection - use ExecuteSqlInterpolated",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_046",
        "pattern": r"SignalR.*\[AllowAnonymous\]",
        "message": "Unauthenticated SignalR hubs allow unauthorized real-time message injection",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_047",
        "pattern": r"Hub\s*:\s*Hub\b(?!.*\[Authorize\])",
        "message": "SignalR Hub without Authorize attribute may be accessible without authentication",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_048",
        "pattern": r"\.Result\b",
        "message": "Accessing Task.Result synchronously causes deadlocks in ASP.NET - use await instead",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_049",
        "pattern": r"\.GetAwaiter\(\)\.GetResult\(\)",
        "message": "GetAwaiter().GetResult() blocks the calling thread and risks deadlock - use await",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_050",
        "pattern": r"MD5\.Create\s*\(\s*\)",
        "message": "MD5 is cryptographically broken - use SHA-256 or better for security-sensitive hashing",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_051",
        "pattern": r"SHA1\.Create\s*\(\s*\)",
        "message": "SHA-1 is deprecated for security use - use SHA-256 or SHA-512",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_053",
        "pattern": r"DllImport\s*\(",
        "message": "P/Invoke via DllImport can execute arbitrary native code - validate library source",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_054",
        "pattern": r"Assembly\.Load\s*\(",
        "message": "Dynamic assembly loading can execute untrusted code - validate assembly source and integrity",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_055",
        "pattern": r"Regex\s*\([^,)]+\)\s*(?!.*RegexOptions\.Compiled)",
        "message": "Non-compiled Regex in hot path causes repeated parsing overhead - use RegexOptions.Compiled",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_056",
        "pattern": r"catch\s*\(\s*Exception\s+\w+\s*\)\s*\{?\s*(return|\/\/)",
        "message": "Catching base Exception and swallowing it hides bugs - catch specific exceptions",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_057",
        "pattern": r"\.AddMvc\s*\(\s*\)(?!.*\.AddJsonOptions)",
        "message": "Default MVC JSON settings may expose internal types - configure serialization explicitly",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_058",
        "pattern": r"new\s+HttpClient\s*\(\s*\)",
        "message": "Creating HttpClient per request exhausts socket connections - use IHttpClientFactory",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_059",
        "pattern": r"LosFormatter",
        "message": "LosFormatter is vulnerable to deserialization attacks - use secure alternatives",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_060",
        "pattern": r"ViewBag\.\w+\s*=.*Request\[",
        "message": "Passing unsanitized request data through ViewBag enables XSS in Razor views",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_061",
        "pattern": r'''\$\w+[^\"']''',
        "message": "Unquoted variable expansion is subject to word splitting and glob expansion attacks",
        "severity": Severity.WARN,
        "file_types": [".sh", ".bash", ".zsh", ".ksh"],
    },
    {
        "id": "r2b_062",
        "pattern": r'eval\s+\"\$',
        "message": "eval with variable input enables arbitrary command execution - avoid eval entirely",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_063",
        "pattern": r"eval\s+\$",
        "message": "eval with unquoted variable is a command injection vector",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_064",
        "pattern": r"if\s+\[\s+-e\s+.*\]\s*;\s*then\s*\n\s*(rm|mv|cp|cat)\s+",
        "message": "TOCTOU race condition - file state may change between test and use",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_065",
        "pattern": r"mktemp\s+/tmp/\w+",
        "message": "Predictable temp file path enables symlink attacks - use mktemp with template (XXXXXX)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_066",
        "pattern": r">\s*/tmp/[a-zA-Z0-9_]+\b",
        "message": "Writing to predictable temp file path is vulnerable to symlink race - use mktemp",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_067",
        "pattern": r"PATH\s*=\s*[^$]",
        "message": "Overwriting PATH without preserving existing value may break command resolution",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_068",
        "pattern": r"export\s+PATH\s*=\s*\.\s*:",
        "message": "Adding current directory to PATH enables trojan binary execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_069",
        "pattern": r"chmod\s+777\s+",
        "message": "chmod 777 grants world read/write/execute - use minimal permissions",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_070",
        "pattern": r"chmod\s+666\s+",
        "message": "chmod 666 grants world read/write - use 644 or more restrictive",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_071",
        "pattern": r"curl\s+.*\|\s*(bash|sh|zsh)",
        "message": "Piping curl output to shell executes unverified remote code",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_072",
        "pattern": r"wget\s+.*\|\s*(bash|sh|zsh)",
        "message": "Piping wget output to shell executes unverified remote code",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_073",
        "pattern": r'''trap\s+['\"]?\s*['\"]?\s+(EXIT|ERR|INT)''',
        "message": "Empty signal trap silently discards signals - handle or log the signal",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_074",
        "pattern": r"kill\s+-9\s+",
        "message": "SIGKILL prevents graceful cleanup - send SIGTERM first and wait before escalating",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_075",
        "pattern": r"rm\s+-rf\s+/\s",
        "message": "rm -rf / can destroy the entire filesystem - this must never appear in scripts",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh", ".yml", ".yaml"],
        "skip_comments": True,
    },
    {
        "id": "r2b_076",
        "pattern": r"rm\s+-rf\s+\$\{?\w+\}?/",
        "message": "rm -rf with variable path can delete unintended directories if variable is empty",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_077",
        "pattern": r"source\s+/dev/stdin",
        "message": "Sourcing from stdin executes arbitrary piped input in current shell context",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_078",
        "pattern": r"\bsudo\s+su\b",
        "message": "sudo su opens an unrestricted root shell - use sudo with specific commands",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_079",
        "pattern": r">\s*/dev/null\s+2>&1",
        "message": "Redirecting all output to /dev/null silences errors that may need investigation",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_080",
        "pattern": r"\[\s+.*\s+==\s+.*\s+\]",
        "message": "Single-bracket test with == is not POSIX - use = for portability or [[ for bash",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_081",
        "pattern": r"echo\s+\$\w+\s*\|",
        "message": "Piping unquoted echo variable leaks data via glob expansion - quote the variable",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_082",
        "pattern": r"for\s+\w+\s+in\s+\$\(ls\s+",
        "message": "Parsing ls output in for loop breaks on filenames with spaces - use glob or find",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_083",
        "pattern": r"read\s+-r?\s+\w+\s*<\s*/dev/urandom",
        "message": "Reading /dev/urandom into a shell variable can include null bytes - use head -c or od",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_084",
        "pattern": r"export\s+\w+=.*password",
        "message": "Exporting passwords as environment variables exposes them in /proc and process listings",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_085",
        "pattern": r"alias\s+(rm|mv|cp)\s*=",
        "message": "Aliasing core utilities changes expected behavior and breaks scripts that depend on them",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_086",
        "pattern": r"\bdd\s+.*of=/dev/[sh]d",
        "message": "dd writing to raw disk device can destroy partition tables - verify target carefully",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_087",
        "pattern": r"nohup\s+.*&\s*$",
        "message": "nohup background process without output redirect may write to nohup.out unexpectedly",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_088",
        "pattern": r"chown\s+-R\s+\w+:\w+\s+/\s*$",
        "message": "Recursive chown on root directory changes ownership of entire filesystem",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_089",
        "pattern": r"IFS\s*=\s*$",
        "message": "Clearing IFS without restoring it breaks word splitting for the rest of the script",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_090",
        "pattern": r";\s*do\s*\n\s*:\s*\n\s*done",
        "message": "Infinite loop with no-op body (busy wait) wastes CPU - use sleep or proper wait mechanism",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_091",
        "pattern": r'''on(click|load|error|mouseover|focus|blur|submit|change|input|keydown|keyup|keypress)\s*=\s*[\"']''',
        "message": "Inline event handlers enable XSS and bypass Content Security Policy",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_092",
        "pattern": r'''href\s*=\s*[\"']javascript:''',
        "message": "javascript: URLs in href enable XSS - use proper event listeners",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_093",
        "pattern": r'''src\s*=\s*[\"']javascript:''',
        "message": "javascript: URL in src attribute enables script injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_094",
        "pattern": r"<iframe\s+(?!.*sandbox)",
        "message": "iframe without sandbox attribute allows embedded content full access to parent page",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_095",
        "pattern": r"<iframe\s+(?!.*X-Frame-Options)",
        "message": "Embeddable pages without X-Frame-Options header are vulnerable to clickjacking",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_096",
        "pattern": r"<form\s+(?!.*action\s*=)",
        "message": "Form without explicit action attribute may submit to an attacker-controlled URL via base tag",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_097",
        "pattern": r"<base\s+href\s*=",
        "message": "HTML base tag changes all relative URLs and can redirect form submissions and script loads",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_098",
        "pattern": r'''<meta\s+http-equiv\s*=\s*[\"']refresh[\"']''',
        "message": "Meta refresh can redirect users to malicious sites without consent",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_099",
        "pattern": r'''<input\s+(?!.*autocomplete\s*=\s*[\"']off)''',
        "message": "Sensitive input fields without autocomplete=off may be cached by browsers",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_100",
        "pattern": r'''<form[^>]*action\s*=\s*[\"']http://''',
        "message": "Form action using HTTP instead of HTTPS transmits data in cleartext",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_101",
        "pattern": r'''style\s*=\s*[\"'][^\"']*expression\s*\(''',
        "message": "CSS expression() in inline styles enables script execution in older IE",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_102",
        "pattern": r'''style\s*=\s*[\"'][^\"']*url\s*\(\s*[\"']?javascript:''',
        "message": "CSS url(javascript:) in style attribute enables XSS",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_103",
        "pattern": r"-moz-binding\s*:",
        "message": "CSS -moz-binding allows XBL injection for script execution in Firefox",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_104",
        "pattern": r"behavior\s*:\s*url\s*\(",
        "message": "CSS behavior property allows HTC attachment for script execution in IE",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_105",
        "pattern": r'''@import\s+url\s*\(\s*[\"']?http://''',
        "message": "CSS @import over HTTP is vulnerable to MITM injection of malicious styles",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_106",
        "pattern": r'''<script\s+src\s*=\s*[\"']http://''',
        "message": "Loading scripts over HTTP enables man-in-the-middle code injection",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_107",
        "pattern": r'''<link\s+rel\s*=\s*[\"']stylesheet[\"']\s+href\s*=\s*[\"']http://''',
        "message": "Loading stylesheets over HTTP enables MITM CSS injection",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_108",
        "pattern": r"innerHTML\s*=",
        "message": "Direct innerHTML assignment with unsanitized input creates XSS vulnerability",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_110",
        "pattern": r"outerHTML\s*=",
        "message": "Setting outerHTML with user input enables XSS - sanitize before assignment",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_111",
        "pattern": r"insertAdjacentHTML\s*\(",
        "message": "insertAdjacentHTML with unsanitized input creates XSS - use textContent or sanitize",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_112",
        "pattern": r"<script[^>]*>(?!.*nonce=)",
        "message": "Inline script without CSP nonce may be blocked or indicates missing Content Security Policy",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_113",
        "pattern": r'''target\s*=\s*[\"']_blank[\"'](?!.*rel\s*=\s*[\"'].*noopener)''',
        "message": "Links with target=_blank without rel=noopener allow reverse tabnapping attacks",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_114",
        "pattern": r"<object\s+data\s*=",
        "message": "HTML object tag can embed arbitrary content including Flash and Java applets",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_115",
        "pattern": r"<embed\s+src\s*=",
        "message": "HTML embed tag can load arbitrary plugins and active content",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_116",
        "pattern": r'''sandbox\s*=\s*[\"'][^\"']*allow-scripts[^\"']*allow-same-origin''',
        "message": "iframe sandbox with allow-scripts and allow-same-origin negates sandboxing",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_117",
        "pattern": r"<svg\s+[^>]*onload\s*=",
        "message": "SVG onload handler enables XSS even in image contexts",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_118",
        "pattern": r'''<math\s+[^>]*href\s*=\s*[\"']javascript:''',
        "message": "MathML javascript: URL enables script execution",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_119",
        "pattern": r'''srcdoc\s*=\s*[\"'][^\"']*<script''',
        "message": "iframe srcdoc with inline scripts injects executable content",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_120",
        "pattern": r'''<form[^>]*method\s*=\s*[\"']get[\"'][^>]*>(?=.*password)''',
        "message": "Form with password field using GET method exposes credentials in URL",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_121",
        "pattern": r"<img\s+(?!.*alt\s*=)",
        "message": "Image without alt attribute is inaccessible to screen readers - add descriptive alt text",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_122",
        "pattern": r'''<img\s+[^>]*alt\s*=\s*[\"']\s*[\"']''',
        "message": "Empty alt text on informational image hides content from assistive technology",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_123",
        "pattern": r"<div\s+onclick",
        "message": "Clickable div is not keyboard accessible - use button or anchor element",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_124",
        "pattern": r"<span\s+onclick",
        "message": "Clickable span is not keyboard accessible - use button or anchor element",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_125",
        "pattern": r"<table\s+(?!.*role\s*=)[^>]*>(?!.*<th)",
        "message": "Data table without header cells is inaccessible - use th elements for column/row headers",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_126",
        "pattern": r'''role\s*=\s*[\"']button[\"']\s+(?!.*tabindex)''',
        "message": "Element with role=button but no tabindex is not keyboard focusable",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_127",
        "pattern": r'''aria-hidden\s*=\s*[\"']true[\"'][^>]*tabindex\s*=\s*[\"']0[\"']''',
        "message": "Element is aria-hidden but focusable, creating confusing screen reader behavior",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_128",
        "pattern": r'''<input\s+(?!.*(?:aria-label|id\s*=\s*[\"']\w+[\"'][^>]*<label|aria-labelledby))''',
        "message": "Input without associated label is inaccessible - use label element or aria-label",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_129",
        "pattern": r'''tabindex\s*=\s*[\"'][2-9]\d*[\"']''',
        "message": "Positive tabindex greater than 1 creates unpredictable tab order - use 0 or -1",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_130",
        "pattern": r"user-select\s*:\s*none",
        "message": "Disabling text selection prevents assistive technology users from copying content",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_131",
        "pattern": r"outline\s*:\s*(none|0)\s*;?\s*}",
        "message": "Removing focus outline makes keyboard navigation invisible - provide custom focus styles",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_132",
        "pattern": r"\*:focus\s*\{\s*outline\s*:\s*(none|0)",
        "message": "Global focus outline removal destroys keyboard navigation visibility",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_133",
        "pattern": r"display\s*:\s*none.*aria-live",
        "message": "aria-live region hidden with display:none will not be announced by screen readers",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_134",
        "pattern": r'''<a\s+href\s*=\s*[\"']#[\"']\s*>''',
        "message": "Anchor with href='#' is not a real link - use button for actions or a valid URL for navigation",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_135",
        "pattern": r"font-size\s*:\s*\d+px",
        "message": "Fixed pixel font sizes prevent user scaling - use rem or em for accessible text sizing",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_136",
        "pattern": r"<marquee",
        "message": "Marquee element causes motion sickness for vestibular disorder users and is non-standard",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_137",
        "pattern": r"<blink",
        "message": "Blink element can trigger seizures in photosensitive users and is non-standard",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_138",
        "pattern": r'''aria-label\s*=\s*[\"']\s*[\"']''',
        "message": "Empty aria-label provides no accessible name - add descriptive text or remove",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_139",
        "pattern": r'''role\s*=\s*[\"']presentation[\"'][^>]*aria-''',
        "message": "Element with role=presentation should not have ARIA attributes - they conflict",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_140",
        "pattern": r"<select\s+(?!.*aria-label|.*<label)",
        "message": "Select element without associated label is inaccessible to screen readers",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_141",
        "pattern": r"<video\s+(?!.*track\s)",
        "message": "Video without caption track is inaccessible to deaf and hard-of-hearing users",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_142",
        "pattern": r"<audio\s+autoplay",
        "message": "Autoplaying audio disrupts screen reader users and violates WCAG 1.4.2",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_143",
        "pattern": r"color\s*:\s*red\s*;?\s*}",
        "message": "Using color alone to convey meaning excludes colorblind users",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_144",
        "pattern": r"<h[1-6][^>]*>\s*<a\s",
        "message": "Heading that contains only a link makes navigation confusing",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_145",
        "pattern": r"aria-role\s*=",
        "message": "aria-role is not a valid attribute - use role instead",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_146",
        "pattern": r"<html\s+(?!.*lang\s*=)",
        "message": "HTML element without lang attribute prevents screen readers from using correct pronunciation",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_147",
        "pattern": r"onmouseover\s*=(?!.*onfocus)",
        "message": "Mouse-only event handler without keyboard equivalent excludes non-mouse users",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_148",
        "pattern": r'''placeholder\s*=\s*[\"'][^\"']+[\"']\s*(?!.*(?:label|aria-label))''',
        "message": "Placeholder as sole label disappears on input and is insufficient for accessibility",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_149",
        "pattern": r"max-width\s*:\s*\d+px\s*;\s*overflow\s*:\s*hidden",
        "message": "Fixed max-width with overflow hidden may clip zoomed text, violating WCAG 1.4.10",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_150",
        "pattern": r"<title>\s*</title>",
        "message": "Empty title element provides no page context for screen readers and bookmarks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_151",
        "pattern": r"open\s*\([^)]+\)\s*\.read\s*\(\s*\)",
        "message": "Synchronous file read in potentially async context blocks the event loop",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_152",
        "pattern": r"async\s+def\s+\w+.*\n.*open\s*\(",
        "message": "Synchronous file I/O inside async function blocks the event loop - use aiofiles",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_153",
        "pattern": r"fs\.readFileSync\s*\(",
        "message": "Synchronous file read in Node.js blocks the event loop - use fs.promises or fs.readFile",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_154",
        "pattern": r"fs\.writeFileSync\s*\(",
        "message": "Synchronous file write blocks the event loop - use fs.promises.writeFile",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_155",
        "pattern": r"\.forEach\s*\(\s*async\s",
        "message": "forEach with async callback does not await iterations - use for...of with await",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_156",
        "pattern": r"cache\s*=\s*\{\s*\}",
        "message": "Unbounded in-memory cache object grows without limit - add eviction or use LRU cache",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_157",
        "pattern": r"@lru_cache\s*\(\s*\)",
        "message": "lru_cache without maxsize parameter grows unbounded - specify maxsize explicitly",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_158",
        "pattern": r"for\s+\w+\s+in\s+\w+:\s*\n\s+for\s+\w+\s+in\s+\w+:\s*\n\s+.*\.append",
        "message": "Nested loop with append may indicate O(n^2) complexity - consider set operations or dict lookup",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_159",
        "pattern": r"\bif\s+\w+\s+in\s+\[",
        "message": "Membership test against list literal is O(n) - use a set literal for O(1) lookup",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_161",
        "pattern": r"Array\s*\(\s*\d{6,}\s*\)",
        "message": "Allocating very large array pre-fills with holes and wastes memory - use streaming or chunking",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_162",
        "pattern": r"setInterval\s*\(\s*(?:async\s+)?function",
        "message": "setInterval with async callback can stack overlapping executions - use setTimeout recursion",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_163",
        "pattern": r"addEventListener\s*\([^)]+\)\s*(?!.*removeEventListener)",
        "message": "Event listener added without corresponding removal creates memory leak on component unmount",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_164",
        "pattern": r"new\s+Map\s*\(\s*\)(?!.*\.delete|.*\.clear)",
        "message": "Map that grows without deletion is an unbounded memory leak - add eviction logic",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_165",
        "pattern": r"SELECT\s+\*\s+FROM",
        "message": "SELECT * fetches all columns including unused data - specify only needed columns",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_166",
        "pattern": r"\.toList\s*\(\s*\)\s*\.\s*size",
        "message": "Converting to list just to get size materializes entire collection - use .length or .count",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_167",
        "pattern": r"string\s*\+\s*=.*\+\s*=",
        "message": "Repeated string concatenation in loop creates O(n^2) allocations - use StringBuilder or join",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_168",
        "pattern": r"re\.compile\s*\([^)]+\)\s*$",
        "message": "Regex compiled inside loop or function body recompiles on each call - move to module level",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_169",
        "pattern": r"useEffect\s*\(\s*\(\)\s*=>\s*\{[^}]*fetch\b[^}]*\}\s*\)",
        "message": "useEffect with fetch but no cleanup can cause state updates on unmounted components",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_170",
        "pattern": r"new\s+RegExp\s*\([^)]+\)",
        "message": "Dynamic RegExp construction in hot path recompiles on each call - cache the compiled regex",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_171",
        "pattern": r"\.findAll\s*\(\s*\)\s*\.stream\s*\(\s*\)\s*\.filter",
        "message": "Loading all records then filtering in Java is O(n) memory - push filter to database query",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_172",
        "pattern": r"time\.Sleep\s*\(\s*time\.\w+\s*\*\s*\d+\s*\)",
        "message": "Blocking sleep in goroutine wastes OS thread - use time.After or context with timeout",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_173",
        "pattern": r"append\s*\(\s*\w+\s*,\s*\w+\s*\.\.\.\s*\)",
        "message": "Appending entire slice in loop without pre-allocation causes repeated re-slicing",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_174",
        "pattern": r"sync\.Mutex\s*\{\s*\}[^}]*map\s*\[",
        "message": "Mutex-protected map may be better served by sync.Map for read-heavy workloads",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_175",
        "pattern": r"defer\s+\w+\.Close\s*\(\s*\)\s*\n.*for\s+",
        "message": "Defer close inside loop delays cleanup until function exit - close explicitly in each iteration",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_176",
        "pattern": r'\"(requets|reqeusts|reqests|requsets|requestss|requrest|requst)\"',
        "message": "Possible typosquatting of 'requests' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_177",
        "pattern": r'\"(lodashs|lodahs|loddash|loadash|lodas)\"',
        "message": "Possible typosquatting of 'lodash' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_178",
        "pattern": r'\"(axois|axioss|axos|axio|axxios)\"',
        "message": "Possible typosquatting of 'axios' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_179",
        "pattern": r'\"(colourama|coloramma|colorma|colorsama)\"',
        "message": "Possible typosquatting of 'colorama' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_180",
        "pattern": r'\"(numpys|nummpy|numpi|numppy)\"',
        "message": "Possible typosquatting of 'numpy' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_181",
        "pattern": r'\"preinstall\"\s*:',
        "message": "preinstall script in package.json can execute arbitrary code before install - audit the script",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_182",
        "pattern": r'\"postinstall\"\s*:',
        "message": "postinstall script in package.json executes after install - audit for malicious behavior",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_183",
        "pattern": r'\"preinstall\"\s*:.*curl\s+',
        "message": "preinstall script downloads remote content - high risk of supply chain attack",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_184",
        "pattern": r'\"postinstall\"\s*:.*wget\s+',
        "message": "postinstall script downloads remote content - high risk of supply chain attack",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_185",
        "pattern": r'\"postinstall\"\s*:.*node\s+-e',
        "message": "postinstall running inline Node code is a common supply chain attack vector",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_186",
        "pattern": r"setup\s*\(\s*[^)]*install_requires\s*=.*subprocess",
        "message": "setup.py install_requires with subprocess indicates possible malicious install hook",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_187",
        "pattern": r"setup\.py.*import\s+(os|subprocess|urllib|socket)",
        "message": "setup.py importing system/network modules may execute code during pip install",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_188",
        "pattern": r'\"resolved\"\s*:\s*\"http://(?!localhost)',
        "message": "Lockfile references non-HTTPS registry URL - packages may be tampered in transit",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_189",
        "pattern": r'\"integrity\"\s*:\s*\"sha1-',
        "message": "Lockfile uses weak SHA-1 integrity hash - update lockfile to use SHA-512",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_190",
        "pattern": r'\"resolved\"\s*:\s*\"https://[^/]*(?!registry\.npmjs\.org|registry\.yarnpkg\.com)',
        "message": "Package resolved from non-standard registry - verify registry trustworthiness",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_191",
        "pattern": r"dependency_links\s*=\s*\[",
        "message": "dependency_links in setup.py can pull packages from arbitrary URLs - use standard PyPI",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_192",
        "pattern": r"--index-url\s+http://(?!localhost)",
        "message": "pip install with HTTP index URL exposes packages to MITM attacks - use HTTPS",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_193",
        "pattern": r"--trusted-host\s+",
        "message": "pip --trusted-host disables SSL verification for package downloads",
        "severity": Severity.WARN,
    },
    {
        "id": "r2b_194",
        "pattern": r"npm\s+install\s+--ignore-scripts\s*$",
        "message": "Installing with --ignore-scripts then manually running scripts bypasses npm audit",
        "severity": Severity.INFO,
    },
    {
        "id": "r2b_195",
        "pattern": r'\"(expresss|expres|exress|xpress|epxress)\"',
        "message": "Possible typosquatting of 'express' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_196",
        "pattern": r'\"(djano|djnago|dajngo|djangoo|djanngo)\"',
        "message": "Possible typosquatting of 'django' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_197",
        "pattern": r'\"(flaskk|flaask|falsk|flak|flaski)\"',
        "message": "Possible typosquatting of 'flask' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_198",
        "pattern": r'\"(reactt|reakt|raect|rreact|reacct)\"',
        "message": "Possible typosquatting of 'react' package - verify package name",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_199",
        "pattern": r"pip\s+install\s+--extra-index-url\s+http://",
        "message": "Extra index URL over HTTP enables dependency confusion and MITM attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "r2b_200",
        "pattern": r'\"install\"\s*:.*&&\s*(curl|wget|nc|bash|sh)\s+',
        "message": "Install script chaining network tools with shell execution is a supply chain attack pattern",
        "severity": Severity.BLOCK,
    },
]

# File-type sets for routing
REACT_EXTENSIONS: frozenset[str] = frozenset({".jsx", ".tsx"})

# Maximum function length in lines before triggering a finding
MAX_FUNCTION_LENGTH: int = 40
