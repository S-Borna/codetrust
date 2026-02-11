"""Anti-pattern rule definitions for static code analysis."""

from src.models.enums import Severity

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
DEVOPS_EXTENSIONS: set[str] = {".dockerfile", ".toml", ".yml", ".yaml"}

# File-name patterns that are treated as DevOps files regardless of extension.
DEVOPS_FILENAMES: set[str] = {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "procfile"}

ANTI_PATTERNS: list[dict[str, str]] = [
    # ═══════════════════════════════════════════════════════════════
    #  GENERIC RULES (Python / JS / TS / Go / Rust / …)
    # ═══════════════════════════════════════════════════════════════

    # --- BLOCK severity ---
    {
        "id": "heredoc",
        "pattern": r"<<[-']?\w+",
        "message": "Heredoc detected. Use template files or multi-line strings.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "hardcoded_secret",
        "pattern": (
            r'(?i)(api[_-]?key|secret|password|token|credentials)'
            r'\s*[:=]\s*["\'][^"\']{8,}["\']'
        ),
        "message": "Possible hardcoded secret. Use environment variables.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "eval_exec",
        "pattern": r"\b(eval|exec)\s*\(",
        "message": "eval/exec is a security risk. Use safe alternatives.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "sql_injection",
        "pattern": r'(?:execute|executemany|cursor\.execute)\s*\(\s*(?:f["\']|[^)]*\.format\s*\()',
        "message": "Possible SQL injection via string formatting. Use parameterized queries.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "pickle_load",
        "pattern": r"pickle\.loads?\s*\(",
        "message": "pickle.load is unsafe with untrusted data. Use JSON or msgpack.",
        "severity": Severity.BLOCK,
    },

    # ═══════════════════════════════════════════════════════════════
    #  SYMPTOM-FIX DETECTION (Root Cause Enforcement — Law 3)
    #  "Fix the cause, never the symptom"
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "except_swallow",
        "pattern": r"^\s*except[\s:]",
        "message": "Exception caught and silently swallowed (pass/...). Handle the error or re-raise.",
        "severity": Severity.BLOCK,
        "special_handler": "check_except_swallow",
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
        "pattern": r"(?:#\s*noqa\b|#\s*type:\s*ignore|@SuppressWarnings|eslint-disable|pragma:\s*no\s*cover)",
        "message": "Lint/type/coverage warning suppressed. Fix the underlying issue instead.",
        "severity": Severity.WARN,
    },
    {
        "id": "sleep_no_context",
        "pattern": r"(?:time\.)?sleep\s*\(",
        "message": "sleep() without explanation. Why is a delay needed? Document or fix root cause.",
        "severity": Severity.INFO,
        "special_handler": "check_sleep_no_context",
        "skip_comments": True,
    },

    # --- WARN severity (generic) ---
    {
        "id": "todo_hack",
        "pattern": r"(?i)#\s*(todo|hack|fixme|xxx|temp)\b",
        "message": "Temporary marker found. Resolve before committing.",
        "severity": Severity.WARN,
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
    #  ANTI-ASSUMPTION RULES (Law 2: "Assume nothing")
    # ═══════════════════════════════════════════════════════════════

    {
        "id": "debug_mode_enabled",
        "pattern": r"(?i)(?:^|\s)(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|\"true\")\b",
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
    },
    {
        "id": "sql_delete_no_where",
        "pattern": r"(?i)^\s*DELETE\s+FROM\s+\w+\s*;",
        "message": "DELETE without WHERE will remove all rows. Add a WHERE clause.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_update_no_where",
        "pattern": r"(?i)^\s*UPDATE\s+\w+\s+SET\s+(?!.*\bWHERE\b)[^;]*;\s*$",
        "message": "UPDATE without WHERE will modify all rows. Add a WHERE clause.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_drop_no_if_exists",
        "pattern": r"(?i)\bDROP\s+(TABLE|DATABASE|INDEX|VIEW)\s+(?!IF\s+EXISTS\b)\w+",
        "message": "DROP without IF EXISTS may fail. Use DROP … IF EXISTS.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_grant_all",
        "pattern": r"(?i)\bGRANT\s+ALL\b",
        "message": "GRANT ALL gives excessive privileges. Grant only what is needed.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
    },
    {
        "id": "sql_foreign_key_checks_off",
        "pattern": r"(?i)SET\s+FOREIGN_KEY_CHECKS\s*=\s*0",
        "message": "Disabling foreign key checks bypasses referential integrity. Ensure it is re-enabled.",
        "severity": Severity.BLOCK,
        "file_types": [".sql"],
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
    {
        "id": "dockerfile_no_healthcheck",
        "pattern": r"^CMD\s",
        "message": "Dockerfile has CMD but no HEALTHCHECK. Add HEALTHCHECK for container orchestration.",
        "severity": Severity.INFO,
        "special_handler": "check_dockerfile_healthcheck",
        "file_types": [".dockerfile"],
    },
    # --- Dockerfile: running as root ---
    {
        "id": "docker_root_user",
        "pattern": r"^CMD\s",
        "message": "Dockerfile runs as root. Add USER instruction to drop privileges.",
        "severity": Severity.WARN,
        "special_handler": "check_docker_root_user",
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
    {
        "id": "docker_no_workdir",
        "pattern": r"^CMD\s",
        "message": "Dockerfile has no WORKDIR. Set explicit working directory.",
        "severity": Severity.INFO,
        "special_handler": "check_docker_no_workdir",
        "file_types": [".dockerfile"],
    },
    # --- Dockerfile: secrets in ENV/ARG ---
    {
        "id": "docker_env_secret",
        "pattern": r"(?i)^(?:ENV|ARG)\s+\S*(?:password|secret|token|api_key|private_key)",
        "message": "Secret in Dockerfile ENV/ARG. Use runtime secrets or build-time --secret flag.",
        "severity": Severity.BLOCK,
        "file_types": [".dockerfile"],
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
        "pattern": r"(?:alembic|migrate|flask\s+db).*&&.*(?:uvicorn|gunicorn|node|npm\s+start)",
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
        "pattern": r"(?i)(?:api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[:=]\s*[\"']?[^\s\"']{8,}",
        "message": "API key or secret in config file. Use environment variables or secret manager.",
        "severity": Severity.BLOCK,
        "file_types": [".yml", ".yaml", ".toml", ".json"],
        "skip_comments": True,
    },
]

# Maximum function length in lines before triggering a finding
MAX_FUNCTION_LENGTH: int = 40
