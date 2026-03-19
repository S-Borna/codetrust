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
    },
    {
        "id": "hardcoded_secret",
        "pattern": (
            r'(?i)(api[_-]?key|secret[_-]?\w*|password|token|credentials)'
            r'(?:\s*:\s*\w+)?\s*[:=]\s*["\'][^"\']{8,}["\']'
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
    },
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
        "pattern": r"(?:#\s*" + "no" + r"qa\b|#\s*type:\s*ig" + r"nore|@Suppress" + r"Warnings|eslint-dis" + r"able|prag" + r"ma:\s*no\s*cover)",
        "message": "Lint/type/coverage warning suppressed. Fix the underlying issue instead.",
        "severity": Severity.WARN,
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

    # --- Database URL with embedded credentials ---
    {
        "id": "database_url_credentials",
        "pattern": r"(?i)(?:database|db|sql|postgres|mysql|mongo|redis)[_-]?(?:url|uri|dsn)(?:\s*:\s*\w+)?\s*[:=]\s*[\"']?[\w+]+://\w+:\S+@",
        "message": "Database URL contains embedded credentials. Use environment variables for username and password.",
        "severity": Severity.BLOCK,
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
    },
    {
        "id": "k8s_host_network",
        "pattern": r"(?i)hostNetwork:\s*true",
        "message": "hostNetwork: true exposes the host network to the pod. Remove unless required.",
        "severity": Severity.WARN,
        "file_types": [".yml", ".yaml"],
    },
    {
        "id": "k8s_host_pid",
        "pattern": r"(?i)hostPID:\s*true",
        "message": "hostPID: true shares the host PID namespace. Remove unless required for debugging.",
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
    },
    {
        "id": "agent_echo_multiline_redirect",
        "pattern": r"echo\s+-e\s+.*\\n.*>\s*\S+",
        "message": "echo -e with newlines to write files. Use proper file I/O or template files.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "agent_cat_heredoc",
        "pattern": r"cat\s*>\s*\S+\s*" + _HEREDOC,
        "message": "cat with heredoc redirect. Heredocs are prohibited. Use template files.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "agent_subprocess_shell_true",
        "pattern": r"subprocess\.\w+\(.*shell\s*=\s*True",
        "message": "subprocess with shell=True. Use shell=False and pass args as list.",
        "severity": Severity.BLOCK,
    },
    {
        "id": "agent_os_system",
        "pattern": r"\bos\.system\s*\(",
        "message": "os.system is unsafe. Use subprocess.run with shell=False.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "agent_os_popen",
        "pattern": r"\bos\.popen\s*\(",
        "message": "os.popen is unsafe. Use subprocess.run with shell=False.",
        "severity": Severity.BLOCK,
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
    },

    # --- Hallucinated Python imports ---
    {
        "id": "hallucinated_import_nonexistent",
        "pattern": r"^(?:from|import)\s+(?:ai_utils|ml_helpers|deep_learning_tools|auto_ml_pipeline|neural_utils|smart_ai|llm_toolkit|ai_framework|model_utils|auto_train|automl_kit)\b",
        "message": "Import from a commonly hallucinated AI package. This package likely does not exist on PyPI.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
    },
    {
        "id": "hallucinated_import_misspelled",
        "pattern": r"^(?:from|import)\s+(?:requets|requsts|beautifulsoup|sklear|tenserflow|pytorch|numpyy|pands|matplotib|sqlachemy|fasttapi|fask|djano)\b",
        "message": "Misspelled import — AI hallucinated a typo. Check PyPI for the correct package name.",
        "severity": Severity.BLOCK,
        "skip_comments": True,
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
    },
    {
        "id": "ruby_system_exec",
        "pattern": r"\b(?:system|exec|%x|`)\s*[\(\"\']",
        "message": "Shell command execution detected. Use shell-escape or parameterized commands.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
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
    },
    {
        "id": "ruby_hallucinated_gem",
        "pattern": r"^require\s+['\"](?:activrecord|actionspack|railties_utils|ruby_json|string_utils|http_client|easy_http|ruby_async|fast_json)\b",
        "message": "Misspelled or hallucinated gem name. Verify the gem exists on rubygems.org.",
        "severity": Severity.BLOCK,
        "file_types": [".rb"],
        "skip_comments": True,
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
    },
    {
        "id": "php_shell_exec",
        "pattern": r"\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\(",
        "message": "Shell command execution detected. Use escapeshellarg/escapeshellcmd for user input.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
    },
    {
        "id": "php_sql_injection",
        "pattern": r'(?:mysql_query|mysqli_query|->query)\s*\(\s*["\'].*?\$',
        "message": "Possible SQL injection via variable interpolation. Use prepared statements (PDO/mysqli).",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
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
    },
    {
        "id": "php_md5_password",
        "pattern": r"\b(?:md5|sha1)\s*\(\s*\$(?:password|pass|pwd)",
        "message": "Weak hash for passwords. Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
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
    },
    {
        "id": "php_hallucinated_namespace",
        "pattern": r"^use\s+(?:Laravel\\Http|Symfony\\Components|Doctrine\\ORM\\Managers|Illuminate\\Facades|GuzzleHttp\\Requests)\b",
        "message": "Misspelled or hallucinated PHP namespace. Verify the package exists on packagist.org.",
        "severity": Severity.BLOCK,
        "file_types": [".php"],
        "skip_comments": True,
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
    },
    {
        "id": "ps_execution_policy_bypass",
        "pattern": r"(?i)Set-ExecutionPolicy\s+(?:Bypass|Unrestricted)",
        "message": "Setting ExecutionPolicy to Bypass/Unrestricted disables script signing checks.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_plaintext_credential",
        "pattern": r"(?i)(?:ConvertTo-SecureString)\s+.*-AsPlainText",
        "message": "Converting plaintext to SecureString exposes secrets. Use credential prompts or vaults.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
    },
    {
        "id": "ps_hardcoded_password",
        "pattern": r'(?i)(?:\$password|\$secret|\$apikey|\$token)\s*=\s*["\'][^"\']{4,}["\']',
        "message": "Hardcoded credential in PowerShell script. Use SecureString, Key Vault, or environment variables.",
        "severity": Severity.BLOCK,
        "file_types": [".ps1", ".psm1"],
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
    },
    {
        "id": "tf_public_s3_acl",
        "pattern": r'(?i)acl\s*=\s*"(?:public-read|public-read-write)"',
        "message": "S3 bucket with public ACL exposes data. Use bucket policies and block public access settings.",
        "severity": Severity.BLOCK,
        "file_types": [".tf", ".hcl"],
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
    },
    {
        "id": "py_flask_debug_mode",
        "pattern": r"app\.run\s*\([^)]*debug\s*=\s*True",
        "message": "Flask debug=True enables remote code execution via the debugger — disable in production",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_django_debug_true",
        "pattern": r"DEBUG\s*=\s*True",
        "message": "Django DEBUG=True exposes stack traces and settings — must be False in production",
        "severity": Severity.BLOCK,
        "file_types": [".py", ".cfg", ".ini"],
    },
    {
        "id": "py_django_secret_key_hardcoded",
        "pattern": r"SECRET_KEY\s*=\s*['\"][^'\"]{8,}['\"]",
        "message": "Django SECRET_KEY is hardcoded — load from environment variable",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_flask_secret_hardcoded",
        "pattern": r"app\.secret_key\s*=\s*['\"][^'\"]+['\"]",
        "message": "Flask secret_key is hardcoded — load from environment variable",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_jinja2_autoescape_off",
        "pattern": r"Environment\s*\([^)]*autoescape\s*=\s*False",
        "message": "Jinja2 autoescape=False enables XSS — enable autoescape for HTML templates",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_assert_auth",
        "pattern": r"assert\s+.*(auth|permission|role|admin|user)",
        "message": "assert is stripped by Python -O flag — never use assert for authentication checks",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_open_write_path_traversal",
        "pattern": r"open\s*\(\s*(request|user|input|params|args|kwargs)",
        "message": "open() with user-controlled path enables path traversal — validate and sanitize path",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "py_header_injection",
        "pattern": r"response\.headers\s*\[.+\]\s*=\s*(request|user|input)",
        "message": "User-controlled value in response header enables header injection — sanitize value",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },

    # --- JavaScript/TypeScript Injection ---
    {
        "id": "js_child_process_exec",
        "pattern": r"child_process\.exec\s*\(|require\(['\"]child_process['\"]\).*\.exec\s*\(",
        "message": "child_process.exec() is vulnerable to command injection — use execFile() with explicit args",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".mjs", ".cjs"],
    },
    {
        "id": "js_innerhtml_xss",
        "pattern": r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])",
        "message": "innerHTML assignment is vulnerable to XSS — use textContent or DOMPurify.sanitize()",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx", ".html"],
    },
    {
        "id": "js_document_write",
        "pattern": r"document\.write\s*\(",
        "message": "document.write() is vulnerable to XSS and blocks rendering — use DOM manipulation instead",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts", ".jsx", ".tsx", ".html"],
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
    },
    {
        "id": "js_sql_string_concat",
        "pattern": r"(query|execute|rawQuery)\s*\([`'\"].*\$\{|[`'\"].*\+\s*(req|user|params|input)",
        "message": "String concatenation in SQL query enables SQL injection — use parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "js_regex_catastrophic",
        "pattern": r"new\s+RegExp\s*\(\s*(req|user|input|params|query)",
        "message": "User-controlled RegExp enables ReDoS — validate and limit user-provided patterns",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "js_insecure_cookie",
        "pattern": r"(httpOnly|secure)\s*:\s*false",
        "message": "Cookie with httpOnly:false or secure:false exposes session to XSS/MITM — set both to true",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
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
    },
    {
        "id": "secret_stripe_key",
        "pattern": r"(sk|pk)_(test|live)_[A-Za-z0-9]{24,}",
        "message": "Stripe API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_openai_key",
        "pattern": r"sk-[A-Za-z0-9]{48}",
        "message": "OpenAI API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_anthropic_key",
        "pattern": r"sk-ant-[A-Za-z0-9\-]{95,}",
        "message": "Anthropic API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_sendgrid_key",
        "pattern": r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}",
        "message": "SendGrid API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
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
    },
    {
        "id": "secret_slack_token",
        "pattern": r"xox[baprs]-[A-Za-z0-9\-]+",
        "message": "Slack token detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_jwt_hardcoded",
        "pattern": r"jwt\.sign\s*\([^,]+,\s*['\"][^'\"]{8,}['\"]",
        "message": "Hardcoded JWT secret — load signing key from environment variable",
        "severity": Severity.BLOCK,
        "file_types": [".js", ".ts"],
    },
    {
        "id": "secret_private_key_header",
        "pattern": r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        "message": "Private key material in source code — store in secure key management system",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_google_api_key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "message": "Google API key detected — restrict key and load from environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_heroku_api_key",
        "pattern": r"[hH]eroku.*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        "message": "Heroku API key detected — revoke immediately and load from environment variable",
        "severity": Severity.BLOCK,
    },
    {
        "id": "secret_gcp_service_account",
        "pattern": r'"type":\s*"service_account"',
        "message": "GCP service account credentials in source — store in secret manager, never commit",
        "severity": Severity.BLOCK,
        "file_types": [".json"],
    },
    {
        "id": "secret_redis_password",
        "pattern": r"redis://[^@\s]+:[^@\s]+@",
        "message": "Redis URL contains credentials — store in environment variable",
        "severity": Severity.BLOCK,
    },

    # --- Cryptography ---
    {
        "id": "crypto_md5_weak",
        "pattern": r"hashlib\.md5\s*\(|MD5\s*\(|\.md5\s*\(",
        "message": "MD5 is cryptographically broken — use SHA-256 or SHA-3 for security-sensitive hashing",
        "severity": Severity.BLOCK,
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
    },
    {
        "id": "crypto_ecb_mode",
        "pattern": r"\.MODE_ECB\b|AES\.MODE_ECB|mode\s*=\s*['\"]?ECB",
        "message": "ECB mode reveals data patterns — use AES-GCM or AES-CBC with random IV",
        "severity": Severity.BLOCK,
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
    },
    {
        "id": "crypto_hardcoded_iv",
        "pattern": r"iv\s*=\s*b['\"][^'\"]{8,16}['\"]|IV\s*=\s*b['\"][^'\"]+['\"]",
        "message": "Hardcoded IV for encryption — generate a random IV for each encryption operation",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "crypto_ssl_no_verify",
        "pattern": r"verify\s*=\s*False|ssl_verify\s*=\s*False|VERIFY_PEER\s*=\s*False|check_hostname\s*=\s*False",
        "message": "SSL certificate verification disabled — enables MITM attacks",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_ssl_v2_v3",
        "pattern": r"SSLv2|SSLv3|TLSv1_0|TLSv1_1|PROTOCOL_SSLv|ssl\.PROTOCOL_TLS\b",
        "message": "SSLv2/SSLv3/TLS1.0/TLS1.1 are deprecated — use TLS 1.2+ (PROTOCOL_TLS_CLIENT)",
        "severity": Severity.BLOCK,
    },
    {
        "id": "crypto_password_plaintext",
        "pattern": r"password\s*=\s*['\"][^'\"]{4,}['\"]",
        "message": "Plaintext password in source — load from environment variable",
        "severity": Severity.BLOCK,
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
    },
    {
        "id": "crypto_insecure_hash_passwords",
        "pattern": r"hashlib\.(md5|sha1|sha256)\s*\([^)]*password",
        "message": "Plain hash for passwords — use bcrypt, argon2, or scrypt with salt",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
    },
    {
        "id": "crypto_empty_cipher_key",
        "pattern": r"key\s*=\s*b['\"]['\"]|encrypt\s*\([^,]+,\s*b['\"]['\"]",
        "message": "Empty encryption key — key must be cryptographically random and of correct length",
        "severity": Severity.BLOCK,
        "file_types": [".py"],
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
        "file_types": [".py", ".js", ".ts"],
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
    },

    # --- Go Security ---
    {
        "id": "go_fmt_errorf_wrap",
        "pattern": r'fmt\.Sprintf\s*\(\s*".*%s.*err',
        "message": "Use fmt.Errorf with %w to wrap errors for proper unwrapping with errors.As/Is",
        "severity": Severity.WARN,
        "file_types": [".go"],
    },
    {
        "id": "go_sql_injection",
        "pattern": r'db\.(Query|Exec|QueryRow)\s*\(\s*fmt\.(Sprintf|Printf)',
        "message": "SQL query built with fmt.Sprintf is vulnerable to SQL injection — use parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
    },
    {
        "id": "go_os_exec_shell",
        "pattern": r'exec\.Command\s*\(\s*"sh"|exec\.Command\s*\(\s*"bash"|exec\.Command\s*\(\s*"cmd"',
        "message": "exec.Command with shell interpreter — use exec.Command with explicit args to avoid injection",
        "severity": Severity.WARN,
        "file_types": [".go"],
    },
    {
        "id": "go_http_listenandserve_no_tls",
        "pattern": r'http\.ListenAndServe\s*\(',
        "message": "http.ListenAndServe uses plain HTTP — use http.ListenAndServeTLS for production",
        "severity": Severity.WARN,
        "file_types": [".go"],
    },
    {
        "id": "go_tls_insecure_skip",
        "pattern": r"InsecureSkipVerify\s*:\s*true",
        "message": "InsecureSkipVerify:true disables TLS certificate validation — enables MITM attacks",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
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
    },
    {
        "id": "go_hardcoded_creds",
        "pattern": r'(password|secret|token|key)\s*:?=\s*"[^"]{6,}"',
        "message": "Hardcoded credentials in Go source — load from environment or secrets manager",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
    },

    # --- Java Security ---
    {
        "id": "java_sql_injection",
        "pattern": r'(Statement|createStatement)\s*\.\s*(execute|executeQuery|executeUpdate)\s*\(\s*".*\+',
        "message": "SQL string concatenation in Java — use PreparedStatement with parameterized queries",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "java_deserialize_object",
        "pattern": r"ObjectInputStream\s*\(|readObject\s*\(\s*\)",
        "message": "Java deserialization is a critical RCE vector — validate class allow-list before deserializing",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "java_xpath_injection",
        "pattern": r"xpath\.evaluate\s*\(|XPath\.compile\s*\(",
        "message": "XPath with user input enables XPath injection — use parameterized XPath or validate input",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "java_xxe_factory",
        "pattern": r"DocumentBuilderFactory\.newInstance\s*\(\s*\)(?!.*setFeature.*FEATURE_SECURE_PROCESSING)",
        "message": "DocumentBuilderFactory without XXE protection — disable external entity processing",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "java_hardcoded_password",
        "pattern": r'(password|passwd|secret|apikey)\s*=\s*"[^"]{4,}"',
        "message": "Hardcoded password/secret in Java — load from environment or secrets manager",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "java_weak_md5_sha1",
        "pattern": r'MessageDigest\.getInstance\s*\(\s*"(MD5|SHA-1|SHA1)"',
        "message": "MD5/SHA-1 are cryptographically broken — use SHA-256 or stronger",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "java_runtime_exec",
        "pattern": r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
        "message": "Runtime.exec() with string argument is vulnerable to command injection — use ProcessBuilder with list",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
    },
    {
        "id": "java_random_not_secure",
        "pattern": r"\bnew\s+Random\s*\(\s*\)",
        "message": "java.util.Random is not cryptographically secure — use SecureRandom for security tokens",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "java_log_injection",
        "pattern": r"log\.(info|warn|error|debug)\s*\([^)]*\+\s*(request|user|input|param)",
        "message": "User input in log statement enables log injection — sanitize input before logging",
        "severity": Severity.WARN,
        "file_types": [".java"],
    },
    {
        "id": "java_spring_actuator_all",
        "pattern": r"management\.endpoints\.web\.exposure\.include\s*=\s*\*",
        "message": "All Spring Boot Actuator endpoints exposed — restrict to specific endpoints in production",
        "severity": Severity.BLOCK,
        "file_types": [".properties", ".yml", ".yaml"],
    },

    # --- C/C++ Security ---
    {
        "id": "c_gets_unsafe",
        "pattern": r"\bgets\s*\(",
        "message": "gets() has no bounds checking — use fgets() with explicit buffer size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
    },
    {
        "id": "c_strcpy_unsafe",
        "pattern": r"\bstrcpy\s*\(",
        "message": "strcpy() is vulnerable to buffer overflow — use strncpy() or strlcpy() with size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
    },
    {
        "id": "c_sprintf_unsafe",
        "pattern": r"\bsprintf\s*\(",
        "message": "sprintf() is vulnerable to buffer overflow — use snprintf() with buffer size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
    },
    {
        "id": "c_strcat_unsafe",
        "pattern": r"\bstrcat\s*\(",
        "message": "strcat() is vulnerable to buffer overflow — use strncat() with remaining size",
        "severity": Severity.BLOCK,
        "file_types": [".c", ".cpp", ".h", ".hpp"],
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
        "id": "rust_unsafe_block",
        "pattern": r"\bunsafe\s*\{",
        "message": "unsafe block — document invariants that make this safe; minimize scope",
        "severity": Severity.INFO,
        "file_types": [".rs"],
    },
    {
        "id": "rust_unwrap_in_production",
        "pattern": r"\.unwrap\s*\(\s*\)",
        "message": ".unwrap() panics on None/Err — use ? operator, expect() with message, or match for error handling",
        "severity": Severity.WARN,
        "file_types": [".rs"],
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
    },
    {
        "id": "rust_sqlx_raw_query",
        "pattern": r'sqlx::query\s*\(\s*&format!\s*\(',
        "message": "sqlx::query with format! string is SQL injection — use query! macro or bind parameters",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
    },
    {
        "id": "rust_from_utf8_unchecked",
        "pattern": r"from_utf8_unchecked\s*\(",
        "message": "from_utf8_unchecked() causes UB on invalid UTF-8 — use from_utf8() with error handling",
        "severity": Severity.BLOCK,
        "file_types": [".rs"],
    },
    {
        "id": "rust_mem_transmute",
        "pattern": r"std::mem::transmute\s*\(",
        "message": "mem::transmute is extremely unsafe — use safe conversions (as, From/Into, bytemuck) instead",
        "severity": Severity.WARN,
        "file_types": [".rs"],
    },
    {
        "id": "rust_panic_in_lib",
        "pattern": r"\bpanic!\s*\(",
        "message": "panic! in library code — return Result/Option to let callers handle errors",
        "severity": Severity.WARN,
        "file_types": [".rs"],
    },

    # --- Shell Security ---
    {
        "id": "sh_curl_bash_pipe",
        "pattern": r"curl\s+.*\|\s*(bash|sh)\b|wget\s+.*\|\s*(bash|sh)\b",
        "message": "curl|bash pipe executes remote code without verification — download, verify checksum, then execute",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
    },
    {
        "id": "sh_chmod_777",
        "pattern": r"chmod\s+(777|a\+rwx|ugo\+rwx)",
        "message": "chmod 777 grants world-writable permissions — use minimal permissions (e.g., 755 for executables)",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
    },
    {
        "id": "sh_rm_rf_root",
        "pattern": r"rm\s+-[rf]+\s+/[^/\w]|rm\s+-[rf]+\s+\$HOME\s+|rm\s+-[rf]+\s+~\s+",
        "message": "rm -rf targeting root or home directory — add path validation before destructive operations",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
    },
    {
        "id": "sh_unquoted_variable",
        "pattern": r"\$[A-Za-z_][A-Za-z0-9_]*(?!\s*['\"]|[A-Za-z0-9_\(])",
        "message": "Unquoted variable in shell — use \"$VAR\" to prevent word splitting and globbing",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash", ".zsh"],
    },
    {
        "id": "sh_sudo_without_check",
        "pattern": r"\bsudo\s+",
        "message": "sudo usage — ensure script validates it's running with appropriate privileges",
        "severity": Severity.INFO,
        "file_types": [".sh", ".bash", ".zsh"],
    },
    {
        "id": "sh_eval_variable",
        "pattern": r"\beval\s+\$",
        "message": "eval with variable enables code injection — avoid eval; use case statements or arrays",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
    },
    {
        "id": "sh_source_remote",
        "pattern": r"source\s+<\s*\(curl|source\s+<\s*\(wget|\.\s+<\s*\(curl",
        "message": "Sourcing remote content executes untrusted code — download and verify before sourcing",
        "severity": Severity.BLOCK,
        "file_types": [".sh", ".bash", ".zsh"],
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
        "id": "db_select_star",
        "pattern": r"SELECT\s+\*\s+FROM",
        "message": "SELECT * loads all columns — specify required columns for performance and security",
        "severity": Severity.INFO,
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
        "pattern": r"(log|logger|logging)\.(info|debug|warning|error)\s*\(.*\b(password|secret|token|key|credit_card|ssn|cvv)\b",
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
    },
    {
        "id": "go_context_background",
        "pattern": r"context\.Background\(\)",
        "message": "context.Background() in handler code. Use the request context (r.Context()) for proper cancellation.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_sync_mutex_copy",
        "pattern": r"func\s+\w+\([^)]*\bsync\.(?:Mutex|RWMutex)\b[^*]",
        "message": "sync.Mutex passed by value (copied). Pass by pointer (*sync.Mutex) to avoid data races.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_channel_leak",
        "pattern": r"go\s+func\s*\([^)]*\)\s*\{[^}]*<-\s*\w+",
        "message": "Goroutine blocking on channel without select/timeout. Use select with context.Done() or time.After.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_nil_map_write",
        "pattern": r"var\s+\w+\s+map\[",
        "message": "Declared map variable without initialization. Writing to a nil map causes a panic. Use make(map[...]).",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_string_builder",
        "pattern": r"for\s.*\{[^}]*\+\s*=\s*[\"']|for\s.*\{[^}]*=\s*\w+\s*\+\s*[\"']",
        "message": "String concatenation in loop. Use strings.Builder for efficient string building.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
    },
    {
        "id": "go_race_condition",
        "pattern": r"go\s+func\s*\([^)]*\)\s*\{[^}]*\b(?:append|delete)\s*\(",
        "message": "Shared data structure modified in goroutine without synchronization. Use sync.Mutex or channels.",
        "severity": Severity.WARN,
        "file_types": [".go"],
        "skip_comments": True,
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
    },
    {
        "id": "go_log_fatal_handler",
        "pattern": r"(?:func\s+\w*[Hh]andl\w*|ServeHTTP).*\{[^}]*log\.Fatal",
        "message": "log.Fatal in HTTP handler calls os.Exit(1), killing the entire server. Use log.Println and http.Error instead.",
        "severity": Severity.BLOCK,
        "file_types": [".go"],
        "skip_comments": True,
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
    },
    {
        "id": "java_equals_null",
        "pattern": r"\.\s*equals\s*\(\s*null\s*\)",
        "message": ".equals(null) always returns false and can throw NPE. Use '== null' for null checks.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
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
    },
    {
        "id": "java_thread_sleep_sync",
        "pattern": r"synchronized\s*\([^)]*\)\s*\{[^}]*Thread\.sleep\s*\(",
        "message": "Thread.sleep() inside synchronized block holds the lock while sleeping. Release the lock first.",
        "severity": Severity.BLOCK,
        "file_types": [".java"],
        "skip_comments": True,
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
    },
    {
        "id": "swift_force_try",
        "pattern": r"\btry!\s+",
        "message": "try! crashes on error. Use do/catch or try? for safe error handling.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "swift_implicitly_unwrapped",
        "pattern": r"(?:var|let)\s+\w+\s*:\s*\w+!(?:\s*$|\s*=)",
        "message": "Implicitly unwrapped optional as property. Use regular optional (?) and unwrap safely.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "swift_nslog_production",
        "pattern": r"\bNSLog\s*\(",
        "message": "NSLog() is slow and visible in device console. Use os_log or Logger for production logging.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "swift_print_production",
        "pattern": r"^\s*print\s*\(",
        "message": "print() in Swift production code. Use os_log or a structured logging framework.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "swift_hardcoded_url",
        "pattern": r'URL\s*\(\s*string:\s*"https?://[^"]+"\s*\)',
        "message": "Hardcoded URL string. Use a configuration file or environment variable for URLs.",
        "severity": Severity.WARN,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "swift_keychain_no_acl",
        "pattern": r"kSecAttrAccessible.*kSecAttrAccessibleAlways",
        "message": "Keychain item accessible when device is locked. Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
        "skip_comments": True,
    },
    {
        "id": "swift_userdefaults_sensitive",
        "pattern": r'(?i)UserDefaults\.\w+\.set\([^)]*(?:password|token|secret|apiKey|creditCard)',
        "message": "Storing sensitive data in UserDefaults (unencrypted). Use Keychain for secrets.",
        "severity": Severity.BLOCK,
        "file_types": [".swift"],
        "skip_comments": True,
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
]

# File-type sets for routing
REACT_EXTENSIONS: frozenset[str] = frozenset({".jsx", ".tsx"})

# Maximum function length in lines before triggering a finding
MAX_FUNCTION_LENGTH: int = 40
