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
