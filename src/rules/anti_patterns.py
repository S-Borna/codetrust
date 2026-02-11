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
    # --- WARN severity ---
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
]

# Maximum function length in lines before triggering a finding
MAX_FUNCTION_LENGTH: int = 40
