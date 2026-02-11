"""Anti-pattern rule definitions for static code analysis."""

from src.models.enums import Severity

# Each rule is a dict with id, pattern (regex), message, severity, and optional special_handler.
# The static analyzer iterates over these and applies each regex to every line.

ANTI_PATTERNS: list[dict[str, str]] = [
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
]

# Maximum function length in lines before triggering a finding
MAX_FUNCTION_LENGTH: int = 40
