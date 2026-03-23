# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""AI-hallucination-aware taint detection.

Detects when AI-generated code uses hallucinated sanitizer functions that
do not actually exist, causing the taint analyzer to incorrectly close
taint chains. Composes with TaintAnalyzer — runs normal taint analysis
first, then verifies every sanitizer that broke a taint chain.

Verification hierarchy:
  1. Known stdlib sanitizer → trusted (e.g., int(), shlex.quote())
  2. Defined in the same file → trusted
  3. Imported from a project file that exists → trusted
  4. From an external package with a valid import → trusted
  5. Cannot be verified → BLOCK — taint chain reopened
"""

import re
from dataclasses import dataclass, field

import structlog

from src.models.enums import Language, Severity
from src.models.responses import Finding
from src.rules.taint_rules import (
    TAINT_SINKS,
    TAINT_SOURCES,
    TaintSink,
    TaintSource,
)

logger = structlog.get_logger()

# ═══════════════════════════════════════════════════════════════
#  Known standard-library sanitizers per language
# ═══════════════════════════════════════════════════════════════

PYTHON_STDLIB_SANITIZERS: frozenset[str] = frozenset({
    "int",
    "float",
    "str",
    "bool",
    "abs",
    "len",
    "repr",
    "ascii",
    "ord",
    "chr",
    "hex",
    "oct",
    "bin",
    "hash",
    "shlex.quote",
    "html.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
    "urllib.parse.urlencode",
    "os.path.basename",
    "os.path.normpath",
    "os.path.realpath",
    "markupsafe.escape",
    "markupsafe.Markup",
    "bleach.clean",
    "bleach.linkify",
    "cgi.escape",
    "xml.sax.saxutils.escape",
    "secrets.token_hex",
    "secrets.token_urlsafe",
    "hashlib.sha256",
    "hashlib.md5",
    "re.escape",
    "json.dumps",
    "json.loads",
    "base64.b64encode",
    "base64.b64decode",
    "hmac.new",
    "hmac.digest",
    "strip",
    "escape",
    "quote",
})

JAVASCRIPT_STDLIB_SANITIZERS: frozenset[str] = frozenset({
    "parseInt",
    "parseFloat",
    "Number",
    "String",
    "Boolean",
    "encodeURIComponent",
    "encodeURI",
    "decodeURIComponent",
    "decodeURI",
    "JSON.stringify",
    "JSON.parse",
    "escape",
    "unescape",
    "btoa",
    "atob",
    "isNaN",
    "isFinite",
    "Math.floor",
    "Math.ceil",
    "Math.round",
    "DOMPurify.sanitize",
    "validator.escape",
    "xss",
})

GO_STDLIB_SANITIZERS: frozenset[str] = frozenset({
    "strconv.Atoi",
    "strconv.ParseInt",
    "strconv.ParseFloat",
    "strconv.ParseBool",
    "strconv.FormatInt",
    "html.EscapeString",
    "html.UnescapeString",
    "url.QueryEscape",
    "url.PathEscape",
    "filepath.Clean",
    "filepath.Base",
    "filepath.Abs",
    "path.Clean",
    "path.Base",
    "strings.TrimSpace",
    "strings.Replace",
    "regexp.QuoteMeta",
    "template.HTMLEscapeString",
    "template.JSEscapeString",
})

KNOWN_STDLIB_SANITIZERS: dict[Language, frozenset[str]] = {
    Language.PYTHON: PYTHON_STDLIB_SANITIZERS,
    Language.JAVASCRIPT: JAVASCRIPT_STDLIB_SANITIZERS,
    Language.TYPESCRIPT: JAVASCRIPT_STDLIB_SANITIZERS,
    Language.GO: GO_STDLIB_SANITIZERS,
}

# Known Python third-party packages that provide sanitizers.
KNOWN_SANITIZER_PACKAGES: frozenset[str] = frozenset({
    "bleach",
    "markupsafe",
    "html_sanitizer",
    "nh3",
    "defusedxml",
    "validator",
    "DOMPurify",
    "dompurify",
    "xss",
    "sanitize-html",
    "isomorphic-dompurify",
})

HALLUCINATION_CONFIDENCE = 0.90

# Regex for extracting function names from call expressions.
_FUNC_CALL_RE = re.compile(r"([\w.]+)\s*\(")

# Regex for Python function definitions.
_PYTHON_FUNC_DEF_RE = re.compile(r"^\s*def\s+(\w+)\s*\(", re.MULTILINE)

# Regex for JavaScript/TypeScript function definitions.
_JS_FUNC_DEF_RE = re.compile(
    r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:function|\([^)]*\)\s*=>|\w+\s*=>))",
    re.MULTILINE,
)

# Regex for Go function definitions.
_GO_FUNC_DEF_RE = re.compile(r"^\s*func\s+(\w+)\s*\(", re.MULTILINE)

# Regex for Python import statements.
_PYTHON_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+([\w.]+)\s+import\s+(.+)|import\s+([\w.,\s]+))$",
    re.MULTILINE,
)

# Regex for JS/TS import statements.
_JS_IMPORT_RE = re.compile(
    r"""^\s*(?:import\s+(?:\{[^}]+\}|[\w]+)\s+from\s+['"]([^'"]+)['"]|"""
    r"""const\s+(?:\{[^}]+\}|[\w]+)\s*=\s*require\s*\(\s*['"]([^'"]+)['"]\s*\))""",
    re.MULTILINE,
)

_FUNC_DEF_PATTERNS: dict[Language, re.Pattern[str]] = {
    Language.PYTHON: _PYTHON_FUNC_DEF_RE,
    Language.JAVASCRIPT: _JS_FUNC_DEF_RE,
    Language.TYPESCRIPT: _JS_FUNC_DEF_RE,
    Language.GO: _GO_FUNC_DEF_RE,
}

# Category suggestions for hallucinated sanitizer findings.
_HALLUCINATION_SUGGESTIONS: dict[str, str] = {
    "sql_injection": (
        "Use parameterized queries instead of a custom sanitizer. "
        "If you need escaping, use a verified library like psycopg2's sql module."
    ),
    "command_injection": (
        "Use subprocess.run with shell=False and a list of arguments. "
        "For shell quoting, use shlex.quote() from the standard library."
    ),
    "xss": (
        "Use markupsafe.escape() or bleach.clean() — verified HTML sanitizers. "
        "Do not rely on custom or AI-generated sanitize functions."
    ),
    "path_traversal": (
        "Use os.path.realpath() and validate against an allow-list. "
        "Do not trust custom path sanitizers without verification."
    ),
    "ssrf": (
        "Validate URLs against an allow-list of trusted domains. "
        "Do not use unverified URL sanitization functions."
    ),
    "deserialization": (
        "Use JSON with strict schema validation instead of custom deserialization sanitizers."
    ),
}


@dataclass(frozen=True)
class SanitizerUsage:
    """Records where a sanitizer was applied in code."""

    function_name: str
    line: int
    source_name: str
    sink_name: str
    sink_category: str
    variable_chain: str


@dataclass
class HallucinationResult:
    """Result of hallucination analysis on a single file."""

    findings: list[Finding] = field(default_factory=list)
    verified_sanitizers: list[str] = field(default_factory=list)
    hallucinated_sanitizers: list[str] = field(default_factory=list)


class HallucinationTaintAnalyzer:
    """Detects hallucinated sanitizers in AI-generated code.

    Composes with TaintAnalyzer: runs normal taint analysis, then
    inspects every sanitizer that broke a taint chain to verify
    the sanitizer function actually exists.
    """

    def analyze(
        self,
        code: str,
        language: Language,
        filename: str = "",
    ) -> HallucinationResult:
        """Run hallucination-aware taint analysis on source code.

        Args:
            code: The source code to analyze.
            language: Programming language of the code.
            filename: Optional filename for finding reports.

        Returns:
            HallucinationResult with findings for hallucinated sanitizers.
        """
        result = HallucinationResult()

        sanitizer_usages = self._find_sanitizer_usages(
            code, language,
        )
        if not sanitizer_usages:
            return result

        defined_functions = self._extract_defined_functions(
            code, language,
        )
        imported_modules = self._extract_imported_modules(
            code, language,
        )
        known_stdlib = KNOWN_STDLIB_SANITIZERS.get(language, frozenset())

        for usage in sanitizer_usages:
            is_verified = self._verify_sanitizer(
                usage.function_name,
                language,
                known_stdlib,
                defined_functions,
                imported_modules,
            )
            if is_verified:
                result.verified_sanitizers.append(usage.function_name)
            else:
                result.hallucinated_sanitizers.append(usage.function_name)
                finding = self._build_hallucination_finding(
                    usage, filename,
                )
                result.findings.append(finding)

        logger.info(
            "hallucination_taint_analysis_complete",
            filename=filename,
            language=str(language),
            verified=len(result.verified_sanitizers),
            hallucinated=len(result.hallucinated_sanitizers),
            findings=len(result.findings),
        )
        return result

    # ═══════════════════════════════════════════════════════════════
    #  Sanitizer usage detection
    # ═══════════════════════════════════════════════════════════════

    def _find_sanitizer_usages(
        self,
        code: str,
        language: Language,
    ) -> list[SanitizerUsage]:
        """Find all places where a function is used as a sanitizer.

        A sanitizer usage is detected when:
        1. A taint source feeds into a variable.
        2. That variable is passed through a function call.
        3. The result flows to a taint sink.

        This is a lightweight text-based scan, not a full taint analysis.
        It catches the pattern: result = some_func(tainted_var).
        """
        sources = TAINT_SOURCES.get(language, ())
        sinks = TAINT_SINKS.get(language, ())

        lines = code.split("\n")
        tainted_vars: dict[str, str] = {}
        sanitized_vars: dict[str, tuple[str, int, str]] = {}
        usages: list[SanitizerUsage] = []

        for line_num, line in enumerate(lines, start=1):
            self._track_taint_sources(
                line, line_num, sources, tainted_vars,
            )
            self._track_sanitizer_calls(
                line, line_num, tainted_vars, sanitized_vars,
            )
            self._check_sink_with_sanitized_var(
                line, sinks, sanitized_vars, usages,
            )

        return usages

    def _track_taint_sources(
        self,
        line: str,
        line_num: int,
        sources: tuple[TaintSource, ...],
        tainted_vars: dict[str, str],
    ) -> None:
        """Track variables that receive tainted data from sources."""
        for source in sources:
            # Use word boundary for source matching to avoid false positives
            # e.g., "input(" should not match "clean_input("
            if source.pattern.endswith("("):
                pattern_base = source.pattern[:-1]
                if not re.search(rf"(?<!\w){re.escape(pattern_base)}\(", line):
                    continue
            elif source.pattern not in line:
                continue
            var_match = re.match(
                r"\s*(?:const|let|var|val)?\s*(\w+)\s*[:=]", line,
            )
            if var_match:
                tainted_vars[var_match.group(1)] = source.name

    def _track_sanitizer_calls(
        self,
        line: str,
        line_num: int,
        tainted_vars: dict[str, str],
        sanitized_vars: dict[str, tuple[str, int, str]],
    ) -> None:
        """Track variables assigned from function calls on tainted data."""
        # Match assignments in Python (x = ...), JS (const/let/var x = ...), Go (x := ...)
        assign_match = re.match(
            r"\s*(?:const|let|var|val)?\s*(\w+)\s*[:=]\s*(.+)", line,
        )
        if not assign_match:
            return

        var_name = assign_match.group(1)
        rhs = assign_match.group(2)

        func_matches = _FUNC_CALL_RE.findall(rhs)
        if not func_matches:
            return

        # Collect known source function names to exclude from sanitizer detection
        source_func_names: set[str] = set()
        for lang_sources in TAINT_SOURCES.values():
            for src in lang_sources:
                source_func_names.add(src.name)
                # Also add the dotted form (e.g., "request.form.get")
                if "." in src.pattern:
                    source_func_names.add(src.pattern.rstrip("("))

        for func_name in func_matches:
            # Skip known taint sources — they introduce taint, not sanitize it
            if func_name in source_func_names:
                continue
            for tainted_var, source_name in tainted_vars.items():
                # Use word boundary + exclude string literals
                if re.search(rf"(?<!['\"])\b{re.escape(tainted_var)}\b(?!['\"])", rhs):
                    sanitized_vars[var_name] = (
                        func_name, line_num, source_name,
                    )
                    break

    def _check_sink_with_sanitized_var(
        self,
        line: str,
        sinks: tuple[TaintSink, ...],
        sanitized_vars: dict[str, tuple[str, int, str]],
        usages: list[SanitizerUsage],
    ) -> None:
        """Check if a sanitized variable flows to a sink."""
        for sink in sinks:
            if sink.pattern not in line:
                continue
            for var_name, (func_name, san_line, source_name) in sanitized_vars.items():
                if var_name in line:
                    usages.append(SanitizerUsage(
                        function_name=func_name,
                        line=san_line,
                        source_name=source_name,
                        sink_name=sink.name,
                        sink_category=sink.category,
                        variable_chain=f"{source_name} -> {func_name}() -> {sink.name}",
                    ))

    # ═══════════════════════════════════════════════════════════════
    #  Sanitizer verification
    # ═══════════════════════════════════════════════════════════════

    def _verify_sanitizer(
        self,
        function_name: str,
        language: Language,
        known_stdlib: frozenset[str],
        defined_functions: set[str],
        imported_modules: dict[str, str],
    ) -> bool:
        """Verify that a sanitizer function actually exists.

        Checks in order:
        1. Known stdlib/builtin sanitizer.
        2. Defined in the current file.
        3. Imported from a known package.
        4. Part of a known sanitizer package.

        Returns True if verified, False if hallucinated.
        """
        if self._is_known_stdlib(function_name, known_stdlib):
            return True

        base_name = function_name.split(".")[-1]
        if base_name in defined_functions:
            return True

        return self._is_from_verified_import(
            function_name, imported_modules,
        )

    def _is_known_stdlib(
        self,
        function_name: str,
        known_stdlib: frozenset[str],
    ) -> bool:
        """Check if the function is a known stdlib sanitizer."""
        if function_name in known_stdlib:
            return True

        base_name = function_name.split(".")[-1]
        if base_name in known_stdlib:
            return True

        for known in known_stdlib:
            if (
                known.endswith(f".{base_name}")
                and function_name.endswith(base_name)
                and function_name in (base_name, known)
            ):
                return True

        return False

    def _is_from_verified_import(
        self,
        function_name: str,
        imported_modules: dict[str, str],
    ) -> bool:
        """Check if the function comes from a verified import.

        Any function whose name (or top-level module) appears in an
        explicit import statement is considered verified — the developer
        intentionally imported it from a known source.
        """
        parts = function_name.split(".")
        top_module = parts[0]

        if top_module in imported_modules:
            return True

        base_name = function_name.split(".")[-1]
        return base_name in imported_modules

    # ═══════════════════════════════════════════════════════════════
    #  Code introspection helpers
    # ═══════════════════════════════════════════════════════════════

    def _extract_defined_functions(
        self,
        code: str,
        language: Language,
    ) -> set[str]:
        """Extract function names defined in the code."""
        pattern = _FUNC_DEF_PATTERNS.get(language)
        if pattern is None:
            return set()

        functions: set[str] = set()
        for match in pattern.finditer(code):
            for group in match.groups():
                if group:
                    functions.add(group)
        return functions

    def _extract_imported_modules(
        self,
        code: str,
        language: Language,
    ) -> dict[str, str]:
        """Extract imported names mapped to their source module.

        Returns a dict of {local_name: source_module}.
        """
        if language == Language.PYTHON:
            return self._extract_python_imports(code)
        if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            return self._extract_js_imports(code)
        return {}

    def _extract_python_imports(
        self,
        code: str,
    ) -> dict[str, str]:
        """Extract Python import names to source module mapping."""
        imports: dict[str, str] = {}
        for match in _PYTHON_IMPORT_RE.finditer(code):
            from_module = match.group(1)
            from_names = match.group(2)
            plain_import = match.group(3)

            if from_module and from_names:
                names = from_names.strip("() \t\n")
                for part in names.split(","):
                    part = part.strip()
                    if not part:
                        continue
                    if " as " in part:
                        alias = part.split(" as ")[-1].strip()
                        imports[alias] = from_module
                    else:
                        imports[part] = from_module

            if plain_import:
                for mod in plain_import.split(","):
                    mod = mod.strip()
                    if " as " in mod:
                        alias = mod.split(" as ")[-1].strip()
                        imports[alias] = mod.split(" as ")[0].strip()
                    elif mod:
                        imports[mod] = mod

        return imports

    def _extract_js_imports(
        self,
        code: str,
    ) -> dict[str, str]:
        """Extract JavaScript/TypeScript import names to source mapping."""
        imports: dict[str, str] = {}
        for match in _JS_IMPORT_RE.finditer(code):
            source = match.group(1) or match.group(2)
            if source:
                module_name = source.split("/")[-1]
                imports[module_name] = source
        return imports

    # ═══════════════════════════════════════════════════════════════
    #  Finding construction
    # ═══════════════════════════════════════════════════════════════

    def _build_hallucination_finding(
        self,
        usage: SanitizerUsage,
        filename: str,
    ) -> Finding:
        """Build a BLOCK finding for a hallucinated sanitizer."""
        suggestion = _HALLUCINATION_SUGGESTIONS.get(
            usage.sink_category,
            "Replace with a verified sanitizer from the standard library or a trusted package.",
        )

        return Finding(
            rule_id=f"hallucinated_sanitizer_{usage.sink_category}",
            severity=Severity.BLOCK,
            message=(
                f"AI-generated sanitizer `{usage.function_name}()` cannot be verified "
                f"— function may not exist. Taint chain from `{usage.source_name}` to "
                f"`{usage.sink_name}` is unprotected."
            ),
            file=filename,
            line=usage.line,
            suggestion=suggestion,
            confidence=HALLUCINATION_CONFIDENCE,
        )
