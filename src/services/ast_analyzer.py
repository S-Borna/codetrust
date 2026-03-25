# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Layer 3: AST-based code analysis using tree-sitter.

Provides deep structural analysis of source code by parsing it into
Abstract Syntax Trees. Detects patterns that regex-based analysis cannot
reliably catch: cyclomatic complexity, unused variables, unreachable code,
and deep nesting.
"""

from collections.abc import Generator
from dataclasses import dataclass

import structlog
import tree_sitter as ts

from src.models.enums import Language, Severity
from src.models.responses import Finding

logger = structlog.get_logger()

COMPLEXITY_THRESHOLD = 10
DEFAULT_MAX_NESTING = 4


@dataclass(frozen=True)
class LanguageNodes:
    """AST node type names for a specific language."""

    function_types: tuple[str, ...]
    branch_types: tuple[str, ...]
    simple_assignment_types: tuple[str, ...]
    return_types: tuple[str, ...]
    nesting_types: tuple[str, ...]
    identifier_type: str
    block_type: str
    # --- AST-migration: call expression and exception handling ---
    call_expression_type: str = "call"
    argument_list_type: str = "argument_list"
    keyword_argument_type: str = "keyword_argument"
    exception_handler_type: str = "except_clause"
    exception_type_node: str = "type"  # field name for exception type in handler


LANGUAGE_NODES: dict[Language, LanguageNodes] = {
    Language.PYTHON: LanguageNodes(
        function_types=("function_definition",),
        branch_types=(
            "if_statement", "elif_clause", "for_statement",
            "while_statement", "except_clause", "boolean_operator",
        ),
        simple_assignment_types=("assignment",),
        return_types=(
            "return_statement", "raise_statement",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement",
            "while_statement", "try_statement",
        ),
        identifier_type="identifier",
        block_type="block",
        call_expression_type="call",
        argument_list_type="argument_list",
        keyword_argument_type="keyword_argument",
        exception_handler_type="except_clause",
        exception_type_node="type",
    ),
    Language.JAVASCRIPT: LanguageNodes(
        function_types=(
            "function_declaration", "arrow_function", "method_definition",
        ),
        branch_types=(
            "if_statement", "for_statement", "while_statement",
            "do_statement", "catch_clause", "ternary_expression",
        ),
        simple_assignment_types=("variable_declarator",),
        return_types=(
            "return_statement", "throw_statement",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement",
            "while_statement", "do_statement", "try_statement",
        ),
        identifier_type="identifier",
        block_type="statement_block",
        call_expression_type="call_expression",
        argument_list_type="arguments",
        keyword_argument_type="",
        exception_handler_type="catch_clause",
        exception_type_node="parameter",
    ),
    Language.TYPESCRIPT: LanguageNodes(
        function_types=(
            "function_declaration", "arrow_function", "method_definition",
        ),
        branch_types=(
            "if_statement", "for_statement", "while_statement",
            "do_statement", "catch_clause", "ternary_expression",
        ),
        simple_assignment_types=("variable_declarator",),
        return_types=(
            "return_statement", "throw_statement",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement",
            "while_statement", "do_statement", "try_statement",
        ),
        identifier_type="identifier",
        block_type="statement_block",
        call_expression_type="call_expression",
        argument_list_type="arguments",
        keyword_argument_type="",
        exception_handler_type="catch_clause",
        exception_type_node="parameter",
    ),
    Language.GO: LanguageNodes(
        function_types=("function_declaration", "method_declaration"),
        branch_types=(
            "if_statement", "for_statement",
            "expression_case", "type_case", "select_statement",
        ),
        simple_assignment_types=("short_var_declaration",),
        return_types=("return_statement",),
        nesting_types=(
            "if_statement", "for_statement", "select_statement",
        ),
        identifier_type="identifier",
        block_type="block",
        call_expression_type="call_expression",
        argument_list_type="argument_list",
        keyword_argument_type="",
        exception_handler_type="",
        exception_type_node="",
    ),
    Language.RUST: LanguageNodes(
        function_types=("function_item",),
        branch_types=(
            "if_expression", "for_expression",
            "while_expression", "match_arm",
        ),
        simple_assignment_types=("let_declaration",),
        return_types=("return_expression",),
        nesting_types=(
            "if_expression", "for_expression",
            "while_expression", "match_expression",
        ),
        identifier_type="identifier",
        block_type="block",
        call_expression_type="call_expression",
        argument_list_type="arguments",
        keyword_argument_type="",
        exception_handler_type="",
        exception_type_node="",
    ),
    Language.JAVA: LanguageNodes(
        function_types=("method_declaration", "constructor_declaration"),
        branch_types=(
            "if_statement", "for_statement", "enhanced_for_statement",
            "while_statement", "do_statement", "catch_clause",
            "ternary_expression", "switch_expression",
        ),
        simple_assignment_types=("local_variable_declaration",),
        return_types=(
            "return_statement", "throw_statement",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement", "enhanced_for_statement",
            "while_statement", "do_statement", "try_statement",
        ),
        identifier_type="identifier",
        block_type="block",
        call_expression_type="method_invocation",
        argument_list_type="argument_list",
        keyword_argument_type="",
        exception_handler_type="catch_clause",
        exception_type_node="catch_type",
    ),
    Language.CSHARP: LanguageNodes(
        function_types=("method_declaration", "constructor_declaration"),
        branch_types=(
            "if_statement", "for_statement", "for_each_statement",
            "while_statement", "do_statement", "catch_clause",
            "conditional_expression", "switch_expression",
        ),
        simple_assignment_types=("variable_declaration",),
        return_types=(
            "return_statement", "throw_statement",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement", "for_each_statement",
            "while_statement", "do_statement", "try_statement",
        ),
        identifier_type="identifier",
        block_type="block",
        call_expression_type="invocation_expression",
        argument_list_type="argument_list",
        keyword_argument_type="",
        exception_handler_type="catch_clause",
        exception_type_node="catch_declaration",
    ),
    Language.CPP: LanguageNodes(
        function_types=("function_definition",),
        branch_types=(
            "if_statement", "for_statement", "for_range_loop",
            "while_statement", "do_statement", "catch_clause",
            "conditional_expression", "case_statement",
        ),
        simple_assignment_types=("declaration",),
        return_types=(
            "return_statement", "throw_statement",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement", "for_range_loop",
            "while_statement", "do_statement", "try_statement",
        ),
        identifier_type="identifier",
        block_type="compound_statement",
        call_expression_type="call_expression",
        argument_list_type="argument_list",
        keyword_argument_type="",
        exception_handler_type="catch_clause",
        exception_type_node="type",
    ),
    Language.RUBY: LanguageNodes(
        function_types=("method",),
        branch_types=(
            "if", "elsif", "unless", "for", "while", "until",
            "when", "rescue", "binary",
        ),
        simple_assignment_types=("assignment",),
        return_types=(
            "return", "raise", "break", "next",
        ),
        nesting_types=(
            "if", "unless", "for", "while", "until",
            "begin", "do_block",
        ),
        identifier_type="identifier",
        block_type="body_statement",
        call_expression_type="call",
        argument_list_type="argument_list",
        keyword_argument_type="pair",
        exception_handler_type="rescue",
        exception_type_node="exceptions",
    ),
    Language.PHP: LanguageNodes(
        function_types=("function_definition", "method_declaration"),
        branch_types=(
            "if_statement", "for_statement", "foreach_statement",
            "while_statement", "do_statement", "catch_clause",
            "conditional_expression", "case_statement",
        ),
        simple_assignment_types=("assignment_expression",),
        return_types=(
            "return_statement", "throw_expression",
            "break_statement", "continue_statement",
        ),
        nesting_types=(
            "if_statement", "for_statement", "foreach_statement",
            "while_statement", "do_statement", "try_statement",
        ),
        identifier_type="name",
        block_type="compound_statement",
        call_expression_type="function_call_expression",
        argument_list_type="arguments",
        keyword_argument_type="",
        exception_handler_type="catch_clause",
        exception_type_node="type_list",
    ),
}

SUPPORTED_LANGUAGES: frozenset[Language] = frozenset(LANGUAGE_NODES.keys())


# ---------------------------------------------------------------------------
# Tree-sitter language loading
# ---------------------------------------------------------------------------


def _load_python_language() -> ts.Language:
    """Load the Python tree-sitter grammar."""
    import tree_sitter_python as tsp

    return ts.Language(tsp.language())


def _load_javascript_language() -> ts.Language:
    """Load the JavaScript tree-sitter grammar."""
    import tree_sitter_javascript as tsjs

    return ts.Language(tsjs.language())


def _load_typescript_language() -> ts.Language:
    """Load the TypeScript tree-sitter grammar."""
    import tree_sitter_typescript as tsts

    return ts.Language(tsts.language_typescript())


def _load_go_language() -> ts.Language:
    """Load the Go tree-sitter grammar."""
    import tree_sitter_go as tsg

    return ts.Language(tsg.language())


def _load_rust_language() -> ts.Language:
    """Load the Rust tree-sitter grammar."""
    import tree_sitter_rust as tsr

    return ts.Language(tsr.language())


def _load_java_language() -> ts.Language:
    """Load the Java tree-sitter grammar."""
    import tree_sitter_java as tsj

    return ts.Language(tsj.language())


def _load_csharp_language() -> ts.Language:
    """Load the C# tree-sitter grammar."""
    import tree_sitter_c_sharp as tscs

    return ts.Language(tscs.language())


def _load_cpp_language() -> ts.Language:
    """Load the C++ tree-sitter grammar."""
    import tree_sitter_cpp as tscpp

    return ts.Language(tscpp.language())


def _load_ruby_language() -> ts.Language:
    """Load the Ruby tree-sitter grammar."""
    import tree_sitter_ruby as tsrb

    return ts.Language(tsrb.language())


def _load_php_language() -> ts.Language:
    """Load the PHP tree-sitter grammar."""
    import tree_sitter_php as tsphp

    return ts.Language(tsphp.language_php())


_LANGUAGE_LOADERS: dict[Language, object] = {
    Language.PYTHON: _load_python_language,
    Language.JAVASCRIPT: _load_javascript_language,
    Language.TYPESCRIPT: _load_typescript_language,
    Language.GO: _load_go_language,
    Language.RUST: _load_rust_language,
    Language.JAVA: _load_java_language,
    Language.CSHARP: _load_csharp_language,
    Language.CPP: _load_cpp_language,
    Language.RUBY: _load_ruby_language,
    Language.PHP: _load_php_language,
}


def _load_language(language: Language) -> ts.Language | None:
    """Load the tree-sitter grammar for a language."""
    loader = _LANGUAGE_LOADERS.get(language)
    if loader is None:
        return None
    try:
        return loader()
    except (ImportError, AttributeError, OSError) as exc:
        logger.warning(
            "tree_sitter_load_failed",
            language=str(language),
            error=str(exc),
        )
        return None


# ---------------------------------------------------------------------------
# Tree walking utilities
# ---------------------------------------------------------------------------


def _walk_tree(node: ts.Node) -> Generator[ts.Node, None, None]:
    """Depth-first walk of all nodes in a subtree."""
    yield node
    for child in node.children:
        yield from _walk_tree(child)


def _find_nodes_by_type(
    root: ts.Node,
    type_names: tuple[str, ...],
) -> list[ts.Node]:
    """Find all nodes matching any of the given type names."""
    return [n for n in _walk_tree(root) if n.type in type_names]


def _get_function_name(func_node: ts.Node) -> str:
    """Extract the function name from a function definition node."""
    name_node = func_node.child_by_field_name("name")
    if name_node is not None:
        return name_node.text.decode("utf-8")
    return "<anonymous>"


def _first_identifier_child(
    node: ts.Node,
    identifier_type: str,
) -> ts.Node | None:
    """Get the first identifier-type child of a node."""
    for child in node.children:
        if child.type == identifier_type:
            return child
    return None


# ---------------------------------------------------------------------------
# Call expression helpers (AST-migration)
# ---------------------------------------------------------------------------


def _get_call_name(call_node: ts.Node) -> str:
    """Extract the callee name from a call expression node.

    Handles simple calls (``foo()``) and attribute calls (``obj.foo()``).
    Returns the full dotted name (e.g. ``httpx.AsyncClient``).
    """
    func = call_node.child_by_field_name("function")
    if func is None:
        # Some languages use first child
        for child in call_node.children:
            if child.type in ("identifier", "attribute", "member_expression",
                              "field_expression", "scoped_identifier"):
                func = child
                break
    if func is None:
        return ""
    return func.text.decode("utf-8")


def _get_call_arguments(call_node: ts.Node, nodes: LanguageNodes) -> list[ts.Node]:
    """Get the argument list children of a call expression."""
    for child in call_node.children:
        if child.type == nodes.argument_list_type:
            return list(child.children)
    args_node = call_node.child_by_field_name("arguments")
    if args_node is not None:
        return list(args_node.children)
    return []


def _has_keyword_arg(
    call_node: ts.Node,
    nodes: LanguageNodes,
    keywords: frozenset[str],
) -> bool:
    """Check if a call has any keyword argument matching the given names.

    For Python: looks for ``keyword_argument`` nodes with matching name.
    For other languages: falls back to checking full argument text.
    """
    args = _get_call_arguments(call_node, nodes)
    if nodes.keyword_argument_type:
        for arg in args:
            if arg.type == nodes.keyword_argument_type:
                name_node = arg.child_by_field_name("name")
                if name_node is None:
                    # Fall back to first identifier child
                    name_node = _first_identifier_child(arg, nodes.identifier_type)
                if name_node is not None:
                    name = name_node.text.decode("utf-8")
                    if name in keywords:
                        return True
    # Fallback: check if any argument text contains a keyword (for struct literals, etc.)
    for arg in args:
        text = arg.text.decode("utf-8")
        for kw in keywords:
            if kw in text:
                return True
    return False


def _call_name_matches(name: str, patterns: frozenset[str]) -> bool:
    """Check if a call name matches any of the given patterns.

    Matches either the full name or the last segment after a dot.
    E.g. ``httpx.AsyncClient`` matches both ``httpx.AsyncClient`` and ``AsyncClient``.
    """
    if name in patterns:
        return True
    last_segment = name.rsplit(".", maxsplit=1)[-1]
    return last_segment in patterns


# ---------------------------------------------------------------------------
# AST-migration: check configurations
# ---------------------------------------------------------------------------

# Calls that MUST have a timeout/deadline argument
TIMEOUT_REQUIRED_CALLS: frozenset[str] = frozenset({
    # Python
    "AsyncClient", "Client", "httpx.AsyncClient", "httpx.Client",
    "aiohttp.ClientSession", "ClientSession",
    "create_engine", "create_async_engine",
    "from_url",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.options",
    # Go
    "http.Client",
    "grpc.Dial", "grpc.DialContext",
    # JS/TS
    "fetch", "axios.create", "axios.get", "axios.post",
    # Java
    "HttpClient.newBuilder", "newHttpClient",
    "DriverManager.getConnection",
    # C#
    "HttpClient", "new HttpClient",
    "SqlConnection", "new SqlConnection",
    "new Regex",
})

TIMEOUT_KEYWORDS: frozenset[str] = frozenset({
    "timeout", "connect_timeout", "socket_timeout",
    "socket_connect_timeout", "read_timeout", "write_timeout",
    "request_timeout", "Timeout", "deadline", "connectTimeout",
    "readTimeout", "writeTimeout", "connectionTimeout",
    "timeout_millis", "timeout_seconds",
})

# Constructors that MUST have a resource limit argument
RESOURCE_LIMIT_CALLS: dict[str, frozenset[str]] = {
    # Call name -> required keyword arguments (any one suffices)
    "ThreadPoolExecutor": frozenset({"max_workers"}),
    "ProcessPoolExecutor": frozenset({"max_workers"}),
    "create_engine": frozenset({"pool_size", "max_overflow"}),
    "create_async_engine": frozenset({"pool_size", "max_overflow"}),
    "ConnectionPool": frozenset({"maxsize", "max_size", "maxconnections"}),
    "Pool": frozenset({"maxsize", "max_size", "maxconnections", "min_size"}),
    "asyncio.Semaphore": frozenset({"value"}),
    "Semaphore": frozenset({"value"}),
    "BoundedSemaphore": frozenset({"value"}),
    "Queue": frozenset({"maxsize"}),
    "asyncio.Queue": frozenset({"maxsize"}),
    "Cache": frozenset({"maxsize", "max_size"}),
    "LRUCache": frozenset({"maxsize", "max_size"}),
    "redis.ConnectionPool": frozenset({"max_connections"}),
}

# Broad exception types that should NOT be caught
BROAD_EXCEPTION_TYPES: frozenset[str] = frozenset({
    "Exception", "BaseException", "object",
    # Java
    "Throwable", "java.lang.Throwable",
    # C#
    "System.Exception",
    # PHP
    "\\Exception", "\\Throwable",
})


# ---------------------------------------------------------------------------
# AST-backed rule mapping: regex rule_id → AST rule_id that supersedes it
# When both fire on the same code, the AST version is more precise.
# ---------------------------------------------------------------------------

AST_SUPERSEDES: dict[str, str] = {
    # Timeout rules → ast_missing_timeout
    "connection_no_timeout": "ast_missing_timeout",
    "async_missing_timeout": "ast_missing_timeout",
    "go_http_no_timeout": "ast_missing_timeout",
    "grpc_no_deadline": "ast_missing_timeout",
    "grpc2_no_deadline": "ast_missing_timeout",
    "csharp_regex_timeout_missing": "ast_missing_timeout",
    "db_no_timeout": "ast_missing_timeout",
    "microservice_no_timeout": "ast_missing_timeout",
    "dart_dio_no_timeout": "ast_missing_timeout",
    "lambda_timeout_too_high": "ast_missing_timeout",
    # Resource limit rules → ast_missing_resource_limit
    "async_thread_pool_no_limit": "ast_missing_resource_limit",
    "db_pool_no_limit": "ast_missing_resource_limit",
    "perf_connection_pool_exhaust": "ast_missing_resource_limit",
    "perf_unbounded_cache": "ast_missing_resource_limit",
    # Exception rules → ast_broad_exception
    "bare_except": "ast_broad_exception",
    "quality_broad_exception_type": "ast_broad_exception",
    "error_broad_retry": "ast_broad_exception",
    # Swallow rules → ast_silent_exception_swallow
    "except_swallow": "ast_silent_exception_swallow",
    "error_silent_timeout": "ast_silent_exception_swallow",
    "error_except_pass": "ast_silent_exception_swallow",
    # Loop growth → ast_unbounded_loop_growth
    "perf_unbounded_list_append": "ast_unbounded_loop_growth",
    # Module-level mutable → ast_module_level_mutable
    "perf_global_list_append": "ast_module_level_mutable",
}

# Set of regex rule IDs that have AST equivalents
AST_BACKED_RULE_IDS: frozenset[str] = frozenset(AST_SUPERSEDES.keys())


# ---------------------------------------------------------------------------
# AstAnalyzer
# ---------------------------------------------------------------------------


class AstAnalyzer:
    """Tree-sitter based code analysis for deep structural checks."""

    def __init__(self) -> None:
        """Initialize the AST analyzer with a language cache."""
        self._language_cache: dict[Language, ts.Language] = {}

    def _get_ts_language(self, language: Language) -> ts.Language | None:
        """Get or load a tree-sitter language, with caching."""
        if language in self._language_cache:
            return self._language_cache[language]
        ts_lang = _load_language(language)
        if ts_lang is not None:
            self._language_cache[language] = ts_lang
        return ts_lang

    def parse_code(self, code: str, language: Language) -> ts.Tree | None:
        """Parse source code into a tree-sitter AST.

        Returns None if the language is not supported or loading fails.
        """
        ts_lang = self._get_ts_language(language)
        if ts_lang is None:
            logger.warning("ast_parse_unsupported", language=str(language))
            return None
        parser = ts.Parser(ts_lang)
        return parser.parse(bytes(code, "utf-8"))

    def analyze(
        self,
        code: str,
        language: Language,
        filename: str = "untitled",
        max_nesting: int = DEFAULT_MAX_NESTING,
        complexity_threshold: int = COMPLEXITY_THRESHOLD,
    ) -> list[Finding]:
        """Run all AST-based checks and return combined findings."""
        tree = self.parse_code(code, language)
        if tree is None:
            return []

        nodes = LANGUAGE_NODES.get(language)
        if nodes is None:
            return []

        root = tree.root_node
        findings: list[Finding] = []
        findings.extend(
            self._analyze_complexity(root, nodes, filename, complexity_threshold)
        )
        findings.extend(self._find_unused_variables(root, nodes, filename))
        findings.extend(self._find_unreachable_code(root, nodes, filename))
        findings.extend(
            self._find_deep_nesting(root, nodes, filename, max_nesting)
        )
        # --- AST-migration phase 1 checks ---
        findings.extend(self._find_missing_timeouts(root, nodes, filename))
        findings.extend(self._find_missing_resource_limits(root, nodes, filename))
        findings.extend(self._find_broad_exception_handlers(root, nodes, filename))
        # --- AST-migration phase 2 checks ---
        findings.extend(self._find_silent_exception_swallow(root, nodes, filename))
        findings.extend(self._find_unbounded_loop_growth(root, nodes, filename))
        findings.extend(self._find_module_level_mutable(root, nodes, filename))

        logger.info(
            "ast_analysis_complete",
            filename=filename,
            language=str(language),
            total_findings=len(findings),
        )
        return findings

    # --- Complexity analysis ---

    def _analyze_complexity(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
        threshold: int,
    ) -> list[Finding]:
        """Compute cyclomatic complexity for all functions."""
        findings: list[Finding] = []
        functions = _find_nodes_by_type(root, nodes.function_types)

        for func_node in functions:
            name = _get_function_name(func_node)
            complexity = self._compute_complexity(func_node, nodes)
            if complexity > threshold:
                findings.append(self._complexity_finding(
                    name, complexity, threshold, filename, func_node,
                ))
        return findings

    def _compute_complexity(
        self,
        func_node: ts.Node,
        nodes: LanguageNodes,
    ) -> int:
        """Count branch nodes within a function for cyclomatic complexity."""
        count = 1
        for child in _walk_tree(func_node):
            if child.type in nodes.branch_types:
                count += 1
        return count

    def _complexity_finding(
        self,
        name: str,
        complexity: int,
        threshold: int,
        filename: str,
        func_node: ts.Node,
    ) -> Finding:
        """Build a Finding for high cyclomatic complexity."""
        return Finding(
            rule_id="ast_high_complexity",
            severity=Severity.WARN,
            message=(
                f"Function '{name}' has cyclomatic complexity "
                f"{complexity} (threshold: {threshold})"
            ),
            file=filename,
            line=func_node.start_point.row + 1,
            suggestion=f"Consider splitting '{name}' into smaller functions",
        )

    # --- Unused variables ---

    def _find_unused_variables(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find variables assigned but never referenced within functions."""
        findings: list[Finding] = []
        functions = _find_nodes_by_type(root, nodes.function_types)

        for func_node in functions:
            unused = self._collect_unused_in_scope(func_node, nodes)
            for var_name, var_node in unused:
                findings.append(Finding(
                    rule_id="ast_unused_variable",
                    severity=Severity.INFO,
                    message=f"Variable '{var_name}' is assigned but never used",
                    file=filename,
                    line=var_node.start_point.row + 1,
                    suggestion=(
                        f"Remove '{var_name}' or prefix with '_' "
                        "if intentionally unused"
                    ),
                ))
        return findings

    def _collect_unused_in_scope(
        self,
        scope_node: ts.Node,
        nodes: LanguageNodes,
    ) -> list[tuple[str, ts.Node]]:
        """Collect variables assigned but never referenced in a scope."""
        target_positions = self._collect_assignment_positions(scope_node, nodes)
        assigned_vars = self._collect_assigned_names(scope_node, nodes)
        referenced = self._collect_references(scope_node, nodes, target_positions)

        return [
            (name, node)
            for name, node in assigned_vars.items()
            if name not in referenced and not name.startswith("_")
        ]

    def _collect_assignment_positions(
        self,
        scope_node: ts.Node,
        nodes: LanguageNodes,
    ) -> set[tuple[int, int]]:
        """Collect (row, col) positions of assignment target identifiers."""
        positions: set[tuple[int, int]] = set()
        for node in _walk_tree(scope_node):
            if node.type in nodes.simple_assignment_types:
                target = _first_identifier_child(node, nodes.identifier_type)
                if target is not None:
                    positions.add(
                        (target.start_point.row, target.start_point.column)
                    )
        return positions

    def _collect_assigned_names(
        self,
        scope_node: ts.Node,
        nodes: LanguageNodes,
    ) -> dict[str, ts.Node]:
        """Collect assigned variable names mapped to first assignment node."""
        assigned: dict[str, ts.Node] = {}
        for node in _walk_tree(scope_node):
            if node.type in nodes.simple_assignment_types:
                target = _first_identifier_child(node, nodes.identifier_type)
                if target is not None:
                    name = target.text.decode("utf-8")
                    if name not in assigned:
                        assigned[name] = target
        return assigned

    def _collect_references(
        self,
        scope_node: ts.Node,
        nodes: LanguageNodes,
        target_positions: set[tuple[int, int]],
    ) -> set[str]:
        """Collect identifier names that are references (not assignments)."""
        referenced: set[str] = set()
        for node in _walk_tree(scope_node):
            if node.type == nodes.identifier_type:
                pos = (node.start_point.row, node.start_point.column)
                if pos not in target_positions:
                    referenced.add(node.text.decode("utf-8"))
        return referenced

    # --- Unreachable code ---

    def _find_unreachable_code(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find code after return/raise/break/continue statements."""
        findings: list[Finding] = []
        blocks = _find_nodes_by_type(root, (nodes.block_type,))
        flagged_lines: set[int] = set()

        for block in blocks:
            self._check_block_for_unreachable(
                block, nodes, filename, findings, flagged_lines,
            )
        return findings

    def _check_block_for_unreachable(
        self,
        block: ts.Node,
        nodes: LanguageNodes,
        filename: str,
        findings: list[Finding],
        flagged_lines: set[int],
    ) -> None:
        """Check a single block node for unreachable statements."""
        found_terminator = False
        skip_types = frozenset({"comment", "}", ""})

        for child in block.children:
            line = child.start_point.row + 1
            if (
                found_terminator
                and child.type not in skip_types
                and line not in flagged_lines
            ):
                flagged_lines.add(line)
                findings.append(Finding(
                    rule_id="ast_unreachable_code",
                    severity=Severity.WARN,
                    message="Unreachable code after return/raise/break",
                    file=filename,
                    line=line,
                    suggestion="Remove unreachable code or restructure control flow",
                ))
                break
            if child.type in nodes.return_types:
                found_terminator = True

    # --- Deep nesting ---

    def _find_deep_nesting(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
        max_depth: int,
    ) -> list[Finding]:
        """Find code with excessive nesting depth."""
        findings: list[Finding] = []
        flagged_lines: set[int] = set()
        self._walk_nesting(
            root, nodes, filename, 0, max_depth, findings, flagged_lines,
        )
        return findings

    def _walk_nesting(
        self,
        node: ts.Node,
        nodes: LanguageNodes,
        filename: str,
        depth: int,
        max_depth: int,
        findings: list[Finding],
        flagged_lines: set[int],
    ) -> None:
        """Recursively walk the tree tracking nesting depth."""
        current_depth = depth
        if node.type in nodes.nesting_types:
            current_depth += 1
            line = node.start_point.row + 1
            if current_depth > max_depth and line not in flagged_lines:
                flagged_lines.add(line)
                findings.append(Finding(
                    rule_id="ast_deep_nesting",
                    severity=Severity.WARN,
                    message=(
                        f"Code is nested {current_depth} levels deep "
                        f"(max: {max_depth})"
                    ),
                    file=filename,
                    line=line,
                    suggestion="Extract nested logic into separate functions",
                ))

        for child in node.children:
            self._walk_nesting(
                child, nodes, filename, current_depth,
                max_depth, findings, flagged_lines,
            )

    # --- AST-migration: Missing timeouts ---

    def _find_missing_timeouts(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find network/DB client calls without explicit timeout parameter.

        Walks all call expressions, matches against TIMEOUT_REQUIRED_CALLS,
        then checks if any timeout-related keyword argument is present.
        """
        findings: list[Finding] = []
        call_type = nodes.call_expression_type
        if not call_type:
            return findings

        for node in _walk_tree(root):
            if node.type != call_type:
                continue
            name = _get_call_name(node)
            if not name:
                continue
            if not _call_name_matches(name, TIMEOUT_REQUIRED_CALLS):
                continue
            if _has_keyword_arg(node, nodes, TIMEOUT_KEYWORDS):
                continue
            findings.append(Finding(
                rule_id="ast_missing_timeout",
                severity=Severity.WARN,
                message=(
                    f"Call to '{name}' without explicit timeout. "
                    f"Add timeout parameter to avoid indefinite blocking."
                ),
                file=filename,
                line=node.start_point.row + 1,
                suggestion="Add timeout=<seconds> or equivalent parameter.",
            ))
        return findings

    # --- AST-migration: Missing resource limits ---

    def _find_missing_resource_limits(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find constructors that create unbounded resources without limits.

        Checks calls like ThreadPoolExecutor() for required limit parameters.
        """
        findings: list[Finding] = []
        call_type = nodes.call_expression_type
        if not call_type:
            return findings

        for node in _walk_tree(root):
            if node.type != call_type:
                continue
            name = _get_call_name(node)
            if not name:
                continue

            # Check both full name and last segment
            required_kws: frozenset[str] | None = None
            for pattern, kws in RESOURCE_LIMIT_CALLS.items():
                if _call_name_matches(name, frozenset({pattern})):
                    required_kws = kws
                    break
            if required_kws is None:
                continue

            if _has_keyword_arg(node, nodes, required_kws):
                continue

            findings.append(Finding(
                rule_id="ast_missing_resource_limit",
                severity=Severity.WARN,
                message=(
                    f"Call to '{name}' without resource limit. "
                    f"Add one of: {', '.join(sorted(required_kws))}."
                ),
                file=filename,
                line=node.start_point.row + 1,
                suggestion=(
                    "Set an explicit limit to prevent unbounded resource usage."
                ),
            ))
        return findings

    # --- AST-migration: Broad exception handlers ---

    def _find_broad_exception_handlers(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find exception handlers that catch overly broad exception types.

        Detects ``except Exception``, ``catch (Throwable)``, bare ``except:``, etc.
        """
        findings: list[Finding] = []
        handler_type = nodes.exception_handler_type
        if not handler_type:
            return findings

        for node in _walk_tree(root):
            if node.type != handler_type:
                continue

            exc_type = self._extract_exception_type(node, nodes)
            line = node.start_point.row + 1

            if exc_type is None:
                # Bare except (no type specified) — Python ``except:``
                # Only flag if the handler body is non-trivial
                # (bare except with just pass is caught by except_swallow)
                findings.append(Finding(
                    rule_id="ast_broad_exception",
                    severity=Severity.WARN,
                    message=(
                        "Bare exception handler catches everything "
                        "including KeyboardInterrupt and SystemExit."
                    ),
                    file=filename,
                    line=line,
                    suggestion="Catch specific exception types instead.",
                ))
            elif exc_type in BROAD_EXCEPTION_TYPES:
                findings.append(Finding(
                    rule_id="ast_broad_exception",
                    severity=Severity.WARN,
                    message=(
                        f"Catching '{exc_type}' is too broad. "
                        f"Catch specific exception types instead."
                    ),
                    file=filename,
                    line=line,
                    suggestion=(
                        "Use specific exceptions like ValueError, "
                        "TypeError, or OSError."
                    ),
                ))
        return findings

    _EXCEPTION_TYPE_NODE_TYPES: frozenset[str] = frozenset({
        "identifier", "type_identifier", "scoped_identifier",
        "qualified_name", "name", "catch_type",
        "type_list", "catch_declaration", "catch_formal_parameter",
        "tuple", "tuple_pattern",
    })

    _SKIP_KEYWORDS: frozenset[str] = frozenset({
        "except", "catch", "rescue", "as", "finally",
    })

    def _extract_exception_type(
        self,
        handler_node: ts.Node,
        nodes: LanguageNodes,
    ) -> str | None:
        """Extract the exception type name from a catch/except handler node.

        Returns None if no type is specified (bare except).
        For tuple types like ``except (ValueError, TypeError)``, returns the
        full tuple text so broad-exception check works correctly.
        """
        # Try field-based access first (Python: except_clause has type field)
        type_node = handler_node.child_by_field_name(nodes.exception_type_node)
        if type_node is not None:
            return type_node.text.decode("utf-8").strip()

        # Fall back to scanning children for type-like nodes
        for child in handler_node.children:
            if child.type in self._EXCEPTION_TYPE_NODE_TYPES:
                # For composite nodes (Java catch_formal_parameter), look deeper
                if child.type in ("catch_formal_parameter", "catch_declaration"):
                    return self._extract_type_from_parameter(child)
                text = child.text.decode("utf-8").strip()
                if text in self._SKIP_KEYWORDS:
                    continue
                return text

        return None

    def _extract_type_from_parameter(
        self,
        param_node: ts.Node,
    ) -> str | None:
        """Extract type from a catch parameter node (Java/C#).

        Java: catch_formal_parameter -> catch_type + identifier
        C#: catch_declaration -> type + identifier
        """
        for child in param_node.children:
            if child.type in ("catch_type", "type_identifier", "identifier",
                              "scoped_identifier", "qualified_name", "type"):
                text = child.text.decode("utf-8").strip()
                # Skip the variable name (lowercase single identifier)
                if child.type == "identifier" and text[0:1].islower():
                    continue
                return text
        return None

    # --- AST-migration phase 2: Silent exception swallow ---

    _EMPTY_BODY_TEXTS: frozenset[str] = frozenset({
        "pass", "...", "continue",
    })

    def _find_silent_exception_swallow(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find exception handlers with empty bodies (pass/... only).

        More precise than regex: correctly identifies the handler body
        regardless of line formatting, and reports the exception type.
        """
        findings: list[Finding] = []
        handler_type = nodes.exception_handler_type
        if not handler_type:
            return findings

        for node in _walk_tree(root):
            if node.type != handler_type:
                continue

            body = self._get_handler_body(node, nodes)
            if body is None:
                continue

            # Check if body contains only pass/... or is empty
            body_statements = [
                c for c in body.children
                if c.type not in ("comment", "", ":")
                and c.text.decode("utf-8").strip()
            ]
            if not body_statements:
                is_empty = True
            else:
                body_text = " ".join(
                    c.text.decode("utf-8").strip() for c in body_statements
                )
                is_empty = body_text in self._EMPTY_BODY_TEXTS

            if is_empty:
                exc_type = self._extract_exception_type(node, nodes)
                type_desc = f"'{exc_type}'" if exc_type else "all exceptions"
                findings.append(Finding(
                    rule_id="ast_silent_exception_swallow",
                    severity=Severity.WARN,
                    message=(
                        f"Exception handler catches {type_desc} and "
                        f"silently swallows it. Log or re-raise."
                    ),
                    file=filename,
                    line=node.start_point.row + 1,
                    suggestion="Add logging or re-raise the exception.",
                ))
        return findings

    def _get_handler_body(
        self,
        handler_node: ts.Node,
        nodes: LanguageNodes,
    ) -> ts.Node | None:
        """Get the body/block node of an exception handler."""
        body = handler_node.child_by_field_name("body")
        if body is not None:
            return body
        # Fall back: find the block child
        for child in handler_node.children:
            if child.type == nodes.block_type:
                return child
        return None

    # --- AST-migration phase 2: Unbounded loop growth ---

    def _find_unbounded_loop_growth(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find .append() or collection growth inside unbounded loops.

        Detects patterns like ``while True: items.append(x)`` which cause
        unbounded memory growth in long-running processes.
        """
        findings: list[Finding] = []
        flagged_lines: set[int] = set()

        for node in _walk_tree(root):
            if not self._is_unbounded_loop(node, nodes):
                continue
            # Search loop body for append/extend/add calls
            for descendant in _walk_tree(node):
                if descendant.type != nodes.call_expression_type:
                    continue
                name = _get_call_name(descendant)
                if not name:
                    continue
                last_part = name.rsplit(".", maxsplit=1)[-1]
                if last_part in ("append", "extend", "add", "push", "insert"):
                    line = descendant.start_point.row + 1
                    if line not in flagged_lines:
                        flagged_lines.add(line)
                        findings.append(Finding(
                            rule_id="ast_unbounded_loop_growth",
                            severity=Severity.WARN,
                            message=(
                                f"Collection growth via '.{last_part}()' inside "
                                f"unbounded loop. Add a size limit or break condition."
                            ),
                            file=filename,
                            line=line,
                            suggestion=(
                                "Add maxlen check, use collections.deque(maxlen=N), "
                                "or ensure the loop has a termination condition."
                            ),
                        ))
        return findings

    def _is_unbounded_loop(
        self,
        node: ts.Node,
        nodes: LanguageNodes,
    ) -> bool:
        """Check if a node is an unbounded loop (while True, loop {}, etc.)."""
        if node.type not in ("while_statement", "while", "loop_expression"):
            return False
        # Check condition: while True / while(true) / while 1
        condition = node.child_by_field_name("condition")
        if condition is not None:
            text = condition.text.decode("utf-8").strip().lower()
            return text in ("true", "1", "yes")
        # Check first meaningful child after 'while'
        for child in node.children:
            if child.type in ("true", "false", "boolean"):
                return child.text.decode("utf-8").strip().lower() == "true"
            if child.type == "parenthesized_expression":
                inner = child.text.decode("utf-8").strip("() ").lower()
                return inner in ("true", "1")
        return False

    # --- AST-migration phase 2: Module-level mutable state ---

    _MUTABLE_CONSTRUCTORS: frozenset[str] = frozenset({
        "dict", "list", "set", "defaultdict", "OrderedDict",
        "Counter", "deque",
    })

    _MUTABLE_LITERALS: frozenset[str] = frozenset({
        "dictionary", "list", "set",  # tree-sitter node types
    })

    def _find_module_level_mutable(
        self,
        root: ts.Node,
        nodes: LanguageNodes,
        filename: str,
    ) -> list[Finding]:
        """Find mutable objects assigned at module scope.

        Module-level ``cache = {}`` or ``results = []`` creates shared mutable
        state that grows unbounded in long-running processes. AST can precisely
        distinguish module-level from function-level assignments.
        """
        findings: list[Finding] = []

        # Only check top-level children of root (module scope)
        # In Python, assignments are wrapped in expression_statement
        for child in root.children:
            assign_node = child
            if child.type not in nodes.simple_assignment_types:
                # Check one level deeper (expression_statement wrapper)
                found = False
                for grandchild in child.children:
                    if grandchild.type in nodes.simple_assignment_types:
                        assign_node = grandchild
                        found = True
                        break
                if not found:
                    continue

            # Get the variable name
            target = _first_identifier_child(assign_node, nodes.identifier_type)
            if target is None:
                continue
            var_name = target.text.decode("utf-8")

            # Skip UPPER_CASE constants (convention: these are immutable)
            if var_name.isupper():
                continue

            # Check if RHS is a mutable literal or constructor
            if self._rhs_is_mutable(assign_node, nodes):
                findings.append(Finding(
                    rule_id="ast_module_level_mutable",
                    severity=Severity.WARN,
                    message=(
                        f"Module-level mutable '{var_name}' creates shared "
                        f"state that can grow unbounded in long-running processes."
                    ),
                    file=filename,
                    line=child.start_point.row + 1,
                    suggestion=(
                        "Move inside a function, use a class, or make immutable "
                        "(tuple/frozenset)."
                    ),
                ))
        return findings

    def _rhs_is_mutable(
        self,
        assignment_node: ts.Node,
        nodes: LanguageNodes,
    ) -> bool:
        """Check if assignment RHS is a mutable literal ({}, [], set()) or constructor."""
        # Check value field
        value = assignment_node.child_by_field_name("value")
        if value is None:
            value = assignment_node.child_by_field_name("right")
        if value is None:
            # Fallback: last child that's not the target or operator
            children = [
                c for c in assignment_node.children
                if c.type not in (nodes.identifier_type, "=", ":", "type")
            ]
            if children:
                value = children[-1]
        if value is None:
            return False

        # Check for literal types
        if value.type in ("dictionary", "list", "set", "dictionary_comprehension",
                          "list_comprehension", "set_comprehension",
                          "object", "array"):
            return True

        # Check for constructor calls: dict(), list(), set(), defaultdict()
        if value.type == nodes.call_expression_type:
            name = _get_call_name(value)
            last = name.rsplit(".", maxsplit=1)[-1]
            return last in self._MUTABLE_CONSTRUCTORS

        return False

    # --- Response building ---

    @staticmethod
    def dedup_with_regex(
        regex_findings: list[Finding],
        ast_findings: list[Finding],
    ) -> list[Finding]:
        """Remove regex findings that are superseded by AST findings on the same line.

        When both a regex rule and its AST equivalent fire on the same file:line,
        keep only the AST finding (more precise, fewer false positives).
        """
        # Build set of (file, line) pairs covered by AST findings
        ast_coverage: set[tuple[str, int]] = set()
        for f in ast_findings:
            if f.rule_id.startswith("ast_"):
                ast_coverage.add((f.file, f.line))

        deduped: list[Finding] = []
        for f in regex_findings:
            if f.rule_id in AST_BACKED_RULE_IDS and (f.file, f.line) in ast_coverage:
                continue  # AST already covers this finding
            deduped.append(f)
        return deduped

    def build_scan_response(
        self,
        findings: list[Finding],
    ) -> dict[str, object]:
        """Build a response dict from findings for API responses."""
        blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
        warns = sum(1 for f in findings if f.severity == Severity.WARN)
        infos = sum(1 for f in findings if f.severity == Severity.INFO)
        verdict = self._compute_verdict(findings)

        return {
            "total_findings": len(findings),
            "blocks": blocks,
            "warnings": warns,
            "infos": infos,
            "findings": findings,
            "verdict": verdict,
        }

    def _compute_verdict(self, findings: list[Finding]) -> str:
        """Compute the overall verdict from findings."""
        if any(f.severity == Severity.BLOCK for f in findings):
            return "BLOCK"
        if any(f.severity == Severity.WARN for f in findings):
            return "WARN"
        return "PASS"

    def build_report(
        self,
        findings: list[Finding],
        title: str = "AST Analysis",
    ) -> str:
        """Build a markdown-formatted report for MCP tools."""
        blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
        warns = sum(1 for f in findings if f.severity == Severity.WARN)
        infos = sum(1 for f in findings if f.severity == Severity.INFO)
        verdict = self._compute_verdict(findings)

        lines: list[str] = [
            f"## {title}",
            "",
            f"**Verdict: {verdict}** | "
            f"{blocks} blocks | {warns} warnings | {infos} info",
            "",
        ]

        if findings:
            lines.append("### Findings")
            lines.append("")
            for f in findings:
                lines.append(
                    f"- [{f.severity}] {f.message} "
                    f"({f.file}:{f.line})"
                )
                if f.suggestion:
                    lines.append(f"  > {f.suggestion}")
            lines.append("")

        return "\n".join(lines)
