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


_LANGUAGE_LOADERS: dict[Language, object] = {
    Language.PYTHON: _load_python_language,
    Language.JAVASCRIPT: _load_javascript_language,
    Language.TYPESCRIPT: _load_typescript_language,
    Language.GO: _load_go_language,
    Language.RUST: _load_rust_language,
    Language.JAVA: _load_java_language,
    Language.CSHARP: _load_csharp_language,
    Language.CPP: _load_cpp_language,
}


def _load_language(language: Language) -> ts.Language | None:
    """Load the tree-sitter grammar for a language."""
    loader = _LANGUAGE_LOADERS.get(language)
    if loader is None:
        return None
    try:
        return loader()  # type: ignore[operator]
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

    # --- Response building ---

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
