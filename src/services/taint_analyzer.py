# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Intra-procedural taint analysis using tree-sitter AST.

Tracks data flow from untrusted sources (e.g., request parameters)
to dangerous sinks (e.g., SQL queries, OS commands) within function
bodies. Reports findings when tainted data reaches a sink without
sanitization.
"""

from dataclasses import dataclass, field

import structlog
import tree_sitter as ts

from src.models.enums import Language, Severity
from src.models.responses import Finding
from src.rules.taint_rules import (
    TAINT_SANITIZERS,
    TAINT_SINKS,
    TAINT_SOURCES,
    TaintSanitizer,
    TaintSink,
    TaintSource,
)
from src.services.ast_analyzer import (
    LANGUAGE_NODES,
    _find_nodes_by_type,
    _load_language,
    _walk_tree,
)

logger = structlog.get_logger()

TAINT_CONFIDENCE_HIGH = 0.9
TAINT_CONFIDENCE_MEDIUM = 0.7
TAINT_CONFIDENCE_SANITIZED = 0.3


@dataclass
class TaintRecord:
    """Tracks a tainted variable and its provenance."""

    var_name: str
    source: TaintSource
    source_line: int
    chain: list[str] = field(default_factory=list)
    sanitized: bool = False


class TaintAnalyzer:
    """Intra-procedural taint analysis using tree-sitter AST."""

    def __init__(self) -> None:
        """Initialize the taint analyzer with a language cache."""
        self._language_cache: dict[Language, ts.Language] = {}

    def analyze(
        self,
        code: str,
        language: Language,
        filename: str = "",
    ) -> list[Finding]:
        """Run taint analysis on source code.

        Parses the code into a tree-sitter AST, then analyzes each
        function body for source-to-sink data flows.
        """
        ts_lang = self._get_ts_language(language)
        if ts_lang is None:
            return []

        parser = ts.Parser(ts_lang)
        tree = parser.parse(bytes(code, "utf-8"))

        nodes = LANGUAGE_NODES.get(language)
        if nodes is None:
            return []

        func_nodes = _find_nodes_by_type(tree.root_node, nodes.function_types)
        findings: list[Finding] = []

        for func_node in func_nodes:
            findings.extend(self._analyze_function(func_node, language, filename))

        logger.info(
            "taint_analysis_complete",
            filename=filename,
            language=str(language),
            total_findings=len(findings),
        )
        return findings

    def _get_ts_language(self, language: Language) -> ts.Language | None:
        """Get or load a tree-sitter language, with caching."""
        if language in self._language_cache:
            return self._language_cache[language]
        ts_lang = _load_language(language)
        if ts_lang is not None:
            self._language_cache[language] = ts_lang
        return ts_lang

    def _analyze_function(
        self,
        func_node: ts.Node,
        language: Language,
        filename: str,
    ) -> list[Finding]:
        """Analyze a single function for source-to-sink data flow."""
        tainted: dict[str, TaintRecord] = {}
        findings: list[Finding] = []

        for node in _walk_tree(func_node):
            self._process_assignment(node, language, tainted)
            self._check_sinks(node, language, tainted, findings, filename)

        return findings

    def _process_assignment(
        self,
        node: ts.Node,
        language: Language,
        tainted: dict[str, TaintRecord],
    ) -> None:
        """Check if a node is an assignment and update taint state."""
        var_name = self._extract_assigned_var(node, language)
        if var_name is None:
            return

        rhs_text = self._extract_rhs_text(node, language)
        if rhs_text is None:
            return

        self._check_source_assignment(var_name, rhs_text, node, language, tainted)
        self._check_propagation(var_name, rhs_text, node, language, tainted)

    def _check_source_assignment(
        self,
        var_name: str,
        rhs_text: str,
        node: ts.Node,
        language: Language,
        tainted: dict[str, TaintRecord],
    ) -> None:
        """Mark variable as tainted if RHS contains a source."""
        source = self._find_source_in_text(rhs_text, language)
        if source is not None:
            line = node.start_point.row + 1
            tainted[var_name] = TaintRecord(
                var_name=var_name,
                source=source,
                source_line=line,
                chain=[var_name],
            )

    def _check_propagation(
        self,
        var_name: str,
        rhs_text: str,
        node: ts.Node,
        language: Language,
        tainted: dict[str, TaintRecord],
    ) -> None:
        """Propagate taint through variable assignments."""
        if var_name in tainted:
            return

        sanitizer = self._find_sanitizer_in_text(rhs_text, language)
        for existing_var, record in tainted.items():
            if existing_var in rhs_text:
                new_chain = [*record.chain, var_name]
                tainted[var_name] = TaintRecord(
                    var_name=var_name,
                    source=record.source,
                    source_line=record.source_line,
                    chain=new_chain,
                    sanitized=sanitizer is not None,
                )
                break

    def _check_sinks(
        self,
        node: ts.Node,
        language: Language,
        tainted: dict[str, TaintRecord],
        findings: list[Finding],
        filename: str,
    ) -> None:
        """Check if any tainted variable flows to a sink at this node."""
        node_text = node.text.decode("utf-8") if node.text else ""
        sink = self._find_sink_in_text(node_text, language)
        if sink is None:
            return

        args = self._extract_call_args_from_text(node_text)
        self._report_tainted_args(args, node_text, sink, node, tainted, findings, filename)

    def _report_tainted_args(
        self,
        args: list[str],
        node_text: str,
        sink: TaintSink,
        node: ts.Node,
        tainted: dict[str, TaintRecord],
        findings: list[Finding],
        filename: str,
    ) -> None:
        """Generate findings for tainted arguments flowing to sinks."""
        sink_line = node.start_point.row + 1
        if not args:
            self._check_inline_taint("", node_text, sink, sink_line, tainted, findings, filename)
            return
        for arg in args:
            record = tainted.get(arg)
            if record is None:
                self._check_inline_taint(arg, node_text, sink, sink_line, tainted, findings, filename)
                continue
            findings.append(self._build_finding(record, sink, sink_line, filename))

    def _check_inline_taint(
        self,
        arg: str,
        node_text: str,
        sink: TaintSink,
        sink_line: int,
        tainted: dict[str, TaintRecord],
        findings: list[Finding],
        filename: str,
    ) -> None:
        """Check if tainted vars appear inline in f-strings or concatenation."""
        for var_name, record in tainted.items():
            if var_name in node_text:
                findings.append(self._build_finding(record, sink, sink_line, filename))
                break

    def _build_finding(
        self,
        record: TaintRecord,
        sink: TaintSink,
        sink_line: int,
        filename: str,
    ) -> Finding:
        """Build a Finding from a taint record and sink match."""
        chain_str = " -> ".join(record.chain)
        confidence = TAINT_CONFIDENCE_SANITIZED if record.sanitized else TAINT_CONFIDENCE_HIGH
        severity = Severity.WARN if record.sanitized else Severity.BLOCK

        return Finding(
            rule_id=f"taint_{sink.category}",
            severity=severity,
            message=(
                f"Tainted data from `{record.source.name}` (line {record.source_line}) "
                f"flows to `{sink.name}` (line {sink_line}) via variable chain: {chain_str}"
            ),
            file=filename,
            line=sink_line,
            suggestion=_suggestion_for_category(sink.category),
            confidence=confidence,
        )

    def _find_source_in_text(
        self,
        text: str,
        language: Language,
    ) -> TaintSource | None:
        """Check if text contains a taint source pattern."""
        sources = TAINT_SOURCES.get(language, ())
        for source in sources:
            if source.pattern in text:
                return source
        return None

    def _find_sink_in_text(
        self,
        text: str,
        language: Language,
    ) -> TaintSink | None:
        """Check if text contains a taint sink pattern."""
        sinks = TAINT_SINKS.get(language, ())
        for sink in sinks:
            if sink.pattern in text:
                return sink
        return None

    def _find_sanitizer_in_text(
        self,
        text: str,
        language: Language,
    ) -> TaintSanitizer | None:
        """Check if text contains a sanitizer pattern."""
        sanitizers = TAINT_SANITIZERS.get(language, ())
        for sanitizer in sanitizers:
            if sanitizer.pattern in text:
                return sanitizer
        return None

    def _extract_assigned_var(
        self,
        node: ts.Node,
        language: Language,
    ) -> str | None:
        """Extract the variable name from an assignment node."""
        nodes_def = LANGUAGE_NODES.get(language)
        if nodes_def is None:
            return None

        if node.type not in nodes_def.simple_assignment_types:
            return None

        return self._get_identifier_from_assignment(node, nodes_def.identifier_type)

    def _get_identifier_from_assignment(
        self,
        node: ts.Node,
        identifier_type: str,
    ) -> str | None:
        """Get the first identifier child text from an assignment node."""
        for child in node.children:
            if child.type == identifier_type:
                return child.text.decode("utf-8") if child.text else None
        return None

    def _extract_rhs_text(
        self,
        node: ts.Node,
        language: Language,
    ) -> str | None:
        """Extract the right-hand side text of an assignment."""
        node_text = node.text.decode("utf-8") if node.text else ""
        if not node_text:
            return None

        if language in (Language.PYTHON,):
            return self._extract_python_rhs(node_text)
        if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            return self._extract_js_rhs(node_text)
        return node_text

    def _extract_python_rhs(self, text: str) -> str | None:
        """Extract RHS from a Python assignment text."""
        eq_pos = text.find("=")
        if eq_pos < 0:
            return None
        return text[eq_pos + 1:].strip()

    def _extract_js_rhs(self, text: str) -> str | None:
        """Extract RHS from a JS/TS variable declarator text."""
        eq_pos = text.find("=")
        if eq_pos < 0:
            return None
        return text[eq_pos + 1:].strip()

    def _extract_call_args(self, call_node: ts.Node) -> list[str]:
        """Extract argument variable names from a function call node."""
        args: list[str] = []
        arg_list = call_node.child_by_field_name("arguments")
        if arg_list is None:
            return args
        for child in arg_list.children:
            if child.type == "identifier" and child.text:
                args.append(child.text.decode("utf-8"))
        return args

    def _extract_call_args_from_text(self, text: str) -> list[str]:
        """Extract argument identifiers from call text heuristically."""
        paren_start = text.find("(")
        if paren_start < 0:
            return []
        paren_end = text.rfind(")")
        if paren_end < 0:
            return []
        inner = text[paren_start + 1:paren_end].strip()
        if not inner:
            return []
        return [arg.strip() for arg in inner.split(",") if arg.strip()]


# ═══════════════════════════════════════════════════════════════
#  Category-specific remediation suggestions
# ═══════════════════════════════════════════════════════════════

_CATEGORY_SUGGESTIONS: dict[str, str] = {
    "sql_injection": "Use parameterized queries (e.g., cursor.execute('SELECT ... WHERE id = ?', (user_id,)))",
    "command_injection": "Use subprocess.run with shell=False and pass arguments as a list",
    "xss": "Sanitize output with markupsafe.escape() or a DOM sanitizer before rendering",
    "path_traversal": "Validate and sanitize file paths; use os.path.realpath() and check against an allow-list",
    "ssrf": "Validate URLs against an allow-list of domains before making requests",
    "deserialization": "Avoid deserializing untrusted data; use JSON with schema validation instead",
}


def _suggestion_for_category(category: str) -> str:
    """Return a remediation suggestion for a taint category."""
    return _CATEGORY_SUGGESTIONS.get(category, "Sanitize untrusted input before use")
