# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Intra-, inter-procedural, and cross-file taint analysis using tree-sitter AST.

Tracks data flow from untrusted sources (e.g., request parameters)
to dangerous sinks (e.g., SQL queries, OS commands) within and across
function bodies and file boundaries. Reports findings when tainted data
reaches a sink without sanitization.

Single-file analysis works in two phases:
  Phase 1 — Build a summary for each function: which parameters carry
            taint from sources, and whether the return value is tainted.
  Phase 2 — Re-analyze functions using summaries so that call-site
            results inherit callee taint information.

Cross-file analysis extends this with additional phases:
  Phase 1 — Build per-file function summaries.
  Phase 2 — Build cross-file import map (which file imports what).
  Phase 3 — Merge imported function summaries into each file's context.
  Phase 4 — Re-analyze each file with merged summaries to detect
            cross-file taint flows.
"""

import re
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

# Synthetic source used during summary building to mark parameters
# as hypothetically tainted for sink-reachability analysis.
_PARAM_TAINT_SOURCE = TaintSource(
    name="__parameter__",
    pattern="__never_matches__",
    language=Language.PYTHON,
    description="Synthetic source for parameter taint tracking",
)


@dataclass
class TaintRecord:
    """Tracks a tainted variable and its provenance."""

    var_name: str
    source: TaintSource
    source_line: int
    chain: list[str] = field(default_factory=list)
    sanitized: bool = False


@dataclass
class FunctionSummary:
    """Inter-procedural summary for a single function.

    Captures whether the function returns tainted data and which
    parameters flow into sinks, enabling cross-function taint tracking.
    """

    name: str
    param_names: list[str] = field(default_factory=list)
    returns_taint: bool = False
    taint_source: TaintSource | None = None
    taint_source_line: int = 0
    params_reaching_sinks: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class CrossFileImport:
    """A resolved cross-file import mapping a local name to a source file.

    Captures e.g. ``from utils import get_user_data`` as:
        local_name='get_user_data', source_file='utils.py',
        original_name='get_user_data'
    """

    local_name: str
    source_file: str
    original_name: str


# Maximum fixpoint iterations for cross-file summary merging.
_MAX_CROSS_FILE_ITERATIONS = 10

# Regex for Python ``from <module> import <names>`` statements.
_PYTHON_FROM_IMPORT_RE = re.compile(
    r"^\s*from\s+([\w.]+)\s+import\s+(.+)$",
    re.MULTILINE,
)


class TaintAnalyzer:
    """Intra-, inter-procedural, and cross-file taint analysis."""

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

        Parses the code into a tree-sitter AST, then performs two passes:
        1. Build function summaries (intra-procedural taint per function).
        2. Re-analyze with inter-procedural call-site taint propagation.
        """
        func_nodes = self._parse_function_nodes(code, language)
        if func_nodes is None:
            return []

        summaries = self._build_all_summaries(func_nodes, language)
        findings = self._run_interprocedural_pass(
            func_nodes, summaries, language, filename,
        )

        logger.info(
            "taint_analysis_complete",
            filename=filename,
            language=str(language),
            total_findings=len(findings),
        )
        return findings

    # ═══════════════════════════════════════════════════════════════
    #  Cross-file (project-level) taint analysis
    # ═══════════════════════════════════════════════════════════════

    def analyze_project(
        self,
        files: dict[str, str],
        language: Language,
    ) -> list[Finding]:
        """Run cross-file taint analysis on a set of project files.

        Tracks tainted data across import boundaries: if file A exports
        a function that returns tainted data and file B imports and calls
        that function, the taint propagates across the file boundary.

        Args:
            files: Dict mapping filepath to source code content.
            language: The programming language for all files.

        Returns:
            List of findings including cross-file taint flows.
        """
        per_file_summaries = self._build_per_file_summaries(files, language)
        import_map = self._build_cross_file_import_map(files, language)
        merged = self._merge_cross_file_summaries(
            per_file_summaries, import_map,
        )
        return self._run_cross_file_analysis(
            files, language, merged,
        )

    def _build_per_file_summaries(
        self,
        files: dict[str, str],
        language: Language,
    ) -> dict[str, dict[str, FunctionSummary]]:
        """Phase 1: build function summaries per file.

        Returns a dict mapping filepath -> {func_name: FunctionSummary}.
        """
        result: dict[str, dict[str, FunctionSummary]] = {}
        for filepath, code in files.items():
            func_nodes = self._parse_function_nodes(code, language)
            if func_nodes is None:
                result[filepath] = {}
                continue
            summaries = self._build_all_summaries(func_nodes, language)
            result[filepath] = summaries
        return result

    def _build_cross_file_import_map(
        self,
        files: dict[str, str],
        language: Language,
    ) -> dict[str, list[CrossFileImport]]:
        """Phase 2: build import map — which file imports what from where.

        Returns a dict mapping filepath -> list of CrossFileImport.
        Currently supports Python ``from <module> import <name>`` syntax.
        """
        if language != Language.PYTHON:
            return {}

        return self._extract_python_cross_file_imports(files)

    def _extract_python_cross_file_imports(
        self,
        files: dict[str, str],
    ) -> dict[str, list[CrossFileImport]]:
        """Extract Python cross-file imports for all project files.

        Resolves ``from <module> import <name>`` to a source file within
        the project, using simple name matching against known filenames.
        """
        import_map: dict[str, list[CrossFileImport]] = {}

        for filepath, code in files.items():
            imports = self._parse_python_from_imports(code, files)
            if imports:
                import_map[filepath] = imports

        return import_map

    def _parse_python_from_imports(
        self,
        code: str,
        all_files: dict[str, str],
    ) -> list[CrossFileImport]:
        """Parse ``from X import Y`` statements and resolve to project files."""
        imports: list[CrossFileImport] = []

        for match in _PYTHON_FROM_IMPORT_RE.finditer(code):
            module_name = match.group(1)
            names_str = match.group(2).strip()

            source_file = self._resolve_module_to_file(
                module_name, all_files,
            )
            if source_file is None:
                continue

            imported_names = self._parse_import_names(names_str)
            for name in imported_names:
                imports.append(CrossFileImport(
                    local_name=name,
                    source_file=source_file,
                    original_name=name,
                ))

        return imports

    def _resolve_module_to_file(
        self,
        module_name: str,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve a Python module name to a filepath in the project.

        Tries common patterns: ``module.py``, ``module/__init__.py``,
        and dotted paths like ``pkg.module`` -> ``pkg/module.py``.
        """
        module_path = module_name.replace(".", "/")
        candidates = [
            f"{module_path}.py",
            f"{module_path}/__init__.py",
        ]

        # Also try just the last segment for flat layouts.
        last_segment = module_name.rsplit(".", maxsplit=1)[-1]
        candidates.append(f"{last_segment}.py")

        for candidate in candidates:
            if candidate in all_files:
                return candidate

        return None

    def _parse_import_names(self, names_str: str) -> list[str]:
        """Parse the imported names from the RHS of a from-import statement.

        Handles ``from x import a, b, c`` and ``from x import (a, b, c)``.
        Strips ``as`` aliases, using the alias as the local name.
        """
        # Remove parentheses if present.
        cleaned = names_str.strip("() \t\n")
        if not cleaned:
            return []

        names: list[str] = []
        for part in cleaned.split(","):
            part = part.strip()
            if not part:
                continue
            # Handle ``name as alias`` — use the alias as local name.
            if " as " in part:
                alias = part.split(" as ")[-1].strip()
                names.append(alias)
            else:
                names.append(part)

        return names

    def _merge_cross_file_summaries(
        self,
        per_file_summaries: dict[str, dict[str, FunctionSummary]],
        import_map: dict[str, list[CrossFileImport]],
    ) -> dict[str, dict[str, FunctionSummary]]:
        """Phase 3: merge imported function summaries into each file's context.

        For each file, if it imports a function from another file, the
        callee's FunctionSummary is added to the importing file's summary
        map so that call-site taint propagation works cross-file.

        Iterates to a fixpoint to handle transitive chains (A->B->C).
        """
        merged: dict[str, dict[str, FunctionSummary]] = {
            fp: dict(sums) for fp, sums in per_file_summaries.items()
        }

        for _ in range(_MAX_CROSS_FILE_ITERATIONS):
            changed = False
            for filepath, imports in import_map.items():
                file_summaries = merged.get(filepath, {})
                for imp in imports:
                    source_summaries = merged.get(imp.source_file, {})
                    source_summary = source_summaries.get(imp.original_name)
                    if source_summary is None:
                        continue

                    existing = file_summaries.get(imp.local_name)
                    if (
                        existing is not None
                        and existing.returns_taint == source_summary.returns_taint
                        and existing.params_reaching_sinks == source_summary.params_reaching_sinks
                    ):
                        continue

                    # Create a copy with the local name for the importing file.
                    imported_summary = FunctionSummary(
                        name=imp.local_name,
                        param_names=list(source_summary.param_names),
                        returns_taint=source_summary.returns_taint,
                        taint_source=source_summary.taint_source,
                        taint_source_line=source_summary.taint_source_line,
                        params_reaching_sinks=dict(source_summary.params_reaching_sinks),
                    )
                    file_summaries[imp.local_name] = imported_summary
                    merged[filepath] = file_summaries
                    changed = True

            if not changed:
                break

        return merged

    def _run_cross_file_analysis(
        self,
        files: dict[str, str],
        language: Language,
        merged_summaries: dict[str, dict[str, FunctionSummary]],
    ) -> list[Finding]:
        """Phase 4: re-analyze each file with cross-file summaries.

        Uses the merged summary map (including imported function summaries)
        so that calls to imported functions propagate taint correctly.
        """
        all_findings: list[Finding] = []

        for filepath, code in files.items():
            func_nodes = self._parse_function_nodes(code, language)
            if func_nodes is None:
                continue

            file_summaries = merged_summaries.get(filepath, {})
            findings = self._run_interprocedural_pass(
                func_nodes, file_summaries, language, filepath,
            )
            all_findings.extend(findings)

        logger.info(
            "cross_file_taint_analysis_complete",
            total_files=len(files),
            total_findings=len(all_findings),
        )
        return all_findings

    # ═══════════════════════════════════════════════════════════════
    #  Single-file parsing and analysis helpers
    # ═══════════════════════════════════════════════════════════════

    def _parse_function_nodes(
        self,
        code: str,
        language: Language,
    ) -> list[ts.Node] | None:
        """Parse source code and return function AST nodes, or None."""
        ts_lang = self._get_ts_language(language)
        if ts_lang is None:
            return None

        parser = ts.Parser(ts_lang)
        tree = parser.parse(bytes(code, "utf-8"))

        nodes = LANGUAGE_NODES.get(language)
        if nodes is None:
            return None

        return _find_nodes_by_type(tree.root_node, nodes.function_types)

    def _run_interprocedural_pass(
        self,
        func_nodes: list[ts.Node],
        summaries: dict[str, FunctionSummary],
        language: Language,
        filename: str,
    ) -> list[Finding]:
        """Phase 2: analyze all functions with inter-procedural summaries."""
        findings: list[Finding] = []
        for func_node in func_nodes:
            findings.extend(
                self._analyze_function(func_node, language, filename, summaries)
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
        summaries: dict[str, FunctionSummary] | None = None,
    ) -> list[Finding]:
        """Analyze a single function for source-to-sink data flow."""
        tainted: dict[str, TaintRecord] = {}
        findings: list[Finding] = []

        for node in _walk_tree(func_node):
            self._process_assignment(node, language, tainted, summaries)
            self._check_sinks(node, language, tainted, findings, filename)
            self._check_callsite_sinks(node, tainted, summaries, findings, filename)

        return self._deduplicate_findings(findings)

    @staticmethod
    def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by (rule_id, line, source reference)."""
        seen: set[tuple[str, int, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.rule_id, f.line, f.message)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _process_assignment(
        self,
        node: ts.Node,
        language: Language,
        tainted: dict[str, TaintRecord],
        summaries: dict[str, FunctionSummary] | None = None,
    ) -> None:
        """Check if a node is an assignment and update taint state."""
        var_name = self._extract_assigned_var(node, language)
        if var_name is None:
            return

        rhs_text = self._extract_rhs_text(node, language)
        if rhs_text is None:
            return

        self._check_source_assignment(var_name, rhs_text, node, language, tainted)
        self._check_callsite_taint(var_name, rhs_text, node, tainted, summaries)
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
                # Sanitized if: (a) this RHS applies a sanitizer, or
                # (b) the source record was already sanitized.
                is_sanitized = sanitizer is not None or record.sanitized
                tainted[var_name] = TaintRecord(
                    var_name=var_name,
                    source=record.source,
                    source_line=record.source_line,
                    chain=new_chain,
                    sanitized=is_sanitized,
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

        # Parameterized SQL breaks taint — %s or ? placeholders mean safe usage
        if sink.category == "sql_injection" and _is_parameterized_query(node_text):
            return

        if not args:
            self._check_inline_taint("", node_text, sink, sink_line, tainted, findings, filename)
            return
        for arg in args:
            record = tainted.get(arg)
            if record is None:
                self._check_inline_taint(arg, node_text, sink, sink_line, tainted, findings, filename)
                continue
            if record.sanitized:
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
        """Check if tainted vars appear inline in f-strings or concatenation.

        Uses word-boundary matching to avoid false positives from variable
        names appearing inside string literals (e.g., 'amount' in SQL text).
        """
        # Strip quoted strings to avoid matching var names inside literals
        stripped = _strip_string_literals(node_text)
        for var_name, record in tainted.items():
            if record.sanitized:
                continue
            if re.search(rf"\b{re.escape(var_name)}\b", stripped):
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

    # ═══════════════════════════════════════════════════════════════
    #  Inter-procedural analysis: summaries and call-site propagation
    # ═══════════════════════════════════════════════════════════════

    def _build_all_summaries(
        self,
        func_nodes: list[ts.Node],
        language: Language,
    ) -> dict[str, FunctionSummary]:
        """Build taint summaries for all functions, iterating to a fixpoint.

        First pass uses no inter-procedural context. Subsequent passes
        feed current summaries into assignment processing so call-site
        taint propagates transitively (A -> B -> C chains).
        """
        summaries: dict[str, FunctionSummary] = {}
        # Initial pass without summaries
        for func_node in func_nodes:
            summary = self._build_function_summary(func_node, language, None)
            if summary is not None:
                summaries[summary.name] = summary

        # Iterate until no new taint-returning functions are discovered
        max_iterations = len(func_nodes) + 1
        for _ in range(max_iterations):
            changed = False
            for func_node in func_nodes:
                summary = self._build_function_summary(
                    func_node, language, summaries,
                )
                if summary is None:
                    continue
                prev = summaries.get(summary.name)
                if prev is not None and prev.returns_taint == summary.returns_taint:
                    continue
                if summary.returns_taint and (prev is None or not prev.returns_taint):
                    changed = True
                summaries[summary.name] = summary
            if not changed:
                break

        return summaries

    def _build_function_summary(
        self,
        func_node: ts.Node,
        language: Language,
        summaries: dict[str, FunctionSummary] | None,
    ) -> FunctionSummary | None:
        """Build a taint summary for a single function.

        Records whether the return value carries taint from any source,
        and which parameters flow into sinks within the function body.
        Uses two taint maps: one for real sources (return-taint) and one
        with params seeded as hypothetically tainted (sink-reachability).
        """
        func_name = self._extract_function_name(func_node)
        if func_name is None:
            return None

        param_names = self._extract_param_names(func_node)

        # Real taint map for return-value analysis
        tainted: dict[str, TaintRecord] = {}
        for node in _walk_tree(func_node):
            self._process_assignment(node, language, tainted, summaries)

        # Param-seeded taint map for sink-reachability analysis
        param_tainted = self._build_param_seeded_taint(
            func_node, param_names, language, summaries,
        )

        return self._summarize_taint_state(
            func_name, param_names, func_node, tainted, param_tainted, language,
        )

    def _build_param_seeded_taint(
        self,
        func_node: ts.Node,
        param_names: list[str],
        language: Language,
        summaries: dict[str, FunctionSummary] | None,
    ) -> dict[str, TaintRecord]:
        """Build taint map with parameters seeded as hypothetically tainted."""
        param_tainted: dict[str, TaintRecord] = {}
        for param in param_names:
            param_tainted[param] = TaintRecord(
                var_name=param,
                source=_PARAM_TAINT_SOURCE,
                source_line=0,
                chain=[param],
            )
        for node in _walk_tree(func_node):
            self._process_assignment(node, language, param_tainted, summaries)
        return param_tainted

    def _summarize_taint_state(
        self,
        func_name: str,
        param_names: list[str],
        func_node: ts.Node,
        tainted: dict[str, TaintRecord],
        param_tainted: dict[str, TaintRecord],
        language: Language,
    ) -> FunctionSummary:
        """Create a FunctionSummary from the taint state of a function."""
        summary = FunctionSummary(name=func_name, param_names=param_names)

        # Check if any return statement carries taint (real sources only)
        self._check_return_taint(func_node, tainted, summary, language)

        # Check which parameters flow to sinks (param-seeded map)
        self._check_params_reaching_sinks(func_node, param_tainted, language, summary)

        return summary

    def _check_return_taint(
        self,
        func_node: ts.Node,
        tainted: dict[str, TaintRecord],
        summary: FunctionSummary,
        language: Language | None = None,
    ) -> None:
        """Check if any return statement in the function returns tainted data."""
        for node in _walk_tree(func_node):
            if node.type != "return_statement":
                continue
            return_text = node.text.decode("utf-8") if node.text else ""
            # Check if return value is a tainted variable
            for var_name, record in tainted.items():
                if var_name in return_text:
                    summary.returns_taint = True
                    summary.taint_source = record.source
                    summary.taint_source_line = record.source_line
                    return
            # Check if return value is a direct source call
            if language is not None:
                source = self._find_source_in_text(return_text, language)
                if source is not None:
                    summary.returns_taint = True
                    summary.taint_source = source
                    summary.taint_source_line = node.start_point.row + 1
                    return

    def _check_params_reaching_sinks(
        self,
        func_node: ts.Node,
        tainted: dict[str, TaintRecord],
        language: Language,
        summary: FunctionSummary,
    ) -> None:
        """Check which tainted parameters reach sinks in the function."""
        for node in _walk_tree(func_node):
            node_text = node.text.decode("utf-8") if node.text else ""
            sink = self._find_sink_in_text(node_text, language)
            if sink is None:
                continue
            for var_name, record in tainted.items():
                if var_name not in node_text:
                    continue
                for param in summary.param_names:
                    if param in record.chain or param == var_name:
                        summary.params_reaching_sinks[param] = sink.category

    def _check_callsite_taint(
        self,
        var_name: str,
        rhs_text: str,
        node: ts.Node,
        tainted: dict[str, TaintRecord],
        summaries: dict[str, FunctionSummary] | None,
    ) -> None:
        """Propagate taint through a function call using callee summaries.

        If the RHS of an assignment is a call to a function whose summary
        indicates it returns tainted data, mark the LHS variable as tainted.
        """
        if summaries is None:
            return
        if var_name in tainted:
            return

        callee_name = self._extract_callee_name(rhs_text)
        if callee_name is None:
            return

        summary = summaries.get(callee_name)
        if summary is None:
            return

        if not summary.returns_taint:
            return
        if summary.taint_source is None:
            return

        tainted[var_name] = TaintRecord(
            var_name=var_name,
            source=summary.taint_source,
            source_line=summary.taint_source_line,
            chain=[f"{callee_name}()", var_name],
        )

    def _check_callsite_sinks(
        self,
        node: ts.Node,
        tainted: dict[str, TaintRecord],
        summaries: dict[str, FunctionSummary] | None,
        findings: list[Finding],
        filename: str,
    ) -> None:
        """Detect tainted args passed to functions with sink-reachable params.

        If a call passes a tainted variable as an argument that the callee
        routes to a sink, generate a finding at the call site.
        """
        if summaries is None:
            return
        if node.type not in ("call", "expression_statement"):
            return

        node_text = node.text.decode("utf-8") if node.text else ""
        callee_name = self._extract_callee_name(node_text)
        if callee_name is None:
            return

        summary = summaries.get(callee_name)
        if summary is None or not summary.params_reaching_sinks:
            return

        call_args = self._extract_call_args_from_text(node_text)
        self._match_tainted_args_to_params(
            call_args, summary, tainted, node, findings, filename,
        )

    def _match_tainted_args_to_params(
        self,
        call_args: list[str],
        summary: FunctionSummary,
        tainted: dict[str, TaintRecord],
        node: ts.Node,
        findings: list[Finding],
        filename: str,
    ) -> None:
        """Match tainted call arguments to sink-reachable callee parameters."""
        for idx, arg in enumerate(call_args):
            record = tainted.get(arg)
            if record is None:
                continue
            if idx >= len(summary.param_names):
                continue
            param_name = summary.param_names[idx]
            sink_category = summary.params_reaching_sinks.get(param_name)
            if sink_category is None:
                continue
            sink_line = node.start_point.row + 1
            findings.append(Finding(
                rule_id=f"taint_{sink_category}",
                severity=Severity.BLOCK,
                message=(
                    f"Tainted data from `{record.source.name}` "
                    f"(line {record.source_line}) flows to sink in "
                    f"`{summary.name}()` via parameter `{param_name}` "
                    f"(line {sink_line})"
                ),
                file=filename,
                line=sink_line,
                suggestion=_suggestion_for_category(sink_category),
                confidence=TAINT_CONFIDENCE_HIGH,
            ))

    def _extract_function_name(self, func_node: ts.Node) -> str | None:
        """Extract the function name from a function definition node."""
        name_node = func_node.child_by_field_name("name")
        if name_node is not None and name_node.text:
            return name_node.text.decode("utf-8")
        return None

    def _extract_param_names(self, func_node: ts.Node) -> list[str]:
        """Extract parameter names from a function definition node."""
        params_node = func_node.child_by_field_name("parameters")
        if params_node is None:
            return []

        param_names: list[str] = []
        for child in _walk_tree(params_node):
            if child.type == "identifier" and child.text:
                param_names.append(child.text.decode("utf-8"))
        return param_names

    def _extract_callee_name(self, rhs_text: str) -> str | None:
        """Extract the function name from a call expression text.

        Given text like ``get_user_input(request)``, returns
        ``get_user_input``. Returns None if no call is detected.
        """
        paren_pos = rhs_text.find("(")
        if paren_pos < 0:
            return None
        callee = rhs_text[:paren_pos].strip()
        if not callee:
            return None
        # Take the last dotted segment for method calls
        parts = callee.split(".")
        return parts[-1] if parts[-1] else None

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
        """Get the first identifier child text from an assignment node.

        Handles both direct identifier children (Python, JS) and
        identifiers nested inside expression_list (Go short_var_declaration).
        """
        for child in node.children:
            if child.type == identifier_type:
                return child.text.decode("utf-8") if child.text else None
            # Go wraps LHS identifiers in expression_list
            if child.type == "expression_list":
                for sub in child.children:
                    if sub.type == identifier_type:
                        return sub.text.decode("utf-8") if sub.text else None
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
        if language == Language.GO:
            return self._extract_go_rhs(node_text)
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

    def _extract_go_rhs(self, text: str) -> str | None:
        """Extract RHS from a Go short variable declaration (`:=`).

        Handles both `x := expr` and `x, err := expr` forms.
        """
        assign_pos = text.find(":=")
        if assign_pos >= 0:
            return text[assign_pos + 2:].strip()
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
#  Parameterized query detection
# ═══════════════════════════════════════════════════════════════

_PARAMETERIZED_PATTERNS = re.compile(
    r"%s|%\(|"          # Python DB-API: %s, %(name)s
    r"\?\s*[,)]|"       # SQLite/JDBC: ? placeholders
    r"\$\d+|"           # PostgreSQL: $1, $2
    r":\w+"             # SQLAlchemy named: :param
)


def _is_parameterized_query(text: str) -> bool:
    """Detect parameterized SQL patterns that neutralize injection risk."""
    return bool(_PARAMETERIZED_PATTERNS.search(text))


# ═══════════════════════════════════════════════════════════════
#  String literal stripping for accurate taint matching
# ═══════════════════════════════════════════════════════════════

_STRING_LITERAL_RE = re.compile(
    r'"""[\s\S]*?"""|'   # Triple-double-quoted
    r"'''[\s\S]*?'''|"   # Triple-single-quoted
    r'"[^"\\]*(?:\\.[^"\\]*)*"|'  # Double-quoted
    r"'[^'\\]*(?:\\.[^'\\]*)*'"   # Single-quoted
)

_FSTRING_EXPR_RE = re.compile(r"\{(\w+)(?:\}|[.!\[])")


def _strip_string_literals(text: str) -> str:
    """Replace string literal content with placeholders.

    Preserves f-string interpolation variable names so taint tracking
    can detect flows like ``f"SELECT ... {user_id}"``.
    """
    # First extract f-string variable references before stripping
    fstring_vars = set(_FSTRING_EXPR_RE.findall(text))
    stripped = _STRING_LITERAL_RE.sub('""', text)
    # Re-inject f-string variable names so they're visible to taint matching
    if fstring_vars:
        stripped += " " + " ".join(fstring_vars)
    return stripped


# ═══════════════════════════════════════════════════════════════
#  Category-specific remediation suggestions
# ═══════════════════════════════════════════════════════════════

_CATEGORY_SUGGESTIONS: dict[str, str] = {
    "sql_injection": "Use parameterized queries (e.g., cursor.execute('SELECT ... WHERE id = ?', (user_id,)))",
    "command_injection": "Use subprocess.run with shell=False and pass arguments as a list",
    "code_injection": "Never pass untrusted data to eval(); use ast.literal_eval() for safe evaluation",
    "xss": "Sanitize output with markupsafe.escape() or a DOM sanitizer before rendering",
    "path_traversal": "Validate and sanitize file paths; use os.path.realpath() and check against an allow-list",
    "ssrf": "Validate URLs against an allow-list of domains before making requests",
    "deserialization": "Avoid deserializing untrusted data; use JSON with schema validation instead",
    "ldap_injection": "Use parameterized LDAP filters or escape special chars with ldap.filter.escape_filter_chars()",
}


def _suggestion_for_category(category: str) -> str:
    """Return a remediation suggestion for a taint category."""
    return _CATEGORY_SUGGESTIONS.get(category, "Sanitize untrusted input before use")
