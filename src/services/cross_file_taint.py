# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Cross-file taint analysis — tracks data flow across import boundaries.

Combines the import graph from CrossFileAnalyzer with the intra-file
taint summaries from TaintAnalyzer to detect taint flows that cross
file boundaries. Supports Python, JavaScript/TypeScript, and Go.

Example: File A exports a function that reads user input. File B
imports that function and passes its return value to a SQL query.
This module detects that cross-file taint chain.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from src.models.enums import Language, Severity
from src.models.responses import Finding
from src.services.cross_file_analyzer import (
    CrossFileAnalyzer,
    ImportEdge,
    detect_language_from_extension,
)
from src.services.taint_analyzer import FunctionSummary, TaintAnalyzer

if TYPE_CHECKING:
    from src.rules.taint_rules import TaintSource

logger = structlog.get_logger()

# Maximum files to analyze for cross-file taint (safety limit).
MAX_TAINT_FILES = 200

# Confidence level for cross-file taint findings.
CROSS_FILE_TAINT_CONFIDENCE = 0.85


@dataclass(frozen=True)
class ExportedSymbol:
    """A function or variable exported from a file."""

    name: str
    file: str
    summary: FunctionSummary | None = None
    is_taint_source: bool = False
    taint_source: TaintSource | None = None
    source_line: int = 0


@dataclass
class CrossFileTaintResult:
    """Result of cross-file taint analysis."""

    findings: list[Finding] = field(default_factory=list)
    total_files: int = 0
    total_exports: int = 0
    tainted_exports: int = 0
    cross_file_flows: int = 0


class CrossFileTaintAnalyzer:
    """Tracks taint data flow across file import boundaries.

    Performs three-phase analysis:
      Phase 1 — Build per-file taint summaries using TaintAnalyzer.
      Phase 2 — Extract exports and match them to import edges.
      Phase 3 — Propagate taint across the import graph, generating
                findings when tainted data from file A reaches a
                sink in file B.
    """

    def __init__(self) -> None:
        """Initialize the cross-file taint analyzer."""
        self._taint_analyzer = TaintAnalyzer()
        self._graph_analyzer = CrossFileAnalyzer()

    def analyze(
        self,
        file_contents: dict[str, str],
        file_languages: dict[str, Language] | None = None,
    ) -> CrossFileTaintResult:
        """Run cross-file taint analysis on a set of project files.

        Args:
            file_contents: Map of relative filepath to file source code.
            file_languages: Optional map of filepath to language.
                If not provided, language is detected from file extension.

        Returns:
            CrossFileTaintResult with findings and metrics.
        """
        if len(file_contents) > MAX_TAINT_FILES:
            logger.warning(
                "cross_file_taint_too_many_files",
                count=len(file_contents),
                limit=MAX_TAINT_FILES,
            )
            file_contents = dict(list(file_contents.items())[:MAX_TAINT_FILES])

        languages = self._detect_languages(file_contents, file_languages)
        graph_result = self._graph_analyzer.analyze_project(
            file_contents, languages,
        )

        summaries_by_file = self._build_file_summaries(
            file_contents, languages,
        )
        exports = self._extract_all_exports(
            file_contents, languages, summaries_by_file,
        )
        findings = self._propagate_cross_file_taint(
            file_contents, languages, summaries_by_file, exports,
        )

        tainted_count = sum(
            1 for exp in exports.values()
            if any(s.is_taint_source or (s.summary and s.summary.returns_taint) for s in exp)
        )

        result = CrossFileTaintResult(
            findings=findings,
            total_files=graph_result.total_files,
            total_exports=sum(len(v) for v in exports.values()),
            tainted_exports=tainted_count,
            cross_file_flows=len(findings),
        )

        logger.info(
            "cross_file_taint_complete",
            total_files=result.total_files,
            total_exports=result.total_exports,
            tainted_exports=result.tainted_exports,
            findings=len(findings),
        )
        return result

    def _detect_languages(
        self,
        file_contents: dict[str, str],
        file_languages: dict[str, Language] | None,
    ) -> dict[str, Language]:
        """Detect languages for all files."""
        languages: dict[str, Language] = {}
        for filepath in file_contents:
            if file_languages and filepath in file_languages:
                languages[filepath] = file_languages[filepath]
            else:
                lang = detect_language_from_extension(filepath)
                if lang is not None:
                    languages[filepath] = lang
        return languages

    def _build_file_summaries(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> dict[str, dict[str, FunctionSummary]]:
        """Build taint summaries for all functions in all files.

        Returns a map of filepath -> {func_name -> FunctionSummary}.
        """
        summaries_by_file: dict[str, dict[str, FunctionSummary]] = {}
        for filepath, content in file_contents.items():
            lang = languages.get(filepath)
            if lang is None:
                continue
            summaries = self._build_single_file_summaries(content, lang)
            if summaries:
                summaries_by_file[filepath] = summaries
        return summaries_by_file

    def _build_single_file_summaries(
        self,
        code: str,
        language: Language,
    ) -> dict[str, FunctionSummary]:
        """Build taint summaries for a single file."""
        func_nodes = self._taint_analyzer._parse_function_nodes(
            code, language,
        )
        if func_nodes is None:
            return {}
        return self._taint_analyzer._build_all_summaries(
            func_nodes, language,
        )

    def _extract_all_exports(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
        summaries_by_file: dict[str, dict[str, FunctionSummary]],
    ) -> dict[str, list[ExportedSymbol]]:
        """Extract exported symbols from all files.

        Returns a map of filepath -> list of ExportedSymbol.
        """
        exports: dict[str, list[ExportedSymbol]] = {}
        for filepath, content in file_contents.items():
            lang = languages.get(filepath)
            if lang is None:
                continue
            summaries = summaries_by_file.get(filepath, {})
            file_exports = self._extract_file_exports(
                filepath, content, lang, summaries,
            )
            if file_exports:
                exports[filepath] = file_exports
        return exports

    def _extract_file_exports(
        self,
        filepath: str,
        code: str,
        language: Language,
        summaries: dict[str, FunctionSummary],
    ) -> list[ExportedSymbol]:
        """Extract exported symbols from a single file."""
        if language == Language.PYTHON:
            return self._extract_python_exports(
                filepath, code, summaries,
            )
        if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            return self._extract_js_ts_exports(
                filepath, code, summaries,
            )
        if language == Language.GO:
            return self._extract_go_exports(
                filepath, code, summaries,
            )
        return []

    def _extract_python_exports(
        self,
        filepath: str,
        code: str,
        summaries: dict[str, FunctionSummary],
    ) -> list[ExportedSymbol]:
        """Extract Python exports: all top-level functions are importable."""
        exports: list[ExportedSymbol] = []
        for name, summary in summaries.items():
            if name.startswith("_"):
                continue
            exports.append(ExportedSymbol(
                name=name,
                file=filepath,
                summary=summary,
                is_taint_source=summary.returns_taint,
                taint_source=summary.taint_source,
                source_line=summary.taint_source_line,
            ))
        return exports

    def _extract_js_ts_exports(
        self,
        filepath: str,
        code: str,
        summaries: dict[str, FunctionSummary],
    ) -> list[ExportedSymbol]:
        """Extract JS/TS exports from export declarations and module.exports.

        Detects:
        - `export function name()`
        - `export default function name()`
        - `export { name }`
        - `module.exports = { name }`
        - `module.exports.name = name`
        - `exports.name = name`
        """
        exports: list[ExportedSymbol] = []
        exported_names = self._find_js_exported_names(code)

        for name in exported_names:
            summary = summaries.get(name)
            is_source = summary.returns_taint if summary else False
            taint_src = summary.taint_source if summary else None
            src_line = summary.taint_source_line if summary else 0
            exports.append(ExportedSymbol(
                name=name,
                file=filepath,
                summary=summary,
                is_taint_source=is_source,
                taint_source=taint_src,
                source_line=src_line,
            ))
        return exports

    def _find_js_exported_names(self, code: str) -> set[str]:
        """Find all exported function/variable names in JS/TS code."""
        names: set[str] = set()

        # export function name() or export default function name()
        for match in re.finditer(
            r"export\s+(?:default\s+)?function\s+(\w+)", code,
        ):
            names.add(match.group(1))

        # export const/let/var name
        for match in re.finditer(
            r"export\s+(?:const|let|var)\s+(\w+)", code,
        ):
            names.add(match.group(1))

        # export { name1, name2 }
        for match in re.finditer(r"export\s*\{([^}]+)\}", code):
            for item in match.group(1).split(","):
                clean = item.strip().split(" as ")[0].strip()
                if clean:
                    names.add(clean)

        # module.exports = { name1, name2 } or module.exports.name = ...
        for match in re.finditer(r"module\.exports\s*=\s*\{([^}]+)\}", code):
            for item in match.group(1).split(","):
                clean = item.strip().split(":")[0].strip()
                if clean:
                    names.add(clean)

        for match in re.finditer(r"module\.exports\.(\w+)\s*=", code):
            names.add(match.group(1))

        # exports.name = ...
        for match in re.finditer(r"exports\.(\w+)\s*=", code):
            names.add(match.group(1))

        return names

    def _extract_go_exports(
        self,
        filepath: str,
        code: str,
        summaries: dict[str, FunctionSummary],
    ) -> list[ExportedSymbol]:
        """Extract Go exports: functions starting with uppercase are exported."""
        exports: list[ExportedSymbol] = []
        for name, summary in summaries.items():
            if not name or not name[0].isupper():
                continue
            exports.append(ExportedSymbol(
                name=name,
                file=filepath,
                summary=summary,
                is_taint_source=summary.returns_taint,
                taint_source=summary.taint_source,
                source_line=summary.taint_source_line,
            ))
        return exports

    def _propagate_cross_file_taint(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
        summaries_by_file: dict[str, dict[str, FunctionSummary]],
        exports: dict[str, list[ExportedSymbol]],
    ) -> list[Finding]:
        """Propagate taint across file boundaries using the import graph.

        For each import edge (file_a imports file_b), check if file_b
        exports tainted functions. If so, check if file_a calls those
        functions and passes the result to a sink.

        Go files in the same directory share package scope, so they are
        treated as implicit imports of each other.
        """
        findings: list[Finding] = []
        graph = self._graph_analyzer._graph

        # Standard import-graph-based propagation
        for _importing_file, edges in graph.edges.items():
            for edge in edges:
                target_exports = exports.get(edge.target_file, [])
                self._check_edge_taint(
                    edge, target_exports, file_contents,
                    languages, summaries_by_file, findings,
                )

        # Go same-package propagation: .go files in the same directory
        self._propagate_go_same_package(
            file_contents, languages, summaries_by_file,
            exports, findings,
        )
        return findings

    def _propagate_go_same_package(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
        summaries_by_file: dict[str, dict[str, FunctionSummary]],
        exports: dict[str, list[ExportedSymbol]],
        findings: list[Finding],
    ) -> None:
        """Propagate taint between Go files in the same directory (package)."""
        go_files_by_dir: dict[str, list[str]] = {}
        for filepath, lang in languages.items():
            if lang != Language.GO:
                continue
            directory = os.path.dirname(filepath) or "."
            if directory not in go_files_by_dir:
                go_files_by_dir[directory] = []
            go_files_by_dir[directory].append(filepath)

        for _directory, go_files in go_files_by_dir.items():
            if len(go_files) < 2:
                continue
            self._check_go_package_taint(
                go_files, file_contents, languages,
                summaries_by_file, exports, findings,
            )

    def _check_go_package_taint(
        self,
        go_files: list[str],
        file_contents: dict[str, str],
        languages: dict[str, Language],
        summaries_by_file: dict[str, dict[str, FunctionSummary]],
        exports: dict[str, list[ExportedSymbol]],
        findings: list[Finding],
    ) -> None:
        """Check all Go file pairs in a package for cross-file taint."""
        for source_file in go_files:
            source_exports = exports.get(source_file, [])
            for target_file in go_files:
                if target_file == source_file:
                    continue
                edge = ImportEdge(
                    source_file=target_file,
                    target_file=source_file,
                    import_name="<same-package>",
                    line=0,
                )
                self._check_edge_taint(
                    edge, source_exports, file_contents,
                    languages, summaries_by_file, findings,
                )

    def _check_edge_taint(
        self,
        edge: ImportEdge,
        target_exports: list[ExportedSymbol],
        file_contents: dict[str, str],
        languages: dict[str, Language],
        summaries_by_file: dict[str, dict[str, FunctionSummary]],
        findings: list[Finding],
    ) -> None:
        """Check a single import edge for cross-file taint flows."""
        importing_code = file_contents.get(edge.source_file, "")
        importing_lang = languages.get(edge.source_file)
        if not importing_code or importing_lang is None:
            return

        for export in target_exports:
            if not export.is_taint_source:
                continue
            if export.summary is None:
                continue
            self._check_export_usage_in_importer(
                export, edge, importing_code,
                importing_lang, summaries_by_file, findings,
            )

    def _check_export_usage_in_importer(
        self,
        export: ExportedSymbol,
        edge: ImportEdge,
        importing_code: str,
        importing_lang: Language,
        summaries_by_file: dict[str, dict[str, FunctionSummary]],
        findings: list[Finding],
    ) -> None:
        """Check if an importing file uses a tainted export unsafely."""
        # Check if the exported function name appears in the importing code
        if export.name not in importing_code:
            return

        # Run taint analysis on the importing file with the exported
        # function injected as a taint-returning summary
        importer_summaries = summaries_by_file.get(
            edge.source_file, {},
        )
        augmented = dict(importer_summaries)
        augmented[export.name] = export.summary

        # Run with augmented summaries for cross-function propagation
        func_nodes = self._taint_analyzer._parse_function_nodes(
            importing_code, importing_lang,
        )
        if func_nodes is None:
            return

        cross_findings = self._taint_analyzer._run_interprocedural_pass(
            func_nodes, augmented, importing_lang, edge.source_file,
        )

        for finding in cross_findings:
            if not finding.rule_id.startswith("taint_"):
                continue
            cross_finding = self._build_cross_file_finding(
                finding, export, edge,
            )
            findings.append(cross_finding)

    def _build_cross_file_finding(
        self,
        original: Finding,
        export: ExportedSymbol,
        edge: ImportEdge,
    ) -> Finding:
        """Build a cross-file taint finding from an intra-file finding."""
        return Finding(
            rule_id=f"cross_file_{original.rule_id}",
            severity=Severity.BLOCK,
            message=(
                f"Cross-file taint: `{export.name}()` in "
                f"`{export.file}` returns tainted data from "
                f"`{export.taint_source.name if export.taint_source else 'unknown'}` "
                f"(line {export.source_line}). "
                f"Imported in `{edge.source_file}` and flows to sink: "
                f"{original.message}"
            ),
            file=edge.source_file,
            line=original.line,
            suggestion=original.suggestion,
            confidence=CROSS_FILE_TAINT_CONFIDENCE,
        )
