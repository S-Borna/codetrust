# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Cross-file import graph analysis — builds a dependency graph across project files.

Resolves imports between project files, propagates findings across boundaries,
and detects circular dependencies. Uses existing tree-sitter parsers for
import extraction.

This is a paid feature in SonarQube, Semgrep, and CodeClimate — CodeTrust provides it free.
"""

from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field

import structlog

from src.models.enums import Language, Severity

logger = structlog.get_logger()

# Maximum files to analyze before we bail out (safety limit).
MAX_FILES = 500

# Maximum graph depth before declaring circular.
MAX_DEPTH = 50


@dataclass(frozen=True)
class ImportEdge:
    """A resolved import edge from one file to another."""

    source_file: str
    target_file: str
    import_name: str
    line: int = 0


@dataclass(frozen=True)
class CrossFileFinding:
    """A finding that propagates across file boundaries."""

    rule_id: str
    severity: Severity
    message: str
    source_file: str
    source_line: int
    propagated_to: str
    propagation_chain: list[str] = field(default_factory=list)


@dataclass
class ImportGraph:
    """Represents the import dependency graph for a project."""

    # Adjacency list: file -> list of files it imports
    edges: dict[str, list[ImportEdge]] = field(default_factory=lambda: defaultdict(list))
    # Reverse adjacency: file -> list of files that import it
    reverse_edges: dict[str, list[ImportEdge]] = field(default_factory=lambda: defaultdict(list))
    # All known project files
    files: set[str] = field(default_factory=set)
    # Circular dependency chains found
    circular_deps: list[list[str]] = field(default_factory=list)

    @property
    def total_edges(self) -> int:
        """Total number of import edges."""
        return sum(len(v) for v in self.edges.values())


@dataclass
class CrossFileAnalysisResponse:
    """Response for cross-file analysis."""

    total_files: int = 0
    total_edges: int = 0
    circular_dependencies: list[list[str]] = field(default_factory=list)
    orphan_files: list[str] = field(default_factory=list)
    hub_files: list[dict[str, str | int]] = field(default_factory=list)
    cross_file_findings: list[CrossFileFinding] = field(default_factory=list)
    latency_ms: int = 0


# --- Import extraction per language (uses existing parsers from src/utils/parsers.py) ---


def _extract_python_local_imports(code: str) -> list[tuple[str, int]]:
    """Extract Python imports that could be local project files.

    Returns list of (module_name, line_number).
    Filters out stdlib and third-party packages (those with dots going up).
    """
    results: list[tuple[str, int]] = []
    for i, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # 'from .module import X' or 'from module import X' or 'import module'
        if stripped.startswith("from "):
            parts = stripped.split()
            if len(parts) >= 2:
                module = parts[1]
                # Relative imports are always local.
                if module.startswith("."):
                    # Remove leading dots.
                    clean = module.lstrip(".")
                    if clean:
                        results.append((clean, i))
                    continue
                # Absolute import — could be local.
                results.append((module.split(".")[0], i))

        elif stripped.startswith("import "):
            parts = stripped.split()
            if len(parts) >= 2:
                module = parts[1].split(",")[0].strip()
                results.append((module.split(".")[0], i))

    return results


def _extract_js_ts_local_imports(code: str) -> list[tuple[str, int]]:
    """Extract JS/TS imports that are local (start with ./ or ../).

    Returns list of (relative_path, line_number).
    """
    import re
    results: list[tuple[str, int]] = []
    # Match: import ... from './path' or require('./path')
    import_re = re.compile(
        r"""(?:import\s+.*?\s+from\s+|require\s*\(\s*)['"](\./[^'"]+|\.{2}/[^'"]+)['"]""",
    )
    for i, line in enumerate(code.splitlines(), 1):
        for match in import_re.finditer(line):
            results.append((match.group(1), i))
    return results


def _extract_go_local_imports(code: str) -> list[tuple[str, int]]:
    """Extract Go imports that might be project-local.

    Go local imports typically share a module prefix.
    """
    import re
    results: list[tuple[str, int]] = []
    # Find the module name from go.mod-style declarations.
    in_import_block = False
    for i, line in enumerate(code.splitlines(), 1):
        stripped = line.strip()
        if stripped == "import (":
            in_import_block = True
            continue
        if in_import_block and stripped == ")":
            in_import_block = False
            continue
        if in_import_block:
            match = re.match(r'"([^"]+)"', stripped)
            if match:
                pkg = match.group(1)
                # Skip stdlib (no dots in first segment) and known external.
                if "/" in pkg and "." in pkg.split("/")[0]:
                    results.append((pkg, i))
        elif stripped.startswith("import "):
            match = re.match(r'import\s+"([^"]+)"', stripped)
            if match:
                pkg = match.group(1)
                if "/" in pkg and "." in pkg.split("/")[0]:
                    results.append((pkg, i))
    return results


def _extract_java_local_imports(code: str) -> list[tuple[str, int]]:
    """Extract Java imports.

    Returns (fully_qualified_class, line_number).
    """
    import re
    results: list[tuple[str, int]] = []
    for i, line in enumerate(code.splitlines(), 1):
        match = re.match(r"import\s+([\w.]+)", line.strip())
        if match:
            results.append((match.group(1), i))
    return results


def _extract_csharp_local_imports(code: str) -> list[tuple[str, int]]:
    """Extract C# using statements.

    Returns (namespace, line_number).
    """
    import re
    results: list[tuple[str, int]] = []
    for i, line in enumerate(code.splitlines(), 1):
        match = re.match(r"using\s+([\w.]+)\s*;", line.strip())
        if match:
            results.append((match.group(1), i))
    return results


LANGUAGE_EXTRACTORS: dict[
    Language,
    type[object] | None,
] = {
    Language.PYTHON: None,
    Language.JAVASCRIPT: None,
    Language.TYPESCRIPT: None,
    Language.GO: None,
    Language.JAVA: None,
    Language.CSHARP: None,
}

# Map languages to their extractors.
_EXTRACTORS: dict[Language, object] = {
    Language.PYTHON: _extract_python_local_imports,
    Language.JAVASCRIPT: _extract_js_ts_local_imports,
    Language.TYPESCRIPT: _extract_js_ts_local_imports,
    Language.GO: _extract_go_local_imports,
    Language.JAVA: _extract_java_local_imports,
    Language.CSHARP: _extract_csharp_local_imports,
}


def detect_language_from_extension(filepath: str) -> Language | None:
    """Detect language from file extension."""
    ext_map: dict[str, Language] = {
        ".py": Language.PYTHON,
        ".js": Language.JAVASCRIPT,
        ".jsx": Language.JAVASCRIPT,
        ".ts": Language.TYPESCRIPT,
        ".tsx": Language.TYPESCRIPT,
        ".go": Language.GO,
        ".java": Language.JAVA,
        ".cs": Language.CSHARP,
        ".rs": Language.RUST,
        ".cpp": Language.CPP,
        ".c": Language.CPP,
        ".h": Language.CPP,
        ".sh": Language.SHELL,
        ".bash": Language.SHELL,
        ".ps1": Language.POWERSHELL,
        ".psm1": Language.POWERSHELL,
        ".psd1": Language.POWERSHELL,
        ".rb": Language.RUBY,
        ".php": Language.PHP,
        ".html": Language.HTML,
        ".htm": Language.HTML,
        ".tf": Language.TERRAFORM,
    }
    ext = os.path.splitext(filepath)[1].lower()
    return ext_map.get(ext)


class CrossFileAnalyzer:
    """Builds an import dependency graph and propagates findings across files.

    Analyzes a project directory to:
    1. Build an import graph showing how files depend on each other.
    2. Detect circular dependencies.
    3. Identify orphan files (not imported by anything).
    4. Identify hub files (imported by many others).
    5. Propagate security findings across import chains.
    """

    def __init__(self) -> None:
        """Initialize the analyzer."""
        self._graph = ImportGraph()

    def _detect_file_languages(
        self,
        file_contents: dict[str, str],
        file_languages: dict[str, Language] | None,
    ) -> dict[str, Language]:
        """Detect languages for files, using provided map or extension-based detection."""
        languages: dict[str, Language] = {}
        for filepath in file_contents:
            if file_languages and filepath in file_languages:
                languages[filepath] = file_languages[filepath]
            else:
                lang = detect_language_from_extension(filepath)
                if lang is not None:
                    languages[filepath] = lang
        return languages

    def _build_graph_and_analyze(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> CrossFileAnalysisResponse:
        """Build the import graph, detect cycles, and compute metrics."""
        import time
        start = time.monotonic()

        self._graph.files = set(file_contents.keys())
        for filepath, content in file_contents.items():
            lang = languages.get(filepath)
            if lang is None:
                continue
            self._extract_and_link(filepath, content, lang, file_contents)

        self._detect_cycles()
        orphans = self._find_orphans()
        hubs = self._find_hubs()
        elapsed_ms = int((time.monotonic() - start) * 1000)

        return CrossFileAnalysisResponse(
            total_files=len(file_contents),
            total_edges=self._graph.total_edges,
            circular_dependencies=self._graph.circular_deps,
            orphan_files=orphans,
            hub_files=hubs,
            cross_file_findings=[],
            latency_ms=elapsed_ms,
        )

    def analyze_project(
        self,
        file_contents: dict[str, str],
        file_languages: dict[str, Language] | None = None,
    ) -> CrossFileAnalysisResponse:
        """Analyze a set of files and build the import graph.

        Args:
            file_contents: Map of relative filepath -> file contents.
            file_languages: Optional map of filepath -> language. If not
                provided, language is detected from extension.

        Returns:
            CrossFileAnalysisResponse with graph analysis results.
        """
        self._graph = ImportGraph()

        if len(file_contents) > MAX_FILES:
            logger.warning(
                "cross_file_too_many_files",
                count=len(file_contents),
                limit=MAX_FILES,
            )
            file_contents = dict(list(file_contents.items())[:MAX_FILES])

        languages = self._detect_file_languages(file_contents, file_languages)
        return self._build_graph_and_analyze(file_contents, languages)

    def propagate_findings(
        self,
        findings: list[dict[str, str | int]],
    ) -> list[CrossFileFinding]:
        """Propagate findings from one file to all files that import it.

        If file A has a security finding and file B imports A, then
        file B inherits an informational finding about the transitive risk.

        Args:
            findings: List of finding dicts with 'file', 'rule_id',
                'severity', 'message', 'line' keys.

        Returns:
            List of CrossFileFinding for propagated issues.
        """
        propagated: list[CrossFileFinding] = []

        for finding in findings:
            source_file = str(finding.get("file", ""))
            if not source_file or source_file not in self._graph.files:
                continue

            severity_str = str(finding.get("severity", "info")).upper()
            # Only propagate BLOCK and WARN findings.
            if severity_str not in ("BLOCK", "WARN"):
                continue

            # Walk reverse edges to find all importers.
            visited: set[str] = set()
            self._propagate_dfs(
                source_file=source_file,
                current_file=source_file,
                finding=finding,
                chain=[source_file],
                visited=visited,
                propagated=propagated,
            )

        return propagated

    def _extract_and_link(
        self,
        filepath: str,
        content: str,
        language: Language,
        all_files: dict[str, str],
    ) -> None:
        """Extract imports from a file and create edges to resolved targets."""
        extractor = _EXTRACTORS.get(language)
        if extractor is None:
            return

        imports = extractor(content)

        for import_name, line in imports:
            resolved = self._resolve_import(filepath, import_name, language, all_files)
            if resolved and resolved != filepath:
                edge = ImportEdge(
                    source_file=filepath,
                    target_file=resolved,
                    import_name=import_name,
                    line=line,
                )
                self._graph.edges[filepath].append(edge)
                self._graph.reverse_edges[resolved].append(edge)

    def _resolve_import(
        self,
        source: str,
        import_name: str,
        language: Language,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve an import name to a project file path.

        Returns the resolved filepath or None if it's external.
        """
        source_dir = os.path.dirname(source)

        if language == Language.PYTHON:
            return self._resolve_python_import(source_dir, import_name, all_files)
        if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            return self._resolve_js_import(source_dir, import_name, all_files)
        if language == Language.GO:
            return self._resolve_go_import(import_name, all_files)
        if language == Language.JAVA:
            return self._resolve_java_import(import_name, all_files)
        if language == Language.CSHARP:
            return self._resolve_csharp_import(import_name, all_files)
        return None

    def _resolve_candidate_path(self, candidate: str, all_files: dict[str, str]) -> str | None:
        """Resolve a candidate path against project files with cross-platform separators."""
        normalized = os.path.normpath(candidate)
        if normalized in all_files:
            return normalized

        as_posix = normalized.replace("\\", "/")
        if as_posix in all_files:
            return as_posix

        as_windows = normalized.replace("/", "\\")
        if as_windows in all_files:
            return as_windows

        return None

    def _resolve_python_import(
        self,
        source_dir: str,
        module: str,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve a Python import to a file.

        'module' could resolve to 'module.py' or 'module/__init__.py'.
        """
        candidates = [
            os.path.join(source_dir, f"{module}.py"),
            os.path.join(source_dir, module, "__init__.py"),
            f"{module}.py",
            f"{module}/__init__.py",
        ]
        # Also try from project root.
        module_path = module.replace(".", "/")
        candidates.extend([
            f"{module_path}.py",
            f"{module_path}/__init__.py",
        ])

        for candidate in candidates:
            resolved = self._resolve_candidate_path(candidate, all_files)
            if resolved is not None:
                return resolved

        return None

    def _resolve_js_import(
        self,
        source_dir: str,
        relative_path: str,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve a JS/TS relative import to a file.

        Tries: exact path, with .js, .ts, .jsx, .tsx, /index.js, /index.ts.
        """
        base = os.path.normpath(os.path.join(source_dir, relative_path))
        candidates = [
            base,
            f"{base}.js",
            f"{base}.ts",
            f"{base}.jsx",
            f"{base}.tsx",
            os.path.join(base, "index.js"),
            os.path.join(base, "index.ts"),
        ]

        for candidate in candidates:
            resolved = self._resolve_candidate_path(candidate, all_files)
            if resolved is not None:
                return resolved

        return None

    def _resolve_go_import(
        self,
        import_path: str,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve a Go import to a project file (best-effort)."""
        # Go imports are package paths. Try matching the suffix against project files.
        for filepath in all_files:
            if filepath.endswith(".go") and import_path.endswith(
                os.path.dirname(filepath).replace(os.sep, "/")
            ):
                return filepath
        return None

    def _resolve_java_import(
        self,
        fqcn: str,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve a Java FQCN to a .java file."""
        # Convert com.example.MyClass to com/example/MyClass.java
        path = fqcn.replace(".", "/") + ".java"
        for filepath in all_files:
            if filepath.endswith(path):
                return filepath
        return None

    def _resolve_csharp_import(
        self,
        namespace: str,
        all_files: dict[str, str],
    ) -> str | None:
        """Resolve a C# using statement to a .cs file (best-effort).

        C# namespaces don't map 1:1 to files, but we try to match.
        """
        path_fragment = namespace.replace(".", "/")
        for filepath in all_files:
            if filepath.endswith(".cs") and path_fragment in filepath:
                return filepath
        return None

    def _detect_cycles(self) -> None:
        """Detect circular dependencies using DFS."""
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            """DFS cycle detection."""
            if len(self._graph.circular_deps) >= 10:
                return  # Limit reported cycles.
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for edge in self._graph.edges.get(node, []):
                target = edge.target_file
                if target not in visited:
                    dfs(target)
                elif target in rec_stack:
                    # Found a cycle.
                    cycle_start = path.index(target)
                    cycle = [*path[cycle_start:], target]
                    self._graph.circular_deps.append(cycle)

            path.pop()
            rec_stack.discard(node)

        for file in sorted(self._graph.files):
            if file not in visited:
                dfs(file)

    def _find_orphans(self) -> list[str]:
        """Find files that are not imported by any other file.

        Excludes entry points (main, __init__, index, etc.).
        """
        entry_patterns = {
            "__init__.py", "__main__.py", "main.py",
            "index.js", "index.ts", "main.go", "Main.java",
            "Program.cs", "App.java",
        }

        orphans: list[str] = []
        for filepath in sorted(self._graph.files):
            basename = os.path.basename(filepath)
            # Skip entry points.
            if basename in entry_patterns:
                continue
            # Skip test files.
            if "test" in basename.lower():
                continue
            # File is an orphan if nothing imports it.
            if filepath not in self._graph.reverse_edges:
                orphans.append(filepath)

        return orphans

    def _find_hubs(self, min_importers: int = 5) -> list[dict[str, str | int]]:
        """Find files imported by many others (potential architectural hubs).

        Args:
            min_importers: Minimum number of importers to qualify as a hub.

        Returns:
            List of dicts with 'file' and 'importers' count.
        """
        hubs: list[dict[str, str | int]] = []
        for filepath in sorted(self._graph.reverse_edges.keys()):
            count = len(self._graph.reverse_edges[filepath])
            if count >= min_importers:
                hubs.append({"file": filepath, "importers": count})

        # Sort by importers descending.
        hubs.sort(key=lambda h: int(h["importers"]), reverse=True)
        return hubs[:20]

    def _create_propagated_finding(
        self,
        source_file: str,
        current_file: str,
        importer: str,
        finding: dict[str, str | int],
        chain: list[str],
    ) -> CrossFileFinding:
        """Create a single propagated finding for a transitive import."""
        return CrossFileFinding(
            rule_id=f"cross-file:{finding.get('rule_id', 'unknown')}",
            severity=Severity.WARN,
            message=(
                f"Transitive risk: {importer} imports {current_file} "
                f"which has {finding.get('rule_id', 'issue')}: "
                f"{finding.get('message', '')}"
            ),
            source_file=source_file,
            source_line=int(finding.get("line", 0)),
            propagated_to=importer,
            propagation_chain=list(chain),
        )

    def _propagate_dfs(
        self,
        source_file: str,
        current_file: str,
        finding: dict[str, str | int],
        chain: list[str],
        visited: set[str],
        propagated: list[CrossFileFinding],
        depth: int = 0,
    ) -> None:
        """DFS propagation of a finding through the reverse import graph."""
        if depth > MAX_DEPTH:
            return
        visited.add(current_file)

        for edge in self._graph.reverse_edges.get(current_file, []):
            importer = edge.source_file
            if importer in visited:
                continue

            propagated.append(
                self._create_propagated_finding(
                    source_file, current_file, importer, finding, chain,
                )
            )
            self._propagate_dfs(
                source_file=source_file,
                current_file=importer,
                finding=finding,
                chain=[*chain, importer],
                visited=visited,
                propagated=propagated,
                depth=depth + 1,
            )
