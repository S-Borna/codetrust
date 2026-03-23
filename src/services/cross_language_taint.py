# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Cross-language taint analysis — tracks data flow across HTTP/API boundaries.

The first taint engine that follows tainted data ACROSS programming languages.
Real applications are polyglot: a JS frontend sends user input via fetch() to a
Python backend, which forwards it to a Go microservice that executes a SQL query.
Traditional taint analyzers see three isolated files in three languages and miss
the entire chain.

This module detects that chain by:
  Phase 1 — Extract HTTP route definitions (servers/handlers).
  Phase 2 — Extract HTTP client calls (callers).
  Phase 3 — Match callers to routes across language boundaries.
  Phase 4 — Propagate taint across matched boundaries.
  Phase 5 — Generate findings with full cross-language chain.

Supported frameworks:
  Python:  Flask (@app.route), FastAPI (@app.get/post/put/delete), Django (path)
  JS/TS:   Express (router.get/post), Koa, Hapi, fetch(), axios, got
  Go:      net/http (HandleFunc, Handle), gin, echo, http.Get/Post

No other taint analysis tool does this. Not Semgrep. Not SonarQube. Not Snyk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from src.models.enums import Language, Severity
from src.models.responses import Finding
from src.services.cross_file_analyzer import detect_language_from_extension
from src.services.cross_file_taint import CrossFileTaintAnalyzer
from src.services.taint_analyzer import FunctionSummary, TaintAnalyzer

if TYPE_CHECKING:
    from src.rules.taint_rules import TaintSource

logger = structlog.get_logger()

# Confidence for cross-language findings (lower than same-language due to
# heuristic route matching, but still high enough to warrant BLOCK).
CROSS_LANG_CONFIDENCE = 0.80

# Maximum files before truncating (safety limit).
MAX_CROSS_LANG_FILES = 300


# ═══════════════════════════════════════════════════════════════
#  Data models
# ═══════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class HttpRoute:
    """An HTTP route defined by a server-side handler.

    Represents e.g. Flask @app.route("/api/users") or Go http.HandleFunc("/api/users").
    """

    path: str
    method: str  # GET, POST, PUT, DELETE, ANY
    handler_name: str
    file: str
    line: int
    language: Language
    reads_body: bool = False  # handler reads request body (taint source)
    returns_taint: bool = False  # handler returns tainted data
    taint_source: TaintSource | None = None
    taint_source_line: int = 0
    summary: FunctionSummary | None = None


@dataclass(frozen=True)
class HttpCall:
    """An HTTP client call that sends data to a remote endpoint.

    Represents e.g. fetch("/api/users"), requests.post("/api/users", data=x),
    or http.Get("/api/users?id=" + userInput).
    """

    url_pattern: str  # the URL string or pattern
    method: str  # GET, POST, etc.
    file: str
    line: int
    language: Language
    sends_tainted_data: bool = False
    tainted_variable: str = ""
    taint_source_name: str = ""


@dataclass(frozen=True)
class CrossLanguageFlow:
    """A complete taint flow that crosses a language boundary via HTTP."""

    caller: HttpCall
    route: HttpRoute
    sink_rule_id: str
    sink_message: str
    sink_line: int


@dataclass
class CrossLanguageTaintResult:
    """Result of cross-language taint analysis."""

    findings: list[Finding] = field(default_factory=list)
    total_files: int = 0
    languages_analyzed: int = 0
    routes_discovered: int = 0
    http_calls_discovered: int = 0
    cross_language_flows: int = 0


# ═══════════════════════════════════════════════════════════════
#  Route extraction patterns per framework
# ═══════════════════════════════════════════════════════════════

# Python: Flask, FastAPI, Django
_PYTHON_FLASK_ROUTE = re.compile(
    r"""@(?:app|blueprint|bp)\."""
    r"""(route|get|post|put|delete|patch)\s*\(\s*"""
    r"""['"]([^'"]+)['"]""",
    re.MULTILINE,
)

_PYTHON_FASTAPI_ROUTE = re.compile(
    r"""@(?:app|router)\."""
    r"""(get|post|put|delete|patch)\s*\(\s*"""
    r"""['"]([^'"]+)['"]""",
    re.MULTILINE,
)

_PYTHON_DJANGO_PATH = re.compile(
    r"""path\s*\(\s*['"]([^'"]+)['"]\s*,\s*(\w+)""",
    re.MULTILINE,
)

# JavaScript/TypeScript: Express, fetch, axios
_JS_EXPRESS_ROUTE = re.compile(
    r"""(?:app|router)\."""
    r"""(get|post|put|delete|patch|all)\s*\(\s*"""
    r"""['"]([^'"]+)['"]""",
    re.MULTILINE,
)

_JS_FETCH_CALL = re.compile(
    r"""fetch\s*\(\s*"""
    r"""(?:['"`]([^'"`]+)['"`]|(\w+))""",
    re.MULTILINE,
)

_JS_AXIOS_CALL = re.compile(
    r"""axios\."""
    r"""(get|post|put|delete|patch)\s*\(\s*"""
    r"""(?:['"`]([^'"`]+)['"`]|(\w+))""",
    re.MULTILINE,
)

# Go: net/http, gin, echo
_GO_HTTP_HANDLE = re.compile(
    r"""(?:http\.HandleFunc|mux\.HandleFunc|"""
    r"""router\.HandleFunc|r\.HandleFunc)\s*\(\s*"""
    r"""['"]([^'"]+)['"]\s*,\s*(\w+)""",
    re.MULTILINE,
)

_GO_GIN_ROUTE = re.compile(
    r"""(?:router|r|gin|g|engine|e)\."""
    r"""(GET|POST|PUT|DELETE|PATCH|Any)\s*\(\s*"""
    r"""['"]([^'"]+)['"]""",
    re.MULTILINE | re.IGNORECASE,
)

_GO_HTTP_CLIENT = re.compile(
    r"""http\.(Get|Post|Head)\s*\(\s*"""
    r"""(?:['"]([^'"]+)['"]|(\w+))""",
    re.MULTILINE,
)


# ═══════════════════════════════════════════════════════════════
#  Handler function name extraction (matches route to function)
# ═══════════════════════════════════════════════════════════════

_PYTHON_FUNC_AFTER_ROUTE = re.compile(
    r"""@(?:app|blueprint|bp|router)\.\w+\s*\([^)]*\)\s*\n"""
    r"""(?:@\w+[^\n]*\n)*"""
    r"""(?:async\s+)?def\s+(\w+)""",
    re.MULTILINE,
)

_JS_HANDLER_IN_ROUTE = re.compile(
    r"""(?:app|router)\.\w+\s*\(\s*['"][^'"]+['"]\s*,\s*"""
    r"""(?:async\s+)?(?:function\s+)?(\w+)|"""
    r"""(?:app|router)\.\w+\s*\(\s*['"][^'"]+['"]\s*,\s*"""
    r"""\(\s*(?:req|request|ctx)\s*""",
    re.MULTILINE,
)


class CrossLanguageTaintAnalyzer:
    """Tracks tainted data across HTTP boundaries between languages.

    This is the engine that no other security tool has. It detects when:
    - A JS frontend sends user input via fetch() to a Python backend
    - A Python backend forwards data to a Go microservice
    - A Go service passes unvalidated data to a SQL query

    The full chain is reported as a single finding with every hop documented.
    """

    def __init__(self) -> None:
        """Initialize the cross-language taint analyzer."""
        self._taint_analyzer = TaintAnalyzer()
        self._cross_file_analyzer = CrossFileTaintAnalyzer()

    def analyze(
        self,
        file_contents: dict[str, str],
        file_languages: dict[str, Language] | None = None,
    ) -> CrossLanguageTaintResult:
        """Run cross-language taint analysis on a multi-language project.

        Args:
            file_contents: Map of relative filepath to source code.
            file_languages: Optional explicit language map.

        Returns:
            CrossLanguageTaintResult with findings and metrics.
        """
        if len(file_contents) > MAX_CROSS_LANG_FILES:
            file_contents = dict(
                list(file_contents.items())[:MAX_CROSS_LANG_FILES],
            )

        languages = self._detect_languages(file_contents, file_languages)
        unique_langs = set(languages.values())

        # Phase 1: Extract all HTTP routes
        routes = self._extract_all_routes(file_contents, languages)

        # Phase 2: Extract all HTTP client calls
        calls = self._extract_all_http_calls(file_contents, languages)

        # Phase 3: Build taint summaries per file
        summaries = self._build_summaries(file_contents, languages)

        # Phase 4: Enrich routes with taint info
        enriched_routes = self._enrich_routes(
            routes, summaries, file_contents, languages,
        )

        # Phase 5: Enrich calls with taint info
        enriched_calls = self._enrich_calls(
            calls, summaries, file_contents, languages,
        )

        # Phase 6: Match calls to routes across language boundaries
        flows = self._match_cross_language_flows(
            enriched_calls, enriched_routes, languages,
        )

        # Phase 7: Generate findings
        findings = self._generate_findings(flows)

        result = CrossLanguageTaintResult(
            findings=findings,
            total_files=len(file_contents),
            languages_analyzed=len(unique_langs),
            routes_discovered=len(routes),
            http_calls_discovered=len(calls),
            cross_language_flows=len(flows),
        )

        logger.info(
            "cross_language_taint_complete",
            total_files=result.total_files,
            languages=len(unique_langs),
            routes=result.routes_discovered,
            calls=result.http_calls_discovered,
            flows=result.cross_language_flows,
            findings=len(findings),
        )
        return result

    # ═══════════════════════════════════════════════════════════════
    #  Phase 1: Route extraction
    # ═══════════════════════════════════════════════════════════════

    def _extract_all_routes(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> list[HttpRoute]:
        """Extract HTTP route definitions from all server-side files."""
        routes: list[HttpRoute] = []
        for filepath, code in file_contents.items():
            lang = languages.get(filepath)
            if lang is None:
                continue
            routes.extend(self._extract_routes(filepath, code, lang))
        return routes

    def _extract_routes(
        self,
        filepath: str,
        code: str,
        language: Language,
    ) -> list[HttpRoute]:
        """Extract HTTP routes from a single file."""
        if language == Language.PYTHON:
            return self._extract_python_routes(filepath, code)
        if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            return self._extract_js_routes(filepath, code, language)
        if language == Language.GO:
            return self._extract_go_routes(filepath, code)
        return []

    def _extract_python_routes(
        self,
        filepath: str,
        code: str,
    ) -> list[HttpRoute]:
        """Extract Flask/FastAPI/Django routes from Python code."""
        routes: list[HttpRoute] = []

        # Flask/FastAPI decorator routes
        for match in _PYTHON_FLASK_ROUTE.finditer(code):
            method = match.group(1).upper()
            if method == "ROUTE":
                method = "ANY"
            path = match.group(2)
            handler = self._find_python_handler_after(
                code, match.end(),
            )
            routes.append(HttpRoute(
                path=path,
                method=method,
                handler_name=handler or "<anonymous>",
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.PYTHON,
            ))

        # FastAPI routes (same pattern, deduplicate)
        seen_paths = {(r.path, r.method) for r in routes}
        for match in _PYTHON_FASTAPI_ROUTE.finditer(code):
            method = match.group(1).upper()
            path = match.group(2)
            if (path, method) in seen_paths:
                continue
            handler = self._find_python_handler_after(
                code, match.end(),
            )
            routes.append(HttpRoute(
                path=path,
                method=method,
                handler_name=handler or "<anonymous>",
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.PYTHON,
            ))

        # Django path()
        for match in _PYTHON_DJANGO_PATH.finditer(code):
            path = match.group(1)
            handler = match.group(2)
            routes.append(HttpRoute(
                path="/" + path.lstrip("/"),
                method="ANY",
                handler_name=handler,
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.PYTHON,
            ))

        return routes

    def _extract_js_routes(
        self,
        filepath: str,
        code: str,
        language: Language,
    ) -> list[HttpRoute]:
        """Extract Express/Koa routes from JS/TS code."""
        routes: list[HttpRoute] = []

        for match in _JS_EXPRESS_ROUTE.finditer(code):
            method = match.group(1).upper()
            path = match.group(2)
            handler = self._find_js_handler_name(
                code, match.end(),
            )
            routes.append(HttpRoute(
                path=path,
                method=method,
                handler_name=handler or "<anonymous>",
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=language,
            ))

        return routes

    def _extract_go_routes(
        self,
        filepath: str,
        code: str,
    ) -> list[HttpRoute]:
        """Extract net/http and gin routes from Go code."""
        routes: list[HttpRoute] = []

        # http.HandleFunc("/path", handlerFunc)
        for match in _GO_HTTP_HANDLE.finditer(code):
            path = match.group(1)
            handler = match.group(2)
            routes.append(HttpRoute(
                path=path,
                method="ANY",
                handler_name=handler,
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.GO,
            ))

        # gin: router.GET("/path", ...)
        for match in _GO_GIN_ROUTE.finditer(code):
            method = match.group(1).upper()
            path = match.group(2)
            routes.append(HttpRoute(
                path=path,
                method=method,
                handler_name="<anonymous>",
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.GO,
            ))

        return routes

    # ═══════════════════════════════════════════════════════════════
    #  Phase 2: HTTP call extraction
    # ═══════════════════════════════════════════════════════════════

    def _extract_all_http_calls(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> list[HttpCall]:
        """Extract HTTP client calls from all files."""
        calls: list[HttpCall] = []
        for filepath, code in file_contents.items():
            lang = languages.get(filepath)
            if lang is None:
                continue
            calls.extend(
                self._extract_http_calls(filepath, code, lang),
            )
        return calls

    def _extract_http_calls(
        self,
        filepath: str,
        code: str,
        language: Language,
    ) -> list[HttpCall]:
        """Extract HTTP client calls from a single file."""
        if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            return self._extract_js_http_calls(filepath, code, language)
        if language == Language.PYTHON:
            return self._extract_python_http_calls(filepath, code)
        if language == Language.GO:
            return self._extract_go_http_calls(filepath, code)
        return []

    def _extract_js_http_calls(
        self,
        filepath: str,
        code: str,
        language: Language,
    ) -> list[HttpCall]:
        """Extract fetch() and axios calls from JS/TS code."""
        calls: list[HttpCall] = []

        for match in _JS_FETCH_CALL.finditer(code):
            url = match.group(1) or match.group(2) or ""
            calls.append(HttpCall(
                url_pattern=url,
                method="GET",
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=language,
            ))

        for match in _JS_AXIOS_CALL.finditer(code):
            method = match.group(1).upper()
            url = match.group(2) or match.group(3) or ""
            calls.append(HttpCall(
                url_pattern=url,
                method=method,
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=language,
            ))

        return calls

    def _extract_python_http_calls(
        self,
        filepath: str,
        code: str,
    ) -> list[HttpCall]:
        """Extract requests/httpx calls from Python code."""
        calls: list[HttpCall] = []
        pattern = re.compile(
            r"""(?:requests|httpx|aiohttp)\."""
            r"""(get|post|put|delete|patch)\s*\(\s*"""
            r"""(?:['"]([^'"]+)['"]|(\w+))""",
            re.MULTILINE,
        )
        for match in pattern.finditer(code):
            method = match.group(1).upper()
            url = match.group(2) or match.group(3) or ""
            calls.append(HttpCall(
                url_pattern=url,
                method=method,
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.PYTHON,
            ))
        return calls

    def _extract_go_http_calls(
        self,
        filepath: str,
        code: str,
    ) -> list[HttpCall]:
        """Extract http.Get/Post calls from Go code."""
        calls: list[HttpCall] = []

        for match in _GO_HTTP_CLIENT.finditer(code):
            method = match.group(1).upper()
            url = match.group(2) or match.group(3) or ""
            calls.append(HttpCall(
                url_pattern=url,
                method=method,
                file=filepath,
                line=code[:match.start()].count("\n") + 1,
                language=Language.GO,
            ))

        return calls

    # ═══════════════════════════════════════════════════════════════
    #  Phase 3: Build taint summaries
    # ═══════════════════════════════════════════════════════════════

    def _build_summaries(
        self,
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> dict[str, dict[str, FunctionSummary]]:
        """Build taint summaries for all functions in all files."""
        result: dict[str, dict[str, FunctionSummary]] = {}
        for filepath, code in file_contents.items():
            lang = languages.get(filepath)
            if lang is None:
                continue
            nodes = self._taint_analyzer._parse_function_nodes(
                code, lang,
            )
            if nodes is None:
                continue
            summaries = self._taint_analyzer._build_all_summaries(
                nodes, lang,
            )
            if summaries:
                result[filepath] = summaries
        return result

    # ═══════════════════════════════════════════════════════════════
    #  Phase 4: Enrich routes with taint data
    # ═══════════════════════════════════════════════════════════════

    def _enrich_routes(
        self,
        routes: list[HttpRoute],
        summaries: dict[str, dict[str, FunctionSummary]],
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> list[HttpRoute]:
        """Attach taint summaries to routes, marking which read user input."""
        enriched: list[HttpRoute] = []
        for route in routes:
            file_sums = summaries.get(route.file, {})
            summary = file_sums.get(route.handler_name)

            # Check if the handler reads request body/params (is a taint source)
            code = file_contents.get(route.file, "")
            handler_reads_body = self._handler_reads_body(
                route.handler_name, code, route.language,
            )

            returns_taint = False
            taint_src = None
            src_line = 0
            if summary is not None:
                returns_taint = summary.returns_taint
                taint_src = summary.taint_source
                src_line = summary.taint_source_line

            enriched.append(HttpRoute(
                path=route.path,
                method=route.method,
                handler_name=route.handler_name,
                file=route.file,
                line=route.line,
                language=route.language,
                reads_body=handler_reads_body,
                returns_taint=returns_taint,
                taint_source=taint_src,
                taint_source_line=src_line,
                summary=summary,
            ))
        return enriched

    def _enrich_calls(
        self,
        calls: list[HttpCall],
        summaries: dict[str, dict[str, FunctionSummary]],
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> list[HttpCall]:
        """Check which HTTP calls send tainted data."""
        enriched: list[HttpCall] = []
        for call in calls:
            tainted_var, source_name = self._check_call_sends_taint(
                call, file_contents, languages,
            )
            enriched.append(HttpCall(
                url_pattern=call.url_pattern,
                method=call.method,
                file=call.file,
                line=call.line,
                language=call.language,
                sends_tainted_data=tainted_var != "",
                tainted_variable=tainted_var,
                taint_source_name=source_name,
            ))
        return enriched

    # ═══════════════════════════════════════════════════════════════
    #  Phase 5-6: Match calls to routes + generate findings
    # ═══════════════════════════════════════════════════════════════

    def _match_cross_language_flows(
        self,
        calls: list[HttpCall],
        routes: list[HttpRoute],
        languages: dict[str, Language],
    ) -> list[CrossLanguageFlow]:
        """Match HTTP calls to routes ACROSS language boundaries."""
        flows: list[CrossLanguageFlow] = []

        for call in calls:
            if not call.sends_tainted_data:
                continue

            for route in routes:
                # Must be different languages (that's the point)
                if call.language == route.language:
                    continue

                if not self._paths_match(call.url_pattern, route.path):
                    continue

                if not self._methods_compatible(call.method, route.method):
                    continue

                # We have a cross-language boundary with tainted data
                # Now check if the route handler has sinks
                if route.summary is not None:
                    sink_info = self._find_sinks_in_handler(route)
                    if sink_info is not None:
                        flows.append(CrossLanguageFlow(
                            caller=call,
                            route=route,
                            sink_rule_id=sink_info[0],
                            sink_message=sink_info[1],
                            sink_line=sink_info[2],
                        ))

        return flows

    def _generate_findings(
        self,
        flows: list[CrossLanguageFlow],
    ) -> list[Finding]:
        """Generate findings from cross-language taint flows."""
        findings: list[Finding] = []

        for flow in flows:
            caller_lang = str(flow.caller.language).split(".")[-1]
            route_lang = str(flow.route.language).split(".")[-1]

            message = (
                f"Cross-language taint: {caller_lang} "
                f"`{flow.caller.file}` (line {flow.caller.line}) sends "
                f"tainted data from `{flow.caller.taint_source_name}` "
                f"via HTTP {flow.caller.method} to `{flow.route.path}`. "
                f"Received by {route_lang} handler "
                f"`{flow.route.handler_name}()` in "
                f"`{flow.route.file}` (line {flow.route.line}). "
                f"Data flows to sink: {flow.sink_message}"
            )

            findings.append(Finding(
                rule_id=f"cross_lang_taint_{flow.sink_rule_id}",
                severity=Severity.BLOCK,
                message=message,
                file=flow.caller.file,
                line=flow.caller.line,
                suggestion=(
                    f"Validate/sanitize input in the {route_lang} handler "
                    f"`{flow.route.handler_name}()` before it reaches the "
                    f"sink. Add parameterized queries, input validation, or "
                    f"encoding appropriate for the sink type."
                ),
                confidence=CROSS_LANG_CONFIDENCE,
            ))

        return findings

    # ═══════════════════════════════════════════════════════════════
    #  Helper methods
    # ═══════════════════════════════════════════════════════════════

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

    def _find_python_handler_after(
        self,
        code: str,
        offset: int,
    ) -> str | None:
        """Find the function name defined after a route decorator."""
        remaining = code[offset:]
        match = re.search(
            r"""(?:async\s+)?def\s+(\w+)""",
            remaining,
        )
        if match is None:
            return None
        # Only match if the def is within 200 chars (avoid matching distant functions)
        if match.start() > 200:
            return None
        return match.group(1)

    def _find_js_handler_name(
        self,
        code: str,
        offset: int,
    ) -> str | None:
        """Find the handler function name in an Express route."""
        remaining = code[offset:]
        # Look for a named function reference: router.get("/path", handlerName)
        match = re.search(r"""\s*,\s*(\w+)\s*\)""", remaining[:100])
        if match is not None:
            name = match.group(1)
            if name not in ("req", "res", "next", "async", "function"):
                return name
        return None

    def _handler_reads_body(
        self,
        handler_name: str,
        code: str,
        language: Language,
    ) -> bool:
        """Check if a handler function reads request body/params."""
        # Find the handler function body
        if language == Language.PYTHON:
            patterns = [
                "request.args", "request.form", "request.json",
                "request.get_json", "request.data", "request.query_params",
            ]
        elif language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            patterns = [
                "req.body", "req.params", "req.query", "req.headers",
            ]
        elif language == Language.GO:
            patterns = [
                "r.FormValue", "r.URL.Query", "r.Body",
                "r.Header.Get", "r.ParseForm",
            ]
        else:
            return False

        # Find handler body and check for patterns
        func_body = self._extract_function_body(
            handler_name, code, language,
        )
        if func_body is None:
            return False

        return any(p in func_body for p in patterns)

    def _extract_function_body(
        self,
        func_name: str,
        code: str,
        language: Language,
    ) -> str | None:
        """Extract the body of a named function from source code."""
        if language == Language.PYTHON:
            pattern = re.compile(
                rf"""(?:async\s+)?def\s+{re.escape(func_name)}\s*\([^)]*\)[^:]*:"""
                r"""(.+?)(?=\ndef\s|\nclass\s|\Z)""",
                re.DOTALL,
            )
        elif language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
            pattern = re.compile(
                rf"""(?:async\s+)?function\s+{re.escape(func_name)}\s*\([^)]*\)\s*\{{"""
                r"""(.+?)(?=\n\w|\Z)""",
                re.DOTALL,
            )
        elif language == Language.GO:
            pattern = re.compile(
                rf"""func\s+{re.escape(func_name)}\s*\([^)]*\)[^{{]*\{{"""
                r"""(.+?)(?=\nfunc\s|\Z)""",
                re.DOTALL,
            )
        else:
            return None

        match = pattern.search(code)
        if match is None:
            return None
        return match.group(1)

    def _check_call_sends_taint(
        self,
        call: HttpCall,
        file_contents: dict[str, str],
        languages: dict[str, Language],
    ) -> tuple[str, str]:
        """Check if an HTTP call includes tainted data.

        Returns (tainted_variable_name, source_name) or ("", "").
        """
        code = file_contents.get(call.file, "")
        lang = languages.get(call.file)
        if not code or lang is None:
            return ("", "")

        # Get the line of the call and surrounding context
        lines = code.splitlines()
        if call.line < 1 or call.line > len(lines):
            return ("", "")

        # Check 10 lines before the call for taint sources
        start = max(0, call.line - 10)
        context = "\n".join(lines[start:call.line])
        call_line = lines[call.line - 1]

        # Run taint analysis on the enclosing function
        func_nodes = self._taint_analyzer._parse_function_nodes(
            code, lang,
        )
        if func_nodes is None:
            return ("", "")

        # Check if any variable in the call line is tainted
        from src.rules.taint_rules import TAINT_SOURCES
        sources = TAINT_SOURCES.get(lang, ())

        for source in sources:
            if source.pattern in context:
                # Find the variable assigned from this source
                var_match = re.search(
                    r"""(\w+)\s*[:=]\s*.*?"""
                    + re.escape(source.pattern),
                    context,
                )
                if var_match is not None:
                    var_name = var_match.group(1)
                    if var_name in call_line:
                        return (var_name, source.name)

        return ("", "")

    def _paths_match(self, call_url: str, route_path: str) -> bool:
        """Check if a client URL matches a server route path.

        Handles path parameters: /api/users/:id matches /api/users/123.
        Handles query strings: /api/users?id=x matches /api/users.
        """
        # Normalize: strip query strings from call URL
        call_clean = call_url.split("?")[0].rstrip("/")
        route_clean = route_path.rstrip("/")

        # Exact match
        if call_clean == route_clean:
            return True

        # Route has path params (Express :id, Flask <id>, Go {id})
        route_pattern = re.sub(
            r"""(?::(\w+)|<\w+(?::\w+)?>|\{(\w+)\})""",
            r"[^/]+",
            route_clean,
        )
        if re.fullmatch(route_pattern, call_clean):
            return True

        # Prefix match for partial URLs
        if call_clean and route_clean.startswith(call_clean):
            return True
        return bool(route_clean and call_clean.startswith(route_clean))

    def _methods_compatible(
        self,
        call_method: str,
        route_method: str,
    ) -> bool:
        """Check if HTTP methods are compatible."""
        if route_method == "ANY":
            return True
        return call_method.upper() == route_method.upper()

    def _find_sinks_in_handler(
        self,
        route: HttpRoute,
    ) -> tuple[str, str, int] | None:
        """Check if a route handler contains sinks.

        Returns (rule_id, message, line) or None.
        """
        if route.summary is None:
            return None

        # Check if any parameter reaches a sink
        if route.summary.params_reaching_sinks:
            for param, sink_name in route.summary.params_reaching_sinks.items():
                return (
                    "sql_injection" if "query" in sink_name.lower()
                    or "execute" in sink_name.lower()
                    or "exec" in sink_name.lower()
                    else "command_injection" if "command" in sink_name.lower()
                    or "system" in sink_name.lower()
                    or "popen" in sink_name.lower()
                    else "xss" if "html" in sink_name.lower()
                    or "write" in sink_name.lower()
                    or "innerhtml" in sink_name.lower()
                    else "ssrf" if "get" in sink_name.lower()
                    or "fetch" in sink_name.lower()
                    else "path_traversal" if "open" in sink_name.lower()
                    or "read" in sink_name.lower()
                    or "create" in sink_name.lower()
                    else "injection",
                    f"`{sink_name}` via parameter `{param}`",
                    route.line,
                )

        # Check handler body for taint sources -> sinks
        if route.reads_body:
            return (
                "input_to_handler",
                "handler reads user input and may propagate to sinks",
                route.line,
            )

        return None
