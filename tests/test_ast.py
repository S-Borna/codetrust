"""Tests for AST-based code analysis (Layer 3)."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from fastapi.testclient import TestClient

from src.models.enums import Language, Severity
from src.models.responses import Finding
from src.services.ast_analyzer import (
    COMPLEXITY_THRESHOLD,
    LANGUAGE_NODES,
    SUPPORTED_LANGUAGES,
    AstAnalyzer,
    _find_nodes_by_type,
    _get_function_name,
    _walk_tree,
)


@pytest.fixture()
def analyzer() -> AstAnalyzer:
    """Create an AstAnalyzer instance for testing."""
    return AstAnalyzer()


# ---------------------------------------------------------------------------
# Parsing tests
# ---------------------------------------------------------------------------


class TestParseCode:
    """Tests for AstAnalyzer.parse_code."""

    def test_parse_python_code(self, analyzer: AstAnalyzer) -> None:
        """Parse valid Python code into a tree."""
        tree = analyzer.parse_code("x = 1\n", Language.PYTHON)
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_parse_javascript_code(self, analyzer: AstAnalyzer) -> None:
        """Parse valid JavaScript code into a tree."""
        tree = analyzer.parse_code("const x = 1;\n", Language.JAVASCRIPT)
        assert tree is not None
        assert tree.root_node.type == "program"

    def test_parse_typescript_code(self, analyzer: AstAnalyzer) -> None:
        """Parse valid TypeScript code into a tree."""
        tree = analyzer.parse_code("const x: number = 1;\n", Language.TYPESCRIPT)
        assert tree is not None
        assert tree.root_node.type == "program"

    def test_parse_go_code(self, analyzer: AstAnalyzer) -> None:
        """Parse valid Go code into a tree."""
        code = "package main\nfunc main() {}\n"
        tree = analyzer.parse_code(code, Language.GO)
        assert tree is not None
        assert tree.root_node.type == "source_file"

    def test_parse_rust_code(self, analyzer: AstAnalyzer) -> None:
        """Parse valid Rust code into a tree."""
        code = "fn main() {}\n"
        tree = analyzer.parse_code(code, Language.RUST)
        assert tree is not None
        assert tree.root_node.type == "source_file"

    def test_parse_empty_code(self, analyzer: AstAnalyzer) -> None:
        """Parse empty code returns a tree with empty root."""
        tree = analyzer.parse_code("", Language.PYTHON)
        assert tree is not None
        assert tree.root_node.child_count == 0

    def test_language_caching(self, analyzer: AstAnalyzer) -> None:
        """Language is cached after first load."""
        analyzer.parse_code("x = 1\n", Language.PYTHON)
        assert Language.PYTHON in analyzer._language_cache

        # Second parse should use cache
        tree = analyzer.parse_code("y = 2\n", Language.PYTHON)
        assert tree is not None


# ---------------------------------------------------------------------------
# Complexity tests
# ---------------------------------------------------------------------------


class TestComplexityAnalysis:
    """Tests for cyclomatic complexity detection."""

    def test_simple_function_passes(self, analyzer: AstAnalyzer) -> None:
        """Simple function with no branches has complexity 1."""
        code = "def foo():\n    return 1\n"
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 0

    def test_high_complexity_flagged(self, analyzer: AstAnalyzer) -> None:
        """Function with many branches is flagged."""
        branches = "\n".join(
            f"    if x == {i}:\n        pass" for i in range(12)
        )
        code = f"def complex_func(x):\n{branches}\n"

        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 1
        assert complexity_findings[0].severity == Severity.WARN
        assert "complex_func" in complexity_findings[0].message

    def test_complexity_threshold_boundary(
        self, analyzer: AstAnalyzer
    ) -> None:
        """Complexity exactly at threshold is not flagged."""
        branches = "\n".join(
            f"    if x == {i}:\n        pass"
            for i in range(COMPLEXITY_THRESHOLD - 1)
        )
        code = f"def boundary_func(x):\n{branches}\n"

        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 0

    def test_complexity_includes_elif(self, analyzer: AstAnalyzer) -> None:
        """elif clauses contribute to complexity."""
        code = (
            "def branchy(x):\n"
            "    if x == 1:\n        pass\n"
            "    elif x == 2:\n        pass\n"
            "    elif x == 3:\n        pass\n"
            "    elif x == 4:\n        pass\n"
            "    elif x == 5:\n        pass\n"
            "    elif x == 6:\n        pass\n"
            "    elif x == 7:\n        pass\n"
            "    elif x == 8:\n        pass\n"
            "    elif x == 9:\n        pass\n"
            "    elif x == 10:\n        pass\n"
            "    elif x == 11:\n        pass\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 1

    def test_complexity_includes_loops(self, analyzer: AstAnalyzer) -> None:
        """For and while loops contribute to complexity."""
        code = (
            "def loopy(items):\n"
            "    for i in items:\n"
            "        for j in items:\n"
            "            if i == j:\n"
            "                while True:\n"
            "                    if i > 0:\n                        break\n"
            "                    if j > 0:\n                        break\n"
            "                    if i == 0:\n                        break\n"
            "                    if j == 0:\n                        break\n"
            "                    if i + j > 10:\n                        break\n"
            "                    if i + j < 0:\n                        break\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 1

    def test_custom_threshold(self, analyzer: AstAnalyzer) -> None:
        """Custom complexity threshold is respected."""
        code = (
            "def small(x):\n"
            "    if x == 1:\n        pass\n"
            "    if x == 2:\n        pass\n"
        )
        # Complexity = 3 (1 base + 2 if), threshold=2 should flag it
        findings = analyzer.analyze(
            code, Language.PYTHON, "test.py",
            complexity_threshold=2,
        )
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 1

    def test_multiple_functions_analyzed(
        self, analyzer: AstAnalyzer
    ) -> None:
        """Each function is analyzed independently."""
        # One simple, one complex
        branches = "\n".join(
            f"    if x == {i}:\n        pass" for i in range(12)
        )
        code = (
            f"def simple():\n    return 1\n\n"
            f"def complex_one(x):\n{branches}\n"
        )

        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 1
        assert "complex_one" in complexity_findings[0].message

    def test_js_complexity(self, analyzer: AstAnalyzer) -> None:
        """Complexity analysis works for JavaScript."""
        branches = "\n".join(
            f"    if (x === {i}) {{ }}" for i in range(12)
        )
        code = f"function complex(x) {{\n{branches}\n}}\n"

        findings = analyzer.analyze(code, Language.JAVASCRIPT, "test.js")
        complexity_findings = [
            f for f in findings if f.rule_id == "ast_high_complexity"
        ]
        assert len(complexity_findings) == 1


# ---------------------------------------------------------------------------
# Unused variable tests
# ---------------------------------------------------------------------------


class TestUnusedVariables:
    """Tests for unused variable detection."""

    def test_unused_variable_flagged(self, analyzer: AstAnalyzer) -> None:
        """Variable assigned but never used is flagged."""
        code = "def foo():\n    unused = 42\n    return 1\n"
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unused_findings = [
            f for f in findings if f.rule_id == "ast_unused_variable"
        ]
        assert len(unused_findings) == 1
        assert "unused" in unused_findings[0].message

    def test_used_variable_not_flagged(self, analyzer: AstAnalyzer) -> None:
        """Variable assigned and used is not flagged."""
        code = "def foo():\n    x = 42\n    return x\n"
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unused_findings = [
            f for f in findings if f.rule_id == "ast_unused_variable"
        ]
        assert len(unused_findings) == 0

    def test_underscore_prefix_not_flagged(
        self, analyzer: AstAnalyzer
    ) -> None:
        """Variables prefixed with _ are intentionally unused."""
        code = "def foo():\n    _ignored = 42\n    return 1\n"
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unused_findings = [
            f for f in findings if f.rule_id == "ast_unused_variable"
        ]
        assert len(unused_findings) == 0

    def test_multiple_unused(self, analyzer: AstAnalyzer) -> None:
        """Multiple unused variables are each flagged."""
        code = (
            "def foo():\n"
            "    a = 1\n"
            "    b = 2\n"
            "    c = 3\n"
            "    return 0\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unused_findings = [
            f for f in findings if f.rule_id == "ast_unused_variable"
        ]
        assert len(unused_findings) == 3

    def test_unused_severity_is_info(self, analyzer: AstAnalyzer) -> None:
        """Unused variables have INFO severity."""
        code = "def foo():\n    unused = 42\n    return 1\n"
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unused_findings = [
            f for f in findings if f.rule_id == "ast_unused_variable"
        ]
        assert unused_findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Unreachable code tests
# ---------------------------------------------------------------------------


class TestUnreachableCode:
    """Tests for unreachable code detection."""

    def test_code_after_return(self, analyzer: AstAnalyzer) -> None:
        """Code after return is flagged as unreachable."""
        code = (
            "def foo():\n"
            "    return 1\n"
            "    x = 2\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unreachable = [
            f for f in findings if f.rule_id == "ast_unreachable_code"
        ]
        assert len(unreachable) == 1
        assert unreachable[0].severity == Severity.WARN

    def test_code_after_raise(self, analyzer: AstAnalyzer) -> None:
        """Code after raise is flagged as unreachable."""
        code = (
            "def foo():\n"
            "    raise ValueError('bad')\n"
            "    x = 2\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unreachable = [
            f for f in findings if f.rule_id == "ast_unreachable_code"
        ]
        assert len(unreachable) == 1

    def test_no_unreachable_in_clean_code(
        self, analyzer: AstAnalyzer
    ) -> None:
        """No unreachable code in well-structured function."""
        code = (
            "def foo(x):\n"
            "    if x > 0:\n"
            "        return x\n"
            "    return 0\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unreachable = [
            f for f in findings if f.rule_id == "ast_unreachable_code"
        ]
        assert len(unreachable) == 0

    def test_return_at_end_is_fine(self, analyzer: AstAnalyzer) -> None:
        """Return at the end of a function is not unreachable."""
        code = (
            "def foo():\n"
            "    x = 1\n"
            "    y = 2\n"
            "    return x + y\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        unreachable = [
            f for f in findings if f.rule_id == "ast_unreachable_code"
        ]
        assert len(unreachable) == 0


# ---------------------------------------------------------------------------
# Deep nesting tests
# ---------------------------------------------------------------------------


class TestDeepNesting:
    """Tests for deep nesting detection."""

    def test_deep_nesting_flagged(self, analyzer: AstAnalyzer) -> None:
        """Code nested beyond max depth is flagged."""
        code = (
            "def foo(x):\n"
            "    if x > 0:\n"
            "        if x > 1:\n"
            "            if x > 2:\n"
            "                if x > 3:\n"
            "                    if x > 4:\n"
            "                        pass\n"
        )
        findings = analyzer.analyze(
            code, Language.PYTHON, "test.py", max_nesting=4,
        )
        nesting = [
            f for f in findings if f.rule_id == "ast_deep_nesting"
        ]
        assert len(nesting) >= 1
        assert nesting[0].severity == Severity.WARN

    def test_shallow_nesting_passes(self, analyzer: AstAnalyzer) -> None:
        """Code within nesting limit is not flagged."""
        code = (
            "def foo(x):\n"
            "    if x > 0:\n"
            "        if x > 1:\n"
            "            pass\n"
        )
        findings = analyzer.analyze(
            code, Language.PYTHON, "test.py", max_nesting=4,
        )
        nesting = [
            f for f in findings if f.rule_id == "ast_deep_nesting"
        ]
        assert len(nesting) == 0

    def test_nesting_at_boundary_passes(
        self, analyzer: AstAnalyzer
    ) -> None:
        """Nesting exactly at max depth is not flagged."""
        code = (
            "def foo(x):\n"
            "    if x > 0:\n"
            "        if x > 1:\n"
            "            if x > 2:\n"
            "                if x > 3:\n"
            "                    pass\n"
        )
        findings = analyzer.analyze(
            code, Language.PYTHON, "test.py", max_nesting=4,
        )
        nesting = [
            f for f in findings if f.rule_id == "ast_deep_nesting"
        ]
        assert len(nesting) == 0

    def test_custom_max_nesting(self, analyzer: AstAnalyzer) -> None:
        """Custom max_nesting parameter is respected."""
        code = (
            "def foo(x):\n"
            "    if x > 0:\n"
            "        if x > 1:\n"
            "            pass\n"
        )
        findings = analyzer.analyze(
            code, Language.PYTHON, "test.py", max_nesting=1,
        )
        nesting = [
            f for f in findings if f.rule_id == "ast_deep_nesting"
        ]
        assert len(nesting) >= 1

    def test_nesting_with_loops(self, analyzer: AstAnalyzer) -> None:
        """Loops count toward nesting depth."""
        code = (
            "def foo(items):\n"
            "    for i in items:\n"
            "        for j in items:\n"
            "            for k in items:\n"
            "                for m in items:\n"
            "                    for n in items:\n"
            "                        pass\n"
        )
        findings = analyzer.analyze(
            code, Language.PYTHON, "test.py", max_nesting=4,
        )
        nesting = [
            f for f in findings if f.rule_id == "ast_deep_nesting"
        ]
        assert len(nesting) >= 1


# ---------------------------------------------------------------------------
# Full analysis orchestration
# ---------------------------------------------------------------------------


class TestAnalyze:
    """Tests for the full analyze() orchestration."""

    def test_analyze_returns_all_finding_types(
        self, analyzer: AstAnalyzer
    ) -> None:
        """Analyze detects multiple issue types in one pass."""
        code = (
            "def problematic(x):\n"
            "    unused = 42\n"
            "    return 1\n"
            "    dead_code = 2\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        rule_ids = {f.rule_id for f in findings}
        assert "ast_unused_variable" in rule_ids
        assert "ast_unreachable_code" in rule_ids

    def test_analyze_clean_code(self, analyzer: AstAnalyzer) -> None:
        """Clean code returns no findings."""
        code = (
            "def add(a, b):\n"
            "    return a + b\n"
        )
        findings = analyzer.analyze(code, Language.PYTHON, "test.py")
        assert len(findings) == 0

    def test_analyze_all_languages_supported(
        self, analyzer: AstAnalyzer
    ) -> None:
        """All supported languages can be analyzed without error."""
        samples = {
            Language.PYTHON: "def foo():\n    return 1\n",
            Language.JAVASCRIPT: "function foo() { return 1; }\n",
            Language.TYPESCRIPT: "function foo(): number { return 1; }\n",
            Language.GO: "package main\nfunc foo() int { return 1 }\n",
            Language.RUST: "fn foo() -> i32 { 1 }\n",
        }
        for lang, code in samples.items():
            findings = analyzer.analyze(code, lang, f"test.{lang}")
            # Should not raise
            assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# Report / response building
# ---------------------------------------------------------------------------


class TestBuildReport:
    """Tests for markdown report and response building."""

    def test_build_report_pass(self, analyzer: AstAnalyzer) -> None:
        """Clean findings produce PASS verdict."""
        report = analyzer.build_report([])
        assert "PASS" in report
        assert "0 blocks" in report

    def test_build_report_with_findings(
        self, analyzer: AstAnalyzer
    ) -> None:
        """Findings are included in the report."""
        findings = [
            Finding(
                rule_id="ast_high_complexity",
                severity=Severity.WARN,
                message="Function 'foo' has cyclomatic complexity 15",
                file="test.py",
                line=1,
                suggestion="Split into smaller functions",
            ),
        ]
        report = analyzer.build_report(findings)
        assert "WARN" in report
        assert "foo" in report
        assert "1 warnings" in report

    def test_build_scan_response(self, analyzer: AstAnalyzer) -> None:
        """build_scan_response returns correct structure."""
        findings = [
            Finding(
                rule_id="test",
                severity=Severity.WARN,
                message="test warning",
                file="f.py",
                line=1,
            ),
            Finding(
                rule_id="test2",
                severity=Severity.INFO,
                message="test info",
                file="f.py",
                line=2,
            ),
        ]
        resp = analyzer.build_scan_response(findings)
        assert resp["total_findings"] == 2
        assert resp["blocks"] == 0
        assert resp["warnings"] == 1
        assert resp["infos"] == 1
        assert resp["verdict"] == "WARN"

    def test_build_scan_response_pass(self, analyzer: AstAnalyzer) -> None:
        """Empty findings produce PASS verdict."""
        resp = analyzer.build_scan_response([])
        assert resp["verdict"] == "PASS"
        assert resp["total_findings"] == 0


# ---------------------------------------------------------------------------
# Tree utilities
# ---------------------------------------------------------------------------


class TestTreeUtilities:
    """Tests for tree walking utility functions."""

    def test_walk_tree_visits_all_nodes(
        self, analyzer: AstAnalyzer
    ) -> None:
        """_walk_tree visits every node in the tree."""
        tree = analyzer.parse_code("x = 1\n", Language.PYTHON)
        assert tree is not None
        nodes = list(_walk_tree(tree.root_node))
        assert len(nodes) > 1  # At least root + children

    def test_find_nodes_by_type(self, analyzer: AstAnalyzer) -> None:
        """_find_nodes_by_type finds matching nodes."""
        code = "def foo():\n    pass\ndef bar():\n    pass\n"
        tree = analyzer.parse_code(code, Language.PYTHON)
        assert tree is not None
        funcs = _find_nodes_by_type(
            tree.root_node, ("function_definition",),
        )
        assert len(funcs) == 2

    def test_get_function_name(self, analyzer: AstAnalyzer) -> None:
        """_get_function_name extracts function name."""
        code = "def hello_world():\n    pass\n"
        tree = analyzer.parse_code(code, Language.PYTHON)
        assert tree is not None
        funcs = _find_nodes_by_type(
            tree.root_node, ("function_definition",),
        )
        assert len(funcs) == 1
        assert _get_function_name(funcs[0]) == "hello_world"


# ---------------------------------------------------------------------------
# Language support
# ---------------------------------------------------------------------------


class TestLanguageSupport:
    """Tests for language support configuration."""

    def test_all_languages_have_nodes(self) -> None:
        """Every supported language has a LanguageNodes config."""
        for lang in SUPPORTED_LANGUAGES:
            assert lang in LANGUAGE_NODES

    def test_supported_languages_complete(self) -> None:
        """All five languages are supported."""
        assert Language.PYTHON in SUPPORTED_LANGUAGES
        assert Language.JAVASCRIPT in SUPPORTED_LANGUAGES
        assert Language.TYPESCRIPT in SUPPORTED_LANGUAGES
        assert Language.GO in SUPPORTED_LANGUAGES
        assert Language.RUST in SUPPORTED_LANGUAGES


# ---------------------------------------------------------------------------
# API endpoint tests
# ---------------------------------------------------------------------------


class TestAstScanEndpoint:
    """Tests for POST /v1/scan/ast API endpoint."""

    @pytest.fixture()
    def client(self) -> TestClient:
        """Create a TestClient with AST analyzer in app state."""
        import fakeredis.aioredis
        from fastapi.testclient import TestClient

        from src.api import app
        from src.services.cache import CacheService
        from src.services.docker_verify import DockerVerifyService
        from src.services.registry import RegistryService
        from src.services.static_analyzer import StaticAnalyzer

        cache = CacheService("redis://localhost:6379")
        cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        http_client = __import__("httpx").AsyncClient()

        app.state.cache = cache
        app.state.http_client = http_client
        app.state.registry = RegistryService(cache, http_client)
        app.state.docker = DockerVerifyService(cache, http_client)
        app.state.analyzer = StaticAnalyzer()
        app.state.ast_analyzer = AstAnalyzer()
        app.state.db = None
        app.state.billing = None
        app.state.auth = None
        app.state.rate_limiter = None

        return TestClient(app, raise_server_exceptions=False)

    def test_ast_scan_clean_code(self, client: TestClient) -> None:
        """AST scan of clean code returns PASS."""
        response = client.post("/v1/scan/ast", json={
            "code": "def foo():\n    return 1\n",
            "language": "python",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PASS"
        assert data["total_findings"] == 0

    def test_ast_scan_complex_code(self, client: TestClient) -> None:
        """AST scan detects high complexity."""
        branches = "\n".join(
            f"    if x == {i}:\n        pass" for i in range(12)
        )
        code = f"def complex_func(x):\n{branches}\n"

        response = client.post("/v1/scan/ast", json={
            "code": code,
            "language": "python",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "WARN"
        assert data["warnings"] > 0

    def test_ast_scan_requires_language(
        self, client: TestClient
    ) -> None:
        """AST scan requires language field."""
        response = client.post("/v1/scan/ast", json={
            "code": "x = 1\n",
        })
        assert response.status_code == 422

    def test_ast_scan_response_model(self, client: TestClient) -> None:
        """AST scan response matches AstScanResponse schema."""
        response = client.post("/v1/scan/ast", json={
            "code": "def foo():\n    unused = 42\n    return 1\n",
            "language": "python",
        })
        assert response.status_code == 200
        data = response.json()
        assert "total_findings" in data
        assert "blocks" in data
        assert "warnings" in data
        assert "infos" in data
        assert "findings" in data
        assert "verdict" in data


# ---------------------------------------------------------------------------
# Deep scan AST integration tests
# ---------------------------------------------------------------------------


class TestDeepScanAstIntegration:
    """Tests for AST integration in deep scan."""

    @pytest.fixture()
    def client(self) -> TestClient:
        """Create a TestClient with all services."""
        import fakeredis.aioredis
        from fastapi.testclient import TestClient

        from src.api import app
        from src.services.cache import CacheService
        from src.services.docker_verify import DockerVerifyService
        from src.services.registry import RegistryService
        from src.services.static_analyzer import StaticAnalyzer

        cache = CacheService("redis://localhost:6379")
        cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        http_client = __import__("httpx").AsyncClient()

        app.state.cache = cache
        app.state.http_client = http_client
        app.state.registry = RegistryService(cache, http_client)
        app.state.docker = DockerVerifyService(cache, http_client)
        app.state.analyzer = StaticAnalyzer()
        app.state.ast_analyzer = AstAnalyzer()
        app.state.db = None
        app.state.billing = None
        app.state.auth = None
        app.state.rate_limiter = None

        return TestClient(app, raise_server_exceptions=False)

    def test_deep_scan_includes_ast(self, client: TestClient) -> None:
        """Deep scan includes AST results when language is supported."""
        response = client.post("/v1/scan/deep", json={
            "code": "def foo():\n    return 1\n",
            "language": "python",
            "verify_imports": False,
        })
        assert response.status_code == 200
        data = response.json()
        assert "ast_scan" in data
        assert data["ast_scan"] is not None
        assert data["ast_scan"]["verdict"] == "PASS"

    def test_deep_scan_ast_findings_in_total(
        self, client: TestClient
    ) -> None:
        """AST findings are counted in total_findings."""
        code = "def foo():\n    unused = 42\n    return 1\n"
        response = client.post("/v1/scan/deep", json={
            "code": code,
            "language": "python",
            "verify_imports": False,
        })
        assert response.status_code == 200
        data = response.json()
        ast_findings = data["ast_scan"]["total_findings"]
        assert ast_findings > 0
        assert data["total_findings"] >= ast_findings
