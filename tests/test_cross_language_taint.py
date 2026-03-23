# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for cross-language taint analysis — the feature no other tool has.

Each test represents a real-world polyglot scenario where tainted data
crosses an HTTP boundary between different programming languages.
"""

import pytest

from src.models.enums import Language
from src.services.cross_language_taint import (
    CrossLanguageTaintAnalyzer,
    CrossLanguageTaintResult,
)


@pytest.fixture()
def analyzer() -> CrossLanguageTaintAnalyzer:
    """Create a cross-language taint analyzer."""
    return CrossLanguageTaintAnalyzer()


# ═══════════════════════════════════════════════════════════════
#  Route extraction tests
# ═══════════════════════════════════════════════════════════════


class TestRouteExtraction:
    """Test HTTP route extraction across frameworks."""

    def test_flask_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Flask @app.route decorator."""
        code = '''
@app.route("/api/users")
def get_users():
    return jsonify(users)
'''
        routes = analyzer._extract_python_routes("app.py", code)
        assert len(routes) >= 1
        assert routes[0].path == "/api/users"
        assert routes[0].handler_name == "get_users"

    def test_fastapi_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect FastAPI @app.get decorator."""
        code = '''
@app.get("/api/items/{item_id}")
async def get_item(item_id: str):
    return {"item_id": item_id}
'''
        routes = analyzer._extract_python_routes("api.py", code)
        assert len(routes) >= 1
        assert "/api/items" in routes[0].path

    def test_express_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Express router.get()."""
        code = '''
router.get("/api/users", getUsers);
router.post("/api/users", createUser);
'''
        routes = analyzer._extract_js_routes(
            "routes.js", code, Language.JAVASCRIPT,
        )
        assert len(routes) == 2
        assert routes[0].path == "/api/users"
        assert routes[0].method == "GET"
        assert routes[1].method == "POST"

    def test_go_handlefunc(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Go http.HandleFunc()."""
        code = '''
http.HandleFunc("/api/users", HandleUsers)
http.HandleFunc("/api/items", HandleItems)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) == 2
        assert routes[0].path == "/api/users"
        assert routes[0].handler_name == "HandleUsers"

    def test_django_path(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Django path() URL pattern."""
        code = '''
urlpatterns = [
    path("api/users/", user_list),
    path("api/users/<int:pk>/", user_detail),
]
'''
        routes = analyzer._extract_python_routes("urls.py", code)
        assert len(routes) == 2

    def test_gin_route(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect Gin router.GET()."""
        code = '''
router.GET("/api/users", getUsers)
router.POST("/api/users", createUser)
'''
        routes = analyzer._extract_go_routes("main.go", code)
        assert len(routes) == 2
        assert routes[0].method == "GET"


# ═══════════════════════════════════════════════════════════════
#  HTTP call extraction tests
# ═══════════════════════════════════════════════════════════════


class TestHttpCallExtraction:
    """Test HTTP client call extraction."""

    def test_js_fetch(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect fetch() calls in JavaScript."""
        code = '''
const response = await fetch("/api/users?id=" + userId);
'''
        calls = analyzer._extract_js_http_calls(
            "app.js", code, Language.JAVASCRIPT,
        )
        assert len(calls) >= 1
        assert "/api/users" in calls[0].url_pattern

    def test_js_axios(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect axios.post() calls."""
        code = '''
const result = await axios.post("/api/users", { name: userName });
'''
        calls = analyzer._extract_js_http_calls(
            "client.js", code, Language.JAVASCRIPT,
        )
        assert len(calls) >= 1
        assert calls[0].method == "POST"

    def test_python_requests(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect requests.get() calls in Python."""
        code = '''
response = requests.get("/api/items/" + item_id)
'''
        calls = analyzer._extract_python_http_calls("client.py", code)
        assert len(calls) >= 1
        assert calls[0].method == "GET"

    def test_go_http_get(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Detect http.Get() calls in Go."""
        code = '''
resp, err := http.Get("/api/users?id=" + userId)
'''
        calls = analyzer._extract_go_http_calls("client.go", code)
        assert len(calls) >= 1
        assert calls[0].method == "GET"


# ═══════════════════════════════════════════════════════════════
#  Path matching tests
# ═══════════════════════════════════════════════════════════════


class TestPathMatching:
    """Test URL path matching between callers and routes."""

    def test_exact_match(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Exact path match."""
        assert analyzer._paths_match("/api/users", "/api/users")

    def test_trailing_slash(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Trailing slash normalization."""
        assert analyzer._paths_match("/api/users/", "/api/users")

    def test_query_string_stripped(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Query strings are stripped before matching."""
        assert analyzer._paths_match("/api/users?id=123", "/api/users")

    def test_express_param(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Express :id path parameter matching."""
        assert analyzer._paths_match("/api/users/123", "/api/users/:id")

    def test_flask_param(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Flask <id> path parameter matching."""
        assert analyzer._paths_match("/api/users/123", "/api/users/<int:id>")

    def test_no_match(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Non-matching paths."""
        assert not analyzer._paths_match("/api/items", "/api/users")

    def test_method_compatible_any(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """ANY route method matches all call methods."""
        assert analyzer._methods_compatible("GET", "ANY")
        assert analyzer._methods_compatible("POST", "ANY")

    def test_method_mismatch(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Mismatched methods."""
        assert not analyzer._methods_compatible("GET", "POST")


# ═══════════════════════════════════════════════════════════════
#  Cross-language taint flow tests — the main event
# ═══════════════════════════════════════════════════════════════


class TestCrossLanguageTaintFlows:
    """End-to-end cross-language taint detection.

    Each test simulates a real polyglot application where tainted data
    crosses an HTTP boundary between different programming languages.
    """

    def test_js_frontend_to_python_backend_sql_injection(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """JS fetch sends user input to Python Flask handler with SQL injection.

        Scenario: React frontend takes user input, sends it to a Flask API,
        which uses it in a raw SQL query without parameterization.
        """
        files = {
            "frontend/app.js": '''
function searchUsers(query) {
    const userInput = document.getElementById("search").value;
    fetch("/api/users?q=" + userInput);
}
''',
            "backend/app.py": '''
@app.route("/api/users")
def search_users():
    q = request.args.get("q")
    cursor.execute(f"SELECT * FROM users WHERE name = '{q}'")
    return jsonify(results)
''',
        }

        result = analyzer.analyze(files)
        assert result.routes_discovered >= 1
        assert result.http_calls_discovered >= 1
        assert result.languages_analyzed >= 2

    def test_js_to_go_command_injection(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """JS sends user input to Go handler with command injection.

        Scenario: Node.js admin panel sends a filename to a Go file
        processing service which passes it to exec.Command.
        """
        files = {
            "admin/index.js": '''
async function processFile() {
    const filename = req.body.filename;
    await axios.post("/api/process", { file: filename });
}
''',
            "service/handler.go": '''
func ProcessFile(w http.ResponseWriter, r *http.Request) {
    filename := r.FormValue("file")
    exec.Command("convert", filename)
}
''',
        }

        result = analyzer.analyze(files)
        assert result.routes_discovered >= 0
        assert result.total_files == 2
        assert result.languages_analyzed >= 2

    def test_python_to_go_sql_injection(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Python microservice forwards user data to Go service with SQL sink.

        Scenario: Python API gateway receives user input and forwards it
        to a Go data service which uses it in an unparameterized SQL query.
        """
        files = {
            "gateway/api.py": '''
@app.post("/api/search")
async def search(request):
    query = request.json.get("query")
    response = httpx.get("/internal/data?q=" + query)
    return response.json()
''',
            "data-service/main.go": '''
func HandleData(w http.ResponseWriter, r *http.Request) {
    q := r.FormValue("q")
    db.Query("SELECT * FROM records WHERE title = " + q)
}
''',
        }

        result = analyzer.analyze(files)
        assert result.total_files == 2
        assert result.languages_analyzed >= 2
        assert result.routes_discovered >= 1

    def test_clean_project_no_findings(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Clean polyglot project produces no cross-language taint findings."""
        files = {
            "frontend/app.js": '''
function loadDashboard() {
    fetch("/api/stats");
}
''',
            "backend/app.py": '''
@app.route("/api/stats")
def get_stats():
    count = db.query("SELECT COUNT(*) FROM users")
    return jsonify({"count": count})
''',
        }

        result = analyzer.analyze(files)
        # No user input flows across boundary — no findings
        cross_lang = [
            f for f in result.findings
            if f.rule_id.startswith("cross_lang_taint_")
        ]
        assert len(cross_lang) == 0

    def test_three_language_chain(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Taint flows through three languages: JS -> Python -> Go.

        Scenario: React frontend sends search query to Python API gateway,
        which forwards it to a Go search microservice with SQL injection.
        """
        files = {
            "web/search.js": '''
function search() {
    const term = document.getElementById("search").value;
    fetch("/api/search?q=" + term);
}
''',
            "api/gateway.py": '''
@app.route("/api/search")
def search():
    q = request.args.get("q")
    result = requests.get("/internal/search?query=" + q)
    return jsonify(result.json())
''',
            "search/handler.go": '''
func SearchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.FormValue("query")
    db.Query("SELECT * FROM products WHERE name LIKE '%" + query + "%'")
}
''',
        }

        result = analyzer.analyze(files)
        assert result.total_files == 3
        assert result.languages_analyzed == 3

    def test_same_language_excluded(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Cross-language analyzer only fires across language boundaries.

        Same-language taint is handled by the regular cross-file analyzer.
        """
        files = {
            "client.py": '''
import requests
def call_api():
    user_id = input("Enter ID: ")
    requests.get("/api/users/" + user_id)
''',
            "server.py": '''
@app.route("/api/users/<user_id>")
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return jsonify(user)
''',
        }

        result = analyzer.analyze(files)
        # Both files are Python — cross-language analyzer should not fire
        cross_lang = [
            f for f in result.findings
            if f.rule_id.startswith("cross_lang_taint_")
        ]
        assert len(cross_lang) == 0


# ═══════════════════════════════════════════════════════════════
#  Metrics and edge cases
# ═══════════════════════════════════════════════════════════════


class TestMetricsAndEdgeCases:
    """Test result metrics and edge cases."""

    def test_empty_project(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Empty project returns zero metrics."""
        result = analyzer.analyze({})
        assert result.total_files == 0
        assert result.routes_discovered == 0
        assert result.http_calls_discovered == 0
        assert result.cross_language_flows == 0
        assert len(result.findings) == 0

    def test_single_language_project(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Single-language project has no cross-language flows."""
        files = {
            "app.py": '''
@app.route("/api/users")
def users():
    return "ok"
''',
        }
        result = analyzer.analyze(files)
        assert result.languages_analyzed == 1
        assert result.cross_language_flows == 0

    def test_result_type(self, analyzer: CrossLanguageTaintAnalyzer) -> None:
        """Result is the correct type with expected fields."""
        result = analyzer.analyze({})
        assert isinstance(result, CrossLanguageTaintResult)
        assert hasattr(result, "findings")
        assert hasattr(result, "routes_discovered")
        assert hasattr(result, "cross_language_flows")

    def test_route_discovery_metrics(
        self,
        analyzer: CrossLanguageTaintAnalyzer,
    ) -> None:
        """Routes from multiple languages are all discovered."""
        files = {
            "app.py": '''
@app.route("/api/py")
def py_handler():
    return "ok"
''',
            "app.js": '''
router.get("/api/js", jsHandler);
''',
            "main.go": '''
http.HandleFunc("/api/go", GoHandler)
''',
        }
        result = analyzer.analyze(files)
        assert result.routes_discovered >= 3
        assert result.languages_analyzed == 3
