# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the taint analysis engine."""

import pytest

from src.models.enums import Language, Severity
from src.services.taint_analyzer import TaintAnalyzer


@pytest.fixture()
def analyzer() -> TaintAnalyzer:
    """Create a TaintAnalyzer instance."""
    return TaintAnalyzer()


# ---------------------------------------------------------------------------
# Python taint detection
# ---------------------------------------------------------------------------


class TestPythonTaint:
    """Tests for Python source-to-sink taint tracking."""

    def test_sql_injection(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to cursor.execute()."""
        code = '''
def handle_request(request):
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK
        assert "request.args" in taint[0].message
        assert "cursor.execute" in taint[0].message

    def test_command_injection(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to os.system()."""
        code = '''
def run_command(request):
    cmd = request.form.get('cmd')
    os.system(cmd)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_ssrf(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to requests.get()."""
        code = '''
def fetch_url(request):
    url = request.args.get('url')
    requests.get(url)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_ssrf"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_path_traversal(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to open()."""
        code = '''
def read_file(request):
    filename = request.args.get('file')
    open(filename)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_path_traversal"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_variable_propagation_chain(self, analyzer: TaintAnalyzer) -> None:
        """Detect taint flowing through a chain of variable assignments."""
        code = '''
def multi_hop(request):
    x = request.args.get('x')
    y = x
    z = y
    os.system(z)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) >= 1
        assert "z" in taint[0].message

    def test_clean_code_no_findings(self, analyzer: TaintAnalyzer) -> None:
        """Functions without taint flows produce no findings."""
        code = '''
def safe_handler():
    name = "hardcoded"
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id.startswith("taint_")]
        assert len(taint) == 0

    def test_sanitized_flow_lower_severity(self, analyzer: TaintAnalyzer) -> None:
        """Sanitized tainted data should report with lower confidence/severity."""
        code = '''
def safe_int_cast(request):
    user_input = request.args.get('id')
    safe_id = int(user_input)
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_id}")
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        if taint:
            assert taint[0].severity == Severity.WARN
            assert taint[0].confidence < 0.5

    def test_deserialization_sink(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to pickle.loads()."""
        code = '''
def deserialize(request):
    data = request.data
    pickle.loads(data)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_deserialization"]
        assert len(taint) >= 1

    def test_xss_render_template_string(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to render_template_string()."""
        code = '''
def render_page(request):
    name = request.args.get('name')
    render_template_string(name)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_xss"]
        assert len(taint) >= 1


# ---------------------------------------------------------------------------
# JavaScript taint detection
# ---------------------------------------------------------------------------


class TestJavaScriptTaint:
    """Tests for JavaScript source-to-sink taint tracking."""

    def test_sql_injection(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to db.query()."""
        code = '''
function handleRequest(req, res) {
    const id = req.params.id;
    db.query("SELECT * FROM users WHERE id = " + id);
}
'''
        findings = analyzer.analyze(code, Language.JAVASCRIPT, "app.js")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_xss_innerhtml(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to innerHTML."""
        code = '''
function renderPage(req, res) {
    const data = req.body.name;
    element.innerHTML = data;
}
'''
        findings = analyzer.analyze(code, Language.JAVASCRIPT, "app.js")
        taint = [f for f in findings if f.rule_id == "taint_xss"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_clean_js_no_findings(self, analyzer: TaintAnalyzer) -> None:
        """Clean JavaScript functions produce no taint findings."""
        code = '''
function safeQuery() {
    const name = "literal";
    db.query("SELECT * FROM users WHERE name = ?", [name]);
}
'''
        findings = analyzer.analyze(code, Language.JAVASCRIPT, "app.js")
        taint = [f for f in findings if f.rule_id.startswith("taint_")]
        assert len(taint) == 0

    def test_variable_propagation_js(self, analyzer: TaintAnalyzer) -> None:
        """Detect taint propagation through JS variable reassignment."""
        code = '''
function process(req, res) {
    const input = req.query.search;
    const term = input;
    document.write(term);
}
'''
        findings = analyzer.analyze(code, Language.JAVASCRIPT, "app.js")
        taint = [f for f in findings if f.rule_id == "taint_xss"]
        assert len(taint) >= 1


# ---------------------------------------------------------------------------
# Edge cases and robustness
# ---------------------------------------------------------------------------


class TestTaintEdgeCases:
    """Tests for edge cases in taint analysis."""

    def test_empty_code(self, analyzer: TaintAnalyzer) -> None:
        """Empty code should produce no findings."""
        findings = analyzer.analyze("", Language.PYTHON, "empty.py")
        assert len(findings) == 0

    def test_no_functions(self, analyzer: TaintAnalyzer) -> None:
        """Module-level code without functions produces no findings."""
        code = "x = 42\ny = x + 1\n"
        findings = analyzer.analyze(code, Language.PYTHON, "module.py")
        assert len(findings) == 0

    def test_unsupported_language(self, analyzer: TaintAnalyzer) -> None:
        """Unsupported language returns empty findings gracefully."""
        findings = analyzer.analyze("some code", Language.JSON, "data.json")
        assert len(findings) == 0

    def test_finding_has_file_and_line(self, analyzer: TaintAnalyzer) -> None:
        """Findings include correct file and line metadata."""
        code = '''
def handler(request):
    val = request.args.get('x')
    os.system(val)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "handler.py")
        taint = [f for f in findings if f.rule_id.startswith("taint_")]
        assert len(taint) >= 1
        assert taint[0].file == "handler.py"
        assert taint[0].line > 0

    def test_finding_has_suggestion(self, analyzer: TaintAnalyzer) -> None:
        """Findings include remediation suggestions."""
        code = '''
def handler(request):
    val = request.args.get('x')
    cursor.execute(val)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "handler.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1
        assert taint[0].suggestion != ""
        assert "parameterized" in taint[0].suggestion.lower()

    def test_multiple_functions_independent(self, analyzer: TaintAnalyzer) -> None:
        """Taint does not leak between separate functions."""
        code = '''
def tainted_func(request):
    val = request.args.get('x')

def clean_func():
    safe = "constant"
    os.system(safe)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) == 0
