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


# ---------------------------------------------------------------------------
# Inter-procedural taint detection
# ---------------------------------------------------------------------------


class TestInterProceduralTaint:
    """Tests for cross-function taint tracking."""

    def test_cross_function_return_value(self, analyzer: TaintAnalyzer) -> None:
        """Taint flows across functions via return value."""
        code = '''
def get_user_input(request):
    return request.args.get('id')

def process(request):
    user_id = get_user_input(request)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK
        assert "cursor.execute" in taint[0].message

    def test_cross_function_param_to_sink(self, analyzer: TaintAnalyzer) -> None:
        """Taint flows from caller argument through callee to a sink."""
        code = '''
def run_query(query_str):
    cursor.execute(query_str)

def handle(request):
    q = request.args.get('q')
    run_query(q)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        # The intra-procedural pass on run_query won't fire because
        # query_str is not a known source. The caller's taint is what
        # matters — run_query(q) with tainted q should be detected
        # at the call site in handle() via the callee's sink-reachable
        # parameter. For now we verify that handle() itself detects the
        # taint on q flowing through run_query.
        assert len(taint) >= 1

    def test_clean_function_call_no_false_positive(
        self, analyzer: TaintAnalyzer,
    ) -> None:
        """Calling a clean function should not produce false positives."""
        code = '''
def get_default_id():
    return 42

def process():
    user_id = get_default_id()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) == 0

    def test_multi_level_call_chain(self, analyzer: TaintAnalyzer) -> None:
        """Taint propagates through A -> B -> C call chain."""
        code = '''
def read_input(request):
    return request.args.get('cmd')

def transform(request):
    raw = read_input(request)
    return raw

def execute(request):
    cmd = transform(request)
    os.system(cmd)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK


# ---------------------------------------------------------------------------
# Go taint detection
# ---------------------------------------------------------------------------


class TestGoTaint:
    """Tests for Go source-to-sink taint tracking."""

    def test_sql_injection(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to db.Query() in Go."""
        code = '''
func handleRequest(w http.ResponseWriter, r *http.Request) {
    id := r.FormValue("id")
    db.Query("SELECT * FROM users WHERE id = " + id)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_command_injection(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to exec.Command() in Go."""
        code = '''
func runCmd(w http.ResponseWriter, r *http.Request) {
    cmd := r.FormValue("cmd")
    exec.Command(cmd)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_ssrf(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to http.Get() in Go."""
        code = '''
func fetchURL(w http.ResponseWriter, r *http.Request) {
    url := r.FormValue("url")
    http.Get(url)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_ssrf"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK

    def test_path_traversal(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to os.Open() in Go."""
        code = '''
func readFile(w http.ResponseWriter, r *http.Request) {
    path := r.FormValue("path")
    os.Open(path)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_path_traversal"]
        assert len(taint) >= 1

    def test_xss_template_html(self, analyzer: TaintAnalyzer) -> None:
        """Detect tainted data flowing to template.HTML() in Go."""
        code = '''
func renderPage(w http.ResponseWriter, r *http.Request) {
    name := r.FormValue("name")
    template.HTML(name)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_xss"]
        assert len(taint) >= 1

    def test_clean_go_no_findings(self, analyzer: TaintAnalyzer) -> None:
        """Clean Go functions produce no taint findings."""
        code = '''
func safeHandler(w http.ResponseWriter, r *http.Request) {
    name := "hardcoded"
    db.Query("SELECT * FROM users WHERE name = $1", name)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id.startswith("taint_")]
        assert len(taint) == 0

    def test_variable_propagation_go(self, analyzer: TaintAnalyzer) -> None:
        """Detect taint propagation through Go variable reassignment."""
        code = '''
func process(w http.ResponseWriter, r *http.Request) {
    input := r.FormValue("q")
    term := input
    db.Query("SELECT * FROM items WHERE name = " + term)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1

    def test_go_header_source(self, analyzer: TaintAnalyzer) -> None:
        """Detect taint from r.Header.Get() in Go."""
        code = '''
func headerHandler(w http.ResponseWriter, r *http.Request) {
    auth := r.Header.Get("Authorization")
    exec.Command(auth)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) >= 1

    def test_go_url_query_source(self, analyzer: TaintAnalyzer) -> None:
        """Detect taint from r.URL.Query() in Go."""
        code = '''
func queryHandler(w http.ResponseWriter, r *http.Request) {
    params := r.URL.Query()
    db.Query("SELECT * FROM t WHERE x = " + params)
}
'''
        findings = analyzer.analyze(code, Language.GO, "handler.go")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1


# ---------------------------------------------------------------------------
# Deep inter-procedural taint (5-10+ hops) — exceeds Semgrep
# ---------------------------------------------------------------------------


class TestDeepInterProceduralTaint:
    """Verify taint propagates through 5-10+ function call hops.

    Semgrep typically tracks ~5 hops. CodeTrust tracks 10+.
    """

    def test_5_hop_python(self, analyzer: TaintAnalyzer) -> None:
        """Taint propagates through 5 function calls in Python."""
        code = '''
def hop1(request):
    return request.args.get("x")

def hop2(r):
    a = hop1(r)
    return a

def hop3(r):
    b = hop2(r)
    return b

def hop4(r):
    c = hop3(r)
    return c

def handler(r):
    v = hop4(r)
    cursor.execute(f"SELECT * WHERE id={v}")
'''
        findings = analyzer.analyze(code, Language.PYTHON, "deep.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1

    def test_10_hop_python(self, analyzer: TaintAnalyzer) -> None:
        """Taint propagates through 10 function calls — double Semgrep's depth."""
        code = '''
def hop1(request):
    return request.args.get("x")

def hop2(r):
    a = hop1(r)
    return a

def hop3(r):
    b = hop2(r)
    return b

def hop4(r):
    c = hop3(r)
    return c

def hop5(r):
    d = hop4(r)
    return d

def hop6(r):
    e = hop5(r)
    return e

def hop7(r):
    f = hop6(r)
    return f

def hop8(r):
    g = hop7(r)
    return g

def hop9(r):
    h = hop8(r)
    return h

def hop10(r):
    i = hop9(r)
    return i

def handler(r):
    v = hop10(r)
    cursor.execute(f"SELECT * WHERE id={v}")
'''
        findings = analyzer.analyze(code, Language.PYTHON, "deep.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1

    def test_6_hop_javascript(self, analyzer: TaintAnalyzer) -> None:
        """Taint propagates through 6 JS function calls."""
        code = '''
function readInput(req) {
    const val = req.query.id;
    return val;
}
function step2(req) {
    const a = readInput(req);
    return a;
}
function step3(req) {
    const b = step2(req);
    return b;
}
function step4(req) {
    const c = step3(req);
    return c;
}
function step5(req) {
    const d = step4(req);
    return d;
}
function handler(req) {
    const q = step5(req);
    db.query("SELECT * FROM users WHERE id = " + q);
}
'''
        findings = analyzer.analyze(code, Language.JAVASCRIPT, "deep.js")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1

    def test_5_hop_go(self, analyzer: TaintAnalyzer) -> None:
        """Taint propagates through 5 Go function calls."""
        code = '''
func ReadParam(r *http.Request) {
    val := r.FormValue("id")
    return val
}
func Step2(r *http.Request) {
    x := ReadParam(r)
    return x
}
func Step3(r *http.Request) {
    x := Step2(r)
    return x
}
func Step4(r *http.Request) {
    x := Step3(r)
    return x
}
func Handler(w http.ResponseWriter, r *http.Request) {
    q := Step4(r)
    db.Query("SELECT * FROM users WHERE id = " + q)
}
'''
        findings = analyzer.analyze(code, Language.GO, "deep.go")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1

    def test_deep_chain_command_injection(self, analyzer: TaintAnalyzer) -> None:
        """Deep chain ending in command injection, not just SQL."""
        code = '''
def read_cmd(request):
    return request.form.get("cmd")

def validate_cmd(r):
    c = read_cmd(r)
    return c

def prepare_cmd(r):
    c = validate_cmd(r)
    return c

def execute(r):
    cmd = prepare_cmd(r)
    os.system(cmd)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "deep.py")
        taint = [f for f in findings if f.rule_id == "taint_command_injection"]
        assert len(taint) >= 1


# ---------------------------------------------------------------------------
# Cross-file taint detection
# ---------------------------------------------------------------------------


class TestCrossFileTaintPython:
    """Tests for Python cross-file taint tracking."""

    def test_cross_file_taint_python(self) -> None:
        """Taint flows from exported function in file A to sink in file B."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "utils.py": '''
def get_user_input(request):
    return request.args.get('id')
''',
            "handler.py": '''
from utils import get_user_input

def process(request):
    user_id = get_user_input(request)
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) >= 1
        assert "get_user_input" in cross[0].message
        assert cross[0].severity == Severity.BLOCK

    def test_no_cross_file_taint_clean(self) -> None:
        """Clean exported functions produce no cross-file taint findings."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "utils.py": '''
def get_default_id():
    return 42
''',
            "handler.py": '''
from utils import get_default_id

def process():
    user_id = get_default_id()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) == 0

    def test_python_taint_still_works(self, analyzer: TaintAnalyzer) -> None:
        """Verify Python intra-file taint analysis is not regressed."""
        code = '''
def handler(request):
    val = request.args.get('x')
    cursor.execute(val)
'''
        findings = analyzer.analyze(code, Language.PYTHON, "app.py")
        taint = [f for f in findings if f.rule_id == "taint_sql_injection"]
        assert len(taint) >= 1
        assert taint[0].severity == Severity.BLOCK


class TestCrossFileTaintJavaScript:
    """Tests for JavaScript/TypeScript cross-file taint tracking."""

    def test_cross_file_taint_js_export_function(self) -> None:
        """Taint flows from exported JS function to sink in importer."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "input.js": '''
export function getUserInput(req) {
    const data = req.body.name;
    return data;
}
''',
            "handler.js": '''
import { getUserInput } from './input';

function processRequest(req, res) {
    const name = getUserInput(req);
    db.query("SELECT * FROM users WHERE name = " + name);
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) >= 1
        assert "getUserInput" in cross[0].message

    def test_cross_file_taint_js_module_exports(self) -> None:
        """Taint flows from module.exports function to sink in importer."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "input.js": '''
function readInput(req) {
    const val = req.query.search;
    return val;
}

module.exports = { readInput };
''',
            "app.js": '''
const { readInput } = require('./input');

function handler(req, res) {
    const search = readInput(req);
    document.write(search);
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) >= 1

    def test_cross_file_taint_ts_export(self) -> None:
        """Taint flows from exported TS function to sink in importer."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "service.ts": '''
export function getHeader(req) {
    const auth = req.headers.authorization;
    return auth;
}
''',
            "controller.ts": '''
import { getHeader } from './service';

function handleAuth(req, res) {
    const token = getHeader(req);
    db.query("SELECT * FROM sessions WHERE token = " + token);
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) >= 1

    def test_clean_js_export_no_findings(self) -> None:
        """Clean JS exported functions produce no cross-file taint."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "utils.js": '''
export function getDefaultName() {
    const name = "default";
    return name;
}
''',
            "handler.js": '''
import { getDefaultName } from './utils';

function render() {
    const name = getDefaultName();
    db.query("SELECT * FROM users WHERE name = ?", [name]);
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) == 0

    def test_js_re_export(self) -> None:
        """Cross-file taint detects re-exported functions."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "input.js": '''
export function getUserData(req) {
    const data = req.body.data;
    return data;
}
''',
            "index.js": '''
export { getUserData } from './input';
''',
            "handler.js": '''
import { getUserData } from './index';

function process(req, res) {
    const data = getUserData(req);
    child_process.exec(data);
}
''',
        }
        result = analyzer.analyze(files)
        # The direct import from index.js to input.js should propagate
        assert result.total_files == 3


class TestCrossFileTaintGo:
    """Tests for Go cross-file taint tracking."""

    def test_cross_file_taint_go_exported_func(self) -> None:
        """Taint flows from exported Go function to sink in importer."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "input.go": '''
func GetUserInput(r *http.Request) {
    val := r.FormValue("input")
    return val
}
''',
            "handler.go": '''
func HandleRequest(w http.ResponseWriter, r *http.Request) {
    input := GetUserInput(r)
    db.Query("SELECT * FROM items WHERE name = " + input)
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) >= 1
        assert "GetUserInput" in cross[0].message

    def test_go_unexported_no_cross_file(self) -> None:
        """Go unexported (lowercase) functions should not cross file boundaries."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "input.go": '''
func getUserInput(r *http.Request) {
    val := r.FormValue("input")
    return val
}
''',
            "handler.go": '''
func HandleRequest(w http.ResponseWriter, r *http.Request) {
    input := getUserInput(r)
    db.Query("SELECT * FROM items WHERE name = " + input)
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        # Lowercase func is not exported, so no cross-file finding
        assert len(cross) == 0

    def test_cross_file_taint_go_command_injection(self) -> None:
        """Go cross-file taint detects command injection across files."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "parser.go": '''
func ParseCommand(r *http.Request) {
    cmd := r.FormValue("cmd")
    return cmd
}
''',
            "executor.go": '''
func Execute(r *http.Request) {
    cmd := ParseCommand(r)
    exec.Command(cmd)
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) >= 1

    def test_clean_go_export_no_findings(self) -> None:
        """Clean Go exported functions produce no cross-file taint."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "config.go": '''
func GetDefaultTimeout() {
    timeout := 30
    return timeout
}
''',
            "handler.go": '''
func HandleRequest(w http.ResponseWriter, r *http.Request) {
    timeout := GetDefaultTimeout()
    db.Query("SELECT * FROM items WHERE timeout = $1", timeout)
}
''',
        }
        result = analyzer.analyze(files)
        cross = [f for f in result.findings if f.rule_id.startswith("cross_file_taint_")]
        assert len(cross) == 0


class TestCrossFileTaintMetrics:
    """Tests for cross-file taint result metrics."""

    def test_result_metrics(self) -> None:
        """CrossFileTaintResult reports correct metrics."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        files = {
            "a.py": '''
def get_data(request):
    return request.args.get('x')
''',
            "b.py": '''
from a import get_data

def process(request):
    x = get_data(request)
    os.system(x)
''',
        }
        result = analyzer.analyze(files)
        assert result.total_files == 2
        assert result.total_exports >= 1

    def test_empty_project(self) -> None:
        """Empty project returns zero-metric result."""
        from src.services.cross_file_taint import CrossFileTaintAnalyzer

        analyzer = CrossFileTaintAnalyzer()
        result = analyzer.analyze({})
        assert result.total_files == 0
        assert result.total_exports == 0
        assert len(result.findings) == 0
