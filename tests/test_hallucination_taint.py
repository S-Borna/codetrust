# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for AI-hallucination-aware taint detection."""

import pytest

from src.models.enums import Language, Severity
from src.services.hallucination_taint import HallucinationTaintAnalyzer


@pytest.fixture()
def analyzer() -> HallucinationTaintAnalyzer:
    """Create a HallucinationTaintAnalyzer instance."""
    return HallucinationTaintAnalyzer()


# ---------------------------------------------------------------------------
# Known stdlib sanitizers — should be trusted
# ---------------------------------------------------------------------------


class TestKnownSanitizers:
    """Verify that known stdlib sanitizers produce no hallucination findings."""

    def test_int_cast_trusted(self, analyzer: HallucinationTaintAnalyzer) -> None:
        """int() is a Python builtin — no hallucination finding."""
        code = '''
def handle(request):
    user_id = request.args.get('id')
    safe_id = int(user_id)
    cursor.execute(f"SELECT * FROM users WHERE id = {safe_id}")
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) == 0
        assert "int" in result.verified_sanitizers

    def test_shlex_quote_trusted(self, analyzer: HallucinationTaintAnalyzer) -> None:
        """shlex.quote() is a stdlib sanitizer — no hallucination finding."""
        code = '''
def run_cmd(request):
    cmd = request.form.get('cmd')
    safe_cmd = shlex.quote(cmd)
    os.system(safe_cmd)
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) == 0
        assert "shlex.quote" in result.verified_sanitizers

    def test_parseint_trusted_javascript(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """parseInt() is a JS builtin — no hallucination finding."""
        code = '''
function handle(req) {
    const userId = req.query.id;
    const safeId = parseInt(userId);
    db.query("SELECT * FROM users WHERE id = " + safeId);
}
'''
        result = analyzer.analyze(code, Language.JAVASCRIPT, "app.js")
        assert len(result.findings) == 0
        assert "parseInt" in result.verified_sanitizers


# ---------------------------------------------------------------------------
# Hallucinated sanitizers — should produce BLOCK findings
# ---------------------------------------------------------------------------


class TestHallucinatedSanitizers:
    """Detect AI-generated sanitizer functions that do not exist."""

    def test_hallucinated_sanitize_sql(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """sanitize_sql() does not exist — should produce BLOCK finding."""
        code = '''
def handle(request):
    user_input = request.args.get("q")
    safe = sanitize_sql(user_input)
    cursor.execute(f"SELECT * FROM users WHERE name = '{safe}'")
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.rule_id == "hallucinated_sanitizer_sql_injection"
        assert finding.severity == Severity.BLOCK
        assert "sanitize_sql" in finding.message
        assert "request.args" in finding.message
        assert "cursor.execute" in finding.message
        assert finding.confidence == 0.90
        assert "sanitize_sql" in result.hallucinated_sanitizers

    def test_hallucinated_clean_input(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """clean_input() does not exist — should produce BLOCK finding."""
        code = '''
def run(request):
    cmd = request.form.get('cmd')
    safe = clean_input(cmd)
    os.system(safe)
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.rule_id == "hallucinated_sanitizer_command_injection"
        assert finding.severity == Severity.BLOCK
        assert "clean_input" in finding.message

    def test_hallucinated_sanitize_path(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """sanitize_path() does not exist — should produce BLOCK finding."""
        code = '''
def read(request):
    filename = request.args.get('file')
    safe_path = sanitize_path(filename)
    open(safe_path)
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.rule_id == "hallucinated_sanitizer_path_traversal"
        assert finding.severity == Severity.BLOCK
        assert "sanitize_path" in finding.message


# ---------------------------------------------------------------------------
# Sanitizer defined in the same file — should be trusted
# ---------------------------------------------------------------------------


class TestLocallyDefinedSanitizer:
    """Sanitizers defined in the same file are trusted."""

    def test_locally_defined_sanitizer_trusted(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """A function defined in the same file is not hallucinated."""
        code = '''
def sanitize_sql(value):
    return value.replace("'", "''")

def handle(request):
    user_input = request.args.get("q")
    safe = sanitize_sql(user_input)
    cursor.execute(f"SELECT * FROM users WHERE name = '{safe}'")
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) == 0
        assert "sanitize_sql" in result.verified_sanitizers


# ---------------------------------------------------------------------------
# Sanitizer from a verified external package — should be trusted
# ---------------------------------------------------------------------------


class TestVerifiedImportSanitizer:
    """Sanitizers from verified imports are trusted."""

    def test_imported_bleach_clean_trusted(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """bleach.clean() from an import statement is trusted."""
        code = '''
from bleach import clean

def handle(request):
    html_input = request.args.get("content")
    safe = clean(html_input)
    render_template_string(safe)
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) == 0
        assert "clean" in result.verified_sanitizers

    def test_imported_from_project_module_trusted(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """A function imported from a project module is trusted."""
        code = '''
from myapp.utils import sanitize_input

def handle(request):
    user_input = request.args.get("q")
    safe = sanitize_input(user_input)
    cursor.execute(f"SELECT * FROM users WHERE name = '{safe}'")
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) == 0
        assert "sanitize_input" in result.verified_sanitizers


# ---------------------------------------------------------------------------
# Multiple hallucinated sanitizers in one file
# ---------------------------------------------------------------------------


class TestMultipleHallucinations:
    """Multiple hallucinated sanitizers detected in a single file."""

    def test_multiple_hallucinated_sanitizers(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """Two different hallucinated sanitizers produce two findings."""
        code = '''
def handle(request):
    sql_input = request.args.get("q")
    safe_sql = sanitize_sql(sql_input)
    cursor.execute(f"SELECT * FROM users WHERE name = '{safe_sql}'")

def run(request):
    cmd_input = request.form.get("cmd")
    safe_cmd = escape_shell(cmd_input)
    os.system(safe_cmd)
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) >= 2
        rule_ids = {f.rule_id for f in result.findings}
        assert "hallucinated_sanitizer_sql_injection" in rule_ids
        assert "hallucinated_sanitizer_command_injection" in rule_ids
        assert len(result.hallucinated_sanitizers) >= 2


# ---------------------------------------------------------------------------
# No sanitizers at all — normal taint flow, no hallucination finding
# ---------------------------------------------------------------------------


class TestNoSanitizers:
    """When no sanitizers are used, no hallucination findings are generated."""

    def test_direct_taint_flow_no_hallucination_finding(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """Direct source-to-sink flow without sanitizer — no hallucination finding."""
        code = '''
def handle(request):
    user_id = request.args.get('id')
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
        result = analyzer.analyze(code, Language.PYTHON, "app.py")
        assert len(result.findings) == 0
        assert len(result.hallucinated_sanitizers) == 0
        assert len(result.verified_sanitizers) == 0

    def test_no_taint_sources_no_findings(
        self, analyzer: HallucinationTaintAnalyzer,
    ) -> None:
        """Code without taint sources produces no findings."""
        code = '''
def compute():
    x = 42
    return x * 2
'''
        result = analyzer.analyze(code, Language.PYTHON, "utils.py")
        assert len(result.findings) == 0
        assert len(result.hallucinated_sanitizers) == 0
