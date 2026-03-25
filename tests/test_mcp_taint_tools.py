# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the three crown-jewel taint MCP tools and deep_scan integration.

These tests verify the MCP tool wiring — that the tools are callable,
parse inputs correctly, and return properly formatted Markdown reports.
The underlying analyzers have their own comprehensive test suites.
"""

from __future__ import annotations

import json

from src.server import (
    codetrust_cross_file_taint,
    codetrust_cross_language_taint,
    codetrust_deep_scan,
    codetrust_hallucination_scan,
)

# ── Test data ───────────────────────────────────────────────────────────────

HALLUCINATED_SANITIZER_CODE = '''
from ai_utils import sanitize_html

def handle(request):
    user_input = request.args.get("name")
    safe = sanitize_html(user_input)
    return render_template_string(safe)
'''

CLEAN_SANITIZER_CODE = '''
from markupsafe import escape

def handle(request):
    user_input = request.args.get("name")
    safe = escape(user_input)
    return safe
'''

FLASK_BACKEND = '''
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/search")
def search():
    query = request.args.get("q")
    return render_template_string("<h1>" + query + "</h1>")
'''

JS_FRONTEND = '''
async function search(userInput) {
    const resp = await fetch("/search?q=" + userInput);
    const html = await resp.text();
    document.getElementById("results").innerHTML = html;
}
'''

PYTHON_FILE_A = '''
from flask import request

def get_user_input():
    return request.args.get("name")
'''

PYTHON_FILE_B = '''
from file_a import get_user_input
import sqlite3

def query_db():
    name = get_user_input()
    conn = sqlite3.connect("db.sqlite")
    conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
'''


# ── Hallucination scan MCP tool ────────────────────────────────────────────


class TestHallucinationScanTool:
    """Tests for codetrust_hallucination_scan MCP tool."""

    async def test_detects_hallucinated_sanitizer(self) -> None:
        """Hallucinated sanitizer is flagged."""
        result = await codetrust_hallucination_scan(
            code=HALLUCINATED_SANITIZER_CODE,
            language="python",
            filename="app.py",
        )
        assert "Hallucination" in result
        assert "sanitize_html" in result
        assert "Verdict: BLOCK" in result

    async def test_clean_code_passes(self) -> None:
        """Real sanitizer (markupsafe.escape) passes."""
        result = await codetrust_hallucination_scan(
            code=CLEAN_SANITIZER_CODE,
            language="python",
            filename="app.py",
        )
        assert "Verdict: PASS" in result

    async def test_unsupported_language(self) -> None:
        """Unsupported language returns error."""
        result = await codetrust_hallucination_scan(
            code="some code",
            language="brainfuck",
            filename="test.bf",
        )
        assert "Error" in result

    async def test_returns_markdown(self) -> None:
        """Output is Markdown-formatted."""
        result = await codetrust_hallucination_scan(
            code=HALLUCINATED_SANITIZER_CODE,
            language="python",
        )
        assert result.startswith("##")


# ── Cross-file taint MCP tool ──────────────────────────────────────────────


class TestCrossFileTaintTool:
    """Tests for codetrust_cross_file_taint MCP tool."""

    async def test_detects_cross_file_flow(self) -> None:
        """Taint flowing from file A to file B is detected."""
        files = {
            "file_a.py": PYTHON_FILE_A,
            "file_b.py": PYTHON_FILE_B,
        }
        result = await codetrust_cross_file_taint(
            files_json=json.dumps(files),
        )
        assert "Cross-File Taint" in result
        assert "Files analyzed" in result

    async def test_empty_json(self) -> None:
        """Empty JSON returns helpful message."""
        result = await codetrust_cross_file_taint(files_json="{}")
        assert "No files provided" in result

    async def test_invalid_json(self) -> None:
        """Invalid JSON returns error."""
        result = await codetrust_cross_file_taint(files_json="not json")
        assert "Error" in result

    async def test_single_clean_file(self) -> None:
        """Single clean file produces no findings."""
        files = {"clean.py": "x = 1\nprint(x)\n"}
        result = await codetrust_cross_file_taint(
            files_json=json.dumps(files),
        )
        assert "Verdict" in result


# ── Cross-language taint MCP tool ───────────────────────────────────────────


class TestCrossLanguageTaintTool:
    """Tests for codetrust_cross_language_taint MCP tool."""

    async def test_detects_js_to_python_xss(self) -> None:
        """JS fetch to Flask route with XSS is detected."""
        files = {
            "backend/app.py": FLASK_BACKEND,
            "frontend/search.js": JS_FRONTEND,
        }
        result = await codetrust_cross_language_taint(
            files_json=json.dumps(files),
        )
        assert "Cross-Language Taint" in result
        assert "Languages detected" in result
        assert "Routes discovered" in result or "routes" in result.lower()

    async def test_empty_json(self) -> None:
        """Empty JSON returns helpful message."""
        result = await codetrust_cross_language_taint(files_json="{}")
        assert "No files provided" in result

    async def test_invalid_json(self) -> None:
        """Invalid JSON returns error."""
        result = await codetrust_cross_language_taint(files_json="{bad}")
        assert "Error" in result

    async def test_single_language_no_cross_lang_finding(self) -> None:
        """Single-language project produces no cross-language findings."""
        files = {"app.py": "print('hello')\n"}
        result = await codetrust_cross_language_taint(
            files_json=json.dumps(files),
        )
        assert "Verdict" in result


# ── Deep scan integration ───────────────────────────────────────────────────


class TestDeepScanTaintIntegration:
    """Tests that deep_scan includes hallucination and multi-file taint."""

    async def test_deep_scan_includes_hallucination(self) -> None:
        """Deep scan runs hallucination analysis on single file."""
        result = await codetrust_deep_scan(
            code=HALLUCINATED_SANITIZER_CODE,
            filename="app.py",
            language="python",
            verify_imports=False,
        )
        assert "Hallucination" in result
        assert "sanitize_html" in result

    async def test_deep_scan_with_additional_files(self) -> None:
        """Deep scan runs cross-file taint when additional files provided."""
        additional = {"file_a.py": PYTHON_FILE_A}
        result = await codetrust_deep_scan(
            code=PYTHON_FILE_B,
            filename="file_b.py",
            language="python",
            verify_imports=False,
            additional_files_json=json.dumps(additional),
        )
        # Should contain deep scan sections
        assert "Deep Scan Report" in result
        assert "Overall Verdict" in result

    async def test_deep_scan_cross_language_with_additional(self) -> None:
        """Deep scan runs cross-language taint when multi-lang files provided."""
        additional = {"frontend/search.js": JS_FRONTEND}
        result = await codetrust_deep_scan(
            code=FLASK_BACKEND,
            filename="backend/app.py",
            language="python",
            verify_imports=False,
            additional_files_json=json.dumps(additional),
        )
        assert "Deep Scan Report" in result

    async def test_deep_scan_without_additional_files(self) -> None:
        """Deep scan works normally without additional files."""
        result = await codetrust_deep_scan(
            code="x = 1\nprint(x)\n",
            filename="clean.py",
            language="python",
            verify_imports=False,
        )
        assert "Deep Scan Report" in result
        assert "Overall Verdict" in result
        # Should NOT contain cross-file/cross-language sections
        assert "Cross-File Taint" not in result
        assert "Cross-Language Taint" not in result
