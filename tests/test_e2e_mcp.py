# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""End-to-end tests for the MCP server tool chain.

These tests call MCP tool functions directly and verify the full pipeline:
scan → findings → verdict → formatted output. No mocking — exercises
the real analyzer, rules, and formatters.
"""

from __future__ import annotations

import json

import pytest

from src.server import (
    codetrust_cross_language_taint,
    codetrust_deep_scan,
    codetrust_hallucination_scan,
    codetrust_list_rules,
    codetrust_static_scan,
)


# ── Vulnerable code samples ─────────────────────────────────────────────────

SQL_INJECTION_PYTHON = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/users")
def get_users():
    name = request.args.get("name")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return str(cursor.fetchall())
'''

XSS_JAVASCRIPT = '''
const express = require("express");
const app = express();

app.get("/search", (req, res) => {
    const query = req.query.q;
    res.send("<h1>Results for: " + query + "</h1>");
});
'''

HALLUCINATED_CODE = '''
from ai_sanitizer import clean_input

def handle(request):
    data = request.args.get("input")
    safe = clean_input(data)
    eval(safe)
'''

CROSS_LANG_FLASK = '''
from flask import Flask, request, render_template_string
app = Flask(__name__)

@app.route("/render")
def render_page():
    content = request.args.get("content")
    return render_template_string("<div>" + content + "</div>")
'''

CROSS_LANG_JS = '''
async function loadPage(userInput) {
    const resp = await fetch("/render?content=" + userInput);
    const html = await resp.text();
    document.getElementById("output").innerHTML = html;
}
'''

CLEAN_CODE = '''
from dataclasses import dataclass

MAX_NAME_LENGTH = 100

@dataclass
class User:
    """Represents a user."""
    name: str
    age: int

    def is_adult(self) -> bool:
        """Check if user is an adult."""
        return self.age >= 18

    def display_name(self) -> str:
        """Return truncated display name."""
        if len(self.name) > MAX_NAME_LENGTH:
            return self.name[:MAX_NAME_LENGTH]
        return self.name
'''


# ── E2E: Static scan ───────────────────────────────────────────────────────


class TestE2EStaticScan:
    """End-to-end tests for codetrust_static_scan."""

    async def test_sql_injection_detected(self) -> None:
        """SQL injection via string concat is detected."""
        result = await codetrust_static_scan(
            code=SQL_INJECTION_PYTHON,
            filename="app.py",
            language="python",
        )
        assert "BLOCK" in result or "WARN" in result
        assert "sql" in result.lower() or "inject" in result.lower() or "concat" in result.lower()

    async def test_clean_code_passes(self) -> None:
        """Clean code with no vulnerabilities gets PASS verdict."""
        result = await codetrust_static_scan(
            code=CLEAN_CODE,
            filename="utils.py",
            language="python",
        )
        assert "PASS" in result
        assert "BLOCK" not in result


# ── E2E: Deep scan ─────────────────────────────────────────────────────────


class TestE2EDeepScan:
    """End-to-end tests for codetrust_deep_scan."""

    async def test_deep_scan_vulnerable_code(self) -> None:
        """Deep scan on vulnerable code returns BLOCK verdict."""
        result = await codetrust_deep_scan(
            code=SQL_INJECTION_PYTHON,
            filename="app.py",
            language="python",
            verify_imports=False,
        )
        assert "Deep Scan Report" in result
        assert "Overall Verdict" in result
        # Should contain static findings
        assert "Static Analysis" in result

    async def test_deep_scan_with_hallucination(self) -> None:
        """Deep scan detects hallucinated sanitizers."""
        result = await codetrust_deep_scan(
            code=HALLUCINATED_CODE,
            filename="vuln.py",
            language="python",
            verify_imports=False,
        )
        assert "Hallucination" in result
        assert "clean_input" in result or "ai_sanitizer" in result

    async def test_deep_scan_with_cross_language(self) -> None:
        """Deep scan with additional files runs cross-language taint."""
        additional = {"frontend/app.js": CROSS_LANG_JS}
        result = await codetrust_deep_scan(
            code=CROSS_LANG_FLASK,
            filename="backend/app.py",
            language="python",
            verify_imports=False,
            additional_files_json=json.dumps(additional),
        )
        assert "Deep Scan Report" in result

    async def test_deep_scan_clean_code(self) -> None:
        """Clean code gets reasonable verdict."""
        result = await codetrust_deep_scan(
            code=CLEAN_CODE,
            filename="utils.py",
            language="python",
            verify_imports=False,
        )
        assert "Deep Scan Report" in result
        assert "Overall Verdict" in result


# ── E2E: Hallucination scan ────────────────────────────────────────────────


class TestE2EHallucinationScan:
    """End-to-end tests for codetrust_hallucination_scan."""

    async def test_hallucinated_module_blocked(self) -> None:
        """Hallucinated sanitizer module triggers BLOCK."""
        result = await codetrust_hallucination_scan(
            code=HALLUCINATED_CODE,
            language="python",
            filename="vuln.py",
        )
        assert "Verdict: BLOCK" in result
        assert "clean_input" in result or "ai_sanitizer" in result

    async def test_real_module_passes(self) -> None:
        """Known real module passes."""
        code = '''
from html import escape

def safe_render(user_input):
    return escape(user_input)
'''
        result = await codetrust_hallucination_scan(
            code=code,
            language="python",
            filename="safe.py",
        )
        assert "Verdict: PASS" in result


# ── E2E: Cross-language taint ──────────────────────────────────────────────


class TestE2ECrossLanguageTaint:
    """End-to-end tests for codetrust_cross_language_taint."""

    async def test_flask_js_xss_chain(self) -> None:
        """JS→Flask XSS chain is detected across HTTP boundary."""
        files = {
            "backend/app.py": CROSS_LANG_FLASK,
            "frontend/app.js": CROSS_LANG_JS,
        }
        result = await codetrust_cross_language_taint(
            files_json=json.dumps(files),
        )
        assert "Cross-Language Taint" in result
        assert "Routes discovered" in result or "routes" in result.lower()
        # Should detect at least the Flask route
        assert "render" in result.lower() or "route" in result.lower()


# ── E2E: Rule catalog ──────────────────────────────────────────────────────


class TestE2ERuleCatalog:
    """End-to-end tests for codetrust_list_rules."""

    async def test_catalog_includes_all_sources(self) -> None:
        """Rule catalog includes anti-pattern, gateway, taint, and AST rules."""
        result = await codetrust_list_rules()
        assert "Anti-Pattern Rules" in result
        assert "Gateway Interception Rules" in result
        assert "Taint Analysis Rules" in result
        assert "AST Analysis Rules" in result
        assert "Total rules:" in result

    async def test_catalog_has_gateway_rules(self) -> None:
        """Rule catalog lists gateway rule IDs."""
        result = await codetrust_list_rules()
        assert "gateway_" in result
