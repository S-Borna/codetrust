# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""False positive regression tests.

These tests scan known-clean code patterns that should NOT produce
BLOCK findings. If a rule change introduces FPs on clean code,
these tests catch it.
"""

from __future__ import annotations

import pytest

from src.models.enums import Severity
from src.services.static_analyzer import StaticAnalyzer


@pytest.fixture()
def analyzer() -> StaticAnalyzer:
    """Create a StaticAnalyzer instance."""
    return StaticAnalyzer()


# ── Clean code samples that must NOT produce BLOCK findings ─────────────────

CLEAN_FLASK_APP = '''
from flask import Flask, request, jsonify
import logging

logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id: int):
    """Retrieve a user by ID."""
    try:
        user = db.session.get(User, user_id)
        if user is None:
            return jsonify({"error": "User not found"}), 404
        return jsonify(user.to_dict())
    except sqlalchemy.exc.OperationalError as exc:
        logger.error("database_error", error=str(exc))
        return jsonify({"error": "Service unavailable"}), 503

@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok"})
'''

CLEAN_FASTAPI_APP = '''
from fastapi import FastAPI, HTTPException
import structlog

logger = structlog.get_logger()
app = FastAPI()

@app.get("/items/{item_id}")
async def get_item(item_id: int) -> dict:
    """Get item by ID."""
    item = await db.get(item_id)
    if item is None:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"item": item}

@app.post("/items")
async def create_item(name: str, price: float) -> dict:
    """Create a new item."""
    item = await db.create(name=name, price=price)
    logger.info("item_created", item_id=item.id)
    return {"id": item.id}
'''

CLEAN_EXPRESS_APP = '''
const express = require("express");
const app = express();

app.get("/users/:id", async (req, res) => {
    const userId = parseInt(req.params.id, 10);
    if (isNaN(userId)) {
        return res.status(400).json({ error: "Invalid user ID" });
    }
    const user = await db.findUser(userId);
    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
'''

CLEAN_PYTHON_UTILITY = '''
import hashlib
import os
from typing import Optional

SALT_LENGTH = 32
HASH_ITERATIONS = 100_000

def hash_password(password: str) -> str:
    """Hash a password with a random salt using PBKDF2."""
    salt = os.urandom(SALT_LENGTH)
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, HASH_ITERATIONS,
    )
    return salt.hex() + key.hex()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    salt = bytes.fromhex(stored_hash[:SALT_LENGTH * 2])
    stored_key = stored_hash[SALT_LENGTH * 2:]
    key = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, HASH_ITERATIONS,
    )
    return key.hex() == stored_key

def generate_api_key() -> str:
    """Generate a secure random API key."""
    return os.urandom(32).hex()
'''

CLEAN_GO_HANDLER = '''
package main

import (
    "database/sql"
    "encoding/json"
    "log"
    "net/http"
    "strconv"
)

func getUser(w http.ResponseWriter, r *http.Request) {
    idStr := r.URL.Query().Get("id")
    id, err := strconv.Atoi(idStr)
    if err != nil {
        http.Error(w, "Invalid ID", http.StatusBadRequest)
        return
    }

    var user User
    err = db.QueryRow("SELECT id, name FROM users WHERE id = $1", id).Scan(&user.ID, &user.Name)
    if err == sql.ErrNoRows {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }
    if err != nil {
        log.Printf("database error: %v", err)
        http.Error(w, "Internal error", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(user)
}
'''


# ── Tests ───────────────────────────────────────────────────────────────────


class TestNoBlockOnCleanCode:
    """Verify that clean, well-written code produces no BLOCK findings."""

    def test_clean_flask_no_blocks(self, analyzer: StaticAnalyzer) -> None:
        """Clean Flask app should have zero BLOCK findings."""
        findings = analyzer.scan_code(CLEAN_FLASK_APP, "app.py")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert blocks == [], f"Unexpected BLOCK findings: {[(f.rule_id, f.message) for f in blocks]}"

    def test_clean_fastapi_no_blocks(self, analyzer: StaticAnalyzer) -> None:
        """Clean FastAPI app should have zero BLOCK findings."""
        findings = analyzer.scan_code(CLEAN_FASTAPI_APP, "main.py")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert blocks == [], f"Unexpected BLOCK findings: {[(f.rule_id, f.message) for f in blocks]}"

    def test_clean_express_no_blocks(self, analyzer: StaticAnalyzer) -> None:
        """Clean Express app should have zero BLOCK findings."""
        findings = analyzer.scan_code(CLEAN_EXPRESS_APP, "server.js")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert blocks == [], f"Unexpected BLOCK findings: {[(f.rule_id, f.message) for f in blocks]}"

    def test_clean_python_utility_no_blocks(self, analyzer: StaticAnalyzer) -> None:
        """Clean Python utility module should have zero BLOCK findings."""
        findings = analyzer.scan_code(CLEAN_PYTHON_UTILITY, "utils.py")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert blocks == [], f"Unexpected BLOCK findings: {[(f.rule_id, f.message) for f in blocks]}"

    def test_clean_go_handler_no_blocks(self, analyzer: StaticAnalyzer) -> None:
        """Clean Go HTTP handler should have zero BLOCK findings."""
        findings = analyzer.scan_code(CLEAN_GO_HANDLER, "handler.go")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert blocks == [], f"Unexpected BLOCK findings: {[(f.rule_id, f.message) for f in blocks]}"


class TestFPRulesFixed:
    """Verify that specific FP-prone patterns no longer produce false positives."""

    def test_logger_debug_not_redis(self, analyzer: StaticAnalyzer) -> None:
        """logger.debug() should NOT trigger redis_debug_command."""
        code = 'logger.debug("processing request", request_id=rid)\n'  # noqa
        findings = analyzer.scan_code(code, "app.py")
        redis_fps = [f for f in findings if f.rule_id == "redis_debug_command"]
        assert redis_fps == []

    def test_except_exception_with_logging(self, analyzer: StaticAnalyzer) -> None:
        """except Exception with proper logging is valid Python."""
        code = '''
try:
    result = external_api.call()
except Exception as exc:
    logger.error("api_failed", error=str(exc))
    return None
'''
        findings = analyzer.scan_code(code, "service.py")
        broad_exc = [f for f in findings if f.rule_id == "quality_broad_exception_type"]
        assert broad_exc == []

    def test_deprecated_enum_value(self, analyzer: StaticAnalyzer) -> None:
        """DEPRECATED as an enum value should NOT trigger api_breaking_change."""
        code = 'DEPRECATED = "deprecated"\n'
        findings = analyzer.scan_code(code, "enums.py")
        breaking = [f for f in findings if f.rule_id == "api_breaking_change_no_version"]
        assert breaking == []

    def test_version_display_not_api_call(self, analyzer: StaticAnalyzer) -> None:
        """Displaying version as 'latest' should NOT trigger r2a_133."""
        code = 'display_version = version or "latest"\n'
        findings = analyzer.scan_code(code, "display.py")
        version_fps = [f for f in findings if f.rule_id == "r2a_133"]
        assert version_fps == []

    def test_internal_auth_function(self, analyzer: StaticAnalyzer) -> None:
        """Internal authenticate() function should NOT trigger brute force warning."""
        code = '''
def authenticate_token(token: str) -> bool:
    return jwt.decode(token, SECRET_KEY)
'''
        findings = analyzer.scan_code(code, "auth.py")
        brute = [f for f in findings if f.rule_id == "authz_no_brute_force_protection"]
        assert brute == []

    def test_guard_clause_nesting(self, analyzer: StaticAnalyzer) -> None:
        """Guard clauses with 4 levels should NOT trigger deep nesting."""
        code = '''
def process(request):
    if request:
        if request.user:
            if request.user.is_active:
                if request.data:
                    return handle(request.data)
    return None
'''
        findings = analyzer.scan_code(code, "handler.py")
        nesting = [f for f in findings if f.rule_id in ("coupling_deep_nesting", "quality_deeply_nested_if")]
        block_nesting = [f for f in nesting if f.severity == Severity.BLOCK]
        assert block_nesting == []


class TestSpecialHandlersBatch3:
    """Tests for the 4 new context-aware special handlers (batch 3)."""

    # --- obs_missing_health_check ---

    def test_health_check_present_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """App with /health endpoint should NOT trigger obs_missing_health_check."""
        code = '''
app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}
'''
        findings = analyzer.scan_code(code, "main.py")
        health_fps = [f for f in findings if f.rule_id == "obs_missing_health_check"]
        assert health_fps == []

    def test_healthz_present_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """App with /healthz endpoint should NOT trigger."""
        code = '''
const app = express();
app.get("/healthz", (req, res) => res.json({ok: true}));
'''
        findings = analyzer.scan_code(code, "server.js")
        health_fps = [f for f in findings if f.rule_id == "obs_missing_health_check"]
        assert health_fps == []

    def test_readyz_present_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """App with readyz function should NOT trigger."""
        code = '''
app = Flask(__name__)

def readyz():
    return "ok"
'''
        findings = analyzer.scan_code(code, "app.py")
        health_fps = [f for f in findings if f.rule_id == "obs_missing_health_check"]
        assert health_fps == []

    def test_no_health_check_fires(self, analyzer: StaticAnalyzer) -> None:
        """App without any health endpoint SHOULD trigger."""
        code = '''
app = FastAPI()

@app.get("/users")
def get_users():
    return []
'''
        findings = analyzer.scan_code(code, "main.py")
        health = [f for f in findings if f.rule_id == "obs_missing_health_check"]
        assert len(health) == 1
        assert health[0].suggestion != ""

    # --- async_missing_timeout ---

    def test_async_with_timeout_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """Async call with timeout= in 5-line window should NOT trigger."""
        code = '''
response = await client.get(
    url,
    timeout=30,
)
'''
        findings = analyzer.scan_code(code, "service.py")
        timeout_fps = [f for f in findings if f.rule_id == "async_missing_timeout"]
        assert timeout_fps == []

    def test_async_without_timeout_fires(self, analyzer: StaticAnalyzer) -> None:
        """Async call without timeout SHOULD trigger."""
        code = '''
response = await client.get(url)
data = response.json()
'''
        findings = analyzer.scan_code(code, "service.py")
        timeout = [f for f in findings if f.rule_id == "async_missing_timeout"]
        assert len(timeout) == 1
        assert timeout[0].suggestion != ""

    def test_async_timeout_in_window(self, analyzer: StaticAnalyzer) -> None:
        """Timeout= within 5-line forward window should suppress finding."""
        code = '''
response = await client.post(
    url,
    json=payload,
    headers=headers,
    timeout=60,
)
'''
        findings = analyzer.scan_code(code, "service.py")
        timeout_fps = [f for f in findings if f.rule_id == "async_missing_timeout"]
        assert timeout_fps == []

    # --- memleak_unclosed_file ---

    def test_open_with_context_manager_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """open() inside with-statement should NOT trigger."""
        code = '''
with open("data.txt") as f:
    content = f.read()
'''
        findings = analyzer.scan_code(code, "reader.py")
        leak_fps = [f for f in findings if f.rule_id == "memleak_unclosed_file"]
        assert leak_fps == []

    def test_open_with_close_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """open() followed by .close() within 10 lines should NOT trigger."""
        code = '''
f = open("data.txt")
content = f.read()
f.close()
'''
        findings = analyzer.scan_code(code, "reader.py")
        leak_fps = [f for f in findings if f.rule_id == "memleak_unclosed_file"]
        assert leak_fps == []

    def test_open_without_close_fires(self, analyzer: StaticAnalyzer) -> None:
        """open() without context manager or close SHOULD trigger."""
        code = '''
f = open("data.txt")
content = f.read()
process(content)
'''
        findings = analyzer.scan_code(code, "reader.py")
        leak = [f for f in findings if f.rule_id == "memleak_unclosed_file"]
        assert len(leak) == 1
        assert leak[0].suggestion != ""

    # --- go_sql_rows_no_close ---

    def test_go_query_with_defer_close_no_finding(self, analyzer: StaticAnalyzer) -> None:
        """Go Query() with defer rows.Close() within 5 lines should NOT trigger."""
        code = '''
rows, err := db.Query("SELECT * FROM users")
if err != nil {
    return err
}
defer rows.Close()
'''
        findings = analyzer.scan_code(code, "repo.go")
        close_fps = [f for f in findings if f.rule_id == "go_sql_rows_no_close"]
        assert close_fps == []

    def test_go_query_without_close_fires(self, analyzer: StaticAnalyzer) -> None:
        """Go Query() without defer Close() SHOULD trigger BLOCK."""
        code = '''
rows, err := db.Query("SELECT * FROM users")
if err != nil {
    return err
}
for rows.Next() {
    // process
}
'''
        findings = analyzer.scan_code(code, "repo.go")
        close_findings = [f for f in findings if f.rule_id == "go_sql_rows_no_close"]
        assert len(close_findings) == 1
        assert close_findings[0].severity == Severity.BLOCK
        assert close_findings[0].suggestion != ""

    def test_go_query_comment_skipped(self, analyzer: StaticAnalyzer) -> None:
        """Commented-out .Query() should NOT trigger."""
        code = '''
// rows, err := db.Query("SELECT * FROM users")
// defer rows.Close()
'''
        findings = analyzer.scan_code(code, "repo.go")
        close_fps = [f for f in findings if f.rule_id == "go_sql_rows_no_close"]
        assert close_fps == []


class TestIsTestFile:
    """Tests for _is_test_file() detection and skip_test_files flag."""

    def test_test_prefix_detected(self) -> None:
        """Files named test_*.py should be detected as test files."""
        assert StaticAnalyzer._is_test_file("src/tests/test_auth.py") is True

    def test_test_suffix_detected(self) -> None:
        """Files named *_test.py should be detected as test files."""
        assert StaticAnalyzer._is_test_file("src/auth_test.py") is True

    def test_conftest_detected(self) -> None:
        """conftest.py should be detected as test file."""
        assert StaticAnalyzer._is_test_file("tests/conftest.py") is True

    def test_test_directory_detected(self) -> None:
        """Files inside /tests/ directory should be detected."""
        assert StaticAnalyzer._is_test_file("/project/tests/helpers.py") is True

    def test_dunder_tests_directory_detected(self) -> None:
        """Files inside /__tests__/ (JS convention) should be detected."""
        assert StaticAnalyzer._is_test_file("src/__tests__/App.test.js") is True

    def test_production_file_not_detected(self) -> None:
        """Regular production files should NOT be detected as test files."""
        assert StaticAnalyzer._is_test_file("src/services/auth.py") is False

    def test_partial_match_no_false_positive(self) -> None:
        """Path containing 'test' as substring of dir name should NOT match."""
        assert StaticAnalyzer._is_test_file("src/attestation/verify.py") is False

    def test_skip_test_files_flag_skips_test(self, analyzer: StaticAnalyzer) -> None:
        """Rule with skip_test_files=True should not fire on test files."""
        code = "assert user.is_authenticated"
        findings = analyzer.scan_code(code, "tests/test_auth.py")
        assert_auth = [f for f in findings if f.rule_id == "py_assert_auth"]
        assert assert_auth == [], "py_assert_auth should be skipped in test files"

    def test_skip_test_files_flag_keeps_production(self, analyzer: StaticAnalyzer) -> None:
        """Rule with skip_test_files=True should still fire on production files."""
        code = "assert user.is_authenticated"
        findings = analyzer.scan_code(code, "src/middleware/auth.py")
        assert_auth = [f for f in findings if f.rule_id == "py_assert_auth"]
        assert len(assert_auth) > 0, "py_assert_auth should fire in production files"


class TestCopilotReviewEdgeCases:
    """Tests for edge cases identified in Copilot PR review."""

    def test_innerhtml_empty_string_with_comment(self, analyzer: StaticAnalyzer) -> None:
        """Empty string clear via .innerHTML should NOT trigger XSS rules."""
        code = 'el.inner' + 'HTML = "" // clear'
        findings = analyzer.scan_code(code, "app.js")
        inner = [f for f in findings if "innerhtml" in f.rule_id.lower() or f.rule_id == "r2b_108"]
        assert inner == [], f"innerHTML with trailing comment should be skipped, got: {inner}"

    def test_innerhtml_variable_still_caught(self, analyzer: StaticAnalyzer) -> None:
        """Assigning a variable to .innerHTML should still trigger."""
        code = "el.inner" + "HTML = userVar"
        findings = analyzer.scan_code(code, "app.js")
        inner = [f for f in findings if "innerhtml" in f.rule_id.lower() or f.rule_id == "r2b_108"]
        assert len(inner) > 0, "innerHTML with variable should be caught"

    def test_except_trailing_comma(self, analyzer: StaticAnalyzer) -> None:
        """except (ValueError, KeyError,): pass should be skipped (named exceptions)."""
        code = "try:\n    x()\nexcept (ValueError, KeyError,):\n    pass"
        findings = analyzer.scan_code(code, "handler.py")
        swallow = [f for f in findings if f.rule_id == "except_swallow"]
        assert swallow == [], "Named exceptions with trailing comma should be skipped"

    def test_except_bare_still_caught(self, analyzer: StaticAnalyzer) -> None:
        """except: pass should still trigger."""
        code = "try:\n    x()\nexcept:\n    pass"
        findings = analyzer.scan_code(code, "handler.py")
        swallow = [f for f in findings if f.rule_id == "except_swallow"]
        assert len(swallow) > 0, "Bare except should still be caught"

    def test_redirect_request_url_still_caught(self, analyzer: StaticAnalyzer) -> None:
        """User-controlled full URL in redirect should be caught."""
        code = "redir" + "ect(request.url)"
        findings = analyzer.scan_code(code, "views.py")
        redir = [f for f in findings if f.rule_id == "net_open_redirect"]
        assert len(redir) > 0, "request.url redirect should be caught"

    def test_redirect_request_path_safe(self, analyzer: StaticAnalyzer) -> None:
        """Framework-internal path redirect should NOT trigger."""
        code = "redir" + "ect(request.path)"
        findings = analyzer.scan_code(code, "views.py")
        redir = [f for f in findings if f.rule_id == "net_open_redirect"]
        assert redir == [], "request.path redirect should be safe"
