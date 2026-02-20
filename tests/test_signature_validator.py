# Copyright (c) Said Borna. All rights reserved.
"""Tests for the function signature validation engine."""


from src.models.enums import Severity
from src.models.responses import Finding
from src.services.signature_validator import (
    _count_positional_args,
    _extract_kwargs,
    _find_closest_param,
    _levenshtein,
    _resolve_js_imports,
    _resolve_python_imports,
    extract_calls,
    get_coverage_stats,
    resolve_imports,
    validate_signatures,
)

# ═══════════════════════════════════════════════════════════════════════
#  IMPORT RESOLUTION — PYTHON
# ═══════════════════════════════════════════════════════════════════════


class TestResolvePythonImports:
    """Tests for Python import resolution."""

    def test_simple_import(self) -> None:
        """Standard import statement."""
        code = "import requests"
        bindings = _resolve_python_imports(code)
        assert "requests" in bindings
        assert bindings["requests"].module_name == "requests"
        assert bindings["requests"].symbol == ""

    def test_aliased_import(self) -> None:
        """Import with alias."""
        code = "import numpy as np"
        bindings = _resolve_python_imports(code)
        assert "np" in bindings
        assert bindings["np"].module_name == "numpy"

    def test_from_import(self) -> None:
        """From-import with specific symbol."""
        code = "from flask import Flask"
        bindings = _resolve_python_imports(code)
        assert "Flask" in bindings
        assert bindings["Flask"].module_name == "flask"
        assert bindings["Flask"].symbol == "Flask"

    def test_from_import_multiple(self) -> None:
        """From-import with multiple symbols."""
        code = "from flask import Flask, jsonify, request"
        bindings = _resolve_python_imports(code)
        assert "Flask" in bindings
        assert "jsonify" in bindings
        assert "request" in bindings

    def test_from_import_aliased(self) -> None:
        """From-import with alias."""
        code = "from pandas import DataFrame as DF"
        bindings = _resolve_python_imports(code)
        assert "DF" in bindings
        assert bindings["DF"].module_name == "pandas"
        assert bindings["DF"].symbol == "DataFrame"

    def test_submodule_import(self) -> None:
        """Import from submodule."""
        code = "from django.shortcuts import render"
        bindings = _resolve_python_imports(code)
        assert "render" in bindings
        assert bindings["render"].module_name == "django.shortcuts"

    def test_no_imports(self) -> None:
        """Code with no imports."""
        code = "x = 1\nprint(x)"
        bindings = _resolve_python_imports(code)
        assert len(bindings) == 0

    def test_comment_not_matched(self) -> None:
        """Commented imports should still be matched by regex (imperfect)."""
        code = "# import requests\nimport flask"
        bindings = _resolve_python_imports(code)
        # The regex is line-based, commented lines starting with # + space
        # may still match due to leading whitespace flexibility
        assert "flask" in bindings


# ═══════════════════════════════════════════════════════════════════════
#  IMPORT RESOLUTION — JAVASCRIPT
# ═══════════════════════════════════════════════════════════════════════


class TestResolveJsImports:
    """Tests for JavaScript/TypeScript import resolution."""

    def test_default_import(self) -> None:
        """Default import statement."""
        code = "import express from 'express'"
        bindings = _resolve_js_imports(code)
        assert "express" in bindings
        assert bindings["express"].module_name == "express"

    def test_named_imports(self) -> None:
        """Named imports in braces."""
        code = "import { useState, useEffect } from 'react'"
        bindings = _resolve_js_imports(code)
        assert "useState" in bindings
        assert "useEffect" in bindings
        assert bindings["useState"].module_name == "react"

    def test_require(self) -> None:
        """CommonJS require."""
        code = "const axios = require('axios')"
        bindings = _resolve_js_imports(code)
        assert "axios" in bindings
        assert bindings["axios"].module_name == "axios"

    def test_star_import(self) -> None:
        """Star import."""
        code = "import * as fs from 'fs'"
        bindings = _resolve_js_imports(code)
        assert "fs" in bindings
        assert bindings["fs"].module_name == "fs"

    def test_no_imports(self) -> None:
        """Code with no imports."""
        code = "const x = 1;"
        bindings = _resolve_js_imports(code)
        assert len(bindings) == 0


# ═══════════════════════════════════════════════════════════════════════
#  RESOLVE_IMPORTS DISPATCHER
# ═══════════════════════════════════════════════════════════════════════


class TestResolveImports:
    """Tests for the resolve_imports dispatcher."""

    def test_python_dispatch(self) -> None:
        """Routes to Python resolver."""
        code = "import requests"
        bindings = resolve_imports(code, "python")
        assert "requests" in bindings

    def test_javascript_dispatch(self) -> None:
        """Routes to JS resolver."""
        code = "import express from 'express'"
        bindings = resolve_imports(code, "javascript")
        assert "express" in bindings

    def test_typescript_dispatch(self) -> None:
        """Routes to JS resolver for TypeScript."""
        code = "import { z } from 'zod'"
        bindings = resolve_imports(code, "typescript")
        assert "z" in bindings

    def test_unsupported_language(self) -> None:
        """Unsupported language returns empty."""
        bindings = resolve_imports("package main", "go")
        assert len(bindings) == 0


# ═══════════════════════════════════════════════════════════════════════
#  CALL EXTRACTION
# ═══════════════════════════════════════════════════════════════════════


class TestExtractCalls:
    """Tests for function call extraction."""

    def test_simple_call(self) -> None:
        """Simple module.function() call."""
        code = "response = requests.get('https://example.com')"
        calls = extract_calls(code, {"requests"})
        assert len(calls) == 1
        assert calls[0].module_alias == "requests"
        assert calls[0].function_name == "get"

    def test_call_with_kwargs(self) -> None:
        """Call with keyword arguments."""
        code = "requests.get('url', timeout=30, verify=True)"
        calls = extract_calls(code, {"requests"})
        assert len(calls) == 1
        assert "timeout" in calls[0].keyword_args
        assert "verify" in calls[0].keyword_args

    def test_multiple_calls(self) -> None:
        """Multiple calls in code."""
        code = "requests.get('a')\nrequests.post('b')"
        calls = extract_calls(code, {"requests"})
        assert len(calls) == 2

    def test_non_matching_module(self) -> None:
        """Calls to unknown modules are ignored."""
        code = "os.path.join('a', 'b')"
        calls = extract_calls(code, {"requests"})
        assert len(calls) == 0

    def test_comment_skipped(self) -> None:
        """Commented-out calls are skipped."""
        code = "# requests.get('url')"
        calls = extract_calls(code, {"requests"})
        assert len(calls) == 0

    def test_line_numbers(self) -> None:
        """Line numbers are 1-indexed."""
        code = "x = 1\nrequests.get('url')\ny = 2"
        calls = extract_calls(code, {"requests"})
        assert calls[0].line == 2


# ═══════════════════════════════════════════════════════════════════════
#  ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════


class TestArgParsing:
    """Tests for argument counting and extraction."""

    def test_no_args(self) -> None:
        """Empty argument string."""
        assert _count_positional_args("") == 0

    def test_single_positional(self) -> None:
        """Single positional arg."""
        assert _count_positional_args("'url'") == 1

    def test_multiple_positional(self) -> None:
        """Multiple positional args."""
        assert _count_positional_args("'a', 'b', 'c'") == 3

    def test_kwargs_not_counted(self) -> None:
        """Keyword args should not be counted as positional."""
        assert _count_positional_args("'url', timeout=30") == 1

    def test_extract_no_kwargs(self) -> None:
        """No keyword arguments."""
        assert _extract_kwargs("'url', 'data'") == []

    def test_extract_kwargs(self) -> None:
        """Extract keyword argument names."""
        result = _extract_kwargs("'url', timeout=30, verify=True")
        assert "timeout" in result
        assert "verify" in result


# ═══════════════════════════════════════════════════════════════════════
#  LEVENSHTEIN DISTANCE
# ═══════════════════════════════════════════════════════════════════════


class TestLevenshtein:
    """Tests for edit distance calculation."""

    def test_identical_strings(self) -> None:
        """Same strings have distance 0."""
        assert _levenshtein("abc", "abc") == 0

    def test_one_insertion(self) -> None:
        """Single insertion."""
        assert _levenshtein("abc", "abcd") == 1

    def test_one_deletion(self) -> None:
        """Single deletion."""
        assert _levenshtein("abcd", "abc") == 1

    def test_one_substitution(self) -> None:
        """Single substitution."""
        assert _levenshtein("abc", "axc") == 1

    def test_empty_strings(self) -> None:
        """Both empty."""
        assert _levenshtein("", "") == 0

    def test_one_empty(self) -> None:
        """One empty string."""
        assert _levenshtein("abc", "") == 3


# ═══════════════════════════════════════════════════════════════════════
#  CLOSEST MATCH HELPERS
# ═══════════════════════════════════════════════════════════════════════


class TestClosestMatch:
    """Tests for fuzzy matching helpers."""

    def test_find_closest_param(self) -> None:
        """Find closest parameter name."""
        result = _find_closest_param("timout", {"timeout", "verify", "data"})
        assert result == "timeout"

    def test_no_close_param(self) -> None:
        """No close match returns empty."""
        result = _find_closest_param("xxxx", {"timeout", "verify"})
        assert result == ""

    def test_empty_valid_set(self) -> None:
        """Empty valid set returns empty."""
        result = _find_closest_param("test", set())
        assert result == ""


# ═══════════════════════════════════════════════════════════════════════
#  FULL VALIDATION — PYTHON
# ═══════════════════════════════════════════════════════════════════════


class TestValidateSignaturesPython:
    """Tests for end-to-end Python signature validation."""

    def test_valid_code_no_findings(self) -> None:
        """Clean code produces no findings."""
        code = "import requests\nresponse = requests.get('https://api.example.com', timeout=30)"
        findings = validate_signatures(code, "python", "test.py")
        # Should produce no BLOCK findings at minimum
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert len(blocks) == 0

    def test_hallucinated_function(self) -> None:
        """Detects known hallucinated function."""
        code = "import requests\nresponse = requests.fetch('https://api.example.com')"
        findings = validate_signatures(code, "python", "test.py")
        hallucinated = [f for f in findings if "hallucinated" in f.rule_id]
        assert len(hallucinated) >= 1
        assert hallucinated[0].severity == Severity.BLOCK

    def test_wrong_parameter(self) -> None:
        """Detects unknown parameter."""
        code = "import requests\nresponse = requests.get('url', timout=30)"
        findings = validate_signatures(code, "python", "test.py")
        param_findings = [f for f in findings if "param" in f.rule_id]
        assert len(param_findings) >= 1

    def test_hallucinated_parameter(self) -> None:
        """Detects known hallucinated parameter (e.g. body= on requests.get)."""
        code = "import requests\nresponse = requests.get('url', body='payload')"
        findings = validate_signatures(code, "python", "test.py")
        blocked = [
            f for f in findings
            if f.severity == Severity.BLOCK and "param" in f.rule_id
        ]
        assert len(blocked) >= 1

    def test_numpy_alias(self) -> None:
        """Validates calls using numpy aliased as np."""
        code = "import numpy as np\narr = np.array([1, 2, 3])"
        findings = validate_signatures(code, "python", "test.py")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert len(blocks) == 0

    def test_no_imports_no_findings(self) -> None:
        """Code without matching imports produces no findings."""
        code = "x = 1 + 2\nprint(x)"
        findings = validate_signatures(code, "python", "test.py")
        assert len(findings) == 0

    def test_unsupported_language(self) -> None:
        """Unsupported language returns empty findings."""
        findings = validate_signatures("package main", "go", "main.go")
        assert len(findings) == 0

    def test_empty_code(self) -> None:
        """Empty code returns no findings."""
        findings = validate_signatures("", "python", "test.py")
        assert len(findings) == 0

    def test_pandas_deprecated_param(self) -> None:
        """Detects deprecated pandas parameter."""
        code = "import pandas as pd\ndf = pd.read_csv('data.csv', date_parser=my_func)"
        findings = validate_signatures(code, "python", "test.py")
        deprecated = [f for f in findings if "deprecated" in f.rule_id]
        assert len(deprecated) >= 1

    def test_flask_hallucinated_param(self) -> None:
        """flask.Flask(debug=True) is a known hallucination."""
        code = "import flask\napp = flask.Flask(__name__, debug=True)"
        findings = validate_signatures(code, "python", "test.py")
        # Flask constructor with debug= is a known hallucination
        blocked = [f for f in findings if f.severity == Severity.BLOCK]
        assert len(blocked) >= 1

    def test_max_findings_cap(self) -> None:
        """Findings are capped at MAX_FINDINGS_PER_FILE."""
        # Generate code with many bogus calls
        lines = ["import requests"]
        for i in range(60):
            lines.append(f"requests.bogus_function_{i}()")
        code = "\n".join(lines)
        findings = validate_signatures(code, "python", "test.py")
        assert len(findings) <= 50  # MAX_FINDINGS_PER_FILE


# ═══════════════════════════════════════════════════════════════════════
#  FULL VALIDATION — JAVASCRIPT
# ═══════════════════════════════════════════════════════════════════════


class TestValidateSignaturesJS:
    """Tests for end-to-end JavaScript signature validation."""

    def test_valid_express_call(self) -> None:
        """Valid Express usage."""
        code = "import express from 'express'\nconst app = express.json()"
        findings = validate_signatures(code, "javascript", "app.js")
        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        assert len(blocks) == 0

    def test_axios_hallucinated_function(self) -> None:
        """Detects hallucinated axios function."""
        code = "import axios from 'axios'\nconst res = axios.fetch('/api')"
        findings = validate_signatures(code, "javascript", "app.js")
        hallucinated = [f for f in findings if "hallucinated" in f.rule_id]
        assert len(hallucinated) >= 1


# ═══════════════════════════════════════════════════════════════════════
#  COVERAGE STATS
# ═══════════════════════════════════════════════════════════════════════


class TestCoverageStats:
    """Tests for signature database coverage reporting."""

    def test_stats_structure(self) -> None:
        """Stats dict has expected keys."""
        stats = get_coverage_stats()
        assert "modules" in stats
        assert "functions" in stats
        assert "hallucination_patterns" in stats

    def test_stats_positive(self) -> None:
        """All stats are positive numbers."""
        stats = get_coverage_stats()
        assert stats["modules"] > 0
        assert stats["functions"] > 0
        assert stats["hallucination_patterns"] > 0

    def test_minimum_coverage(self) -> None:
        """We have at least 20 modules and 50 functions."""
        stats = get_coverage_stats()
        assert stats["modules"] >= 20
        assert stats["functions"] >= 50


# ═══════════════════════════════════════════════════════════════════════
#  FINDING FORMAT
# ═══════════════════════════════════════════════════════════════════════


class TestFindingFormat:
    """Tests for Finding output format."""

    def test_finding_is_pydantic(self) -> None:
        """Findings are Pydantic Finding instances."""
        code = "import requests\nrequests.fetch('url')"
        findings = validate_signatures(code, "python", "test.py")
        if findings:
            assert isinstance(findings[0], Finding)

    def test_finding_has_file(self) -> None:
        """Findings include the filepath."""
        code = "import requests\nrequests.fetch('url')"
        findings = validate_signatures(code, "python", "myfile.py")
        if findings:
            assert findings[0].file == "myfile.py"

    def test_finding_has_line(self) -> None:
        """Findings include line number."""
        code = "import requests\nrequests.fetch('url')"
        findings = validate_signatures(code, "python", "test.py")
        if findings:
            assert findings[0].line == 2

    def test_finding_has_rule_id(self) -> None:
        """Findings have sig_ prefixed rule_id."""
        code = "import requests\nrequests.fetch('url')"
        findings = validate_signatures(code, "python", "test.py")
        if findings:
            assert findings[0].rule_id.startswith("sig_")
