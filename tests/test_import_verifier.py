"""Tests for import verification — the bridge between static analysis and live registry checks."""

from unittest.mock import AsyncMock, patch

import pytest

from src.models.enums import Registry, Severity, VerifyStatus
from src.models.responses import PackageResult
from src.services.import_verifier import (
    _collect_js_imports,
    _collect_python_imports,
    _find_import_line,
    _results_to_findings,
    async_verify_file_imports,
    collect_source_files,
    verify_file_imports_sync,
)

# --- _find_import_line ---


class TestFindImportLine:
    """Test exact line detection for imports."""

    def test_basic_import(self) -> None:
        code = "import os\nimport requests\nimport json\n"
        assert _find_import_line(code, "requests") == 2

    def test_from_import(self) -> None:
        code = "from flask import Flask\nimport os\n"
        assert _find_import_line(code, "flask") == 1

    def test_mapped_package(self) -> None:
        """opencv-python is imported as cv2."""
        code = "import os\nimport cv2\nimport json\n"
        assert _find_import_line(code, "opencv-python") == 2

    def test_mapped_package_pil(self) -> None:
        """Pillow is imported as PIL."""
        code = "from PIL import Image\nimport os\n"
        assert _find_import_line(code, "Pillow") == 1

    def test_not_found_returns_1(self) -> None:
        code = "import os\nimport json\n"
        assert _find_import_line(code, "nonexistent") == 1

    def test_skips_comments(self) -> None:
        code = "# import requests\nimport requests\n"
        assert _find_import_line(code, "requests") == 2


# --- _collect_python_imports ---


class TestCollectPythonImports:
    """Test import collection from Python files."""

    def test_basic_collection(self) -> None:
        files = [
            ("app.py", "import requests\nimport flask\n"),
            ("lib.py", "import requests\nimport numpy\n"),
        ]
        result = _collect_python_imports(files)
        assert "requests" in result
        assert "flask" in result
        assert "numpy" in result
        # requests appears in both files
        assert len(result["requests"]) == 2

    def test_stdlib_skipped(self) -> None:
        files = [("app.py", "import os\nimport json\nimport requests\n")]
        result = _collect_python_imports(files)
        assert "os" not in result
        assert "json" not in result
        assert "requests" in result

    def test_empty_code(self) -> None:
        files = [("app.py", "")]
        result = _collect_python_imports(files)
        assert len(result) == 0

    def test_relative_import_skipped(self) -> None:
        files = [("app.py", "from . import utils\nimport requests\n")]
        result = _collect_python_imports(files)
        assert "requests" in result
        assert len(result) == 1


# --- _collect_js_imports ---


class TestCollectJsImports:
    """Test import collection from JS/TS files."""

    def test_basic_import(self) -> None:
        files = [("app.js", "import express from 'express';\n")]
        result = _collect_js_imports(files)
        assert "express" in result

    def test_require(self) -> None:
        files = [("app.js", "const lodash = require('lodash');\n")]
        result = _collect_js_imports(files)
        assert "lodash" in result


# --- _results_to_findings ---


class TestResultsToFindings:
    """Test conversion of PackageResult to finding dicts."""

    def test_not_found_becomes_block(self) -> None:
        results = [
            PackageResult(
                package="fakepackage",
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Not found",
                suggestion="flask",
            ),
        ]
        package_map = {"fakepackage": [("app.py", 3)]}
        findings = _results_to_findings(results, package_map, "Python")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "import_not_found"
        assert findings[0]["severity"] == "BLOCK"
        assert "fakepackage" in findings[0]["message"]
        assert "hallucination" in findings[0]["message"]
        assert "flask" in findings[0]["message"]
        assert findings[0]["file"] == "app.py"
        assert findings[0]["line"] == 3

    def test_deprecated_becomes_warn(self) -> None:
        results = [
            PackageResult(
                package="oldpkg",
                registry=Registry.PYPI,
                status=VerifyStatus.DEPRECATED,
                severity=Severity.WARN,
                message="Deprecated",
            ),
        ]
        package_map = {"oldpkg": [("app.py", 5)]}
        findings = _results_to_findings(results, package_map, "Python")
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "import_deprecated"
        assert findings[0]["severity"] == "WARN"

    def test_verified_produces_no_finding(self) -> None:
        results = [
            PackageResult(
                package="requests",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="Verified",
            ),
        ]
        package_map = {"requests": [("app.py", 1)]}
        findings = _results_to_findings(results, package_map, "Python")
        assert len(findings) == 0

    def test_multiple_files_same_package(self) -> None:
        """If 2 files import a nonexistent package, produce 2 findings."""
        results = [
            PackageResult(
                package="hallucinated_pkg",
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Not found",
            ),
        ]
        package_map = {
            "hallucinated_pkg": [("app.py", 2), ("lib.py", 5)],
        }
        findings = _results_to_findings(results, package_map, "Python")
        assert len(findings) == 2
        files = [f["file"] for f in findings]
        assert "app.py" in files
        assert "lib.py" in files


# --- async_verify_file_imports ---


class TestAsyncVerifyFileImports:
    """Integration tests using mocked registry."""

    @pytest.mark.asyncio
    async def test_hallucinated_import_found(self) -> None:
        """A nonexistent package import should produce a BLOCK finding."""
        py_files = [
            ("app.py", "import flaskk\n"),  # typo of flask
        ]

        mock_result = PackageResult(
            package="flaskk",
            registry=Registry.PYPI,
            status=VerifyStatus.NOT_FOUND,
            severity=Severity.BLOCK,
            message="Not found",
            suggestion="flask",
        )

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=[mock_result],
        ):
            findings = await async_verify_file_imports(py_files=py_files)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "import_not_found"
        assert findings[0]["severity"] == "BLOCK"
        assert findings[0]["file"] == "app.py"

    @pytest.mark.asyncio
    async def test_all_imports_verified(self) -> None:
        """All real packages should produce no findings."""
        py_files = [
            ("app.py", "import requests\nimport flask\n"),
        ]

        mock_results = [
            PackageResult(
                package="requests",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="OK",
            ),
            PackageResult(
                package="flask",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="OK",
            ),
        ]

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=mock_results,
        ):
            findings = await async_verify_file_imports(py_files=py_files)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_mixed_results(self) -> None:
        """Mix of real and hallucinated imports."""
        py_files = [
            ("app.py", "import requests\nimport ai_magic_lib\n"),
        ]

        mock_results = [
            PackageResult(
                package="requests",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="OK",
            ),
            PackageResult(
                package="ai_magic_lib",
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Not found",
            ),
        ]

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=mock_results,
        ):
            findings = await async_verify_file_imports(py_files=py_files)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "import_not_found"
        assert "ai_magic_lib" in findings[0]["message"]

    @pytest.mark.asyncio
    async def test_no_files_no_findings(self) -> None:
        findings = await async_verify_file_imports(py_files=[], js_files=[])
        assert findings == []

    @pytest.mark.asyncio
    async def test_registry_error_graceful(self) -> None:
        """Registry errors should not crash the scan."""
        py_files = [("app.py", "import requests\n")]

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            side_effect=Exception("Connection refused"),
        ):
            findings = await async_verify_file_imports(py_files=py_files)

        assert findings == []


# --- verify_file_imports_sync ---


class TestVerifyFileImportsSync:
    """Test sync wrapper."""

    def test_sync_wrapper_works(self) -> None:
        mock_result = PackageResult(
            package="fakepkg",
            registry=Registry.PYPI,
            status=VerifyStatus.NOT_FOUND,
            severity=Severity.BLOCK,
            message="Not found",
        )

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=[mock_result],
        ):
            findings = verify_file_imports_sync(
                py_files=[("app.py", "import fakepkg\n")],
            )

        assert len(findings) == 1
        assert findings[0]["severity"] == "BLOCK"

    def test_sync_wrapper_error_returns_empty(self) -> None:
        """If everything blows up, return empty list."""
        with patch(
            "src.services.import_verifier.async_verify_file_imports",
            side_effect=RuntimeError("boom"),
        ):
            findings = verify_file_imports_sync(
                py_files=[("app.py", "import requests\n")],
            )
        assert findings == []


# --- collect_source_files ---


class TestCollectSourceFiles:
    """Test file collection from targets."""

    def test_collect_from_file(self, tmp_path) -> None:
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\n")
        py_files, _js_files = collect_source_files([str(py_file)])
        assert len(py_files) == 1
        assert py_files[0][0] == str(py_file)

    def test_collect_from_dir(self, tmp_path) -> None:
        (tmp_path / "app.py").write_text("import requests\n")
        (tmp_path / "index.js").write_text("import express from 'express';\n")
        (tmp_path / "test_app.py").write_text("import pytest\n")  # skipped

        py_files, js_files = collect_source_files([str(tmp_path)])
        assert len(py_files) == 1  # test_app.py skipped
        assert len(js_files) == 1

    def test_skips_excluded_dirs(self, tmp_path) -> None:
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "lib.py").write_text("import requests\n")
        (tmp_path / "app.py").write_text("import flask\n")

        py_files, _js = collect_source_files([str(tmp_path)])
        assert len(py_files) == 1
        assert py_files[0][0] == str(tmp_path / "app.py")


# --- End-to-end scenario tests ---


class TestEndToEndScenarios:
    """Simulate real-world scan scenarios with mocked registry."""

    def test_ai_generated_code_with_hallucinated_import(self) -> None:
        """AI generated code that imports a nonexistent package."""
        code = """\
import os
import json
import requests
import ai_helper_utils  # AI hallucinated this package

from flask import Flask

app = Flask(__name__)
"""
        py_files = [("ai_code.py", code)]

        mock_results = [
            PackageResult(
                package="requests", registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED, severity=Severity.INFO,
                message="OK",
            ),
            PackageResult(
                package="ai_helper_utils", registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND, severity=Severity.BLOCK,
                message="Not found", suggestion="",
            ),
            PackageResult(
                package="flask", registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED, severity=Severity.INFO,
                message="OK",
            ),
        ]

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=mock_results,
        ):
            findings = verify_file_imports_sync(py_files=py_files)

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "import_not_found"
        assert findings[0]["file"] == "ai_code.py"
        assert findings[0]["line"] == 4  # import ai_helper_utils is on line 4
        assert "hallucination" in findings[0]["message"]

    def test_real_project_no_hallucinations(self) -> None:
        """A project using only real packages should pass clean."""
        code = """\
import requests
import flask
import sqlalchemy
from celery import Celery
"""
        py_files = [("app.py", code)]

        mock_results = [
            PackageResult(
                package=p, registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED, severity=Severity.INFO,
                message="OK",
            )
            for p in ["requests", "flask", "sqlalchemy", "celery"]
        ]

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=mock_results,
        ):
            findings = verify_file_imports_sync(py_files=py_files)

        assert len(findings) == 0

    def test_multiple_hallucinations_across_files(self) -> None:
        """Multiple files with different hallucinated imports."""
        files = [
            ("api.py", "import flask\nimport magic_api_wrapper\n"),
            ("ml.py", "import numpy\nimport super_ml_toolkit\n"),
        ]

        mock_results = [
            PackageResult(
                package="flask", registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED, severity=Severity.INFO,
                message="OK",
            ),
            PackageResult(
                package="magic_api_wrapper", registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND, severity=Severity.BLOCK,
                message="Not found",
            ),
            PackageResult(
                package="numpy", registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED, severity=Severity.INFO,
                message="OK",
            ),
            PackageResult(
                package="super_ml_toolkit", registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND, severity=Severity.BLOCK,
                message="Not found",
            ),
        ]

        with patch(
            "src.services.import_verifier._verify_packages",
            new_callable=AsyncMock,
            return_value=mock_results,
        ):
            findings = verify_file_imports_sync(py_files=files)

        assert len(findings) == 2
        rule_ids = {f["rule_id"] for f in findings}
        assert rule_ids == {"import_not_found"}
        packages = {f["message"].split("'")[1] for f in findings}
        assert "magic_api_wrapper" in packages
        assert "super_ml_toolkit" in packages
