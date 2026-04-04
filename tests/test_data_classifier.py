# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for Data Classification Engine."""

from __future__ import annotations

from pathlib import Path

from src.services.data_classifier import DataSensitivity, classify_file, classify_text


class TestPublicClassification:
    """Content that should be classified as PUBLIC."""

    def test_readme_file(self) -> None:
        result = classify_text("# Installation\nRun pip install codetrust", file_path="README.md")
        assert result.sensitivity == DataSensitivity.PUBLIC

    def test_docs_directory(self) -> None:
        result = classify_text("# API Reference\nEndpoints:", file_path="docs/api.md")
        assert result.sensitivity == DataSensitivity.PUBLIC

    def test_license_file(self) -> None:
        result = classify_text("MIT License\nPermission is hereby granted", file_path="LICENSE")
        assert result.sensitivity == DataSensitivity.PUBLIC

    def test_examples_directory(self) -> None:
        result = classify_text("print('hello world')", file_path="examples/hello.py")
        assert result.sensitivity == DataSensitivity.PUBLIC

    def test_markdown_docs(self) -> None:
        result = classify_text("## Getting Started\nFirst install", file_path="CONTRIBUTING.md")
        assert result.sensitivity == DataSensitivity.PUBLIC


class TestInternalClassification:
    """Content that should be classified as INTERNAL."""

    def test_src_business_code(self) -> None:
        result = classify_text("def calculate_risk():\n    return score * weight", file_path="src/risk.py")
        assert result.sensitivity == DataSensitivity.INTERNAL

    def test_lib_code(self) -> None:
        result = classify_text("class Parser:\n    pass", file_path="lib/parser.py")
        assert result.sensitivity == DataSensitivity.INTERNAL

    def test_test_files(self) -> None:
        result = classify_text("def test_hello():\n    assert True", file_path="tests/test_hello.py")
        assert result.sensitivity == DataSensitivity.INTERNAL

    def test_plain_text_no_path(self) -> None:
        result = classify_text("Regular business logic code with no PII or secrets")
        assert result.sensitivity == DataSensitivity.INTERNAL


class TestConfidentialClassification:
    """Content that should be classified as CONFIDENTIAL."""

    def test_customer_data_reference(self) -> None:
        result = classify_text("query = db.get_customer_data(user_id)", file_path="src/query.py")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL

    def test_financial_reference(self) -> None:
        result = classify_text("total_revenue = calculate_invoice_total()", file_path="src/billing.py")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL

    def test_sql_with_personal_columns(self) -> None:
        result = classify_text("SELECT email, phone FROM users WHERE id=?", file_path="src/db.py")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL

    def test_employee_data(self) -> None:
        result = classify_text("employee_data = get_records(dept_id)", file_path="src/hr.py")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL

    def test_finance_directory(self) -> None:
        result = classify_text("print('report')", file_path="finance/report.py")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL

    def test_email_pii_raises_to_confidential(self) -> None:
        result = classify_text("Contact: test@example.com for info", file_path="src/handler.py")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL


class TestRestrictedClassification:
    """Content that should be classified as RESTRICTED."""

    def test_env_file_path(self) -> None:
        result = classify_text("DB_HOST=localhost", file_path=".env")
        assert result.sensitivity == DataSensitivity.RESTRICTED

    def test_secrets_directory(self) -> None:
        result = classify_text("key data", file_path="secrets/master.key")
        assert result.sensitivity == DataSensitivity.RESTRICTED

    def test_credentials_directory(self) -> None:
        result = classify_text("creds", file_path="credentials/prod.json")
        assert result.sensitivity == DataSensitivity.RESTRICTED

    def test_pem_file(self) -> None:
        result = classify_text("cert data", file_path="certs/server.pem")
        assert result.sensitivity == DataSensitivity.RESTRICTED

    def test_api_key_in_content(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        result = classify_text(text, file_path="src/config.py")
        assert result.sensitivity == DataSensitivity.RESTRICTED

    def test_private_key_content(self) -> None:
        result = classify_text("-----BEGIN RSA PRIVATE KEY-----", file_path="src/auth.py")
        assert result.sensitivity == DataSensitivity.RESTRICTED

    def test_connection_string(self) -> None:
        result = classify_text("uri = postgres://user:pass@host/db", file_path="src/db.py")
        assert result.sensitivity >= DataSensitivity.RESTRICTED

    def test_gdpr_marker(self) -> None:
        result = classify_text("This data is subject to GDPR processing rules", file_path="src/privacy.py")
        assert result.sensitivity == DataSensitivity.RESTRICTED


class TestPIIIntegration:
    """Test that PII findings raise classification level."""

    def test_critical_pii_raises_to_restricted(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        result = classify_text(text)
        assert result.sensitivity == DataSensitivity.RESTRICTED
        assert len(result.pii_findings) > 0

    def test_medium_pii_raises_to_confidential(self) -> None:
        result = classify_text("Email: user@company.com")
        assert result.sensitivity >= DataSensitivity.CONFIDENTIAL

    def test_no_pii_stays_at_base_level(self) -> None:
        result = classify_text("x = 42", file_path="src/math.py")
        assert result.sensitivity == DataSensitivity.INTERNAL
        assert len(result.pii_findings) == 0


class TestConfidence:
    """Test confidence scoring."""

    def test_high_confidence_for_restricted_path(self) -> None:
        result = classify_text("data", file_path=".env.production")
        assert result.confidence >= 0.85

    def test_confidence_in_valid_range(self) -> None:
        result = classify_text("hello")
        assert 0.0 <= result.confidence <= 1.0

    def test_pii_increases_confidence(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        result = classify_text(text)
        assert result.confidence >= 0.85


class TestClassifyFile:
    """Test file classification."""

    def test_classify_readme(self) -> None:
        readme = Path("README.md")
        if readme.is_file():
            result = classify_file(readme)
            assert result.sensitivity == DataSensitivity.PUBLIC
            assert result.file_path == str(readme)

    def test_classify_nonexistent_raises(self) -> None:
        import pytest
        with pytest.raises(OSError):
            classify_file(Path("/nonexistent/file.py"))


class TestToDict:
    """Test serialization."""

    def test_to_dict_fields(self) -> None:
        import json
        result = classify_text("hello", file_path="test.py")
        d = result.to_dict()
        json.dumps(d)
        assert "sensitivity" in d
        assert "confidence" in d
        assert "reasons" in d
        assert "indicators" in d
        assert d["sensitivity"] in ("public", "internal", "confidential", "restricted")
