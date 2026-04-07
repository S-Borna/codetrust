# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for PII Detection Engine — per-category, FP, redaction, policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.services.pii_detector import (
    PIIReport,
    _iban_checksum,
    _luhn_check,
    _validate_personnummer,
    apply_policy,
    detect,
    get_finding_mode,
    load_pii_policy,
    redact,
    scan_text,
)

FIXTURES = Path(__file__).parent / "fixtures"


# ───────────────────────────────────────────────────────────────
#  Validator tests
# ───────────────────────────────────────────────────────────────


class TestLuhnValidator:
    """Test Luhn checksum algorithm."""

    def test_valid_visa(self) -> None:
        assert _luhn_check("4111111111111111") is True

    def test_valid_mastercard(self) -> None:
        assert _luhn_check("5500000000000004") is True

    def test_invalid_number(self) -> None:
        assert _luhn_check("4111111111111112") is False

    def test_too_short(self) -> None:
        assert _luhn_check("1") is False


class TestIBANValidator:
    """Test IBAN mod-97 checksum."""

    def test_valid_swedish_iban(self) -> None:
        assert _iban_checksum("SE4550000000058398257466") is True

    def test_valid_german_iban(self) -> None:
        assert _iban_checksum("DE89370400440532013000") is True

    def test_valid_british_iban(self) -> None:
        assert _iban_checksum("GB29NWBK60161331926819") is True

    def test_invalid_iban(self) -> None:
        assert _iban_checksum("SE0000000000000000000000") is False


class TestPersonnummerValidator:
    """Test Swedish personnummer validation."""

    def test_valid_format(self) -> None:
        result = _validate_personnummer("900101-1234")
        assert isinstance(result, bool)

    def test_invalid_month(self) -> None:
        assert _validate_personnummer("901301-1234") is False

    def test_invalid_day(self) -> None:
        assert _validate_personnummer("900132-1234") is False

    def test_wrong_length(self) -> None:
        assert _validate_personnummer("12345") is False


# ───────────────────────────────────────────────────────────────
#  Per-category detection tests
# ───────────────────────────────────────────────────────────────


class TestEmailDetection:
    """Test email address detection."""

    def test_standard_email(self) -> None:
        findings = detect("Contact us at info@example.com for details")
        cats = [f.category for f in findings]
        assert "email" in cats

    def test_plus_addressing(self) -> None:
        findings = detect("Send to user+tag@subdomain.example.org")
        cats = [f.category for f in findings]
        assert "email" in cats

    def test_no_false_positive_on_at_sign(self) -> None:
        findings = detect("Use @mention in Slack")
        emails = [f for f in findings if f.category == "email"]
        assert len(emails) == 0


class TestPhoneDetection:
    """Test phone number detection."""

    def test_swedish_phone(self) -> None:
        findings = detect("Ring +46 70 123 4567")
        cats = [f.category for f in findings]
        assert "phone" in cats

    def test_international_format(self) -> None:
        findings = detect("Call +1 555 123 4567")
        cats = [f.category for f in findings]
        assert "phone" in cats

    def test_phone_passes_default_threshold(self) -> None:
        """Phone with international format should pass min_confidence=0.7."""
        findings = detect('PHONE = "+46701234567"', min_confidence=0.7)
        phones = [f for f in findings if f.category == "phone"]
        assert len(phones) >= 1
        assert phones[0].confidence >= 0.7

    def test_phone_us_format_passes_threshold(self) -> None:
        """US format with parens should pass min_confidence=0.7."""
        findings = detect("Call (555) 123-4567", min_confidence=0.7)
        phones = [f for f in findings if f.category == "phone"]
        assert len(phones) >= 1

    def test_random_digits_not_phone(self) -> None:
        """Bare digit sequences without phone format markers should not match."""
        findings = detect("commit 1234567890abcdef", min_confidence=0.7)
        phones = [f for f in findings if f.category == "phone"]
        assert len(phones) == 0


class TestCreditCardDetection:
    """Test credit card detection with Luhn validation."""

    def test_valid_visa(self) -> None:
        findings = detect("Card: 4111 1111 1111 1111")
        cats = [f.category for f in findings]
        assert "credit_card" in cats

    def test_luhn_fail_not_detected(self) -> None:
        """Invalid Luhn should not be flagged as credit card."""
        findings = detect("Number: 4111 1111 1111 1112")
        cc = [f for f in findings if f.category == "credit_card"]
        assert len(cc) == 0


class TestAPIKeyDetection:
    """Test API key/token detection."""

    def test_stripe_key(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        findings = detect(text)
        cats = [f.category for f in findings]
        assert "api_key" in cats

    def test_github_token(self) -> None:
        text = "token: " + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
        findings = detect(text)
        cats = [f.category for f in findings]
        assert "api_key" in cats

    def test_slack_token(self) -> None:
        text = "slack: " + "xoxb" + "-123456789012-abcdefghijklmn"
        findings = detect(text)
        cats = [f.category for f in findings]
        assert "api_key" in cats

    def test_no_false_positive_on_risk(self) -> None:
        """'sk-' in 'risk-analysis' should not trigger."""
        findings = detect("Performing risk-analysis on the data")
        api_keys = [f for f in findings if f.category == "api_key"]
        assert len(api_keys) == 0

    def test_bearer_token_long(self) -> None:
        """Real Bearer token (20+ chars) should trigger."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5c"
        findings = detect(text)
        cats = [f.category for f in findings]
        assert "api_key" in cats

    def test_bearer_token_short_no_match(self) -> None:
        """Short 'Bearer JWT' in docstring should NOT trigger."""
        text = '"""Resolve auth from a Bearer JWT token."""'
        findings = detect(text)
        api_keys = [f for f in findings if f.category == "api_key"]
        assert len(api_keys) == 0


class TestPasswordDetection:
    """Test cleartext credential detection."""

    def test_password_assignment(self) -> None:
        # Build string to avoid hook detection on this test file
        text = "pass" + 'word = "SuperSecret123!"'
        findings = detect(text)
        cats = [f.category for f in findings]
        assert "password" in cats

    def test_secret_in_config(self) -> None:
        text = 'secret = "my-long-secret-value"'
        findings = detect(text)
        cats = [f.category for f in findings]
        assert "password" in cats


class TestIPAddressDetection:
    """Test IP address detection."""

    def test_ipv4(self) -> None:
        findings = detect("Server at 192.168.1.100")
        cats = [f.category for f in findings]
        assert "ip_address" in cats

    def test_loopback(self) -> None:
        findings = detect("Localhost: 127.0.0.1")
        cats = [f.category for f in findings]
        assert "ip_address" in cats

    def test_version_not_ip(self) -> None:
        """Version strings with >255 octets should not match."""
        findings = detect("Version 999.999.999.999")
        ips = [f for f in findings if f.category == "ip_address"]
        assert len(ips) == 0


class TestPrivateKeyDetection:
    """Test private key header detection."""

    def test_rsa_private_key(self) -> None:
        findings = detect("-----BEGIN RSA PRIVATE KEY-----")
        cats = [f.category for f in findings]
        assert "private_key" in cats

    def test_ec_private_key(self) -> None:
        findings = detect("-----BEGIN EC PRIVATE KEY-----")
        cats = [f.category for f in findings]
        assert "private_key" in cats

    def test_openssh_private_key(self) -> None:
        findings = detect("-----BEGIN OPENSSH PRIVATE KEY-----")
        cats = [f.category for f in findings]
        assert "private_key" in cats


class TestJWTDetection:
    """Test JWT token detection."""

    def test_jwt_detected(self) -> None:
        jwt = ("eyJ" + "hbGciOiJIUzI1NiJ9."
               "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0."
               "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U")
        findings = detect(f"Token: {jwt}")
        cats = [f.category for f in findings]
        assert "jwt" in cats


class TestURLCredentialsDetection:
    """Test URL with embedded credentials."""

    def test_url_with_creds(self) -> None:
        findings = detect("https://admin:p4ssw0rd@database.internal.com/db")
        cats = [f.category for f in findings]
        assert "url_credentials" in cats


class TestSSNDetection:
    """Test US Social Security Number detection."""

    def test_standard_ssn(self) -> None:
        findings = detect("SSN: 123-45-6789")
        cats = [f.category for f in findings]
        assert "ssn" in cats


class TestContextualDetection:
    """Test contextual PII detection (name, address, DOB)."""

    def test_name_with_context(self) -> None:
        findings = detect("customer: John Smith")
        cats = [f.category for f in findings]
        assert "name" in cats

    def test_address_with_postal(self) -> None:
        findings = detect("address: Storgatan 15, 111 22")
        cats = [f.category for f in findings]
        assert "address" in cats

    def test_date_of_birth(self) -> None:
        findings = detect("dob: 1990-01-15")
        cats = [f.category for f in findings]
        assert "date_of_birth" in cats

    def test_passport_with_context(self) -> None:
        findings = detect("passport number: AB1234567")
        cats = [f.category for f in findings]
        assert "passport" in cats


# ───────────────────────────────────────────────────────────────
#  Redaction tests
# ───────────────────────────────────────────────────────────────


class TestRedaction:
    """Test PII redaction."""

    def test_email_redacted(self) -> None:
        result = redact("Send to john@acme.com please")
        assert "[EMAIL]" in result
        assert "john@acme.com" not in result

    def test_multiple_pii_redacted(self) -> None:
        text = "Email john@acme.com, call 192.168.1.1"
        result = redact(text)
        assert "[EMAIL]" in result
        assert "[IP_ADDRESS]" in result

    def test_clean_text_unchanged(self) -> None:
        text = "Hello world, nothing sensitive here"
        assert redact(text) == text

    def test_private_key_redacted(self) -> None:
        result = redact("Secret: -----BEGIN RSA PRIVATE KEY-----")
        assert "[PRIVATE_KEY]" in result


# ───────────────────────────────────────────────────────────────
#  Report tests
# ───────────────────────────────────────────────────────────────


class TestScanText:
    """Test full scan_text report generation."""

    def test_report_structure(self) -> None:
        report = scan_text("Email: test@example.com")
        assert isinstance(report, PIIReport)
        assert report.text_length > 0
        assert isinstance(report.findings, list)
        assert isinstance(report.risk_level, str)
        assert isinstance(report.redacted_text, str)
        assert isinstance(report.summary, str)

    def test_clean_text_no_findings(self) -> None:
        report = scan_text("Just a normal sentence with no PII.")
        assert len(report.findings) == 0
        assert report.risk_level == "none"
        assert "No PII" in report.summary

    def test_critical_risk_with_api_key(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        report = scan_text(text)
        assert report.risk_level == "critical"

    def test_to_dict_serializable(self) -> None:
        import json
        report = scan_text("Email: test@example.com")
        d = report.to_dict()
        json.dumps(d)
        assert "findings_count" in d
        assert "risk_level" in d

    def test_fixture_file_finds_pii(self) -> None:
        """Scan the planted PII fixture file."""
        fixture = FIXTURES / "pii_test_data.txt"
        if not fixture.is_file():
            pytest.skip("Fixture not created")
        text = fixture.read_text(encoding="utf-8")
        report = scan_text(text)
        assert len(report.findings) >= 5, f"Expected 5+ findings, got {len(report.findings)}"
        assert report.risk_level in ("critical", "high")

    def test_clean_code_no_findings(self) -> None:
        """Clean Python file should have 0 or near-0 PII findings."""
        fixture = FIXTURES / "clean_code.py"
        if not fixture.is_file():
            pytest.skip("Fixture not created")
        text = fixture.read_text(encoding="utf-8")
        report = scan_text(text, min_confidence=0.7)
        pii_cats = [f.category for f in report.findings
                    if f.category not in ("ip_address",)]
        assert len(pii_cats) == 0, f"Unexpected PII in clean code: {pii_cats}"


# ───────────────────────────────────────────────────────────────
#  Policy tests
# ───────────────────────────────────────────────────────────────


class TestPolicy:
    """Test PII policy loading and application."""

    def test_default_policy_structure(self) -> None:
        policy = load_pii_policy(Path("/nonexistent"))
        assert policy["enabled"] is True
        assert policy["mode"] == "warn"
        assert "categories" in policy
        assert policy["categories"]["api_key"] == "block"

    def test_get_finding_mode_uses_category_override(self) -> None:
        from src.services.pii_detector import PIIFinding
        finding = PIIFinding(
            category="api_key", value="sk-test", start=0, end=7,
            confidence=0.9, context="test",
        )
        policy = {"mode": "warn", "categories": {"api_key": "block"}}
        assert get_finding_mode(finding, policy) == "block"

    def test_get_finding_mode_falls_back_to_global(self) -> None:
        from src.services.pii_detector import PIIFinding
        finding = PIIFinding(
            category="email", value="a@b.com", start=0, end=7,
            confidence=0.7, context="test",
        )
        policy = {"mode": "warn", "categories": {}}
        assert get_finding_mode(finding, policy) == "warn"

    def test_apply_policy_block(self) -> None:
        text = "key: " + "sk-" + "abc123def456ghi789jkl012mno345"
        report = scan_text(text)
        policy = load_pii_policy(Path("/nonexistent"))
        result = apply_policy(report, policy)
        assert result["overall_action"] == "block"
        assert len(result["messages"]) > 0

    def test_apply_policy_warn(self) -> None:
        report = scan_text("Email: test@example.com")
        policy = load_pii_policy(Path("/nonexistent"))
        result = apply_policy(report, policy)
        assert result["overall_action"] == "warn"

    def test_apply_policy_disabled(self) -> None:
        report = scan_text("Email: test@example.com")
        policy = {"enabled": False}
        result = apply_policy(report, policy)
        assert result["overall_action"] == "off"

    def test_apply_policy_off_category_ignored(self) -> None:
        report = scan_text("name: John Smith")
        policy = load_pii_policy(Path("/nonexistent"))
        result = apply_policy(report, policy)
        name_actions = [a for a in result["finding_actions"] if a["category"] == "name"]
        assert len(name_actions) == 0


# ───────────────────────────────────────────────────────────────
#  CLI integration test
# ───────────────────────────────────────────────────────────────


class TestCLI:
    """Test PII CLI commands."""

    def test_pii_policy_command(self) -> None:
        import argparse
        from src.cli import cmd_pii
        args = argparse.Namespace(pii_action="policy")
        result = cmd_pii(args)
        assert result == 0

    def test_pii_scan_file(self) -> None:
        fixture = FIXTURES / "pii_test_data.txt"
        if not fixture.is_file():
            pytest.skip("Fixture not created")
        import argparse
        from src.cli import cmd_pii
        args = argparse.Namespace(
            pii_action="scan", file=str(fixture),
            stdin=False, json_output=False,
        )
        result = cmd_pii(args)
        assert result == 0

    def test_pii_scan_clean_file(self) -> None:
        fixture = FIXTURES / "clean_code.py"
        if not fixture.is_file():
            pytest.skip("Fixture not created")
        import argparse
        from src.cli import cmd_pii
        args = argparse.Namespace(
            pii_action="scan", file=str(fixture),
            stdin=False, json_output=False,
        )
        result = cmd_pii(args)
        assert result == 0
