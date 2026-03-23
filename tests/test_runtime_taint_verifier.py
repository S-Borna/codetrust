# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the runtime taint verification engine."""

from unittest.mock import AsyncMock

import pytest

from src.models.enums import Language, Severity
from src.models.responses import Finding, SandboxResponse
from src.services.runtime_taint_verifier import (
    TAINT_VERIFIED_MARKER,
    VERIFIED_CONFIDENCE,
    RuntimeTaintVerifier,
    VerificationMethod,
    extract_category_from_rule_id,
    generate_exploit_payload,
)
from src.services.sandbox import SandboxService

# ═══════════════════════════════════════════════════════════════
#  Fixtures
# ═══════════════════════════════════════════════════════════════


def _make_finding(
    rule_id: str,
    confidence: float = 0.7,
) -> Finding:
    """Create a Finding with minimal required fields."""
    return Finding(
        rule_id=rule_id,
        severity=Severity.BLOCK,
        message=f"Taint flow detected: {rule_id}",
        file="app.py",
        line=10,
        confidence=confidence,
    )


def _make_sandbox_verified() -> SandboxResponse:
    """Create a SandboxResponse simulating a verified exploit."""
    return SandboxResponse(
        exit_code=0,
        stdout=f"{TAINT_VERIFIED_MARKER}\n",
        stderr="",
        timed_out=False,
        latency_ms=50,
    )


def _make_sandbox_blocked() -> SandboxResponse:
    """Create a SandboxResponse simulating a blocked exploit."""
    return SandboxResponse(
        exit_code=1,
        stdout="",
        stderr="",
        timed_out=False,
        latency_ms=30,
    )


def _make_sandbox_error() -> SandboxResponse:
    """Create a SandboxResponse with a service error."""
    return SandboxResponse(
        exit_code=-1,
        error="Docker is not available",
        latency_ms=0,
    )


@pytest.fixture()
def mock_sandbox() -> SandboxService:
    """Create a mock SandboxService with Docker available."""
    sandbox = SandboxService()
    sandbox.is_docker_available = AsyncMock(return_value=True)
    sandbox.execute_code = AsyncMock(return_value=_make_sandbox_verified())
    return sandbox


@pytest.fixture()
def mock_sandbox_unavailable() -> SandboxService:
    """Create a mock SandboxService with Docker unavailable."""
    sandbox = SandboxService()
    sandbox.is_docker_available = AsyncMock(return_value=False)
    return sandbox


@pytest.fixture()
def verifier(mock_sandbox: SandboxService) -> RuntimeTaintVerifier:
    """Create a RuntimeTaintVerifier with a mocked sandbox."""
    return RuntimeTaintVerifier(sandbox=mock_sandbox)


@pytest.fixture()
def verifier_no_sandbox(
    mock_sandbox_unavailable: SandboxService,
) -> RuntimeTaintVerifier:
    """Create a RuntimeTaintVerifier with unavailable sandbox."""
    return RuntimeTaintVerifier(sandbox=mock_sandbox_unavailable)


# ═══════════════════════════════════════════════════════════════
#  Payload generation tests
# ═══════════════════════════════════════════════════════════════


class TestPayloadGeneration:
    """Tests for exploit payload generation per category."""

    def test_sql_injection_payload(self) -> None:
        """SQL injection payload contains OR clause."""
        payload = generate_exploit_payload("sql_injection")
        assert payload is not None
        assert "OR 1=1" in payload.payload
        assert payload.category == "sql_injection"
        assert TAINT_VERIFIED_MARKER in payload.wrapper_template

    def test_command_injection_payload(self) -> None:
        """Command injection payload contains shell metacharacter."""
        payload = generate_exploit_payload("command_injection")
        assert payload is not None
        assert ";" in payload.payload
        assert "echo" in payload.payload
        assert payload.category == "command_injection"

    def test_xss_payload(self) -> None:
        """XSS payload contains script tag."""
        payload = generate_exploit_payload("xss")
        assert payload is not None
        assert "<script>" in payload.payload
        assert payload.category == "xss"

    def test_path_traversal_payload(self) -> None:
        """Path traversal payload contains directory traversal."""
        payload = generate_exploit_payload("path_traversal")
        assert payload is not None
        assert "../" in payload.payload
        assert payload.category == "path_traversal"

    def test_ssrf_payload(self) -> None:
        """SSRF payload targets cloud metadata endpoint."""
        payload = generate_exploit_payload("ssrf")
        assert payload is not None
        assert "169.254.169.254" in payload.payload
        assert payload.category == "ssrf"

    def test_unsupported_category_returns_none(self) -> None:
        """Unknown categories return None."""
        assert generate_exploit_payload("unknown_category") is None

    def test_all_payloads_have_marker(self) -> None:
        """Every supported payload includes the verification marker."""
        categories = [
            "sql_injection",
            "command_injection",
            "xss",
            "path_traversal",
            "ssrf",
        ]
        for cat in categories:
            payload = generate_exploit_payload(cat)
            assert payload is not None, f"No payload for {cat}"
            assert TAINT_VERIFIED_MARKER in payload.wrapper_template


# ═══════════════════════════════════════════════════════════════
#  Category extraction tests
# ═══════════════════════════════════════════════════════════════


class TestCategoryExtraction:
    """Tests for rule_id to category mapping."""

    def test_extract_sql_injection(self) -> None:
        """Extract sql_injection from taint_sql_injection."""
        assert extract_category_from_rule_id("taint_sql_injection") == "sql_injection"

    def test_extract_command_injection(self) -> None:
        """Extract command_injection from taint_command_injection."""
        result = extract_category_from_rule_id("taint_command_injection")
        assert result == "command_injection"

    def test_non_taint_rule_returns_empty(self) -> None:
        """Non-taint rule IDs return empty string."""
        assert extract_category_from_rule_id("sec_hardcoded_secret") == ""

    def test_empty_rule_id(self) -> None:
        """Empty rule_id returns empty string."""
        assert extract_category_from_rule_id("") == ""


# ═══════════════════════════════════════════════════════════════
#  Verification with sandbox available
# ═══════════════════════════════════════════════════════════════


class TestVerificationWithSandbox:
    """Tests for runtime verification when sandbox is available."""

    @pytest.mark.asyncio()
    async def test_verified_finding_has_high_confidence(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Verified findings receive VERIFIED_CONFIDENCE."""
        findings = [_make_finding("taint_sql_injection", confidence=0.7)]
        summary = await verifier.verify_findings(findings)

        assert summary.verified == 1
        assert summary.unverified == 0
        result = summary.results[0]
        assert result.verified is True
        assert result.confidence == VERIFIED_CONFIDENCE

    @pytest.mark.asyncio()
    async def test_verified_finding_has_exploit_payload(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Verified findings include the exploit payload string."""
        findings = [_make_finding("taint_sql_injection")]
        summary = await verifier.verify_findings(findings)

        result = summary.results[0]
        assert result.exploit_payload != ""
        assert "OR 1=1" in result.exploit_payload

    @pytest.mark.asyncio()
    async def test_verified_method_is_sandbox_exploit(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Verified findings report sandbox_exploit method."""
        findings = [_make_finding("taint_command_injection")]
        summary = await verifier.verify_findings(findings)

        result = summary.results[0]
        assert result.verification_method == VerificationMethod.SANDBOX_EXPLOIT

    @pytest.mark.asyncio()
    async def test_blocked_exploit_preserves_original_confidence(
        self,
        mock_sandbox: SandboxService,
    ) -> None:
        """When exploit fails, original confidence is preserved."""
        mock_sandbox.execute_code = AsyncMock(
            return_value=_make_sandbox_blocked(),
        )
        verifier = RuntimeTaintVerifier(sandbox=mock_sandbox)
        original_confidence = 0.65
        findings = [
            _make_finding("taint_xss", confidence=original_confidence),
        ]
        summary = await verifier.verify_findings(findings)

        result = summary.results[0]
        assert result.verified is False
        assert result.confidence == original_confidence
        assert result.verification_method == VerificationMethod.PAYLOAD_BLOCKED

    @pytest.mark.asyncio()
    async def test_sandbox_error_returns_unverified(
        self,
        mock_sandbox: SandboxService,
    ) -> None:
        """Sandbox errors produce unverified results."""
        mock_sandbox.execute_code = AsyncMock(
            return_value=_make_sandbox_error(),
        )
        verifier = RuntimeTaintVerifier(sandbox=mock_sandbox)
        findings = [_make_finding("taint_sql_injection")]
        summary = await verifier.verify_findings(findings)

        result = summary.results[0]
        assert result.verified is False
        assert result.verification_method == VerificationMethod.SANDBOX_ERROR

    @pytest.mark.asyncio()
    async def test_unsupported_category_skipped(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Findings with unsupported categories are skipped."""
        findings = [_make_finding("sec_hardcoded_secret")]
        summary = await verifier.verify_findings(findings)

        assert summary.unverified == 1
        result = summary.results[0]
        assert result.verified is False
        assert result.verification_method == VerificationMethod.UNSUPPORTED_CATEGORY

    @pytest.mark.asyncio()
    async def test_multiple_findings_mixed_results(
        self,
        mock_sandbox: SandboxService,
    ) -> None:
        """Batch with mixed categories produces correct counts."""
        call_count = 0

        async def alternate_results(
            code: str, language: Language, timeout: int,
        ) -> SandboxResponse:
            nonlocal call_count
            call_count += 1
            if call_count % 2 == 1:
                return _make_sandbox_verified()
            return _make_sandbox_blocked()

        mock_sandbox.execute_code = AsyncMock(side_effect=alternate_results)
        verifier = RuntimeTaintVerifier(sandbox=mock_sandbox)

        findings = [
            _make_finding("taint_sql_injection"),
            _make_finding("taint_xss"),
            _make_finding("taint_command_injection"),
        ]
        summary = await verifier.verify_findings(findings)

        assert summary.total == 3
        assert summary.verified == 2
        assert summary.unverified == 1


# ═══════════════════════════════════════════════════════════════
#  Graceful degradation — sandbox unavailable
# ═══════════════════════════════════════════════════════════════


class TestGracefulDegradation:
    """Tests for behavior when sandbox is not available."""

    @pytest.mark.asyncio()
    async def test_sandbox_unavailable_returns_all_unverified(
        self, verifier_no_sandbox: RuntimeTaintVerifier,
    ) -> None:
        """All findings are unverified when sandbox is down."""
        findings = [
            _make_finding("taint_sql_injection"),
            _make_finding("taint_xss"),
        ]
        summary = await verifier_no_sandbox.verify_findings(findings)

        assert summary.sandbox_unavailable is True
        assert summary.verified == 0
        assert summary.unverified == 2

    @pytest.mark.asyncio()
    async def test_sandbox_unavailable_preserves_confidence(
        self, verifier_no_sandbox: RuntimeTaintVerifier,
    ) -> None:
        """Original confidence preserved when sandbox unavailable."""
        original = 0.72
        findings = [_make_finding("taint_sql_injection", confidence=original)]
        summary = await verifier_no_sandbox.verify_findings(findings)

        result = summary.results[0]
        assert result.confidence == original
        assert result.verified is False

    @pytest.mark.asyncio()
    async def test_sandbox_unavailable_method(
        self, verifier_no_sandbox: RuntimeTaintVerifier,
    ) -> None:
        """Method is SANDBOX_UNAVAILABLE when Docker is down."""
        findings = [_make_finding("taint_path_traversal")]
        summary = await verifier_no_sandbox.verify_findings(findings)

        result = summary.results[0]
        assert result.verification_method == VerificationMethod.SANDBOX_UNAVAILABLE


# ═══════════════════════════════════════════════════════════════
#  Confidence comparison
# ═══════════════════════════════════════════════════════════════


class TestConfidenceComparison:
    """Verified findings always have higher confidence than unverified."""

    @pytest.mark.asyncio()
    async def test_verified_confidence_exceeds_original(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Verified confidence (0.95) exceeds typical static (0.7)."""
        original = 0.7
        findings = [_make_finding("taint_sql_injection", confidence=original)]
        summary = await verifier.verify_findings(findings)

        result = summary.results[0]
        assert result.verified is True
        assert result.confidence > original

    @pytest.mark.asyncio()
    async def test_verified_beats_unverified_same_finding(
        self,
        mock_sandbox: SandboxService,
    ) -> None:
        """For the same finding, verified confidence > unverified."""
        original = 0.7

        # First: verified run
        mock_sandbox.execute_code = AsyncMock(
            return_value=_make_sandbox_verified(),
        )
        verifier = RuntimeTaintVerifier(sandbox=mock_sandbox)
        findings = [_make_finding("taint_sql_injection", confidence=original)]
        verified_summary = await verifier.verify_findings(findings)

        # Second: blocked run
        mock_sandbox.execute_code = AsyncMock(
            return_value=_make_sandbox_blocked(),
        )
        verifier2 = RuntimeTaintVerifier(sandbox=mock_sandbox)
        unverified_summary = await verifier2.verify_findings(findings)

        verified_conf = verified_summary.results[0].confidence
        unverified_conf = unverified_summary.results[0].confidence
        assert verified_conf > unverified_conf


# ═══════════════════════════════════════════════════════════════
#  Per-category verification
# ═══════════════════════════════════════════════════════════════


class TestPerCategoryVerification:
    """Each vulnerability category verifies correctly in sandbox."""

    @pytest.mark.asyncio()
    @pytest.mark.parametrize(
        "rule_id",
        [
            "taint_sql_injection",
            "taint_command_injection",
            "taint_xss",
            "taint_path_traversal",
            "taint_ssrf",
        ],
    )
    async def test_category_verifies_successfully(
        self,
        mock_sandbox: SandboxService,
        rule_id: str,
    ) -> None:
        """Each supported category produces a verified result."""
        verifier = RuntimeTaintVerifier(sandbox=mock_sandbox)
        findings = [_make_finding(rule_id)]
        summary = await verifier.verify_findings(findings)

        assert summary.verified == 1
        result = summary.results[0]
        assert result.verified is True
        assert result.confidence == VERIFIED_CONFIDENCE
        assert result.exploit_payload != ""

    @pytest.mark.asyncio()
    async def test_deserialization_unsupported(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Deserialization category has no payload generator yet."""
        findings = [_make_finding("taint_deserialization")]
        summary = await verifier.verify_findings(findings)

        result = summary.results[0]
        assert result.verified is False
        assert result.verification_method == VerificationMethod.UNSUPPORTED_CATEGORY


# ═══════════════════════════════════════════════════════════════
#  Edge cases
# ═══════════════════════════════════════════════════════════════


class TestEdgeCases:
    """Edge case handling."""

    @pytest.mark.asyncio()
    async def test_empty_findings_list(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Empty input returns empty summary."""
        summary = await verifier.verify_findings([])
        assert summary.total == 0
        assert summary.verified == 0
        assert summary.unverified == 0
        assert summary.results == []

    @pytest.mark.asyncio()
    async def test_summary_counts_match_results(
        self, verifier: RuntimeTaintVerifier,
    ) -> None:
        """Summary counts equal the length of results list."""
        findings = [
            _make_finding("taint_sql_injection"),
            _make_finding("taint_xss"),
            _make_finding("sec_other"),
        ]
        summary = await verifier.verify_findings(findings)

        assert len(summary.results) == summary.total
        assert summary.verified + summary.unverified == summary.total

    @pytest.mark.asyncio()
    async def test_default_sandbox_created_if_none(self) -> None:
        """Verifier creates its own SandboxService if none provided."""
        verifier = RuntimeTaintVerifier(sandbox=None)
        assert verifier._sandbox is not None
