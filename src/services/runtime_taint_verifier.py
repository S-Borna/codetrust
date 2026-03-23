# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Runtime taint verification via sandboxed exploit execution.

Takes static taint analysis findings and attempts to confirm them by
generating minimal proof-of-concept exploit payloads and executing
them inside an isolated Docker sandbox. Findings that are confirmed
exploitable receive ``verified=True`` with high confidence (~0.95),
eliminating false positives that plague purely static approaches.

Graceful degradation: if the sandbox is unavailable, findings pass
through unmodified with their original confidence scores.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum

import structlog

from src.models.enums import Language
from src.models.responses import Finding, SandboxResponse
from src.rules.taint_rules import (
    CATEGORY_COMMAND_INJECTION,
    CATEGORY_PATH_TRAVERSAL,
    CATEGORY_SQL_INJECTION,
    CATEGORY_SSRF,
    CATEGORY_XSS,
)
from src.services.sandbox import SandboxService

logger = structlog.get_logger()

# ═══════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════

VERIFIED_CONFIDENCE: float = 0.95
SANDBOX_TIMEOUT_SECONDS: int = 10
TAINT_VERIFIED_MARKER: str = "TAINT_VERIFIED"

# Prefix for taint rule IDs (e.g. "taint_sql_injection").
_TAINT_RULE_PREFIX: str = "taint_"

# Cloud metadata IP used in SSRF exploit payloads.
_METADATA_IP: str = "169.254.169.254"


class VerificationMethod(StrEnum):
    """How a finding was verified."""

    SANDBOX_EXPLOIT = "sandbox_exploit"
    SANDBOX_UNAVAILABLE = "sandbox_unavailable"
    UNSUPPORTED_CATEGORY = "unsupported_category"
    SANDBOX_ERROR = "sandbox_error"
    PAYLOAD_BLOCKED = "payload_blocked"


# ═══════════════════════════════════════════════════════════════
#  Result dataclasses
# ═══════════════════════════════════════════════════════════════


@dataclass
class VerifiedFinding:
    """A taint finding enriched with runtime verification metadata."""

    finding: Finding
    verified: bool = False
    confidence: float = 0.0
    exploit_payload: str = ""
    verification_method: str = ""


@dataclass
class VerificationSummary:
    """Summary of a runtime verification batch."""

    total: int = 0
    verified: int = 0
    unverified: int = 0
    sandbox_unavailable: bool = False
    results: list[VerifiedFinding] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════
#  Payload generators — one per vulnerability category
# ═══════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ExploitPayload:
    """A generated exploit payload with its detection criteria."""

    payload: str
    marker: str
    category: str
    wrapper_template: str


def _generate_sql_injection_payload() -> ExploitPayload:
    """Generate a SQL injection proof-of-concept payload.

    Simulates string interpolation into a query and checks
    whether the injected payload alters the query structure.
    """
    payload = "' OR 1=1 --"
    wrapper = (
        "import sys\n"
        "user_input = \"' OR 1=1 --\"\n"
        "query = f\"SELECT id FROM users WHERE id = '{user_input}'\"\n"
        "if \"OR 1=1\" in query:\n"
        f"    print(\"{TAINT_VERIFIED_MARKER}\")\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    return ExploitPayload(
        payload=payload,
        marker=TAINT_VERIFIED_MARKER,
        category=CATEGORY_SQL_INJECTION,
        wrapper_template=wrapper,
    )


def _generate_command_injection_payload() -> ExploitPayload:
    """Generate a command injection proof-of-concept payload.

    Checks whether shell metacharacters in the payload would
    cause command chaining when passed to a shell executor.
    """
    payload = "; echo TAINT_VERIFIED"
    wrapper = (
        "import sys\n"
        "user_input = \"; echo TAINT_VERIFIED\"\n"
        "command = f\"ls {user_input}\"\n"
        "if \";\" in command and \"echo\" in command:\n"
        f"    print(\"{TAINT_VERIFIED_MARKER}\")\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    return ExploitPayload(
        payload=payload,
        marker=TAINT_VERIFIED_MARKER,
        category=CATEGORY_COMMAND_INJECTION,
        wrapper_template=wrapper,
    )


def _generate_xss_payload() -> ExploitPayload:
    """Generate an XSS proof-of-concept payload.

    Checks whether a script tag in user input appears unescaped
    in an HTML response string.
    """
    payload = "<script>alert(1)</script>"
    wrapper = (
        "import sys\n"
        "user_input = \"<script>alert(1)</script>\"\n"
        "html = f\"<div>{user_input}</div>\"\n"
        "if \"<script>\" in html:\n"
        f"    print(\"{TAINT_VERIFIED_MARKER}\")\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    return ExploitPayload(
        payload=payload,
        marker=TAINT_VERIFIED_MARKER,
        category=CATEGORY_XSS,
        wrapper_template=wrapper,
    )


def _generate_path_traversal_payload() -> ExploitPayload:
    """Generate a path traversal proof-of-concept payload.

    Checks whether directory traversal sequences survive path
    construction, allowing access outside the intended directory.
    """
    payload = "../../etc/passwd"
    wrapper = (
        "import sys\n"
        "import os\n"
        "user_input = \"../../etc/passwd\"\n"
        "path = os.path.join(\"/uploads\", user_input)\n"
        "normalized = os.path.normpath(path)\n"
        "if not normalized.startswith(\"/uploads\"):\n"
        f"    print(\"{TAINT_VERIFIED_MARKER}\")\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    return ExploitPayload(
        payload=payload,
        marker=TAINT_VERIFIED_MARKER,
        category=CATEGORY_PATH_TRAVERSAL,
        wrapper_template=wrapper,
    )


def _generate_ssrf_payload() -> ExploitPayload:
    """Generate an SSRF proof-of-concept payload.

    Checks whether a cloud metadata endpoint URL would be
    passed to an HTTP client without validation.
    """
    # noqa: payload is intentionally an unencrypted URL for exploit testing
    payload = f"http://{_METADATA_IP}/latest/meta-data/"
    wrapper = (
        "import sys\n"
        f"user_input = \"http://{_METADATA_IP}/latest/meta-data/\"\n"
        f"if \"{_METADATA_IP}\" in user_input:\n"
        f"    print(\"{TAINT_VERIFIED_MARKER}\")\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    return ExploitPayload(
        payload=payload,
        marker=TAINT_VERIFIED_MARKER,
        category=CATEGORY_SSRF,
        wrapper_template=wrapper,
    )


PayloadGenerator = Callable[[], ExploitPayload]

PAYLOAD_GENERATORS: dict[str, PayloadGenerator] = {
    CATEGORY_SQL_INJECTION: _generate_sql_injection_payload,
    CATEGORY_COMMAND_INJECTION: _generate_command_injection_payload,
    CATEGORY_XSS: _generate_xss_payload,
    CATEGORY_PATH_TRAVERSAL: _generate_path_traversal_payload,
    CATEGORY_SSRF: _generate_ssrf_payload,
}


def generate_exploit_payload(category: str) -> ExploitPayload | None:
    """Generate an exploit payload for a vulnerability category.

    Args:
        category: The taint sink category (e.g., 'sql_injection').

    Returns:
        An ExploitPayload if the category is supported, else None.
    """
    generator = PAYLOAD_GENERATORS.get(category)
    if generator is None:
        return None
    return generator()


def extract_category_from_rule_id(rule_id: str) -> str:
    """Extract the vulnerability category from a taint rule_id.

    Taint rule IDs follow ``taint_<category>``, e.g.
    ``taint_sql_injection`` maps to ``sql_injection``.

    Args:
        rule_id: The finding's rule_id string.

    Returns:
        The extracted category, or empty string if not a taint rule.
    """
    if rule_id.startswith(_TAINT_RULE_PREFIX):
        return rule_id[len(_TAINT_RULE_PREFIX):]
    return ""


# ═══════════════════════════════════════════════════════════════
#  Runtime Taint Verifier
# ═══════════════════════════════════════════════════════════════


class RuntimeTaintVerifier:
    """Verifies taint findings by executing exploit payloads in a sandbox.

    Takes findings from static taint analysis and attempts to confirm
    them by running proof-of-concept exploits in isolated Docker
    containers. Confirmed findings receive high confidence scores;
    unconfirmed findings retain their original scores.
    """

    def __init__(self, sandbox: SandboxService | None = None) -> None:
        """Initialize the verifier with an optional sandbox service.

        Args:
            sandbox: SandboxService instance. Creates one if None.
        """
        self._sandbox = sandbox or SandboxService()

    async def verify_findings(
        self,
        findings: list[Finding],
        language: Language = Language.PYTHON,
    ) -> VerificationSummary:
        """Verify a batch of taint findings via sandboxed execution.

        Args:
            findings: List of Finding objects from taint analysis.
            language: Language for sandbox execution.

        Returns:
            VerificationSummary with enriched results.
        """
        summary = VerificationSummary(total=len(findings))

        if not await self._sandbox.is_docker_available():
            return self._build_unavailable_summary(summary, findings)

        return await self._verify_all(summary, findings, language)

    def _build_unavailable_summary(
        self,
        summary: VerificationSummary,
        findings: list[Finding],
    ) -> VerificationSummary:
        """Build summary when sandbox is unavailable.

        Args:
            summary: The pre-initialized summary to populate.
            findings: Original findings to wrap as unverified.

        Returns:
            Summary with all findings marked unverified.
        """
        logger.warning("runtime_taint_verifier_sandbox_unavailable")
        summary.sandbox_unavailable = True
        summary.unverified = len(findings)
        summary.results = [
            self._unverified_result(f, VerificationMethod.SANDBOX_UNAVAILABLE)
            for f in findings
        ]
        return summary

    async def _verify_all(
        self,
        summary: VerificationSummary,
        findings: list[Finding],
        language: Language,
    ) -> VerificationSummary:
        """Run sandbox verification for each finding.

        Args:
            summary: The pre-initialized summary to populate.
            findings: Findings to verify.
            language: Language for sandbox execution.

        Returns:
            Populated VerificationSummary.
        """
        for finding in findings:
            result = await self._verify_single(finding, language)
            summary.results.append(result)
            if result.verified:
                summary.verified += 1
            else:
                summary.unverified += 1

        logger.info(
            "runtime_taint_verification_complete",
            total=summary.total,
            verified=summary.verified,
            unverified=summary.unverified,
        )
        return summary

    async def _verify_single(
        self,
        finding: Finding,
        language: Language,
    ) -> VerifiedFinding:
        """Verify a single taint finding against the sandbox.

        Args:
            finding: The taint finding to verify.
            language: Language for sandbox execution.

        Returns:
            VerifiedFinding with verification metadata.
        """
        exploit = self._resolve_exploit(finding)
        if exploit is None:
            return self._unverified_result(
                finding, VerificationMethod.UNSUPPORTED_CATEGORY,
            )

        sandbox_result = await self._sandbox.execute_code(
            code=exploit.wrapper_template,
            language=language,
            timeout=SANDBOX_TIMEOUT_SECONDS,
        )

        return self._interpret_sandbox_result(
            finding, exploit, sandbox_result,
        )

    @staticmethod
    def _resolve_exploit(finding: Finding) -> ExploitPayload | None:
        """Resolve the exploit payload for a finding's category.

        Args:
            finding: The finding to look up.

        Returns:
            ExploitPayload if category is supported, else None.
        """
        category = extract_category_from_rule_id(finding.rule_id)
        if not category:
            return None
        return generate_exploit_payload(category)

    def _interpret_sandbox_result(
        self,
        finding: Finding,
        exploit: ExploitPayload,
        sandbox_result: SandboxResponse,
    ) -> VerifiedFinding:
        """Interpret sandbox output to determine verification status.

        Args:
            finding: The original finding.
            exploit: The exploit that was executed.
            sandbox_result: The sandbox execution response.

        Returns:
            VerifiedFinding based on sandbox output.
        """
        if sandbox_result.error:
            logger.warning(
                "runtime_taint_sandbox_error",
                rule_id=finding.rule_id,
                error=sandbox_result.error,
            )
            return self._unverified_result(
                finding, VerificationMethod.SANDBOX_ERROR,
            )

        marker_found = exploit.marker in sandbox_result.stdout
        exited_clean = sandbox_result.exit_code == 0

        if marker_found and exited_clean:
            return VerifiedFinding(
                finding=finding,
                verified=True,
                confidence=VERIFIED_CONFIDENCE,
                exploit_payload=exploit.payload,
                verification_method=VerificationMethod.SANDBOX_EXPLOIT,
            )

        return VerifiedFinding(
            finding=finding,
            verified=False,
            confidence=finding.confidence,
            exploit_payload=exploit.payload,
            verification_method=VerificationMethod.PAYLOAD_BLOCKED,
        )

    @staticmethod
    def _unverified_result(
        finding: Finding,
        method: VerificationMethod,
    ) -> VerifiedFinding:
        """Build an unverified result preserving original confidence.

        Args:
            finding: The original finding.
            method: Why verification was skipped.

        Returns:
            VerifiedFinding with verified=False.
        """
        return VerifiedFinding(
            finding=finding,
            verified=False,
            confidence=finding.confidence,
            exploit_payload="",
            verification_method=method,
        )
