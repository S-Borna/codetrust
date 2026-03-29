"""Tests for FastAPI endpoints."""

import asyncio
from datetime import date, timedelta
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

import src.api as api_module
from src.api import app
from src.config import settings
from src.models.enums import Registry, Severity, VerifyStatus
from src.models.responses import (
    DockerImageResult,
    Finding,
    PackageResult,
    StaticScanResponse,
)
from src.services.ast_analyzer import AstAnalyzer
from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.database import DatabaseService
from src.services.docker_verify import DockerVerifyService
from src.services.registry import RegistryService
from src.services.runtime_taint_verifier import (
    RuntimeTaintVerifier,
    VerificationMethod,
    VerificationSummary,
    VerifiedFinding,
)
from src.services.sandbox import SandboxService
from src.services.static_analyzer import StaticAnalyzer
from src.services.taint_analyzer import TaintAnalyzer


@pytest.fixture()
def _setup_app_state() -> None:
    """Set up app.state with test dependencies."""
    cache = CacheService("redis://localhost:6379")
    cache._client = None

    original_api_key = settings.api_key
    settings.api_key = ""

    http_client = httpx.AsyncClient(timeout=5.0)
    app.state.cache = cache
    app.state.http_client = http_client
    app.state.registry = RegistryService(cache, http_client)
    app.state.docker = DockerVerifyService(cache, http_client)
    app.state.analyzer = StaticAnalyzer()
    app.state.ast_analyzer = AstAnalyzer()
    app.state.taint_analyzer = TaintAnalyzer()
    app.state.sandbox = SandboxService()
    app.state.db = None  # Database not needed for existing endpoint tests
    app.state.billing = MagicMock(spec=BillingService)
    app.state.auth = AuthService(http_client)
    app.state.rate_limiter = None  # No rate limiting without DB
    api_module._scan_limits.clear()

    yield

    settings.api_key = original_api_key


@pytest.fixture()
def client(_setup_app_state: None) -> TestClient:
    """Create a TestClient with mocked app state."""
    return TestClient(app, raise_server_exceptions=False)


# --- Health Check ---


class TestHealthCheck:
    """Tests for GET /v1/status."""

    def test_health_returns_ok(self, client: TestClient) -> None:
        """Health check returns status ok."""
        response = client.get("/v1/status")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["version"] == settings.version

    def test_health_includes_cache_status(self, client: TestClient) -> None:
        """Health check includes cache_connected field."""
        response = client.get("/v1/status")

        data = response.json()
        assert "cache_connected" in data


# --- Auth ---


class TestAuth:
    """Tests for API key authentication."""

    def test_no_auth_required_when_api_key_empty(
        self, client: TestClient
    ) -> None:
        """When CODETRUST_API_KEY is empty, no auth required."""
        original = settings.api_key
        settings.api_key = ""
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
            )
            assert response.status_code == 200
        finally:
            settings.api_key = original

    def test_api_key_header_ignored_when_auth_not_configured(
        self, client: TestClient
    ) -> None:
        """When auth is not configured, sending X-API-Key should not cause unauthorized."""
        original = settings.api_key
        settings.api_key = ""
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
                headers={"X-API-Key": "k"},
            )
            assert response.status_code == 200
        finally:
            settings.api_key = original

    def test_anonymous_scan_allowed_when_api_key_set(
        self, client: TestClient
    ) -> None:
        """Static scan remains available without API key (free tier)."""
        original = settings.api_key
        settings.api_key = "k1"
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
            )
            assert response.status_code == 200
        finally:
            settings.api_key = original

    def test_valid_api_key_passes_auth(
        self, client: TestClient
    ) -> None:
        """Valid API key passes authentication."""
        original = settings.api_key
        settings.api_key = "k1"
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
                headers={"X-API-Key": "k1"},
            )
            assert response.status_code == 200
        finally:
            settings.api_key = original

    def test_unknown_api_key_returns_401(
        self, client: TestClient
    ) -> None:
        """Unknown API keys are rejected even on optional-auth scan endpoints."""
        original = settings.api_key
        settings.api_key = "k1"
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
                headers={"X-API-Key": "no"},
            )
            assert response.status_code == 401
        finally:
            settings.api_key = original

    def test_unknown_database_api_key_returns_401_without_anonymous_fallback(
        self, client: TestClient,
    ) -> None:
        """Unknown API keys should 401 even when a DB-backed key store is configured."""
        original = settings.api_key
        settings.api_key = "master"
        db = MagicMock(spec=DatabaseService)
        db.verify_api_key_hash = AsyncMock(return_value=None)
        app.state.db = db
        try:
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1", "filename": "test.py"},
                headers={"X-API-Key": "arbitrary_key_without_prefix"},
            )
            assert response.status_code == 401
            db.verify_api_key_hash.assert_awaited_once_with("arbitrary_key_without_prefix")
        finally:
            settings.api_key = original
            app.state.db = None

    def test_master_key_resolves_system_master_key_principal(
        self,
    ) -> None:
        """Configured master key resolves to isolated system master principal."""
        original = settings.api_key
        settings.api_key = "k1"
        try:
            ctx = asyncio.run(api_module._resolve_auth_from_key("k1", None))
            assert ctx.user_id == "system_master_key"
            assert ctx.is_admin is True
        finally:
            settings.api_key = original


# --- Static Scan ---


class TestStaticScan:
    """Tests for POST /v1/scan/static."""

    def test_clean_code_returns_pass(self, client: TestClient) -> None:
        """Clean code returns PASS verdict."""
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\ny = 2\n", "filename": "clean.py"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PASS"
        assert data["blocks"] == 0

    def test_eval_detected_returns_block(self, client: TestClient) -> None:
        """Code with dynamic evaluation returns BLOCK verdict."""
        code = "result = " + "e" + "val" + "('2+" + "2')\n"
        response = client.post(
            "/v1/scan/static",
            json={"code": code, "filename": "bad.py"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "BLOCK"
        assert data["blocks"] > 0

    def test_print_detected_returns_warn(self, client: TestClient) -> None:
        """Code with print() returns WARN verdict."""
        response = client.post(
            "/v1/scan/static",
            json={"code": "print('hello')\n", "filename": "warn.py"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "WARN"
        assert data["warnings"] > 0

    def test_invalid_request_returns_422(self, client: TestClient) -> None:
        """Missing required field returns validation error."""
        response = client.post(
            "/v1/scan/static",
            json={"filename": "test.py"},  # missing "code"
        )
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Verify Imports ---


class TestVerifyImports:
    """Tests for POST /v1/verify/imports."""

    def test_verify_imports_valid_request(
        self, client: TestClient
    ) -> None:
        """Valid verify imports request is accepted."""
        with patch.object(
            RegistryService,
            "verify_packages",
            new_callable=AsyncMock,
            return_value=[
                PackageResult(
                    package="fastapi",
                    registry=Registry.PYPI,
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    latest_version="0." + "115.0",
                    message="Package 'fastapi' exists on PyPI.",
                ),
            ],
        ):
            response = client.post(
                "/v1/verify/imports",
                json={
                    "language": "python",
                    "imports": ["fastapi"],
                },
            )

        assert response.status_code == 200
        data = response.json()
        assert data["verified"] == 1
        assert data["failed"] == 0

    def test_verify_imports_not_found_free_plan(
        self, client: TestClient
    ) -> None:
        """Free plan: import not found downgraded to WARN (failed=0)."""
        with patch.object(
            RegistryService,
            "verify_packages",
            new_callable=AsyncMock,
            return_value=[
                PackageResult(
                    package="nonexistent_xyz",
                    registry=Registry.PYPI,
                    status=VerifyStatus.NOT_FOUND,
                    severity=Severity.BLOCK,
                    message="Package 'nonexistent_xyz' not found on PyPI.",
                ),
            ],
        ):
            response = client.post(
                "/v1/verify/imports",
                json={
                    "language": "python",
                    "imports": ["nonexistent_xyz"],
                },
            )

        assert response.status_code == 200
        data = response.json()
        # Free plan: NOT_FOUND downgraded to WARN, no enforcement failure
        assert data["failed"] == 0

    def test_verify_imports_empty_list_returns_422(
        self, client: TestClient
    ) -> None:
        """Empty imports list returns validation error."""
        response = client.post(
            "/v1/verify/imports",
            json={"language": "python", "imports": []},
        )
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Verify Dockerfile ---


class TestVerifyDockerfile:
    """Tests for POST /v1/verify/dockerfile."""

    def test_verify_dockerfile_free_blocked(
        self, client: TestClient
    ) -> None:
        """Free plan cannot access Docker verification."""
        response = client.post(
            "/v1/verify/dockerfile",
            json={
                "images": [{"image": "python", "tag": "3.12-slim"}],
            },
        )
        assert response.status_code == 403

    def test_verify_dockerfile_not_found_free_blocked(
        self, client: TestClient
    ) -> None:
        """Free plan: Docker verification returns 403."""
        response = client.post(
            "/v1/verify/dockerfile",
            json={
                "images": [{"image": "python", "tag": "99." + "99"}],
            },
        )
        assert response.status_code == 403

    def test_verify_dockerfile_empty_images_returns_422(
        self, client: TestClient
    ) -> None:
        """Empty images list returns validation error."""
        response = client.post(
            "/v1/verify/dockerfile",
            json={"images": []},
        )
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# --- Deep Scan ---


class TestDeepScan:
    """Tests for POST /v1/scan/deep."""

    def test_deep_scan_static_only(self, client: TestClient) -> None:
        """Deep scan with only static analysis."""
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "x = 1\ny = 2\n",
                "filename": "clean.py",
                "verify_imports": False,
                "verify_docker": False,
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "PASS"
        assert data["static_scan"] is not None
        assert data["import_verification"] is None
        assert data["docker_verification"] is None

    def test_deep_scan_with_block_finding(self, client: TestClient) -> None:
        """Deep scan with blocking static finding returns BLOCK verdict."""
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "result = " + "e" + "val" + "('2+" + "2')\n",
                "filename": "bad.py",
                "verify_imports": False,
                "verify_docker": False,
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "BLOCK"

    def test_deep_scan_missing_code_returns_422(
        self, client: TestClient
    ) -> None:
        """Missing code field returns validation error."""
        response = client.post(
            "/v1/scan/deep",
            json={"filename": "test.py"},
            headers={"X-API-Key": "ct_pro_test"},
        )
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    @patch.object(RegistryService, "verify_packages", new_callable=AsyncMock)
    def test_deep_scan_with_imports(
        self, mock_verify: AsyncMock, client: TestClient
    ) -> None:
        """Deep scan includes import verification when requested."""
        mock_verify.return_value = [
            PackageResult(
                package="fastapi",
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                latest_version="0." + "115.0",
                message="Package exists on PyPI",
            ),
        ]
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "import fastapi\n",
                "filename": "app.py",
                "language": "python",
                "verify_imports": True,
                "verify_docker": False,
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["import_verification"] is not None
        assert data["import_verification"]["verified"] == 1

    @patch.object(DockerVerifyService, "verify_images", new_callable=AsyncMock)
    def test_deep_scan_with_docker(
        self, mock_verify: AsyncMock, client: TestClient
    ) -> None:
        """Deep scan includes Docker verification when requested."""
        mock_verify.return_value = [
            DockerImageResult(
                image="python",
                tag="3.12-slim",
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message="Image tag verified",
            ),
        ]
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "x = 1\n",
                "filename": "app.py",
                "verify_imports": False,
                "verify_docker": True,
                "dockerfile_content": "FROM python:3.12-slim\n",
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["docker_verification"] is not None
        assert data["docker_verification"]["verified"] == 1

    @patch.object(RegistryService, "verify_packages", new_callable=AsyncMock)
    def test_deep_scan_failed_import_blocks(
        self, mock_verify: AsyncMock, client: TestClient
    ) -> None:
        """Deep scan with failed imports returns BLOCK verdict."""
        mock_verify.return_value = [
            PackageResult(
                package="nonexistent",
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message="Package not found",
            ),
        ]
        response = client.post(
            "/v1/scan/deep",
            json={
                "code": "import nonexistent\n",
                "filename": "app.py",
                "language": "python",
                "verify_imports": True,
                "verify_docker": False,
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["overall_verdict"] == "BLOCK"
        assert data["import_verification"]["failed"] == 1


class TestTierAndRateLimits:
    """Tier enforcement and in-memory rate-limit behavior."""

    def test_unauthenticated_scan_works(self, client: TestClient) -> None:
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "a.py"},
        )
        assert response.status_code == 200
        assert "findings" in response.json()

    def test_free_tier_25th_scan_succeeds(self, client: TestClient) -> None:
        headers = {
            "X-CodeTrust-Installation-ID": "install-free-25",
            "X-Forwarded-For": "203.0.113.10",
        }
        for _ in range(25):
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1\n", "filename": "f.py"},
                headers=headers,
            )
        assert response.status_code == 200

    def test_free_tier_26th_scan_returns_429(self, client: TestClient) -> None:
        headers = {
            "X-CodeTrust-Installation-ID": "install-free-26",
            "X-Forwarded-For": "203.0.113.11",
        }
        for _ in range(25):
            client.post(
                "/v1/scan/static",
                json={"code": "x = 1\n", "filename": "f.py"},
                headers=headers,
            )
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "f.py"},
            headers=headers,
        )
        assert response.status_code == 429
        payload = response.json()
        assert payload["error"] == "daily_scan_limit_reached"
        assert payload["limit"] == 25
        assert payload["used"] == 26
        assert "pricing" in payload["upgrade_url"]

    def test_pro_user_unlimited_scans(self, client: TestClient) -> None:
        headers = {
            "X-API-Key": "ct_pro_unlimited",
            "X-CodeTrust-Installation-ID": "install-pro-1",
            "X-Forwarded-For": "203.0.113.12",
        }
        for _ in range(200):
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1\n", "filename": "pro.py"},
                headers=headers,
            )
            assert response.status_code == 200

    def test_429_includes_resets_at(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        day = date(2026, 3, 15)
        monkeypatch.setattr(api_module, "_utc_today", lambda: day)
        headers = {
            "X-CodeTrust-Installation-ID": "install-reset-header",
            "X-Forwarded-For": "203.0.113.13",
        }
        for _ in range(100):
            client.post(
                "/v1/scan/static",
                json={"code": "x = 1\n", "filename": "reset.py"},
                headers=headers,
            )
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "reset.py"},
            headers=headers,
        )
        assert response.status_code == 429
        assert response.json()["resets_at"] == "2026-03-16T00:00:00+00:00"

    def test_rate_limit_resets_next_day(self, client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        first_day = date(2026, 3, 15)
        second_day = first_day + timedelta(days=1)
        monkeypatch.setattr(api_module, "_utc_today", lambda: first_day)
        headers = {
            "X-CodeTrust-Installation-ID": "install-day-roll",
            "X-Forwarded-For": "203.0.113.14",
        }
        for _ in range(101):
            client.post(
                "/v1/scan/static",
                json={"code": "x = 1\n", "filename": "roll.py"},
                headers=headers,
            )

        monkeypatch.setattr(api_module, "_utc_today", lambda: second_day)
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "roll.py"},
            headers=headers,
        )
        assert response.status_code == 200

    def test_import_verification_free(self, client: TestClient) -> None:
        with patch.object(
            RegistryService,
            "verify_packages",
            new_callable=AsyncMock,
            return_value=[],
        ):
            response = client.post(
                "/v1/verify/imports",
                json={"language": "python", "imports": ["fastapi"]},
                headers={"X-Forwarded-For": "203.0.113.15"},
            )
        assert response.status_code == 200

    def test_vuln_scan_requires_pro(self, client: TestClient) -> None:
        response = client.post(
            "/v1/vuln/scan",
            json={"language": "python", "packages": ["fastapi"]},
            headers={"X-API-Key": "ct_free_user", "X-Forwarded-For": "203.0.113.16"},
        )
        assert response.status_code == 403
        assert response.json()["error"] == "upgrade_required"

    def test_license_scan_requires_pro(self, client: TestClient) -> None:
        response = client.post(
            "/v1/license/scan",
            json={"language": "python", "packages": ["fastapi"]},
            headers={"X-API-Key": "ct_free_user", "X-Forwarded-For": "203.0.113.17"},
        )
        assert response.status_code == 403
        assert response.json()["required_plan"] == "pro"

    def test_sbom_requires_pro(self, client: TestClient) -> None:
        """SBOM requires Pro plan — free gets 403."""
        response = client.post(
            "/v1/sbom/generate",
            json={"language": "python", "packages": ["fastapi"]},
        )
        assert response.status_code == 403
        assert response.json()["required_plan"] == "pro"

    @pytest.mark.parametrize(
        ("path", "payload", "required_plan"),
        [
            ("/v1/vuln/scan", {"packages": [{"name": "requests"}]}, "pro"),
            ("/v1/license/scan", {"packages": [{"name": "requests"}]}, "pro"),
            ("/v1/scan/cross-file", {"files": [{"filename": "a.py", "code": "import b"}]}, "pro"),
            ("/v1/sbom/generate", {"packages": [{"name": "requests"}]}, "pro"),
        ],
    )
    def test_paid_endpoints_gate_before_body_validation(
        self,
        client: TestClient,
        path: str,
        payload: dict[str, object],
        required_plan: str,
    ) -> None:
        """Free-tier callers should get plan gating before payload schema validation."""
        response = client.post(path, json=payload)
        assert response.status_code == 403
        assert response.json()["error"] == "upgrade_required"
        assert response.json()["required_plan"] == required_plan

    def test_fix_apply_requires_pro(self, client: TestClient) -> None:
        """Autofix requires Pro plan — free gets 403."""
        response = client.post(
            "/v1/fix/apply",
            json={"files": {"a.py": "x = 1\n"}},
        )
        assert response.status_code == 403
        assert response.json()["required_plan"] == "pro"

    def test_orgs_require_team(self, client: TestClient) -> None:
        """Org management requires Team plan — Pro gets 403."""
        response = client.post(
            "/v1/orgs",
            json={"name": "Acme"},
            headers={"X-API-Key": "ct_pro_user", "X-Forwarded-For": "203.0.113.20"},
        )
        assert response.status_code == 403
        assert response.json()["required_plan"] == "team"

    def test_version_check_never_blocks(self, client: TestClient) -> None:
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "v.py"},
            headers={
                "X-API-Key": "ct_free_user",
                "X-Client-Version": "2.5.0",
                "X-Forwarded-For": "203.0.113.21",
            },
        )
        assert response.status_code == 200
        assert response.headers.get("X-CodeTrust-Upgrade-Available") == "true"

    def test_upgrade_hints_in_free_scan(self, client: TestClient) -> None:
        response = client.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "hint.py"},
            headers={
                "X-CodeTrust-Installation-ID": "install-hints",
                "X-Forwarded-For": "203.0.113.22",
            },
        )
        assert response.status_code == 200
        hints = response.json().get("upgrade_hints", [])
        assert isinstance(hints, list)
        assert len(hints) > 0

    def test_free_static_strips_signature_findings(self, client: TestClient) -> None:
        signature_finding = Finding(
            rule_id="signature_hallucinated_function",
            severity=Severity.BLOCK,
            message="Unknown function",
            file="sample.py",
            line=1,
            suggestion="Use valid API",
        )
        with patch.object(
            StaticAnalyzer,
            "scan_code",
            return_value=[signature_finding],
        ), patch.object(
            StaticAnalyzer,
            "build_scan_response",
            return_value=StaticScanResponse(
                total_findings=1,
                blocks=1,
                warnings=0,
                infos=0,
                findings=[signature_finding],
                verdict="BLOCK",
            ),
        ):
            response = client.post(
                "/v1/scan/static",
                json={"code": "x = 1\n", "filename": "sig.py"},
                headers={
                    "X-CodeTrust-Installation-ID": "install-free-filter",
                    "X-Forwarded-For": "203.0.113.23",
                },
            )
        assert response.status_code == 200
        payload = response.json()
        assert payload["total_findings"] == 0
        assert payload["blocks"] == 0
        assert payload["verdict"] == "PASS"
        hints = payload.get("upgrade_hints", [])
        assert any("Signature validation" in hint for hint in hints)


class TestAdminBootstrap:
    """Admin bootstrap and adoption overview behavior."""

    def test_bootstrap_dashboard_api_key_requires_master(
        self, client: TestClient,
    ) -> None:
        original = settings.api_key
        settings.api_key = "master"
        db = MagicMock(spec=DatabaseService)
        key_record = MagicMock()
        key_record.user_id = "u2"
        key_record.id = "auth-key"
        db_user = MagicMock()
        db_user.plan = "pro"
        db.verify_api_key_hash = AsyncMock(return_value=key_record)
        db.get_user = AsyncMock(return_value=db_user)
        app.state.db = db
        try:
            response = client.post(
                "/v1/admin/dashboard/bootstrap-api-key",
                json={"user_id": "u1", "email": "user@example.com", "name": "User"},
                headers={"X-API-Key": "ct_live_non_master"},
            )
            assert response.status_code == 403
        finally:
            settings.api_key = original

    def test_bootstrap_dashboard_api_key_success(
        self, client: TestClient,
    ) -> None:
        original = settings.api_key
        settings.api_key = "master"

        db = MagicMock(spec=DatabaseService)
        db_user = MagicMock()
        db_user.id = "u1"
        db_user.plan = "pro"
        db.get_user = AsyncMock(return_value=db_user)
        record = MagicMock()
        record.id = "k1"
        record.prefix = "ct_live_abc12345"
        db.rotate_dashboard_api_key = AsyncMock(return_value=("ct_live_bootstrap", record))
        app.state.db = db

        try:
            response = client.post(
                "/v1/admin/dashboard/bootstrap-api-key",
                json={"user_id": "u1", "email": "user@example.com", "name": "User"},
                headers={"X-API-Key": "master"},
            )
            assert response.status_code == 200
            payload = response.json()
            assert payload["user_id"] == "u1"
            assert payload["plan"] == "pro"
            assert payload["api_key"] == "ct_live_bootstrap"
        finally:
            settings.api_key = original

    def test_admin_adoption_overview_returns_metrics(
        self, client: TestClient,
    ) -> None:
        original = settings.api_key
        settings.api_key = "master"

        db = MagicMock(spec=DatabaseService)
        db.get_adoption_overview = AsyncMock(
            return_value={
                "total_users": 5,
                "free_users": 3,
                "pro_users": 1,
                "enterprise_users": 1,
                "total_api_keys": 7,
                "active_api_keys": 6,
                "active_users_30d": 4,
                "total_scans_30d": 42,
            },
        )
        app.state.db = db

        try:
            response = client.get(
                "/v1/admin/adoption/overview",
                headers={"X-API-Key": "master"},
            )
            assert response.status_code == 200
            assert response.json()["total_users"] == 5
        finally:
            settings.api_key = original

    def test_telemetry_opt_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.telemetry_client import _telemetry_suppressed

        monkeypatch.setenv("CODETRUST_TELEMETRY", "0")
        assert _telemetry_suppressed() is True


# --- Taint Verified Scan ---


class TestTaintVerifiedScan:
    """Tests for POST /v1/scan/taint/verified."""

    def test_clean_code_returns_pass(self, client: TestClient) -> None:
        """Clean code with no taint flows returns PASS verdict."""
        response = client.post(
            "/v1/scan/taint/verified",
            json={
                "code": "x = 1\ny = 2\n",
                "filename": "clean.py",
                "language": "python",
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PASS"
        assert data["total"] == 0
        assert data["verified_count"] == 0

    def test_tainted_code_returns_findings(self, client: TestClient) -> None:
        """Code with taint flow from request to SQL returns findings."""
        code = (
            "def handler(request):\n"
            "    user_id = request.args.get('id')\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        )
        response = client.post(
            "/v1/scan/taint/verified",
            json={
                "code": code,
                "filename": "app.py",
                "language": "python",
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] > 0
        assert data["verdict"] in ("WARN", "BLOCK")
        assert len(data["taint_findings"]) > 0
        assert len(data["verified_findings"]) > 0

    def test_unsupported_language_returns_pass(self, client: TestClient) -> None:
        """Unsupported taint language returns PASS with no findings."""
        response = client.post(
            "/v1/scan/taint/verified",
            json={
                "code": "fn main() {}",
                "filename": "main.rs",
                "language": "rust",
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "PASS"
        assert data["total"] == 0

    def test_missing_code_returns_422(self, client: TestClient) -> None:
        """Missing code field returns validation error."""
        response = client.post(
            "/v1/scan/taint/verified",
            json={"filename": "test.py", "language": "python"},
            headers={"X-API-Key": "ct_pro_test"},
        )
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    def test_missing_language_returns_422(self, client: TestClient) -> None:
        """Missing language field returns validation error."""
        response = client.post(
            "/v1/scan/taint/verified",
            json={"code": "x = 1", "filename": "test.py"},
            headers={"X-API-Key": "ct_pro_test"},
        )
        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY

    @patch.object(
        RuntimeTaintVerifier, "verify_findings", new_callable=AsyncMock,
    )
    @patch.object(TaintAnalyzer, "analyze")
    def test_verified_finding_metadata(
        self,
        mock_taint: MagicMock,
        mock_verify: AsyncMock,
        client: TestClient,
    ) -> None:
        """Verified findings include exploit payload and method."""
        taint_finding = Finding(
            rule_id="taint_sql_injection",
            severity=Severity.BLOCK,
            message="SQL injection via user input",
            file="app.py",
            line=7,
            suggestion="Use parameterized queries",
            confidence=0.9,
        )
        mock_taint.return_value = [taint_finding]
        mock_verify.return_value = VerificationSummary(
            total=1,
            verified=1,
            unverified=0,
            sandbox_unavailable=False,
            results=[
                VerifiedFinding(
                    finding=taint_finding,
                    verified=True,
                    confidence=0.95,
                    exploit_payload="' OR 1=1 --",
                    verification_method=VerificationMethod.SANDBOX_EXPLOIT,
                ),
            ],
        )

        response = client.post(
            "/v1/scan/taint/verified",
            json={
                "code": "from flask import request\nx = request.args.get('id')\n",
                "filename": "app.py",
                "language": "python",
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["verdict"] == "BLOCK"
        assert data["verified_count"] == 1
        vf = data["verified_findings"][0]
        assert vf["verified"] is True
        assert vf["confidence"] == 0.95
        assert vf["exploit_payload"] == "' OR 1=1 --"
        assert vf["verification_method"] == "sandbox_exploit"

    @patch.object(
        RuntimeTaintVerifier, "verify_findings", new_callable=AsyncMock,
    )
    @patch.object(TaintAnalyzer, "analyze")
    def test_sandbox_unavailable_returns_unverified(
        self,
        mock_taint: MagicMock,
        mock_verify: AsyncMock,
        client: TestClient,
    ) -> None:
        """When sandbox is unavailable, findings are returned unverified."""
        taint_finding = Finding(
            rule_id="taint_xss",
            severity=Severity.WARN,
            message="XSS via user input",
            file="app.py",
            line=3,
            confidence=0.7,
        )
        mock_taint.return_value = [taint_finding]
        mock_verify.return_value = VerificationSummary(
            total=1,
            verified=0,
            unverified=1,
            sandbox_unavailable=True,
            results=[
                VerifiedFinding(
                    finding=taint_finding,
                    verified=False,
                    confidence=0.7,
                    exploit_payload="",
                    verification_method=VerificationMethod.SANDBOX_UNAVAILABLE,
                ),
            ],
        )

        response = client.post(
            "/v1/scan/taint/verified",
            json={
                "code": "from flask import request\nx = request.args.get('q')\n",
                "filename": "app.py",
                "language": "python",
            },
            headers={"X-API-Key": "ct_pro_test"},
        )

        assert response.status_code == 200
        data = response.json()
        assert data["sandbox_unavailable"] is True
        assert data["verified_count"] == 0
        assert data["unverified_count"] == 1
