"""Tests for dashboard API endpoints — API keys, scan history, usage, billing."""

from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.database import DatabaseService


_TELEMETRY_EVENT_PAYLOAD: dict[str, object] = {
    "instance_id": "a" * 32,
    "client": "cli",
    "client_version": "2.3.2",
    "schema_version": 1,
    "event_type": "scan_completed",
    "scan_type": "static",
    "verdict": "PASS",
    "language": "python",
    "delta_scans": 1,
    "delta_findings_total": 3,
    "delta_hallucinated_packages_prevented": 0,
    "delta_destructive_commands_blocked": 0,
}


def _setup_app_state(app_obj: object) -> None:
    """Set up app state for testing."""
    from src.services.ast_analyzer import AstAnalyzer
    from src.services.cache import CacheService
    from src.services.sandbox import SandboxService
    from src.services.static_analyzer import StaticAnalyzer

    state = getattr(app_obj, "state", None)
    if state is None:
        return

    http_client = httpx.AsyncClient(timeout=5.0)
    state.analyzer = StaticAnalyzer()
    state.ast_analyzer = AstAnalyzer()
    state.sandbox = SandboxService()
    state.cache = MagicMock(spec=CacheService)
    state.cache.is_connected = AsyncMock(return_value=False)
    state.registry = MagicMock()
    state.docker = MagicMock()
    state.billing = MagicMock(spec=BillingService)
    state.billing.is_configured.return_value = False
    state.auth = AuthService(http_client)
    state.rate_limiter = None


@pytest.fixture()
def client_with_db(tmp_path: object) -> "TestClient":
    """Create TestClient with real in-memory database."""
    import asyncio

    from src.api import app, settings as api_settings
    from src.services.rate_limiter import RateLimiter

    _setup_app_state(app)

    # Create a real DB service with SQLite for testing
    db = DatabaseService("sqlite+aiosqlite:///:memory:")
    loop = asyncio.new_event_loop()
    loop.run_until_complete(db.create_tables())
    loop.close()
    app.state.db = db
    app.state.rate_limiter = RateLimiter(db)

    original_api_key = api_settings.api_key
    original_version = api_settings.version
    original_jwt_secret = api_settings.jwt_secret
    original_jwt_algorithm = api_settings.jwt_algorithm

    api_settings.api_key = ""
    api_settings.version = "1.0.0-test"
    api_settings.jwt_secret = ""
    api_settings.jwt_algorithm = "HS256"

    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield client
    finally:
        client.close()
        api_settings.api_key = original_api_key
        api_settings.version = original_version
        api_settings.jwt_secret = original_jwt_secret
        api_settings.jwt_algorithm = original_jwt_algorithm


@pytest.fixture()
def client_no_db() -> "TestClient":
    """Create TestClient with no database available."""
    from src.api import app, settings as api_settings

    _setup_app_state(app)
    app.state.db = None
    app.state.rate_limiter = None

    original_api_key = api_settings.api_key
    original_version = api_settings.version
    original_jwt_secret = api_settings.jwt_secret
    original_jwt_algorithm = api_settings.jwt_algorithm

    api_settings.api_key = ""
    api_settings.version = "1.0.0-test"
    api_settings.jwt_secret = ""
    api_settings.jwt_algorithm = "HS256"

    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield client
    finally:
        client.close()
        api_settings.api_key = original_api_key
        api_settings.version = original_version
        api_settings.jwt_secret = original_jwt_secret
        api_settings.jwt_algorithm = original_jwt_algorithm


# --- API Key endpoint tests ---


class TestApiKeyEndpoints:
    """Tests for API key management endpoints."""

    def test_create_api_key(self, client_with_db: TestClient) -> None:
        """POST /v1/api-keys creates a new key."""
        resp = client_with_db.post(
            "/v1/api-keys", json={"name": "CI Server"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["key"].startswith("ct_live_")
        assert data["name"] == "CI Server"
        assert data["prefix"]
        assert data["id"]

    def test_create_api_key_default_name(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/api-keys uses 'Default' when no name given."""
        resp = client_with_db.post("/v1/api-keys", json={})
        assert resp.status_code == 200
        assert resp.json()["name"] == "Default"

    def test_list_api_keys_empty(self, client_with_db: TestClient) -> None:
        """GET /v1/api-keys returns empty list initially."""
        resp = client_with_db.get("/v1/api-keys")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_api_keys_after_create(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/api-keys returns created keys."""
        client_with_db.post("/v1/api-keys", json={"name": "Key 1"})
        client_with_db.post("/v1/api-keys", json={"name": "Key 2"})

        resp = client_with_db.get("/v1/api-keys")
        assert resp.status_code == 200
        keys = resp.json()
        assert len(keys) == 2

    def test_revoke_api_key_success(
        self, client_with_db: TestClient,
    ) -> None:
        """DELETE /v1/api-keys/{id} revokes a key."""
        create_resp = client_with_db.post(
            "/v1/api-keys", json={"name": "Temp"},
        )
        key_id = create_resp.json()["id"]

        resp = client_with_db.delete(f"/v1/api-keys/{key_id}")
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True

    def test_revoke_api_key_not_found(
        self, client_with_db: TestClient,
    ) -> None:
        """DELETE /v1/api-keys/{id} returns 404 for unknown key."""
        resp = client_with_db.delete("/v1/api-keys/nonexistent")
        assert resp.status_code == 404


# --- Scan history endpoint tests ---


class TestScanHistoryEndpoints:
    """Tests for scan history endpoints."""

    def test_scan_history_empty(self, client_with_db: TestClient) -> None:
        """GET /v1/scans/history returns empty list initially."""
        resp = client_with_db.get("/v1/scans/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["scans"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    def test_scan_history_with_pagination(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/scans/history supports pagination."""
        resp = client_with_db.get(
            "/v1/scans/history?page=1&per_page=10",
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["per_page"] == 10


# --- Usage endpoint tests ---


class TestUsageEndpoints:
    """Tests for usage stats endpoints."""

    def test_usage_stats_empty(self, client_with_db: TestClient) -> None:
        """GET /v1/usage returns empty stats initially."""
        resp = client_with_db.get("/v1/usage")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_scans"] == 0
        assert data["period_days"] == 30
        assert data["days"] == []

    def test_usage_stats_custom_period(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/usage?days=7 uses custom period."""
        resp = client_with_db.get("/v1/usage?days=7")
        assert resp.status_code == 200
        assert resp.json()["period_days"] == 7


# --- Billing endpoint tests ---


class TestBillingEndpoints:
    """Tests for billing endpoints."""

    def test_checkout_billing_not_configured(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/billing/checkout returns 503 when not configured."""
        resp = client_with_db.post(
            "/v1/billing/checkout", json={"plan": "pro"},
        )
        assert resp.status_code == 503

    def test_portal_billing_not_configured(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/billing/portal returns 503 when not configured."""
        resp = client_with_db.post("/v1/billing/portal")
        assert resp.status_code == 503


class TestTelemetryEndpoints:
    """Tests for anonymous telemetry endpoints."""

    def test_ingest_telemetry_ok_without_db(self, client_no_db: TestClient) -> None:
        """POST /v1/telemetry returns 200 even when DB is unavailable."""
        resp = client_no_db.post("/v1/telemetry", json=_TELEMETRY_EVENT_PAYLOAD)
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_ingest_telemetry_aggregates_into_public_stats(
        self, client_with_db: TestClient,
    ) -> None:
        """Inserted telemetry deltas show up in GET /v1/stats/public."""
        ingest = client_with_db.post("/v1/telemetry", json=_TELEMETRY_EVENT_PAYLOAD)
        assert ingest.status_code == 200

        stats = client_with_db.get("/v1/stats/public")
        assert stats.status_code == 200
        data = stats.json()

        assert data["telemetry_events_total"] == 1
        assert data["telemetry_unique_instances"] == 1
        assert data["telemetry_scans_total"] == 1
        assert data["telemetry_findings_total"] == 3


# --- Database unavailable tests ---


class TestDatabaseUnavailable:
    """Tests for endpoints when database is unavailable."""

    def test_api_keys_returns_503(self, client_no_db: TestClient) -> None:
        """API key endpoints return 503 without database."""
        resp = client_no_db.get("/v1/api-keys")
        assert resp.status_code == 503

    def test_scan_history_returns_503(
        self, client_no_db: TestClient,
    ) -> None:
        """Scan history returns 503 without database."""
        resp = client_no_db.get("/v1/scans/history")
        assert resp.status_code == 503

    def test_usage_returns_503(self, client_no_db: TestClient) -> None:
        """Usage stats returns 503 without database."""
        resp = client_no_db.get("/v1/usage")
        assert resp.status_code == 503
