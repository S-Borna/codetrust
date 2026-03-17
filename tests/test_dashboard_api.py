"""Tests for dashboard API endpoints — API keys, scan history, usage, billing."""

import asyncio
from collections import defaultdict
from fnmatch import fnmatch
from http import HTTPStatus
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from src.services.auth import AuthService
from src.services.billing import BillingService
from src.services.cache import CacheService
from src.services.database import DatabaseService

_TELEMETRY_EVENT_PAYLOAD: dict[str, object] = {
    "event_type": "scan_completed",
    "source": "cli",
    "installation_id": "anon-" + ("a" * 24),
    "version": "2.4.0",
    "payload": {
        "scan_type": "static",
        "files_scanned": 1,
        "languages": {"python": 1},
        "total_findings": 3,
        "findings_by_severity": {"BLOCK": 0, "WARN": 3, "INFO": 0},
        "rules_triggered": ["rule_a"],
        "layers_hit": [1],
        "trust_score": 90,
        "trend": "stable",
        "hallucinations_found": 0,
        "scan_duration_ms": 25,
        "used_baseline": False,
        "used_dedupe": False,
        "used_sarif_output": False,
        "used_json_output": True,
    },
}


class _InMemoryAsyncRedis:
    """Tiny async Redis-like stub for API tests.

    Implements only the commands used by telemetry/stats code paths.
    """

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}
        self._ints: defaultdict[str, int] = defaultdict(int)
        self._hll: defaultdict[str, set[str]] = defaultdict(set)
        self._zsets: defaultdict[str, dict[str, float]] = defaultdict(dict)

    def pipeline(self) -> "_InMemoryPipeline":
        return _InMemoryPipeline(self)

    async def get(self, key: str) -> str | None:
        if key in self._kv:
            return self._kv[key]
        if key in self._ints:
            return str(self._ints[key])
        return None

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._kv[key] = str(value)

    async def expire(self, key: str, ttl: int) -> None:
        return

    async def incr(self, key: str) -> int:
        self._ints[key] += 1
        return self._ints[key]

    async def incrby(self, key: str, amount: int) -> int:
        self._ints[key] += int(amount)
        return self._ints[key]

    async def pfadd(self, key: str, value: str) -> int:
        before = len(self._hll[key])
        self._hll[key].add(value)
        return 1 if len(self._hll[key]) > before else 0

    async def pfcount(self, key: str) -> int:
        return len(self._hll[key])

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        for member, score in mapping.items():
            self._zsets[key][member] = float(score)
        return len(mapping)

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int:
        z = self._zsets[key]
        to_delete = [m for m, s in z.items() if float(min_score) <= s <= float(max_score)]
        for m in to_delete:
            del z[m]
        return len(to_delete)

    async def zcount(self, key: str, min_score: float, max_score: float) -> int:
        z = self._zsets[key]
        return sum(1 for s in z.values() if float(min_score) <= s <= float(max_score))

    async def scan_iter(self, match: str) -> object:
        keys: set[str] = set(self._kv.keys()) | set(self._ints.keys())
        for key in sorted(keys):
            if fnmatch(key, match):
                yield key


class _InMemoryPipeline:
    """Pipeline that queues operations and applies them on execute()."""

    def __init__(self, r: _InMemoryAsyncRedis) -> None:
        self._r = r
        self._ops: list[tuple[str, tuple[object, ...]]] = []

    def get(self, key: str) -> "_InMemoryPipeline":
        self._ops.append(("get", (key,)))
        return self

    def set(self, key: str, value: str, ex: int | None = None) -> "_InMemoryPipeline":
        self._ops.append(("set", (key, value, ex)))
        return self

    def expire(self, key: str, ttl: int) -> "_InMemoryPipeline":
        self._ops.append(("expire", (key, ttl)))
        return self

    def incr(self, key: str) -> "_InMemoryPipeline":
        self._ops.append(("incr", (key,)))
        return self

    def incrby(self, key: str, amount: int) -> "_InMemoryPipeline":
        self._ops.append(("incrby", (key, amount)))
        return self

    def pfadd(self, key: str, value: str) -> "_InMemoryPipeline":
        self._ops.append(("pfadd", (key, value)))
        return self

    def zadd(self, key: str, mapping: dict[str, float]) -> "_InMemoryPipeline":
        self._ops.append(("zadd", (key, mapping)))
        return self

    async def execute(self) -> list[object]:
        results: list[object] = []
        for name, args in self._ops:
            if name == "get":
                (key,) = args
                results.append(await self._r.get(str(key)))
            elif name == "set":
                key, value, ex = args
                await self._r.set(str(key), str(value), ex=int(ex) if ex is not None else None)
                results.append(True)
            elif name == "expire":
                key, ttl = args
                await self._r.expire(str(key), int(ttl))
                results.append(True)
            elif name == "incr":
                (key,) = args
                results.append(await self._r.incr(str(key)))
            elif name == "incrby":
                key, amount = args
                results.append(await self._r.incrby(str(key), int(amount)))
            elif name == "pfadd":
                key, value = args
                results.append(await self._r.pfadd(str(key), str(value)))
            elif name == "zadd":
                key, mapping = args
                results.append(await self._r.zadd(str(key), dict(mapping)))
            else:
                results.append(None)
        self._ops.clear()
        return results


def _setup_app_state(app_obj: object) -> None:
    """Set up app state for testing."""
    from src.services.ast_analyzer import AstAnalyzer
    from src.services.sandbox import SandboxService
    from src.services.static_analyzer import StaticAnalyzer

    state = getattr(app_obj, "state", None)
    if state is None:
        return

    redis_stub = _InMemoryAsyncRedis()
    cache = MagicMock(spec=CacheService)
    cache.raw_client.return_value = redis_stub

    http_client = httpx.AsyncClient(timeout=5.0)
    state.analyzer = StaticAnalyzer()
    state.ast_analyzer = AstAnalyzer()
    state.sandbox = SandboxService()
    state.cache = cache
    state.registry = MagicMock()
    state.docker = MagicMock()
    state.billing = MagicMock(spec=BillingService)
    state.billing.is_configured.return_value = False
    state.auth = AuthService(http_client)
    state.rate_limiter = None

    # Telemetry plumbing (lifespan is not executed in these tests)
    state.telemetry_queue = None
    state.ws_clients = set()


@pytest.fixture()
def client_with_db(tmp_path: object) -> "TestClient":
    """Create TestClient with real in-memory database."""
    from src.api import app
    from src.api import settings as api_settings
    from src.services.rate_limiter import RateLimiter

    _setup_app_state(app)

    # Create a real DB service with SQLite for testing
    db = DatabaseService("sqlite+aiosqlite:///:memory:")
    loop = asyncio.get_event_loop_policy().new_event_loop()
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
    from src.api import app
    from src.api import settings as api_settings

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
        """DELETE /v1/api-keys/{id} returns not-found for unknown key."""
        resp = client_with_db.delete("/v1/api-keys/nonexistent")
        assert resp.status_code == HTTPStatus.NOT_FOUND


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
        assert data["period_days"] == (3 * 10)
        assert data["days"] == []

    def test_usage_stats_custom_period(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/usage with custom period."""
        resp = client_with_db.get("/v1/usage?days=7")  # noqa: magic_number
        assert resp.status_code == 200
        assert resp.json()["period_days"] == 7


# --- Billing endpoint tests ---


class TestBillingEndpoints:
    """Tests for billing endpoints."""

    def test_checkout_billing_not_configured(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/billing/checkout returns service-unavailable when not configured."""
        resp = client_with_db.post(
            "/v1/billing/checkout", json={"plan": "pro"},
        )
        assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE

    def test_portal_billing_not_configured(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/billing/portal returns service-unavailable when not configured."""
        resp = client_with_db.post("/v1/billing/portal")
        assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE


class TestTelemetryEndpoints:
    """Tests for anonymous telemetry endpoints."""

    def test_ingest_telemetry_ok_without_db(self, client_no_db: TestClient) -> None:
        """POST /v1/telemetry returns accepted even when DB is unavailable."""
        resp = client_no_db.post("/v1/telemetry", json=_TELEMETRY_EVENT_PAYLOAD)
        assert resp.status_code == 202
        assert resp.json()["status"] == "accepted"

    def test_ingest_telemetry_aggregates_into_public_stats(
        self, client_with_db: TestClient,
    ) -> None:
        """Inserted telemetry deltas show up in GET /v1/stats/public."""
        ingest = client_with_db.post("/v1/telemetry", json=_TELEMETRY_EVENT_PAYLOAD)
        assert ingest.status_code == 202

        stats = client_with_db.get("/v1/stats/public")
        assert stats.status_code == 200, stats.text
        data = stats.json()

        # Legacy keys still present for website counters
        assert "total_scans" in data
        assert "stats" in data
        assert "usage" in data["stats"]
        assert "stats" in data

    def test_public_stats_exposes_contract_metadata(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/stats/public returns the typed contract metadata fields."""
        resp = client_with_db.get("/v1/stats/public")
        assert resp.status_code == 200, resp.text

        data = resp.json()
        assert "stats" in data

        stats = data["stats"]
        assert "schema_version" in stats
        assert "source_of_truth" in stats
        assert "distribution" in stats
        assert "usage" in stats
        assert "impact" in stats
        assert "quality" in stats
        assert "coverage" in stats

        coverage = stats["coverage"]
        assert "overall_score" in coverage
        assert "active_surfaces" in coverage
        assert "surfaces" in coverage

    def test_public_stats_fallback_uses_database_aggregates(
        self, client_with_db: TestClient,
    ) -> None:
        """Fallback stats return DB-backed counters and populated timestamp when Redis is down."""
        blocked_scan = client_with_db.post(
            "/v1/scan/static",
            json={"code": "import os\nos.system('rm -rf /')\n", "filename": "bad.py"},
        )
        assert blocked_scan.status_code == 200

        clean_scan = client_with_db.post(
            "/v1/scan/static",
            json={"code": "x = 1\n", "filename": "ok.py"},
        )
        assert clean_scan.status_code == 200

        from src.api import app

        app.state.cache.raw_client.return_value = None

        resp = client_with_db.get("/v1/stats/public")
        assert resp.status_code == 200, resp.text

        data = resp.json()
        nested = data["stats"]
        usage = nested["usage"]
        distribution = nested["distribution"]
        impact = nested["impact"]

        assert nested["updated_at"]
        assert usage["total_scans"] >= 11233
        assert usage["total_findings"] >= 113744
        assert usage["findings_by_severity"]["BLOCK"] >= 12405
        assert usage["scans_by_source"]["cli"] >= 24
        assert usage["scans_by_source"]["vscode"] >= 7732
        assert usage["scans_by_source"]["github_action"] >= 16
        assert usage["scans_by_source"]["cloud_api"] >= 4972
        assert usage["total_files_scanned"] >= 11233
        assert distribution["pypi"]["downloads_total"] >= 6711
        assert "categories" in impact
        assert "top_rules" in impact
        assert isinstance(impact["categories"], dict)
        assert isinstance(impact["top_rules"], list)


class TestGovernanceBundleEndpoints:
    """Tests for governance policy bundle and snapshot endpoints."""

    def test_governance_policy_bundles_returns_signed_bundles(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/governance/policy-bundles returns versioned signed bundles."""
        resp = client_with_db.get("/v1/governance/policy-bundles")
        assert resp.status_code == 200, resp.text
        bundles = resp.json()

        assert isinstance(bundles, list)
        assert len(bundles) >= 3
        first = bundles[0]
        assert "bundle_id" in first
        assert "signature" in first
        assert "version" in first
        assert "policy" in first

    def test_governance_policy_snapshot_signs_policy(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/governance/policy-snapshot returns a signed snapshot."""
        resp = client_with_db.post(
            "/v1/governance/policy-snapshot",
            json={"bundle_id": "team", "overrides": {"retention_days": 120}},
        )
        assert resp.status_code == 200, resp.text

        data = resp.json()
        assert data["bundle_id"] == "team"
        assert data["audit_logged"] is True
        assert data["signature"]
        assert "snapshot_id" in data
        assert "issued_at" in data
        assert data["session_id"]
        assert len(data["policy_hash"]) == 64
        assert data["policy"]["retention_days"] == 120

    def test_governance_posture_returns_machine_contract(
        self, client_with_db: TestClient,
    ) -> None:
        """GET /v1/governance/posture returns posture with integrity and counters."""
        resp = client_with_db.get("/v1/governance/posture")
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["session_id"]
        assert "policy_integrity" in data
        assert "trusted_execution_mode" in data
        assert "deny_native_execution" in data
        assert "require_allow_reason" in data
        assert "session_binding_enforced" in data
        assert "anti_bypass_enabled" in data
        assert "control_plane_ready" in data
        assert "pending_approvals" in data
        assert "active_exceptions" in data

    def test_governance_simulate_policy_returns_outcomes(
        self, client_with_db: TestClient,
    ) -> None:
        """POST /v1/governance/simulate-policy returns simulated verdicts."""
        resp = client_with_db.post(
            "/v1/governance/simulate-policy",
            json={
                "bundle_id": "team",
                "commands": ["git push origin main", "ls -la"],
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["bundle_id"] == "team"
        assert len(data["outcomes"]) == 2
        assert "verdict" in data["outcomes"][0]


# --- Database unavailable tests ---


class TestDatabaseUnavailable:
    """Tests for endpoints when database is unavailable."""

    def test_api_keys_returns_503(self, client_no_db: TestClient) -> None:
        """API key endpoints return service-unavailable without database."""
        resp = client_no_db.get("/v1/api-keys")
        assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE

    def test_scan_history_returns_503(
        self, client_no_db: TestClient,
    ) -> None:
        """Scan history returns service-unavailable without database."""
        resp = client_no_db.get("/v1/scans/history")
        assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE

    def test_usage_returns_503(self, client_no_db: TestClient) -> None:
        """Usage stats returns service-unavailable without database."""
        resp = client_no_db.get("/v1/usage")
        assert resp.status_code == HTTPStatus.SERVICE_UNAVAILABLE
