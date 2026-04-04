# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for Real-time Governance Dashboard API endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from fastapi.testclient import TestClient


@pytest.fixture()
def _setup_app_state() -> None:
    """Minimal app state for dashboard endpoints."""
    from src.config import settings

    original_api_key = settings.api_key
    settings.api_key = ""
    yield
    settings.api_key = original_api_key


@pytest.fixture()
def client(_setup_app_state: None) -> TestClient:
    """Create test client."""
    from fastapi.testclient import TestClient as FastAPITestClient
    from src.api import app
    return FastAPITestClient(app, raise_server_exceptions=False)


class TestOverviewEndpoint:
    """Test GET /v1/dashboard/overview."""

    def test_returns_all_six_sections(self, client: TestClient) -> None:
        response = client.get("/v1/dashboard/overview")
        assert response.status_code == 200
        data = response.json()
        for section in ("enforcement", "compliance", "pii", "classification", "cost", "integrity"):
            assert section in data, f"Missing section: {section}"

    def test_enforcement_structure(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/overview").json()
        enf = data["enforcement"]
        assert "layers_active" in enf
        assert "total_blocks_24h" in enf
        assert "total_warns_24h" in enf
        assert isinstance(enf["top_blocked_rules"], list)

    def test_compliance_all_frameworks(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/overview").json()
        comp = data["compliance"]
        for fw in ("owasp_asi", "eu_ai_act", "nist_rmf"):
            assert fw in comp
            assert "status" in comp[fw]
            assert "full" in comp[fw]
            assert "total" in comp[fw]

    def test_pii_structure(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/overview").json()
        pii = data["pii"]
        assert "scans_24h" in pii
        assert "blocks_24h" in pii

    def test_cost_structure(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/overview").json()
        cost = data["cost"]
        assert "current_month_usd" in cost
        assert "budget_pct" in cost
        assert "top_developer" in cost
        assert "anomalies_24h" in cost

    def test_integrity_structure(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/overview").json()
        integrity = data["integrity"]
        for key in ("sessions_analyzed", "trustworthy", "questionable", "unreliable"):
            assert key in integrity


class TestTimelineEndpoint:
    """Test GET /v1/dashboard/timeline."""

    def test_returns_events_list(self, client: TestClient) -> None:
        response = client.get("/v1/dashboard/timeline?hours=24")
        assert response.status_code == 200
        data = response.json()
        assert "event_count" in data
        assert isinstance(data["events"], list)

    def test_hours_parameter(self, client: TestClient) -> None:
        response = client.get("/v1/dashboard/timeline?hours=1")
        assert response.status_code == 200

    def test_default_24_hours(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/timeline").json()
        assert data["hours"] == 24


class TestAlertsEndpoint:
    """Test GET /v1/dashboard/alerts."""

    def test_returns_alerts_list(self, client: TestClient) -> None:
        response = client.get("/v1/dashboard/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "alert_count" in data
        assert isinstance(data["alerts"], list)

    def test_alert_structure(self, client: TestClient) -> None:
        data = client.get("/v1/dashboard/alerts").json()
        for alert in data["alerts"]:
            assert "type" in alert
            assert "severity" in alert
            assert "message" in alert


class TestAuthRequired:
    """Test that auth is required when API key is set."""

    def test_overview_requires_auth(self) -> None:
        from src.config import settings
        original = settings.api_key
        settings.api_key = "test-secret-key-12345678"

        from fastapi.testclient import TestClient as FastAPITestClient
        from src.api import app
        tc = FastAPITestClient(app, raise_server_exceptions=False)
        response = tc.get("/v1/dashboard/overview")
        assert response.status_code in (401, 403)

        settings.api_key = original
