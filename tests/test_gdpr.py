"""Tests for GDPR data export and deletion service."""

from __future__ import annotations

import json

import pytest

from src.services.gdpr import GDPRService

# ---------------------------------------------------------------------------
# Fixtures — uses the same async DB from conftest
# ---------------------------------------------------------------------------

@pytest.fixture
async def db_service():
    """Create an in-memory DatabaseService with tables."""
    from src.services.database import DatabaseService

    db = DatabaseService("sqlite+aiosqlite:///:memory:")
    await db.create_tables()
    yield db
    await db.close()


@pytest.fixture
def gdpr_service(db_service) -> GDPRService:
    return GDPRService(db_service)


@pytest.fixture
async def sample_user(db_service):
    """Create a sample user with related data."""
    user = await db_service.create_user(
        github_id="gh-12345",
        email="test@example.com",
        name="Test User",
        avatar_url="https://avatar.example.com/test.png",
    )
    # Create API key
    await db_service.create_api_key(user.id, "Test Key")
    # Create scan log
    await db_service.log_scan(
        user_id=user.id,
        scan_type="static",
        verdict="PASS",
        findings_count=3,
        latency_ms=42,
        language="python",
        filename="main.py",
    )
    # Create usage day
    await db_service.increment_daily_usage(user.id, 3, 42)
    return user


# ---------------------------------------------------------------------------
# Export tests
# ---------------------------------------------------------------------------

class TestExportUserData:
    @pytest.mark.asyncio
    async def test_export_full_user(self, gdpr_service, sample_user) -> None:
        data = await gdpr_service.export_user_data(sample_user.id)

        assert data["export_metadata"]["user_id"] == sample_user.id
        assert data["export_metadata"]["format_version"] == "1.0"
        assert "Art. 15" in data["export_metadata"]["gdpr_articles"][0]

        assert data["profile"]["email"] == "test@example.com"
        assert data["profile"]["name"] == "Test User"
        assert data["profile"]["github_id"] == "gh-12345"
        assert data["profile"]["plan"] == "free"

        assert len(data["api_keys"]) == 1
        assert data["api_keys"][0]["name"] == "Test Key"
        assert data["api_keys"][0]["is_revoked"] is False

        assert len(data["scan_history"]) == 1
        assert data["scan_history"][0]["scan_type"] == "static"
        assert data["scan_history"][0]["verdict"] == "PASS"
        assert data["scan_history"][0]["findings_count"] == 3

        assert len(data["usage_statistics"]) == 1
        assert data["usage_statistics"][0]["scan_count"] == 1

        assert "content_data" in data["data_categories"]

    @pytest.mark.asyncio
    async def test_export_nonexistent_user(self, gdpr_service) -> None:
        data = await gdpr_service.export_user_data("nonexistent")
        assert data == {}

    @pytest.mark.asyncio
    async def test_export_user_no_data(self, gdpr_service, db_service) -> None:
        user = await db_service.create_user(github_id="gh-empty", email="e@e.com")
        data = await gdpr_service.export_user_data(user.id)

        assert data["profile"]["email"] == "e@e.com"
        assert len(data["api_keys"]) == 0
        assert len(data["scan_history"]) == 0
        assert len(data["usage_statistics"]) == 0

    @pytest.mark.asyncio
    async def test_export_is_json_serializable(self, gdpr_service, sample_user) -> None:
        data = await gdpr_service.export_user_data(sample_user.id)
        # Must not raise
        json_str = json.dumps(data, default=str)
        assert len(json_str) > 100

    @pytest.mark.asyncio
    async def test_export_contains_timestamps(self, gdpr_service, sample_user) -> None:
        data = await gdpr_service.export_user_data(sample_user.id)
        assert data["export_metadata"]["exported_at"] is not None
        assert data["profile"]["created_at"] is not None


# ---------------------------------------------------------------------------
# Deletion tests
# ---------------------------------------------------------------------------

class TestDeleteUserData:
    @pytest.mark.asyncio
    async def test_delete_full_user(self, gdpr_service, sample_user, db_service) -> None:
        result = await gdpr_service.delete_user_data(sample_user.id)

        assert result["deleted"] is True
        assert result["user_id"] == sample_user.id
        assert result["records_deleted"]["api_keys"] == 1
        assert result["records_deleted"]["scan_logs"] == 1
        assert result["records_deleted"]["usage_days"] == 1
        assert "Art. 17" in result["gdpr_article"]

        # Verify data is gone
        user = await db_service.get_user(sample_user.id)
        assert user is None

        keys = await db_service.list_api_keys(sample_user.id)
        assert len(keys) == 0

        scans = await db_service.get_scan_history(sample_user.id)
        assert len(scans) == 0

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user(self, gdpr_service) -> None:
        result = await gdpr_service.delete_user_data("nonexistent")
        assert result["deleted"] is False
        assert result["reason"] == "user_not_found"

    @pytest.mark.asyncio
    async def test_delete_user_no_data(self, gdpr_service, db_service) -> None:
        user = await db_service.create_user(github_id="gh-empty2")
        result = await gdpr_service.delete_user_data(user.id)

        assert result["deleted"] is True
        assert result["records_deleted"]["api_keys"] == 0
        assert result["records_deleted"]["scan_logs"] == 0
        assert result["records_deleted"]["usage_days"] == 0

    @pytest.mark.asyncio
    async def test_delete_then_export_empty(self, gdpr_service, sample_user) -> None:
        await gdpr_service.delete_user_data(sample_user.id)
        data = await gdpr_service.export_user_data(sample_user.id)
        assert data == {}

    @pytest.mark.asyncio
    async def test_delete_has_timestamp(self, gdpr_service, sample_user) -> None:
        result = await gdpr_service.delete_user_data(sample_user.id)
        assert "deleted_at" in result


# ---------------------------------------------------------------------------
# Audit anonymization tests
# ---------------------------------------------------------------------------

class TestAnonymizeAudit:
    @pytest.mark.asyncio
    async def test_anonymize_entries(self, gdpr_service, tmp_path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        entries = [
            json.dumps({"agent_id": "user-1", "action": "scan", "verdict": "PASS"}),
            json.dumps({"agent_id": "user-2", "action": "scan", "verdict": "WARN"}),
            json.dumps({"agent_id": "user-1", "action": "deep", "verdict": "BLOCK"}),
        ]
        audit_file.write_text("\n".join(entries) + "\n")

        count = await gdpr_service.anonymize_audit_entries(
            "user-1", str(audit_file),
        )

        assert count == 2
        lines = [json.loads(line) for line in audit_file.read_text().strip().split("\n")]
        assert lines[0]["agent_id"] == "REDACTED"
        assert lines[1]["agent_id"] == "user-2"
        assert lines[2]["agent_id"] == "REDACTED"

    @pytest.mark.asyncio
    async def test_anonymize_no_file(self, gdpr_service) -> None:
        count = await gdpr_service.anonymize_audit_entries(
            "user-1", "/nonexistent/audit.jsonl",
        )
        assert count == 0

    @pytest.mark.asyncio
    async def test_anonymize_empty_file(self, gdpr_service, tmp_path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        audit_file.write_text("")
        count = await gdpr_service.anonymize_audit_entries(
            "user-1", str(audit_file),
        )
        assert count == 0

    @pytest.mark.asyncio
    async def test_anonymize_user_id_field(self, gdpr_service, tmp_path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        entry = json.dumps({"user_id": "user-x", "agent_id": "user-x", "data": "ok"})
        audit_file.write_text(entry + "\n")

        count = await gdpr_service.anonymize_audit_entries(
            "user-x", str(audit_file),
        )
        assert count == 1
        line = json.loads(audit_file.read_text().strip())
        assert line["user_id"] == "REDACTED"
        assert line["agent_id"] == "REDACTED"
        assert line["data"] == "ok"

    @pytest.mark.asyncio
    async def test_anonymize_malformed_json(self, gdpr_service, tmp_path) -> None:
        audit_file = tmp_path / "audit.jsonl"
        audit_file.write_text("not-json\n")
        count = await gdpr_service.anonymize_audit_entries(
            "user-1", str(audit_file),
        )
        assert count == 0
