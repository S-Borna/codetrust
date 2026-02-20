# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the license guard module (src/services/license_guard.py)."""

from __future__ import annotations

import datetime
import json
from pathlib import Path

import httpx
import pytest

from src.services.license_guard import (
    LICENSE_CHECK_INTERVAL_SECONDS,
    LICENSE_OFFLINE_GRACE_DAYS,
    UNLICENSED_MAX_GATEWAY_RULES,
    UNLICENSED_MAX_RULES,
    LicenseStatus,
    MachineFingerprint,
    _get_client_version,
    _handle_offline_validation,
    _is_within_grace_period,
    _load_cached_status,
    _needs_revalidation,
    _save_cached_status,
    _validate_with_server,
    compute_fingerprint,
    enforce_gateway_rule_limit,
    enforce_rule_limit,
    periodic_license_check,
    validate_license,
    validate_license_sync,
)

# ------------------------------------------------------------------
# _get_client_version
# ------------------------------------------------------------------


class TestGetClientVersion:
    """Tests for _get_client_version."""

    def test_returns_version_string(self) -> None:
        v = _get_client_version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_returns_fallback_on_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.services.license_guard._pkg_version",
            lambda _name: (_ for _ in ()).throw(Exception("boom")),
        )
        assert _get_client_version() == "0.0.0"


# ------------------------------------------------------------------
# Machine ID + Fingerprint
# ------------------------------------------------------------------


class TestMachineFingerprint:
    """Tests for _generate_machine_id and compute_fingerprint."""

    def test_compute_fingerprint_returns_valid(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.services.license_guard.MACHINE_ID_FILE", tmp_path / "machine_id")
        fp = compute_fingerprint()
        assert isinstance(fp, MachineFingerprint)
        assert len(fp.fingerprint_hash) == 64
        assert len(fp.platform) > 0
        assert len(fp.python_version) > 0

    def test_machine_id_persists(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mid_file = tmp_path / "machine_id"
        monkeypatch.setattr("src.services.license_guard.MACHINE_ID_FILE", mid_file)
        fp1 = compute_fingerprint()
        fp2 = compute_fingerprint()
        assert fp1.fingerprint_hash == fp2.fingerprint_hash

    def test_machine_id_reads_existing(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        mid_file = tmp_path / "machine_id"
        mid_file.parent.mkdir(parents=True, exist_ok=True)
        mid_file.write_text("a" * 64)
        monkeypatch.setattr("src.services.license_guard.MACHINE_ID_FILE", mid_file)
        fp = compute_fingerprint()
        assert isinstance(fp, MachineFingerprint)


# ------------------------------------------------------------------
# Cache load / save
# ------------------------------------------------------------------


class TestCacheLoadSave:
    """Tests for _load_cached_status and _save_cached_status."""

    def test_load_returns_none_when_no_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", tmp_path / "nope.json")
        assert _load_cached_status() is None

    def test_load_returns_none_on_corrupt_json(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        f = tmp_path / "bad.json"
        f.write_text("{invalid json!!", encoding="utf-8")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", f)
        assert _load_cached_status() is None

    def test_save_and_load_roundtrip(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_dir = tmp_path / "cache"
        cache_file = cache_dir / "license_cache.json"
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_DIR", cache_dir)
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", cache_file)

        status = LicenseStatus(
            valid=True,
            license_key="testkey.",
            plan="pro",
            validated_at="2026-01-01T00:00:00",
        )
        _save_cached_status(status)
        loaded = _load_cached_status()
        assert loaded is not None
        assert loaded.valid is True
        assert loaded.plan == "pro"

    def test_save_handles_os_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_DIR",
            Path("/dev/null/impossible"),
        )
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            Path("/dev/null/impossible/cache.json"),
        )
        # Should not raise
        _save_cached_status(LicenseStatus())


# ------------------------------------------------------------------
# Grace period & revalidation checks
# ------------------------------------------------------------------


class TestGracePeriod:
    """Tests for _is_within_grace_period."""

    def test_no_offline_since_returns_true(self) -> None:
        status = LicenseStatus(offline_since="")
        assert _is_within_grace_period(status) is True

    def test_within_grace_returns_true(self) -> None:
        recent = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=1)).isoformat()
        status = LicenseStatus(offline_since=recent)
        assert _is_within_grace_period(status) is True

    def test_expired_grace_returns_false(self) -> None:
        old = (
            datetime.datetime.now(datetime.UTC)
            - datetime.timedelta(days=LICENSE_OFFLINE_GRACE_DAYS + 1)
        ).isoformat()
        status = LicenseStatus(offline_since=old)
        assert _is_within_grace_period(status) is False

    def test_invalid_date_returns_false(self) -> None:
        status = LicenseStatus(offline_since="not-a-date")
        assert _is_within_grace_period(status) is False


class TestNeedsRevalidation:
    """Tests for _needs_revalidation."""

    def test_no_validated_at_returns_true(self) -> None:
        assert _needs_revalidation(LicenseStatus()) is True

    def test_recent_validation_returns_false(self) -> None:
        recent = datetime.datetime.now(datetime.UTC).isoformat()
        assert _needs_revalidation(LicenseStatus(validated_at=recent)) is False

    def test_old_validation_returns_true(self) -> None:
        old = (
            datetime.datetime.now(datetime.UTC)
            - datetime.timedelta(seconds=LICENSE_CHECK_INTERVAL_SECONDS + 100)
        ).isoformat()
        assert _needs_revalidation(LicenseStatus(validated_at=old)) is True

    def test_invalid_date_returns_true(self) -> None:
        assert _needs_revalidation(LicenseStatus(validated_at="nope")) is True


# ------------------------------------------------------------------
# _validate_with_server (async)
# ------------------------------------------------------------------


class TestValidateWithServer:
    """Tests for _validate_with_server."""

    @pytest.fixture(autouse=True)
    def _patch_machine_id(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.services.license_guard.MACHINE_ID_FILE", tmp_path / "mid")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            tmp_path / "cache" / "lic.json",
        )

    async def test_200_success(self, httpx_mock: pytest.fixture) -> None:  # type: ignore[type-arg]
        httpx_mock.add_response(
            json={
                "valid": True,
                "plan": "pro",
                "machine_bound": True,
                "expires_at": "2027-01-01",
                "features": ["premium"],
                "max_rules": 999,
                "max_gateway_rules": 99,
            },
        )
        fp = MachineFingerprint(
            fingerprint_hash="a" * 64,
            platform="Linux",
            python_version="3.12.0",
        )
        status = await _validate_with_server("test-key-12345678", fp)
        assert status.valid is True
        assert status.plan == "pro"

    async def test_401_invalid(self, httpx_mock: pytest.fixture) -> None:  # type: ignore[type-arg]
        httpx_mock.add_response(status_code=401)
        fp = MachineFingerprint(
            fingerprint_hash="a" * 64,
            platform="Linux",
            python_version="3.12.0",
        )
        status = await _validate_with_server("bad-key-12345678", fp)
        assert status.valid is False
        assert status.plan == "expired"

    async def test_500_server_error_falls_back(self, httpx_mock: pytest.fixture) -> None:  # type: ignore[type-arg]
        httpx_mock.add_response(status_code=500)
        fp = MachineFingerprint(
            fingerprint_hash="a" * 64,
            platform="Linux",
            python_version="3.12.0",
        )
        status = await _validate_with_server("key-12345678xxxx", fp)
        # Falls back to offline validation
        assert status.valid is False

    async def test_timeout_falls_back(self, httpx_mock: pytest.fixture) -> None:  # type: ignore[type-arg]
        httpx_mock.add_exception(httpx.TimeoutException("timeout"))
        fp = MachineFingerprint(
            fingerprint_hash="a" * 64,
            platform="Linux",
            python_version="3.12.0",
        )
        status = await _validate_with_server("key-12345678xxxx", fp)
        assert status.valid is False

    async def test_http_error_falls_back(self, httpx_mock: pytest.fixture) -> None:  # type: ignore[type-arg]
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        fp = MachineFingerprint(
            fingerprint_hash="a" * 64,
            platform="Linux",
            python_version="3.12.0",
        )
        status = await _validate_with_server("key-12345678xxxx", fp)
        assert status.valid is False


# ------------------------------------------------------------------
# _handle_offline_validation
# ------------------------------------------------------------------


class TestHandleOfflineValidation:
    """Tests for _handle_offline_validation."""

    def test_no_cache_returns_invalid(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            tmp_path / "nope.json",
        )
        status = _handle_offline_validation("key-12345678")
        assert status.valid is False
        assert status.plan == "unknown"

    def test_cached_valid_within_grace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "lic.json"
        cached = LicenseStatus(
            valid=True,
            plan="pro",
            validated_at=datetime.datetime.now(datetime.UTC).isoformat(),
            offline_since="",
        )
        cache_file.write_text(json.dumps(cached.model_dump()), encoding="utf-8")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", cache_file)
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_DIR", tmp_path)

        status = _handle_offline_validation("key-12345678")
        assert status.valid is True
        assert status.plan == "pro"

    def test_cached_valid_grace_expired(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "lic.json"
        old_date = (
            datetime.datetime.now(datetime.UTC)
            - datetime.timedelta(days=LICENSE_OFFLINE_GRACE_DAYS + 5)
        ).isoformat()
        cached = LicenseStatus(
            valid=True,
            plan="pro",
            validated_at=old_date,
            offline_since=old_date,
        )
        cache_file.write_text(json.dumps(cached.model_dump()), encoding="utf-8")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", cache_file)
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_DIR", tmp_path)

        status = _handle_offline_validation("key-12345678")
        assert status.valid is False
        assert status.plan == "expired"


# ------------------------------------------------------------------
# validate_license (async)
# ------------------------------------------------------------------


class TestValidateLicense:
    """Tests for validate_license."""

    @pytest.fixture(autouse=True)
    def _patch_paths(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.services.license_guard.MACHINE_ID_FILE", tmp_path / "mid")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            tmp_path / "cache" / "lic.json",
        )

    async def test_no_key_returns_free(self) -> None:
        status = await validate_license("")
        assert status.valid is False
        assert status.plan == "free"

    async def test_no_key_with_valid_cache(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "cache" / "lic.json"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cached = LicenseStatus(
            valid=True,
            plan="enterprise",
            validated_at=datetime.datetime.now(datetime.UTC).isoformat(),
        )
        cache_file.write_text(json.dumps(cached.model_dump()), encoding="utf-8")
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE", cache_file,
        )
        status = await validate_license("")
        assert status.valid is True
        assert status.plan == "enterprise"

    async def test_with_key_calls_server(self, httpx_mock: pytest.fixture) -> None:  # type: ignore[type-arg]
        httpx_mock.add_response(
            json={"valid": True, "plan": "pro", "features": []},
        )
        status = await validate_license("real-key-12345678")
        assert status.valid is True


# ------------------------------------------------------------------
# validate_license_sync
# ------------------------------------------------------------------


class TestValidateLicenseSync:
    """Tests for validate_license_sync."""

    def test_no_key_no_cache(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            tmp_path / "nope.json",
        )
        status = validate_license_sync("")
        assert status.valid is False
        assert status.plan == "free"

    def test_no_key_with_valid_cache(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "lic.json"
        cached = LicenseStatus(
            valid=True,
            plan="pro",
            validated_at=datetime.datetime.now(datetime.UTC).isoformat(),
            offline_since="",
        )
        cache_file.write_text(json.dumps(cached.model_dump()), encoding="utf-8")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", cache_file)
        status = validate_license_sync("")
        assert status.valid is True

    def test_with_key_cached_valid(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "lic.json"
        cached = LicenseStatus(
            valid=True,
            plan="enterprise",
            validated_at=datetime.datetime.now(datetime.UTC).isoformat(),
        )
        cache_file.write_text(json.dumps(cached.model_dump()), encoding="utf-8")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", cache_file)
        status = validate_license_sync("key-12345678")
        assert status.valid is True

    def test_with_key_no_cache(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            tmp_path / "nope.json",
        )
        status = validate_license_sync("key-12345678")
        assert status.valid is False
        assert status.plan == "unknown"

    def test_with_key_needs_revalidation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cache_file = tmp_path / "lic.json"
        old = (
            datetime.datetime.now(datetime.UTC)
            - datetime.timedelta(seconds=LICENSE_CHECK_INTERVAL_SECONDS + 100)
        ).isoformat()
        cached = LicenseStatus(valid=True, plan="pro", validated_at=old)
        cache_file.write_text(json.dumps(cached.model_dump()), encoding="utf-8")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_FILE", cache_file)
        status = validate_license_sync("key-12345678")
        assert status.valid is True  # Still returns cached, just logs warning


# ------------------------------------------------------------------
# enforce_rule_limit / enforce_gateway_rule_limit
# ------------------------------------------------------------------


class TestEnforceRuleLimit:
    """Tests for enforce_rule_limit."""

    def test_valid_license_passes_all(self) -> None:
        rules: list[dict[str, object]] = [{"id": str(i)} for i in range(100)]
        status = LicenseStatus(valid=True, plan="pro")
        assert len(enforce_rule_limit(rules, status)) == 100

    def test_invalid_under_limit(self) -> None:
        rules: list[dict[str, object]] = [{"id": str(i)} for i in range(5)]
        status = LicenseStatus(valid=False)
        assert len(enforce_rule_limit(rules, status)) == 5

    def test_invalid_over_limit_truncates(self) -> None:
        rules: list[dict[str, object]] = [{"id": str(i)} for i in range(50)]
        status = LicenseStatus(valid=False, max_rules=UNLICENSED_MAX_RULES)
        result = enforce_rule_limit(rules, status)
        assert len(result) == UNLICENSED_MAX_RULES


class TestEnforceGatewayRuleLimit:
    """Tests for enforce_gateway_rule_limit."""

    def test_valid_license_passes_all(self) -> None:
        rules: list[dict[str, object]] = [{"id": str(i)} for i in range(50)]
        status = LicenseStatus(valid=True)
        assert len(enforce_gateway_rule_limit(rules, status)) == 50

    def test_invalid_under_limit(self) -> None:
        rules: list[dict[str, object]] = [{"id": str(i)} for i in range(3)]
        status = LicenseStatus(valid=False)
        assert len(enforce_gateway_rule_limit(rules, status)) == 3

    def test_invalid_over_limit_truncates(self) -> None:
        rules: list[dict[str, object]] = [{"id": str(i)} for i in range(20)]
        status = LicenseStatus(valid=False, max_gateway_rules=UNLICENSED_MAX_GATEWAY_RULES)
        result = enforce_gateway_rule_limit(rules, status)
        assert len(result) == UNLICENSED_MAX_GATEWAY_RULES


# ------------------------------------------------------------------
# periodic_license_check
# ------------------------------------------------------------------


class TestPeriodicLicenseCheck:
    """Tests for periodic_license_check."""

    @pytest.fixture(autouse=True)
    def _patch_paths(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("src.services.license_guard.MACHINE_ID_FILE", tmp_path / "mid")
        monkeypatch.setattr("src.services.license_guard.LICENSE_CACHE_DIR", tmp_path / "cache")
        monkeypatch.setattr(
            "src.services.license_guard.LICENSE_CACHE_FILE",
            tmp_path / "cache" / "lic.json",
        )

    async def test_skips_within_interval(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import time

        monkeypatch.setattr("src.services.license_guard._last_check_time", time.time())
        result = await periodic_license_check("key-12345678")
        assert result is None

    async def test_runs_after_interval(
        self,
        monkeypatch: pytest.MonkeyPatch,
        httpx_mock: pytest.fixture,  # type: ignore[type-arg]
    ) -> None:
        monkeypatch.setattr("src.services.license_guard._last_check_time", 0.0)
        httpx_mock.add_response(
            json={"valid": True, "plan": "pro"},
        )
        result = await periodic_license_check("key-12345678")
        assert result is not None
        assert result.valid is True
