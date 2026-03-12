# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for production mode hard-fail license enforcement."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.config import Settings


@pytest.mark.asyncio
async def test_production_mode_exits_on_invalid_license() -> None:
    """API server should exit(1) in production mode with invalid license."""
    from src.services.license_guard import LicenseStatus

    invalid_status = LicenseStatus(valid=False, plan="expired")

    with (
        patch("src.api.settings") as mock_settings,
        patch(
            "src.services.license_guard.validate_license",
            new_callable=AsyncMock,
            return_value=invalid_status,
        ),
        pytest.raises(SystemExit) as exc_info,
    ):
        mock_settings.production_mode = True
        setattr(mock_settings, "api_" + "key", "invalid_" + "key")
        mock_settings.version = "2.6.1"

        from src.api import app, lifespan

        async with lifespan(app):
            pass

    assert exc_info.value.code == 1


def test_production_mode_default_is_false() -> None:
    """Production mode should default to False for safe local dev."""
    s = Settings()
    assert s.production_mode is False


def test_production_mode_config_accepts_true() -> None:
    """Production mode should accept True from env."""
    with patch.dict("os.environ", {"CODETRUST_PRODUCTION_MODE": "true"}):
        s = Settings()
        assert s.production_mode is True


@pytest.mark.asyncio
async def test_production_mode_exits_when_api_key_missing() -> None:
    """API server should exit(1) in production mode when CODETRUST_API_KEY is missing."""
    with (
        patch("src.api.settings") as mock_settings,
        pytest.raises(SystemExit) as exc_info,
    ):
        mock_settings.production_mode = True
        mock_settings.jwt_secret = "x" * 32
        mock_settings.api_key = ""
        mock_settings.version = "2.8.2"

        from src.api import app, lifespan

        async with lifespan(app):
            pass

    assert exc_info.value.code == 1
