# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Tests for the license compliance service."""

from __future__ import annotations

import httpx
import pytest
from pytest_httpx import HTTPXMock

from src.models.enums import Language, Severity
from src.services.cache import CacheService
from src.services.license_checker import (
    ECOSYSTEM_URLS,
    LicenseInfo,
    LicenseRisk,
    LicenseScanResponse,
    LicenseService,
    classify_license,
)


# ── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
async def fake_cache() -> CacheService:
    """In-memory cache backed by fakeredis."""
    import fakeredis.aioredis

    cache = CacheService("redis://localhost:6379")
    cache._client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return cache


@pytest.fixture()
def mock_http_client() -> httpx.AsyncClient:
    """HTTP client — all calls intercepted by pytest-httpx."""
    return httpx.AsyncClient()


@pytest.fixture()
async def license_service(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
) -> LicenseService:
    """LicenseService wired to fake cache and mocked HTTP."""
    return LicenseService(cache=fake_cache, http_client=mock_http_client)


# ── Registry response fixtures ─────────────────────────────────────────────

PYPI_MIT_RESPONSE = {
    "info": {
        "name": "flask",
        "version": "3.0.0",
        "license": "MIT",
        "classifiers": ["License :: OSI Approved :: MIT License"],
    }
}

PYPI_GPL_RESPONSE = {
    "info": {
        "name": "some-gpl-lib",
        "version": "1.0.0",
        "license": "GPL-3.0",
        "classifiers": [],
    }
}

PYPI_AGPL_RESPONSE = {
    "info": {
        "name": "agpl-lib",
        "version": "2.0.0",
        "license": "AGPL-3.0",
        "classifiers": [],
    }
}

PYPI_UNKNOWN_LICENSE_RESPONSE = {
    "info": {
        "name": "obscure-lib",
        "version": "0.1.0",
        "license": "",
        "classifiers": [],
    }
}

PYPI_CLASSIFIER_ONLY_RESPONSE = {
    "info": {
        "name": "classifier-lib",
        "version": "1.0.0",
        "license": "UNKNOWN",
        "classifiers": [
            "License :: OSI Approved :: Apache Software License",
        ],
    }
}

NPM_MIT_RESPONSE = {
    "name": "express",
    "version": "4.18.2",
    "license": "MIT",
}

NPM_ISC_RESPONSE = {
    "name": "semver",
    "version": "7.5.0",
    "license": "ISC",
}

NPM_OBJECT_LICENSE_RESPONSE = {
    "name": "old-pkg",
    "version": "1.0.0",
    "license": {"type": "BSD-3-Clause", "url": "https://example.com"},
}


# ── classify_license unit tests ────────────────────────────────────────────


class TestClassifyLicense:
    """Tests for the classify_license function."""

    def test_mit_is_permissive(self) -> None:
        """MIT license classified as permissive."""
        risk, spdx = classify_license("MIT")
        assert risk == LicenseRisk.PERMISSIVE
        assert spdx == "MIT"

    def test_apache_is_permissive(self) -> None:
        """Apache-2.0 classified as permissive."""
        risk, _ = classify_license("Apache-2.0")
        assert risk == LicenseRisk.PERMISSIVE

    def test_bsd_is_permissive(self) -> None:
        """BSD-3-Clause classified as permissive."""
        risk, _ = classify_license("BSD-3-Clause")
        assert risk == LicenseRisk.PERMISSIVE

    def test_isc_is_permissive(self) -> None:
        """ISC classified as permissive."""
        risk, _ = classify_license("ISC")
        assert risk == LicenseRisk.PERMISSIVE

    def test_gpl3_is_strong_copyleft(self) -> None:
        """GPL-3.0 classified as strong copyleft."""
        risk, _ = classify_license("GPL-3.0")
        assert risk == LicenseRisk.STRONG_COPYLEFT

    def test_gplv2_is_strong_copyleft(self) -> None:
        """GPLv2 classified as strong copyleft."""
        risk, _ = classify_license("GPLv2")
        assert risk == LicenseRisk.STRONG_COPYLEFT

    def test_lgpl_is_weak_copyleft(self) -> None:
        """LGPL classified as weak copyleft (not strong)."""
        risk, _ = classify_license("LGPL-3.0")
        assert risk == LicenseRisk.WEAK_COPYLEFT

    def test_mpl_is_weak_copyleft(self) -> None:
        """MPL-2.0 classified as weak copyleft."""
        risk, _ = classify_license("MPL-2.0")
        assert risk == LicenseRisk.WEAK_COPYLEFT

    def test_agpl_is_network_copyleft(self) -> None:
        """AGPL-3.0 classified as network copyleft."""
        risk, _ = classify_license("AGPL-3.0")
        assert risk == LicenseRisk.NETWORK_COPYLEFT

    def test_sspl_is_network_copyleft(self) -> None:
        """SSPL classified as network copyleft."""
        risk, _ = classify_license("SSPL-1.0")
        assert risk == LicenseRisk.NETWORK_COPYLEFT

    def test_empty_is_unknown(self) -> None:
        """Empty string classified as unknown."""
        risk, spdx = classify_license("")
        assert risk == LicenseRisk.UNKNOWN
        assert spdx == ""

    def test_none_string_is_unknown(self) -> None:
        """'UNKNOWN' string classified as unknown."""
        risk, _ = classify_license("UNKNOWN")
        assert risk == LicenseRisk.UNKNOWN

    def test_case_insensitive(self) -> None:
        """Classification is case-insensitive."""
        risk, _ = classify_license("mit")
        assert risk == LicenseRisk.PERMISSIVE


# ── LicenseInfo severity mapping ───────────────────────────────────────────


class TestLicenseInfoSeverity:
    """Tests for LicenseInfo.severity property."""

    def test_network_copyleft_is_block(self) -> None:
        """AGPL triggers BLOCK severity."""
        info = LicenseInfo(
            package="x", ecosystem="PyPI",
            license_name="AGPL-3.0", risk=LicenseRisk.NETWORK_COPYLEFT,
        )
        assert info.severity == Severity.BLOCK

    def test_strong_copyleft_is_block(self) -> None:
        """GPL triggers BLOCK severity."""
        info = LicenseInfo(
            package="x", ecosystem="PyPI",
            license_name="GPL-3.0", risk=LicenseRisk.STRONG_COPYLEFT,
        )
        assert info.severity == Severity.BLOCK

    def test_weak_copyleft_is_warn(self) -> None:
        """LGPL triggers WARN severity."""
        info = LicenseInfo(
            package="x", ecosystem="PyPI",
            license_name="LGPL-3.0", risk=LicenseRisk.WEAK_COPYLEFT,
        )
        assert info.severity == Severity.WARN

    def test_permissive_is_info(self) -> None:
        """MIT triggers INFO severity."""
        info = LicenseInfo(
            package="x", ecosystem="PyPI",
            license_name="MIT", risk=LicenseRisk.PERMISSIVE,
        )
        assert info.severity == Severity.INFO


# ── PyPI license extraction ────────────────────────────────────────────────


class TestPyPILicenseCheck:
    """Tests for checking PyPI packages."""

    async def test_mit_package(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """PyPI package with MIT license is permissive."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="flask")
        httpx_mock.add_response(url=url, json=PYPI_MIT_RESPONSE)

        result = await license_service.check_package("flask", "PyPI")

        assert result.risk == LicenseRisk.PERMISSIVE
        assert "MIT" in result.license_name

    async def test_gpl_package(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """PyPI package with GPL-3.0 is strong copyleft."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="some-gpl-lib")
        httpx_mock.add_response(url=url, json=PYPI_GPL_RESPONSE)

        result = await license_service.check_package("some-gpl-lib", "PyPI")

        assert result.risk == LicenseRisk.STRONG_COPYLEFT

    async def test_agpl_package(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """PyPI package with AGPL is network copyleft."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="agpl-lib")
        httpx_mock.add_response(url=url, json=PYPI_AGPL_RESPONSE)

        result = await license_service.check_package("agpl-lib", "PyPI")

        assert result.risk == LicenseRisk.NETWORK_COPYLEFT

    async def test_unknown_license(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """PyPI package with no license is unknown."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="obscure-lib")
        httpx_mock.add_response(url=url, json=PYPI_UNKNOWN_LICENSE_RESPONSE)

        result = await license_service.check_package("obscure-lib", "PyPI")

        assert result.risk == LicenseRisk.UNKNOWN

    async def test_classifier_fallback(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Falls back to classifier when license field is UNKNOWN."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="classifier-lib")
        httpx_mock.add_response(url=url, json=PYPI_CLASSIFIER_ONLY_RESPONSE)

        result = await license_service.check_package("classifier-lib", "PyPI")

        assert result.risk == LicenseRisk.PERMISSIVE
        assert "Apache" in result.license_name

    async def test_registry_timeout(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Timeout returns unknown, does not raise."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="flask")
        httpx_mock.add_exception(httpx.ReadTimeout("timeout"), url=url)

        result = await license_service.check_package("flask", "PyPI")

        assert result.risk == LicenseRisk.UNKNOWN

    async def test_registry_404(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """404 returns unknown license."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="nonexistent")
        httpx_mock.add_response(url=url, status_code=404)

        result = await license_service.check_package("nonexistent", "PyPI")

        assert result.risk == LicenseRisk.UNKNOWN


# ── npm license extraction ─────────────────────────────────────────────────


class TestNPMLicenseCheck:
    """Tests for checking npm packages."""

    async def test_npm_mit(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """npm package with MIT string license."""
        url = ECOSYSTEM_URLS["npm"].format(package="express")
        httpx_mock.add_response(url=url, json=NPM_MIT_RESPONSE)

        result = await license_service.check_package("express", "npm")

        assert result.risk == LicenseRisk.PERMISSIVE

    async def test_npm_object_license(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """npm package with object-style license (legacy format)."""
        url = ECOSYSTEM_URLS["npm"].format(package="old-pkg")
        httpx_mock.add_response(url=url, json=NPM_OBJECT_LICENSE_RESPONSE)

        result = await license_service.check_package("old-pkg", "npm")

        assert result.risk == LicenseRisk.PERMISSIVE
        assert "BSD" in result.license_name


# ── Cache tests ────────────────────────────────────────────────────────────


class TestLicenseCache:
    """Tests for cache behavior."""

    async def test_cache_hit(
        self,
        license_service: LicenseService,
        fake_cache: CacheService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Cached license is returned without hitting registry."""
        cached = {"license_name": "MIT", "risk": "permissive", "spdx_id": "MIT"}
        await fake_cache.set_json("codetrust:license:PyPI:flask", cached, 3600)

        result = await license_service.check_package("flask", "PyPI")

        assert result.risk == LicenseRisk.PERMISSIVE
        assert len(httpx_mock.get_requests()) == 0

    async def test_result_cached_after_fetch(
        self,
        license_service: LicenseService,
        fake_cache: CacheService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Result is stored in cache after successful fetch."""
        url = ECOSYSTEM_URLS["PyPI"].format(package="requests")
        httpx_mock.add_response(url=url, json=PYPI_MIT_RESPONSE)

        await license_service.check_package("requests", "PyPI")

        cached = await fake_cache.get_json("codetrust:license:PyPI:requests")
        assert cached is not None
        assert cached["risk"] == "permissive"


# ── Batch scan tests ───────────────────────────────────────────────────────


class TestCheckPackages:
    """Tests for LicenseService.check_packages (batch)."""

    async def test_batch_mixed_licenses(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Batch scan with permissive + copyleft packages."""
        httpx_mock.add_response(
            url=ECOSYSTEM_URLS["PyPI"].format(package="flask"),
            json=PYPI_MIT_RESPONSE,
        )
        httpx_mock.add_response(
            url=ECOSYSTEM_URLS["PyPI"].format(package="some-gpl-lib"),
            json=PYPI_GPL_RESPONSE,
        )

        result = await license_service.check_packages(
            language=Language.PYTHON,
            packages=["flask", "some-gpl-lib"],
        )

        assert result.total_packages == 2
        assert result.permissive_count == 1
        assert result.strong_copyleft_count == 1
        assert not result.compliant

    async def test_batch_all_permissive(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """All permissive packages — compliant."""
        httpx_mock.add_response(
            url=ECOSYSTEM_URLS["PyPI"].format(package="flask"),
            json=PYPI_MIT_RESPONSE,
        )

        result = await license_service.check_packages(
            language=Language.PYTHON,
            packages=["flask"],
        )

        assert result.compliant
        assert result.permissive_count == 1

    async def test_batch_unsupported_language(
        self,
        license_service: LicenseService,
    ) -> None:
        """Unsupported language returns empty response."""
        result = await license_service.check_packages(
            language=Language.TERRAFORM,
            packages=["some-pkg"],
        )

        assert result.total_packages == 1
        assert result.permissive_count == 0

    async def test_batch_agpl_triggers_noncompliant(
        self,
        license_service: LicenseService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """AGPL package makes batch non-compliant."""
        httpx_mock.add_response(
            url=ECOSYSTEM_URLS["PyPI"].format(package="agpl-lib"),
            json=PYPI_AGPL_RESPONSE,
        )

        result = await license_service.check_packages(
            language=Language.PYTHON,
            packages=["agpl-lib"],
        )

        assert not result.compliant
        assert result.network_copyleft_count == 1
