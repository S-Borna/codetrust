"""Tests for the registry verification service (Layer 2)."""

import json

import httpx
from pytest_httpx import HTTPXMock

from src.config import settings
from src.models.enums import Language, Registry, VerifyStatus
from src.services.cache import CacheService
from src.services.registry import RegistryService
from src.utils.parsers import (
    extract_js_imports,
    extract_python_imports,
    parse_dockerfile_from,
    parse_package_json_deps,
    parse_requirements_txt,
)
from src.utils.similarity import suggest_npm_package, suggest_pypi_package

# ---------------------------------------------------------------------------
# CacheService tests (with fakeredis)
# ---------------------------------------------------------------------------


class TestCacheService:
    """Tests for the Redis cache service."""

    async def test_set_and_get(self, fake_cache: CacheService) -> None:
        await fake_cache.set("test_key", "test_value", 60)
        result = await fake_cache.get("test_key")
        assert result == "test_value"

    async def test_get_miss(self, fake_cache: CacheService) -> None:
        result = await fake_cache.get("nonexistent")
        assert result is None

    async def test_set_json_and_get_json(self, fake_cache: CacheService) -> None:
        data = {"exists": True, "latest": "1.0.0", "deprecated": False}
        await fake_cache.set_json("pkg_key", data, 60)
        result = await fake_cache.get_json("pkg_key")
        assert result is not None
        assert result["exists"] is True
        assert result["latest"] == "1.0.0"

    async def test_get_json_miss(self, fake_cache: CacheService) -> None:
        result = await fake_cache.get_json("no_key")
        assert result is None

    async def test_make_key(self, fake_cache: CacheService) -> None:
        key = fake_cache._make_key("pypi", "fastapi")
        assert key == "codetrust:pypi:fastapi"

    async def test_is_connected(self, fake_cache: CacheService) -> None:
        result = await fake_cache.is_connected()
        assert result is True

    async def test_graceful_degradation_get(
        self, disconnected_cache: CacheService
    ) -> None:
        result = await disconnected_cache.get("anything")
        assert result is None

    async def test_graceful_degradation_set(
        self, disconnected_cache: CacheService
    ) -> None:
        # Should not raise
        await disconnected_cache.set("key", "value", 60)

    async def test_graceful_degradation_connected(
        self, disconnected_cache: CacheService
    ) -> None:
        result = await disconnected_cache.is_connected()
        assert result is False


# ---------------------------------------------------------------------------
# Registry — PyPI — known package VERIFIED
# ---------------------------------------------------------------------------


class TestRegistryPyPI:
    """Tests for PyPI package verification."""

    async def test_known_package_verified(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Known package returns VERIFIED."""
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="fastapi"),
            json={
                "info": {"version": "0.115.0", "classifiers": []},
                "releases": {"0.115.0": [{}], "0.114.0": [{}]},
            },
        )
        result = await registry_service.verify_python_package("fastapi")
        assert result.status == VerifyStatus.VERIFIED
        assert result.package == "fastapi"
        assert result.latest_version == "0.115.0"

    async def test_unknown_package_not_found(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Unknown package returns NOT_FOUND with suggestion."""
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="reqeusts"),
            status_code=404,
        )
        result = await registry_service.verify_python_package("reqeusts")
        assert result.status == VerifyStatus.NOT_FOUND
        assert result.severity.value == "BLOCK"
        assert "Did you mean" in result.suggestion or result.suggestion == ""

    async def test_known_package_wrong_version(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Known package with wrong version returns VERSION_MISMATCH."""
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="flask"),
            json={
                "info": {"version": "3.0.0", "classifiers": []},
                "releases": {"3.0.0": [{}], "2.3.0": [{}]},
            },
        )
        result = await registry_service.verify_python_package("flask", "99.0.0")
        assert result.status == VerifyStatus.VERSION_MISMATCH
        assert result.requested_version == "99.0.0"
        assert "99.0.0" in result.message

    async def test_known_package_correct_version(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Known package with correct version returns VERIFIED."""
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="flask"),
            json={
                "info": {"version": "3.0.0", "classifiers": []},
                "releases": {"3.0.0": [{}], "2.3.0": [{}]},
            },
        )
        result = await registry_service.verify_python_package("flask", "3.0.0")
        assert result.status == VerifyStatus.VERIFIED
        assert result.requested_version == "3.0.0"

    async def test_registry_timeout(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Registry timeout returns TIMEOUT."""
        httpx_mock.add_exception(
            httpx.ReadTimeout("Connection timed out"),
            url=settings.pypi_url.format(package="slow_pkg"),
        )
        result = await registry_service.verify_python_package("slow_pkg")
        assert result.status == VerifyStatus.TIMEOUT

    async def test_cache_hit_skips_http(
        self,
        registry_service: RegistryService,
        fake_cache: CacheService,
    ) -> None:
        """Cache hit skips HTTP call entirely."""
        # Pre-populate cache
        cache_key = fake_cache._make_key("pypi", "cached_pkg")
        await fake_cache.set_json(
            cache_key,
            {"exists": True, "latest": "2.0.0", "deprecated": False},
            60,
        )
        # No httpx_mock setup = if HTTP is called, it will fail
        result = await registry_service.verify_python_package("cached_pkg")
        assert result.status == VerifyStatus.VERIFIED
        assert result.cached is True
        assert result.latest_version == "2.0.0"


# ---------------------------------------------------------------------------
# Registry — npm
# ---------------------------------------------------------------------------


class TestRegistryNPM:
    """Tests for npm package verification."""

    async def test_known_npm_package(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            url=settings.npm_url.format(package="express"),
            json={
                "dist-tags": {"latest": "4.18.2"},
                "versions": {"4.18.2": {}, "4.17.1": {}},
            },
        )
        result = await registry_service.verify_npm_package("express")
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.NPM

    async def test_unknown_npm_package(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            url=settings.npm_url.format(package="nonexistent_xyz_pkg"),
            status_code=404,
        )
        result = await registry_service.verify_npm_package("nonexistent_xyz_pkg")
        assert result.status == VerifyStatus.NOT_FOUND

    async def test_npm_version_mismatch(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        httpx_mock.add_response(
            url=settings.npm_url.format(package="react"),
            json={
                "dist-tags": {"latest": "18.2.0"},
                "versions": {"18.2.0": {}, "17.0.2": {}},
            },
        )
        result = await registry_service.verify_npm_package("react", "99.0.0")
        assert result.status == VerifyStatus.VERSION_MISMATCH


# ---------------------------------------------------------------------------
# Registry — batch verify
# ---------------------------------------------------------------------------


class TestBatchVerify:
    """Tests for batch package verification."""

    async def test_batch_verify_concurrent(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Batch verify runs concurrently and returns correct results."""
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="fastapi"),
            json={
                "info": {"version": "0.115.0", "classifiers": []},
                "releases": {"0.115.0": [{}]},
            },
        )
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="flask"),
            json={
                "info": {"version": "3.0.0", "classifiers": []},
                "releases": {"3.0.0": [{}]},
            },
        )
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="nonexistent_pkg_xyz"),
            status_code=404,
        )

        results = await registry_service.verify_packages(
            Language.PYTHON,
            ["fastapi", "flask", "nonexistent_pkg_xyz"],
        )
        assert len(results) == 3

        statuses = {r.package: r.status for r in results}
        assert statuses["fastapi"] == VerifyStatus.VERIFIED
        assert statuses["flask"] == VerifyStatus.VERIFIED
        assert statuses["nonexistent_pkg_xyz"] == VerifyStatus.NOT_FOUND

    async def test_batch_verify_with_requirements(
        self,
        registry_service: RegistryService,
        httpx_mock: HTTPXMock,
    ) -> None:
        """Batch verify uses requirements.txt for version pinning."""
        httpx_mock.add_response(
            url=settings.pypi_url.format(package="flask"),
            json={
                "info": {"version": "3.0.0", "classifiers": []},
                "releases": {"3.0.0": [{}], "2.3.0": [{}]},
            },
        )

        results = await registry_service.verify_packages(
            Language.PYTHON,
            ["flask"],
            requirements="flask==2.3.0",
        )
        assert len(results) == 1
        assert results[0].status == VerifyStatus.VERIFIED
        assert results[0].requested_version == "2.3.0"


# ---------------------------------------------------------------------------
# Parsers — Python imports
# ---------------------------------------------------------------------------


class TestPythonImports:
    """Tests for Python import extraction."""

    def test_import_simple(self) -> None:
        code = "import requests\nimport flask"
        result = extract_python_imports(code)
        assert "requests" in result
        assert "flask" in result

    def test_from_import(self) -> None:
        code = "from fastapi import FastAPI"
        result = extract_python_imports(code)
        assert "fastapi" in result

    def test_dotted_import(self) -> None:
        code = "import requests.auth"
        result = extract_python_imports(code)
        assert "requests" in result

    def test_relative_import_skipped(self) -> None:
        code = "from . import utils\nfrom .models import User"
        result = extract_python_imports(code)
        assert len(result) == 0

    def test_stdlib_skipped(self) -> None:
        code = "import os\nimport sys\nimport json\nimport requests"
        result = extract_python_imports(code)
        assert "os" not in result
        assert "sys" not in result
        assert "json" not in result
        assert "requests" in result

    def test_import_mapping(self) -> None:
        code = "import PIL\nfrom cv2 import imread\nfrom yaml import safe_load"
        result = extract_python_imports(code)
        assert "Pillow" in result
        assert "opencv-python" in result
        assert "PyYAML" in result

    def test_comments_skipped(self) -> None:
        code = "# import os\nimport requests"
        result = extract_python_imports(code)
        assert "requests" in result
        assert len(result) == 1

    def test_empty_code(self) -> None:
        result = extract_python_imports("")
        assert result == []


# ---------------------------------------------------------------------------
# Parsers — JS imports
# ---------------------------------------------------------------------------


class TestJSImports:
    """Tests for JavaScript/TypeScript import extraction."""

    def test_import_from(self) -> None:
        code = "import React from 'react'"
        result = extract_js_imports(code)
        assert "react" in result

    def test_named_import(self) -> None:
        code = "import { useState } from 'react'"
        result = extract_js_imports(code)
        assert "react" in result

    def test_require(self) -> None:
        code = "const express = require('express')"
        result = extract_js_imports(code)
        assert "express" in result

    def test_scoped_package(self) -> None:
        code = "import { Input } from '@mui/material'"
        result = extract_js_imports(code)
        assert "@mui/material" in result

    def test_relative_skipped(self) -> None:
        code = "import utils from './utils'\nimport config from '../config'"
        result = extract_js_imports(code)
        assert len(result) == 0

    def test_node_builtin_skipped(self) -> None:
        code = "import fs from 'fs'\nimport path from 'path'"
        result = extract_js_imports(code)
        assert len(result) == 0

    def test_path_alias_skipped(self) -> None:
        """Next.js/Vite @/ ~/ #/ path aliases should not be treated as npm packages."""
        code = (
            "import { Button } from '@/components/ui/button'\n"
            "import { api } from '@/lib/api'\n"
            "import { config } from '~/config'\n"
            "import { schema } from '#/db/schema'\n"
            "import { Input } from '@mui/material'\n"
        )
        result = extract_js_imports(code)
        assert "@/components" not in result
        assert "@/lib" not in result
        assert "~/config" not in result
        assert "#/db" not in result
        assert "@mui/material" in result
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Parsers — requirements.txt
# ---------------------------------------------------------------------------


class TestParseRequirements:
    """Tests for requirements.txt parsing."""

    def test_simple_pins(self) -> None:
        content = "flask==3.0.0\nrequests>=2.31.0"
        result = parse_requirements_txt(content)
        assert result["flask"] == "3.0.0"
        assert result["requests"] == "2.31.0"

    def test_comments_and_blanks(self) -> None:
        content = "# comment\n\nflask==3.0.0\n"
        result = parse_requirements_txt(content)
        assert "flask" in result
        assert len(result) == 1

    def test_extras(self) -> None:
        content = "uvicorn[standard]==0.30.0"
        result = parse_requirements_txt(content)
        assert result["uvicorn"] == "0.30.0"

    def test_git_urls_skipped(self) -> None:
        content = "git+https://github.com/user/repo.git\nflask==3.0.0"
        result = parse_requirements_txt(content)
        assert len(result) == 1
        assert "flask" in result

    def test_r_includes_skipped(self) -> None:
        content = "-r requirements-base.txt\nflask==3.0.0"
        result = parse_requirements_txt(content)
        assert len(result) == 1

    def test_no_version(self) -> None:
        content = "flask\nrequests"
        result = parse_requirements_txt(content)
        assert result["flask"] == ""
        assert result["requests"] == ""


# ---------------------------------------------------------------------------
# Parsers — Dockerfile FROM
# ---------------------------------------------------------------------------


class TestDockerfileParsing:
    """Tests for Dockerfile FROM line parsing."""

    def test_simple_from(self) -> None:
        content = "FROM python:3.12-slim"
        result = parse_dockerfile_from(content)
        assert result == [("python", "3.12-slim")]

    def test_from_with_alias(self) -> None:
        content = "FROM python:3.12-slim AS builder"
        result = parse_dockerfile_from(content)
        assert result == [("python", "3.12-slim")]

    def test_from_no_tag(self) -> None:
        content = "FROM node"
        result = parse_dockerfile_from(content)
        assert result == [("node", "latest")]

    def test_from_with_platform(self) -> None:
        content = "FROM --platform=linux/amd64 python:3.12"
        result = parse_dockerfile_from(content)
        assert result == [("python", "3.12")]

    def test_multistage(self) -> None:
        content = "FROM python:3.12-slim AS builder\nRUN pip install .\nFROM python:3.12-slim"
        result = parse_dockerfile_from(content)
        assert len(result) == 2

    def test_arg_substitution(self) -> None:
        content = "ARG BASE=python:3.12\nFROM $BASE"
        result = parse_dockerfile_from(content)
        assert result == [("python", "3.12")]


# ---------------------------------------------------------------------------
# Parsers — package.json
# ---------------------------------------------------------------------------


class TestPackageJsonParsing:
    """Tests for package.json dependency parsing."""

    def test_parse_deps(self) -> None:
        content = json.dumps({
            "dependencies": {"react": "^18.2.0", "express": "~4.18.2"},
            "devDependencies": {"typescript": "^5.0.0"},
        })
        result = parse_package_json_deps(content)
        assert result["react"] == "18.2.0"
        assert result["express"] == "4.18.2"
        assert result["typescript"] == "5.0.0"

    def test_invalid_json(self) -> None:
        result = parse_package_json_deps("not json at all")
        assert result == {}


# ---------------------------------------------------------------------------
# Similarity — fuzzy matching
# ---------------------------------------------------------------------------


class TestSimilarity:
    """Tests for fuzzy package name matching."""

    def test_pypi_typo_suggestion(self) -> None:
        result = suggest_pypi_package("reqeusts")
        assert "requests" in result.lower()

    def test_pypi_no_match(self) -> None:
        result = suggest_pypi_package("zzzzzznotapackagezzzzz")
        assert result == ""

    def test_npm_typo_suggestion(self) -> None:
        result = suggest_npm_package("exprss")
        assert "express" in result.lower()

    def test_npm_no_match(self) -> None:
        result = suggest_npm_package("zzzzzznotapackagezzzzz")
        assert result == ""
