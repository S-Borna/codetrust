"""Layer 2: Package registry verification service (PyPI, npm)."""

import asyncio

import httpx
import structlog

from src.config import settings
from src.models.enums import Language, Registry, Severity, VerifyStatus
from src.models.responses import PackageResult
from src.services.cache import CacheService
from src.utils.parsers import parse_requirements_txt
from src.utils.similarity import suggest_npm_package, suggest_pypi_package

logger = structlog.get_logger()

# Concurrency limit for batch registry calls
_SEMAPHORE_LIMIT: int = 20


class RegistryService:
    """Verifies packages exist in language registries (PyPI, npm)."""

    def __init__(
        self, cache: CacheService, http_client: httpx.AsyncClient
    ) -> None:
        """Initialize with cache and HTTP client."""
        self._cache = cache
        self._http = http_client

    async def verify_python_package(
        self, package: str, version: str = ""
    ) -> PackageResult:
        """Check if a Python package exists on PyPI.

        Flow:
        1. Check cache
        2. If miss: GET PyPI JSON API
        3. If 200: exists -> check version if specified
        4. If 404: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "pypi", f"{package}:{version}" if version else package
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                package, Registry.PYPI, version, cached
            )

        return await self._check_pypi_package(package, version, cache_key)

    async def _check_pypi_package(
        self, package: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual PyPI API check."""
        try:
            data = await self._check_pypi(package)
        except httpx.TimeoutException:
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.TIMEOUT,
                severity=Severity.WARN,
                message=f"Timeout verifying '{package}'.",
            )
        except httpx.HTTPError as exc:
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.ERROR,
                severity=Severity.WARN,
                message=f"HTTP error verifying '{package}': {exc}",
            )

        if data is None:
            suggestion = suggest_pypi_package(package)
            await self._cache.set_json(
                cache_key,
                {"exists": False, "latest": "", "deprecated": False},
                settings.cache_ttl_not_found,
            )
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message=f"Package '{package}' not found on PyPI.",
                suggestion=suggestion,
            )

        return await self._process_pypi_response(
            package, version, data, cache_key
        )

    async def _process_pypi_response(
        self,
        package: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful PyPI API response."""
        info = data.get("info", {})
        if not isinstance(info, dict):
            info = {}
        latest = str(info.get("version", ""))

        # Check deprecation (yanked or classifiers)
        classifiers = info.get("classifiers", [])
        deprecated = False
        if isinstance(classifiers, list):
            deprecated = any("Inactive" in str(c) for c in classifiers)

        await self._cache.set_json(
            self._cache._make_key("pypi", package),
            {"exists": True, "latest": latest, "deprecated": deprecated},
            settings.cache_ttl_package_exists,
        )

        if deprecated:
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.DEPRECATED,
                severity=Severity.WARN,
                latest_version=latest,
                message=f"Package '{package}' is deprecated.",
            )

        if version:
            return self._check_pypi_version(
                package, version, data, latest, cache_key
            )

        return PackageResult(
            package=package,
            registry=Registry.PYPI,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' exists on PyPI.",
        )

    def _check_pypi_version(
        self,
        package: str,
        version: str,
        data: dict[str, object],
        latest: str,
        cache_key: str,
    ) -> PackageResult:
        """Check if a specific version exists on PyPI."""
        releases = data.get("releases", {})
        if not isinstance(releases, dict):
            releases = {}

        if version in releases:
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                requested_version=version,
                latest_version=latest,
                message=f"Package '{package}=={version}' verified.",
            )

        return PackageResult(
            package=package,
            registry=Registry.PYPI,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version=version,
            latest_version=latest,
            message=f"Version '{version}' not found for '{package}'.",
            suggestion=f"Latest version is {latest}.",
        )

    async def verify_npm_package(
        self, package: str, version: str = ""
    ) -> PackageResult:
        """Check if an npm package exists on registry.npmjs.org.

        Flow: Same as PyPI but against npm registry.
        """
        cache_key = self._cache._make_key(
            "npm", f"{package}:{version}" if version else package
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                package, Registry.NPM, version, cached
            )

        return await self._check_npm_package(package, version, cache_key)

    async def _check_npm_package(
        self, package: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual npm registry check."""
        try:
            data = await self._check_npm(package)
        except httpx.TimeoutException:
            return PackageResult(
                package=package,
                registry=Registry.NPM,
                status=VerifyStatus.TIMEOUT,
                severity=Severity.WARN,
                message=f"Timeout verifying '{package}'.",
            )
        except httpx.HTTPError as exc:
            return PackageResult(
                package=package,
                registry=Registry.NPM,
                status=VerifyStatus.ERROR,
                severity=Severity.WARN,
                message=f"HTTP error verifying '{package}': {exc}",
            )

        if data is None:
            suggestion = suggest_npm_package(package)
            await self._cache.set_json(
                cache_key,
                {"exists": False, "latest": "", "deprecated": False},
                settings.cache_ttl_not_found,
            )
            return PackageResult(
                package=package,
                registry=Registry.NPM,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message=f"Package '{package}' not found on npm.",
                suggestion=suggestion,
            )

        return await self._process_npm_response(
            package, version, data, cache_key
        )

    async def _process_npm_response(
        self,
        package: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful npm registry response."""
        dist_tags = data.get("dist-tags", {})
        if not isinstance(dist_tags, dict):
            dist_tags = {}
        latest = str(dist_tags.get("latest", ""))

        deprecated = "deprecated" in str(data.get("description", "")).lower()

        await self._cache.set_json(
            self._cache._make_key("npm", package),
            {"exists": True, "latest": latest, "deprecated": deprecated},
            settings.cache_ttl_package_exists,
        )

        if version:
            return self._check_npm_version(
                package, version, data, latest
            )

        return PackageResult(
            package=package,
            registry=Registry.NPM,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' exists on npm.",
        )

    def _check_npm_version(
        self,
        package: str,
        version: str,
        data: dict[str, object],
        latest: str,
    ) -> PackageResult:
        """Check if a specific version exists on npm."""
        versions = data.get("versions", {})
        if not isinstance(versions, dict):
            versions = {}

        if version in versions:
            return PackageResult(
                package=package,
                registry=Registry.NPM,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                requested_version=version,
                latest_version=latest,
                message=f"Package '{package}@{version}' verified.",
            )

        return PackageResult(
            package=package,
            registry=Registry.NPM,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version=version,
            latest_version=latest,
            message=f"Version '{version}' not found for '{package}'.",
            suggestion=f"Latest version is {latest}.",
        )

    async def verify_packages(
        self,
        language: Language,
        packages: list[str],
        requirements: str = "",
    ) -> list[PackageResult]:
        """Verify a batch of packages concurrently.

        Parses requirements for version pins, then fans out verification
        with asyncio.gather using a semaphore for rate limiting.
        """
        version_map = parse_requirements_txt(requirements) if requirements else {}
        semaphore = asyncio.Semaphore(_SEMAPHORE_LIMIT)

        async def verify_one(pkg: str) -> PackageResult:
            async with semaphore:
                version = version_map.get(pkg.lower(), "")
                return await self._verify_single(language, pkg, version)

        results = await asyncio.gather(
            *[verify_one(pkg) for pkg in packages]
        )
        return list(results)

    async def _verify_single(
        self, language: Language, package: str, version: str
    ) -> PackageResult:
        """Route to the correct registry verifier."""
        try:
            if language in (Language.PYTHON,):
                return await self.verify_python_package(package, version)
            if language in (Language.JAVASCRIPT, Language.TYPESCRIPT):
                return await self.verify_npm_package(package, version)
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.SKIPPED,
                severity=Severity.INFO,
                message=f"Registry verification not supported for {language}.",
            )
        except httpx.TimeoutException:
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.TIMEOUT,
                severity=Severity.WARN,
                message=f"Timeout verifying '{package}'.",
            )
        except httpx.HTTPError as exc:
            return PackageResult(
                package=package,
                registry=Registry.PYPI,
                status=VerifyStatus.ERROR,
                severity=Severity.WARN,
                message=f"HTTP error verifying '{package}': {exc}",
            )

    async def _check_pypi(self, package: str) -> dict[str, object] | None:
        """Raw PyPI API call. Returns JSON response or None on 404/error."""
        url = settings.pypi_url.format(package=package)
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("pypi_timeout", package=package)
            raise
        except httpx.HTTPError as exc:
            logger.warning("pypi_error", package=package, error=str(exc))
            raise

    async def _check_npm(self, package: str) -> dict[str, object] | None:
        """Raw npm registry call. Returns JSON response or None on 404/error."""
        url = settings.npm_url.format(package=package)
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("npm_timeout", package=package)
            raise
        except httpx.HTTPError as exc:
            logger.warning("npm_error", package=package, error=str(exc))
            raise

    def _build_cached_result(
        self,
        package: str,
        registry: Registry,
        version: str,
        cached: dict[str, str | bool | int | float],
    ) -> PackageResult:
        """Build a PackageResult from cached data."""
        exists = bool(cached.get("exists", False))
        latest = str(cached.get("latest", ""))
        deprecated = bool(cached.get("deprecated", False))

        if not exists:
            return PackageResult(
                package=package,
                registry=registry,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message=f"Package '{package}' not found (cached).",
                cached=True,
            )

        if deprecated:
            return PackageResult(
                package=package,
                registry=registry,
                status=VerifyStatus.DEPRECATED,
                severity=Severity.WARN,
                latest_version=latest,
                message=f"Package '{package}' is deprecated (cached).",
                cached=True,
            )

        return PackageResult(
            package=package,
            registry=registry,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' verified (cached).",
            cached=True,
        )
