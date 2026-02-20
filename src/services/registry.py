# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Layer 2: Package registry verification service (PyPI, npm, Go proxy, crates.io)."""

import asyncio

import httpx
import structlog

from src.config import settings
from src.models.enums import Language, Registry, Severity, VerifyStatus
from src.models.responses import PackageResult
from src.services.cache import CacheService
from src.utils.parsers import parse_requirements_txt
from src.utils.similarity import (
    suggest_crates_package,
    suggest_go_module,
    suggest_maven_package,
    suggest_npm_package,
    suggest_nuget_package,
    suggest_packagist_package,
    suggest_pypi_package,
    suggest_rubygems_package,
)

logger = structlog.get_logger()

# Concurrency limit for batch registry calls
_SEMAPHORE_LIMIT: int = 20


def _timeout_result(package: str, registry: Registry) -> PackageResult:
    """Build a PackageResult for a registry timeout."""
    return PackageResult(
        package=package,
        registry=registry,
        status=VerifyStatus.TIMEOUT,
        severity=Severity.WARN,
        message=f"Timeout verifying '{package}'.",
    )


def _http_error_result(
    package: str, registry: Registry, exc: httpx.HTTPError,
) -> PackageResult:
    """Build a PackageResult for an HTTP error."""
    return PackageResult(
        package=package,
        registry=registry,
        status=VerifyStatus.ERROR,
        severity=Severity.WARN,
        message=f"HTTP error verifying '{package}': {exc}",
    )


async def _not_found_result(
    package: str,
    registry: Registry,
    suggestion: str,
    cache: CacheService,
    cache_key: str,
) -> PackageResult:
    """Build a PackageResult for a not-found package and cache it."""
    await cache.set_json(
        cache_key,
        {"exists": False, "latest": "", "deprecated": False},
        settings.cache_ttl_not_found,
    )
    return PackageResult(
        package=package,
        registry=registry,
        status=VerifyStatus.NOT_FOUND,
        severity=Severity.BLOCK,
        message=f"Package '{package}' not found on {registry.value}.",
        suggestion=suggestion,
    )


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
            return _timeout_result(package, Registry.PYPI)
        except httpx.HTTPError as exc:
            return _http_error_result(package, Registry.PYPI, exc)

        if data is None:
            return await _not_found_result(
                package, Registry.PYPI,
                suggest_pypi_package(package), self._cache, cache_key,
            )

        return await self._process_pypi_response(
            package, version, data, cache_key,
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
        deprecated = self._is_pypi_deprecated(info)

        await self._cache_package("pypi", package, latest, deprecated)

        if deprecated:
            return self._deprecated_result(package, Registry.PYPI, latest)

        if version:
            return self._check_pypi_version(
                package, version, data, latest, cache_key,
            )

        return self._verified_result(package, Registry.PYPI, latest)

    @staticmethod
    def _is_pypi_deprecated(info: dict[str, object]) -> bool:
        """Check if a PyPI package is deprecated via classifiers."""
        classifiers = info.get("classifiers", [])
        if isinstance(classifiers, list):
            return any("Inactive" in str(c) for c in classifiers)
        return False

    async def _cache_package(
        self, registry_prefix: str, package: str,
        latest: str, deprecated: bool,
    ) -> None:
        """Cache package existence data."""
        await self._cache.set_json(
            self._cache._make_key(registry_prefix, package),
            {"exists": True, "latest": latest, "deprecated": deprecated},
            settings.cache_ttl_package_exists,
        )

    @staticmethod
    def _deprecated_result(
        package: str, registry: Registry, latest: str,
    ) -> PackageResult:
        """Build a PackageResult for a deprecated package."""
        return PackageResult(
            package=package,
            registry=registry,
            status=VerifyStatus.DEPRECATED,
            severity=Severity.WARN,
            latest_version=latest,
            message=f"Package '{package}' is deprecated.",
        )

    @staticmethod
    def _verified_result(
        package: str, registry: Registry, latest: str,
    ) -> PackageResult:
        """Build a PackageResult for a verified package."""
        return PackageResult(
            package=package,
            registry=registry,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' exists on {registry.value}.",
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
            return _timeout_result(package, Registry.NPM)
        except httpx.HTTPError as exc:
            return _http_error_result(package, Registry.NPM, exc)

        if data is None:
            return await _not_found_result(
                package, Registry.NPM,
                suggest_npm_package(package), self._cache, cache_key,
            )

        return await self._process_npm_response(
            package, version, data, cache_key,
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
            """Verify a single package within the semaphore."""
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
            if language == Language.GO:
                return await self.verify_go_module(package, version)
            if language == Language.RUST:
                return await self.verify_crates_package(package, version)
            if language == Language.RUBY:
                return await self.verify_rubygems_package(package, version)
            if language == Language.PHP:
                return await self.verify_packagist_package(package, version)
            if language == Language.JAVA:
                return await self.verify_maven_package(package, version)
            if language == Language.CSHARP:
                return await self.verify_nuget_package(package, version)
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

    # --- Go proxy verification ---

    async def verify_go_module(
        self, module: str, version: str = ""
    ) -> PackageResult:
        """Check if a Go module exists on proxy.golang.org.

        Flow:
        1. Check cache
        2. If miss: GET proxy.golang.org/{module}/@latest
        3. If 200: exists -> check version if specified
        4. If 404/410: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "go", f"{module}:{version}" if version else module
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                module, Registry.GO_PROXY, version, cached
            )

        return await self._check_go_module(module, version, cache_key)

    async def _check_go_module(
        self, module: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual Go proxy API check."""
        try:
            data = await self._check_go_proxy(module)
        except httpx.TimeoutException:
            return _timeout_result(module, Registry.GO_PROXY)
        except httpx.HTTPError as exc:
            return _http_error_result(module, Registry.GO_PROXY, exc)

        if data is None:
            return await _not_found_result(
                module, Registry.GO_PROXY,
                suggest_go_module(module), self._cache, cache_key,
            )

        return await self._process_go_response(
            module, version, data, cache_key,
        )

    async def _process_go_response(
        self,
        module: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful Go proxy response."""
        latest = str(data.get("Version", ""))

        await self._cache.set_json(
            self._cache._make_key("go", module),
            {"exists": True, "latest": latest, "deprecated": False},
            settings.cache_ttl_package_exists,
        )

        if version:
            return await self._check_go_version(module, version, latest)

        return PackageResult(
            package=module,
            registry=Registry.GO_PROXY,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Module '{module}' exists on Go proxy.",
        )

    async def _check_go_version(
        self, module: str, version: str, latest: str
    ) -> PackageResult:
        """Check if a specific Go module version exists."""
        try:
            url = settings.go_proxy_url.replace(
                "/@latest", f"/@v/{version}.info"
            ).format(package=module)
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                return PackageResult(
                    package=module,
                    registry=Registry.GO_PROXY,
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    requested_version=version,
                    latest_version=latest,
                    message=f"Module '{module}@{version}' verified.",
                )
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.debug("go_proxy_lookup_failed", module=module, error=str(exc))

        return PackageResult(
            package=module,
            registry=Registry.GO_PROXY,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version=version,
            latest_version=latest,
            message=f"Version '{version}' not found for '{module}'.",
            suggestion=f"Latest version is {latest}.",
        )

    async def _check_go_proxy(
        self, module: str
    ) -> dict[str, object] | None:
        """Raw Go proxy call. Returns JSON or None on 404/410."""
        url = settings.go_proxy_url.format(package=module)
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("go_proxy_timeout", module=module)
            raise
        except httpx.HTTPError as exc:
            logger.warning("go_proxy_error", module=module, error=str(exc))
            raise

    # --- crates.io verification ---

    @property
    def _crates_user_agent(self) -> str:
        """Build crates.io User-Agent from config."""
        return f"CodeTrust/{settings.version} ({settings.tool_info_uri})"

    async def verify_crates_package(
        self, crate: str, version: str = ""
    ) -> PackageResult:
        """Check if a Rust crate exists on crates.io.

        Flow:
        1. Check cache
        2. If miss: GET crates.io/api/v1/crates/{crate}
        3. If 200: exists -> check version if specified
        4. If 404: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "crates", f"{crate}:{version}" if version else crate
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                crate, Registry.CRATES, version, cached
            )

        return await self._check_crates_package(crate, version, cache_key)

    async def _check_crates_package(
        self, crate: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual crates.io API check."""
        try:
            data = await self._check_crates(crate)
        except httpx.TimeoutException:
            return _timeout_result(crate, Registry.CRATES)
        except httpx.HTTPError as exc:
            return _http_error_result(crate, Registry.CRATES, exc)

        if data is None:
            return await _not_found_result(
                crate, Registry.CRATES,
                suggest_crates_package(crate), self._cache, cache_key,
            )

        return await self._process_crates_response(
            crate, version, data, cache_key,
        )

    async def _process_crates_response(
        self,
        crate: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful crates.io response."""
        crate_data = data.get("crate", {})
        if not isinstance(crate_data, dict):
            crate_data = {}
        latest = str(crate_data.get("max_version", ""))

        await self._cache.set_json(
            self._cache._make_key("crates", crate),
            {"exists": True, "latest": latest, "deprecated": False},
            settings.cache_ttl_package_exists,
        )

        if version:
            return self._check_crates_version(
                crate, version, data, latest
            )

        return PackageResult(
            package=crate,
            registry=Registry.CRATES,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Crate '{crate}' exists on crates.io.",
        )

    def _check_crates_version(
        self,
        crate: str,
        version: str,
        data: dict[str, object],
        latest: str,
    ) -> PackageResult:
        """Check if a specific version exists on crates.io."""
        versions_list = data.get("versions", [])
        if not isinstance(versions_list, list):
            versions_list = []

        version_nums = [
            str(v.get("num", ""))
            for v in versions_list
            if isinstance(v, dict)
        ]

        if version in version_nums:
            return PackageResult(
                package=crate,
                registry=Registry.CRATES,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                requested_version=version,
                latest_version=latest,
                message=f"Crate '{crate}=={version}' verified.",
            )

        return PackageResult(
            package=crate,
            registry=Registry.CRATES,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version=version,
            latest_version=latest,
            message=f"Version '{version}' not found for '{crate}'.",
            suggestion=f"Latest version is {latest}.",
        )

    async def _check_crates(
        self, crate: str
    ) -> dict[str, object] | None:
        """Raw crates.io API call. Returns JSON or None on 404."""
        url = settings.crates_url.format(package=crate)
        try:
            response = await self._http.get(
                url,
                timeout=settings.http_timeout,
                headers={"User-Agent": self._crates_user_agent},
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("crates_timeout", crate=crate)
            raise
        except httpx.HTTPError as exc:
            logger.warning("crates_error", crate=crate, error=str(exc))
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
            return self._cached_not_found(package, registry)

        if deprecated:
            return self._cached_deprecated(package, registry, latest)

        return self._cached_verified(package, registry, latest)

    @staticmethod
    def _cached_not_found(package: str, registry: Registry) -> PackageResult:
        """Build a cached not-found result."""
        return PackageResult(
            package=package, registry=registry,
            status=VerifyStatus.NOT_FOUND, severity=Severity.BLOCK,
            message=f"Package '{package}' not found (cached).", cached=True,
        )

    @staticmethod
    def _cached_deprecated(
        package: str, registry: Registry, latest: str,
    ) -> PackageResult:
        """Build a cached deprecated result."""
        return PackageResult(
            package=package, registry=registry,
            status=VerifyStatus.DEPRECATED, severity=Severity.WARN,
            latest_version=latest,
            message=f"Package '{package}' is deprecated (cached).", cached=True,
        )

    @staticmethod
    def _cached_verified(
        package: str, registry: Registry, latest: str,
    ) -> PackageResult:
        """Build a cached verified result."""
        return PackageResult(
            package=package, registry=registry,
            status=VerifyStatus.VERIFIED, severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' verified (cached).", cached=True,
        )

    # --- RubyGems verification ---

    async def verify_rubygems_package(
        self, gem: str, version: str = ""
    ) -> PackageResult:
        """Check if a Ruby gem exists on rubygems.org.

        Flow:
        1. Check cache
        2. If miss: GET rubygems.org/api/v1/gems/{gem}.json
        3. If 200: exists -> check version if specified
        4. If 404: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "rubygems", f"{gem}:{version}" if version else gem
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                gem, Registry.RUBYGEMS, version, cached
            )

        return await self._check_rubygems_package(gem, version, cache_key)

    async def _check_rubygems_package(
        self, gem: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual RubyGems API check."""
        try:
            data = await self._check_rubygems(gem)
        except httpx.TimeoutException:
            return _timeout_result(gem, Registry.RUBYGEMS)
        except httpx.HTTPError as exc:
            return _http_error_result(gem, Registry.RUBYGEMS, exc)

        if data is None:
            return await _not_found_result(
                gem, Registry.RUBYGEMS,
                suggest_rubygems_package(gem), self._cache, cache_key,
            )

        return await self._process_rubygems_response(
            gem, version, data, cache_key,
        )

    async def _process_rubygems_response(
        self,
        gem: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful RubyGems response."""
        latest = str(data.get("version", ""))

        await self._cache.set_json(
            self._cache._make_key("rubygems", gem),
            {"exists": True, "latest": latest, "deprecated": False},
            settings.cache_ttl_package_exists,
        )

        if version:
            return await self._check_rubygems_version(gem, version, latest)

        return PackageResult(
            package=gem,
            registry=Registry.RUBYGEMS,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Gem '{gem}' exists on rubygems.org.",
        )

    async def _check_rubygems_version(
        self, gem: str, version: str, latest: str
    ) -> PackageResult:
        """Check if a specific gem version exists on RubyGems."""
        try:
            url = f"https://rubygems.org/api/v1/versions/{gem}.json"
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                versions_data: list[dict[str, object]] = response.json()
                version_nums = [
                    str(v.get("number", ""))
                    for v in versions_data
                    if isinstance(v, dict)
                ]
                if version in version_nums:
                    return PackageResult(
                        package=gem,
                        registry=Registry.RUBYGEMS,
                        status=VerifyStatus.VERIFIED,
                        severity=Severity.INFO,
                        requested_version=version,
                        latest_version=latest,
                        message=f"Gem '{gem}=={version}' verified.",
                    )
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.debug("rubygems_version_check_failed", gem=gem, error=str(exc))

        return PackageResult(
            package=gem,
            registry=Registry.RUBYGEMS,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version=version,
            latest_version=latest,
            message=f"Version '{version}' not found for '{gem}'.",
            suggestion=f"Latest version is {latest}.",
        )

    async def _check_rubygems(
        self, gem: str
    ) -> dict[str, object] | None:
        """Raw RubyGems API call. Returns JSON or None on 404."""
        url = settings.rubygems_url.format(package=gem)
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("rubygems_timeout", gem=gem)
            raise
        except httpx.HTTPError as exc:
            logger.warning("rubygems_error", gem=gem, error=str(exc))
            raise

    # --- Packagist (PHP) verification ---

    async def verify_packagist_package(
        self, package: str, version: str = ""
    ) -> PackageResult:
        """Check if a PHP package exists on packagist.org.

        Flow:
        1. Check cache
        2. If miss: GET repo.packagist.org/p2/{vendor/package}.json
        3. If 200: exists -> check version if specified
        4. If 404: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "packagist", f"{package}:{version}" if version else package
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                package, Registry.PACKAGIST, version, cached
            )

        return await self._check_packagist_package(package, version, cache_key)

    async def _check_packagist_package(
        self, package: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual Packagist API check."""
        try:
            data = await self._check_packagist(package)
        except httpx.TimeoutException:
            return _timeout_result(package, Registry.PACKAGIST)
        except httpx.HTTPError as exc:
            return _http_error_result(package, Registry.PACKAGIST, exc)

        if data is None:
            return await _not_found_result(
                package, Registry.PACKAGIST,
                suggest_packagist_package(package), self._cache, cache_key,
            )

        return await self._process_packagist_response(
            package, version, data, cache_key,
        )

    async def _process_packagist_response(
        self,
        package: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful Packagist response."""
        packages_data = data.get("packages", {})
        if not isinstance(packages_data, dict):
            packages_data = {}

        versions_list = packages_data.get(package, [])
        if isinstance(versions_list, list) and versions_list:
            latest = str(versions_list[0].get("version", ""))
        else:
            latest = ""

        await self._cache.set_json(
            self._cache._make_key("packagist", package),
            {"exists": True, "latest": latest, "deprecated": False},
            settings.cache_ttl_package_exists,
        )

        if version and versions_list:
            version_nums = [
                str(v.get("version", ""))
                for v in versions_list
                if isinstance(v, dict)
            ]
            if version in version_nums:
                return PackageResult(
                    package=package,
                    registry=Registry.PACKAGIST,
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    requested_version=version,
                    latest_version=latest,
                    message=f"Package '{package}@{version}' verified.",
                )
            return PackageResult(
                package=package,
                registry=Registry.PACKAGIST,
                status=VerifyStatus.VERSION_MISMATCH,
                severity=Severity.WARN,
                requested_version=version,
                latest_version=latest,
                message=f"Version '{version}' not found for '{package}'.",
                suggestion=f"Latest version is {latest}.",
            )

        return PackageResult(
            package=package,
            registry=Registry.PACKAGIST,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' exists on packagist.org.",
        )

    async def _check_packagist(
        self, package: str
    ) -> dict[str, object] | None:
        """Raw Packagist API call. Returns JSON or None on 404."""
        url = settings.packagist_url.format(package=package)
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("packagist_timeout", package=package)
            raise
        except httpx.HTTPError as exc:
            logger.warning("packagist_error", package=package, error=str(exc))
            raise

    # --- Maven Central verification ---

    async def verify_maven_package(
        self, artifact: str, version: str = ""
    ) -> PackageResult:
        """Check if a Maven artifact exists on Maven Central.

        Expects artifact in 'groupId:artifactId' format.

        Flow:
        1. Check cache
        2. If miss: GET search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}
        3. If found: exists -> check version if specified
        4. If not: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "maven", f"{artifact}:{version}" if version else artifact
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                artifact, Registry.MAVEN, version, cached
            )

        return await self._check_maven_package(artifact, version, cache_key)

    async def _check_maven_package(
        self, artifact: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual Maven Central API check."""
        try:
            data = await self._check_maven(artifact)
        except httpx.TimeoutException:
            return _timeout_result(artifact, Registry.MAVEN)
        except httpx.HTTPError as exc:
            return _http_error_result(artifact, Registry.MAVEN, exc)

        if data is None:
            return await _not_found_result(
                artifact, Registry.MAVEN,
                suggest_maven_package(artifact), self._cache, cache_key,
            )

        return await self._process_maven_response(
            artifact, version, data, cache_key,
        )

    async def _process_maven_response(
        self,
        artifact: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful Maven Central response."""
        response_data = data.get("response", {})
        if not isinstance(response_data, dict):
            response_data = {}

        docs = response_data.get("docs", [])
        if not isinstance(docs, list) or not docs:
            return await _not_found_result(
                artifact, Registry.MAVEN,
                suggest_maven_package(artifact), self._cache, cache_key,
            )

        first_doc = docs[0] if isinstance(docs[0], dict) else {}
        latest = str(first_doc.get("latestVersion", ""))

        await self._cache.set_json(
            self._cache._make_key("maven", artifact),
            {"exists": True, "latest": latest, "deprecated": False},
            settings.cache_ttl_package_exists,
        )

        if version:
            version_count = int(first_doc.get("versionCount", 0))
            if version_count > 0:
                return await self._check_maven_version(
                    artifact, version, latest
                )

        return PackageResult(
            package=artifact,
            registry=Registry.MAVEN,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Artifact '{artifact}' exists on Maven Central.",
        )

    async def _check_maven_version(
        self, artifact: str, version: str, latest: str
    ) -> PackageResult:
        """Check if a specific Maven artifact version exists."""
        parts = artifact.split(":")
        if len(parts) != 2:
            return PackageResult(
                package=artifact,
                registry=Registry.MAVEN,
                status=VerifyStatus.VERSION_MISMATCH,
                severity=Severity.WARN,
                requested_version=version,
                latest_version=latest,
                message=f"Version '{version}' not found for '{artifact}'.",
                suggestion=f"Latest version is {latest}.",
            )

        group_id, artifact_id = parts
        try:
            url = (
                f"https://search.maven.org/solrsearch/select"
                f"?q=g:{group_id}+AND+a:{artifact_id}+AND+v:{version}"
                f"&rows=1&wt=json"
            )
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                data: dict[str, object] = response.json()
                resp = data.get("response", {})
                if isinstance(resp, dict) and resp.get("numFound", 0):
                    return PackageResult(
                        package=artifact,
                        registry=Registry.MAVEN,
                        status=VerifyStatus.VERIFIED,
                        severity=Severity.INFO,
                        requested_version=version,
                        latest_version=latest,
                        message=f"Artifact '{artifact}:{version}' verified.",
                    )
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.debug(
                "maven_version_check_failed", artifact=artifact, error=str(exc)
            )

        return PackageResult(
            package=artifact,
            registry=Registry.MAVEN,
            status=VerifyStatus.VERSION_MISMATCH,
            severity=Severity.WARN,
            requested_version=version,
            latest_version=latest,
            message=f"Version '{version}' not found for '{artifact}'.",
            suggestion=f"Latest version is {latest}.",
        )

    async def _check_maven(
        self, artifact: str
    ) -> dict[str, object] | None:
        """Raw Maven Central API call. Returns JSON or None on error."""
        parts = artifact.split(":")
        if len(parts) != 2:
            return None

        group_id, artifact_id = parts
        url = settings.maven_url.format(group=group_id, artifact=artifact_id)
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("maven_timeout", artifact=artifact)
            raise
        except httpx.HTTPError as exc:
            logger.warning("maven_error", artifact=artifact, error=str(exc))
            raise

    # --- NuGet verification ---

    async def verify_nuget_package(
        self, package: str, version: str = ""
    ) -> PackageResult:
        """Check if a .NET package exists on nuget.org.

        Flow:
        1. Check cache
        2. If miss: GET api.nuget.org/v3-flatcontainer/{package}/index.json
        3. If 200: exists -> check version if specified
        4. If 404: NOT_FOUND -> fuzzy match suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key(
            "nuget", f"{package}:{version}" if version else package
        )

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(
                package, Registry.NUGET, version, cached
            )

        return await self._check_nuget_package(package, version, cache_key)

    async def _check_nuget_package(
        self, package: str, version: str, cache_key: str
    ) -> PackageResult:
        """Perform the actual NuGet API check."""
        try:
            data = await self._check_nuget(package)
        except httpx.TimeoutException:
            return _timeout_result(package, Registry.NUGET)
        except httpx.HTTPError as exc:
            return _http_error_result(package, Registry.NUGET, exc)

        if data is None:
            return await _not_found_result(
                package, Registry.NUGET,
                suggest_nuget_package(package), self._cache, cache_key,
            )

        return await self._process_nuget_response(
            package, version, data, cache_key,
        )

    async def _process_nuget_response(
        self,
        package: str,
        version: str,
        data: dict[str, object],
        cache_key: str,
    ) -> PackageResult:
        """Process a successful NuGet response."""
        versions_list = data.get("versions", [])
        if not isinstance(versions_list, list):
            versions_list = []

        latest = str(versions_list[-1]) if versions_list else ""

        await self._cache.set_json(
            self._cache._make_key("nuget", package),
            {"exists": True, "latest": latest, "deprecated": False},
            settings.cache_ttl_package_exists,
        )

        if version:
            if version.lower() in [v.lower() for v in versions_list if isinstance(v, str)]:
                return PackageResult(
                    package=package,
                    registry=Registry.NUGET,
                    status=VerifyStatus.VERIFIED,
                    severity=Severity.INFO,
                    requested_version=version,
                    latest_version=latest,
                    message=f"Package '{package}@{version}' verified.",
                )
            return PackageResult(
                package=package,
                registry=Registry.NUGET,
                status=VerifyStatus.VERSION_MISMATCH,
                severity=Severity.WARN,
                requested_version=version,
                latest_version=latest,
                message=f"Version '{version}' not found for '{package}'.",
                suggestion=f"Latest version is {latest}.",
            )

        return PackageResult(
            package=package,
            registry=Registry.NUGET,
            status=VerifyStatus.VERIFIED,
            severity=Severity.INFO,
            latest_version=latest,
            message=f"Package '{package}' exists on nuget.org.",
        )

    async def _check_nuget(
        self, package: str
    ) -> dict[str, object] | None:
        """Raw NuGet API call. Returns JSON or None on 404."""
        url = settings.nuget_url.format(package=package.lower())
        try:
            response = await self._http.get(
                url, timeout=settings.http_timeout
            )
            if response.status_code == 200:
                result: dict[str, object] = response.json()
                return result
            return None
        except httpx.TimeoutException:
            logger.warning("nuget_timeout", package=package)
            raise
        except httpx.HTTPError as exc:
            logger.warning("nuget_error", package=package, error=str(exc))
            raise
