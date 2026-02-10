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
    suggest_npm_package,
    suggest_pypi_package,
)

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
            if language == Language.GO:
                return await self.verify_go_module(package, version)
            if language == Language.RUST:
                return await self.verify_crates_package(package, version)
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
            return PackageResult(
                package=module,
                registry=Registry.GO_PROXY,
                status=VerifyStatus.TIMEOUT,
                severity=Severity.WARN,
                message=f"Timeout verifying '{module}'.",
            )
        except httpx.HTTPError as exc:
            return PackageResult(
                package=module,
                registry=Registry.GO_PROXY,
                status=VerifyStatus.ERROR,
                severity=Severity.WARN,
                message=f"HTTP error verifying '{module}': {exc}",
            )

        if data is None:
            suggestion = suggest_go_module(module)
            await self._cache.set_json(
                cache_key,
                {"exists": False, "latest": "", "deprecated": False},
                settings.cache_ttl_not_found,
            )
            return PackageResult(
                package=module,
                registry=Registry.GO_PROXY,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message=f"Module '{module}' not found on Go proxy.",
                suggestion=suggestion,
            )

        return await self._process_go_response(
            module, version, data, cache_key
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
        except (httpx.TimeoutException, httpx.HTTPError):
            pass

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

    _CRATES_USER_AGENT: str = "CodeTrust/1.0.0 (https://github.com/codetrust)"

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
            return PackageResult(
                package=crate,
                registry=Registry.CRATES,
                status=VerifyStatus.TIMEOUT,
                severity=Severity.WARN,
                message=f"Timeout verifying '{crate}'.",
            )
        except httpx.HTTPError as exc:
            return PackageResult(
                package=crate,
                registry=Registry.CRATES,
                status=VerifyStatus.ERROR,
                severity=Severity.WARN,
                message=f"HTTP error verifying '{crate}': {exc}",
            )

        if data is None:
            suggestion = suggest_crates_package(crate)
            await self._cache.set_json(
                cache_key,
                {"exists": False, "latest": "", "deprecated": False},
                settings.cache_ttl_not_found,
            )
            return PackageResult(
                package=crate,
                registry=Registry.CRATES,
                status=VerifyStatus.NOT_FOUND,
                severity=Severity.BLOCK,
                message=f"Crate '{crate}' not found on crates.io.",
                suggestion=suggestion,
            )

        return await self._process_crates_response(
            crate, version, data, cache_key
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
                headers={"User-Agent": self._CRATES_USER_AGENT},
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
