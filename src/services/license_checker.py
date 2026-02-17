"""License compliance service — extracts and classifies dependency licenses.

Piggybacks on existing registry API responses (PyPI, npm) to extract
license information. Flags copyleft licenses (GPL, AGPL) that may be
incompatible with commercial use.

This is a paid feature in Snyk, FOSSA, and WhiteSource — CodeTrust provides it free.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum

import httpx
import structlog

from src.models.enums import Language, Severity
from src.services.cache import CacheService  # noqa: TC001 — used at runtime

logger = structlog.get_logger()

CACHE_TTL_LICENSE = 86400  # 24 hours — licenses rarely change
_SEMAPHORE_LIMIT = 20
_REQUEST_TIMEOUT = 10.0


class LicenseRisk(str, Enum):  # noqa: UP042 — StrEnum requires Python 3.11+
    """License risk classification."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak_copyleft"
    STRONG_COPYLEFT = "strong_copyleft"
    NETWORK_COPYLEFT = "network_copyleft"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


# License classification database.
# Keys are normalized (uppercase, stripped) substrings.
PERMISSIVE_LICENSES: frozenset[str] = frozenset({
    "MIT",
    "BSD",
    "ISC",
    "APACHE",
    "ZLIB",
    "UNLICENSE",
    "CC0",
    "WTFPL",
    "0BSD",
    "BOOST",
    "PSF",
    "PYTHON",
    "ARTISTIC",
    "UNICODE",
    "X11",
    "CURL",
    "JSON",
    "BLUE OAK",
})

WEAK_COPYLEFT_LICENSES: frozenset[str] = frozenset({
    "LGPL",
    "MPL",
    "EPL",
    "CDDL",
    "CPL",
    "EUPL",
})

STRONG_COPYLEFT_LICENSES: frozenset[str] = frozenset({
    "GPL-2",
    "GPL-3",
    "GPLV2",
    "GPLV3",
    "GNU GENERAL PUBLIC LICENSE",
})

NETWORK_COPYLEFT_LICENSES: frozenset[str] = frozenset({
    "AGPL",
    "SSPL",
    "OSL",
})

# Map of ecosystem to registry URL template.
ECOSYSTEM_URLS: dict[str, str] = {
    "PyPI": "https://pypi.org/pypi/{package}/json",
    "npm": "https://registry.npmjs.org/{package}",
}


@dataclass(frozen=True)
class LicenseInfo:
    """License information for a single package."""

    package: str
    ecosystem: str
    license_name: str
    risk: LicenseRisk
    spdx_id: str = ""

    @property
    def severity(self) -> Severity:
        """Map license risk to CodeTrust severity."""
        if self.risk == LicenseRisk.NETWORK_COPYLEFT:
            return Severity.BLOCK
        if self.risk == LicenseRisk.STRONG_COPYLEFT:
            return Severity.BLOCK
        if self.risk == LicenseRisk.WEAK_COPYLEFT:
            return Severity.WARN
        if self.risk == LicenseRisk.UNKNOWN:
            return Severity.WARN
        return Severity.INFO


@dataclass
class LicenseScanResponse:
    """Aggregated license scan results."""

    total_packages: int = 0
    permissive_count: int = 0
    weak_copyleft_count: int = 0
    strong_copyleft_count: int = 0
    network_copyleft_count: int = 0
    unknown_count: int = 0
    risk_packages: list[LicenseInfo] = field(default_factory=list)
    all_licenses: list[LicenseInfo] = field(default_factory=list)
    compliant: bool = True
    latency_ms: int = 0


def classify_license(raw_license: str) -> tuple[LicenseRisk, str]:
    """Classify a license string into a risk category.

    Args:
        raw_license: The raw license string from the registry.

    Returns:
        Tuple of (LicenseRisk, normalized_spdx_id).
    """
    if not raw_license or raw_license.strip().upper() in ("UNKNOWN", "NONE", ""):
        return LicenseRisk.UNKNOWN, ""

    normalized = raw_license.strip().upper()

    # Check network copyleft first (most restrictive).
    for pattern in NETWORK_COPYLEFT_LICENSES:
        if pattern in normalized:
            return LicenseRisk.NETWORK_COPYLEFT, raw_license.strip()

    # Check strong copyleft (but exclude LGPL which is weak).
    for pattern in STRONG_COPYLEFT_LICENSES:
        if pattern in normalized:
            # Make sure it's not LGPL.
            if "LGPL" in normalized or "LESSER" in normalized:
                continue
            return LicenseRisk.STRONG_COPYLEFT, raw_license.strip()

    # Check weak copyleft.
    for pattern in WEAK_COPYLEFT_LICENSES:
        if pattern in normalized:
            return LicenseRisk.WEAK_COPYLEFT, raw_license.strip()

    # Check permissive.
    for pattern in PERMISSIVE_LICENSES:
        if pattern in normalized:
            return LicenseRisk.PERMISSIVE, raw_license.strip()

    # Check for "GPL" alone (without L prefix) — strong copyleft.
    if "GPL" in normalized and "LGPL" not in normalized:
        return LicenseRisk.STRONG_COPYLEFT, raw_license.strip()

    return LicenseRisk.UNKNOWN, raw_license.strip()


class LicenseService:
    """Checks package licenses against registry APIs.

    Extracts license data from PyPI and npm responses. Classifies
    each license by risk level and flags potential compliance issues.
    """

    def __init__(
        self,
        cache: CacheService,
        http_client: httpx.AsyncClient,
    ) -> None:
        """Initialize with shared cache and HTTP client."""
        self._cache = cache
        self._http = http_client
        self._semaphore = asyncio.Semaphore(_SEMAPHORE_LIMIT)

    async def check_package(
        self,
        package: str,
        ecosystem: str,
    ) -> LicenseInfo:
        """Check the license of a single package.

        Args:
            package: Package name.
            ecosystem: Registry ecosystem ('PyPI' or 'npm').

        Returns:
            LicenseInfo with the classification.
        """
        cache_key = f"codetrust:license:{ecosystem}:{package}"

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._deserialize(cached, package, ecosystem)

        async with self._semaphore:
            return await self._fetch_license(package, ecosystem, cache_key)

    async def check_packages(
        self,
        language: Language,
        packages: list[str],
    ) -> LicenseScanResponse:
        """Check licenses for multiple packages in parallel.

        Args:
            language: Programming language.
            packages: List of package names.

        Returns:
            LicenseScanResponse with aggregated results.
        """
        ecosystem = self._language_to_ecosystem(language)
        if not ecosystem:
            logger.info("license_unsupported_language", language=language)
            return LicenseScanResponse(total_packages=len(packages))

        import time
        start = time.monotonic()

        tasks = [self.check_package(pkg, ecosystem) for pkg in packages]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed: list[LicenseInfo] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(
                    "license_check_error",
                    package=packages[i],
                    error=str(result),
                )
                processed.append(LicenseInfo(
                    package=packages[i],
                    ecosystem=ecosystem,
                    license_name="",
                    risk=LicenseRisk.UNKNOWN,
                ))
            else:
                processed.append(result)

        elapsed_ms = int((time.monotonic() - start) * 1000)
        return self._build_response(processed, elapsed_ms)

    async def _fetch_license(
        self,
        package: str,
        ecosystem: str,
        cache_key: str,
    ) -> LicenseInfo:
        """Fetch license from the package registry."""
        url_template = ECOSYSTEM_URLS.get(ecosystem)
        if not url_template:
            return LicenseInfo(
                package=package,
                ecosystem=ecosystem,
                license_name="",
                risk=LicenseRisk.UNKNOWN,
            )

        url = url_template.format(package=package)
        try:
            response = await self._http.get(url, timeout=_REQUEST_TIMEOUT)
            if response.status_code != 200:
                return LicenseInfo(
                    package=package,
                    ecosystem=ecosystem,
                    license_name="",
                    risk=LicenseRisk.UNKNOWN,
                )
            data = response.json()
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.warning(
                "license_fetch_error",
                package=package,
                ecosystem=ecosystem,
                error=str(exc),
            )
            return LicenseInfo(
                package=package,
                ecosystem=ecosystem,
                license_name="",
                risk=LicenseRisk.UNKNOWN,
            )

        raw_license = self._extract_license(data, ecosystem)
        risk, spdx_id = classify_license(raw_license)

        result = LicenseInfo(
            package=package,
            ecosystem=ecosystem,
            license_name=raw_license,
            risk=risk,
            spdx_id=spdx_id,
        )

        # Cache the result.
        await self._cache.set_json(
            cache_key,
            {
                "license_name": raw_license,
                "risk": risk.value,
                "spdx_id": spdx_id,
            },
            CACHE_TTL_LICENSE,
        )

        if risk in (LicenseRisk.STRONG_COPYLEFT, LicenseRisk.NETWORK_COPYLEFT):
            logger.info(
                "license_risk_found",
                package=package,
                license=raw_license,
                risk=risk.value,
            )

        return result

    def _extract_license(
        self,
        data: dict[str, object],
        ecosystem: str,
    ) -> str:
        """Extract the license string from a registry response."""
        if ecosystem == "PyPI":
            return self._extract_pypi_license(data)
        if ecosystem == "npm":
            return self._extract_npm_license(data)
        return ""

    def _extract_pypi_license(self, data: dict[str, object]) -> str:
        """Extract license from a PyPI JSON response.

        PyPI provides license in info.license and info.classifiers.
        """
        info = data.get("info", {})
        if not isinstance(info, dict):
            return ""

        # Try the license field first.
        license_str = str(info.get("license", "") or "")
        if license_str and license_str.upper() not in ("UNKNOWN", "NONE", ""):
            return license_str.strip()

        # Fall back to classifiers.
        classifiers = info.get("classifiers", [])
        if isinstance(classifiers, list):
            for classifier in classifiers:
                c = str(classifier)
                if c.startswith("License :: OSI Approved ::"):
                    # e.g. "License :: OSI Approved :: MIT License"
                    parts = c.split(" :: ")
                    if len(parts) >= 3:
                        return parts[-1].strip()

        return ""

    def _extract_npm_license(self, data: dict[str, object]) -> str:
        """Extract license from an npm registry response.

        npm provides license as a string or object with 'type' field.
        """
        license_field = data.get("license", "")
        if isinstance(license_field, str):
            return license_field.strip()
        if isinstance(license_field, dict):
            return str(license_field.get("type", "")).strip()
        return ""

    def _deserialize(
        self,
        data: dict[str, str | bool | int | float] | None,
        package: str,
        ecosystem: str,
    ) -> LicenseInfo:
        """Deserialize a cached license result."""
        if data is None:
            return LicenseInfo(
                package=package,
                ecosystem=ecosystem,
                license_name="",
                risk=LicenseRisk.UNKNOWN,
            )

        license_name = str(data.get("license_name", ""))
        risk_str = str(data.get("risk", "unknown"))
        try:
            risk = LicenseRisk(risk_str)
        except ValueError:
            risk = LicenseRisk.UNKNOWN
        spdx_id = str(data.get("spdx_id", ""))

        return LicenseInfo(
            package=package,
            ecosystem=ecosystem,
            license_name=license_name,
            risk=risk,
            spdx_id=spdx_id,
        )

    @staticmethod
    def _language_to_ecosystem(language: Language) -> str:
        """Map CodeTrust Language to registry ecosystem."""
        mapping: dict[Language, str] = {
            Language.PYTHON: "PyPI",
            Language.JAVASCRIPT: "npm",
            Language.TYPESCRIPT: "npm",
        }
        return mapping.get(language, "")

    def _build_response(
        self,
        results: list[LicenseInfo],
        latency_ms: int,
    ) -> LicenseScanResponse:
        """Build aggregated license scan response."""
        permissive = 0
        weak_copyleft = 0
        strong_copyleft = 0
        network_copyleft = 0
        unknown = 0
        risk_packages: list[LicenseInfo] = []

        for r in results:
            if r.risk == LicenseRisk.PERMISSIVE:
                permissive += 1
            elif r.risk == LicenseRisk.WEAK_COPYLEFT:
                weak_copyleft += 1
                risk_packages.append(r)
            elif r.risk == LicenseRisk.STRONG_COPYLEFT:
                strong_copyleft += 1
                risk_packages.append(r)
            elif r.risk == LicenseRisk.NETWORK_COPYLEFT:
                network_copyleft += 1
                risk_packages.append(r)
            else:
                unknown += 1
                risk_packages.append(r)

        compliant = strong_copyleft == 0 and network_copyleft == 0

        return LicenseScanResponse(
            total_packages=len(results),
            permissive_count=permissive,
            weak_copyleft_count=weak_copyleft,
            strong_copyleft_count=strong_copyleft,
            network_copyleft_count=network_copyleft,
            unknown_count=unknown,
            risk_packages=risk_packages,
            all_licenses=results,
            compliant=compliant,
            latency_ms=latency_ms,
        )
