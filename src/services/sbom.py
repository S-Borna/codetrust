# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""SBOM generation service for CycloneDX and SPDX JSON outputs."""

from __future__ import annotations

import datetime
import json
import time
from dataclasses import dataclass

from src.models.enums import Language

CYCLOENDX_SPEC_VERSION = "1.5"
SPDX_SPEC_VERSION = "SPDX-2.3"
SBOM_TOOL_NAME = "CodeTrust"
SBOM_TOOL_VERSION = "2.8.2"
PACKAGE_VERSION_UNKNOWN = "unknown"
SPDX_NO_ASSERTION = "NOASSERTION"


@dataclass(frozen=True)
class SbomResult:
    """Generated SBOM documents and metadata."""

    ecosystem: str
    document_name: str
    component_count: int
    cyclonedx_json: str
    spdx_json: str
    latency_ms: int


@dataclass(frozen=True)
class PackageEntry:
    """Normalized package identity for SBOM rendering."""

    name: str
    version: str


class SbomService:
    """Builds deterministic CycloneDX and SPDX JSON documents."""

    def generate(
        self,
        language: Language,
        packages: list[str],
        versions: dict[str, str],
        document_name: str,
    ) -> SbomResult:
        """Generate both CycloneDX and SPDX documents for the package list."""
        started = time.monotonic()
        ecosystem = _language_to_ecosystem(language)
        normalized = _normalize_packages(packages, versions)
        cyclonedx = _build_cyclonedx(document_name, ecosystem, normalized)
        spdx = _build_spdx(document_name, ecosystem, normalized)
        return SbomResult(
            ecosystem=ecosystem,
            document_name=document_name,
            component_count=len(normalized),
            cyclonedx_json=json.dumps(cyclonedx, sort_keys=True),
            spdx_json=json.dumps(spdx, sort_keys=True),
            latency_ms=int((time.monotonic() - started) * 1000),
        )


def _language_to_ecosystem(language: Language) -> str:
    """Map a language to SBOM package ecosystem."""
    mapping: dict[Language, str] = {
        Language.PYTHON: "pypi",
        Language.JAVASCRIPT: "npm",
        Language.TYPESCRIPT: "npm",
        Language.GO: "golang",
        Language.RUST: "cargo",
        Language.JAVA: "maven",
        Language.CSHARP: "nuget",
        Language.RUBY: "gem",
        Language.PHP: "composer",
    }
    return mapping.get(language, "generic")


def _normalize_packages(packages: list[str], versions: dict[str, str]) -> list[PackageEntry]:
    """Deduplicate and sort package input for deterministic output."""
    deduped = sorted({pkg.strip() for pkg in packages if pkg.strip()})
    normalized: list[PackageEntry] = []
    for package in deduped:
        version = versions.get(package, PACKAGE_VERSION_UNKNOWN).strip()
        normalized.append(PackageEntry(name=package, version=version or PACKAGE_VERSION_UNKNOWN))
    return normalized


def _build_cyclonedx(
    document_name: str,
    ecosystem: str,
    packages: list[PackageEntry],
) -> dict[str, object]:
    """Build CycloneDX 1.5 JSON structure."""
    serial = _serial_number(document_name)
    components = [_cyclonedx_component(ecosystem, pkg) for pkg in packages]
    metadata = {
        "timestamp": _timestamp(),
        "tools": {"components": [{"name": SBOM_TOOL_NAME, "version": SBOM_TOOL_VERSION}]},
        "component": {
            "type": "application",
            "name": document_name,
            "version": SBOM_TOOL_VERSION,
            "bom-ref": f"pkg:generic/{document_name}@{SBOM_TOOL_VERSION}",
        },
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLOENDX_SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


def _cyclonedx_component(ecosystem: str, package: PackageEntry) -> dict[str, object]:
    """Build a single CycloneDX component node."""
    purl = f"pkg:{ecosystem}/{package.name}@{package.version}"
    return {
        "type": "library",
        "name": package.name,
        "version": package.version,
        "bom-ref": purl,
        "purl": purl,
    }


def _build_spdx(
    document_name: str,
    ecosystem: str,
    packages: list[PackageEntry],
) -> dict[str, object]:
    """Build SPDX 2.3 JSON structure."""
    created = _timestamp()
    return {
        "spdxVersion": SPDX_SPEC_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": document_name,
        "documentNamespace": _spdx_namespace(document_name),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {SBOM_TOOL_NAME}-{SBOM_TOOL_VERSION}"],
        },
        "packages": [_spdx_package(ecosystem, pkg) for pkg in packages],
        "relationships": _spdx_relationships(packages),
    }


def _spdx_package(ecosystem: str, package: PackageEntry) -> dict[str, object]:
    """Build a single SPDX package entry."""
    return {
        "name": package.name,
        "SPDXID": _spdx_id(package.name),
        "versionInfo": package.version,
        "downloadLocation": SPDX_NO_ASSERTION,
        "licenseConcluded": SPDX_NO_ASSERTION,
        "licenseDeclared": SPDX_NO_ASSERTION,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:{ecosystem}/{package.name}@{package.version}",
            },
        ],
    }


def _spdx_relationships(packages: list[PackageEntry]) -> list[dict[str, str]]:
    """Build SPDX document-to-package relationship edges."""
    relationships: list[dict[str, str]] = []
    for package in packages:
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": _spdx_id(package.name),
            }
        )
    return relationships


def _spdx_id(package_name: str) -> str:
    """Create a stable SPDX package identifier."""
    return f"SPDXRef-Package-{package_name.replace('.', '-').replace('_', '-')}"


def _spdx_namespace(document_name: str) -> str:
    """Create a deterministic SPDX namespace URI."""
    return f"https://codetrust.ai/spdx/{document_name}/{_timestamp()}"


def _serial_number(document_name: str) -> str:
    """Create CycloneDX serial number using document name and timestamp."""
    base = document_name.replace(" ", "-")
    return f"urn:uuid:codetrust-{base}-{int(time.time())}"


def _timestamp() -> str:
    """Return current UTC timestamp in RFC 3339 format."""
    return datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
