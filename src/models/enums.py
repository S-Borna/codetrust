"""Enums used throughout the CodeTrust platform."""

from enum import StrEnum


class Severity(StrEnum):
    """Finding severity level."""

    BLOCK = "BLOCK"  # Must fix before proceeding
    WARN = "WARN"  # Should fix, not blocking
    INFO = "INFO"  # Suggestion/improvement


class VerifyStatus(StrEnum):
    """Status of a package or image verification."""

    VERIFIED = "VERIFIED"  # Exists and valid
    NOT_FOUND = "NOT_FOUND"  # Does not exist in registry
    DEPRECATED = "DEPRECATED"  # Exists but deprecated
    VERSION_MISMATCH = "VERSION_MISMATCH"  # Package exists, version doesn't
    TIMEOUT = "TIMEOUT"  # Registry didn't respond
    ERROR = "ERROR"  # Unexpected error
    SKIPPED = "SKIPPED"  # Not checkable (e.g. local package)


class Language(StrEnum):
    """Supported programming languages."""

    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"


class Registry(StrEnum):
    """Supported package registries."""

    PYPI = "pypi"
    NPM = "npm"
    CRATES = "crates"
    GO_PROXY = "go_proxy"
    DOCKER_HUB = "docker_hub"
    GHCR = "ghcr"
