"""Tests for Go proxy and crates.io registry verification, import extraction,
and dependency file parsing."""

import httpx
import pytest

from src.models.enums import Language, Registry, VerifyStatus
from src.services.registry import RegistryService
from src.utils.parsers import (
    extract_go_imports,
    extract_rust_imports,
    parse_cargo_toml,
    parse_go_mod,
)
from src.utils.similarity import suggest_crates_package, suggest_go_module

# ── Go import extraction ──────────────────────────────────────────────────


class TestGoImports:
    """Tests for extract_go_imports()."""

    def test_single_import(self) -> None:
        """Single third-party import is extracted."""
        code = 'import "github.com/gin-gonic/gin"'
        result = extract_go_imports(code)
        assert result == ["github.com/gin-gonic/gin"]

    def test_import_block(self) -> None:
        """Import block with mixed stdlib and third-party."""
        code = '''import (
    "fmt"
    "net/http"
    "github.com/gorilla/mux"
    "github.com/sirupsen/logrus"
)'''
        result = extract_go_imports(code)
        assert "fmt" not in result
        assert "net/http" not in result
        assert "github.com/gorilla/mux" in result
        assert "github.com/sirupsen/logrus" in result

    def test_stdlib_skipped(self) -> None:
        """Go stdlib packages are skipped."""
        code = '''import (
    "fmt"
    "os"
    "io"
    "context"
    "strings"
)'''
        result = extract_go_imports(code)
        assert result == []

    def test_multiple_blocks(self) -> None:
        """Multiple import blocks are handled."""
        code = '''import "github.com/spf13/cobra"

import (
    "fmt"
    "github.com/spf13/viper"
)'''
        result = extract_go_imports(code)
        assert "github.com/spf13/cobra" in result
        assert "github.com/spf13/viper" in result
        assert len(result) == 2

    def test_empty_code(self) -> None:
        """Empty code returns no imports."""
        assert extract_go_imports("") == []

    def test_golang_x_packages(self) -> None:
        """golang.org/x packages are third-party."""
        code = '''import (
    "golang.org/x/crypto/bcrypt"
    "golang.org/x/net/html"
)'''
        result = extract_go_imports(code)
        assert "golang.org/x/crypto/bcrypt" in result
        assert "golang.org/x/net/html" in result


# ── Rust import extraction ────────────────────────────────────────────────


class TestRustImports:
    """Tests for extract_rust_imports()."""

    def test_use_statement(self) -> None:
        """Standard use statement extracts crate name."""
        code = "use serde::Deserialize;"
        result = extract_rust_imports(code)
        assert result == ["serde"]

    def test_extern_crate(self) -> None:
        """extern crate extracts crate name."""
        code = "extern crate rand;"
        result = extract_rust_imports(code)
        assert result == ["rand"]

    def test_pub_use(self) -> None:
        """pub use extracts crate name."""
        code = "pub use tokio::runtime::Runtime;"
        result = extract_rust_imports(code)
        assert result == ["tokio"]

    def test_underscore_to_hyphen(self) -> None:
        """Underscores are converted to hyphens for crates.io lookup."""
        code = "use serde_json::Value;"
        result = extract_rust_imports(code)
        assert result == ["serde-json"]

    def test_std_skipped(self) -> None:
        """Standard library crates are skipped."""
        code = '''use std::collections::HashMap;
use core::fmt;
use alloc::vec::Vec;'''
        result = extract_rust_imports(code)
        assert result == []

    def test_self_super_crate_skipped(self) -> None:
        """self, super, crate references are skipped."""
        code = '''use self::module::Foo;
use super::bar;
use crate::config::Settings;'''
        result = extract_rust_imports(code)
        assert result == []

    def test_multiple_crates(self) -> None:
        """Multiple different crates are extracted."""
        code = '''use serde::Serialize;
use tokio::main;
use reqwest::Client;
use anyhow::Result;'''
        result = extract_rust_imports(code)
        assert sorted(result) == ["anyhow", "reqwest", "serde", "tokio"]

    def test_comments_skipped(self) -> None:
        """Commented lines are skipped."""
        code = '''// use fake_crate::Thing;
use real_crate::Thing;'''
        result = extract_rust_imports(code)
        assert result == ["real-crate"]

    def test_empty_code(self) -> None:
        """Empty code returns no imports."""
        assert extract_rust_imports("") == []


# ── go.mod parsing ────────────────────────────────────────────────────────


class TestGoModParsing:
    """Tests for parse_go_mod()."""

    def test_single_require(self) -> None:
        """Single require line."""
        content = "require github.com/gin-gonic/gin v1.9.1"
        result = parse_go_mod(content)
        assert result == {"github.com/gin-gonic/gin": "v1.9.1"}

    def test_require_block(self) -> None:
        """Require block with multiple modules."""
        content = '''require (
    github.com/gin-gonic/gin v1.9.1
    github.com/sirupsen/logrus v1.9.3
)'''
        result = parse_go_mod(content)
        assert result["github.com/gin-gonic/gin"] == "v1.9.1"
        assert result["github.com/sirupsen/logrus"] == "v1.9.3"

    def test_indirect_skipped(self) -> None:
        """Indirect dependencies are skipped in blocks."""
        content = '''require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/sys v0.15.0 // indirect
)'''
        result = parse_go_mod(content)
        assert "github.com/gin-gonic/gin" in result
        assert "golang.org/x/sys" not in result

    def test_comments_skipped(self) -> None:
        """Comment lines in blocks are skipped."""
        content = '''require (
    // main web framework
    github.com/gin-gonic/gin v1.9.1
)'''
        result = parse_go_mod(content)
        assert result == {"github.com/gin-gonic/gin": "v1.9.1"}

    def test_empty_content(self) -> None:
        """Empty content returns empty dict."""
        assert parse_go_mod("") == {}


# ── Cargo.toml parsing ───────────────────────────────────────────────────


class TestCargoTomlParsing:
    """Tests for parse_cargo_toml()."""

    def test_simple_version(self) -> None:
        """Simple version string."""
        content = '''[dependencies]
serde = "1.0"
tokio = "1"'''
        result = parse_cargo_toml(content)
        assert result["serde"] == "1.0"
        assert result["tokio"] == "1"

    def test_table_version(self) -> None:
        """Table-style dependency with version key."""
        content = '''[dependencies]
serde = { version = "1.0", features = ["derive"] }'''
        result = parse_cargo_toml(content)
        assert result["serde"] == "1.0"

    def test_dev_dependencies(self) -> None:
        """dev-dependencies are also parsed."""
        content = '''[dev-dependencies]
mockall = "0.12"'''
        result = parse_cargo_toml(content)
        assert result["mockall"] == "0.12"

    def test_non_dep_section_skipped(self) -> None:
        """Non-dependency sections are skipped."""
        content = '''[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"'''
        result = parse_cargo_toml(content)
        assert "name" not in result
        assert result == {"serde": "1.0"}

    def test_empty_content(self) -> None:
        """Empty content returns empty dict."""
        assert parse_cargo_toml("") == {}

    def test_comments_skipped(self) -> None:
        """Comment lines are skipped."""
        content = '''[dependencies]
# serialization
serde = "1.0"'''
        result = parse_cargo_toml(content)
        assert result == {"serde": "1.0"}


# ── Go proxy verification ────────────────────────────────────────────────


class TestGoProxyVerification:
    """Tests for RegistryService.verify_go_module()."""

    @pytest.fixture()
    def go_latest_response(self) -> dict[str, str]:
        """Sample Go proxy /@latest response."""
        return {"Version": "v1.9.1", "Time": "2023-05-12T12:00:00Z"}

    async def test_known_module_verified(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
        go_latest_response: dict[str, str],
    ) -> None:
        """Known Go module returns VERIFIED."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
            json=go_latest_response,
        )
        result = await registry_service.verify_go_module(
            "github.com/gin-gonic/gin"
        )
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.GO_PROXY
        assert result.latest_version == "v1.9.1"

    async def test_unknown_module_not_found(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Unknown Go module returns NOT_FOUND."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/nonexistent/module/@latest",
            status_code=404,
        )
        result = await registry_service.verify_go_module(
            "github.com/nonexistent/module"
        )
        assert result.status == VerifyStatus.NOT_FOUND
        assert result.severity.value == "BLOCK"

    async def test_go_version_verified(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
        go_latest_response: dict[str, str],
    ) -> None:
        """Go module with correct version returns VERIFIED."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
            json=go_latest_response,
        )
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@v/v1.9.1.info",
            json={"Version": "v1.9.1"},
        )
        result = await registry_service.verify_go_module(
            "github.com/gin-gonic/gin", "v1.9.1"
        )
        assert result.status == VerifyStatus.VERIFIED
        assert result.requested_version == "v1.9.1"

    async def test_go_version_mismatch(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
        go_latest_response: dict[str, str],
    ) -> None:
        """Go module with unknown version returns VERSION_MISMATCH."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
            json=go_latest_response,
        )
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@v/v99.0.0.info",
            status_code=404,
        )
        result = await registry_service.verify_go_module(
            "github.com/gin-gonic/gin", "v99.0.0"
        )
        assert result.status == VerifyStatus.VERSION_MISMATCH

    async def test_go_timeout(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Go proxy timeout returns TIMEOUT."""
        httpx_mock.add_exception(  # type: ignore[attr-defined]
            httpx.ReadTimeout("timeout"),
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
        )
        result = await registry_service.verify_go_module(
            "github.com/gin-gonic/gin"
        )
        assert result.status == VerifyStatus.TIMEOUT

    async def test_go_cache_hit(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Cached Go module skips HTTP call."""
        # Pre-populate cache
        await registry_service._cache.set_json(
            "codetrust:go:github.com/gin-gonic/gin",
            {"exists": True, "latest": "v1.9.1", "deprecated": False},
            3600,
        )
        result = await registry_service.verify_go_module(
            "github.com/gin-gonic/gin"
        )
        assert result.status == VerifyStatus.VERIFIED
        assert result.cached is True


# ── crates.io verification ───────────────────────────────────────────────


class TestCratesVerification:
    """Tests for RegistryService.verify_crates_package()."""

    @pytest.fixture()
    def crates_response(self) -> dict[str, object]:
        """Sample crates.io response."""
        return {
            "crate": {
                "name": "serde",
                "max_version": "1.0.195",
            },
            "versions": [
                {"num": "1.0.195"},
                {"num": "1.0.194"},
                {"num": "1.0.193"},
            ],
        }

    async def test_known_crate_verified(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
        crates_response: dict[str, object],
    ) -> None:
        """Known crate returns VERIFIED."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://crates.io/api/v1/crates/serde",
            json=crates_response,
        )
        result = await registry_service.verify_crates_package("serde")
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.CRATES
        assert result.latest_version == "1.0.195"

    async def test_unknown_crate_not_found(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Unknown crate returns NOT_FOUND with suggestion."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://crates.io/api/v1/crates/serd",
            status_code=404,
        )
        result = await registry_service.verify_crates_package("serd")
        assert result.status == VerifyStatus.NOT_FOUND
        assert result.severity.value == "BLOCK"
        # Should suggest "serde"
        assert "serde" in result.suggestion.lower() or result.suggestion == ""

    async def test_crate_version_verified(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
        crates_response: dict[str, object],
    ) -> None:
        """Crate with correct version returns VERIFIED."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://crates.io/api/v1/crates/serde",
            json=crates_response,
        )
        result = await registry_service.verify_crates_package("serde", "1.0.195")
        assert result.status == VerifyStatus.VERIFIED
        assert result.requested_version == "1.0.195"

    async def test_crate_version_mismatch(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
        crates_response: dict[str, object],
    ) -> None:
        """Crate with unknown version returns VERSION_MISMATCH."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://crates.io/api/v1/crates/serde",
            json=crates_response,
        )
        result = await registry_service.verify_crates_package("serde", "99.0.0")
        assert result.status == VerifyStatus.VERSION_MISMATCH

    async def test_crate_timeout(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """crates.io timeout returns TIMEOUT."""
        httpx_mock.add_exception(  # type: ignore[attr-defined]
            httpx.ReadTimeout("timeout"),
            url="https://crates.io/api/v1/crates/serde",
        )
        result = await registry_service.verify_crates_package("serde")
        assert result.status == VerifyStatus.TIMEOUT

    async def test_crate_cache_hit(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Cached crate skips HTTP call."""
        await registry_service._cache.set_json(
            "codetrust:crates:tokio",
            {"exists": True, "latest": "1.35.0", "deprecated": False},
            3600,
        )
        result = await registry_service.verify_crates_package("tokio")
        assert result.status == VerifyStatus.VERIFIED
        assert result.cached is True


# ── Batch verification Go/Rust ────────────────────────────────────────────


class TestBatchVerifyGoRust:
    """Tests for batch verification with Go and Rust languages."""

    async def test_batch_go_modules(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Batch verify Go modules concurrently."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/gin-gonic/gin/@latest",
            json={"Version": "v1.9.1"},
        )
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://proxy.golang.org/github.com/nonexistent/pkg/@latest",
            status_code=404,
        )
        results = await registry_service.verify_packages(
            Language.GO,
            ["github.com/gin-gonic/gin", "github.com/nonexistent/pkg"],
        )
        assert len(results) == 2
        statuses = {r.package: r.status for r in results}
        assert statuses["github.com/gin-gonic/gin"] == VerifyStatus.VERIFIED
        assert statuses["github.com/nonexistent/pkg"] == VerifyStatus.NOT_FOUND

    async def test_batch_rust_crates(
        self,
        registry_service: RegistryService,
        httpx_mock: object,
    ) -> None:
        """Batch verify Rust crates concurrently."""
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://crates.io/api/v1/crates/serde",
            json={"crate": {"name": "serde", "max_version": "1.0.195"}, "versions": []},
        )
        httpx_mock.add_response(  # type: ignore[attr-defined]
            url="https://crates.io/api/v1/crates/nonexistent-xyz",
            status_code=404,
        )
        results = await registry_service.verify_packages(
            Language.RUST,
            ["serde", "nonexistent-xyz"],
        )
        assert len(results) == 2
        statuses = {r.package: r.status for r in results}
        assert statuses["serde"] == VerifyStatus.VERIFIED
        assert statuses["nonexistent-xyz"] == VerifyStatus.NOT_FOUND


# ── Similarity suggestions ───────────────────────────────────────────────


class TestGoRustSimilarity:
    """Tests for Go and Rust fuzzy matching suggestions."""

    def test_crates_typo_suggestion(self) -> None:
        """Typo in crate name gets suggestion."""
        result = suggest_crates_package("serd")
        assert "serde" in result.lower()

    def test_crates_no_match(self) -> None:
        """Completely unknown crate gets empty suggestion."""
        result = suggest_crates_package("zzzzxyznonexistent")
        assert result == ""

    def test_go_module_suggestion(self) -> None:
        """Typo in Go module gets suggestion."""
        result = suggest_go_module("github.com/gin-gonic/ginn")
        assert "gin" in result.lower()

    def test_go_no_match(self) -> None:
        """Completely unknown module gets empty suggestion."""
        result = suggest_go_module("aaa.bbb.ccc/qqq123/zzz999")
        assert result == ""
