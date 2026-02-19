"""Tests for Ruby, PHP, Maven, and NuGet registry verification,
import extraction, and dependency file parsing."""

import httpx
import pytest

from src.models.enums import Language, Registry, VerifyStatus
from src.services.registry import RegistryService
from src.utils.parsers import (
    extract_php_imports,
    extract_ruby_imports,
    parse_composer_json,
    parse_csproj,
    parse_gemfile,
    parse_pom_xml,
)
from src.utils.similarity import (
    suggest_maven_package,
    suggest_nuget_package,
    suggest_packagist_package,
    suggest_rubygems_package,
)

# ── Ruby import extraction ─────────────────────────────────────────────


class TestRubyImports:
    """Tests for extract_ruby_imports()."""

    def test_basic_require(self) -> None:
        """Single require statement is extracted."""
        code = "require 'nokogiri'"
        result = extract_ruby_imports(code)
        assert result == ["nokogiri"]

    def test_double_quoted_require(self) -> None:
        """Double-quoted require is extracted."""
        code = 'require "rails"'
        result = extract_ruby_imports(code)
        assert result == ["rails"]

    def test_multiple_requires(self) -> None:
        """Multiple requires are extracted."""
        code = "require 'rails'\nrequire 'nokogiri'\nrequire 'pg'\n"
        result = extract_ruby_imports(code)
        assert "rails" in result
        assert "nokogiri" in result
        assert "pg" in result

    def test_stdlib_skipped(self) -> None:
        """Ruby stdlib modules are skipped."""
        code = "require 'json'\nrequire 'csv'\nrequire 'net/http'\nrequire 'rails'\n"
        result = extract_ruby_imports(code)
        assert "json" not in result
        assert "csv" not in result
        assert "net" not in result
        assert "rails" in result

    def test_require_relative_skipped(self) -> None:
        """require_relative is skipped (always local)."""
        code = "require_relative './helper'\nrequire 'rails'\n"
        result = extract_ruby_imports(code)
        assert "./helper" not in result
        assert "helper" not in result
        assert "rails" in result

    def test_submodule_stripped(self) -> None:
        """Sub-path require extracts top-level gem name."""
        code = "require 'active_support/core_ext'\n"
        result = extract_ruby_imports(code)
        assert result == ["active_support"]

    def test_comments_skipped(self) -> None:
        """Comments are ignored."""
        code = "# require 'dont_extract'\nrequire 'rails'\n"
        result = extract_ruby_imports(code)
        assert "dont_extract" not in result
        assert "rails" in result

    def test_empty_code(self) -> None:
        """Empty code returns empty list."""
        assert extract_ruby_imports("") == []


# ── PHP import extraction ──────────────────────────────────────────────


class TestPhpImports:
    """Tests for extract_php_imports()."""

    def test_basic_use(self) -> None:
        """Single use statement is extracted."""
        code = "use Illuminate\\Support\\Facades\\DB;"
        result = extract_php_imports(code)
        assert result == ["illuminate/support"]

    def test_multiple_use(self) -> None:
        """Multiple use statements are extracted."""
        code = (
            "use GuzzleHttp\\Client;\n"
            "use Monolog\\Logger;\n"
            "use Illuminate\\Database\\Eloquent\\Model;\n"
        )
        result = extract_php_imports(code)
        assert "guzzlehttp/client" in result
        assert "monolog/logger" in result
        assert "illuminate/database" in result

    def test_builtin_skipped(self) -> None:
        """PHP built-in extensions are skipped."""
        code = "use PDO;\nuse Illuminate\\Support\\Str;\n"
        result = extract_php_imports(code)
        assert "illuminate/support" in result

    def test_comments_skipped(self) -> None:
        """Comments are ignored."""
        code = "// use DontExtract\\This;\nuse Monolog\\Logger;\n"
        result = extract_php_imports(code)
        assert "monolog/logger" in result
        assert len(result) == 1

    def test_empty_code(self) -> None:
        """Empty code returns empty list."""
        assert extract_php_imports("") == []


# ── Gemfile parsing ────────────────────────────────────────────────────


class TestGemfileParsing:
    """Tests for parse_gemfile()."""

    def test_basic_gems(self) -> None:
        """Parse simple gem declarations."""
        content = "gem 'rails', '~> 7.0'\ngem 'nokogiri'\n"
        result = parse_gemfile(content)
        assert result["rails"] == "~> 7.0"
        assert result["nokogiri"] == ""

    def test_version_specifiers(self) -> None:
        """Parse gems with various version constraints."""
        content = (
            "gem 'pg', '>= 1.1'\n"
            "gem 'puma', '~> 6.0'\n"
        )
        result = parse_gemfile(content)
        assert result["pg"] == ">= 1.1"
        assert result["puma"] == "~> 6.0"

    def test_comments_skipped(self) -> None:
        """Comments are ignored."""
        content = "# gem 'skip_me'\ngem 'rails'\n"
        result = parse_gemfile(content)
        assert "skip_me" not in result
        assert "rails" in result

    def test_empty_gemfile(self) -> None:
        """Empty Gemfile returns empty dict."""
        assert parse_gemfile("") == {}


# ── composer.json parsing ─────────────────────────────────────────────


class TestComposerJsonParsing:
    """Tests for parse_composer_json()."""

    def test_basic_require(self) -> None:
        """Parse basic require section."""
        content = '{"require": {"laravel/framework": "^10.0", "guzzlehttp/guzzle": "^7.0"}}'
        result = parse_composer_json(content)
        assert result["laravel/framework"] == "^10.0"
        assert result["guzzlehttp/guzzle"] == "^7.0"

    def test_require_dev(self) -> None:
        """Parse require-dev section."""
        content = '{"require-dev": {"phpunit/phpunit": "^10.0"}}'
        result = parse_composer_json(content)
        assert result["phpunit/phpunit"] == "^10.0"

    def test_php_skipped(self) -> None:
        """PHP version requirement is skipped."""
        content = '{"require": {"php": ">=8.1", "laravel/framework": "^10.0"}}'
        result = parse_composer_json(content)
        assert "php" not in result
        assert "laravel/framework" in result

    def test_ext_skipped(self) -> None:
        """ext-* extensions are skipped."""
        content = '{"require": {"ext-mbstring": "*", "monolog/monolog": "^3.0"}}'
        result = parse_composer_json(content)
        assert "ext-mbstring" not in result
        assert "monolog/monolog" in result

    def test_invalid_json(self) -> None:
        """Invalid JSON returns empty dict."""
        assert parse_composer_json("{invalid") == {}

    def test_empty(self) -> None:
        """Empty JSON returns empty dict."""
        assert parse_composer_json("{}") == {}


# ── pom.xml parsing ───────────────────────────────────────────────────


class TestPomXmlParsing:
    """Tests for parse_pom_xml()."""

    def test_basic_dependency(self) -> None:
        """Parse a simple Maven dependency."""
        content = """
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>33.0.0-jre</version>
        </dependency>
        """
        result = parse_pom_xml(content)
        assert result["com.google.guava:guava"] == "33.0.0-jre"

    def test_multiple_dependencies(self) -> None:
        """Parse multiple Maven dependencies."""
        content = """
        <dependency>
            <groupId>org.slf4j</groupId>
            <artifactId>slf4j-api</artifactId>
            <version>2.0.9</version>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
            <version>2.16.0</version>
        </dependency>
        """
        result = parse_pom_xml(content)
        assert len(result) == 2
        assert result["org.slf4j:slf4j-api"] == "2.0.9"

    def test_empty(self) -> None:
        """Empty content returns empty dict."""
        assert parse_pom_xml("") == {}


# ── .csproj parsing ───────────────────────────────────────────────────


class TestCsprojParsing:
    """Tests for parse_csproj()."""

    def test_basic_package(self) -> None:
        """Parse a simple PackageReference."""
        content = '<PackageReference Include="Newtonsoft.Json" Version="13.0.3" />'
        result = parse_csproj(content)
        assert result["Newtonsoft.Json"] == "13.0.3"

    def test_multiple_packages(self) -> None:
        """Parse multiple PackageReferences."""
        content = """
        <PackageReference Include="Serilog" Version="3.1.1" />
        <PackageReference Include="xunit" Version="2.6.2" />
        """
        result = parse_csproj(content)
        assert result["Serilog"] == "3.1.1"
        assert result["xunit"] == "2.6.2"

    def test_no_version(self) -> None:
        """PackageReference without version."""
        content = '<PackageReference Include="AutoMapper" />'
        result = parse_csproj(content)
        assert result["AutoMapper"] == ""

    def test_empty(self) -> None:
        """Empty content returns empty dict."""
        assert parse_csproj("") == {}


# ── Fuzzy matching ─────────────────────────────────────────────────────


class TestFuzzyMatching:
    """Tests for new registry suggest functions."""

    def test_rubygems_suggestion(self) -> None:
        """Close match returns suggestion for RubyGems."""
        result = suggest_rubygems_package("railss")
        assert "rails" in result.lower()

    def test_packagist_suggestion(self) -> None:
        """Close match returns suggestion for Packagist."""
        result = suggest_packagist_package("monolog/monologg")
        assert "monolog" in result.lower()

    def test_maven_suggestion(self) -> None:
        """Close match returns suggestion for Maven."""
        result = suggest_maven_package("com.google.guava:guavva")
        assert "guava" in result.lower()

    def test_nuget_suggestion(self) -> None:
        """Close match returns suggestion for NuGet."""
        result = suggest_nuget_package("Newtonsoft.Jsonn")
        assert "newtonsoft" in result.lower()

    def test_no_match_returns_empty(self) -> None:
        """No close match returns empty string."""
        assert suggest_rubygems_package("xyznonexistent123") == ""
        assert suggest_packagist_package("xyznonexistent123") == ""
        assert suggest_maven_package("xyznonexistent123") == ""
        assert suggest_nuget_package("xyznonexistent123") == ""


# ── RubyGems registry verification ────────────────────────────────────


class TestRubyGemsVerification:
    """Tests for verify_rubygems_package()."""

    @pytest.mark.anyio
    async def test_known_gem_verified(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Verified gem returns VERIFIED status."""
        httpx_mock.add_response(
            url="https://rubygems.org/api/v1/gems/rails.json",
            json={"name": "rails", "version": "7.1.3"},
        )
        result = await registry_service.verify_rubygems_package("rails")
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.RUBYGEMS

    @pytest.mark.anyio
    async def test_unknown_gem_not_found(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Unknown gem returns NOT_FOUND status."""
        httpx_mock.add_response(
            url="https://rubygems.org/api/v1/gems/fakegem999.json",
            status_code=404,
        )
        result = await registry_service.verify_rubygems_package("fakegem999")
        assert result.status == VerifyStatus.NOT_FOUND

    @pytest.mark.anyio
    async def test_rubygems_timeout(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Timeout returns TIMEOUT status."""
        httpx_mock.add_exception(
            httpx.ReadTimeout("timeout"),
            url="https://rubygems.org/api/v1/gems/rails.json",
        )
        result = await registry_service.verify_rubygems_package("rails")
        assert result.status == VerifyStatus.TIMEOUT


# ── Packagist registry verification ───────────────────────────────────


class TestPackagistVerification:
    """Tests for verify_packagist_package()."""

    @pytest.mark.anyio
    async def test_known_package_verified(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Verified Packagist package returns VERIFIED status."""
        httpx_mock.add_response(
            url="https://repo.packagist.org/p2/monolog/monolog.json",
            json={
                "packages": {
                    "monolog/monolog": [
                        {"version": "3.5.0"},
                        {"version": "3.4.0"},
                    ]
                }
            },
        )
        result = await registry_service.verify_packagist_package("monolog/monolog")
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.PACKAGIST

    @pytest.mark.anyio
    async def test_unknown_package_not_found(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Unknown Packagist package returns NOT_FOUND status."""
        httpx_mock.add_response(
            url="https://repo.packagist.org/p2/fake/package999.json",
            status_code=404,
        )
        result = await registry_service.verify_packagist_package("fake/package999")
        assert result.status == VerifyStatus.NOT_FOUND


# ── Maven Central registry verification ───────────────────────────────


class TestMavenVerification:
    """Tests for verify_maven_package()."""

    @pytest.mark.anyio
    async def test_known_artifact_verified(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Verified Maven artifact returns VERIFIED status."""
        httpx_mock.add_response(
            url="https://search.maven.org/solrsearch/select?q=g:com.google.guava+AND+a:guava&rows=1&wt=json",
            json={
                "response": {
                    "numFound": 1,
                    "docs": [
                        {
                            "g": "com.google.guava",
                            "a": "guava",
                            "latestVersion": "33.0.0-jre",
                            "versionCount": 50,
                        }
                    ],
                }
            },
        )
        result = await registry_service.verify_maven_package("com.google.guava:guava")
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.MAVEN

    @pytest.mark.anyio
    async def test_unknown_artifact_not_found(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Unknown Maven artifact returns NOT_FOUND status."""
        httpx_mock.add_response(
            url="https://search.maven.org/solrsearch/select?q=g:fake.group+AND+a:fake-artifact&rows=1&wt=json",
            json={"response": {"numFound": 0, "docs": []}},
        )
        result = await registry_service.verify_maven_package("fake.group:fake-artifact")
        assert result.status == VerifyStatus.NOT_FOUND


# ── NuGet registry verification ───────────────────────────────────────


class TestNuGetVerification:
    """Tests for verify_nuget_package()."""

    @pytest.mark.anyio
    async def test_known_package_verified(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Verified NuGet package returns VERIFIED status."""
        httpx_mock.add_response(
            url="https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json",
            json={"versions": ["12.0.1", "13.0.1", "13.0.3"]},
        )
        result = await registry_service.verify_nuget_package("Newtonsoft.Json")
        assert result.status == VerifyStatus.VERIFIED
        assert result.registry == Registry.NUGET

    @pytest.mark.anyio
    async def test_nuget_version_verified(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Specific NuGet version is verified."""
        httpx_mock.add_response(
            url="https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json",
            json={"versions": ["12.0.1", "13.0.1", "13.0.3"]},
        )
        result = await registry_service.verify_nuget_package("Newtonsoft.Json", "13.0.3")
        assert result.status == VerifyStatus.VERIFIED

    @pytest.mark.anyio
    async def test_nuget_version_mismatch(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Non-existent NuGet version returns VERSION_MISMATCH."""
        httpx_mock.add_response(
            url="https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json",
            json={"versions": ["12.0.1", "13.0.1", "13.0.3"]},
        )
        result = await registry_service.verify_nuget_package("Newtonsoft.Json", "99.0.0")
        assert result.status == VerifyStatus.VERSION_MISMATCH

    @pytest.mark.anyio
    async def test_unknown_nuget_not_found(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Unknown NuGet package returns NOT_FOUND status."""
        httpx_mock.add_response(
            url="https://api.nuget.org/v3-flatcontainer/fakepkg999/index.json",
            status_code=404,
        )
        result = await registry_service.verify_nuget_package("FakePkg999")
        assert result.status == VerifyStatus.NOT_FOUND


# ── Registry routing ──────────────────────────────────────────────────


class TestRegistryRouting:
    """Tests that _verify_single routes to the correct registry."""

    @pytest.mark.anyio
    async def test_ruby_routes_to_rubygems(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Ruby language routes to RubyGems."""
        httpx_mock.add_response(
            url="https://rubygems.org/api/v1/gems/rails.json",
            json={"name": "rails", "version": "7.1.3"},
        )
        result = await registry_service._verify_single(Language.RUBY, "rails", "")
        assert result.registry == Registry.RUBYGEMS

    @pytest.mark.anyio
    async def test_php_routes_to_packagist(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """PHP language routes to Packagist."""
        httpx_mock.add_response(
            url="https://repo.packagist.org/p2/monolog/monolog.json",
            json={"packages": {"monolog/monolog": [{"version": "3.5.0"}]}},
        )
        result = await registry_service._verify_single(Language.PHP, "monolog/monolog", "")
        assert result.registry == Registry.PACKAGIST

    @pytest.mark.anyio
    async def test_java_routes_to_maven(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """Java language routes to Maven."""
        httpx_mock.add_response(
            url="https://search.maven.org/solrsearch/select?q=g:junit+AND+a:junit&rows=1&wt=json",
            json={"response": {"numFound": 1, "docs": [{"latestVersion": "4.13.2", "versionCount": 10}]}},
        )
        result = await registry_service._verify_single(Language.JAVA, "junit:junit", "")
        assert result.registry == Registry.MAVEN

    @pytest.mark.anyio
    async def test_csharp_routes_to_nuget(
        self, registry_service: RegistryService, httpx_mock: pytest.fixture
    ) -> None:
        """C# language routes to NuGet."""
        httpx_mock.add_response(
            url="https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json",
            json={"versions": ["13.0.3"]},
        )
        result = await registry_service._verify_single(Language.CSHARP, "Newtonsoft.Json", "")
        assert result.registry == Registry.NUGET
