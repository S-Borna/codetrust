"""Tests for Docker image/tag verification service."""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from src.models.enums import VerifyStatus
from src.models.requests import DockerImageInput
from src.services.cache import CacheService
from src.services.docker_verify import DockerVerifyService


@pytest.fixture()
async def docker_service(
    fake_cache: CacheService,
    mock_http_client: httpx.AsyncClient,
) -> DockerVerifyService:
    """Create a DockerVerifyService with fake cache and mock HTTP client."""
    return DockerVerifyService(fake_cache, mock_http_client)


# --- verify_image_tag: VERIFIED ---


class TestDockerVerified:
    """Tests for images that exist on Docker Hub."""

    async def test_existing_tag_returns_verified(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Known image:tag returns VERIFIED."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/python/tags/3.12-slim",
            json={"name": "3.12-slim"},
            status_code=200,
        )

        result = await docker_service.verify_image_tag("python", "3.12-slim")

        assert result.status == VerifyStatus.VERIFIED
        assert result.image == "python"
        assert result.tag == "3.12-slim"

    async def test_latest_tag_default(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Omitting tag defaults to 'latest'."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/nginx/tags/latest",
            json={"name": "latest"},
            status_code=200,
        )

        result = await docker_service.verify_image_tag("nginx")

        assert result.status == VerifyStatus.VERIFIED
        assert result.tag == "latest"


# --- verify_image_tag: NOT_FOUND ---


class TestDockerNotFound:
    """Tests for images/tags that do not exist."""

    async def test_nonexistent_tag_returns_not_found(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Unknown tag returns NOT_FOUND with suggestions."""
        # Tag check returns 404
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/python/tags/99.99",
            status_code=404,
        )
        # Fetch available tags for suggestion
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/python/tags?page_size=100",
            json={
                "results": [
                    {"name": "3.12-slim"},
                    {"name": "3.12"},
                    {"name": "3.11-slim"},
                ]
            },
            status_code=200,
        )

        result = await docker_service.verify_image_tag("python", "99.99")

        assert result.status == VerifyStatus.NOT_FOUND
        assert "99.99" in result.message
        assert len(result.available_tags) > 0

    async def test_not_found_caches_result(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """NOT_FOUND results are cached."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/fake/tags/bad",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/fake/tags?page_size=100",
            json={"results": []},
            status_code=200,
        )

        # First call hits network
        result1 = await docker_service.verify_image_tag("fake", "bad")
        assert result1.status == VerifyStatus.NOT_FOUND

        # Second call should hit cache (no new HTTP mock needed)
        result2 = await docker_service.verify_image_tag("fake", "bad")
        assert result2.status == VerifyStatus.NOT_FOUND
        assert "cached" in result2.message.lower()


# --- verify_image_tag: TIMEOUT ---


class TestDockerTimeout:
    """Tests for timeout scenarios."""

    async def test_timeout_returns_timeout_status(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Registry timeout returns TIMEOUT status."""
        httpx_mock.add_exception(
            httpx.TimeoutException("Connection timed out"),
            url="https://hub.docker.com/v2/repositories/library/python/tags/3.12",
        )

        result = await docker_service.verify_image_tag("python", "3.12")

        assert result.status == VerifyStatus.TIMEOUT
        assert "timeout" in result.message.lower()


# --- verify_image_tag: ERROR ---


class TestDockerError:
    """Tests for HTTP error scenarios."""

    async def test_http_error_returns_error_status(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """HTTP error returns ERROR status."""
        httpx_mock.add_exception(
            httpx.ConnectError("Connection refused"),
            url="https://hub.docker.com/v2/repositories/library/python/tags/3.12",
        )

        result = await docker_service.verify_image_tag("python", "3.12")

        assert result.status == VerifyStatus.ERROR
        assert "error" in result.message.lower()


# --- Cache hit ---


class TestDockerCacheHit:
    """Tests for cached Docker results."""

    async def test_cache_hit_skips_http(
        self, docker_service: DockerVerifyService, fake_cache: CacheService
    ) -> None:
        """Cached result skips HTTP call entirely."""
        # Pre-populate cache
        key = fake_cache._make_key("docker", "python:3.12-slim")
        await fake_cache.set_json(key, {"exists": True}, 86400)

        # No httpx mock registered — would fail if HTTP call was made
        result = await docker_service.verify_image_tag("python", "3.12-slim")

        assert result.status == VerifyStatus.VERIFIED
        assert "cached" in result.message.lower()

    async def test_cached_not_found(
        self, docker_service: DockerVerifyService, fake_cache: CacheService
    ) -> None:
        """Cached NOT_FOUND result is returned correctly."""
        key = fake_cache._make_key("docker", "fake:bad")
        await fake_cache.set_json(key, {"exists": False}, 3600)

        result = await docker_service.verify_image_tag("fake", "bad")

        assert result.status == VerifyStatus.NOT_FOUND
        assert "cached" in result.message.lower()


# --- Batch verification ---


class TestDockerBatchVerify:
    """Tests for batch image verification."""

    async def test_batch_verify_concurrent(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Batch verify runs multiple images concurrently."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/python/tags/3.12",
            json={"name": "3.12"},
            status_code=200,
        )
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/nginx/tags/latest",
            json={"name": "latest"},
            status_code=200,
        )
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/redis/tags/7-alpine",
            json={"name": "7-alpine"},
            status_code=200,
        )

        images = [
            DockerImageInput(image="python", tag="3.12"),
            DockerImageInput(image="nginx", tag="latest"),
            DockerImageInput(image="redis", tag="7-alpine"),
        ]

        results = await docker_service.verify_images(images)

        assert len(results) == 3
        assert all(r.status == VerifyStatus.VERIFIED for r in results)

    async def test_batch_mixed_results(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Batch verify handles mix of verified and not-found."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/python/tags/3.12",
            json={"name": "3.12"},
            status_code=200,
        )
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/fakeimage/tags/bad",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/fakeimage/tags?page_size=100",
            json={"results": []},
            status_code=200,
        )

        images = [
            DockerImageInput(image="python", tag="3.12"),
            DockerImageInput(image="fakeimage", tag="bad"),
        ]

        results = await docker_service.verify_images(images)

        assert len(results) == 2
        statuses = {r.image: r.status for r in results}
        assert statuses["python"] == VerifyStatus.VERIFIED
        assert statuses["fakeimage"] == VerifyStatus.NOT_FOUND


# --- Available tags suggestion ---


class TestDockerAvailableTags:
    """Tests for tag suggestion functionality."""

    async def test_available_tags_returned_on_not_found(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """NOT_FOUND result includes available tags as suggestions."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/node/tags/99.0",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/node/tags?page_size=100",
            json={
                "results": [
                    {"name": "20"},
                    {"name": "20-slim"},
                    {"name": "18"},
                    {"name": "18-alpine"},
                    {"name": "lts"},
                ]
            },
            status_code=200,
        )

        result = await docker_service.verify_image_tag("node", "99.0")

        assert result.status == VerifyStatus.NOT_FOUND
        assert len(result.available_tags) == 5
        assert "20" in result.available_tags

    async def test_available_tags_cached(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock,
        fake_cache: CacheService,
    ) -> None:
        """Available tags are cached after first fetch."""
        # Pre-populate tags cache
        tags_key = fake_cache._make_key("docker", "node:_tags")
        await fake_cache.set_json(tags_key, {"tags": ["20", "18", "lts"]}, 86400)

        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/node/tags/99.0",
            status_code=404,
        )
        # No tags list mock — should use cache

        result = await docker_service.verify_image_tag("node", "99.0")

        assert result.status == VerifyStatus.NOT_FOUND
        assert "20" in result.available_tags

    async def test_tags_fetch_error_returns_empty(
        self, docker_service: DockerVerifyService, httpx_mock: HTTPXMock
    ) -> None:
        """Error fetching tags returns empty list gracefully."""
        httpx_mock.add_response(
            url="https://hub.docker.com/v2/repositories/library/custom/tags/v1",
            status_code=404,
        )
        httpx_mock.add_exception(
            httpx.TimeoutException("Tags timeout"),
            url="https://hub.docker.com/v2/repositories/library/custom/tags?page_size=100",
        )

        result = await docker_service.verify_image_tag("custom", "v1")

        assert result.status == VerifyStatus.NOT_FOUND
        assert result.available_tags == []
