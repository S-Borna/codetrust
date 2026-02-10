"""Layer 2: Docker image and tag verification against Docker Hub."""

import asyncio

import httpx
import structlog

from src.config import settings
from src.models.enums import Severity, VerifyStatus
from src.models.requests import DockerImageInput
from src.models.responses import DockerImageResult
from src.services.cache import CacheService

logger = structlog.get_logger()

# Concurrency limit for batch Docker Hub calls
_SEMAPHORE_LIMIT: int = 10

# Max number of suggested tags to return
_MAX_SUGGESTED_TAGS: int = 10


class DockerVerifyService:
    """Verifies Docker images and tags exist on Docker Hub."""

    def __init__(
        self, cache: CacheService, http_client: httpx.AsyncClient
    ) -> None:
        """Initialize with cache and HTTP client."""
        self._cache = cache
        self._http = http_client

    async def verify_image_tag(
        self, image: str, tag: str = "latest"
    ) -> DockerImageResult:
        """Check if image:tag exists on Docker Hub.

        Flow:
        1. Cache check: codetrust:docker:{image}:{tag}
        2. GET Docker Hub tag API
        3. If 200: VERIFIED
        4. If 404: NOT_FOUND -> fetch available tags for suggestion
        5. Cache result
        """
        cache_key = self._cache._make_key("docker", f"{image}:{tag}")

        cached = await self._cache.get_json(cache_key)
        if cached is not None:
            return self._build_cached_result(image, tag, cached)

        return await self._check_docker_tag(image, tag, cache_key)

    async def _check_docker_tag(
        self, image: str, tag: str, cache_key: str
    ) -> DockerImageResult:
        """Perform the actual Docker Hub API check."""
        try:
            exists = await self._fetch_tag(image, tag)
        except httpx.TimeoutException:
            logger.warning("docker_timeout", image=image, tag=tag)
            return DockerImageResult(
                image=image,
                tag=tag,
                status=VerifyStatus.TIMEOUT,
                severity=Severity.WARN,
                message=f"Timeout verifying '{image}:{tag}'.",
            )
        except httpx.HTTPError as exc:
            logger.warning("docker_error", image=image, tag=tag, error=str(exc))
            return DockerImageResult(
                image=image,
                tag=tag,
                status=VerifyStatus.ERROR,
                severity=Severity.WARN,
                message=f"HTTP error verifying '{image}:{tag}': {exc}",
            )

        if exists:
            await self._cache.set_json(
                cache_key,
                {"exists": True},
                settings.cache_ttl_docker_tag,
            )
            return DockerImageResult(
                image=image,
                tag=tag,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message=f"Image '{image}:{tag}' verified on Docker Hub.",
            )

        return await self._handle_not_found(image, tag, cache_key)

    async def _handle_not_found(
        self, image: str, tag: str, cache_key: str
    ) -> DockerImageResult:
        """Handle a tag not found: cache result and suggest alternatives."""
        await self._cache.set_json(
            cache_key,
            {"exists": False},
            settings.cache_ttl_not_found,
        )

        available = await self._fetch_available_tags(image)
        suggestion = ""
        if available:
            suggestion = f"Available tags: {', '.join(available[:5])}"

        return DockerImageResult(
            image=image,
            tag=tag,
            status=VerifyStatus.NOT_FOUND,
            severity=Severity.BLOCK,
            message=f"Tag '{tag}' not found for image '{image}'.",
            suggestion=suggestion,
            available_tags=available[:_MAX_SUGGESTED_TAGS],
        )

    async def verify_images(
        self, images: list[DockerImageInput]
    ) -> list[DockerImageResult]:
        """Verify a batch of Docker images concurrently."""
        semaphore = asyncio.Semaphore(_SEMAPHORE_LIMIT)

        async def verify_one(item: DockerImageInput) -> DockerImageResult:
            async with semaphore:
                return await self.verify_image_tag(item.image, item.tag)

        results = await asyncio.gather(
            *[verify_one(item) for item in images]
        )
        return list(results)

    async def _fetch_tag(self, image: str, tag: str) -> bool:
        """Check if a specific tag exists on Docker Hub. Returns True/False."""
        url = settings.docker_hub_tags_url.format(image=image, tag=tag)
        try:
            response = await self._http.get(url, timeout=settings.http_timeout)
            return response.status_code == 200
        except httpx.TimeoutException:
            raise
        except httpx.HTTPError:
            raise

    async def _fetch_available_tags(
        self, image: str, limit: int = _MAX_SUGGESTED_TAGS
    ) -> list[str]:
        """Fetch available tags for an image to suggest alternatives."""
        tags_cache_key = self._cache._make_key("docker", f"{image}:_tags")

        cached = await self._cache.get_json(tags_cache_key)
        if cached is not None:
            tags = cached.get("tags", [])
            if isinstance(tags, list):
                return [str(t) for t in tags[:limit]]

        try:
            tags = await self._fetch_tags_from_hub(image, limit)
        except (httpx.TimeoutException, httpx.HTTPError) as exc:
            logger.warning(
                "docker_tags_fetch_error",
                image=image,
                error=str(exc),
            )
            return []

        if tags:
            await self._cache.set_json(
                tags_cache_key,
                {"tags": tags},
                settings.cache_ttl_docker_tag,
            )

        return tags

    async def _fetch_tags_from_hub(
        self, image: str, limit: int
    ) -> list[str]:
        """Raw Docker Hub tags list call."""
        url = settings.docker_hub_list_url.format(image=image)
        response = await self._http.get(url, timeout=settings.http_timeout)

        if response.status_code != 200:
            return []

        data = response.json()
        results = data.get("results", [])
        if not isinstance(results, list):
            return []

        return self._extract_tag_names(results, limit)

    def _extract_tag_names(
        self, results: list[dict[str, object]], limit: int
    ) -> list[str]:
        """Extract tag names from Docker Hub API response."""
        tags: list[str] = []
        for item in results:
            if isinstance(item, dict):
                name = item.get("name")
                if isinstance(name, str):
                    tags.append(name)
            if len(tags) >= limit:
                break
        return tags

    def _build_cached_result(
        self,
        image: str,
        tag: str,
        cached: dict[str, str | bool | int | float],
    ) -> DockerImageResult:
        """Build a DockerImageResult from cached data."""
        exists = bool(cached.get("exists", False))

        if exists:
            return DockerImageResult(
                image=image,
                tag=tag,
                status=VerifyStatus.VERIFIED,
                severity=Severity.INFO,
                message=f"Image '{image}:{tag}' verified (cached).",
            )

        return DockerImageResult(
            image=image,
            tag=tag,
            status=VerifyStatus.NOT_FOUND,
            severity=Severity.BLOCK,
            message=f"Tag '{tag}' not found for image '{image}' (cached).",
        )
