"""Application settings via pydantic-settings, loaded from environment variables."""

from pydantic import ConfigDict
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration via environment variables prefixed with CODETRUST_."""

    model_config = ConfigDict(env_prefix="CODETRUST_")

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    version: str = "1.0.0"

    # --- Auth ---
    api_key: str = ""  # Empty = no auth required (local dev)

    # --- Redis ---
    redis_url: str = "redis://localhost:6379"
    redis_enabled: bool = True

    # --- Cache TTLs (seconds) ---
    cache_ttl_package_exists: int = 86400  # 24h — package existence rarely changes
    cache_ttl_package_version: int = 3600  # 1h — new versions release frequently
    cache_ttl_docker_tag: int = 86400  # 24h
    cache_ttl_api_endpoint: int = 1800  # 30min — endpoints can change
    cache_ttl_not_found: int = 3600  # 1h — retry not-found after 1h

    # --- HTTP ---
    http_timeout: float = 10.0  # seconds
    http_max_connections: int = 50
    http_max_keepalive: int = 20

    # --- Registry URLs ---
    pypi_url: str = "https://pypi.org/pypi/{package}/json"
    pypi_version_url: str = "https://pypi.org/pypi/{package}/{version}/json"
    npm_url: str = "https://registry.npmjs.org/{package}"
    crates_url: str = "https://crates.io/api/v1/crates/{package}"
    go_proxy_url: str = "https://proxy.golang.org/{package}/@latest"
    docker_hub_tags_url: str = (
        "https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}"
    )
    docker_hub_list_url: str = (
        "https://hub.docker.com/v2/repositories/library/{image}/tags?page_size=100"
    )

    # --- Rate Limits ---
    free_tier_daily_limit: int = 100
    pro_tier_daily_limit: int = 10_000


settings = Settings()
