"""Application settings via pydantic-settings, loaded from environment variables."""

import os

from pydantic import ConfigDict, model_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration via environment variables prefixed with CODETRUST_."""

    model_config = ConfigDict(env_prefix="CODETRUST_", strict=True)

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    version: str = "1.7.0"

    # --- Auth ---
    api_key: str = ""  # Empty = no auth required (local dev)

    # --- Redis ---
    redis_url: str = "redis://localhost:6379"
    redis_enabled: bool = True

    @model_validator(mode="after")
    def _resolve_platform_env_vars(self) -> "Settings":
        """Fallback to platform env vars (Railway, Render, Heroku, etc.).

        These platforms set REDIS_URL / DATABASE_URL automatically.
        We prefer CODETRUST_-prefixed vars but fall back gracefully.
        """
        # Redis: CODETRUST_REDIS_URL > REDIS_PRIVATE_URL > REDIS_URL
        if self.redis_url == "redis://localhost:6379":
            for var in ("REDIS_PRIVATE_URL", "REDIS_URL"):
                val = os.environ.get(var)
                if val:
                    self.redis_url = val
                    break

        # Database: CODETRUST_DATABASE_URL > DATABASE_PRIVATE_URL > DATABASE_URL
        if self.database_url == "sqlite+aiosqlite:///codetrust.db":
            for var in ("DATABASE_PRIVATE_URL", "DATABASE_URL"):
                val = os.environ.get(var)
                if val:
                    # Ensure async driver for SQLAlchemy
                    if val.startswith("postgresql://"):
                        val = val.replace("postgresql://", "postgresql+asyncpg://", 1)
                    self.database_url = val
                    break

        return self

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

    # --- Sandbox ---
    sandbox_enabled: bool = False  # Must be explicitly enabled
    sandbox_memory_limit: str = "256m"
    sandbox_default_timeout: int = 10  # seconds
    sandbox_max_timeout: int = 30
    sandbox_image_python: str = "codetrust-sandbox-python:latest"
    sandbox_image_node: str = "codetrust-sandbox-node:latest"
    sandbox_image_go: str = "codetrust-sandbox-go:latest"
    sandbox_image_rust: str = "codetrust-sandbox-rust:latest"

    # --- Rate Limits ---
    free_tier_daily_limit: int = 100
    pro_tier_daily_limit: int = 10_000

    # --- Database ---
    database_url: str = "sqlite+aiosqlite:///codetrust.db"
    database_echo: bool = False
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # --- Stripe ---
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_enterprise: str = ""

    # --- OAuth (GitHub) ---
    github_client_id: str = ""
    github_client_secret: str = ""
    github_token_url: str = "https://github.com/login/oauth/access_token"
    github_user_url: str = "https://api.github.com/user"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24  # 24 hours

    # --- Dashboard ---
    dashboard_url: str = "http://localhost:3000"

    # --- SARIF ---
    sarif_schema_url: str = "https://json.schemastore.org/sarif-2.1.0.json"
    tool_info_uri: str = "https://github.com/codetrust-ai/codetrust"


settings = Settings()
