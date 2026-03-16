# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Application settings via pydantic-settings, loaded from environment variables."""

from pydantic import AliasChoices, ConfigDict, Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """All configuration via environment variables prefixed with CODETRUST_."""

    model_config = ConfigDict(env_prefix="CODETRUST_", strict=True)

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False
    version: str = "2.9.0"

    # --- Auth ---
    api_key: str = ""  # Empty = no auth required (local dev)
    require_auth_for_all_requests: bool = False

    # --- Redis ---
    redis_url: str = Field(
        default="redis://localhost:6379",
        validation_alias=AliasChoices("CODETRUST_REDIS_URL", "REDIS_URL"),
    )
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
    rubygems_url: str = "https://rubygems.org/api/v1/gems/{package}.json"
    packagist_url: str = "https://repo.packagist.org/p2/{package}.json"
    maven_url: str = "https://search.maven.org/solrsearch/select?q=g:{group}+AND+a:{artifact}&rows=1&wt=json"
    nuget_url: str = "https://api.nuget.org/v3-flatcontainer/{package}/index.json"
    docker_hub_tags_url: str = (
        "https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}"
    )
    docker_hub_list_url: str = (
        "https://hub.docker.com/v2/repositories/library/{image}/tags?page_size=100"
    )

    # --- External Stats ---
    pepy_api_key: str = ""  # pepy.tech API key for download stats

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
    github_app_id: str = ""
    github_app_private_key: str = ""
    github_app_webhook_secret: str = ""
    github_app_api_url: str = "https://api.github.com"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24  # 24 hours

    # --- SSO / OIDC ---
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid,profile,email"
    oidc_allowed_domains: str = ""  # comma-separated, empty = all
    oidc_role_claim: str = "roles"

    # --- Dashboard ---
    dashboard_url: str = "https://codetrust.ai"

    # --- Feedback Intake ---
    feedback_recipient_email: str = "said@saidborna.com"
    feedback_smtp_host: str = ""
    feedback_smtp_port: int = 587
    feedback_smtp_username: str = ""
    feedback_smtp_password: str = ""
    feedback_smtp_from_email: str = ""
    feedback_smtp_use_tls: bool = True
    feedback_smtp_use_ssl: bool = False
    feedback_smtp_timeout: float = 10.0
    feedback_webhook_url: str = ""
    feedback_webhook_token: str = ""
    feedback_webhook_timeout: float = 8.0
    feedback_report_sink_path: str = ".codetrust/report-intake.jsonl"

    # --- License ---
    license_key: str = ""  # Commercial license key for full feature access
    license_check_interval: int = 43_200  # 12 hours between re-validations
    license_offline_grace_days: int = 7  # Days allowed offline before lockout

    # --- Client Version Enforcement ---
    min_client_version: str = "2.6.1"  # Advisory minimum client version

    # --- Production Mode ---
    production_mode: bool = False  # True = hard-fail on invalid license (API server)

    # --- Rule Delivery ---
    rules_hmac_secret: str = ""  # HMAC secret for signing premium rule bundles

    # --- SARIF ---
    sarif_schema_url: str = "https://json.schemastore.org/sarif-2.1.0.json"
    tool_info_uri: str = "https://codetrust.ai"


settings = Settings()
