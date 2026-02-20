"""Tests for Batch 3 config scanning rules.

Covers 36 rules across 7 categories:
  - Redis (6) — .conf files
  - HashiCorp Vault (5) — .hcl files
  - Prometheus / Grafana (5) — .yml / .yaml files
  - Systemd (5) — .service / .timer files
  - Docker Compose Advanced (5) — .yml / .yaml files
  - GitHub Actions Advanced (5) — .yml / .yaml files
  - General Config Hygiene (5) — cross-cutting
"""

from __future__ import annotations

from src.cli import (
    SOURCE_EXTS,
    scan_text,
)
from src.rules.anti_patterns import ANTI_PATTERNS, DEVOPS_EXTENSIONS
from src.services.static_analyzer import StaticAnalyzer

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

_analyzer = StaticAnalyzer()

BATCH3_RULE_IDS: set[str] = {
    # Redis
    "redis_bind_all", "redis_protected_mode_off", "redis_weak_password",
    "redis_maxmemory_noeviction", "redis_save_disabled", "redis_aof_no_fsync",
    # Vault
    "vault_tls_disabled", "vault_file_storage", "vault_disable_mlock",
    "vault_telemetry_unauth", "vault_max_lease_long",
    # Monitoring
    "prom_scrape_too_fast", "prom_eval_too_fast",
    "grafana_anon_access", "grafana_default_admin", "grafana_allow_embedding",
    # Systemd
    "systemd_restart_disabled", "systemd_restart_no_delay",
    "systemd_unlimited_resource", "systemd_exec_shell_wrapper",
    "systemd_no_timeout_stop",
    # Docker Compose Advanced
    "compose_ipc_host", "compose_network_host", "compose_pid_host",
    "compose_restart_always", "compose_env_inline_secret",
    # GitHub Actions Advanced
    "ci_pull_request_target", "ci_write_all_permissions",
    "ci_curl_pipe_shell", "ci_checkout_persist_creds",
    "ci_inject_untrusted_input",
    # General Config
    "config_ssl_verify_off", "config_weak_tls_version",
    "config_world_writable", "config_listen_all_interfaces",
    "config_private_key_inline",
}

BATCH3_RULE_COUNT = 36


def _find(code: str, filename: str, rule_id: str) -> bool:
    """Return True if the rule fires on the given code via StaticAnalyzer."""
    findings = _analyzer.scan_code(code, filename)
    return any(f.rule_id == rule_id for f in findings)


def _cli_find(code: str, filepath: str, rule_id: str) -> bool:
    """Return True if the rule fires via the CLI scanner."""
    findings = scan_text(code, filepath)
    return any(f["rule_id"] == rule_id for f in findings)


# ═══════════════════════════════════════════════════════════════════════════
#  META TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestBatch3Meta:
    """Verify Batch 3 rules exist in ANTI_PATTERNS and extension routing."""

    def test_batch3_rules_present(self) -> None:
        """All 36 Batch 3 rule IDs must exist in ANTI_PATTERNS."""
        backend_ids = {r["id"] for r in ANTI_PATTERNS}
        missing = BATCH3_RULE_IDS - backend_ids
        assert not missing, f"Missing rule IDs: {missing}"

    def test_batch3_count(self) -> None:
        """Exactly 36 Batch 3 rules must exist."""
        assert len(BATCH3_RULE_IDS) == BATCH3_RULE_COUNT

    def test_backend_has_204_rules(self) -> None:
        """Backend ANTI_PATTERNS must contain 204 rules (199 + 5 diagnostic markers)."""
        assert len(ANTI_PATTERNS) == 204

    def test_no_duplicate_ids(self) -> None:
        """All rule IDs across ANTI_PATTERNS must be unique."""
        ids = [r["id"] for r in ANTI_PATTERNS]
        assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_new_extensions_in_source_exts(self) -> None:
        """New file extensions (.service, .timer, .ini, .cfg) must be in SOURCE_EXTS."""
        for ext in (".service", ".timer", ".ini", ".cfg"):
            assert ext in SOURCE_EXTS, f"{ext} not in SOURCE_EXTS"

    def test_new_extensions_in_devops_extensions(self) -> None:
        """New file extensions must be in DEVOPS_EXTENSIONS."""
        for ext in (".service", ".timer", ".ini", ".cfg"):
            assert ext in DEVOPS_EXTENSIONS, f"{ext} not in DEVOPS_EXTENSIONS"


# ═══════════════════════════════════════════════════════════════════════════
#  REDIS RULES (.conf)
# ═══════════════════════════════════════════════════════════════════════════

class TestRedisRules:
    """Redis configuration security rules."""

    def test_redis_bind_all(self) -> None:
        assert _find("bind 0.0.0.0", "redis.conf", "redis_bind_all")

    def test_redis_bind_all_star(self) -> None:
        assert _find("bind *", "redis.conf", "redis_bind_all")

    def test_redis_bind_safe(self) -> None:
        assert not _find("bind 127.0.0.1", "redis.conf", "redis_bind_all")

    def test_redis_protected_mode_off(self) -> None:
        assert _find("protected-mode no", "redis.conf", "redis_protected_mode_off")

    def test_redis_protected_mode_on(self) -> None:
        assert not _find("protected-mode yes", "redis.conf", "redis_protected_mode_off")

    def test_redis_weak_password(self) -> None:
        assert _find("requirepass foobared", "redis.conf", "redis_weak_password")

    def test_redis_weak_password_admin(self) -> None:
        assert _find("requirepass admin", "redis.conf", "redis_weak_password")

    def test_redis_strong_password(self) -> None:
        assert not _find("requirepass s3cur3-r4nd0m-p@ssw0rd!", "redis.conf", "redis_weak_password")

    def test_redis_maxmemory_noeviction(self) -> None:
        assert _find("maxmemory-policy noeviction", "redis.conf", "redis_maxmemory_noeviction")

    def test_redis_maxmemory_lru(self) -> None:
        assert not _find("maxmemory-policy allkeys-lru", "redis.conf", "redis_maxmemory_noeviction")

    def test_redis_save_disabled(self) -> None:
        assert _find('save ""', "redis.conf", "redis_save_disabled")

    def test_redis_aof_no_fsync(self) -> None:
        assert _find("appendfsync no", "redis.conf", "redis_aof_no_fsync")

    def test_redis_aof_everysec(self) -> None:
        assert not _find("appendfsync everysec", "redis.conf", "redis_aof_no_fsync")

    def test_redis_cli_routing(self) -> None:
        """Redis rules must fire on .conf via CLI scanner."""
        assert _cli_find("protected-mode no", "configs/redis.conf", "redis_protected_mode_off")


# ═══════════════════════════════════════════════════════════════════════════
#  VAULT RULES (.hcl)
# ═══════════════════════════════════════════════════════════════════════════

class TestVaultRules:
    """HashiCorp Vault configuration rules."""

    def test_vault_tls_disabled(self) -> None:
        assert _find("tls_disable = 1", "vault.hcl", "vault_tls_disabled")

    def test_vault_tls_disabled_true(self) -> None:
        assert _find('tls_disable = true', "vault.hcl", "vault_tls_disabled")

    def test_vault_tls_enabled(self) -> None:
        assert not _find("tls_disable = 0", "vault.hcl", "vault_tls_disabled")

    def test_vault_file_storage(self) -> None:
        assert _find('storage "file" {', "vault.hcl", "vault_file_storage")

    def test_vault_consul_storage(self) -> None:
        assert not _find('storage "consul" {', "vault.hcl", "vault_file_storage")

    def test_vault_disable_mlock(self) -> None:
        assert _find("disable_mlock = true", "vault.hcl", "vault_disable_mlock")

    def test_vault_mlock_enabled(self) -> None:
        assert not _find("disable_mlock = false", "vault.hcl", "vault_disable_mlock")

    def test_vault_telemetry_unauth(self) -> None:
        assert _find("unauthenticated_metrics_access = true", "vault.hcl", "vault_telemetry_unauth")

    def test_vault_max_lease_long(self) -> None:
        assert _find('max_lease_ttl = "8760h"', "vault.hcl", "vault_max_lease_long")

    def test_vault_max_lease_short(self) -> None:
        assert not _find('max_lease_ttl = "768h"', "vault.hcl", "vault_max_lease_long")

    def test_vault_cli_routing(self) -> None:
        """Vault rules must fire on .hcl via CLI scanner."""
        assert _cli_find("tls_disable = 1", "configs/vault.hcl", "vault_tls_disabled")


# ═══════════════════════════════════════════════════════════════════════════
#  MONITORING RULES (.yml / .yaml)
# ═══════════════════════════════════════════════════════════════════════════

class TestMonitoringRules:
    """Prometheus and Grafana monitoring rules."""

    def test_prom_scrape_too_fast(self) -> None:
        assert _find("scrape_interval: 2s", "prometheus.yml", "prom_scrape_too_fast")

    def test_prom_scrape_ok(self) -> None:
        assert not _find("scrape_interval: 15s", "prometheus.yml", "prom_scrape_too_fast")

    def test_prom_eval_too_fast(self) -> None:
        assert _find("evaluation_interval: 3s", "prometheus.yml", "prom_eval_too_fast")

    def test_prom_eval_ok(self) -> None:
        assert not _find("evaluation_interval: 30s", "prometheus.yml", "prom_eval_too_fast")

    def test_grafana_anon_access(self) -> None:
        assert _find("GF_AUTH_ANONYMOUS_ENABLED = true", "docker-compose.yml", "grafana_anon_access")

    def test_grafana_anon_off(self) -> None:
        assert not _find("GF_AUTH_ANONYMOUS_ENABLED = false", "docker-compose.yml", "grafana_anon_access")

    def test_grafana_default_admin(self) -> None:
        assert _find("GF_SECURITY_ADMIN_PASSWORD = admin", "docker-compose.yml", "grafana_default_admin")

    def test_grafana_strong_password(self) -> None:
        assert not _find("GF_SECURITY_ADMIN_PASSWORD = xK9!mZ2@pL5q", "docker-compose.yml", "grafana_default_admin")

    def test_grafana_allow_embedding(self) -> None:
        assert _find("GF_SECURITY_ALLOW_EMBEDDING = true", "docker-compose.yml", "grafana_allow_embedding")


# ═══════════════════════════════════════════════════════════════════════════
#  SYSTEMD RULES (.service / .timer)
# ═══════════════════════════════════════════════════════════════════════════

class TestSystemdRules:
    """Systemd unit file rules."""

    def test_systemd_restart_disabled(self) -> None:
        assert _find("Restart=no", "myapp.service", "systemd_restart_disabled")

    def test_systemd_restart_on_failure(self) -> None:
        assert not _find("Restart=on-failure", "myapp.service", "systemd_restart_disabled")

    def test_systemd_restart_no_delay(self) -> None:
        assert _find("RestartSec=0", "myapp.service", "systemd_restart_no_delay")

    def test_systemd_restart_delay_ok(self) -> None:
        assert not _find("RestartSec=5", "myapp.service", "systemd_restart_no_delay")

    def test_systemd_unlimited_nofile(self) -> None:
        assert _find("LimitNOFILE=infinity", "myapp.service", "systemd_unlimited_resource")

    def test_systemd_unlimited_nproc(self) -> None:
        assert _find("LimitNPROC=unlimited", "myapp.service", "systemd_unlimited_resource")

    def test_systemd_bounded_limit(self) -> None:
        assert not _find("LimitNOFILE=65535", "myapp.service", "systemd_unlimited_resource")

    def test_systemd_exec_shell_wrapper(self) -> None:
        assert _find("ExecStart=/bin/bash -c echo hello", "myapp.service", "systemd_exec_shell_wrapper")

    def test_systemd_exec_direct(self) -> None:
        assert not _find("ExecStart=/usr/bin/myapp --port 8080", "myapp.service", "systemd_exec_shell_wrapper")

    def test_systemd_no_timeout_stop(self) -> None:
        assert _find("TimeoutStopSec=0", "myapp.service", "systemd_no_timeout_stop")

    def test_systemd_no_timeout_infinity(self) -> None:
        assert _find("TimeoutStopSec=infinity", "myapp.service", "systemd_no_timeout_stop")

    def test_systemd_timeout_ok(self) -> None:
        assert not _find("TimeoutStopSec=90", "myapp.service", "systemd_no_timeout_stop")

    def test_systemd_timer_file(self) -> None:
        """Rules must also fire on .timer files."""
        assert _find("Restart=no", "backup.timer", "systemd_restart_disabled")

    def test_systemd_cli_routing(self) -> None:
        """Systemd rules must fire on .service via CLI scanner."""
        assert _cli_find("RestartSec=0", "units/myapp.service", "systemd_restart_no_delay")


# ═══════════════════════════════════════════════════════════════════════════
#  DOCKER COMPOSE ADVANCED RULES
# ═══════════════════════════════════════════════════════════════════════════

class TestComposeAdvancedRules:
    """Docker Compose advanced security rules."""

    def test_compose_ipc_host(self) -> None:
        assert _find("  ipc: host", "docker-compose.yml", "compose_ipc_host")

    def test_compose_network_host(self) -> None:
        assert _find("  network_mode: host", "docker-compose.yml", "compose_network_host")

    def test_compose_network_bridge(self) -> None:
        assert not _find("  network_mode: bridge", "docker-compose.yml", "compose_network_host")

    def test_compose_pid_host(self) -> None:
        assert _find("  pid: host", "docker-compose.yml", "compose_pid_host")

    def test_compose_restart_always(self) -> None:
        assert _find("  restart: always", "docker-compose.yml", "compose_restart_always")

    def test_compose_restart_unless_stopped(self) -> None:
        assert not _find("  restart: unless-stopped", "docker-compose.yml", "compose_restart_always")

    def test_compose_env_inline_secret(self) -> None:
        assert _find("  - DB_PASSWORD=supersecret123", "docker-compose.yml", "compose_env_inline_secret")

    def test_compose_env_inline_postgres(self) -> None:
        assert _find("  - POSTGRES_PASSWORD=mypass123", "docker-compose.yml", "compose_env_inline_secret")

    def test_compose_env_ref_ok(self) -> None:
        """Short values (< 4 chars) should not trigger."""
        assert not _find("  - DB_PASSWORD=xx", "docker-compose.yml", "compose_env_inline_secret")


# ═══════════════════════════════════════════════════════════════════════════
#  GITHUB ACTIONS ADVANCED RULES
# ═══════════════════════════════════════════════════════════════════════════

class TestGitHubActionsAdvancedRules:
    """GitHub Actions security rules."""

    def test_ci_pull_request_target(self) -> None:
        assert _find("  pull_request_target:", ".github/workflows/ci.yml", "ci_pull_request_target")

    def test_ci_pull_request_ok(self) -> None:
        assert not _find("  pull_request:", ".github/workflows/ci.yml", "ci_pull_request_target")

    def test_ci_write_all_permissions(self) -> None:
        assert _find("  permissions: write-all", ".github/workflows/ci.yml", "ci_write_all_permissions")

    def test_ci_scoped_permissions(self) -> None:
        assert not _find("  permissions:\n    contents: write", ".github/workflows/ci.yml", "ci_write_all_permissions")

    def test_ci_curl_pipe_shell(self) -> None:
        assert _find("curl -sL https://example.com/install | bash", ".github/workflows/ci.yml", "ci_curl_pipe_shell")

    def test_ci_curl_pipe_sh(self) -> None:
        assert _find("curl https://example.com/script | sh", ".github/workflows/ci.yml", "ci_curl_pipe_shell")

    def test_ci_curl_download_ok(self) -> None:
        assert not _find("curl -o script.sh https://example.com/install", ".github/workflows/ci.yml", "ci_curl_pipe_shell")

    def test_ci_checkout_persist_creds(self) -> None:
        assert _find("persist-credentials: true", ".github/workflows/ci.yml", "ci_checkout_persist_creds")

    def test_ci_checkout_no_persist(self) -> None:
        assert not _find("persist-credentials: false", ".github/workflows/ci.yml", "ci_checkout_persist_creds")

    def test_ci_inject_untrusted_input_issue(self) -> None:
        assert _find("${{ github.event.issue.title }}", ".github/workflows/ci.yml", "ci_inject_untrusted_input")

    def test_ci_inject_untrusted_input_pr_body(self) -> None:
        assert _find("${{ github.event.pull_request.body }}", ".github/workflows/ci.yml", "ci_inject_untrusted_input")

    def test_ci_inject_safe_ref(self) -> None:
        assert not _find("${{ github.ref }}", ".github/workflows/ci.yml", "ci_inject_untrusted_input")

    def test_ci_rules_cli_routing(self) -> None:
        """CI rules must fire on GitHub Actions workflow files via CLI."""
        assert _cli_find(
            "  pull_request_target:",
            ".github/workflows/build.yml",
            "ci_pull_request_target",
        )


# ═══════════════════════════════════════════════════════════════════════════
#  GENERAL CONFIG HYGIENE RULES
# ═══════════════════════════════════════════════════════════════════════════

class TestConfigHygieneRules:
    """Cross-cutting configuration hygiene rules."""

    def test_config_ssl_verify_off_yaml(self) -> None:
        assert _find("ssl_verify: false", "config.yml", "config_ssl_verify_off")

    def test_config_ssl_verify_off_toml(self) -> None:
        assert _find("verify_ssl = 0", "config.toml", "config_ssl_verify_off")

    def test_config_ssl_verify_on(self) -> None:
        assert not _find("ssl_verify: true", "config.yml", "config_ssl_verify_off")

    def test_config_ssl_verify_off_ini(self) -> None:
        assert _find("tls_verify = no", "app.ini", "config_ssl_verify_off")

    def test_config_weak_tls_version(self) -> None:
        assert _find("tls_version: 1.0", "config.yml", "config_weak_tls_version")

    def test_config_weak_tls_sslv3(self) -> None:
        assert _find("ssl_version = SSLv3", "app.cfg", "config_weak_tls_version")

    def test_config_tls_12_ok(self) -> None:
        assert not _find("tls_min_version: 1.2", "config.yml", "config_weak_tls_version")

    def test_config_world_writable(self) -> None:
        assert _find("chmod 777 /var/data", "deploy.yml", "config_world_writable")

    def test_config_world_writable_mode(self) -> None:
        assert _find("mode: 0777", "deploy.yml", "config_world_writable")

    def test_config_restricted_ok(self) -> None:
        assert not _find("chmod 755 /var/data", "deploy.yml", "config_world_writable")

    def test_config_listen_all_interfaces(self) -> None:
        assert _find('listen_address: "0.0.0.0"', "config.yml", "config_listen_all_interfaces")

    def test_config_listen_localhost(self) -> None:
        assert not _find("listen_address: 127.0.0.1", "config.yml", "config_listen_all_interfaces")

    def test_config_private_key_inline(self) -> None:
        assert _find("-----BEGIN RSA PRIVATE KEY-----", "config.yml", "config_private_key_inline")

    def test_config_private_key_ec(self) -> None:
        assert _find("-----BEGIN EC PRIVATE KEY-----", "secrets.toml", "config_private_key_inline")

    def test_config_public_key_ok(self) -> None:
        assert not _find("-----BEGIN PUBLIC KEY-----", "config.yml", "config_private_key_inline")


# ═══════════════════════════════════════════════════════════════════════════
#  CLI ROUTING INTEGRATION
# ═══════════════════════════════════════════════════════════════════════════

class TestBatch3CLIRouting:
    """Verify CLI scanner routes Batch 3 rules to correct file types."""

    def test_conf_files_get_redis_and_nginx_rules(self) -> None:
        """Both Redis and Nginx rules must fire on .conf files."""
        findings = scan_text(
            "protected-mode no\nserver_tokens on;",
            "app.conf",
        )
        rule_ids = {f["rule_id"] for f in findings}
        assert "redis_protected_mode_off" in rule_ids
        assert "nginx_server_tokens_on" in rule_ids

    def test_hcl_files_get_vault_rules(self) -> None:
        """Vault rules must fire on .hcl files via CLI."""
        findings = scan_text('storage "file" {', "config.hcl")
        rule_ids = {f["rule_id"] for f in findings}
        assert "vault_file_storage" in rule_ids

    def test_ini_files_scanned(self) -> None:
        """New .ini extension must be scanned by CLI."""
        findings = scan_text("ssl_verify = false", "app.ini")
        rule_ids = {f["rule_id"] for f in findings}
        assert "config_ssl_verify_off" in rule_ids

    def test_service_files_get_systemd_rules(self) -> None:
        """Systemd rules must fire on .service files."""
        findings = scan_text("Restart=no\n", "myapp.service")
        rule_ids = {f["rule_id"] for f in findings}
        assert "systemd_restart_disabled" in rule_ids

    def test_ci_files_get_advanced_rules(self) -> None:
        """CI advanced rules must fire in .github/workflows."""
        findings = scan_text(
            "  permissions: write-all\n",
            ".github/workflows/ci.yml",
        )
        rule_ids = {f["rule_id"] for f in findings}
        assert "ci_write_all_permissions" in rule_ids
