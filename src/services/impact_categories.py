# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Rule-to-category mapping for impact telemetry.

Every BLOCK finding must map to exactly one of 6 impact categories.
The sum of all category counters must equal total_blocks.
"""

from __future__ import annotations

IMPACT_CATEGORY_OTHER: str = "other"

# ─── Explicit rule → category mappings ───────────────────────────────────────
# These take priority over prefix matching.

RULE_TO_CATEGORY: dict[str, str] = {
    # Category 1: Destructive Commands Blocked
    "agent_os_system": "destructive_commands",
    "agent_os_popen": "destructive_commands",
    "agent_subprocess_shell": "destructive_commands",
    "agent_subprocess_shell_true": "destructive_commands",
    "agent_rm_rf": "destructive_commands",
    "sql_drop_table": "destructive_commands",
    "sql_drop_no_if_exists": "destructive_commands",
    "sql_truncate": "destructive_commands",
    "sql_delete_no_where": "destructive_commands",
    "git_force_push": "destructive_commands",
    "docker_run_privileged": "destructive_commands",
    "k8s_privileged_pod": "destructive_commands",
    "k8s_privileged": "destructive_commands",

    # Category 2: AI Hallucinations Caught
    "import_not_found": "hallucinations",
    "sig_unknown_function": "hallucinations",
    "sig_too_few_args": "hallucinations",
    "sig_too_many_args": "hallucinations",
    "hallucinated_import_nonexistent": "hallucinations",
    "hallucinated_import_misspelled": "hallucinations",
    "hallucinated_method_chain": "hallucinations",
    "hallucinated_config_option": "hallucinations",
    "hallucinated_cli_flag": "hallucinations",
    "hallucinated_version": "hallucinations",
    "hallucinated_env_var": "hallucinations",
    "placeholder_url": "hallucinations",

    # Category 3: Secrets Exposure Prevented
    "hardcoded_secret": "secrets_exposure",
    "api_key_in_config": "secrets_exposure",
    "database_url_credentials": "secrets_exposure",
    "ansible_plaintext_password": "secrets_exposure",
    "private_key_in_code": "secrets_exposure",
    "config_private_key_inline": "secrets_exposure",
    "docker_env_secret": "secrets_exposure",
    "cfn_hardcoded_credentials": "secrets_exposure",
    "ps_hardcoded_password": "secrets_exposure",
    "redis_weak_password": "secrets_exposure",
    "auth_plaintext_password_storage": "secrets_exposure",
    "env_default_secret_key": "secrets_exposure",

    # Category 4: Injection Attacks Stopped
    "eval_exec": "injection_attacks",
    "string_concat_sql": "injection_attacks",
    "heredoc": "injection_attacks",
    "agent_code_injection": "injection_attacks",
    "sql_injection": "injection_attacks",
    "ruby_eval": "injection_attacks",
    "php_eval": "injection_attacks",
    "pickle_load": "injection_attacks",
    "python_yaml_load_unsafe": "injection_attacks",
    "deser_yaml_load_unsafe": "injection_attacks",
    "ml2_pickle_load_unsafe": "injection_attacks",
    "net_open_redirect": "injection_attacks",
    "path_traversal_dotdot": "injection_attacks",

    # Category 5: Unsafe Configurations Detected
    "config_world_writable": "unsafe_config",
    "debug_mode_enabled": "unsafe_config",
    "any_type": "unsafe_config",
    "datetime_utcnow": "unsafe_config",
    "bare_except": "unsafe_config",
    "mutable_default": "unsafe_config",
    "docker_latest_tag": "unsafe_config",
    "config_ssl_verify_off": "unsafe_config",
    "except_swallow": "unsafe_config",
    "symptom_fix_marker": "unsafe_config",
    "sleep_no_context": "unsafe_config",

    # Category 6: Supply Chain Risks Identified
    "cve_detected": "supply_chain",
    "license_violation": "supply_chain",
    "docker_image_unverified": "supply_chain",
    "ci_unpinned_action": "supply_chain",
    "tf_no_versioned_module": "supply_chain",
}

# ─── Prefix-based fallback mapping ───────────────────────────────────────────
# When a rule_id is not in RULE_TO_CATEGORY, match by prefix.
# Order matters: first match wins.

PREFIX_TO_CATEGORY: list[tuple[str, str]] = [
    # Injection / code execution
    ("sql_", "injection_attacks"),
    ("xss_", "injection_attacks"),
    ("xxe_", "injection_attacks"),
    ("ssrf_", "injection_attacks"),
    ("deser_", "injection_attacks"),
    ("data_pipeline_sql", "injection_attacks"),
    ("sec_xml_external", "injection_attacks"),

    # Secrets and crypto
    ("crypto_", "secrets_exposure"),
    ("sec_", "secrets_exposure"),
    ("auth_", "secrets_exposure"),
    ("tls_", "secrets_exposure"),
    ("py_flask_secret", "secrets_exposure"),
    ("py_django_secret", "secrets_exposure"),
    ("flask_session_no_secret", "secrets_exposure"),

    # Hallucinations
    ("hallucinated_", "hallucinations"),

    # Destructive
    ("k8s_", "destructive_commands"),

    # Unsafe config — broad patterns
    ("docker_", "unsafe_config"),
    ("py_flask_debug", "unsafe_config"),
    ("flask_jinja2", "unsafe_config"),
    ("ci_", "unsafe_config"),
    ("obs_", "unsafe_config"),
    ("a11y_", "unsafe_config"),
    ("long_function", "unsafe_config"),

    # Supply chain
    ("license_", "supply_chain"),
    ("cve_", "supply_chain"),

    # Numbered rules — categorize by prefix
    ("r1a_", "injection_attacks"),
    ("r1b_", "injection_attacks"),
    ("r2a_", "unsafe_config"),
    ("r2b_", "unsafe_config"),

    # Catch-all patterns for remaining common prefixes
    ("js_", "injection_attacks"),
    ("react_", "unsafe_config"),
    ("node_", "injection_attacks"),
    ("go_", "unsafe_config"),
    ("rust_", "unsafe_config"),
    ("ruby_", "injection_attacks"),
    ("php_", "injection_attacks"),
    ("java_", "injection_attacks"),
    ("net_", "injection_attacks"),
    ("mobile_", "unsafe_config"),
    ("browser_", "injection_attacks"),
    ("log_", "unsafe_config"),
    ("graphql_", "unsafe_config"),
    ("win_", "destructive_commands"),
    ("linux_", "destructive_commands"),
    ("macos_", "destructive_commands"),
]


CATEGORY_DISPLAY: dict[str, dict[str, str]] = {
    "destructive_commands": {
        "label": "Destructive Commands Blocked",
        "description": "rm -rf, DROP TABLE, force push, privileged containers",
        "icon": "🛡️",
    },
    "hallucinations": {
        "label": "AI Hallucinations Caught",
        "description": "Non-existent packages, unknown functions, wrong signatures",
        "icon": "🧠",
    },
    "secrets_exposure": {
        "label": "Secrets Exposure Prevented",
        "description": "Hardcoded API keys, passwords, tokens, credentials",
        "icon": "🔑",
    },
    "injection_attacks": {
        "label": "Injection Attacks Stopped",
        "description": "eval/exec, SQL injection, XSS, deserialization",
        "icon": "🐛",
    },
    "unsafe_config": {
        "label": "Unsafe Configurations Detected",
        "description": "Debug mode, missing timeouts, weak ciphers, code quality",
        "icon": "⚙️",
    },
    "supply_chain": {
        "label": "Supply Chain Risks Identified",
        "description": "CVE-affected packages, license violations, unverified images",
        "icon": "📦",
    },
}

IMPACT_CATEGORIES: tuple[str, ...] = (
    "destructive_commands",
    "hallucinations",
    "secrets_exposure",
    "injection_attacks",
    "unsafe_config",
    "supply_chain",
    IMPACT_CATEGORY_OTHER,
)

PUBLIC_IMPACT_CATEGORIES: tuple[str, ...] = (
    "destructive_commands",
    "hallucinations",
    "secrets_exposure",
    "injection_attacks",
    "unsafe_config",
    "supply_chain",
)


def get_rule_category(rule_id: str) -> str:
    """Return the impact category for a rule id.

    Checks explicit mapping first, then prefix-based fallback.
    Returns category key used for impact telemetry counters.

    Args:
        rule_id: CodeTrust rule id.

    Returns:
        Category key. Falls back to 'unsafe_config' if no match
        (every finding must count toward a visible category).
    """
    explicit = RULE_TO_CATEGORY.get(rule_id)
    if explicit is not None:
        return explicit

    for prefix, category in PREFIX_TO_CATEGORY:
        if rule_id.startswith(prefix):
            return category

    # Fallback: every BLOCK must be visible in a category.
    # 'unsafe_config' is the broadest bucket.
    return "unsafe_config"
