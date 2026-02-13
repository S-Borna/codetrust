"""Tests for custom rule loading from YAML/TOML."""

from __future__ import annotations

from src.gateway.custom_rules import (
    _normalize_rule,
    _validate_rule,
    load_custom_rules,
    load_custom_rules_toml,
    load_custom_rules_yaml,
)

# --- Validation ---


class TestValidation:
    def test_valid_rule(self):
        rule = {"id": "test", "pattern": r"\bfoo\b", "message": "No foo"}
        assert _validate_rule(rule, "terminal") is None

    def test_missing_id(self):
        rule = {"pattern": r"\bfoo\b", "message": "No foo"}
        err = _validate_rule(rule, "terminal")
        assert err and "id" in err

    def test_missing_pattern(self):
        rule = {"id": "test", "message": "No foo"}
        err = _validate_rule(rule, "terminal")
        assert err and "pattern" in err

    def test_missing_message(self):
        rule = {"id": "test", "pattern": r"\bfoo\b"}
        err = _validate_rule(rule, "terminal")
        assert err and "message" in err

    def test_invalid_severity(self):
        rule = {"id": "test", "pattern": r"\bfoo\b", "message": "x", "severity": "INFO"}
        err = _validate_rule(rule, "terminal")
        assert err and "severity" in err

    def test_invalid_regex(self):
        rule = {"id": "test", "pattern": r"[invalid", "message": "x"}
        err = _validate_rule(rule, "terminal")
        assert err and "regex" in err

    def test_not_a_dict(self):
        err = _validate_rule("string", "terminal")
        assert err and "not a dict" in err

    def test_empty_id(self):
        rule = {"id": "", "pattern": r"\bfoo\b", "message": "x"}
        err = _validate_rule(rule, "terminal")
        assert err and "invalid id" in err


# --- Normalization ---


class TestNormalization:
    def test_prefixes_custom(self):
        raw = {"id": "my_rule", "pattern": r"\bx\b", "message": "msg"}
        normalized = _normalize_rule(raw)
        assert normalized["id"] == "custom_my_rule"

    def test_already_prefixed(self):
        raw = {"id": "custom_my_rule", "pattern": r"\bx\b", "message": "msg"}
        normalized = _normalize_rule(raw)
        assert normalized["id"] == "custom_my_rule"

    def test_defaults_severity_block(self):
        raw = {"id": "rule", "pattern": r"\bx\b", "message": "msg"}
        normalized = _normalize_rule(raw)
        assert normalized["severity"] == "BLOCK"

    def test_keeps_warn(self):
        raw = {"id": "rule", "pattern": r"\bx\b", "message": "msg", "severity": "WARN"}
        normalized = _normalize_rule(raw)
        assert normalized["severity"] == "WARN"

    def test_suggestion_default(self):
        raw = {"id": "rule", "pattern": r"\bx\b", "message": "msg"}
        normalized = _normalize_rule(raw)
        assert normalized["suggestion"] == ""


# --- YAML loading ---


class TestYamlLoading:
    def test_file_not_found(self, tmp_path):
        terminal, content = load_custom_rules_yaml(tmp_path / "nope.yaml")
        assert terminal == []
        assert content == []

    def test_load_terminal_rules(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(
            'terminal_rules:\n'
            '  - id: no_docker_priv\n'
            '    pattern: "docker\\\\s+run\\\\s+--privileged"\n'
            '    message: "No privileged containers"\n'
            '    severity: BLOCK\n'
        )
        terminal, content = load_custom_rules_yaml(yaml_file)
        assert len(terminal) == 1
        assert terminal[0]["id"] == "custom_no_docker_priv"
        assert content == []

    def test_load_content_rules(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(
            'content_rules:\n'
            '  - id: no_debug\n'
            '    pattern: "debugger;"\n'
            '    message: "Remove debugger"\n'
            '    severity: WARN\n'
        )
        terminal, content = load_custom_rules_yaml(yaml_file)
        assert terminal == []
        assert len(content) == 1
        assert content[0]["id"] == "custom_no_debug"

    def test_skip_invalid_rules(self, tmp_path):
        yaml_file = tmp_path / "rules.yaml"
        yaml_file.write_text(
            'terminal_rules:\n'
            '  - id: good_rule\n'
            '    pattern: "foo"\n'
            '    message: "Valid rule"\n'
            '  - id: bad_rule\n'
            '    pattern: "[invalid"\n'  # bad regex
            '    message: "Invalid regex"\n'
        )
        terminal, _content = load_custom_rules_yaml(yaml_file)
        assert len(terminal) == 1
        assert terminal[0]["id"] == "custom_good_rule"


# --- TOML loading ---


class TestTomlLoading:
    def test_empty_data(self):
        terminal, content = load_custom_rules_toml({})
        assert terminal == []
        assert content == []

    def test_load_from_toml_structure(self):
        data = {
            "codetrust": {
                "governance": {
                    "custom_rules": {
                        "terminal_rules": [
                            {
                                "id": "no_wget",
                                "pattern": r"wget\s+http://",
                                "message": "Use https for downloads",
                                "severity": "WARN",
                            }
                        ],
                        "content_rules": [],
                    }
                }
            }
        }
        terminal, _content = load_custom_rules_toml(data)
        assert len(terminal) == 1
        assert terminal[0]["id"] == "custom_no_wget"
        assert terminal[0]["severity"] == "WARN"

    def test_skip_invalid_toml_rule(self):
        data = {
            "codetrust": {
                "governance": {
                    "custom_rules": {
                        "terminal_rules": [
                            {"id": "", "pattern": "x", "message": "bad id"}
                        ]
                    }
                }
            }
        }
        terminal, _ = load_custom_rules_toml(data)
        assert terminal == []


# --- Full loader ---


class TestLoadCustomRules:
    def test_empty_workspace(self, tmp_path):
        terminal, content = load_custom_rules(tmp_path)
        assert terminal == []
        assert content == []

    def test_yaml_rules_loaded(self, tmp_path):
        rules_dir = tmp_path / ".codetrust"
        rules_dir.mkdir()
        yaml_file = rules_dir / "custom_rules.yaml"
        yaml_file.write_text(
            'terminal_rules:\n'
            '  - id: test_rule\n'
            '    pattern: "test_pattern"\n'
            '    message: "Test message"\n'
        )
        terminal, _content = load_custom_rules(tmp_path)
        assert len(terminal) == 1
        assert terminal[0]["id"] == "custom_test_rule"

    def test_deduplication(self, tmp_path):
        """Same rule ID in YAML and TOML — YAML wins."""
        rules_dir = tmp_path / ".codetrust"
        rules_dir.mkdir()
        yaml_file = rules_dir / "custom_rules.yaml"
        yaml_file.write_text(
            'terminal_rules:\n'
            '  - id: dupe_rule\n'
            '    pattern: "yaml_pattern"\n'
            '    message: "From YAML"\n'
        )
        toml_file = tmp_path / ".codetrust.toml"
        toml_file.write_text(
            '[codetrust.governance.custom_rules]\n'
            '[[codetrust.governance.custom_rules.terminal_rules]]\n'
            'id = "dupe_rule"\n'
            'pattern = "toml_pattern"\n'
            'message = "From TOML"\n'
        )
        terminal, _ = load_custom_rules(tmp_path)
        # Only one instance of the rule
        matching = [r for r in terminal if r["id"] == "custom_dupe_rule"]
        assert len(matching) == 1
        # YAML takes priority
        assert matching[0]["message"] == "From YAML"


# --- Integration with CommandInterceptor ---


class TestInterceptorIntegration:
    def test_custom_terminal_rule_applied(self, tmp_path):
        rules_dir = tmp_path / ".codetrust"
        rules_dir.mkdir()
        yaml_file = rules_dir / "custom_rules.yaml"
        yaml_file.write_text(
            'terminal_rules:\n'
            '  - id: no_reboot\n'
            '    pattern: "reboot"\n'
            '    message: "Reboot not allowed"\n'
            '    severity: BLOCK\n'
        )

        from src.gateway.interceptor import CommandInterceptor

        interceptor = CommandInterceptor(workspace=str(tmp_path))
        result = interceptor.check_terminal("sudo reboot")
        assert result.blocked
        assert result.rule_id == "custom_no_reboot"

    def test_custom_content_rule_applied(self, tmp_path):
        rules_dir = tmp_path / ".codetrust"
        rules_dir.mkdir()
        yaml_file = rules_dir / "custom_rules.yaml"
        yaml_file.write_text(
            'content_rules:\n'
            '  - id: no_debugger\n'
            '    pattern: "debugger;"\n'
            '    message: "Debugger statement"\n'
            '    severity: WARN\n'
        )

        from src.gateway.interceptor import CommandInterceptor

        interceptor = CommandInterceptor(workspace=str(tmp_path))
        result = interceptor.check_file_write(
            "test.js", "function foo() {\n  debugger;\n}"
        )
        assert result.verdict == "WARN"
        assert result.rule_id == "custom_no_debugger"

    def test_no_custom_rules_still_works(self):
        """Without workspace, interceptor uses only built-in rules."""
        from src.gateway.interceptor import CommandInterceptor

        interceptor = CommandInterceptor()
        result = interceptor.check_terminal("ls -la")
        assert not result.blocked
