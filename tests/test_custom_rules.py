"""Tests for custom rule loading from YAML/TOML."""

from __future__ import annotations

from src.gateway.custom_rules import (
    _normalize_rule,
    _validate_rule,
    load_custom_rules,
    load_custom_rules_toml,
    load_custom_rules_yaml,
)
from src.models.enums import Severity as SeverityEnum
from src.services.custom_rules import (
    load_custom_rules as load_scan_custom_rules,
)
from src.services.custom_rules import (
    merge_with_builtin,
    validate_custom_rules,
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


# ═══════════════════════════════════════════════════════════════════════
#  STATIC ANALYZER CUSTOM RULES (src/services/custom_rules.py)
# ═══════════════════════════════════════════════════════════════════════




class TestScanValidateCustomRules:
    """Validation of .codetrust-rules.yml rule definitions."""

    def test_valid_rules_no_errors(self) -> None:
        rules = [
            {"id": "no_print", "pattern": r"print\(", "message": "Use logging", "severity": "WARN"},
            {"id": "no_eval", "pattern": r"\beval\(", "message": "No eval", "severity": "BLOCK"},
        ]
        errors = validate_custom_rules(rules)
        assert errors == []

    def test_not_a_list(self) -> None:
        errors = validate_custom_rules("not a list")
        assert len(errors) == 1
        assert "must be a list" in errors[0]

    def test_missing_id(self) -> None:
        rules = [{"pattern": r"foo", "message": "bar"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "'id'" in errors[0]

    def test_missing_pattern(self) -> None:
        rules = [{"id": "test", "message": "bar"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "'pattern'" in errors[0]

    def test_missing_message(self) -> None:
        rules = [{"id": "test", "pattern": r"foo"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "'message'" in errors[0]

    def test_invalid_regex(self) -> None:
        rules = [{"id": "bad", "pattern": r"[invalid", "message": "test"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "invalid regex" in errors[0]

    def test_invalid_severity(self) -> None:
        rules = [{"id": "x", "pattern": r"x", "message": "x", "severity": "CRITICAL"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "invalid severity" in errors[0]

    def test_rule_not_a_dict(self) -> None:
        rules = ["just a string"]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "not a mapping" in errors[0]

    def test_empty_id(self) -> None:
        rules = [{"id": "", "pattern": r"x", "message": "x"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "empty" in errors[0]

    def test_file_types_not_a_list(self) -> None:
        rules = [{"id": "x", "pattern": r"x", "message": "x", "file_types": ".py"}]
        errors = validate_custom_rules(rules)
        assert len(errors) == 1
        assert "file_types must be a list" in errors[0]


class TestScanLoadCustomRules:
    """Loading rules from .codetrust-rules.yml."""

    def test_valid_yaml_loads(self, tmp_path) -> None:
        rules_file = tmp_path / ".codetrust-rules.yml"
        rules_file.write_text(
            "rules:\n"
            "  - id: no_print\n"
            '    pattern: "print\\\\("\n'
            '    message: "Use logging"\n'
            "    severity: WARN\n"
            '    file_types: [".py"]\n'
        )
        result = load_scan_custom_rules(str(tmp_path))
        assert len(result) == 1
        assert result[0]["id"] == "custom_no_print"
        assert result[0]["severity"] == SeverityEnum.WARN
        assert result[0]["file_types"] == [".py"]

    def test_yaml_alt_extension(self, tmp_path) -> None:
        rules_file = tmp_path / ".codetrust-rules.yaml"
        rules_file.write_text(
            "rules:\n"
            "  - id: alt_rule\n"
            '    pattern: "foo"\n'
            '    message: "No foo"\n'
        )
        result = load_scan_custom_rules(str(tmp_path))
        assert len(result) == 1
        assert result[0]["id"] == "custom_alt_rule"

    def test_missing_file_returns_empty(self, tmp_path) -> None:
        result = load_scan_custom_rules(str(tmp_path))
        assert result == []

    def test_invalid_yaml_returns_empty(self, tmp_path) -> None:
        rules_file = tmp_path / ".codetrust-rules.yml"
        rules_file.write_text("{{invalid yaml content")
        result = load_scan_custom_rules(str(tmp_path))
        assert result == []

    def test_invalid_rules_skipped(self, tmp_path) -> None:
        rules_file = tmp_path / ".codetrust-rules.yml"
        rules_file.write_text(
            "rules:\n"
            "  - id: good_rule\n"
            '    pattern: "foo"\n'
            '    message: "Valid"\n'
            "  - id: bad_rule\n"
            '    pattern: "[invalid"\n'
            '    message: "Invalid regex"\n'
        )
        result = load_scan_custom_rules(str(tmp_path))
        assert len(result) == 1
        assert result[0]["id"] == "custom_good_rule"

    def test_negate_field_preserved(self, tmp_path) -> None:
        rules_file = tmp_path / ".codetrust-rules.yml"
        rules_file.write_text(
            "rules:\n"
            "  - id: require_boundary\n"
            '    pattern: "<ErrorBoundary"\n'
            '    message: "Must have ErrorBoundary"\n'
            "    severity: WARN\n"
            "    negate: true\n"
        )
        result = load_scan_custom_rules(str(tmp_path))
        assert len(result) == 1
        assert result[0]["negate"] is True

    def test_non_dict_yaml_returns_empty(self, tmp_path) -> None:
        rules_file = tmp_path / ".codetrust-rules.yml"
        rules_file.write_text("- just\n- a\n- list\n")
        result = load_scan_custom_rules(str(tmp_path))
        assert result == []


class TestScanMergeWithBuiltin:
    """Merging custom rules with built-in ANTI_PATTERNS."""

    def test_no_overlap(self) -> None:
        builtin = [
            {"id": "builtin_1", "pattern": r"x", "message": "b1", "severity": SeverityEnum.WARN},
        ]
        custom = [
            {"id": "custom_mine", "pattern": r"y", "message": "c1", "severity": SeverityEnum.WARN},
        ]
        merged = merge_with_builtin(custom, builtin)
        assert len(merged) == 2
        ids = {r["id"] for r in merged}
        assert ids == {"builtin_1", "custom_mine"}

    def test_custom_overrides_builtin_by_id(self) -> None:
        builtin = [
            {"id": "shared_id", "pattern": r"old", "message": "old msg", "severity": SeverityEnum.WARN},
            {"id": "other", "pattern": r"x", "message": "keep", "severity": SeverityEnum.INFO},
        ]
        custom = [
            {"id": "shared_id", "pattern": r"new", "message": "new msg", "severity": SeverityEnum.BLOCK},
        ]
        merged = merge_with_builtin(custom, builtin)
        assert len(merged) == 2
        shared = next(r for r in merged if r["id"] == "shared_id")
        assert shared["pattern"] == r"new"
        assert shared["message"] == "new msg"

    def test_empty_custom(self) -> None:
        builtin = [{"id": "a", "pattern": r"x", "message": "m", "severity": SeverityEnum.WARN}]
        merged = merge_with_builtin([], builtin)
        assert len(merged) == 1

    def test_empty_builtin(self) -> None:
        custom = [{"id": "a", "pattern": r"x", "message": "m", "severity": SeverityEnum.WARN}]
        merged = merge_with_builtin(custom, [])
        assert len(merged) == 1


class TestScanCustomRuleIntegration:
    """Integration: custom rules processed by StaticAnalyzer."""

    def test_custom_rule_matches_code(self) -> None:
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        custom = [{
            "id": "custom_no_print",
            "pattern": r"print\(",
            "message": "Use logging",
            "severity": SeverityEnum.WARN,
        }]
        findings = analyzer.scan_code('print("hello")', filename="app.py", custom_rules=custom)
        matched = [f for f in findings if f.rule_id == "custom_no_print"]
        assert len(matched) == 1
        assert matched[0].severity == SeverityEnum.WARN
        assert matched[0].line == 1

    def test_custom_rule_file_types_restriction(self) -> None:
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        custom = [{
            "id": "custom_py_only",
            "pattern": r"console\.log",
            "message": "Wrong logger",
            "severity": SeverityEnum.WARN,
            "file_types": [".py"],
        }]
        # Should NOT match in .js file
        findings_js = analyzer.scan_code('console.log("hi")', filename="app.js", custom_rules=custom)
        matched_js = [f for f in findings_js if f.rule_id == "custom_py_only"]
        assert matched_js == []

        # Should match in .py file
        findings_py = analyzer.scan_code('console.log("hi")', filename="app.py", custom_rules=custom)
        matched_py = [f for f in findings_py if f.rule_id == "custom_py_only"]
        assert len(matched_py) == 1

    def test_negate_mode_fires_when_pattern_absent(self) -> None:
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        custom = [{
            "id": "custom_require_boundary",
            "pattern": r"<ErrorBoundary",
            "message": "Must have ErrorBoundary",
            "severity": SeverityEnum.WARN,
            "negate": True,
        }]
        # Pattern absent -> finding
        code_without = "<div>Hello</div>"
        findings = analyzer.scan_code(code_without, filename="Page.tsx", custom_rules=custom)
        matched = [f for f in findings if f.rule_id == "custom_require_boundary"]
        assert len(matched) == 1

    def test_negate_mode_silent_when_pattern_present(self) -> None:
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        custom = [{
            "id": "custom_require_boundary",
            "pattern": r"<ErrorBoundary",
            "message": "Must have ErrorBoundary",
            "severity": SeverityEnum.WARN,
            "negate": True,
        }]
        code_with = '<ErrorBoundary fallback={<Err/>}>\n  <App/>\n</ErrorBoundary>'
        findings = analyzer.scan_code(code_with, filename="Page.tsx", custom_rules=custom)
        matched = [f for f in findings if f.rule_id == "custom_require_boundary"]
        assert matched == []

    def test_scan_without_custom_rules_unchanged(self) -> None:
        """Passing no custom_rules should behave identically to before."""
        from src.services.static_analyzer import StaticAnalyzer

        analyzer = StaticAnalyzer()
        code = "x = 1"
        findings_default = analyzer.scan_code(code, filename="app.py")
        findings_none = analyzer.scan_code(code, filename="app.py", custom_rules=None)
        findings_empty = analyzer.scan_code(code, filename="app.py", custom_rules=[])
        # All three should produce the same results
        assert len(findings_default) == len(findings_none) == len(findings_empty)
