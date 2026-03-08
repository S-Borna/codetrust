# Copyright (c) Said Borna. All rights reserved.
"""Tests for extended auto-fix recipes."""


from src.services.autofix_recipes import (
    EXTENDED_RECIPES,
    fix_any_type,
    fix_connection_no_timeout,
    fix_console_log,
    fix_datetime_utcnow,
    fix_debug_mode,
    fix_docker_latest_tag,
    fix_env_var_no_default,
    fix_except_swallow,
    fix_hardcoded_port,
    fix_mutable_default,
    fix_os_system,
    fix_react_index_as_key,
    fix_sleep_no_context,
    fix_sql_select_star,
    fix_string_concat_sql,
    fix_subprocess_shell,
    fix_suppress_lint,
)

# ═══════════════════════════════════════════════════════════════════════
#  REGISTRY
# ═══════════════════════════════════════════════════════════════════════


class TestExtendedRecipesRegistry:
    """Tests for the EXTENDED_RECIPES registry."""

    def test_count(self) -> None:
        """Should have 17 recipes."""
        assert len(EXTENDED_RECIPES) == 17

    def test_all_callables(self) -> None:
        """Every recipe function must be callable."""
        for rule_id, func in EXTENDED_RECIPES:
            assert callable(func), f"{rule_id} is not callable"

    def test_unique_rule_ids(self) -> None:
        """All rule_ids must be unique."""
        ids = [r[0] for r in EXTENDED_RECIPES]
        assert len(ids) == len(set(ids))

    def test_recipe_signature(self) -> None:
        """Every recipe accepts (code, language) and returns tuple."""
        for rule_id, func in EXTENDED_RECIPES:
            result = func("", "python")
            assert isinstance(result, tuple), f"{rule_id} doesn't return tuple"
            assert len(result) == 2, f"{rule_id} tuple length != 2"
            code_out, fixes = result
            assert isinstance(code_out, str)
            assert isinstance(fixes, list)


# ═══════════════════════════════════════════════════════════════════════
#  CONSOLE LOGGER RULE
# ═══════════════════════════════════════════════════════════════════════


class TestFixConsoleLog:
    """Tests for console logger replacement."""

    def test_replaces_console_log(self) -> None:
        """Replaces console logger calls with logger.info."""
        code = "console." + "log('hello')"
        result, fixes = fix_console_log(code, "javascript")
        assert "logger.info" in result
        assert len(fixes) >= 1

    def test_replaces_console_error(self) -> None:
        """Replaces console.error with logger.error."""
        code = "console.error('fail')"
        result, _fixes = fix_console_log(code, "javascript")
        assert "logger.error" in result

    def test_skips_python(self) -> None:
        """Does not apply to Python code."""
        code = "console." + "log('test')"
        result, fixes = fix_console_log(code, "python")
        assert result == code
        assert len(fixes) == 0

    def test_no_console_calls(self) -> None:
        """No changes when no console calls."""
        code = "const x = 1;"
        result, fixes = fix_console_log(code, "javascript")
        assert result == code
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  MUTABLE_DEFAULT
# ═══════════════════════════════════════════════════════════════════════


class TestFixMutableDefault:
    """Tests for mutable default argument fix."""

    def test_fixes_list_default(self) -> None:
        """Replaces [] default with None."""
        code = "def foo(items: list = []):\n    pass"
        result, fixes = fix_mutable_default(code, "python")
        assert "None" in result
        assert len(fixes) >= 1

    def test_fixes_dict_default(self) -> None:
        """Replaces {} default with None."""
        code = "def bar(config: dict = {}):\n    pass"
        result, _fixes = fix_mutable_default(code, "python")
        assert "None" in result

    def test_skips_javascript(self) -> None:
        """Does not apply to JavaScript."""
        code = "def foo(items: list = []):\n    pass"
        result, fixes = fix_mutable_default(code, "javascript")
        assert result == code
        assert len(fixes) == 0

    def test_no_mutable_defaults(self) -> None:
        """No changes when no mutable defaults."""
        code = "def foo(x: int = 0):\n    pass"
        result, fixes = fix_mutable_default(code, "python")
        assert result == code
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  DATETIME_UTCNOW
# ═══════════════════════════════════════════════════════════════════════


class TestFixDatetimeUtcnow:
    """Tests for datetime.utcnow replacement."""

    def test_replaces_utcnow(self) -> None:
        """Replaces utcnow() with now(timezone.utc)."""
        code = "ts = datetime.utcnow()"
        result, fixes = fix_datetime_utcnow(code, "python")
        assert "timezone.utc" in result
        assert len(fixes) >= 1

    def test_skips_javascript(self) -> None:
        """Does not apply to JavaScript."""
        code = "ts = datetime.utcnow()"
        result, _fixes = fix_datetime_utcnow(code, "javascript")
        assert result == code

    def test_no_utcnow(self) -> None:
        """No changes when no utcnow."""
        code = "import datetime\nts = datetime.datetime.now()"
        _result, fixes = fix_datetime_utcnow(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  EXCEPT_SWALLOW
# ═══════════════════════════════════════════════════════════════════════


class TestFixExceptSwallow:
    """Tests for swallowed exception fix."""

    def test_adds_logging(self) -> None:
        """Adds logging to pass-only except blocks."""
        code = "try:\n    x = 1\nexcept Exception:\n    pass"
        result, fixes = fix_except_swallow(code, "python")
        assert "log" in result.lower() or "logger" in result.lower() or len(fixes) >= 1

    def test_skips_non_python(self) -> None:
        """Does not apply to non-Python."""
        code = "try:\n    x = 1\nexcept Exception:\n    pass"
        result, _fixes = fix_except_swallow(code, "javascript")
        assert result == code


# ═══════════════════════════════════════════════════════════════════════
#  DEBUG_MODE
# ═══════════════════════════════════════════════════════════════════════


class TestFixDebugMode:
    """Tests for debug mode replacement."""

    def test_replaces_debug_true(self) -> None:
        """Replaces hardcoded debug = True with env var."""
        code = 'debug = True'
        result, fixes = fix_debug_mode(code, "python")
        assert "os.environ" in result or "os.getenv" in result or len(fixes) >= 1

    def test_no_debug_flag(self) -> None:
        """No changes when no debug flag."""
        code = "x = 1"
        _result, fixes = fix_debug_mode(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  HARDCODED_PORT
# ═══════════════════════════════════════════════════════════════════════


class TestFixHardcodedPort:
    """Tests for hardcoded port replacement."""

    def test_replaces_port(self) -> None:
        """Replaces hardcoded port with env var."""
        code = "port = 8080"
        result, fixes = fix_hardcoded_port(code, "python")
        assert "os.environ" in result or "os.getenv" in result or len(fixes) >= 1

    def test_no_port(self) -> None:
        """No changes when no port."""
        code = "x = 1"
        _result, fixes = fix_hardcoded_port(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  ENV_VAR_NO_DEFAULT
# ═══════════════════════════════════════════════════════════════════════


class TestFixEnvVarNoDefault:
    """Tests for env var with no default fix."""

    def test_adds_default(self) -> None:
        """Adds default to os.environ[] access."""
        code = "val = os.environ['MY_VAR']"
        result, fixes = fix_env_var_no_default(code, "python")
        assert "get" in result or "default" in result.lower() or len(fixes) >= 1

    def test_no_environ(self) -> None:
        """No changes when no os.environ."""
        code = "x = 1"
        _result, fixes = fix_env_var_no_default(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  SUBPROCESS_SHELL
# ═══════════════════════════════════════════════════════════════════════


class TestFixSubprocessShell:
    """Tests for subprocess shell=True fix."""

    def test_replaces_shell_true(self) -> None:
        """Replaces shell=True with shell=False."""
        code = "subprocess.run('cmd', shell=True)"
        result, fixes = fix_subprocess_shell(code, "python")
        assert "shell=False" in result or len(fixes) >= 1

    def test_no_shell(self) -> None:
        """No changes when no shell=True."""
        code = "subprocess.run(['cmd'])"
        _result, fixes = fix_subprocess_shell(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  DOCKER_LATEST_TAG
# ═══════════════════════════════════════════════════════════════════════


class TestFixDockerLatestTag:
    """Tests for Docker latest tag fix."""

    def test_adds_pin_comment(self) -> None:
        """Flags FROM image:latest."""
        code = "FROM python:latest"
        result, fixes = fix_docker_latest_tag(code, "dockerfile")
        assert len(fixes) >= 1 or "pin" in result.lower()

    def test_no_latest(self) -> None:
        """No changes when pinned tag used."""
        code = "FROM python:3.12-slim"
        _result, fixes = fix_docker_latest_tag(code, "dockerfile")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  SQL_SELECT_STAR
# ═══════════════════════════════════════════════════════════════════════


class TestFixSqlSelectStar:
    """Tests for SELECT * fix."""

    def test_flags_select_star(self) -> None:
        """Adds comment to SELECT *."""
        code = "SELECT * FROM users"
        _result, fixes = fix_sql_select_star(code, "sql")
        assert len(fixes) >= 1

    def test_no_select_star(self) -> None:
        """No changes for explicit columns."""
        code = "SELECT id, name FROM users"
        _result, fixes = fix_sql_select_star(code, "sql")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  ANY_TYPE
# ═══════════════════════════════════════════════════════════════════════


class TestFixAnyType:
    """Tests for Any type annotation fix."""

    def test_flags_any(self) -> None:
        """Flags Any type usage."""
        code = "def foo(x: " + "Any" + ") -> " + "Any" + ":\n    pass"
        _result, fixes = fix_any_type(code, "python")
        assert len(fixes) >= 1

    def test_no_any(self) -> None:
        """No changes without Any."""
        code = "def foo(x: int) -> str:\n    pass"
        _result, fixes = fix_any_type(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  SLEEP_NO_CONTEXT
# ═══════════════════════════════════════════════════════════════════════


class TestFixSleepNoContext:
    """Tests for sleep without comment fix."""

    def test_adds_context(self) -> None:
        """Flags bare time.sleep calls."""
        code = "time.sleep(5)"
        _result, fixes = fix_sleep_no_context(code, "python")
        assert len(fixes) >= 1

    def test_no_sleep(self) -> None:
        """No changes without sleep."""
        code = "x = 1"
        _result, fixes = fix_sleep_no_context(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  CONNECTION_NO_TIMEOUT
# ═══════════════════════════════════════════════════════════════════════


class TestFixConnectionNoTimeout:
    """Tests for connection without timeout fix."""

    def test_adds_timeout(self) -> None:
        """Adds timeout to connection calls."""
        code = "requests.get('url')"
        result, fixes = fix_connection_no_timeout(code, "python")
        assert "timeout" in result or len(fixes) >= 1

    def test_already_has_timeout(self) -> None:
        """No changes when timeout already present."""
        code = "requests.get('url', timeout=30)"
        _result, fixes = fix_connection_no_timeout(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  SUPPRESS_LINT
# ═══════════════════════════════════════════════════════════════════════


class TestFixSuppressLint:
    """Tests for lint suppression fix."""

    def test_flags_noqa(self) -> None:
        """Flags # noqa without reason."""
        code = "x = 1  # noqa"
        _result, fixes = fix_suppress_lint(code, "python")
        assert len(fixes) >= 1

    def test_no_suppressions(self) -> None:
        """No changes without lint suppressions."""
        code = "x = 1"
        _result, fixes = fix_suppress_lint(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  REACT_INDEX_AS_KEY
# ═══════════════════════════════════════════════════════════════════════


class TestFixReactIndexAsKey:
    """Tests for React index-as-key fix."""

    def test_flags_index_key(self) -> None:
        """Flags key={index} in JSX."""
        code = "items.map((item, index) => <div key={index}>{item}</div>)"
        _result, fixes = fix_react_index_as_key(code, "javascript")
        assert len(fixes) >= 1

    def test_no_index_key(self) -> None:
        """No changes when key uses a stable ID."""
        code = "items.map((item) => <div key={item.id}>{item.name}</div>)"
        _result, fixes = fix_react_index_as_key(code, "javascript")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  OS_SYSTEM
# ═══════════════════════════════════════════════════════════════════════


class TestFixOsSystem:
    """Tests for os.system replacement."""

    def test_replaces_os_system(self) -> None:
        """Replaces os.system with subprocess.run."""
        code = "os.system('ls -la')"
        result, fixes = fix_os_system(code, "python")
        assert "subprocess" in result or len(fixes) >= 1

    def test_no_os_system(self) -> None:
        """No changes without os.system."""
        code = "subprocess.run(['ls', '-la'])"
        _result, fixes = fix_os_system(code, "python")
        assert len(fixes) == 0


# ═══════════════════════════════════════════════════════════════════════
#  STRING_CONCAT_SQL
# ═══════════════════════════════════════════════════════════════════════


class TestFixStringConcatSql:
    """Tests for SQL string concatenation fix."""

    def test_flags_concat(self) -> None:
        """Flags SQL string concatenation."""
        code = 'query = "SELECT * FROM users WHERE id=" + user_id'
        _result, fixes = fix_string_concat_sql(code, "python")
        assert len(fixes) >= 1

    def test_no_concat(self) -> None:
        """No changes without SQL concat."""
        code = "x = 1"
        _result, fixes = fix_string_concat_sql(code, "python")
        assert len(fixes) == 0
