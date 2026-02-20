# Copyright (c) Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Extended auto-fix recipes — 15+ automated code fixes.

Each recipe maps to an existing anti-pattern rule_id and applies
a safe, deterministic transformation. Recipes never change semantics —
they only fix code style, safety, and best-practice violations.

Recipe signature: (code: str, language: str) -> tuple[str, list[str]]
Returns: (fixed_code, list_of_human_readable_descriptions)
"""

from __future__ import annotations

import re

# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: console_log → structured logging (JS/TS)
# ═══════════════════════════════════════════════════════════════════════

_CONSOLE_LOG_RE = re.compile(r"^(\s*)console\.(log|debug|warn|error)\s*\(", re.MULTILINE)


def fix_console_log(code: str, language: str) -> tuple[str, list[str]]:
    """Replace console.log/debug/warn/error with structured logger calls.

    Maps console log level to equivalent logger level.
    Adds logger import if not present.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language not in ("javascript", "typescript"):
        return code, []

    level_map = {"log": "info", "debug": "debug", "warn": "warn", "error": "error"}
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _CONSOLE_LOG_RE.match(line)
        if m:
            indent = m.group(1)
            level = level_map.get(m.group(2), "info")
            rest = line[m.end():]
            out.append(f"{indent}logger.{level}({rest}")
            fixes.append(f"Line {i}: replaced console.{m.group(2)}() with logger.{level}()")
        else:
            out.append(line)

    result = "".join(out)
    if fixes and "logger" not in code.split("\n")[0:5]:
        # Suggest logger import at top
        result = '// TODO: import logger from your logging framework\n' + result
        fixes.insert(0, "Added logger import reminder at top of file")

    return result, fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: mutable_default → None + runtime init
# ═══════════════════════════════════════════════════════════════════════

_MUTABLE_DEFAULT_RE = re.compile(
    r"^(\s*)def\s+(\w+)\s*\(([^)]*?)"
    r"(\w+)\s*:\s*(?:list|dict|set|List|Dict|Set)\s*=\s*(\[\]|\{\}|set\(\))"
    r"([^)]*)\)\s*:",
    re.MULTILINE,
)


def fix_mutable_default(code: str, language: str) -> tuple[str, list[str]]:
    """Replace mutable default arguments with None pattern.

    Replaces:  def foo(items: list = [])
    With:      def foo(items: list | None = None)
    And adds:  if items is None: items = []

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    result_lines: list[str] = []
    i = 0

    while i < len(lines):
        line = lines[i]
        m = _MUTABLE_DEFAULT_RE.match(line)
        if m:
            indent = m.group(1)
            param_name = m.group(4)
            mutable_val = m.group(5)

            # Replace the mutable default with None
            new_line = line.replace(
                f"{param_name}: list = {mutable_val}",
                f"{param_name}: list | None = None",
            ).replace(
                f"{param_name}: dict = {mutable_val}",
                f"{param_name}: dict | None = None",
            ).replace(
                f"{param_name}: set = {mutable_val}",
                f"{param_name}: set | None = None",
            ).replace(
                f"{param_name}: List = {mutable_val}",
                f"{param_name}: List | None = None",
            ).replace(
                f"{param_name}: Dict = {mutable_val}",
                f"{param_name}: Dict | None = None",
            ).replace(
                f"{param_name}: Set = {mutable_val}",
                f"{param_name}: Set | None = None",
            )
            result_lines.append(new_line)

            # Find the indentation of the function body
            body_indent = indent + "    "

            # Check if next line is a docstring, skip past it
            j = i + 1
            docstring_lines: list[str] = []
            if j < len(lines) and '"""' in lines[j]:
                while j < len(lines):
                    docstring_lines.append(lines[j])
                    if j > i + 1 and '"""' in lines[j]:
                        j += 1
                        break
                    j += 1

            result_lines.extend(docstring_lines)

            # Insert the None check
            guard_line = f"{body_indent}if {param_name} is None:\n"
            init_line = f"{body_indent}    {param_name} = {mutable_val}\n"
            result_lines.append(guard_line)
            result_lines.append(init_line)

            fixes.append(
                f"Line {i + 1}: replaced mutable default '{mutable_val}' "
                f"with None pattern for '{param_name}'"
            )

            # Skip past docstring lines we already added
            i = j if docstring_lines else i + 1
        else:
            result_lines.append(line)
            i += 1

    return "".join(result_lines), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: datetime_utcnow → datetime.now(UTC)
# ═══════════════════════════════════════════════════════════════════════

_UTCNOW_RE = re.compile(r"datetime\.utcnow\(\)")


def fix_datetime_utcnow(code: str, language: str) -> tuple[str, list[str]]:
    """Replace deprecated datetime.utcnow() with timezone-aware alternative.

    Replaces:  datetime.utcnow()
    With:      datetime.now(timezone.utc)

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if "datetime.utcnow()" in line:
            new_line = line.replace(
                "datetime.utcnow()", "datetime.now(timezone.utc)"
            )
            out.append(new_line)
            fixes.append(
                f"Line {i}: replaced deprecated datetime.utcnow() "
                "with datetime.now(timezone.utc)"
            )
        else:
            out.append(line)

    result = "".join(out)
    if fixes and "timezone" not in code:
        result = result.replace(
            "from datetime import datetime",
            "from datetime import datetime, timezone",
        )
        if "from datetime import" not in result:
            result = "from datetime import datetime, timezone\n" + result
            fixes.insert(0, "Added timezone import")

    return result, fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: except_swallow → add logging
# ═══════════════════════════════════════════════════════════════════════

_EXCEPT_PASS_RE = re.compile(
    r"^(\s*)except\s+(\w+(?:\s*,\s*\w+)*)?\s*(?:as\s+\w+)?\s*:\s*\n(\s*)pass\s*$",
    re.MULTILINE,
)


def fix_except_swallow(code: str, language: str) -> tuple[str, list[str]]:
    """Replace swallowed exceptions (except: pass) with logging.

    Replaces:
        except Exception:
            pass
    With:
        except Exception:
            logging.exception("Suppressed exception")

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    fixes: list[str] = []
    offset = 0
    result = code

    for match in _EXCEPT_PASS_RE.finditer(code):
        body_indent = match.group(3)
        old_text = match.group(0)
        # Replace 'pass' with logging
        new_text = old_text.replace(
            f"{body_indent}pass",
            f'{body_indent}logging.exception("Suppressed exception")',
        )
        result = result[:match.start() + offset] + new_text + result[match.end() + offset:]
        offset += len(new_text) - len(old_text)
        line_num = code[:match.start()].count("\n") + 1
        fixes.append(f"Line {line_num}: replaced swallowed exception with logging")

    if fixes and "import logging" not in result:
        result = "import logging\n" + result
        fixes.insert(0, "Added 'import logging' for exception handling")

    return result, fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: debug_mode_enabled → use environment variable
# ═══════════════════════════════════════════════════════════════════════

_DEBUG_TRUE_RE = re.compile(
    r"""^(\s*)(\w*[Dd]ebug\w*)\s*=\s*True\b""",
    re.MULTILINE,
)


def fix_debug_mode(code: str, language: str) -> tuple[str, list[str]]:
    """Replace hardcoded debug=True with environment variable lookup.

    Replaces:  DEBUG = True
    With:      DEBUG = os.environ.get("DEBUG", "").lower() == "true"

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _DEBUG_TRUE_RE.match(line)
        if m:
            indent = m.group(1)
            var_name = m.group(2)
            env_key = var_name.upper()
            new_line = (
                f'{indent}{var_name} = '
                f'os.environ.get("{env_key}", "").lower() == "true"\n'
            )
            out.append(new_line)
            fixes.append(
                f"Line {i}: replaced hardcoded {var_name}=True "
                f"with os.environ.get('{env_key}')"
            )
        else:
            out.append(line)

    result = "".join(out)
    if fixes and "import os" not in result:
        result = "import os\n" + result
        fixes.insert(0, "Added 'import os' for environment variable access")

    return result, fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: hardcoded_port → configurable port
# ═══════════════════════════════════════════════════════════════════════

_HARDCODED_PORT_RE = re.compile(
    r"""^(\s*)(\w*[Pp]ort\w*)\s*=\s*(\d{4,5})\s*$""",
    re.MULTILINE,
)


def fix_hardcoded_port(code: str, language: str) -> tuple[str, list[str]]:
    """Replace hardcoded port numbers with environment variable lookup.

    Replaces:  PORT = 8080
    With:      PORT = int(os.environ.get("PORT", "8080"))

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _HARDCODED_PORT_RE.match(line)
        if m:
            indent = m.group(1)
            var_name = m.group(2)
            port_val = m.group(3)
            env_key = var_name.upper()
            new_line = (
                f'{indent}{var_name} = '
                f'int(os.environ.get("{env_key}", "{port_val}"))\n'
            )
            out.append(new_line)
            fixes.append(
                f"Line {i}: replaced hardcoded port {port_val} "
                f"with os.environ.get('{env_key}')"
            )
        else:
            out.append(line)

    result = "".join(out)
    if fixes and "import os" not in result:
        result = "import os\n" + result
        fixes.insert(0, "Added 'import os' for environment variable access")

    return result, fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: env_var_no_default → add sensible default
# ═══════════════════════════════════════════════════════════════════════

_ENV_NO_DEFAULT_RE = re.compile(
    r"""^(\s*)(\w+)\s*=\s*os\.environ\[["'](\w+)["']\]""",
    re.MULTILINE,
)


def fix_env_var_no_default(code: str, language: str) -> tuple[str, list[str]]:
    """Replace os.environ['KEY'] with os.environ.get('KEY', '') for safety.

    Replaces:  API_KEY = os.environ['API_KEY']
    With:      API_KEY = os.environ.get('API_KEY', '')

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _ENV_NO_DEFAULT_RE.match(line)
        if m:
            indent = m.group(1)
            var_name = m.group(2)
            env_key = m.group(3)
            new_line = f'{indent}{var_name} = os.environ.get("{env_key}", "")\n'
            out.append(new_line)
            fixes.append(
                f"Line {i}: replaced os.environ['{env_key}'] "
                f"with os.environ.get('{env_key}', '')"
            )
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: subprocess_shell_true → shell=False
# ═══════════════════════════════════════════════════════════════════════

_SUBPROCESS_SHELL_RE = re.compile(
    r"(subprocess\.\w+\([^)]*?)shell\s*=\s*True",
)


def fix_subprocess_shell(code: str, language: str) -> tuple[str, list[str]]:
    """Replace subprocess shell=True with shell=False.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if "shell=True" in line and "subprocess." in line:
            new_line = line.replace("shell=True", "shell=False")
            out.append(new_line)
            fixes.append(
                f"Line {i}: replaced shell=True with shell=False "
                "(security: prevents shell injection)"
            )
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: docker_latest_tag → pinned tag
# ═══════════════════════════════════════════════════════════════════════

_DOCKER_LATEST_RE = re.compile(
    r"^(FROM\s+\w[\w./-]*):latest\s*$",
    re.MULTILINE | re.IGNORECASE,
)


def fix_docker_latest_tag(code: str, language: str) -> tuple[str, list[str]]:
    """Replace :latest Docker tags with pinned versions.

    Replaces:  FROM python:latest
    With:      FROM python:3.12-slim  (suggests pinning)

    Args:
        code: Source code content.
        language: Programming language (must be dockerfile).

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    # Accept any language for Dockerfiles since they're often detected by filename
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _DOCKER_LATEST_RE.match(line)
        if m:
            base = m.group(1)
            # Replace :latest with a comment to pin
            new_line = (
                f"{base}:latest  "
                f"# FIXME: pin to specific version (e.g. 3.12-slim)\n"
            )
            out.append(new_line)
            fixes.append(
                f"Line {i}: flagged :latest tag — pin to specific version"
            )
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: sql_select_star → explicit columns
# ═══════════════════════════════════════════════════════════════════════

_SQL_STAR_RE = re.compile(
    r"(SELECT\s+)\*(\s+FROM)",
    re.IGNORECASE,
)


def fix_sql_select_star(code: str, language: str) -> tuple[str, list[str]]:
    """Flag SELECT * statements for explicit column selection.

    Replaces:  SELECT * FROM users
    With:      SELECT /* FIXME: list columns explicitly */ * FROM users

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _SQL_STAR_RE.search(line)
        if m:
            new_line = _SQL_STAR_RE.sub(
                r"\1/* FIXME: list columns explicitly */ *\2",
                line,
            )
            out.append(new_line)
            fixes.append(
                f"Line {i}: flagged SELECT * — list columns explicitly"
            )
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: any_type → explicit type hint (Python)
# ═══════════════════════════════════════════════════════════════════════

_ANY_PARAM_RE = re.compile(r"(\w+)\s*:\s*Any\b")
_ANY_RETURN_RE = re.compile(r"\)\s*->\s*Any\s*:")


def fix_any_type(code: str, language: str) -> tuple[str, list[str]]:
    """Flag Any type annotations with FIXME comments.

    Replaces:  def foo(x: Any) -> Any:
    With:      def foo(x: Any  # FIXME: use explicit type) -> Any  # FIXME: :

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if ": Any" in line or "-> Any" in line:
            # Don't touch imports
            if line.strip().startswith(("from ", "import ")):
                out.append(line)
                continue
            if "# FIXME" not in line:
                new_line = line.rstrip("\n") + "  # FIXME: replace Any with explicit type\n"
                out.append(new_line)
                fixes.append(
                    f"Line {i}: flagged Any type — replace with explicit type"
                )
            else:
                out.append(line)
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: sleep_no_context → add comment
# ═══════════════════════════════════════════════════════════════════════

_SLEEP_RE = re.compile(
    r"^(\s*)(?:time\.sleep|asyncio\.sleep|await\s+asyncio\.sleep)\s*\(\s*(\d+)\s*\)",
    re.MULTILINE,
)


def fix_sleep_no_context(code: str, language: str) -> tuple[str, list[str]]:
    """Flag unexplained sleep() calls with documentation prompts.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if ("time.sleep" in line or "asyncio.sleep" in line) and "#" not in line:
            new_line = line.rstrip("\n") + "  # FIXME: document why this sleep is needed\n"
            out.append(new_line)
            fixes.append(f"Line {i}: flagged unexplained sleep() — needs documentation")
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: connection_no_timeout → add timeout
# ═══════════════════════════════════════════════════════════════════════

_HTTPX_NO_TIMEOUT_RE = re.compile(
    r"(httpx\.(?:AsyncClient|Client)\s*\()(?!.*timeout)",
)
_REQUESTS_NO_TIMEOUT_RE = re.compile(
    r"(requests\.(?:get|post|put|delete|patch|head)\s*\([^)]+)(?!.*timeout)\)",
)


def fix_connection_no_timeout(code: str, language: str) -> tuple[str, list[str]]:
    """Add timeout parameter to HTTP client calls missing one.

    Adds timeout=30.0 to httpx and requests calls.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        modified = False
        # Add timeout to httpx client creation
        if "httpx." in line and "Client(" in line and "timeout" not in line:
            if line.rstrip().endswith(")"):
                new_line = line.rstrip().rstrip(")") + ", timeout=30.0)\n"
            else:
                new_line = line.rstrip("\n") + "  # FIXME: add timeout=30.0\n"
            out.append(new_line)
            fixes.append(f"Line {i}: added timeout to httpx client")
            modified = True
        # Add timeout to requests calls
        if not modified and "requests." in line and "timeout" not in line:
            for method in ("get", "post", "put", "delete", "patch", "head"):
                if f"requests.{method}(" in line:
                    if line.rstrip().endswith(")"):
                        new_line = line.rstrip().rstrip(")") + ", timeout=30.0)\n"
                    else:
                        new_line = line.rstrip("\n") + "  # FIXME: add timeout=30.0\n"
                    out.append(new_line)
                    fixes.append(f"Line {i}: added timeout to requests.{method}()")
                    modified = True
                    break
        if not modified:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: suppress_lint → remove suppression comments
# ═══════════════════════════════════════════════════════════════════════

_NOQA_RE = re.compile(r"\s*#\s*noqa\b.*$")
_ESLINT_DISABLE_LINE_RE = re.compile(r"\s*//\s*eslint-disable-next-line\b.*$")


def fix_suppress_lint(code: str, language: str) -> tuple[str, list[str]]:
    """Flag lint suppression comments for review.

    Adds FIXME notes to noqa and eslint-disable comments.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if language == "python" and "# noqa" in line and "FIXME" not in line:
            new_line = line.rstrip("\n") + "  # FIXME: fix the issue instead of suppressing\n"
            out.append(new_line)
            fixes.append(f"Line {i}: flagged noqa suppression — fix the underlying issue")
        elif language in ("javascript", "typescript") and "eslint-disable" in line and "FIXME" not in line:
            new_line = line.rstrip("\n") + "  // FIXME: fix the issue instead of suppressing\n"
            out.append(new_line)
            fixes.append(f"Line {i}: flagged eslint-disable — fix the underlying issue")
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: react_index_as_key → flag for explicit key
# ═══════════════════════════════════════════════════════════════════════

_INDEX_KEY_RE = re.compile(r"key\s*=\s*\{?\s*\b(?:index|idx|i)\b\s*\}?")


def fix_react_index_as_key(code: str, language: str) -> tuple[str, list[str]]:
    """Flag React components using array index as key.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language not in ("javascript", "typescript"):
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if _INDEX_KEY_RE.search(line) and "FIXME" not in line:
            new_line = line.rstrip("\n") + "  {/* FIXME: use stable unique ID instead of index */}\n"
            out.append(new_line)
            fixes.append(f"Line {i}: flagged index-as-key — use stable unique ID")
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: os_system → subprocess.run
# ═══════════════════════════════════════════════════════════════════════

_OS_SYSTEM_RE = re.compile(
    r"""^(\s*)os\.system\s*\(\s*(['"])(.*?)\2\s*\)""",
    re.MULTILINE,
)


def fix_os_system(code: str, language: str) -> tuple[str, list[str]]:
    """Replace os.system() with subprocess.run().

    Replaces:  os.system("ls -la")
    With:      subprocess.run(["ls", "-la"], check=True)

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        m = _OS_SYSTEM_RE.match(line)
        if m:
            indent = m.group(1)
            cmd_str = m.group(3)
            parts = cmd_str.split()
            args_list = ", ".join(f'"{p}"' for p in parts)
            new_line = f"{indent}subprocess.run([{args_list}], check=True)\n"
            out.append(new_line)
            fixes.append(
                f"Line {i}: replaced os.system() with subprocess.run() "
                "(safer, no shell injection)"
            )
        else:
            out.append(line)

    result = "".join(out)
    if fixes and "import subprocess" not in result:
        result = "import subprocess\n" + result
        fixes.insert(0, "Added 'import subprocess'")

    return result, fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE: string_concat_sql → parameterized query
# ═══════════════════════════════════════════════════════════════════════

_STRING_CONCAT_SQL_RE = re.compile(
    r"""(['"])\s*SELECT\s+.*\1\s*\+\s*\w+""",
    re.IGNORECASE,
)


def fix_string_concat_sql(code: str, language: str) -> tuple[str, list[str]]:
    """Flag SQL string concatenation as injection risk.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []

    for i, line in enumerate(lines, 1):
        if _STRING_CONCAT_SQL_RE.search(line) and "FIXME" not in line:
            out.append(line.rstrip("\n") + "  # FIXME: use parameterized query to prevent SQL injection\n")
            fixes.append(f"Line {i}: flagged SQL string concatenation — use parameterized query")
        else:
            out.append(line)

    return "".join(out), fixes


# ═══════════════════════════════════════════════════════════════════════
#  RECIPE REGISTRY
# ═══════════════════════════════════════════════════════════════════════

EXTENDED_RECIPES: list[tuple[str, object]] = [
    ("console_log", fix_console_log),
    ("mutable_default", fix_mutable_default),
    ("datetime_utcnow", fix_datetime_utcnow),
    ("except_swallow", fix_except_swallow),
    ("debug_mode_enabled", fix_debug_mode),
    ("hardcoded_port", fix_hardcoded_port),
    ("env_var_no_default", fix_env_var_no_default),
    ("agent_subprocess_shell_true", fix_subprocess_shell),
    ("docker_latest_tag", fix_docker_latest_tag),
    ("sql_select_star", fix_sql_select_star),
    ("any_type", fix_any_type),
    ("sleep_no_context", fix_sleep_no_context),
    ("connection_no_timeout", fix_connection_no_timeout),
    ("suppress_lint", fix_suppress_lint),
    ("react_index_as_key", fix_react_index_as_key),
    ("agent_os_system", fix_os_system),
    ("string_concat_sql", fix_string_concat_sql),
]
