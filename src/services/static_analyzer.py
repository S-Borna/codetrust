# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Layer 1: Regex-based anti-pattern detection engine. Runs locally, no network calls."""

import ast
import os
import re
from pathlib import Path

import structlog

from src.models.enums import Severity
from src.models.responses import Finding, StaticScanResponse
from src.rules.anti_patterns import (
    ANTI_PATTERNS,
    DEVOPS_EXTENSIONS,
    DEVOPS_FILENAMES,
    MAX_FUNCTION_LENGTH,
    SQL_EXTENSIONS,
)
from src.rules.enterprise import (
    FORBIDDEN_PATTERNS,
    RECOMMENDED_DIRS,
    RECOMMENDED_FILES,
    REQUIRED_FILES,
)

logger = structlog.get_logger()


class StaticAnalyzer:
    """Regex-based anti-pattern detection. Runs locally, no network calls."""

    def __init__(self, premium_rules: list[dict[str, object]] | None = None) -> None:
        """Initialize with optional premium rules from server-side delivery.

        Args:
            premium_rules: Additional rules fetched from cloud API.
                           If None, only the bundled ANTI_PATTERNS are used.
                           In production (server-side), this is None because
                           the server has all rules locally.
        """
        from src.services.rule_delivery import FREE_TIER_RULE_IDS, merge_rules

        if premium_rules is not None:
            # Client-side: merge free-tier + server-delivered premium rules
            free_only = [r for r in ANTI_PATTERNS if r.get("id") in FREE_TIER_RULE_IDS]
            # Deserialize severity strings back to enum for premium rules
            deserialized: list[dict[str, object]] = []
            for rule in premium_rules:
                entry = dict(rule)
                if isinstance(entry.get("severity"), str):
                    entry["severity"] = Severity(entry["severity"])
                deserialized.append(entry)
            self._rules: list[dict[str, object]] = merge_rules(free_only, deserialized)
        else:
            # Server-side or local dev: use all bundled rules
            self._rules = list(ANTI_PATTERNS)

        logger.info("static_analyzer_initialized", rule_count=len(self._rules))

    @property
    def active_rule_count(self) -> int:
        """Number of active rules loaded."""
        return len(self._rules)

    def _is_devops_file(self, filename: str, ext: str) -> bool:
        """Check if a file is a DevOps/infrastructure file."""
        basename = os.path.basename(filename).lower()
        return ext in DEVOPS_EXTENSIONS or basename in DEVOPS_FILENAMES

    def _dispatch_special_handler(
        self,
        handler: str,
        lines: list[str],
        filename: str,
    ) -> list[Finding] | None:
        """Dispatch to a special handler, returning findings or None if not handled."""
        handlers: dict[str, object] = {
            "check_function_length": self._check_function_lengths,
            "check_connection_timeout": self._check_connection_timeout,
            "check_dockerfile_healthcheck": self._check_dockerfile_healthcheck,
            "check_compose_healthcheck": self._check_compose_healthcheck,
            "check_except_swallow": self._check_except_swallow,
            "check_sleep_no_context": self._check_sleep_no_context,
            "check_docker_root_user": self._check_docker_root_user,
            "check_docker_no_workdir": self._check_docker_no_workdir,
            "check_ci_no_timeout": self._check_ci_no_timeout,
            "check_render_set_state": self._check_render_set_state,
            "check_obs_health_check": self._check_obs_health_check,
            "check_async_timeout": self._check_async_timeout,
            "check_unclosed_file": self._check_unclosed_file,
            "check_go_sql_close": self._check_go_sql_close,
        }
        fn = handlers.get(handler)
        if fn is not None:
            return fn(lines, filename)
        return None

    def _should_skip_rule(
        self,
        rule: dict[str, str],
        ext: str,
        filename: str,
    ) -> bool:
        """Check if a rule should be skipped for the given file."""
        rule_file_types = rule.get("file_types")
        if rule_file_types:
            if ext not in rule_file_types:
                basename = os.path.basename(filename).lower()
                if basename not in DEVOPS_FILENAMES:
                    return True
                if not any(ft in DEVOPS_EXTENSIONS for ft in rule_file_types):
                    return True
        else:
            if ext in SQL_EXTENSIONS:
                return True

        exclude_path_contains = rule.get("exclude_path_contains")
        if exclude_path_contains:
            normalized_filename = filename.replace("\\", "/").lower()
            for path_fragment in exclude_path_contains:
                if path_fragment.lower() in normalized_filename:
                    return True
        return False

    def scan_code(
        self,
        code: str,
        filename: str = "",
        custom_rules: list[dict[str, object]] | None = None,
    ) -> list[Finding]:
        """Run all anti-pattern rules against a code string.

        Args:
            code: Source code content to scan.
            filename: File path for extension-based rule filtering.
            custom_rules: Optional user-defined rules from .codetrust-rules.yml.
                          If provided, they are appended to the active rule set
                          for this scan invocation only.
        """
        findings: list[Finding] = []
        lines = code.splitlines()
        ext = os.path.splitext(filename)[1].lower() if filename else ""

        active_rules = self._rules
        if custom_rules:
            active_rules = list(self._rules) + list(custom_rules)

        for rule in active_rules:
            if self._should_skip_rule(rule, ext, filename):
                continue

            handler = rule.get("special_handler", "")
            if handler:
                result = self._dispatch_special_handler(handler, lines, filename)
                if result is not None:
                    findings.extend(result)
                    continue

            if rule.get("negate"):
                findings.extend(self._apply_negate_rule(rule, lines, filename))
            else:
                findings.extend(self._apply_rule(rule, lines, filename))

        logger.info(
            "static_scan_complete",
            filename=filename,
            total_findings=len(findings),
        )
        return findings

    @staticmethod
    def _line_matches_rule(
        line: str,
        stripped: str,
        in_docstring: bool,
        skip_comments: bool,
        rule_id: str,
    ) -> bool:
        """Check if a line should be skipped for comment/docstring/noqa reasons."""
        if "noqa" in line and rule_id != "suppress_lint":
            return False
        return not (skip_comments and (
            in_docstring
            or stripped.startswith("#")
            or stripped.startswith('"""')
            or stripped.startswith("'''")
        ))

    @staticmethod
    def _is_docstring_boundary(stripped: str) -> bool:
        """Check if a line is a docstring boundary (open/close).

        Only toggles on lines where triple-quotes appear at the START,
        not when referenced inside code (e.g. ``if '\"\"\"' in text:``).
        """
        for quote in ('"""', "'''"):
            if stripped.startswith(quote) and stripped.count(quote) == 1:
                    return True
        return False

    def _apply_rule(
        self,
        rule: dict[str, str],
        lines: list[str],
        filename: str,
    ) -> list[Finding]:
        """Apply a single regex rule to all lines of code."""
        findings: list[Finding] = []
        pattern = re.compile(rule["pattern"])
        skip_comments = bool(rule.get("skip_comments"))
        in_docstring = False

        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_docstring_boundary(stripped):
                in_docstring = not in_docstring
            if not self._line_matches_rule(
                line, stripped, in_docstring, skip_comments, rule["id"],
            ):
                continue
            if pattern.search(line):
                findings.append(Finding(
                    rule_id=rule["id"],
                    severity=Severity(rule["severity"]),
                    message=rule["message"],
                    file=filename,
                    line=line_num,
                    suggestion=str(rule.get("suggestion", "")),
                ))
        return findings

    def _apply_negate_rule(
        self,
        rule: dict[str, object],
        lines: list[str],
        filename: str,
    ) -> list[Finding]:
        """Apply a negated rule: fire if pattern is NOT found in the file.

        Used for rules like 'require_error_boundary' where a component
        MUST contain a certain pattern. If the pattern is absent, a
        finding is emitted on line 1.
        """
        pattern = re.compile(str(rule["pattern"]))
        for line in lines:
            if pattern.search(line):
                return []

        return [Finding(
            rule_id=str(rule["id"]),
            severity=Severity(rule["severity"]),
            message=str(rule["message"]),
            file=filename,
            line=1,
            suggestion=str(rule.get("suggestion", "")),
        )]

    def _check_function_lengths(
        self,
        lines: list[str],
        filename: str,
    ) -> list[Finding]:
        """Check that no function exceeds MAX_FUNCTION_LENGTH lines.

        Uses Python AST for .py files (accurate class-aware ranges),
        falls back to regex-based detection for non-Python or invalid files.
        """
        if filename.endswith(".py"):
            try:
                return self._check_function_lengths_ast(
                    "\n".join(lines), filename,
                )
            except SyntaxError:
                logger.debug("ast_parse_failed_for_length_check", filename=filename)
        return self._check_function_lengths_regex(lines, filename)

    def _check_function_lengths_ast(
        self,
        code: str,
        filename: str,
    ) -> list[Finding]:
        """AST-based function length check — accurate for Python files."""
        findings: list[Finding] = []
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = node.end_lineno or node.lineno
                length = end - node.lineno + 1
                if length > MAX_FUNCTION_LENGTH:
                    findings.append(
                        Finding(
                            rule_id="long_function",
                            severity=Severity.INFO,
                            message=(
                                f"Function '{node.name}' is {length} lines "
                                f"(max {MAX_FUNCTION_LENGTH})."
                            ),
                            file=filename,
                            line=node.lineno,
                            suggestion="Split into smaller functions.",
                        )
                    )
        return findings

    def _check_function_lengths_regex(
        self,
        lines: list[str],
        filename: str,
    ) -> list[Finding]:
        """Regex-based function length check — fallback for non-Python files."""
        findings: list[Finding] = []
        func_pattern = re.compile(r"^(\s*)(async\s+)?def\s+(\w+)")
        func_starts: list[tuple[int, int, str]] = []

        for line_num, line in enumerate(lines, start=1):
            match = func_pattern.match(line)
            if match:
                indent = len(match.group(1))
                name = match.group(3)
                func_starts.append((line_num, indent, name))

        for idx, (start_line, indent, name) in enumerate(func_starts):
            end_line = self._find_function_end(
                lines, start_line, indent, func_starts, idx
            )
            length = end_line - start_line + 1
            if length > MAX_FUNCTION_LENGTH:
                findings.append(
                    Finding(
                        rule_id="long_function",
                        severity=Severity.INFO,
                        message=(
                            f"Function '{name}' is {length} lines "
                            f"(max {MAX_FUNCTION_LENGTH})."
                        ),
                        file=filename,
                        line=start_line,
                        suggestion="Split into smaller functions.",
                    )
                )

        return findings

    def _find_function_end(
        self,
        lines: list[str],
        start_line: int,
        indent: int,
        func_starts: list[tuple[int, int, str]],
        current_idx: int,
    ) -> int:
        """Find the last line of a function body."""
        # If there's a next function at the same or lesser indent, use that
        for next_idx in range(current_idx + 1, len(func_starts)):
            next_start, next_indent, _ = func_starts[next_idx]
            if next_indent <= indent:
                # Walk backwards from next function to find last non-empty line
                for i in range(next_start - 2, start_line - 1, -1):
                    if lines[i].strip():
                        return i + 1  # Convert to 1-based
                return start_line

        # Last function — scan to end of file
        last_content_line = start_line
        for i in range(start_line, len(lines)):
            line = lines[i]
            if line.strip():
                # Check if it's still part of the function
                stripped = line.lstrip()
                line_indent = len(line) - len(stripped)
                if i == start_line - 1 or line_indent > indent or stripped == "":
                    last_content_line = i + 1  # Convert to 1-based
                elif line_indent <= indent and i > start_line:
                    break
                else:
                    last_content_line = i + 1

        return last_content_line

    def _check_connection_timeout(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag network/DB connection calls that lack a timeout parameter."""
        findings: list[Finding] = []
        pattern = re.compile(
            r"(?:from_url|AsyncClient|Client|create_async_engine|create_engine|aiohttp\.ClientSession)\s*\("
        )
        for line_num, line in enumerate(lines, start=1):
            if "noqa" in line:
                continue
            if pattern.search(line):
                # Look within a 5-line window for timeout parameters
                window = "\n".join(lines[max(0, line_num - 1):min(len(lines), line_num + 5)])
                if re.search(r"(?:timeout|connect_timeout|socket_timeout|socket_connect_timeout)", window):
                    continue
                findings.append(
                    Finding(
                        rule_id="connection_no_timeout",
                        severity=Severity.WARN,
                        message="Network/DB connection without explicit timeout. Add connect_timeout or socket_timeout.",
                        file=filename,
                        line=line_num,
                        suggestion="Add timeout parameter to avoid indefinite blocking.",
                    )
                )
        return findings

    def _check_dockerfile_healthcheck(
        self, lines: list[str], filename: str,
    ) -> list[Finding]:
        """Flag Dockerfiles that have CMD but no HEALTHCHECK."""
        findings: list[Finding] = []
        full_text = "\n".join(lines)
        has_cmd = bool(re.search(r"^CMD\s", full_text, re.MULTILINE))
        has_healthcheck = bool(re.search(r"^HEALTHCHECK\s", full_text, re.MULTILINE))
        if has_cmd and not has_healthcheck:
            cmd_line = next(
                (i for i, line in enumerate(lines, 1) if re.match(r"^CMD\s", line)),
                1,
            )
            findings.append(
                Finding(
                    rule_id="dockerfile_no_healthcheck",
                    severity=Severity.INFO,
                    message="Dockerfile has CMD but no HEALTHCHECK instruction.",
                    file=filename,
                    line=cmd_line,
                    suggestion="Add HEALTHCHECK to enable container orchestration health monitoring.",
                )
            )
        return findings

    def _check_compose_healthcheck(
        self, lines: list[str], filename: str,
    ) -> list[Finding]:
        """Flag docker-compose services that have no healthcheck."""
        findings: list[Finding] = []
        # Simple heuristic: find 'image:' lines and check if 'healthcheck:' appears
        # in the same service block (before next service at same indent level)
        for line_num, line in enumerate(lines, start=1):
            if re.match(r"^\s{2,4}image:\s", line):
                # Look ahead for healthcheck before next service
                block = "\n".join(lines[line_num:min(len(lines), line_num + 20)])
                if "healthcheck:" not in block:
                    findings.append(
                        Finding(
                            rule_id="compose_no_healthcheck",
                            severity=Severity.INFO,
                            message="Docker Compose service has no healthcheck defined.",
                            file=filename,
                            line=line_num,
                            suggestion="Add healthcheck for reliable orchestration.",
                        )
                    )
        return findings

    def _check_except_swallow(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag except blocks that swallow errors (pass/... with no logging)."""
        findings: list[Finding] = []
        except_pattern = re.compile(r"^\s*except[\s:]")
        in_docstring = False
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if self._is_docstring_boundary(stripped):
                in_docstring = not in_docstring
            if in_docstring:
                continue
            if "noqa" in line:
                continue
            if except_pattern.match(line):
                # Check the next non-empty lines (up to 3) in the except block
                except_indent = len(line) - len(line.lstrip())
                body_lines: list[str] = []
                for i in range(line_num, min(len(lines), line_num + 5)):
                    next_line = lines[i].rstrip()
                    if not next_line.strip():
                        continue
                    next_indent = len(next_line) - len(next_line.lstrip())
                    if next_indent <= except_indent and i > line_num - 1:
                        break
                    if next_indent > except_indent:
                        body_lines.append(next_line.strip())

                body = " ".join(body_lines)
                # Swallowed if body is only pass, ..., or continue
                if body in ("pass", "...", "continue", "pass  # " + "noqa"):
                    findings.append(
                        Finding(
                            rule_id="except_swallow",
                            severity=Severity.BLOCK,
                            message="Exception caught and silently swallowed. Handle the error or re-raise.",
                            file=filename,
                            line=line_num,
                            suggestion="Log the error, re-raise, or handle the root cause.",
                        )
                    )
        return findings

    def _check_sleep_no_context(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag sleep calls without a preceding comment explaining why."""
        findings: list[Finding] = []
        sleep_pattern = re.compile(r"(?:time\.)?sleep\s*\(")
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if "noqa" in line:
                continue
            if stripped.startswith("#"):
                continue
            if sleep_pattern.search(line):
                # Check if previous non-empty line is a comment
                has_context = False
                for i in range(line_num - 2, max(-1, line_num - 4), -1):
                    if i < 0:
                        break
                    prev = lines[i].strip()
                    if not prev:
                        continue
                    if prev.startswith("#"):
                        has_context = True
                    break

                if not has_context:
                    findings.append(
                        Finding(
                            rule_id="sleep_no_context",
                            severity=Severity.INFO,
                            message="sleep call without explanation. Why is a delay needed?",
                            file=filename,
                            line=line_num,
                            suggestion="Add a comment explaining the reason for the delay.",
                        )
                    )
        return findings

    def _check_docker_root_user(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag Dockerfiles that run as root (no USER instruction)."""
        findings: list[Finding] = []
        full_text = "\n".join(lines)
        has_cmd = bool(re.search(r"^CMD\s", full_text, re.MULTILINE))
        has_user = bool(re.search(r"^USER\s", full_text, re.MULTILINE))
        if has_cmd and not has_user:
            cmd_line = next(
                (i for i, ln in enumerate(lines, 1) if re.match(r"^CMD\s", ln)),
                1,
            )
            findings.append(
                Finding(
                    rule_id="docker_root_user",
                    severity=Severity.WARN,
                    message="Dockerfile runs as root. Add USER instruction to drop privileges.",
                    file=filename,
                    line=cmd_line,
                    suggestion="Add 'USER nonroot' or 'USER 1000' before CMD.",
                )
            )
        return findings

    def _check_docker_no_workdir(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag Dockerfiles without WORKDIR instruction."""
        findings: list[Finding] = []
        full_text = "\n".join(lines)
        has_cmd = bool(re.search(r"^CMD\s", full_text, re.MULTILINE))
        has_workdir = bool(re.search(r"^WORKDIR\s", full_text, re.MULTILINE))
        if has_cmd and not has_workdir:
            findings.append(
                Finding(
                    rule_id="docker_no_workdir",
                    severity=Severity.INFO,
                    message="Dockerfile has no WORKDIR. Set explicit working directory.",
                    file=filename,
                    line=1,
                    suggestion="Add 'WORKDIR /app' to set a predictable working directory.",
                )
            )
        return findings

    def _check_ci_no_timeout(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag CI jobs (runs-on:) without timeout-minutes."""
        findings: list[Finding] = []
        for line_num, line in enumerate(lines, start=1):
            if re.match(r"^\s+runs-on:\s", line):
                # Check surrounding job block (30 lines) for timeout-minutes
                start = max(0, line_num - 5)
                end = min(len(lines), line_num + 30)
                block = "\n".join(lines[start:end])
                if "timeout-minutes:" not in block:
                    findings.append(
                        Finding(
                            rule_id="ci_no_timeout",
                            severity=Severity.INFO,
                            message="CI job has no timeout-minutes. Add timeout to prevent hung pipelines.",
                            file=filename,
                            line=line_num,
                            suggestion="Add 'timeout-minutes: 15' to the job definition.",
                        )
                    )
        return findings

    def _check_render_set_state(self, lines: list[str], filename: str) -> list[Finding]:
        """Flag setState calls only when they're in the render body, not callbacks.

        setState in useCallback, event handlers, useEffect, or async
        functions is valid React. Only top-level component body setState
        (outside any callback/handler scope) indicates a render-loop bug.
        """
        findings: list[Finding] = []
        # Track nesting: inside useCallback, useEffect, event handler, or async
        callback_patterns = re.compile(
            r"(?:useCallback|useEffect|useMemo|useLayoutEffect|"
            r"addEventListener|setTimeout|setInterval|"
            r"\.then\(|\.catch\(|async\s)"
        )
        set_state_re = re.compile(r"(?:set[A-Z]\w+|setState)\s*\(")

        callback_depth = 0
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            # Track callback/handler scope depth
            if callback_patterns.search(stripped):
                callback_depth += 1
            # Track brace depth for callback scopes
            callback_depth += stripped.count("{") - stripped.count("}")
            if callback_depth < 0:
                callback_depth = 0

            # Only flag setState when NOT inside any callback scope
            # Also skip if preceded by arrow function on same line
            if callback_depth == 0 and set_state_re.search(stripped) and "=>" not in stripped:
                    findings.append(
                        Finding(
                            rule_id="react_set_state_in_render",
                            severity=Severity.WARN,
                            message="Possible state update during render. Move setState calls into event handlers or useEffect.",
                            file=filename,
                            line=line_num,
                            suggestion="Wrap in useEffect, useCallback, or an event handler.",
                        )
                    )
        return findings

    def _check_obs_health_check(
        self, lines: list[str], filename: str,
    ) -> list[Finding]:
        """Flag app/server init when no health endpoint exists in the file.

        Scans the entire file for /health, /healthz, /readyz, /livez, /ping
        endpoints before flagging. Only fires if none are found.
        """
        full_text = "\n".join(lines)
        health_pattern = re.compile(
            r"""(?ix)
            (?:/health[z]?|/readyz|/livez|/ping)      # URL path
            | (?:health[_\-]?check|healthz|readyz)     # function/route name
            """,
        )
        if health_pattern.search(full_text):
            return []

        # Find the app/server init line — require framework constructor call
        init_pattern = re.compile(
            r"(?:app|server)\s*=\s*(?:FastAPI|Flask|Express|Starlette|Sanic|Quart|Django)\s*\("
            r"|(?:express|fastapi|flask|starlette|sanic)\s*\(",
        )
        for line_num, line in enumerate(lines, start=1):
            if init_pattern.search(line):
                return [Finding(
                    rule_id="obs_missing_health_check",
                    severity=Severity.WARN,
                    message="Application without health check endpoint. Add /health for load balancer monitoring.",
                    file=filename,
                    line=line_num,
                    suggestion="Add a health check endpoint: @app.get('/health') or app.get('/healthz', handler).",
                )]
        return []

    def _check_async_timeout(
        self, lines: list[str], filename: str,
    ) -> list[Finding]:
        """Flag async HTTP calls without timeout in a 5-line forward window.

        Checks the current line plus 4 lines ahead for timeout= parameter.
        Only matches HTTP client calls (client.get, http.post, etc.),
        not ORM/cache calls (session.get, redis.delete, cache.get).
        """
        findings: list[Finding] = []
        # Match HTTP-like client calls, require "client/http/session()" context
        call_pattern = re.compile(
            r"await\s+(?:(?:http_?)?client|session\(\)|\brequests\b|aiohttp|httpx|urllib)"
            r"\.\s*(?:get|post|put|delete|patch|head|options|request|fetch)\s*\(",
        )
        timeout_kw_pattern = re.compile(r"\btimeout\s*=")
        for line_num, line in enumerate(lines, start=1):
            if "noqa" in line:
                continue
            if call_pattern.search(line):
                window_end = min(len(lines), line_num + 4)
                window = "\n".join(lines[line_num - 1:window_end])
                if timeout_kw_pattern.search(window):
                    continue
                findings.append(Finding(
                    rule_id="async_missing_timeout",
                    severity=Severity.WARN,
                    message="Async HTTP call without timeout. Add explicit timeout to prevent hanging.",
                    file=filename,
                    line=line_num,
                    suggestion="Add timeout= parameter: await client.get(url, timeout=30).",
                ))
        return findings

    def _check_unclosed_file(
        self, lines: list[str], filename: str,
    ) -> list[Finding]:
        """Flag open() calls not inside with-statement and without .close() within 10 lines."""
        findings: list[Finding] = []
        open_pattern = re.compile(r"^\s*(\w+)\s*=\s*open\s*\(")
        for line_num, line in enumerate(lines, start=1):
            if "noqa" in line:
                continue
            match = open_pattern.search(line)
            if not match:
                continue
            var_name = match.group(1)

            # Check if this line is inside a with-statement
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            # Look at the preceding line for 'with' at same or lower indent
            if line_num >= 2:
                prev_line = lines[line_num - 2]
                prev_stripped = prev_line.lstrip()
                prev_indent = len(prev_line) - len(prev_stripped)
                if (
                    prev_indent <= indent
                    and not prev_stripped.startswith("#")
                    and re.match(r"^with\s+.*\bopen\s*\(", prev_stripped)
                ):
                    continue
            # Also check if 'with' is on the same line
            if stripped.startswith("with "):
                continue

            # Look ahead 10 lines for .close(), including the current line
            window_end = min(len(lines), line_num + 10)
            close_pattern = re.compile(
                rf"{re.escape(var_name)}\.close\s*\(",
            )
            found_close = False
            for ahead_line in lines[line_num - 1:window_end]:
                if close_pattern.search(ahead_line):
                    found_close = True
                    break
            if found_close:
                continue

            findings.append(Finding(
                rule_id="memleak_unclosed_file",
                severity=Severity.WARN,
                message="File opened without context manager. Use 'with open(...) as f:' instead.",
                file=filename,
                line=line_num,
                suggestion="Use a context manager: with open(path) as f: ...",
            ))
        return findings

    def _check_go_sql_close(
        self, lines: list[str], filename: str,
    ) -> list[Finding]:
        """Flag .Query() calls without defer rows.Close() within 5 lines.

        Excludes URL/Request query getters like r.URL.Query() which take no SQL args.
        Matches other .Query( calls (excluding .QueryRow) regardless of argument type.
        """
        findings: list[Finding] = []
        # Match .Query( with a string or variable arg, not .Query().Get() (URL getter)
        query_pattern = re.compile(r"\.Query\s*\(")
        url_query_pattern = re.compile(r"\.(?:URL|Request)\.Query\s*\(\s*\)")
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("//") or "noqa" in line:
                continue
            if not query_pattern.search(line):
                continue
            # Skip URL query getters: r.URL.Query(), req.URL.Query()
            if url_query_pattern.search(line):
                continue
            # Skip QueryRow (different method, has its own rule)
            if ".QueryRow" in line:
                continue

            # Look ahead 5 lines (including current line) for defer ... .Close()
            window_end = min(len(lines), line_num + 5)
            window = "\n".join(lines[line_num - 1:window_end])
            if re.search(r"defer\s+\w+\.Close\s*\(", window):
                continue

            findings.append(Finding(
                rule_id="go_sql_rows_no_close",
                severity=Severity.BLOCK,
                message="SQL Rows not closed. Add 'defer rows.Close()' to prevent connection pool exhaustion.",
                file=filename,
                line=line_num,
                suggestion="Add 'defer rows.Close()' immediately after error check.",
            ))
        return findings

    def check_repo_structure(self, root: str) -> list[Finding]:
        """Check repository for required/recommended files and structure issues."""
        findings: list[Finding] = []
        root_path = Path(root)

        findings.extend(self._check_required_files(root_path))
        findings.extend(self._check_recommended_files(root_path))
        findings.extend(self._check_recommended_dirs(root_path))
        findings.extend(self._check_forbidden_files(root_path))

        logger.info(
            "repo_structure_check_complete",
            root=root,
            total_findings=len(findings),
        )
        return findings

    def _check_required_files(self, root: Path) -> list[Finding]:
        """Check that all required files exist."""
        findings: list[Finding] = []
        for filename in REQUIRED_FILES:
            if not (root / filename).exists():
                findings.append(
                    Finding(
                        rule_id="missing_required_file",
                        severity=Severity.BLOCK,
                        message=f"Required file '{filename}' is missing.",
                        file=filename,
                        suggestion=f"Create {filename} in the project root.",
                    )
                )
        return findings

    def _check_recommended_files(self, root: Path) -> list[Finding]:
        """Check that recommended files exist."""
        findings: list[Finding] = []
        for filename in RECOMMENDED_FILES:
            path = root / filename
            if not path.exists():
                findings.append(
                    Finding(
                        rule_id="missing_recommended_file",
                        severity=Severity.WARN,
                        message=f"Recommended file '{filename}' is missing.",
                        file=filename,
                        suggestion=f"Consider adding {filename}.",
                    )
                )
        return findings

    def _check_recommended_dirs(self, root: Path) -> list[Finding]:
        """Check that recommended directories exist."""
        findings: list[Finding] = []
        for dirname in RECOMMENDED_DIRS:
            if not (root / dirname).is_dir():
                findings.append(
                    Finding(
                        rule_id="missing_recommended_dir",
                        severity=Severity.WARN,
                        message=f"Recommended directory '{dirname}/' is missing.",
                        file=dirname,
                        suggestion=f"Create {dirname}/ directory.",
                    )
                )
        return findings

    def _check_forbidden_files(self, root: Path) -> list[Finding]:
        """Check that forbidden files are not committed."""
        findings: list[Finding] = []
        for pattern in FORBIDDEN_PATTERNS:
            matches = list(root.glob(pattern))
            # Also check recursively
            matches.extend(root.glob(f"**/{pattern}"))
            for match in matches:
                # Skip items inside .git directory
                if ".git" in match.parts:
                    continue
                rel_path = str(match.relative_to(root))
                findings.append(
                    Finding(
                        rule_id="forbidden_file",
                        severity=Severity.WARN,
                        message=f"File '{rel_path}' should not be committed.",
                        file=rel_path,
                        suggestion=f"Add '{pattern}' to .gitignore.",
                    )
                )
        # Deduplicate by file path
        seen: set[str] = set()
        unique_findings: list[Finding] = []
        for finding in findings:
            if finding.file not in seen:
                seen.add(finding.file)
                unique_findings.append(finding)
        return unique_findings

    def build_report(self, findings: list[Finding], title: str) -> str:
        """Format findings into a human-readable markdown report."""
        if not findings:
            return f"## {title}\n\n**PASS** — No issues found.\n"

        blocks = [f for f in findings if f.severity == Severity.BLOCK]
        warns = [f for f in findings if f.severity == Severity.WARN]
        infos = [f for f in findings if f.severity == Severity.INFO]

        verdict = self._compute_verdict(findings)
        lines: list[str] = [
            f"## {title}",
            "",
            f"**Verdict: {verdict}** | "
            f"{len(blocks)} blocks | "
            f"{len(warns)} warnings | "
            f"{len(infos)} infos",
            "",
        ]

        if blocks:
            lines.append("### 🚫 BLOCK")
            lines.extend(self._format_findings(blocks))

        if warns:
            lines.append("### ⚠️ WARN")
            lines.extend(self._format_findings(warns))

        if infos:
            lines.append("### INFO")
            lines.extend(self._format_findings(infos))

        return "\n".join(lines)

    def _format_findings(self, findings: list[Finding]) -> list[str]:
        """Format a group of findings as markdown list items."""
        lines: list[str] = []
        for finding in findings:
            location = ""
            if finding.file and finding.line:
                location = f" ({finding.file}:{finding.line})"
            elif finding.file:
                location = f" ({finding.file})"

            suggestion = ""
            if finding.suggestion:
                suggestion = f" → {finding.suggestion}"

            lines.append(
                f"- **{finding.rule_id}**{location}: "
                f"{finding.message}{suggestion}"
            )
        lines.append("")
        return lines

    def _compute_verdict(self, findings: list[Finding]) -> str:
        """Compute overall verdict from findings."""
        severities = {f.severity for f in findings}
        if Severity.BLOCK in severities:
            return "BLOCK"
        if Severity.WARN in severities:
            return "WARN"
        return "PASS"

    def build_scan_response(
        self, findings: list[Finding]
    ) -> StaticScanResponse:
        """Build a StaticScanResponse from a list of findings."""
        blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
        warns = sum(1 for f in findings if f.severity == Severity.WARN)
        infos = sum(1 for f in findings if f.severity == Severity.INFO)
        verdict = self._compute_verdict(findings)

        return StaticScanResponse(
            total_findings=len(findings),
            blocks=blocks,
            warnings=warns,
            infos=infos,
            findings=findings,
            verdict=verdict,
        )

    # ═══════════════════════════════════════════════════════════════
    #  AI DRIFT SCORE — composite trust metric
    # ═══════════════════════════════════════════════════════════════

    from typing import ClassVar

    # Rule categories for drift score breakdown
    CATEGORY_MAP: ClassVar[dict[str, str]] = {
        # Anti-Hallucination (Law 1) — AI fabrication detection
        "hardcoded_secret": "anti_hallucination",
        "eval_exec": "anti_hallucination",
        "sql_injection": "anti_hallucination",
        "pickle_load": "anti_hallucination",
        "api_key_in_config": "anti_hallucination",
        "docker_env_secret": "anti_hallucination",
        "hallucinated_localhost_port": "anti_hallucination",
        "hallucinated_api_endpoint": "anti_hallucination",
        "hallucinated_env_var": "anti_hallucination",
        "placeholder_url": "anti_hallucination",
        "fake_api_key_format": "anti_hallucination",
        "hallucinated_import_nonexistent": "anti_hallucination",
        "hallucinated_import_misspelled": "anti_hallucination",
        "hallucinated_method_chain": "anti_hallucination",
        "hallucinated_config_option": "anti_hallucination",
        "hallucinated_cli_flag": "anti_hallucination",
        "hallucinated_version": "anti_hallucination",
        "phantom_file_reference": "anti_hallucination",
        "hallucinated_http_status": "anti_hallucination",
        # Anti-Assumption (Law 2) — never assume, verify
        "magic_number": "anti_assumption",
        "hardcoded_port": "anti_assumption",
        "debug_mode_enabled": "anti_assumption",
        "any_type": "anti_assumption",
        "mutable_default": "anti_assumption",
        "hardcoded_ip": "anti_assumption",
        # Root Cause (Law 3) — fix the root, not the symptom
        "except_swallow": "root_cause",
        "bare_except": "root_cause",
        "null_coalesce_smell": "root_cause",
        "suppress_lint": "root_cause",
        "sleep_no_context": "root_cause",
        # Container Hygiene
        "docker_root_user": "container_hygiene",
        "docker_latest_tag": "container_hygiene",
        "docker_no_workdir": "container_hygiene",
        "dockerfile_no_healthcheck": "container_hygiene",
        "compose_no_healthcheck": "container_hygiene",
        # CI/CD
        "ci_unpinned_action": "ci_cd",
        "ci_no_timeout": "ci_cd",
        "blocking_prestart": "ci_cd",
        "healthcheck_timeout_low": "ci_cd",
        # DevOps
        "connection_no_timeout": "devops",
        "unbounded_retry": "devops",
        "retry_exponential_unbounded": "devops",
    }

    def _compute_category_scores(
        self, findings: list[Finding],
    ) -> tuple[int, dict[str, dict[str, int | float | str]], int]:
        """Compute per-category scores and total weight from findings."""
        weights = {Severity.BLOCK: 10, Severity.WARN: 3, Severity.INFO: 1}
        categories: dict[str, dict[str, int | float]] = {
            "anti_hallucination": {"findings": 0, "weight": 0},
            "anti_assumption": {"findings": 0, "weight": 0},
            "root_cause": {"findings": 0, "weight": 0},
            "container_hygiene": {"findings": 0, "weight": 0},
            "ci_cd": {"findings": 0, "weight": 0},
            "devops": {"findings": 0, "weight": 0},
        }
        total_weight = 0
        for f in findings:
            w = weights.get(f.severity, 1)
            total_weight += w
            cat = self.CATEGORY_MAP.get(f.rule_id, "devops")
            if cat in categories:
                categories[cat]["findings"] += 1
                categories[cat]["weight"] += w

        cat_scores: dict[str, dict[str, int | float | str]] = {}
        for cat_name, data in categories.items():
            cat_weight = data["weight"]
            cat_score = max(0, 100 - cat_weight * 5)
            cat_status = "PASS" if cat_score >= 70 else ("WARN" if cat_score >= 40 else "FAIL")
            cat_scores[cat_name] = {
                "score": cat_score,
                "findings": data["findings"],
                "status": cat_status,
            }

        halluc_count = categories["anti_hallucination"]["findings"]
        return total_weight, cat_scores, int(halluc_count)

    def calculate_drift_score(self, findings: list[Finding]) -> dict:
        """Calculate AI Drift Score from scan findings.

        Returns a trust metric: 100 = perfect, 0 = critical.
        Breaks down by category matching CodeTrust's Three Laws.
        Tracks baseline and trend when a project path is available.
        """
        total_weight, cat_scores, halluc_count = self._compute_category_scores(findings)

        score = max(0, 100 - total_weight)
        grade = self._score_to_grade(score)
        ai_trust_score = max(0, 100 - halluc_count * 15)

        return {
            "score": score,
            "grade": grade,
            "total_findings": len(findings),
            "ai_trust_score": ai_trust_score,
            "ai_trust_grade": self._score_to_grade(ai_trust_score),
            "categories": cat_scores,
        }

    @staticmethod
    def _score_to_grade(score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 95:
            return "A+"
        if score >= 90:
            return "A"
        if score >= 80:
            return "B+"
        if score >= 70:
            return "B"
        if score >= 60:
            return "C+"
        if score >= 50:
            return "C"
        if score >= 30:
            return "D"
        return "F"

    def _load_drift_history(
        self, baseline_file: Path,
    ) -> tuple[list[dict], int | None]:
        """Load drift baseline history from file."""
        import json
        if not baseline_file.exists():
            return [], None
        try:
            data = json.loads(baseline_file.read_text())
            return data.get("history", []), data.get("baseline_score")
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("drift_baseline_load_failed: %s", exc)
            return [], None

    @staticmethod
    def _compute_trend(history: list[dict]) -> str:
        """Compute trend direction from recent history."""
        recent = history[-5:]
        if len(recent) < 2:
            return "new"
        recent_scores = [h["score"] for h in recent]
        trend_delta = recent_scores[-1] - recent_scores[0]
        if trend_delta > 3:
            return "improving"
        if trend_delta < -3:
            return "degrading"
        return "stable"

    def _save_drift_baseline(
        self,
        baseline_dir: Path,
        baseline_file: Path,
        baseline_score: int,
        current: dict,
        history: list[dict],
    ) -> None:
        """Save updated drift baseline to file."""
        import json
        try:
            baseline_dir.mkdir(parents=True, exist_ok=True)
            baseline_data = {
                "baseline_score": baseline_score,
                "last_score": current["score"],
                "last_grade": current["grade"],
                "history": history,
            }
            baseline_file.write_text(json.dumps(baseline_data, indent=2))
        except OSError:
            logger.warning("drift_baseline_save_failed", path=str(baseline_file))

    @staticmethod
    def _build_data_point(current: dict) -> dict:
        """Build a history data point from current drift score."""
        import time
        return {
            "timestamp": time.time(),
            "score": current["score"],
            "grade": current["grade"],
            "ai_trust_score": current["ai_trust_score"],
            "total_findings": current["total_findings"],
        }

    @staticmethod
    def _apply_trend_data(
        current: dict, delta: int, baseline_score: int,
        trend: str, scan_count: int,
    ) -> None:
        """Extend current score dict with trend metadata."""
        current["delta_from_baseline"] = delta
        current["baseline_score"] = baseline_score
        current["trend"] = trend
        current["scan_count"] = scan_count
        current["trend_direction"] = (
            "+" + str(delta) if delta > 0 else str(delta) if delta < 0 else "±0"
        )

    def calculate_drift_with_baseline(
        self,
        findings: list[Finding],
        project_path: str,
    ) -> dict:
        """Calculate drift score with baseline comparison and trend tracking."""
        current = self.calculate_drift_score(findings)
        baseline_dir = Path(project_path) / ".codetrust"
        baseline_file = baseline_dir / "drift_baseline.json"

        history, baseline_score = self._load_drift_history(baseline_file)

        history.append(self._build_data_point(current))
        history = history[-100:]

        if baseline_score is None:
            baseline_score = current["score"]

        delta = current["score"] - baseline_score
        trend = self._compute_trend(history)

        self._save_drift_baseline(
            baseline_dir, baseline_file, baseline_score, current, history,
        )
        self._apply_trend_data(current, delta, baseline_score, trend, len(history))
        return current
