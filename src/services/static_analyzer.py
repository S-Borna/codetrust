"""Layer 1: Regex-based anti-pattern detection engine. Runs locally, no network calls."""

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

    def _is_devops_file(self, filename: str, ext: str) -> bool:
        """Check if a file is a DevOps/infrastructure file."""
        basename = os.path.basename(filename).lower()
        return ext in DEVOPS_EXTENSIONS or basename in DEVOPS_FILENAMES

    def scan_code(self, code: str, filename: str = "") -> list[Finding]:
        """Run all anti-pattern rules against a code string."""
        findings: list[Finding] = []
        lines = code.splitlines()
        ext = os.path.splitext(filename)[1].lower() if filename else ""

        for rule in ANTI_PATTERNS:
            handler = rule.get("special_handler", "")

            # --- file-type routing ---
            rule_file_types = rule.get("file_types")
            if rule_file_types:
                # Rule is language-specific — only run on matching extensions
                if ext not in rule_file_types:
                    # Also match DevOps filenames (e.g. "Dockerfile" has no ext)
                    basename = os.path.basename(filename).lower()
                    if basename not in DEVOPS_FILENAMES:
                        continue
                    if not any(ft in DEVOPS_EXTENSIONS for ft in rule_file_types):
                        continue
            else:
                # Generic rule — skip files that belong to a dedicated language
                if ext in SQL_EXTENSIONS:
                    continue

            if handler == "check_function_length":
                findings.extend(self._check_function_lengths(lines, filename))
                continue
            if handler == "check_connection_timeout":
                findings.extend(self._check_connection_timeout(lines, filename))
                continue
            if handler == "check_dockerfile_healthcheck":
                findings.extend(self._check_dockerfile_healthcheck(lines, filename))
                continue
            if handler == "check_compose_healthcheck":
                findings.extend(self._check_compose_healthcheck(lines, filename))
                continue
            if handler == "check_except_swallow":
                findings.extend(self._check_except_swallow(lines, filename))
                continue
            if handler == "check_sleep_no_context":
                findings.extend(self._check_sleep_no_context(lines, filename))
                continue
            if handler == "check_docker_root_user":
                findings.extend(self._check_docker_root_user(lines, filename))
                continue
            if handler == "check_docker_no_workdir":
                findings.extend(self._check_docker_no_workdir(lines, filename))
                continue
            if handler == "check_ci_no_timeout":
                findings.extend(self._check_ci_no_timeout(lines, filename))
                continue

            findings.extend(
                self._apply_rule(rule, lines, filename)
            )

        logger.info(
            "static_scan_complete",
            filename=filename,
            total_findings=len(findings),
        )
        return findings

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
            if stripped.count('"""') == 1 or stripped.count("'''") == 1:
                in_docstring = not in_docstring
            if skip_comments and (
                in_docstring
                or stripped.startswith("#")
                or stripped.startswith('"""')
                or stripped.startswith("'''")
            ):
                continue

            if "noqa" in line:
                continue

            if pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=rule["id"],
                        severity=Severity(rule["severity"]),
                        message=rule["message"],
                        file=filename,
                        line=line_num,
                        suggestion="",
                    )
                )

        return findings

    def _check_function_lengths(
        self,
        lines: list[str],
        filename: str,
    ) -> list[Finding]:
        """Check that no function exceeds MAX_FUNCTION_LENGTH lines."""
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
        for line_num, line in enumerate(lines, start=1):
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
                if body in ("pass", "...", "continue", "pass  # noqa"):
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
        """Flag sleep() calls without a preceding comment explaining why."""
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
                            message="sleep() without explanation. Why is a delay needed?",
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
        # Anti-Hallucination (Law 1)
        "hardcoded_secret": "anti_hallucination",
        "eval_exec": "anti_hallucination",
        "sql_injection": "anti_hallucination",
        "pickle_load": "anti_hallucination",
        "api_key_in_config": "anti_hallucination",
        "docker_env_secret": "anti_hallucination",
        # Anti-Assumption (Law 2)
        "magic_number": "anti_assumption",
        "hardcoded_port": "anti_assumption",
        "debug_mode_enabled": "anti_assumption",
        "any_type": "anti_assumption",
        "mutable_default": "anti_assumption",
        "hardcoded_ip": "anti_assumption",
        # Root Cause (Law 3)
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

    def calculate_drift_score(self, findings: list[Finding]) -> dict:
        """Calculate AI Drift Score from scan findings.

        Returns a trust metric: 100 = perfect, 0 = critical.
        Breaks down by category matching CodeTrust's Three Laws.
        """
        weights = {Severity.BLOCK: 10, Severity.WARN: 3, Severity.INFO: 1}

        # Category scores
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

        # Score: 100 - penalty, floor at 0
        score = max(0, 100 - total_weight)

        # Grade
        if score >= 90:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        # Category scores (100 minus category penalty, capped)
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

        return {
            "score": score,
            "grade": grade,
            "total_findings": len(findings),
            "categories": cat_scores,
        }
