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
