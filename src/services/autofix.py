# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""Auto-fix PR generation service — applies fixes and opens pull requests.

Uses the GitHub API to create branches, commit fixes, and open PRs
with detailed descriptions of what was fixed and why.

This is a paid feature in Snyk (Auto-fix PRs) and Dependabot — CodeTrust provides it free.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    import re

    import httpx

logger = structlog.get_logger()

GITHUB_API_BASE = "https://api.github.com"
BRANCH_PREFIX = "codetrust/autofix"
_REQUEST_TIMEOUT = 15.0

# Autofix recipes: rule_id -> (description, fix_function)
# Additional recipes can be registered via register_recipe().


@dataclass(frozen=True)
class FixedFile:
    """A file with applied fixes."""

    path: str
    original_content: str
    fixed_content: str
    fixes_applied: list[str]


@dataclass(frozen=True)
class AutoFixResult:
    """Result of applying auto-fix recipes to code."""

    files_fixed: list[FixedFile] = field(default_factory=list)
    total_fixes: int = 0
    pr_url: str = ""
    branch_name: str = ""
    error: str = ""


@dataclass(frozen=True)
class PRInfo:
    """Information about a created pull request."""

    url: str
    number: int
    branch: str
    title: str


# --- Fix Recipes ---

def fix_print_to_logging(code: str, language: str) -> tuple[str, list[str]]:
    """Replace print() statements with logging.info().

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    import re
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []
    print_re = re.compile(r"^(\s*)print\s*\(")

    for i, line in enumerate(lines, 1):
        m = print_re.match(line)
        if m:
            indent = m.group(1)
            out.append(indent + "logging.info(" + line[m.end():])
            fixes.append(f"Line {i}: replaced print() with logging.info()")
        else:
            out.append(line)

    result = "".join(out)

    if fixes and "import logging" not in result:
        # Add import at top.
        result = "import logging\n" + result
        fixes.insert(0, "Added 'import logging' at top of file")

    return result, fixes


def fix_bare_except(code: str, language: str) -> tuple[str, list[str]]:
    """Replace bare 'except' with 'except Exception'.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    if language != "python":
        return code, []

    import re
    lines = code.splitlines(keepends=True)
    fixes: list[str] = []
    out: list[str] = []
    bare_except_re = re.compile(r"^(\s*)except\s*:")

    for i, line in enumerate(lines, 1):
        m = bare_except_re.match(line)
        if m:
            indent = m.group(1)
            out.append(f"{indent}except Exception:\n")
            fixes.append(f"Line {i}: replaced bare 'except' with 'except Exception'")
        else:
            out.append(line)

    return "".join(out), fixes


def _replace_secrets_in_lines(
    lines: list[str],
    language: str,
    secret_re: re.Pattern[str],
) -> tuple[list[str], list[str]]:
    """Scan lines and replace hardcoded secrets with env var lookups."""
    fixes: list[str] = []
    out: list[str] = []
    for i, line in enumerate(lines, 1):
        m = secret_re.match(line)
        if m:
            indent = m.group(1)
            var_name = m.group(2)
            env_var = var_name.upper()
            if language == "python":
                out.append(f'{indent}{var_name} = os.environ.get("{env_var}", "")\n')
            else:
                out.append(f"{indent}const {var_name} = process.env.{env_var} || '';\n")
            fixes.append(
                f"Line {i}: moved hardcoded secret '{var_name}' to environment variable"
            )
        else:
            out.append(line)
    return out, fixes


def fix_hardcoded_secrets(code: str, language: str) -> tuple[str, list[str]]:
    """Replace hardcoded secret patterns with environment variable lookups.

    Args:
        code: Source code content.
        language: Programming language.

    Returns:
        Tuple of (fixed_code, list_of_fix_descriptions).
    """
    import re

    if language not in ("python", "javascript", "typescript"):
        return code, []

    secret_re = re.compile(
        r"""^(\s*)(\w*(?:secret|password|api_key|api_secret|token|private_key)\w*)\s*=\s*["']([^"']{8,})["']""",
        re.IGNORECASE,
    )
    out, fixes = _replace_secrets_in_lines(
        code.splitlines(keepends=True), language, secret_re,
    )
    result = "".join(out)

    if fixes and language == "python" and "import os" not in result:
        result = "import os\n" + result
        fixes.insert(0, "Added 'import os' for environment variable access")

    return result, fixes


# Registry of all available fix recipes.
FIX_RECIPES: list[tuple[str, object]] = [
    ("print_to_logging", fix_print_to_logging),
    ("bare_except", fix_bare_except),
    ("hardcoded_secrets", fix_hardcoded_secrets),
]


class AutoFixService:
    """Applies autofix recipes and optionally creates GitHub PRs.

    Can operate in two modes:
    1. Local mode: apply fixes to files and return the diffs.
    2. PR mode: create a branch, commit fixes, and open a PR on GitHub.
    """

    def __init__(
        self,
        http_client: httpx.AsyncClient | None = None,
        github_token: str = "",
    ) -> None:
        """Initialize with optional HTTP client for GitHub API calls.

        Args:
            http_client: Shared httpx client. Required for PR mode.
            github_token: GitHub personal access token with repo scope.
        """
        self._http = http_client
        self._github_token = github_token

    @staticmethod
    def _apply_recipes_to_file(
        filepath: str,
        content: str,
        language: str,
        active_recipes: list[tuple[str, object]],
    ) -> FixedFile | None:
        """Apply all active recipes to a single file."""
        all_fixes: list[str] = []
        current = content
        for _recipe_name, recipe_fn in active_recipes:
            current, fixes = recipe_fn(current, language)
            all_fixes.extend(fixes)
        if not all_fixes:
            return None
        return FixedFile(
            path=filepath,
            original_content=content,
            fixed_content=current,
            fixes_applied=all_fixes,
        )

    def apply_fixes(
        self,
        file_contents: dict[str, str],
        file_languages: dict[str, str],
        recipes: list[str] | None = None,
    ) -> AutoFixResult:
        """Apply autofix recipes to a set of files.

        Args:
            file_contents: Map of filepath -> content.
            file_languages: Map of filepath -> language string.
            recipes: Optional list of recipe names to apply.
                If None, all recipes are applied.

        Returns:
            AutoFixResult with fixed files and statistics.
        """
        active_recipes = FIX_RECIPES
        if recipes:
            recipe_set = set(recipes)
            active_recipes = [
                (name, fn) for name, fn in FIX_RECIPES
                if name in recipe_set
            ]

        fixed_files: list[FixedFile] = []
        total_fixes = 0
        for filepath, content in file_contents.items():
            language = file_languages.get(filepath, "")
            result = self._apply_recipes_to_file(
                filepath, content, language, active_recipes,
            )
            if result is not None:
                fixed_files.append(result)
                total_fixes += len(result.fixes_applied)

        return AutoFixResult(
            files_fixed=fixed_files,
            total_fixes=total_fixes,
        )

    @staticmethod
    def _make_branch_name(owner: str, repo: str) -> str:
        """Generate a unique branch name for an autofix PR."""
        import hashlib
        import time
        timestamp = int(time.time())
        hash_suffix = hashlib.sha256(
            f"{timestamp}:{owner}/{repo}".encode()
        ).hexdigest()[:8]
        return f"{BRANCH_PREFIX}-{hash_suffix}"

    async def _commit_fixed_files(
        self, owner: str, repo: str, branch_name: str,
        files_fixed: list[FixedFile],
    ) -> None:
        """Commit each fixed file to the branch."""
        for fixed_file in files_fixed:
            await self._update_file(
                owner, repo, branch_name,
                fixed_file.path,
                fixed_file.fixed_content,
                f"fix: {', '.join(fixed_file.fixes_applied[:3])}",
            )

    async def _push_and_open_pr(
        self,
        owner: str,
        repo: str,
        base_branch: str,
        branch_name: str,
        fix_result: AutoFixResult,
        title: str,
        body: str,
    ) -> AutoFixResult:
        """Create branch, commit fixes, and open the pull request."""
        base_sha = await self._get_branch_sha(owner, repo, base_branch)
        if not base_sha:
            return AutoFixResult(
                files_fixed=fix_result.files_fixed,
                total_fixes=fix_result.total_fixes,
                error=f"Branch '{base_branch}' not found.",
            )

        await self._create_branch(owner, repo, branch_name, base_sha)
        await self._commit_fixed_files(owner, repo, branch_name, fix_result.files_fixed)

        if not title:
            title = f"fix: CodeTrust autofix — {fix_result.total_fixes} issues resolved"
        if not body:
            body = self._generate_pr_body(fix_result)

        pr_info = await self._create_pull_request(
            owner, repo, branch_name, base_branch, title, body,
        )
        return AutoFixResult(
            files_fixed=fix_result.files_fixed,
            total_fixes=fix_result.total_fixes,
            pr_url=pr_info.url,
            branch_name=branch_name,
        )

    async def create_pr(
        self,
        owner: str,
        repo: str,
        base_branch: str,
        fix_result: AutoFixResult,
        title: str = "",
        body: str = "",
    ) -> AutoFixResult:
        """Create a GitHub PR with the applied fixes."""
        if not self._http or not self._github_token:
            return AutoFixResult(
                files_fixed=fix_result.files_fixed,
                total_fixes=fix_result.total_fixes,
                error="GitHub token not configured. Set CODETRUST_GITHUB_TOKEN.",
            )

        if not fix_result.files_fixed:
            return AutoFixResult(error="No fixes to commit.")

        branch_name = self._make_branch_name(owner, repo)
        try:
            return await self._push_and_open_pr(
                owner, repo, base_branch, branch_name,
                fix_result, title, body,
            )
        except Exception as exc:
            logger.error("autofix_pr_failed", error=str(exc))
            return AutoFixResult(
                files_fixed=fix_result.files_fixed,
                total_fixes=fix_result.total_fixes,
                error=f"Failed to create PR: {exc}",
            )

    def _generate_pr_body(self, fix_result: AutoFixResult) -> str:
        """Generate a descriptive PR body from fix results."""
        lines = [
            "## CodeTrust Auto-Fix Report",
            "",
            f"**Total fixes applied:** {fix_result.total_fixes}",
            f"**Files modified:** {len(fix_result.files_fixed)}",
            "",
            "### Changes",
            "",
        ]

        for fixed in fix_result.files_fixed:
            lines.append(f"#### `{fixed.path}`")
            for fix in fixed.fixes_applied:
                lines.append(f"- {fix}")
            lines.append("")

        lines.extend([
            "---",
            "*This PR was automatically generated by [CodeTrust](https://codetrust.ai).*",
            "*Review each change carefully before merging.*",
        ])

        return "\n".join(lines)

    async def _get_branch_sha(
        self, owner: str, repo: str, branch: str,
    ) -> str:
        """Get the latest commit SHA for a branch."""
        if not self._http:
            return ""
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/ref/heads/{branch}"
        response = await self._http.get(
            url,
            headers=self._auth_headers(),
            timeout=_REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            return ""
        data = response.json()
        obj = data.get("object", {})
        return str(obj.get("sha", "")) if isinstance(obj, dict) else ""

    async def _create_branch(
        self, owner: str, repo: str, branch: str, sha: str,
    ) -> None:
        """Create a new branch from a commit SHA."""
        if not self._http:
            return
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/git/refs"
        response = await self._http.post(
            url,
            headers=self._auth_headers(),
            json={"ref": f"refs/heads/{branch}", "sha": sha},
            timeout=_REQUEST_TIMEOUT,
        )
        response.raise_for_status()

    async def _update_file(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        content: str,
        message: str,
    ) -> None:
        """Create or update a file in the repository."""
        if not self._http:
            return
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/contents/{path}"

        # Get current file SHA (needed for update).
        get_response = await self._http.get(
            url,
            headers=self._auth_headers(),
            params={"ref": branch},
            timeout=_REQUEST_TIMEOUT,
        )
        file_sha = ""
        if get_response.status_code == 200:
            file_sha = str(get_response.json().get("sha", ""))

        payload: dict[str, str] = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if file_sha:
            payload["sha"] = file_sha

        response = await self._http.put(
            url,
            headers=self._auth_headers(),
            json=payload,
            timeout=_REQUEST_TIMEOUT,
        )
        response.raise_for_status()

    async def _create_pull_request(
        self,
        owner: str,
        repo: str,
        head: str,
        base: str,
        title: str,
        body: str,
    ) -> PRInfo:
        """Create a pull request on GitHub."""
        if not self._http:
            return PRInfo(url="", number=0, branch=head, title=title)
        url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/pulls"
        response = await self._http.post(
            url,
            headers=self._auth_headers(),
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            },
            timeout=_REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        data = response.json()
        return PRInfo(
            url=str(data.get("html_url", "")),
            number=int(data.get("number", 0)),
            branch=head,
            title=title,
        )

    def _auth_headers(self) -> dict[str, str]:
        """Build GitHub API authorization headers."""
        return {
            "Authorization": f"token {self._github_token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
