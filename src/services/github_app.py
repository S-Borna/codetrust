# Copyright (c) 2026 Said Borna. All rights reserved.
# Proprietary — see LICENSE for terms.
"""GitHub App integration for pull request webhook scanning and sticky comments."""

from __future__ import annotations

import base64
import datetime
import hmac
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING

import httpx
import jwt
import structlog

from src.config import settings
from src.models.enums import Severity

if TYPE_CHECKING:
    from src.models.responses import Finding
    from src.services.static_analyzer import StaticAnalyzer

logger = structlog.get_logger()

GITHUB_V3_ACCEPT = "application/vnd.github+json"
REQUEST_TIMEOUT_SECONDS = 15.0
APP_JWT_LIFETIME_SECONDS = 540
PR_COMMENT_MARKER = "<!-- codetrust-github-app-comment -->"
SUPPORTED_PR_ACTIONS = {"opened", "synchronize", "reopened"}
MAX_FILES_PER_PR = 50
MAX_FILE_BYTES = 300_000
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".cs", ".cpp", ".c", ".h",
}


@dataclass(frozen=True)
class GitHubAppEventResult:
    """Normalized webhook processing result."""

    processed: bool
    event: str
    action: str
    reason: str
    comment_url: str = ""
    total_findings: int = 0
    blocks: int = 0
    warnings: int = 0
    infos: int = 0


@dataclass(frozen=True)
class PullRequestTarget:
    """Minimal target details from a pull request webhook payload."""

    owner: str
    repo: str
    number: int
    head_sha: str
    installation_id: int


class GitHubAppService:
    """Handles GitHub App auth, pull request scanning, and sticky comments."""

    def __init__(self, http_client: httpx.AsyncClient, analyzer: StaticAnalyzer) -> None:
        """Initialize service with shared HTTP client and static analyzer."""
        self._http = http_client
        self._analyzer = analyzer

    def is_configured(self) -> bool:
        """Return True when all required GitHub App settings are configured."""
        return bool(
            settings.github_app_id
            and settings.github_app_private_key
            and settings.github_app_webhook_secret
        )

    def verify_webhook_signature(self, payload: bytes, header: str) -> bool:
        """Verify X-Hub-Signature-256 using the configured webhook secret."""
        if not self.is_configured():
            logger.warning("github_app_not_configured")
            return False
        if not header.startswith("sha256="):
            return False
        expected = "sha256=" + hmac.new(
            settings.github_app_webhook_secret.encode("utf-8"),
            payload,
            sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, header)

    async def handle_webhook_event(
        self,
        event: str,
        payload: dict[str, object],
    ) -> GitHubAppEventResult:
        """Handle pull_request webhook events and publish a sticky PR comment."""
        if not self.is_configured():
            return GitHubAppEventResult(False, event, "", "github_app_not_configured")
        if event != "pull_request":
            return GitHubAppEventResult(False, event, "", "event_not_supported")

        action = str(payload.get("action", ""))
        if action not in SUPPORTED_PR_ACTIONS:
            return GitHubAppEventResult(False, event, action, "action_not_supported")

        target = self._extract_pull_request_target(payload)
        if target is None:
            return GitHubAppEventResult(False, event, action, "payload_missing_fields")

        token = await self._create_installation_token(target.installation_id)
        if not token:
            return GitHubAppEventResult(False, event, action, "installation_token_failed")

        scan = await self._scan_pull_request(target, token)
        comment_url = await self._upsert_pull_request_comment(target, token, scan["body"])
        return GitHubAppEventResult(
            processed=True,
            event=event,
            action=action,
            reason="processed",
            comment_url=comment_url,
            total_findings=scan["total"],
            blocks=scan["blocks"],
            warnings=scan["warnings"],
            infos=scan["infos"],
        )

    def _extract_pull_request_target(
        self,
        payload: dict[str, object],
    ) -> PullRequestTarget | None:
        """Extract owner/repo/pr/head/installation from webhook payload."""
        repo_obj = payload.get("repository")
        pr_obj = payload.get("pull_request")
        install_obj = payload.get("installation")
        if not isinstance(repo_obj, dict) or not isinstance(pr_obj, dict):
            return None
        if not isinstance(install_obj, dict):
            return None

        owner_obj = repo_obj.get("owner")
        head_obj = pr_obj.get("head")
        if not isinstance(owner_obj, dict) or not isinstance(head_obj, dict):
            return None

        owner = str(owner_obj.get("login", "")).strip()
        repo = str(repo_obj.get("name", "")).strip()
        head_sha = str(head_obj.get("sha", "")).strip()
        pr_number = self._safe_int(pr_obj.get("number"))
        installation_id = self._safe_int(install_obj.get("id"))
        if not owner or not repo or not head_sha or pr_number <= 0 or installation_id <= 0:
            return None
        return PullRequestTarget(owner, repo, pr_number, head_sha, installation_id)

    @staticmethod
    def _safe_int(value: object) -> int:
        """Convert value to int and return 0 for invalid/non-positive values."""
        try:
            parsed = int(str(value))
            return parsed if parsed > 0 else 0
        except (TypeError, ValueError):
            return 0

    async def _create_installation_token(self, installation_id: int) -> str:
        """Create an installation token using a signed GitHub App JWT."""
        jwt_token = self._build_app_jwt()
        if not jwt_token:
            return ""

        url = f"{settings.github_app_api_url}/app/installations/{installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": GITHUB_V3_ACCEPT,
            "User-Agent": "CodeTrust-GitHub-App",
        }
        try:
            resp = await self._http.post(url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
            resp.raise_for_status()
            data = resp.json()
            token = data.get("token", "")
            return str(token) if token else ""
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("github_installation_token_error", error=str(exc))
            return ""

    def _build_app_jwt(self) -> str:
        """Build a short-lived GitHub App JWT signed with the app private key."""
        try:
            now = datetime.datetime.now(datetime.UTC)
            payload = {
                "iat": int((now - datetime.timedelta(seconds=60)).timestamp()),
                "exp": int((now + datetime.timedelta(seconds=APP_JWT_LIFETIME_SECONDS)).timestamp()),
                "iss": settings.github_app_id,
            }
            encoded = jwt.encode(payload, settings.github_app_private_key, algorithm="RS256")
            return str(encoded)
        except (ValueError, TypeError, jwt.PyJWTError) as exc:
            logger.error("github_app_jwt_error", error=str(exc))
            return ""

    async def _scan_pull_request(
        self,
        target: PullRequestTarget,
        token: str,
    ) -> dict[str, object]:
        """Scan changed PR files and return markdown comment plus severity counts."""
        pr_files = await self._list_pull_request_files(target, token)
        findings = await self._collect_findings_from_files(target, token, pr_files)
        blocks, warnings, infos = self._count_by_severity(findings)
        body = self._build_comment_body(target, findings, blocks, warnings, infos)
        return {
            "body": body,
            "total": len(findings),
            "blocks": blocks,
            "warnings": warnings,
            "infos": infos,
        }

    async def _list_pull_request_files(
        self,
        target: PullRequestTarget,
        token: str,
    ) -> list[dict[str, object]]:
        """List changed files in a pull request."""
        url = (
            f"{settings.github_app_api_url}/repos/{target.owner}/{target.repo}/pulls/"
            f"{target.number}/files?per_page={MAX_FILES_PER_PR}"
        )
        try:
            resp = await self._http.get(
                url,
                headers=self._auth_headers(token),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            data = resp.json()
            return data if isinstance(data, list) else []
        except (httpx.HTTPError, ValueError) as exc:
            logger.error("github_pr_files_error", error=str(exc))
            return []

    async def _collect_findings_from_files(
        self,
        target: PullRequestTarget,
        token: str,
        pr_files: list[dict[str, object]],
    ) -> list[Finding]:
        """Fetch changed file contents at head SHA and run static analyzer."""
        findings: list[Finding] = []
        for item in pr_files:
            path = str(item.get("filename", ""))
            if not self._is_scannable_path(path):
                continue
            content = await self._fetch_file_content(target, token, path)
            if not content:
                continue
            findings.extend(self._analyzer.scan_code(content, path))
        return findings

    @staticmethod
    def _is_scannable_path(path: str) -> bool:
        """Return True for supported file extensions and non-empty paths."""
        if not path:
            return False
        lower = path.lower()
        return any(lower.endswith(ext) for ext in SUPPORTED_EXTENSIONS)

    async def _fetch_file_content(
        self,
        target: PullRequestTarget,
        token: str,
        path: str,
    ) -> str:
        """Fetch file content at PR head SHA via GitHub contents API."""
        url = f"{settings.github_app_api_url}/repos/{target.owner}/{target.repo}/contents/{path}"
        try:
            resp = await self._http.get(
                url,
                headers=self._auth_headers(token),
                params={"ref": target.head_sha},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if resp.status_code == 404:
                return ""
            resp.raise_for_status()
            data = resp.json()
            encoded = data.get("content", "")
            if not isinstance(encoded, str) or len(encoded) > MAX_FILE_BYTES * 2:
                return ""
            return base64.b64decode(encoded.encode("utf-8")).decode("utf-8", errors="ignore")
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("github_file_fetch_error", file=path, error=str(exc))
            return ""

    @staticmethod
    def _count_by_severity(findings: list[Finding]) -> tuple[int, int, int]:
        """Count BLOCK/WARN/INFO findings."""
        blocks = sum(1 for f in findings if f.severity == Severity.BLOCK)
        warns = sum(1 for f in findings if f.severity == Severity.WARN)
        infos = sum(1 for f in findings if f.severity == Severity.INFO)
        return blocks, warns, infos

    def _build_comment_body(
        self,
        target: PullRequestTarget,
        findings: list[Finding],
        blocks: int,
        warnings: int,
        infos: int,
    ) -> str:
        """Build markdown body for a sticky pull request comment."""
        verdict = "BLOCK" if blocks else ("WARN" if warnings else "PASS")
        lines = [
            PR_COMMENT_MARKER,
            "## CodeTrust GitHub App Scan",
            f"**Verdict:** {verdict}",
            f"**PR:** #{target.number}",
            f"**Findings:** {len(findings)} total ({blocks} BLOCK, {warnings} WARN, {infos} INFO)",
            "",
        ]
        if not findings:
            lines.append("No anti-pattern findings detected in changed source files.")
            return "\n".join(lines)

        lines.append("### Top Findings")
        for finding in findings[:10]:
            file_hint = finding.file or "unknown"
            line_hint = finding.line if finding.line > 0 else 1
            lines.append(
                f"- **{finding.severity.value}** `{finding.rule_id}` in `{file_hint}:{line_hint}` — {finding.message}"
            )
        if len(findings) > 10:
            lines.append(f"- ... and {len(findings) - 10} more findings")
        return "\n".join(lines)

    async def _upsert_pull_request_comment(
        self,
        target: PullRequestTarget,
        token: str,
        body: str,
    ) -> str:
        """Update prior CodeTrust comment if present, otherwise create a new one."""
        existing_id = await self._find_existing_comment_id(target, token)
        if existing_id > 0:
            return await self._update_comment(target, token, existing_id, body)
        return await self._create_comment(target, token, body)

    async def _find_existing_comment_id(self, target: PullRequestTarget, token: str) -> int:
        """Find existing sticky comment ID by marker."""
        url = (
            f"{settings.github_app_api_url}/repos/{target.owner}/{target.repo}/issues/"
            f"{target.number}/comments?per_page=100"
        )
        try:
            resp = await self._http.get(
                url,
                headers=self._auth_headers(token),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            raw_comments = resp.json()
            if not isinstance(raw_comments, list):
                return 0
            for comment in raw_comments:
                if not isinstance(comment, dict):
                    continue
                body = str(comment.get("body", ""))
                if PR_COMMENT_MARKER in body:
                    return int(comment.get("id", 0))
            return 0
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("github_comment_lookup_error", error=str(exc))
            return 0

    async def _update_comment(
        self,
        target: PullRequestTarget,
        token: str,
        comment_id: int,
        body: str,
    ) -> str:
        """Update an existing issue comment and return the HTML URL."""
        url = f"{settings.github_app_api_url}/repos/{target.owner}/{target.repo}/issues/comments/{comment_id}"
        try:
            resp = await self._http.patch(
                url,
                headers=self._auth_headers(token),
                json={"body": body},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            return str(resp.json().get("html_url", ""))
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.error("github_comment_update_error", error=str(exc))
            return ""

    async def _create_comment(self, target: PullRequestTarget, token: str, body: str) -> str:
        """Create a new issue comment and return the HTML URL."""
        url = f"{settings.github_app_api_url}/repos/{target.owner}/{target.repo}/issues/{target.number}/comments"
        try:
            resp = await self._http.post(
                url,
                headers=self._auth_headers(token),
                json={"body": body},
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            resp.raise_for_status()
            return str(resp.json().get("html_url", ""))
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.error("github_comment_create_error", error=str(exc))
            return ""

    @staticmethod
    def _auth_headers(token: str) -> dict[str, str]:
        """Build GitHub API headers for installation-token requests."""
        return {
            "Authorization": f"Bearer {token}",
            "Accept": GITHUB_V3_ACCEPT,
            "User-Agent": "CodeTrust-GitHub-App",
        }
