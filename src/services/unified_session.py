# Copyright (c) Said Borna. All rights reserved.
"""Unified session token service — cross-surface audit chain.

Issues session tokens that span IDE, CLI, CI, and API surfaces,
creating a single audit chain ID for traceability across all
governance actions in a session.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field

import structlog

logger = structlog.get_logger()

VALID_SURFACES: frozenset[str] = frozenset({"ide", "cli", "ci", "api"})
DEFAULT_TTL_MINUTES: int = 60
MAX_TTL_MINUTES: int = 1440
SECONDS_PER_MINUTE: int = 60


@dataclass(frozen=True)
class UnifiedSession:
    """Represents a cross-surface unified session."""

    session_token: str
    surfaces: list[str]
    issued_at: float
    expires_at: float
    agent_id: str
    workspace_id: str
    audit_chain_id: str


@dataclass
class UnifiedSessionStore:
    """In-memory store for unified session tokens.

    In production, this backs onto Redis or database storage.
    For the MCP gateway (single-process), in-memory is sufficient.
    """

    _sessions: dict[str, UnifiedSession] = field(default_factory=dict)

    def issue(
        self,
        *,
        surfaces: list[str],
        agent_id: str = "unknown",
        workspace_id: str = "",
        ttl_minutes: int = DEFAULT_TTL_MINUTES,
    ) -> UnifiedSession:
        """Issue a new unified session token.

        Args:
            surfaces: Which surfaces this token covers (ide, cli, ci, api).
            agent_id: Agent that requested the session.
            workspace_id: Workspace scope for this session.
            ttl_minutes: Token lifetime in minutes.

        Returns:
            A new UnifiedSession with generated token and audit chain ID.
        """
        validated_surfaces = sorted(
            s for s in surfaces if s in VALID_SURFACES
        )
        if not validated_surfaces:
            validated_surfaces = ["api"]

        ttl = min(max(ttl_minutes, 1), MAX_TTL_MINUTES)
        now = time.time()
        token = os.urandom(24).hex()
        chain_seed = f"{token}:{agent_id}:{workspace_id}:{now}"
        audit_chain_id = f"chain-{hashlib.sha256(chain_seed.encode()).hexdigest()[:16]}"

        session = UnifiedSession(
            session_token=token,
            surfaces=validated_surfaces,
            issued_at=now,
            expires_at=now + (ttl * SECONDS_PER_MINUTE),
            agent_id=agent_id,
            workspace_id=workspace_id,
            audit_chain_id=audit_chain_id,
        )

        self._sessions[token] = session
        self._prune_expired(now)

        logger.info(
            "unified_session_issued",
            token_prefix=token[:8],
            surfaces=validated_surfaces,
            agent_id=agent_id,
            workspace_id=workspace_id,
            audit_chain_id=audit_chain_id,
            ttl_minutes=ttl,
        )
        return session

    def validate(self, token: str) -> UnifiedSession | None:
        """Validate a session token and return the session if valid.

        Args:
            token: The session token to validate.

        Returns:
            The UnifiedSession if valid and not expired, None otherwise.
        """
        if not token:
            return None

        now = time.time()
        self._prune_expired(now)

        session = self._sessions.get(token)
        if session is None:
            return None

        if session.expires_at <= now:
            self._sessions.pop(token, None)
            return None

        return session

    def revoke(self, token: str) -> bool:
        """Revoke a session token.

        Args:
            token: The session token to revoke.

        Returns:
            True if the token was found and revoked, False otherwise.
        """
        removed = self._sessions.pop(token, None)
        if removed is not None:
            logger.info(
                "unified_session_revoked",
                token_prefix=token[:8],
                audit_chain_id=removed.audit_chain_id,
            )
            return True
        return False

    def list_active(self) -> list[UnifiedSession]:
        """List all active (non-expired) sessions.

        Returns:
            List of active UnifiedSession objects.
        """
        now = time.time()
        self._prune_expired(now)
        return list(self._sessions.values())

    def _prune_expired(self, now: float) -> None:
        """Remove expired sessions from the store."""
        expired_tokens = [
            tok for tok, sess in self._sessions.items()
            if sess.expires_at <= now
        ]
        for tok in expired_tokens:
            self._sessions.pop(tok, None)
