"""GDPR data export and deletion service.

Implements the following GDPR rights:
  - Right of Access (Art. 15): Export all personal data
  - Right to Erasure (Art. 17): Delete all personal data
  - Right to Data Portability (Art. 20): Machine-readable export (JSON)

Usage:
    gdpr = GDPRService(database_service)
    data = await gdpr.export_user_data(user_id)
    await gdpr.delete_user_data(user_id)
"""

from __future__ import annotations

import datetime
from typing import Any

import structlog
from sqlalchemy import delete, select

from src.models.database import ApiKeyRecord, ScanLog, UsageDay, User

logger = structlog.get_logger()


class GDPRService:
    """GDPR compliance service for user data operations."""

    def __init__(self, db_service: Any) -> None:
        """Initialize with a DatabaseService instance.

        Args:
            db_service: DatabaseService instance with _session_factory.
        """
        self._db = db_service

    async def export_user_data(self, user_id: str) -> dict[str, Any]:
        """Export all personal data for a user (GDPR Art. 15 + Art. 20).

        Returns a JSON-serializable dict containing:
        - User profile information
        - API keys (metadata only, not hashes)
        - Scan history
        - Usage statistics

        Args:
            user_id: The user's database ID.

        Returns:
            Dict with all user data, or empty dict if user not found.
        """
        async with self._db._session_factory() as session:
            # Fetch user
            user = await session.get(User, user_id)
            if user is None:
                logger.warning("gdpr_export_user_not_found", user_id=user_id)
                return {}

            # Fetch API keys
            keys_stmt = (
                select(ApiKeyRecord)
                .where(ApiKeyRecord.user_id == user_id)
                .order_by(ApiKeyRecord.created_at.desc())
            )
            keys_result = await session.execute(keys_stmt)
            api_keys = list(keys_result.scalars().all())

            # Fetch scan logs
            scans_stmt = (
                select(ScanLog)
                .where(ScanLog.user_id == user_id)
                .order_by(ScanLog.created_at.desc())
            )
            scans_result = await session.execute(scans_stmt)
            scan_logs = list(scans_result.scalars().all())

            # Fetch usage days
            usage_stmt = (
                select(UsageDay)
                .where(UsageDay.user_id == user_id)
                .order_by(UsageDay.date.desc())
            )
            usage_result = await session.execute(usage_stmt)
            usage_days = list(usage_result.scalars().all())

        export = {
            "export_metadata": {
                "exported_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "user_id": user_id,
                "format_version": "1.0",
                "gdpr_articles": ["Art. 15 — Right of Access", "Art. 20 — Data Portability"],
            },
            "profile": {
                "id": user.id,
                "github_id": user.github_id,
                "email": user.email,
                "name": user.name,
                "avatar_url": user.avatar_url,
                "plan": user.plan,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            },
            "api_keys": [
                {
                    "id": k.id,
                    "name": k.name,
                    "prefix": k.prefix,
                    "is_revoked": k.is_revoked,
                    "created_at": k.created_at.isoformat() if k.created_at else None,
                    "revoked_at": k.revoked_at.isoformat() if k.revoked_at else None,
                    "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                }
                for k in api_keys
            ],
            "scan_history": [
                {
                    "id": s.id,
                    "scan_type": s.scan_type,
                    "verdict": s.verdict,
                    "findings_count": s.findings_count,
                    "language": s.language,
                    "filename": s.filename,
                    "latency_ms": s.latency_ms,
                    "input_size": s.input_size,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
                for s in scan_logs
            ],
            "usage_statistics": [
                {
                    "date": d.date.isoformat(),
                    "scan_count": d.scan_count,
                    "findings_total": d.findings_total,
                    "avg_latency_ms": d.avg_latency_ms,
                }
                for d in usage_days
            ],
            "data_categories": {
                "profile_data": "GitHub ID, email, name, avatar URL",
                "authentication_data": "API key metadata (names, prefixes, timestamps)",
                "usage_data": "Scan history, daily aggregates, latency metrics",
                "content_data": "None — scanned code is NOT stored after processing",
            },
        }

        logger.info(
            "gdpr_data_exported",
            user_id=user_id,
            keys=len(api_keys),
            scans=len(scan_logs),
            usage_days=len(usage_days),
        )
        return export

    async def delete_user_data(self, user_id: str) -> dict[str, Any]:
        """Delete all personal data for a user (GDPR Art. 17 — Right to Erasure).

        Cascades deletion through:
        1. Usage statistics
        2. Scan logs
        3. API keys
        4. User profile

        Args:
            user_id: The user's database ID.

        Returns:
            Dict with deletion summary (counts of deleted records).
        """
        async with self._db._session_factory() as session:
            # Check user exists
            user = await session.get(User, user_id)
            if user is None:
                logger.warning("gdpr_delete_user_not_found", user_id=user_id)
                return {"deleted": False, "reason": "user_not_found"}

            # Count records before deletion
            usage_count = (
                await session.execute(
                    select(UsageDay).where(UsageDay.user_id == user_id)
                )
            ).scalars().all()
            scan_count = (
                await session.execute(
                    select(ScanLog).where(ScanLog.user_id == user_id)
                )
            ).scalars().all()
            key_count = (
                await session.execute(
                    select(ApiKeyRecord).where(ApiKeyRecord.user_id == user_id)
                )
            ).scalars().all()

            counts = {
                "usage_days": len(usage_count),
                "scan_logs": len(scan_count),
                "api_keys": len(key_count),
            }

            # Delete in order (FK constraints)
            await session.execute(
                delete(UsageDay).where(UsageDay.user_id == user_id)
            )
            await session.execute(
                delete(ScanLog).where(ScanLog.user_id == user_id)
            )
            await session.execute(
                delete(ApiKeyRecord).where(ApiKeyRecord.user_id == user_id)
            )
            await session.execute(
                delete(User).where(User.id == user_id)
            )

            await session.commit()

        logger.info(
            "gdpr_data_deleted",
            user_id=user_id,
            **counts,
        )

        return {
            "deleted": True,
            "user_id": user_id,
            "deleted_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "records_deleted": counts,
            "gdpr_article": "Art. 17 — Right to Erasure",
        }

    async def anonymize_audit_entries(
        self, user_id: str, audit_path: str = "",
    ) -> int:
        """Anonymize audit log entries for a deleted user.

        Replaces user identifiers with 'REDACTED' in the audit log.
        This preserves the audit trail for compliance while removing PII.

        Args:
            user_id: The user ID to anonymize.
            audit_path: Path to audit.jsonl file.

        Returns:
            Number of entries anonymized.
        """
        import json
        from pathlib import Path

        if not audit_path:
            audit_path = str(Path.cwd() / ".codetrust" / "audit.jsonl")

        path = Path(audit_path)
        if not path.exists():
            return 0

        lines = path.read_text().strip().split("\n")
        count = 0
        new_lines = []

        for line in lines:
            if not line.strip():
                new_lines.append(line)
                continue
            try:
                entry = json.loads(line)
                if entry.get("agent_id") == user_id or entry.get("user_id") == user_id:
                    entry["agent_id"] = "REDACTED"
                    if "user_id" in entry:
                        entry["user_id"] = "REDACTED"
                    count += 1
                new_lines.append(json.dumps(entry))
            except json.JSONDecodeError:
                new_lines.append(line)

        path.write_text("\n".join(new_lines) + "\n")

        logger.info("gdpr_audit_anonymized", user_id=user_id, entries=count)
        return count
