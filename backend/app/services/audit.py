from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import redact
from app.models.auth import AuditLog


def record_audit(
    db: Session,
    *,
    action: str,
    status: str,
    user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    safe_details = redact(details or {})
    if not isinstance(safe_details, dict):
        safe_details = {}
    entry = AuditLog(
        action=action,
        status=status,
        user_id=user_id,
        target_type=target_type,
        target_id=target_id,
        ip_address=ip_address,
        details=safe_details,
    )
    db.add(entry)
    return entry

