from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select

from app.api.dependencies import AuthContext, CsrfAuth, DbSession, require_permission
from app.core.permissions import Permission
from app.models.auth import AuditLog, LoginAttempt, User
from app.models.network import ConnectionEvent, NodeScanResult
from app.models.settings import SystemSetting
from app.schemas.admin import (
    AdminLogList,
    AdminLogRead,
    AdminSettingsRead,
    AdminSettingsUpdate,
    LogSource,
)
from app.services.admin_settings import ADMIN_SETTINGS_KEY
from app.services.audit import record_audit


router = APIRouter(tags=["administration"])
AuditAuth = Annotated[AuthContext, Depends(require_permission(Permission.AUDIT_READ))]
SettingsAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.SETTINGS_MANAGE))
]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _count(db: DbSession, model: type) -> int:
    return int(db.scalar(select(func.count()).select_from(model)) or 0)


@router.get("/logs", response_model=AdminLogList)
def list_logs(
    _: AuditAuth,
    db: DbSession,
    source: Annotated[LogSource | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AdminLogList:
    fetch_limit = limit + offset
    entries: list[AdminLogRead] = []
    total = 0
    if source in {None, "audit"}:
        total += _count(db, AuditLog)
        users = {
            user.id: user.username
            for user in db.scalars(select(User)).all()
        }
        for audit_row in db.scalars(
            select(AuditLog).order_by(AuditLog.created_at.desc()).limit(fetch_limit)
        ).all():
            entries.append(
                AdminLogRead(
                    id=f"audit-{audit_row.id}",
                    source="audit",
                    category="AUDIT",
                    level="INFO" if audit_row.status == "success" else "ERROR",
                    message=audit_row.action,
                    actor=(
                        users.get(audit_row.user_id)
                        if audit_row.user_id is not None
                        else None
                    ),
                    target=(
                        f"{audit_row.target_type}:{audit_row.target_id}"
                        if audit_row.target_type and audit_row.target_id
                        else audit_row.target_type
                    ),
                    details=audit_row.details,
                    created_at=audit_row.created_at,
                )
            )
    if source in {None, "login"}:
        total += _count(db, LoginAttempt)
        for login_row in db.scalars(
            select(LoginAttempt)
            .order_by(LoginAttempt.attempted_at.desc())
            .limit(fetch_limit)
        ).all():
            entries.append(
                AdminLogRead(
                    id=f"login-{login_row.id}",
                    source="login",
                    category="LOGIN",
                    level="INFO" if login_row.success else "WARN",
                    message="login succeeded" if login_row.success else "login failed",
                    actor=login_row.username,
                    target=login_row.ip_address,
                    details={"failure_reason": login_row.failure_reason},
                    created_at=login_row.attempted_at,
                )
            )
    if source in {None, "connection"}:
        total += _count(db, ConnectionEvent)
        for connection_row in db.scalars(
            select(ConnectionEvent)
            .order_by(ConnectionEvent.created_at.desc())
            .limit(fetch_limit)
        ).all():
            entries.append(
                AdminLogRead(
                    id=f"connection-{connection_row.id}",
                    source="connection",
                    category=(
                        "SOCKS5" if "socks" in connection_row.event_type else "OPENVPN"
                    ),
                    level=(
                        "ERROR"
                        if connection_row.status in {"FAILED", "failure"}
                        else "INFO"
                    ),
                    message=connection_row.message or connection_row.event_type,
                    actor=None,
                    target=(
                        f"connection:{connection_row.connection_id}"
                        if connection_row.connection_id is not None
                        else None
                    ),
                    details=connection_row.details,
                    created_at=connection_row.created_at,
                )
            )
    if source in {None, "scan"}:
        total += _count(db, NodeScanResult)
        for scan_row in db.scalars(
            select(NodeScanResult)
            .order_by(NodeScanResult.created_at.desc())
            .limit(fetch_limit)
        ).all():
            entries.append(
                AdminLogRead(
                    id=f"scan-{scan_row.id}",
                    source="scan",
                    category="DETECTION",
                    level="INFO" if scan_row.status == "SUCCEEDED" else "WARN",
                    message=f"{scan_row.scan_type} scan {scan_row.status}",
                    actor=None,
                    target=f"node:{scan_row.node_id}",
                    details={
                        "error_code": scan_row.error_code,
                        "exit_ip": scan_row.exit_ip,
                        "simulated": scan_row.details.get("simulated") is True,
                    },
                    created_at=scan_row.created_at,
                )
            )
    entries.sort(key=lambda entry: entry.created_at, reverse=True)
    return AdminLogList(
        items=entries[offset : offset + limit],
        total=total,
        limit=limit,
        offset=offset,
    )


def _settings_values(request: Request, db: DbSession) -> dict[str, object]:
    configured = request.app.state.settings
    stored = db.scalar(select(SystemSetting).where(SystemSetting.key == ADMIN_SETTINGS_KEY))
    values: dict[str, object] = {
        "node_refresh_minutes": 30,
        "scan_concurrency": configured.scan_concurrency,
        "socks_port_start": configured.socks_port_start,
        "socks_port_end": configured.socks_port_end,
        "namespace_dns_servers": list(configured.namespace_dns_servers),
        "log_retention_days": 30,
        "health_check_interval_seconds": configured.health_check_interval_seconds,
        "auto_switch_max_per_hour": configured.auto_switch_max_per_hour,
    }
    if stored is not None:
        values.update(stored.value)
    return values


def _settings_read(request: Request, db: DbSession, *, restart: bool) -> AdminSettingsRead:
    values = _settings_values(request, db)
    token = request.app.state.settings.ipinfo_api_token
    return AdminSettingsRead(
        **values,
        ipinfo_api_token_configured=bool(token and token.get_secret_value()),
        requires_restart=restart,
    )


@router.get("/settings", response_model=AdminSettingsRead)
def get_settings(
    request: Request,
    _: SettingsAuth,
    db: DbSession,
) -> AdminSettingsRead:
    return _settings_read(request, db, restart=False)


@router.put("/settings", response_model=AdminSettingsRead)
def update_settings(
    request: Request,
    payload: AdminSettingsUpdate,
    auth: SettingsAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> AdminSettingsRead:
    del csrf
    stored = db.scalar(select(SystemSetting).where(SystemSetting.key == ADMIN_SETTINGS_KEY))
    if stored is None:
        stored = SystemSetting(key=ADMIN_SETTINGS_KEY, value={}, is_secret=False)
        db.add(stored)
    stored.value = payload.model_dump(mode="json")
    record_audit(
        db,
        action="settings.update",
        status="success",
        user_id=auth.user.id,
        target_type="system_settings",
        target_id=ADMIN_SETTINGS_KEY,
        ip_address=_client_ip(request),
        details={"keys": sorted(stored.value)},
    )
    db.commit()
    return _settings_read(request, db, restart=True)
