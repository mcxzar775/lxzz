from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import desc, select, update
from sqlalchemy.orm import Session

from app.api.dependencies import AppSettings, CsrfAuth, CurrentAuth, DbSession
from app.core.permissions import permissions_for
from app.core.security import (
    hash_password,
    hash_token,
    new_token,
    normalize_username,
    password_needs_rehash,
    verify_password,
)
from app.db.base import utcnow
from app.models.auth import LoginAttempt, User, UserSession
from app.schemas.auth import AuthResponse, ChangePasswordRequest, LoginRequest, UserRead
from app.services.audit import record_audit


router = APIRouter(prefix="/auth", tags=["authentication"])


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _recent_failed_attempts(
    db: Session,
    *,
    username: str,
    ip_address: str,
    lock_minutes: int,
) -> int:
    cutoff = utcnow() - timedelta(minutes=lock_minutes)
    attempts = db.scalars(
        select(LoginAttempt)
        .where(
            LoginAttempt.username == username,
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.attempted_at >= cutoff,
        )
        .order_by(desc(LoginAttempt.attempted_at), desc(LoginAttempt.id))
    ).all()
    failures = 0
    for attempt in attempts:
        if attempt.success:
            break
        failures += 1
    return failures


def _auth_response(user: User) -> AuthResponse:
    return AuthResponse(
        user=UserRead.model_validate(user),
        permissions=sorted(item.value for item in permissions_for(user.role)),
    )


@router.post("/login", response_model=AuthResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    settings: AppSettings,
    db: DbSession,
) -> AuthResponse:
    candidate = payload.username.strip().lower()[:64]
    try:
        username = normalize_username(payload.username)
    except ValueError:
        username = candidate
    ip_address = _client_ip(request)
    if _recent_failed_attempts(
        db,
        username=username,
        ip_address=ip_address,
        lock_minutes=settings.login_lock_minutes,
    ) >= settings.login_max_attempts:
        record_audit(
            db,
            action="auth.login",
            status="locked",
            ip_address=ip_address,
            details={"username": username},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Try again later.",
        )

    user = db.scalar(select(User).where(User.username == username))
    if (
        user is None
        or not user.is_active
        or not verify_password(payload.password, user.password_hash)
    ):
        db.add(
            LoginAttempt(
                username=username,
                ip_address=ip_address,
                success=False,
                failure_reason="invalid_credentials",
            )
        )
        record_audit(
            db,
            action="auth.login",
            status="failed",
            user_id=user.id if user else None,
            ip_address=ip_address,
            details={"username": username, "reason": "invalid_credentials"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    now = utcnow()
    user.last_login_at = now
    db.add(
        LoginAttempt(username=username, ip_address=ip_address, success=True)
    )
    session_token = new_token()
    csrf_token = new_token()
    lifetime = (
        timedelta(days=settings.remember_session_days)
        if payload.remember_me
        else timedelta(minutes=settings.session_minutes)
    )
    db.add(
        UserSession(
            user_id=user.id,
            token_hash=hash_token(session_token),
            csrf_token_hash=hash_token(csrf_token),
            expires_at=now + lifetime,
            remember_me=payload.remember_me,
            ip_address=ip_address,
            user_agent=request.headers.get("user-agent", "")[:512] or None,
        )
    )
    record_audit(
        db,
        action="auth.login",
        status="success",
        user_id=user.id,
        ip_address=ip_address,
    )
    db.commit()

    max_age = int(lifetime.total_seconds()) if payload.remember_me else None
    response.set_cookie(
        settings.session_cookie_name,
        session_token,
        max_age=max_age,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="lax",
        path="/",
    )
    return _auth_response(user)


@router.get("/me", response_model=AuthResponse)
def me(context: CurrentAuth) -> AuthResponse:
    return _auth_response(context.user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    context: CsrfAuth,
    settings: AppSettings,
    db: DbSession,
) -> None:
    context.session.revoked_at = utcnow()
    record_audit(
        db,
        action="auth.logout",
        status="success",
        user_id=context.user.id,
        ip_address=_client_ip(request),
    )
    db.commit()
    response.delete_cookie(settings.session_cookie_name, path="/")
    response.delete_cookie(settings.csrf_cookie_name, path="/")


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    context: CsrfAuth,
    db: DbSession,
) -> None:
    if not verify_password(payload.current_password, context.user.password_hash):
        record_audit(
            db,
            action="auth.password_change",
            status="failed",
            user_id=context.user.id,
            ip_address=_client_ip(request),
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )
    context.user.password_hash = hash_password(payload.new_password)
    context.user.password_changed_at = utcnow()
    db.execute(
        update(UserSession)
        .where(
            UserSession.user_id == context.user.id,
            UserSession.id != context.session.id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=utcnow())
    )
    record_audit(
        db,
        action="auth.password_change",
        status="success",
        user_id=context.user.id,
        ip_address=_client_ip(request),
    )
    db.commit()
