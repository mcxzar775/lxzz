from dataclasses import dataclass
from datetime import timezone
from typing import Annotated, Callable

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.permissions import Permission, has_permission
from app.core.security import constant_time_token_matches, hash_token
from app.db.base import utcnow
from app.db.session import get_db
from app.models.auth import User, UserSession


DbSession = Annotated[Session, Depends(get_db)]


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: UserSession


def get_app_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


AppSettings = Annotated[Settings, Depends(get_app_settings)]


def _is_expired(session: UserSession) -> bool:
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return expires_at <= utcnow()


def get_auth_context(
    request: Request,
    settings: AppSettings,
    db: DbSession,
) -> AuthContext:
    session_token = request.cookies.get(settings.session_cookie_name)
    if not session_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user_session = db.scalar(
        select(UserSession).where(UserSession.token_hash == hash_token(session_token))
    )
    if user_session is None or user_session.revoked_at is not None or _is_expired(user_session):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    user = db.get(User, user_session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    return AuthContext(user=user, session=user_session)


CurrentAuth = Annotated[AuthContext, Depends(get_auth_context)]


def require_permission(permission: Permission) -> Callable[[CurrentAuth], AuthContext]:
    def dependency(context: CurrentAuth) -> AuthContext:
        if not has_permission(context.user.role, permission):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permission denied")
        return context

    return dependency


def require_csrf(
    context: CurrentAuth,
    csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
) -> AuthContext:
    if not csrf_token or not constant_time_token_matches(
        csrf_token, context.session.csrf_token_hash
    ):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")
    return context


CsrfAuth = Annotated[AuthContext, Depends(require_csrf)]
