from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, update

from app.api.dependencies import AuthContext, CsrfAuth, DbSession, require_permission
from app.core.permissions import Permission
from app.core.security import hash_password, normalize_username
from app.db.base import utcnow
from app.models.auth import User, UserSession
from app.models.enums import UserRole
from app.schemas.auth import UserRead
from app.schemas.users import UserCreate, UserList, UserPasswordReset, UserUpdate
from app.services.audit import record_audit


router = APIRouter(prefix="/users", tags=["users"])
ManageUsersAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.USERS_MANAGE))
]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _active_super_admins(db: DbSession) -> int:
    return int(
        db.scalar(
            select(func.count(User.id)).where(
                User.role == UserRole.SUPER_ADMIN,
                User.is_active.is_(True),
            )
        )
        or 0
    )


def _protect_last_super_admin(
    db: DbSession,
    user: User,
    *,
    next_role: UserRole | None = None,
    next_active: bool | None = None,
) -> None:
    will_be_super = (next_role or user.role) == UserRole.SUPER_ADMIN
    will_be_active = user.is_active if next_active is None else next_active
    if (
        user.role == UserRole.SUPER_ADMIN
        and user.is_active
        and (not will_be_super or not will_be_active)
        and _active_super_admins(db) <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The last active super administrator cannot be removed",
        )


@router.get("", response_model=UserList)
def list_users(
    _: ManageUsersAuth,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> UserList:
    total = int(db.scalar(select(func.count(User.id))) or 0)
    users = db.scalars(select(User).order_by(User.id).limit(limit).offset(offset)).all()
    return UserList(items=[UserRead.model_validate(item) for item in users], total=total)


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    _: ManageUsersAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> UserRead:
    del csrf
    try:
        username = normalize_username(payload.username)
        password_hash = hash_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = User(username=username, password_hash=password_hash, role=payload.role)
    db.add(user)
    db.flush()
    record_audit(
        db,
        action="user.create",
        status="success",
        user_id=_.user.id,
        target_type="user",
        target_id=str(user.id),
        ip_address=_client_ip(request),
        details={"username": username, "role": payload.role.value},
    )
    db.commit()
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    _: ManageUsersAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> UserRead:
    del csrf
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    _protect_last_super_admin(
        db,
        user,
        next_role=payload.role,
        next_active=payload.is_active,
    )
    if payload.role is not None:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
        if not payload.is_active:
            db.execute(
                update(UserSession)
                .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
                .values(revoked_at=utcnow())
            )
    record_audit(
        db,
        action="user.update",
        status="success",
        user_id=_.user.id,
        target_type="user",
        target_id=str(user.id),
        ip_address=_client_ip(request),
        details={
            "role": payload.role.value if payload.role else None,
            "is_active": payload.is_active,
        },
    )
    db.commit()
    return UserRead.model_validate(user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def deactivate_user(
    user_id: int,
    request: Request,
    _: ManageUsersAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> None:
    del csrf
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    _protect_last_super_admin(db, user, next_active=False)
    user.is_active = False
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    record_audit(
        db,
        action="user.deactivate",
        status="success",
        user_id=_.user.id,
        target_type="user",
        target_id=str(user.id),
        ip_address=_client_ip(request),
    )
    db.commit()


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def reset_user_password(
    user_id: int,
    payload: UserPasswordReset,
    request: Request,
    auth: ManageUsersAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> None:
    del csrf
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    try:
        user.password_hash = hash_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    user.password_changed_at = utcnow()
    db.execute(
        update(UserSession)
        .where(UserSession.user_id == user.id, UserSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    record_audit(
        db,
        action="user.password_reset",
        status="success",
        user_id=auth.user.id,
        target_type="user",
        target_id=str(user.id),
        ip_address=_client_ip(request),
        details={"sessions_revoked": True},
    )
    db.commit()
