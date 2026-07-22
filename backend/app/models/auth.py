from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, utcnow
from app.models.enums import UserRole


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[UserRole] = mapped_column(
        String(32), default=UserRole.VIEWER, nullable=False, index=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(String(512))
    password_changed_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list["UserSession"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def totp_enabled(self) -> bool:
        return bool(self.totp_secret_encrypted)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_token_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    remember_me: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))

    user: Mapped[User] = relationship(back_populates="sessions")


class LoginAttempt(Base):
    __tablename__ = "login_attempts"
    __table_args__ = (
        Index("ix_login_attempt_principal_time", "username", "ip_address", "attempted_at"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), index=True)
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(String(64))
    attempted_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(96), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True, nullable=False)
