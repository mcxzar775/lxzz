from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import UserRole


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    remember_me: bool = False


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    role: UserRole
    is_active: bool
    totp_enabled: bool
    created_at: datetime
    last_login_at: datetime | None


class AuthResponse(BaseModel):
    user: UserRead
    permissions: list[str]


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)
