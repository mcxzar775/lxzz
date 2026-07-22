from pydantic import BaseModel, Field, model_validator

from app.models.enums import UserRole
from app.schemas.auth import UserRead


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    role: UserRole | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def require_change(self) -> "UserUpdate":
        if self.role is None and self.is_active is None:
            raise ValueError("at least one user field must be changed")
        return self


class UserPasswordReset(BaseModel):
    new_password: str = Field(min_length=12, max_length=1024)


class UserList(BaseModel):
    items: list[UserRead]
    total: int
