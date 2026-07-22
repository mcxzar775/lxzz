from typing import Any

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class SystemSetting(TimestampMixin, Base):
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    value: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_secret: Mapped[bool] = mapped_column(default=False, nullable=False)

