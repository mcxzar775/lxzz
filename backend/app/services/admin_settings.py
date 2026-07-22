from pydantic import ValidationError
from sqlalchemy import Engine, inspect, select

from app.core.config import Settings
from app.db.session import create_session_factory
from app.models.settings import SystemSetting


ADMIN_SETTINGS_KEY = "admin_ui"
RUNTIME_SETTING_FIELDS = frozenset(
    {
        "scan_concurrency",
        "socks_port_start",
        "socks_port_end",
        "namespace_dns_servers",
        "health_check_interval_seconds",
        "auto_switch_max_per_hour",
    }
)


def apply_stored_runtime_settings(settings: Settings, engine: Engine) -> Settings:
    """Apply only non-secret, explicitly allowlisted settings after a restart."""
    if not inspect(engine).has_table(SystemSetting.__tablename__):
        return settings
    factory = create_session_factory(engine)
    with factory() as db:
        stored = db.scalar(
            select(SystemSetting).where(SystemSetting.key == ADMIN_SETTINGS_KEY)
        )
    if stored is None or stored.is_secret:
        return settings
    overrides = {
        key: value
        for key, value in stored.value.items()
        if key in RUNTIME_SETTING_FIELDS
    }
    if not overrides:
        return settings
    try:
        return Settings.model_validate({**settings.model_dump(), **overrides})
    except ValidationError as exc:
        raise RuntimeError("stored non-secret runtime settings are invalid") from exc
