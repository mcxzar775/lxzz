from pathlib import Path

from alembic import command
from alembic.config import Config
from pytest import MonkeyPatch
from sqlalchemy import create_engine, inspect

from app.cli import init_db
from app.core.config import Settings


EXPECTED_TABLES = {
    "audit_logs",
    "blocked_nodes",
    "connection_events",
    "login_attempts",
    "node_scan_results",
    "scheduled_tasks",
    "service_checks",
    "socks_endpoints",
    "system_settings",
    "user_sessions",
    "users",
    "vpn_connections",
    "vpngate_nodes",
}

EXPECTED_NODE_INTELLIGENCE_COLUMNS = {
    "classified_exit_ip",
    "exit_country_code",
    "exit_country_name",
    "exit_city",
    "intelligence_source",
    "intelligence_checked_at",
    "network_classification_reasons",
}


def test_alembic_upgrade_and_downgrade(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"
    backend_dir = Path(__file__).resolve().parents[1]
    config = Config(str(backend_dir / "alembic.ini"))
    config.attributes["database_url"] = database_url
    command.upgrade(config, "head")
    engine = create_engine(database_url)
    assert EXPECTED_TABLES.issubset(set(inspect(engine).get_table_names()))
    node_columns = {
        column["name"] for column in inspect(engine).get_columns("vpngate_nodes")
    }
    assert EXPECTED_NODE_INTELLIGENCE_COLUMNS.issubset(node_columns)
    command.downgrade(config, "base")
    assert not EXPECTED_TABLES.intersection(inspect(engine).get_table_names())
    engine.dispose()


def test_cli_init_db_supports_relative_sqlite_url(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    settings = Settings(environment="test", database_url="sqlite:///./nested/app.db")
    init_db(settings)
    engine = create_engine(f"sqlite:///{tmp_path / 'nested' / 'app.db'}")
    assert EXPECTED_TABLES.issubset(set(inspect(engine).get_table_names()))
    engine.dispose()
