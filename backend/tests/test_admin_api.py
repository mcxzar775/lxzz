from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import NetworkType
from app.models.network import VPNGateNode
from app.main import create_app
from conftest import UserCredentials, login
from vpngate_helpers import make_openvpn_config


def _node() -> VPNGateNode:
    return VPNGateNode(
        config_hash="a" * 64,
        host_name="node-1",
        ip_address="8.8.8.8",
        score=1000,
        ping_ms=25,
        speed_bps=1_000_000,
        country_long="United States",
        country_code="US",
        sessions=1,
        uptime_seconds=100,
        total_users=10,
        total_traffic_bytes=1000,
        protocol="udp",
        remote_port=1194,
        sanitized_config=make_openvpn_config().decode("utf-8"),
        is_available=True,
        network_type=NetworkType.PUBLIC_VPN,
    )


def test_super_admin_reads_logs_and_updates_non_secret_settings(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = login(client, test_users.super_username, test_users.super_password)

    initial = client.get("/api/v1/settings")
    updated = client.put(
        "/api/v1/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "node_refresh_minutes": 45,
            "scan_concurrency": 2,
            "socks_port_start": 22000,
            "socks_port_end": 22099,
            "namespace_dns_servers": ["1.1.1.1", "9.9.9.9"],
            "log_retention_days": 60,
            "health_check_interval_seconds": 90,
            "auto_switch_max_per_hour": 5,
        },
    )
    reread = client.get("/api/v1/settings")
    logs = client.get("/api/v1/logs?limit=50")

    assert initial.status_code == 200
    assert "ipinfo_api_token" not in initial.json()
    assert updated.status_code == 200, updated.text
    assert updated.json()["requires_restart"] is True
    assert reread.json()["node_refresh_minutes"] == 45
    assert reread.json()["socks_port_start"] == 22000
    assert logs.status_code == 200
    assert any(item["message"] == "settings.update" for item in logs.json()["items"])
    assert all("password" not in str(item).lower() for item in logs.json()["items"])

    restarted = create_app(app.state.settings)
    try:
        assert restarted.state.settings.scan_concurrency == 2
        assert restarted.state.settings.socks_port_start == 22000
        assert restarted.state.settings.socks_port_end == 22099
        assert restarted.state.settings.namespace_dns_servers == ("1.1.1.1", "9.9.9.9")
        assert restarted.state.settings.health_check_interval_seconds == 90
    finally:
        restarted.state.engine.dispose()


def test_admin_cannot_read_audit_logs_or_manage_system_settings(
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    logs = client.get("/api/v1/logs")
    settings = client.get("/api/v1/settings")
    update = client.put(
        "/api/v1/settings",
        headers={"X-CSRF-Token": csrf},
        json={
            "node_refresh_minutes": 30,
            "scan_concurrency": 3,
            "socks_port_start": 21000,
            "socks_port_end": 21999,
            "namespace_dns_servers": ["1.1.1.1"],
            "log_retention_days": 30,
            "health_check_interval_seconds": 60,
            "auto_switch_max_per_hour": 5,
        },
    )

    assert logs.status_code == 403
    assert settings.status_code == 403
    assert update.status_code == 403


def test_super_admin_reads_safe_runtime_diagnostics(
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    login(client, test_users.super_username, test_users.super_password)

    response = client.get("/api/v1/diagnostics")

    assert response.status_code == 200
    body = response.json()
    assert body["runtime_mode"] == "simulated"
    assert body["real_feature_gates"]["network"] is False
    assert body["checks"][0] == {
        "key": "database",
        "label": "Database",
        "status": "PASS",
        "detail": "reachable",
    }
    serialized = response.text.lower()
    assert "password" not in serialized
    assert "token" not in serialized
    assert "cookie" not in serialized


def test_admin_cannot_read_runtime_diagnostics(
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    login(client, test_users.admin_username, test_users.admin_password)

    assert client.get("/api/v1/diagnostics").status_code == 403


def test_node_blacklist_is_visible_and_reversible(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        node = _node()
        db.add(node)
        db.commit()
        db.refresh(node)
        node_id = node.id
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    blocked = client.post(
        f"/api/v1/nodes/{node_id}/block",
        headers={"X-CSRF-Token": csrf},
        json={"reason": "operator decision"},
    )
    listing = client.get("/api/v1/nodes")
    unblocked = client.delete(
        f"/api/v1/nodes/{node_id}/block",
        headers={"X-CSRF-Token": csrf},
    )
    relisted = client.get("/api/v1/nodes")

    assert blocked.status_code == 200, blocked.text
    assert listing.json()["items"][0]["is_blocked"] is True
    assert unblocked.status_code == 200
    assert relisted.json()["items"][0]["is_blocked"] is False
