from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker
from typing import Any

from app.models.enums import NetworkType
from app.models.network import SocksEndpoint, VPNConnection, VPNGateNode
from app.services.network import MockNetworkExecutor
from conftest import UserCredentials, login
from vpngate_helpers import make_openvpn_config


def _acceptance_node(identifier: int, address: str) -> VPNGateNode:
    return VPNGateNode(
        id=identifier,
        config_hash=f"{identifier:064x}",
        host_name=f"acceptance-{identifier}",
        ip_address=address,
        score=10_000 - identifier,
        ping_ms=20 + identifier,
        speed_bps=5_000_000,
        country_long="United States",
        country_code="US",
        sessions=10,
        uptime_seconds=3_600,
        total_users=100,
        total_traffic_bytes=1_000_000,
        protocol="udp",
        remote_port=1194,
        sanitized_config=make_openvpn_config(address).decode("utf-8"),
        is_available=True,
        network_type=NetworkType.PUBLIC_VPN,
    )


def test_mock_end_to_end_acceptance_keeps_two_exits_isolated(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        db.add_all(
            [
                _acceptance_node(101, "198.51.100.101"),
                _acceptance_node(102, "198.51.100.102"),
            ]
        )
        db.commit()
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    created_connections: list[dict[str, Any]] = []
    for index, node_id in enumerate((101, 102), start=1):
        response = client.post(
            "/api/v1/connections",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": f"acceptance-exit-{index}",
                "node_id": node_id,
                "create_socks": True,
                "socks_username": f"acceptance{index}",
                "client_ip_allowlist": ["203.0.113.0/24"],
            },
        )
        assert response.status_code == 201, response.text
        created_connections.append(response.json()["connection"])

    first, second = created_connections
    assert first["namespace"] != second["namespace"]
    assert (first["namespace"], first["tun_device"]) != (
        second["namespace"],
        second["tun_device"],
    )
    assert first["socks_port"] != second["socks_port"]

    started: list[dict[str, Any]] = []
    for connection in created_connections:
        response = client.post(
            f"/api/v1/connections/{connection['id']}/start",
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["result"]["simulated"] is True
        assert body["connection"]["socks_active"] is True
        started.append(body["connection"])

    assert started[0]["exit_ip"] == "198.51.100.101"
    assert started[1]["exit_ip"] == "198.51.100.102"

    checks = client.post(
        f"/api/v1/connections/{first['id']}/check-unlock",
        headers={"X-CSRF-Token": csrf},
        json={"services": ["netflix", "chatgpt", "openai_api", "youtube"]},
    )
    assert checks.status_code == 200, checks.text
    assert {item["service_name"] for item in checks.json()["items"]} == {
        "netflix",
        "chatgpt",
        "openai_api",
        "youtube",
    }
    assert all(item["status"] == "UNKNOWN" for item in checks.json()["items"])

    stopped = client.post(
        f"/api/v1/connections/{first['id']}/stop",
        headers={"X-CSRF-Token": csrf},
    )
    assert stopped.status_code == 200, stopped.text
    listed = client.get("/api/v1/connections")
    assert listed.status_code == 200, listed.text
    by_id = {item["id"]: item for item in listed.json()["items"]}
    assert by_id[first["id"]]["status"] == "STOPPED"
    assert by_id[first["id"]]["socks_active"] is False
    assert by_id[second["id"]]["status"] == "RUNNING"
    assert by_id[second["id"]]["socks_active"] is True

    deleted = client.delete(
        f"/api/v1/connections/{first['id']}",
        headers={"X-CSRF-Token": csrf},
    )
    assert deleted.status_code == 204, deleted.text
    with factory() as db:
        assert db.get(VPNConnection, int(first["id"])) is None
        endpoint_count = db.scalar(
            select(func.count(SocksEndpoint.id)).where(
                SocksEndpoint.connection_id == int(first["id"])
            )
        )
        assert endpoint_count == 0

    executor = app.state.network_executor
    assert isinstance(executor, MockNetworkExecutor)
    assert executor.commands == []
