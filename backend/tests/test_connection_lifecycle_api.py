from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.auth import AuditLog
from app.models.enums import NetworkType
from app.models.network import BlockedNode, FavoriteNode, VPNGateNode
from app.services.network import MockNetworkExecutor
from conftest import UserCredentials, login
from vpngate_helpers import make_openvpn_config


def _node(identifier: int, ip_address: str, *, available: bool = True) -> VPNGateNode:
    return VPNGateNode(
        id=identifier,
        config_hash=f"{identifier:064x}",
        host_name=f"node-{identifier}",
        ip_address=ip_address,
        score=1000,
        ping_ms=25,
        speed_bps=2_000_000,
        country_long="United States",
        country_code="US",
        sessions=1,
        uptime_seconds=100,
        total_users=10,
        total_traffic_bytes=1000,
        protocol="udp",
        remote_port=1194,
        sanitized_config=make_openvpn_config(ip_address).decode("utf-8"),
        is_available=available,
        network_type=NetworkType.PUBLIC_VPN,
    )


def test_connection_lifecycle_api_is_fully_simulated(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        db.add_all([_node(1, "8.8.8.8"), _node(2, "1.1.1.1")])
        db.commit()
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    created = client.post(
        "/api/v1/connections",
        headers={"X-CSRF-Token": csrf},
        json={
            "name": "primary-exit",
            "node_id": 1,
            "create_socks": True,
            "socks_username": "operator1",
            "client_ip_allowlist": ["203.0.113.10/32"],
        },
    )

    assert created.status_code == 201, created.text
    payload = created.json()
    connection_id = payload["connection"]["id"]
    first_password = payload["one_time_socks_password"]
    assert isinstance(first_password, str) and len(first_password) >= 20
    assert payload["connection"]["status"] == "STOPPED"
    assert payload["connection"]["socks_port"] == 21000

    started = client.post(
        f"/api/v1/connections/{connection_id}/start",
        headers={"X-CSRF-Token": csrf},
    )
    assert started.status_code == 200, started.text
    assert started.json()["connection"]["status"] == "RUNNING"
    assert started.json()["connection"]["socks_active"] is True
    assert started.json()["result"]["simulated"] is True

    restarted = client.post(
        f"/api/v1/connections/{connection_id}/restart",
        headers={"X-CSRF-Token": csrf},
    )
    assert restarted.status_code == 200, restarted.text
    assert restarted.json()["connection"]["status"] == "RUNNING"

    stopped = client.post(
        f"/api/v1/connections/{connection_id}/stop",
        headers={"X-CSRF-Token": csrf},
    )
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["connection"]["status"] == "STOPPED"
    assert stopped.json()["connection"]["socks_active"] is False

    rotated = client.post(
        f"/api/v1/connections/{connection_id}/rotate-password",
        headers={"X-CSRF-Token": csrf},
    )
    assert rotated.status_code == 200, rotated.text
    second_password = rotated.json()["one_time_socks_password"]
    assert second_password != first_password

    executor = app.state.network_executor
    assert isinstance(executor, MockNetworkExecutor)
    assert executor.commands == []
    with factory() as db:
        audit_payload = str(
            list(db.scalars(select(AuditLog).order_by(AuditLog.id)).all())
        )
        audit_details = str(
            [entry.details for entry in db.scalars(select(AuditLog)).all()]
        )
        assert first_password not in audit_payload
        assert second_password not in audit_payload
        assert first_password not in audit_details
        assert second_password not in audit_details

    deleted = client.delete(
        f"/api/v1/connections/{connection_id}",
        headers={"X-CSRF-Token": csrf},
    )
    assert deleted.status_code == 204


def test_connection_create_rejects_unavailable_or_blocked_node(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        unavailable = _node(1, "8.8.8.8", available=False)
        blocked = _node(2, "1.1.1.1")
        db.add_all([unavailable, blocked])
        db.flush()
        db.add(
            BlockedNode(
                node_id=blocked.id,
                config_hash=blocked.config_hash,
                reason="operator block",
            )
        )
        db.commit()
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    unavailable_response = client.post(
        "/api/v1/connections",
        headers={"X-CSRF-Token": csrf},
        json={"name": "unavailable-node", "node_id": 1},
    )
    blocked_response = client.post(
        "/api/v1/connections",
        headers={"X-CSRF-Token": csrf},
        json={"name": "blocked-node", "node_id": 2},
    )

    assert unavailable_response.status_code == 409
    assert blocked_response.status_code == 409


def test_connection_create_and_update_routing_policy(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        node = _node(1, "8.8.8.8")
        db.add(node)
        db.flush()
        db.add(FavoriteNode(node_id=node.id))
        db.commit()
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    created = client.post(
        "/api/v1/connections",
        headers={"X-CSRF-Token": csrf},
        json={
            "name": "favorite-exit",
            "node_id": 1,
            "routing_mode": "FAVORITES",
            "create_socks": False,
        },
    )

    assert created.status_code == 201, created.text
    connection = created.json()["connection"]
    assert connection["routing_mode"] == "FAVORITES"
    assert connection["preferred_country_code"] is None

    updated = client.put(
        f"/api/v1/connections/{connection['id']}/routing",
        headers={"X-CSRF-Token": csrf},
        json={
            "routing_mode": "FIXED_COUNTRY",
            "preferred_country_code": "us",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["routing_mode"] == "FIXED_COUNTRY"
    assert updated.json()["preferred_country_code"] == "US"

    mismatched = client.put(
        f"/api/v1/connections/{connection['id']}/routing",
        headers={"X-CSRF-Token": csrf},
        json={
            "routing_mode": "FIXED_COUNTRY",
            "preferred_country_code": "JP",
        },
    )
    assert mismatched.status_code == 409


def test_connection_mutations_require_manage_permission_and_csrf(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        db.add(_node(1, "8.8.8.8"))
        db.commit()
    admin_csrf = login(client, test_users.admin_username, test_users.admin_password)
    del admin_csrf

    missing_csrf = client.post(
        "/api/v1/connections",
        json={"name": "missing-csrf", "node_id": 1},
    )
    viewer_csrf = login(
        client,
        test_users.viewer_username,
        test_users.viewer_password,
    )
    forbidden = client.post(
        "/api/v1/connections",
        headers={"X-CSRF-Token": viewer_csrf},
        json={"name": "viewer-denied", "node_id": 1},
    )

    assert missing_csrf.status_code == 403
    assert forbidden.status_code == 403
