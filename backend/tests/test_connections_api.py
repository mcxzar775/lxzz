from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import ConnectionStatus
from app.models.network import VPNConnection
from app.services.network.namespace import allocate_namespace_plan
from conftest import UserCredentials, login


def _create_connection(app: FastAPI, *, status: ConnectionStatus) -> VPNConnection:
    plan = allocate_namespace_plan(1)
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        connection = VPNConnection(
            name="test-exit",
            namespace=plan.namespace,
            veth_host=plan.host_veth,
            veth_namespace=plan.namespace_veth,
            subnet_cidr=plan.subnet_cidr,
            status=status,
        )
        db.add(connection)
        db.commit()
        db.refresh(connection)
        db.expunge(connection)
        return connection


def test_admin_runs_simulated_unlock_checks_and_viewer_reads_history(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    connection = _create_connection(app, status=ConnectionStatus.RUNNING)
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    checked = client.post(
        f"/api/v1/connections/{connection.id}/check-unlock",
        headers={"X-CSRF-Token": csrf},
        json={"services": ["netflix", "chatgpt", "openai_api", "youtube"]},
    )

    assert checked.status_code == 200, checked.text
    items = checked.json()["items"]
    assert len(items) == 4
    assert all(item["status"] == "UNKNOWN" for item in items)
    assert all(item["details"]["simulated"] is True for item in items)

    login(client, test_users.viewer_username, test_users.viewer_password)
    listing = client.get("/api/v1/connections?status=RUNNING")
    history = client.get(
        f"/api/v1/connections/{connection.id}/checks?service=netflix"
    )
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["items"][0]["service_name"] == "netflix"


def test_unlock_checks_require_running_connection_csrf_and_manage_permission(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    connection = _create_connection(app, status=ConnectionStatus.STOPPED)
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    stopped = client.post(
        f"/api/v1/connections/{connection.id}/check-unlock",
        headers={"X-CSRF-Token": csrf},
        json={},
    )
    missing_csrf = client.post(
        f"/api/v1/connections/{connection.id}/check-unlock",
        json={},
    )
    viewer_csrf = login(
        client,
        test_users.viewer_username,
        test_users.viewer_password,
    )
    forbidden = client.post(
        f"/api/v1/connections/{connection.id}/check-unlock",
        headers={"X-CSRF-Token": viewer_csrf},
        json={},
    )

    assert stopped.status_code == 409
    assert missing_csrf.status_code == 403
    assert forbidden.status_code == 403


def test_unlock_request_rejects_duplicates_and_unknown_services(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    connection = _create_connection(app, status=ConnectionStatus.RUNNING)
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    duplicate = client.post(
        f"/api/v1/connections/{connection.id}/check-unlock",
        headers={"X-CSRF-Token": csrf},
        json={"services": ["netflix", "netflix"]},
    )
    unknown = client.post(
        f"/api/v1/connections/{connection.id}/check-unlock",
        headers={"X-CSRF-Token": csrf},
        json={"services": ["arbitrary"]},
    )

    assert duplicate.status_code == 422
    assert unknown.status_code == 422
