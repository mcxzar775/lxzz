from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from conftest import UserCredentials, login
from app.models.enums import ConnectionStatus
from app.models.network import ServiceCheck, VPNConnection
from app.services.network.namespace import allocate_namespace_plan


def test_viewer_can_load_minimal_dashboard(
    client: TestClient, test_users: UserCredentials
) -> None:
    login(client, test_users.viewer_username, test_users.viewer_password)
    response = client.get("/api/v1/dashboard")
    assert response.status_code == 200
    payload = response.json()
    assert payload["counts"] == {
        "total_nodes": 0,
        "available_nodes": 0,
        "online_vpns": 0,
        "online_socks": 0,
        "anomalies": 0,
        "residential_likely": 0,
        "netflix_full": 0,
        "chatgpt_available": 0,
    }
    assert payload["network_executor"] == "MockNetworkExecutor"
    assert 0 <= payload["system"]["memory_percent"] <= 100


def test_dashboard_counts_only_latest_service_result_per_connection(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        connections: list[VPNConnection] = []
        for connection_id in (1, 2):
            plan = allocate_namespace_plan(connection_id)
            connection = VPNConnection(
                name=f"exit-{connection_id}",
                namespace=plan.namespace,
                veth_host=plan.host_veth,
                veth_namespace=plan.namespace_veth,
                subnet_cidr=plan.subnet_cidr,
                status=ConnectionStatus.RUNNING,
            )
            db.add(connection)
            connections.append(connection)
        db.flush()
        db.add_all(
            [
                ServiceCheck(
                    connection_id=connections[0].id,
                    service_name="netflix",
                    status="FULL",
                ),
                ServiceCheck(
                    connection_id=connections[0].id,
                    service_name="netflix",
                    status="BLOCKED",
                ),
                ServiceCheck(
                    connection_id=connections[1].id,
                    service_name="netflix",
                    status="FULL",
                ),
                ServiceCheck(
                    connection_id=connections[0].id,
                    service_name="chatgpt",
                    status="UNLOCKED",
                ),
                ServiceCheck(
                    connection_id=connections[1].id,
                    service_name="chatgpt",
                    status="UNLOCKED",
                ),
                ServiceCheck(
                    connection_id=connections[1].id,
                    service_name="chatgpt",
                    status="UNSUPPORTED_REGION",
                ),
            ]
        )
        db.commit()

    login(client, test_users.viewer_username, test_users.viewer_password)
    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200
    assert response.json()["counts"]["netflix_full"] == 1
    assert response.json()["counts"]["chatgpt_available"] == 1
