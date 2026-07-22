from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import ConnectionStatus
from app.models.network import ConnectionEvent, SocksEndpoint, VPNConnection
from app.services.connections import recover_interrupted_connections
from app.services.network import MockNetworkExecutor
from app.services.network.commands import NetworkOperation


def _interrupted_connection() -> VPNConnection:
    return VPNConnection(
        name="interrupted-exit",
        namespace="lxvpn-1",
        veth_host="lvh1",
        veth_namespace="lvn1",
        subnet_cidr="10.220.0.0/30",
        status=ConnectionStatus.RUNNING,
        exit_ip="198.51.100.10",
        pid=4321,
    )


def _active_endpoint(connection_id: int) -> SocksEndpoint:
    return SocksEndpoint(
        connection_id=connection_id,
        port=21000,
        username="recovery-user",
        encrypted_password="encrypted-not-a-credential",
        client_ip_allowlist=["203.0.113.0/24"],
        is_active=True,
    )


def test_application_startup_closes_unverified_mock_endpoints(
    app: FastAPI,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        connection = _interrupted_connection()
        db.add(connection)
        db.flush()
        db.add(_active_endpoint(connection.id))
        db.commit()
        connection_id = connection.id

    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200

    with factory() as db:
        recovered = db.get(VPNConnection, connection_id)
        assert recovered is not None
        assert recovered.status == ConnectionStatus.STOPPED
        assert recovered.exit_ip is None
        assert recovered.pid is None
        assert recovered.last_error == "startup_recovery"
        endpoint = db.scalar(
            select(SocksEndpoint).where(
                SocksEndpoint.connection_id == connection_id
            )
        )
        assert endpoint is not None
        assert endpoint.is_active is False
        event = db.scalar(
            select(ConnectionEvent).where(
                ConnectionEvent.connection_id == connection_id,
                ConnectionEvent.event_type == "connection_startup_recovery",
            )
        )
        assert event is not None
        assert event.details == {"simulated": True, "runtime_purged": False}

    executor = app.state.network_executor
    assert isinstance(executor, MockNetworkExecutor)
    assert executor.commands == []


def test_real_startup_recovery_uses_only_fixed_connection_purge(
    app: FastAPI,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        connection = _interrupted_connection()
        connection.name = "real-recovery-exit"
        connection.namespace = "lxvpn-2"
        connection.veth_host = "lvh2"
        connection.veth_namespace = "lvn2"
        connection.subnet_cidr = "10.220.0.4/30"
        db.add(connection)
        db.commit()
        connection_id = connection.id

    executor = MockNetworkExecutor()
    recovered = recover_interrupted_connections(
        factory,
        executor,
        enable_real_connections=True,
    )

    assert recovered == 1
    assert len(executor.commands) == 1
    assert executor.commands[0].operation is NetworkOperation.CONNECTION_PURGE
    assert executor.commands[0].arguments == (str(connection_id),)
