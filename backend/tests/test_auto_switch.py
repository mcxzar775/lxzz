import asyncio
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import utcnow
from app.models.enums import ConnectionStatus, NetworkType, RoutingMode
from app.models.network import (
    BlockedNode,
    ConnectionEvent,
    FavoriteNode,
    SocksEndpoint,
    VPNConnection,
    VPNGateNode,
)
from app.services.auto_switch import (
    AutoSwitchOperationError,
    ConnectionRuntimeDriver,
    ConnectionSwitchService,
    HealthObservation,
    HealthPolicy,
    MockConnectionRuntimeDriver,
    RealConnectionRuntimeDriver,
    SwitchExecution,
    SwitchMode,
    SwitchStatus,
    SwitchTrigger,
    select_candidate_node,
)
from app.services.ip_intelligence import (
    IPClassificationSummary,
    NodeIntelligenceEnricher,
)
from app.services.network import MockNetworkExecutor
from app.services.network.killswitch import (
    KillSwitchManager,
    KillSwitchPlan,
    KillSwitchRuntime,
    build_killswitch_plan,
)
from app.services.network.namespace import allocate_namespace_plan
from app.services.network.openvpn_manager import (
    OpenVPNManager,
    OpenVPNOperationError,
    OpenVPNRuntime,
)
from app.services.network.socks5 import (
    Socks5Runtime,
    SocksEndpointService,
)
from app.services.scanning.probe import ExitProbeResult, NamespaceExitProbe
from app.services.unlock import (
    UnlockCheckCoordinator,
    UnlockCheckResult,
    UnlockServiceName,
)
from conftest import UserCredentials, login
from vpngate_helpers import make_openvpn_config


def _node(
    identifier: int,
    ip_address: str,
    *,
    ping_ms: int = 30,
    speed_bps: int = 2_000_000,
    score: int = 1000,
    available: bool = True,
    network_type: NetworkType = NetworkType.PUBLIC_VPN,
    country_code: str = "US",
) -> VPNGateNode:
    return VPNGateNode(
        id=identifier,
        config_hash=f"{identifier:064x}",
        host_name=f"node-{identifier}",
        ip_address=ip_address,
        score=score,
        ping_ms=ping_ms,
        speed_bps=speed_bps,
        country_long="United States",
        country_code=country_code,
        sessions=1,
        uptime_seconds=100,
        total_users=100,
        total_traffic_bytes=1000,
        protocol="udp",
        remote_port=1194,
        sanitized_config=make_openvpn_config(ip_address).decode("utf-8"),
        is_available=available,
        network_type=network_type,
    )


def _connection(node_id: int, *, identifier: int = 1) -> VPNConnection:
    plan = allocate_namespace_plan(identifier)
    return VPNConnection(
        id=identifier,
        name=f"connection-{identifier}",
        node_id=node_id,
        namespace=plan.namespace,
        veth_host=plan.host_veth,
        veth_namespace=plan.namespace_veth,
        subnet_cidr=plan.subnet_cidr,
        status=ConnectionStatus.RUNNING,
        exit_ip="8.8.8.8",
    )


def test_candidate_selection_honors_country_favorites_and_fixed_node_modes(
    app: FastAPI,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        current = _node(1, "8.8.8.8", country_code="US")
        fastest_jp = _node(2, "1.1.1.1", ping_ms=5, country_code="JP")
        favorite_jp = _node(3, "9.9.9.9", ping_ms=20, country_code="JP")
        db.add_all([current, fastest_jp, favorite_jp])
        db.flush()
        db.add(FavoriteNode(node_id=favorite_jp.id))

        country_connection = _connection(current.id, identifier=1)
        country_connection.routing_mode = RoutingMode.FIXED_COUNTRY
        country_connection.preferred_country_code = "JP"
        db.add(country_connection)
        db.flush()
        assert select_candidate_node(
            db, country_connection, HealthPolicy()
        ).id == fastest_jp.id

        favorite_connection = _connection(current.id, identifier=2)
        favorite_connection.routing_mode = RoutingMode.FAVORITES
        db.add(favorite_connection)
        db.flush()
        assert select_candidate_node(
            db, favorite_connection, HealthPolicy()
        ).id == favorite_jp.id

        fixed_connection = _connection(current.id, identifier=3)
        fixed_connection.routing_mode = RoutingMode.FIXED_NODE
        db.add(fixed_connection)
        db.flush()
        with pytest.raises(
            AutoSwitchOperationError,
            match="fixed_node_auto_switch_disabled",
        ):
            select_candidate_node(db, fixed_connection, HealthPolicy())


def test_candidate_selection_excludes_current_blocked_and_policy_mismatch(
    app: FastAPI,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        current = _node(1, "8.8.8.8", ping_ms=10)
        blocked = _node(2, "1.1.1.1", ping_ms=5)
        datacenter = _node(
            3,
            "9.9.9.9",
            ping_ms=8,
            network_type=NetworkType.DATACENTER,
        )
        eligible = _node(
            4,
            "4.2.2.2",
            ping_ms=20,
            network_type=NetworkType.RESIDENTIAL_LIKELY,
        )
        connection = _connection(current.id)
        db.add_all([current, blocked, datacenter, eligible])
        db.flush()
        db.add(connection)
        db.flush()
        db.add(
            BlockedNode(
                node_id=blocked.id,
                config_hash=blocked.config_hash,
                reason="test block",
            )
        )
        db.flush()

        selected = select_candidate_node(
            db,
            connection,
            HealthPolicy(
                allowed_network_types=frozenset(
                    {NetworkType.RESIDENTIAL_LIKELY}
                )
            ),
        )

        assert selected.id == eligible.id


def test_manual_switch_api_is_simulated_and_persists_safe_event(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        db.add_all(
            [_node(1, "8.8.8.8", ping_ms=50), _node(2, "1.1.1.1", ping_ms=20)]
        )
        db.flush()
        db.add(_connection(1))
        db.commit()
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    response = client.post(
        "/api/v1/connections/1/switch",
        headers={"X-CSRF-Token": csrf},
        json={},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["status"] == "SUCCEEDED"
    assert payload["candidate_node_id"] == 2
    assert payload["simulated"] is True
    assert payload["steps"] == [
        "KILLSWITCH_VERIFIED",
        "OPENVPN_STOPPED",
        "KILLSWITCH_UPDATED",
        "OPENVPN_STARTED",
        "EXIT_IP_VERIFIED",
        "NETWORK_TYPE_VERIFIED",
        "SERVICES_VERIFIED",
    ]
    executor = cast(MockNetworkExecutor, app.state.network_executor)
    assert executor.commands == []

    login(client, test_users.viewer_username, test_users.viewer_password)
    events = client.get("/api/v1/connections/1/events")
    assert events.status_code == 200
    assert events.json()["items"][0]["event_type"] == "manual_switch"
    assert "sanitized_config" not in str(events.json())


def test_health_check_api_is_simulated_and_requires_manage_permission(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        db.add(_node(1, "8.8.8.8"))
        db.flush()
        db.add(_connection(1))
        db.commit()
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    checked = client.post(
        "/api/v1/connections/1/health-check",
        headers={"X-CSRF-Token": csrf},
        json={},
    )

    assert checked.status_code == 200, checked.text
    assert checked.json()["healthy"] is True
    assert checked.json()["simulated"] is True
    assert checked.json()["auto_switch"] is None
    executor = cast(MockNetworkExecutor, app.state.network_executor)
    assert executor.commands == []

    viewer_csrf = login(
        client,
        test_users.viewer_username,
        test_users.viewer_password,
    )
    forbidden = client.post(
        "/api/v1/connections/1/health-check",
        headers={"X-CSRF-Token": viewer_csrf},
        json={},
    )
    assert forbidden.status_code == 403


def test_automatic_switch_limit_counts_attempts_in_the_last_hour(
    app: FastAPI,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    with factory() as db:
        connection = _connection(1)
        db.add_all([_node(1, "8.8.8.8"), _node(2, "1.1.1.1")])
        db.flush()
        db.add(connection)
        db.flush()
        db.add_all(
            [
                ConnectionEvent(
                    connection_id=connection.id,
                    event_type="auto_switch",
                    status="FAILED",
                    message="attempt",
                    details={},
                    created_at=utcnow(),
                )
                for _ in range(5)
            ]
        )
        db.flush()
        service = ConnectionSwitchService(
            MockConnectionRuntimeDriver(),
            max_auto_switches_per_hour=5,
        )

        with pytest.raises(AutoSwitchOperationError) as captured:
            asyncio.run(
                service.switch(
                    db,
                    connection,
                    HealthPolicy(),
                    mode=SwitchMode.AUTOMATIC,
                    trigger=SwitchTrigger.HEALTH_CHECK_FAILED,
                )
            )

        assert captured.value.code == "auto_switch_rate_limited"


class FailingHealthDriver:
    def __init__(self) -> None:
        self.switch_calls = 0

    async def health(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        policy: HealthPolicy,
    ) -> HealthObservation:
        del connection, node, policy
        return HealthObservation(
            healthy=False,
            trigger=SwitchTrigger.OPENVPN_DISCONNECTED,
            exit_ip=None,
            latency_ms=None,
            download_bps=None,
            network_type=NetworkType.UNKNOWN,
            failure_code="openvpn_disconnected",
            simulated=True,
        )

    async def switch(
        self,
        connection: VPNConnection,
        current_node: VPNGateNode,
        candidate: VPNGateNode,
        endpoint: SocksEndpoint | None,
        policy: HealthPolicy,
    ) -> SwitchExecution:
        del current_node, endpoint, policy
        self.switch_calls += 1
        return SwitchExecution(
            exit_ip=candidate.ip_address,
            latency_ms=float(candidate.ping_ms or 0),
            download_bps=candidate.speed_bps or 0,
            network_type=candidate.network_type,
            unlock_checks=(),
            steps=("KILLSWITCH_VERIFIED", "OPENVPN_STARTED"),
            socks_resumed=False,
            simulated=True,
        )


def test_consecutive_health_failures_trigger_automatic_switch(
    app: FastAPI,
) -> None:
    factory: sessionmaker[Session] = app.state.session_factory
    driver = FailingHealthDriver()
    service = ConnectionSwitchService(
        cast(ConnectionRuntimeDriver, driver),
        failure_threshold=3,
    )
    with factory() as db:
        connection = _connection(1)
        db.add_all([_node(1, "8.8.8.8"), _node(2, "1.1.1.1")])
        db.flush()
        db.add(connection)
        db.flush()

        outcomes = [
            asyncio.run(
                service.check_health(
                    db,
                    connection,
                    HealthPolicy(),
                    auto_switch=True,
                )
            )
            for _ in range(3)
        ]
        db.flush()

        assert outcomes[0].switch_outcome is None
        assert outcomes[1].switch_outcome is None
        assert outcomes[2].switch_outcome is not None
        assert outcomes[2].switch_outcome.status is SwitchStatus.SUCCEEDED
        assert connection.node_id == 2
        assert connection.consecutive_failures == 0
        assert connection.auto_switch_count == 1
        assert driver.switch_calls == 1
        assert db.scalar(
            select(func.count(ConnectionEvent.id)).where(
                ConnectionEvent.connection_id == connection.id
            )
        ) == 4


class RecordingKillSwitch:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def build_plan(
        self,
        connection_id: int,
        *,
        node_id: int,
        remote_address: str,
        remote_port: int,
        remote_protocol: str,
        socks_port: int | None,
        client_ip_allowlist: tuple[str, ...] = (),
    ) -> KillSwitchPlan:
        return build_killswitch_plan(
            connection_id,
            node_id=node_id,
            remote_address=remote_address,
            remote_port=remote_port,
            remote_protocol=remote_protocol,
            socks_port=socks_port,
            client_ip_allowlist=client_ip_allowlist,
        )

    def status(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        self.events.append(f"killswitch_status_{plan.node_id}")
        return KillSwitchRuntime(plan.connection_id, plan.namespace, True, "nftables")

    def apply(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        self.events.append(f"killswitch_apply_{plan.node_id}")
        return KillSwitchRuntime(plan.connection_id, plan.namespace, True, "nftables")


class RecordingOpenVPN:
    def __init__(self, events: list[str], *, start_fails: bool = False) -> None:
        self.events = events
        self.start_fails = start_fails

    def stop(self, connection_id: int, *, node_id: int) -> OpenVPNRuntime:
        self.events.append(f"openvpn_stop_{node_id}")
        return OpenVPNRuntime(connection_id, node_id, "lxvpn-1", "tun0", False, None)

    def stage_config(self, node_id: int, sanitized_config: str) -> object:
        assert sanitized_config
        self.events.append(f"stage_config_{node_id}")
        return object()

    def start(
        self,
        connection_id: int,
        *,
        node_id: int,
        sanitized_config: str,
    ) -> OpenVPNRuntime:
        assert sanitized_config
        self.events.append(f"openvpn_start_{node_id}")
        if self.start_fails:
            raise OpenVPNOperationError("openvpn_start_failed")
        return OpenVPNRuntime(connection_id, node_id, "lxvpn-1", "tun0", True, 1234)


class RecordingSocks:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def stop(self, endpoint: SocksEndpoint) -> Socks5Runtime:
        self.events.append("socks_stop")
        endpoint.is_active = False
        return Socks5Runtime(
            endpoint.connection_id,
            endpoint.id,
            "lxvpn-1",
            endpoint.port,
            False,
            None,
        )

    def start(self, endpoint: SocksEndpoint) -> Socks5Runtime:
        self.events.append("socks_start")
        endpoint.is_active = True
        return Socks5Runtime(
            endpoint.connection_id,
            endpoint.id,
            "lxvpn-1",
            endpoint.port,
            True,
            2345,
        )


class RecordingExitProbe:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def probe(self, resource_id: int) -> ExitProbeResult:
        assert resource_id == 1
        self.events.append("exit_probe")
        return ExitProbeResult("1.1.1.1", 25.0, 3_000_000, True, True)


class RecordingIntelligence:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def enrich_node(
        self,
        node: VPNGateNode,
        *,
        exit_ip: str,
    ) -> IPClassificationSummary:
        assert node.id == 2
        assert exit_ip == "1.1.1.1"
        self.events.append("intelligence")
        return IPClassificationSummary(
            source="test",
            network_type=NetworkType.PUBLIC_VPN,
            confidence=0.8,
            reasons=("vpngate_source",),
        )


class EmptyUnlockCoordinator:
    async def check(
        self,
        connection_id: int,
        services: tuple[UnlockServiceName, ...],
    ) -> list[UnlockCheckResult]:
        del connection_id, services
        return []


def _real_driver(events: list[str], *, start_fails: bool = False) -> RealConnectionRuntimeDriver:
    return RealConnectionRuntimeDriver(
        cast(KillSwitchManager, RecordingKillSwitch(events)),
        cast(OpenVPNManager, RecordingOpenVPN(events, start_fails=start_fails)),
        cast(SocksEndpointService, RecordingSocks(events)),
        cast(NamespaceExitProbe, RecordingExitProbe(events)),
        cast(NodeIntelligenceEnricher, RecordingIntelligence(events)),
        cast(UnlockCheckCoordinator, EmptyUnlockCoordinator()),
    )


def _active_endpoint() -> SocksEndpoint:
    return SocksEndpoint(
        id=1,
        connection_id=1,
        port=21000,
        username="tester",
        encrypted_password="encrypted",
        client_ip_allowlist=[],
        is_active=True,
    )


def test_real_driver_enforces_fail_closed_switch_order() -> None:
    events: list[str] = []
    execution = asyncio.run(
        _real_driver(events).switch(
            _connection(1),
            _node(1, "8.8.8.8"),
            _node(2, "1.1.1.1"),
            _active_endpoint(),
            HealthPolicy(),
        )
    )

    assert events == [
        "socks_stop",
        "killswitch_status_1",
        "openvpn_stop_1",
        "stage_config_2",
        "killswitch_apply_2",
        "openvpn_start_2",
        "exit_probe",
        "intelligence",
        "socks_start",
    ]
    assert execution.pid == 1234
    assert execution.socks_resumed is True
    assert "KILLSWITCH_UPDATED" in execution.steps


def test_real_driver_keeps_new_killswitch_when_new_openvpn_fails() -> None:
    events: list[str] = []

    with pytest.raises(AutoSwitchOperationError) as captured:
        asyncio.run(
            _real_driver(events, start_fails=True).switch(
                _connection(1),
                _node(1, "8.8.8.8"),
                _node(2, "1.1.1.1"),
                _active_endpoint(),
                HealthPolicy(),
            )
        )

    assert captured.value.code == "openvpn_start_failed"
    assert events == [
        "socks_stop",
        "killswitch_status_1",
        "openvpn_stop_1",
        "stage_config_2",
        "killswitch_apply_2",
        "openvpn_start_2",
        "openvpn_stop_2",
    ]
