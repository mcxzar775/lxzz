import asyncio
import os
from typing import Protocol

from app.models.enums import ConnectionStatus, NetworkType
from app.models.network import SocksEndpoint, VPNConnection, VPNGateNode
from app.services.auto_switch.types import (
    AutoSwitchOperationError,
    HealthObservation,
    HealthPolicy,
    SwitchExecution,
    SwitchTrigger,
    unlock_checks_satisfy_policy,
)
from app.services.ip_intelligence import NodeIntelligenceEnricher
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor
from app.services.network.killswitch import (
    KillSwitchManager,
    KillSwitchOperationError,
    KillSwitchPlan,
)
from app.services.network.openvpn_manager import (
    OpenVPNManager,
    OpenVPNOperationError,
)
from app.services.network.socks5 import (
    Socks5OperationError,
    SocksEndpointService,
)
from app.services.scanning.probe import ExitProbeError, NamespaceExitProbe
from app.services.unlock import (
    MockUnlockProbe,
    UnlockCheckCoordinator,
    UnlockCheckResult,
)


class ConnectionRuntimeDriver(Protocol):
    async def health(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        policy: HealthPolicy,
    ) -> HealthObservation: ...

    async def switch(
        self,
        connection: VPNConnection,
        current_node: VPNGateNode,
        candidate: VPNGateNode,
        endpoint: SocksEndpoint | None,
        policy: HealthPolicy,
    ) -> SwitchExecution: ...


def _policy_failure(
    *,
    exit_ip_changed: bool,
    latency_ms: float,
    download_bps: int,
    network_type: NetworkType,
    policy: HealthPolicy,
    unlock_ok: bool,
) -> tuple[SwitchTrigger, str] | None:
    if exit_ip_changed:
        return SwitchTrigger.EXIT_IP_CHANGED, "exit_ip_changed"
    if (
        policy.max_latency_ms is not None
        and latency_ms > policy.max_latency_ms
    ) or (
        policy.min_download_bps is not None
        and download_bps < policy.min_download_bps
    ):
        return SwitchTrigger.PERFORMANCE_DEGRADED, "performance_policy_failed"
    if policy.allowed_network_types and network_type not in policy.allowed_network_types:
        return SwitchTrigger.NETWORK_POLICY_MISMATCH, "network_policy_failed"
    if not unlock_ok:
        return SwitchTrigger.SERVICE_UNAVAILABLE, "service_policy_failed"
    return None


class MockConnectionRuntimeDriver:
    """Deterministic dry-run driver. It never invokes a network executor."""

    def __init__(self) -> None:
        self._unlock_probe = MockUnlockProbe()

    async def health(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        policy: HealthPolicy,
    ) -> HealthObservation:
        del policy
        await asyncio.sleep(0)
        return HealthObservation(
            healthy=True,
            trigger=None,
            exit_ip=connection.exit_ip or node.classified_exit_ip or node.ip_address,
            latency_ms=float(node.ping_ms or 0),
            download_bps=node.speed_bps or 0,
            network_type=NetworkType(node.network_type),
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
        del current_node
        checks = tuple(
            self._unlock_probe.check(connection.id, service_name)
            for service_name in policy.required_services
        )
        steps: list[str] = []
        socks_was_active = endpoint is not None and endpoint.is_active
        if socks_was_active:
            steps.append("SOCKS_STOPPED")
        steps.extend(
            (
                "KILLSWITCH_VERIFIED",
                "OPENVPN_STOPPED",
                "KILLSWITCH_UPDATED",
                "OPENVPN_STARTED",
                "EXIT_IP_VERIFIED",
                "NETWORK_TYPE_VERIFIED",
                "SERVICES_VERIFIED",
            )
        )
        if socks_was_active:
            steps.append("SOCKS_RESUMED")
        await asyncio.sleep(0)
        return SwitchExecution(
            exit_ip=candidate.classified_exit_ip or candidate.ip_address,
            latency_ms=float(candidate.ping_ms or 0),
            download_bps=candidate.speed_bps or 0,
            network_type=NetworkType(candidate.network_type),
            unlock_checks=checks,
            steps=tuple(steps),
            socks_resumed=socks_was_active,
            simulated=True,
            pid=None,
        )


class RealConnectionRuntimeDriver:
    def __init__(
        self,
        killswitch_manager: KillSwitchManager,
        openvpn_manager: OpenVPNManager,
        socks_service: SocksEndpointService,
        exit_probe: NamespaceExitProbe,
        intelligence_service: NodeIntelligenceEnricher,
        unlock_coordinator: UnlockCheckCoordinator,
    ) -> None:
        self._killswitch = killswitch_manager
        self._openvpn = openvpn_manager
        self._socks = socks_service
        self._exit_probe = exit_probe
        self._intelligence = intelligence_service
        self._unlock = unlock_coordinator

    async def _checks(
        self,
        connection_id: int,
        policy: HealthPolicy,
    ) -> tuple[UnlockCheckResult, ...]:
        if not policy.required_services:
            return ()
        return tuple(
            await self._unlock.check(connection_id, policy.required_services)
        )

    async def health(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        policy: HealthPolicy,
    ) -> HealthObservation:
        try:
            runtime = await asyncio.to_thread(
                self._openvpn.status,
                connection.id,
                node_id=node.id,
            )
        except OpenVPNOperationError:
            runtime = None
        if runtime is None or not runtime.running:
            return HealthObservation(
                healthy=False,
                trigger=SwitchTrigger.OPENVPN_DISCONNECTED,
                exit_ip=None,
                latency_ms=None,
                download_bps=None,
                network_type=NetworkType.UNKNOWN,
                failure_code="openvpn_disconnected",
            )
        try:
            probe = await asyncio.to_thread(self._exit_probe.probe, connection.id)
        except ExitProbeError:
            return HealthObservation(
                healthy=False,
                trigger=SwitchTrigger.EXIT_IP_UNAVAILABLE,
                exit_ip=None,
                latency_ms=None,
                download_bps=None,
                network_type=NetworkType.UNKNOWN,
                failure_code="exit_ip_unavailable",
            )
        classification = await self._intelligence.enrich_node(
            node,
            exit_ip=probe.exit_ip,
        )
        checks = await self._checks(connection.id, policy)
        failure = _policy_failure(
            exit_ip_changed=(
                connection.exit_ip is not None and connection.exit_ip != probe.exit_ip
            ),
            latency_ms=probe.latency_ms,
            download_bps=probe.download_bps,
            network_type=classification.network_type,
            policy=policy,
            unlock_ok=unlock_checks_satisfy_policy(checks),
        )
        if failure is not None:
            trigger, failure_code = failure
            return HealthObservation(
                healthy=False,
                trigger=trigger,
                exit_ip=probe.exit_ip,
                latency_ms=probe.latency_ms,
                download_bps=probe.download_bps,
                network_type=classification.network_type,
                unlock_checks=checks,
                failure_code=failure_code,
            )
        return HealthObservation(
            healthy=True,
            trigger=None,
            exit_ip=probe.exit_ip,
            latency_ms=probe.latency_ms,
            download_bps=probe.download_bps,
            network_type=classification.network_type,
            unlock_checks=checks,
        )

    def _plan(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> KillSwitchPlan:
        return self._killswitch.build_plan(
            connection.id,
            node_id=node.id,
            remote_address=node.ip_address,
            remote_port=node.remote_port,
            remote_protocol=node.protocol,
            socks_port=endpoint.port if endpoint is not None else None,
            client_ip_allowlist=(
                tuple(endpoint.client_ip_allowlist) if endpoint is not None else ()
            ),
        )

    async def switch(
        self,
        connection: VPNConnection,
        current_node: VPNGateNode,
        candidate: VPNGateNode,
        endpoint: SocksEndpoint | None,
        policy: HealthPolicy,
    ) -> SwitchExecution:
        if connection.status not in {ConnectionStatus.RUNNING, ConnectionStatus.FAILED}:
            raise AutoSwitchOperationError("connection_not_switchable")
        old_plan = self._plan(connection, current_node, endpoint)
        new_plan = self._plan(connection, candidate, endpoint)
        socks_was_active = endpoint is not None and endpoint.is_active
        old_openvpn_stopped = False
        new_killswitch_applied = False
        new_openvpn_attempted = False
        steps: list[str] = []
        try:
            if socks_was_active and endpoint is not None:
                runtime = await asyncio.to_thread(self._socks.stop, endpoint)
                if runtime.running:
                    raise AutoSwitchOperationError("socks_stop_failed")
                steps.append("SOCKS_STOPPED")

            killswitch = await asyncio.to_thread(self._killswitch.status, old_plan)
            if not killswitch.active:
                raise AutoSwitchOperationError("killswitch_not_active")
            steps.append("KILLSWITCH_VERIFIED")

            old_runtime = await asyncio.to_thread(
                self._openvpn.stop,
                connection.id,
                node_id=current_node.id,
            )
            if old_runtime.running:
                raise AutoSwitchOperationError("openvpn_stop_failed")
            old_openvpn_stopped = True
            steps.append("OPENVPN_STOPPED")

            await asyncio.to_thread(
                self._openvpn.stage_config,
                candidate.id,
                candidate.sanitized_config,
            )
            await asyncio.to_thread(self._killswitch.apply, new_plan)
            new_killswitch_applied = True
            steps.append("KILLSWITCH_UPDATED")

            new_openvpn_attempted = True
            new_runtime = await asyncio.to_thread(
                self._openvpn.start,
                connection.id,
                node_id=candidate.id,
                sanitized_config=candidate.sanitized_config,
            )
            if not new_runtime.running:
                raise AutoSwitchOperationError("openvpn_start_failed")
            steps.append("OPENVPN_STARTED")

            probe = await asyncio.to_thread(self._exit_probe.probe, connection.id)
            steps.append("EXIT_IP_VERIFIED")
            classification = await self._intelligence.enrich_node(
                candidate,
                exit_ip=probe.exit_ip,
            )
            if (
                policy.max_latency_ms is not None
                and probe.latency_ms > policy.max_latency_ms
            ) or (
                policy.min_download_bps is not None
                and probe.download_bps < policy.min_download_bps
            ):
                raise AutoSwitchOperationError("performance_policy_failed")
            if (
                policy.allowed_network_types
                and classification.network_type not in policy.allowed_network_types
            ):
                raise AutoSwitchOperationError("network_policy_failed")
            steps.append("NETWORK_TYPE_VERIFIED")

            checks = await self._checks(connection.id, policy)
            if not unlock_checks_satisfy_policy(checks):
                raise AutoSwitchOperationError("service_policy_failed")
            steps.append("SERVICES_VERIFIED")

            socks_resumed = False
            if socks_was_active and endpoint is not None:
                socks_runtime = await asyncio.to_thread(self._socks.start, endpoint)
                if not socks_runtime.running:
                    raise AutoSwitchOperationError("socks_resume_failed")
                socks_resumed = True
                steps.append("SOCKS_RESUMED")
            return SwitchExecution(
                exit_ip=probe.exit_ip,
                latency_ms=probe.latency_ms,
                download_bps=probe.download_bps,
                network_type=classification.network_type,
                unlock_checks=checks,
                steps=tuple(steps),
                socks_resumed=socks_resumed,
                simulated=False,
                pid=new_runtime.pid,
            )
        except Exception as exc:
            cleanup_failed = False
            if new_openvpn_attempted:
                try:
                    await asyncio.to_thread(
                        self._openvpn.stop,
                        connection.id,
                        node_id=candidate.id,
                    )
                except Exception:
                    cleanup_failed = True
            if old_openvpn_stopped and not new_killswitch_applied:
                try:
                    await asyncio.to_thread(self._killswitch.apply, old_plan)
                except Exception:
                    cleanup_failed = True
            if isinstance(exc, AutoSwitchOperationError):
                code = exc.code
            elif isinstance(
                exc,
                (
                    KillSwitchOperationError,
                    OpenVPNOperationError,
                    Socks5OperationError,
                    ExitProbeError,
                ),
            ):
                code = exc.code
            else:
                code = "switch_internal_error"
            if cleanup_failed:
                code = f"{code}_cleanup_failed"
            raise AutoSwitchOperationError(code) from exc


def build_connection_runtime_driver(
    executor: NetworkExecutor,
    *,
    enable_real_auto_switch: bool,
    killswitch_manager: KillSwitchManager,
    openvpn_manager: OpenVPNManager,
    socks_service: SocksEndpointService,
    exit_probe: NamespaceExitProbe,
    intelligence_service: NodeIntelligenceEnricher,
    unlock_coordinator: UnlockCheckCoordinator,
) -> ConnectionRuntimeDriver:
    if not enable_real_auto_switch:
        return MockConnectionRuntimeDriver()
    if os.getenv("VPNGATE_ENABLE_REAL_AUTO_SWITCH") != "true":
        raise RuntimeError(
            "real auto switch requires VPNGATE_ENABLE_REAL_AUTO_SWITCH=true"
        )
    if not isinstance(executor, RealNetworkExecutor):
        raise RuntimeError("real auto switch requires the real network executor")
    return RealConnectionRuntimeDriver(
        killswitch_manager,
        openvpn_manager,
        socks_service,
        exit_probe,
        intelligence_service,
        unlock_coordinator,
    )
