import asyncio
import os
from typing import Protocol

from app.models.enums import ConnectionStatus, NetworkType
from app.models.network import SocksEndpoint, VPNConnection, VPNGateNode
from app.services.connections.types import (
    ConnectionLifecycleError,
    ConnectionRuntimeResult,
)
from app.services.ip_intelligence import NodeIntelligenceEnricher
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor
from app.services.network.killswitch import (
    KillSwitchManager,
    KillSwitchOperationError,
    KillSwitchPlan,
)
from app.services.network.namespace import (
    NamespaceManager,
    NamespaceOperationError,
    NamespacePlan,
    allocate_namespace_plan,
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


class ConnectionLifecycleDriver(Protocol):
    async def start(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> ConnectionRuntimeResult: ...

    async def stop(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> ConnectionRuntimeResult: ...


class MockConnectionLifecycleDriver:
    """Database-only lifecycle simulation; no network executor is invoked."""

    async def start(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> ConnectionRuntimeResult:
        del connection
        await asyncio.sleep(0)
        steps = [
            "NAMESPACE_CREATED",
            "KILLSWITCH_APPLIED",
            "OPENVPN_STARTED",
            "EXIT_IP_VERIFIED",
            "NETWORK_TYPE_VERIFIED",
        ]
        if endpoint is not None:
            steps.append("SOCKS_STARTED")
        return ConnectionRuntimeResult(
            status=ConnectionStatus.RUNNING,
            exit_ip=node.classified_exit_ip or node.ip_address,
            network_type=NetworkType(node.network_type),
            pid=None,
            socks_active=endpoint is not None,
            steps=tuple(steps),
            simulated=True,
        )

    async def stop(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> ConnectionRuntimeResult:
        del connection, node
        await asyncio.sleep(0)
        steps = []
        if endpoint is not None and endpoint.is_active:
            steps.append("SOCKS_STOPPED")
        steps.extend(("OPENVPN_STOPPED", "KILLSWITCH_REMOVED", "NAMESPACE_REMOVED"))
        return ConnectionRuntimeResult(
            status=ConnectionStatus.STOPPED,
            exit_ip=None,
            network_type=NetworkType.UNKNOWN,
            pid=None,
            socks_active=False,
            steps=tuple(steps),
            simulated=True,
        )


class RealConnectionLifecycleDriver:
    def __init__(
        self,
        namespace_manager: NamespaceManager,
        killswitch_manager: KillSwitchManager,
        openvpn_manager: OpenVPNManager,
        socks_service: SocksEndpointService,
        exit_probe: NamespaceExitProbe,
        intelligence_service: NodeIntelligenceEnricher,
        *,
        dns_servers: tuple[str, ...],
    ) -> None:
        self._namespace = namespace_manager
        self._killswitch = killswitch_manager
        self._openvpn = openvpn_manager
        self._socks = socks_service
        self._exit_probe = exit_probe
        self._intelligence = intelligence_service
        self._dns_servers = dns_servers

    def _plans(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> tuple[NamespacePlan, KillSwitchPlan]:
        namespace_plan = allocate_namespace_plan(
            connection.id,
            dns_servers=self._dns_servers,
        )
        if (
            connection.namespace != namespace_plan.namespace
            or connection.veth_host != namespace_plan.host_veth
            or connection.veth_namespace != namespace_plan.namespace_veth
            or connection.subnet_cidr != namespace_plan.subnet_cidr
        ):
            raise ConnectionLifecycleError("connection_namespace_mismatch")
        killswitch_plan = self._killswitch.build_plan(
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
        return namespace_plan, killswitch_plan

    @staticmethod
    def _code(exc: Exception) -> str:
        if isinstance(
            exc,
            (
                ConnectionLifecycleError,
                KillSwitchOperationError,
                NamespaceOperationError,
                OpenVPNOperationError,
                Socks5OperationError,
                ExitProbeError,
            ),
        ):
            return exc.code
        return "connection_lifecycle_failed"

    async def start(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> ConnectionRuntimeResult:
        namespace_plan, killswitch_plan = self._plans(connection, node, endpoint)
        namespace_created = False
        killswitch_applied = False
        openvpn_attempted = False
        steps: list[str] = []
        try:
            await asyncio.to_thread(self._namespace.create, namespace_plan)
            namespace_created = True
            steps.append("NAMESPACE_CREATED")
            await asyncio.to_thread(
                self._openvpn.stage_config,
                node.id,
                node.sanitized_config,
            )
            await asyncio.to_thread(self._killswitch.apply, killswitch_plan)
            killswitch_applied = True
            steps.append("KILLSWITCH_APPLIED")
            openvpn_attempted = True
            runtime = await asyncio.to_thread(
                self._openvpn.start,
                connection.id,
                node_id=node.id,
                sanitized_config=node.sanitized_config,
            )
            steps.append("OPENVPN_STARTED")
            probe = await asyncio.to_thread(self._exit_probe.probe, connection.id)
            steps.append("EXIT_IP_VERIFIED")
            classification = await self._intelligence.enrich_node(
                node,
                exit_ip=probe.exit_ip,
            )
            steps.append("NETWORK_TYPE_VERIFIED")
            socks_active = False
            if endpoint is not None:
                socks_runtime = await asyncio.to_thread(self._socks.start, endpoint)
                if not socks_runtime.running:
                    raise ConnectionLifecycleError("socks_start_failed")
                socks_active = True
                steps.append("SOCKS_STARTED")
            return ConnectionRuntimeResult(
                status=ConnectionStatus.RUNNING,
                exit_ip=probe.exit_ip,
                network_type=classification.network_type,
                pid=runtime.pid,
                socks_active=socks_active,
                steps=tuple(steps),
                simulated=False,
            )
        except Exception as exc:
            cleanup_failed = False
            openvpn_stopped = not openvpn_attempted
            if openvpn_attempted:
                try:
                    await asyncio.to_thread(
                        self._openvpn.stop,
                        connection.id,
                        node_id=node.id,
                    )
                    openvpn_stopped = True
                except Exception:
                    cleanup_failed = True
            killswitch_removed = not killswitch_applied
            if killswitch_applied and openvpn_stopped:
                try:
                    await asyncio.to_thread(self._killswitch.remove, killswitch_plan)
                    killswitch_removed = True
                except Exception:
                    cleanup_failed = True
            if namespace_created and openvpn_stopped and killswitch_removed:
                report = await asyncio.to_thread(self._namespace.delete, namespace_plan)
                cleanup_failed = cleanup_failed or not report.succeeded
            code = self._code(exc)
            if cleanup_failed:
                code = f"{code}_cleanup_failed"
            raise ConnectionLifecycleError(code) from exc

    async def stop(
        self,
        connection: VPNConnection,
        node: VPNGateNode,
        endpoint: SocksEndpoint | None,
    ) -> ConnectionRuntimeResult:
        namespace_plan, killswitch_plan = self._plans(connection, node, endpoint)
        steps: list[str] = []
        try:
            if endpoint is not None and endpoint.is_active:
                socks_runtime = await asyncio.to_thread(self._socks.stop, endpoint)
                if socks_runtime.running:
                    raise ConnectionLifecycleError("socks_stop_failed")
                steps.append("SOCKS_STOPPED")
            openvpn_runtime = await asyncio.to_thread(
                self._openvpn.stop,
                connection.id,
                node_id=node.id,
            )
            if openvpn_runtime.running:
                raise ConnectionLifecycleError("openvpn_stop_failed")
            steps.append("OPENVPN_STOPPED")
            await asyncio.to_thread(self._killswitch.remove, killswitch_plan)
            steps.append("KILLSWITCH_REMOVED")
            cleanup = await asyncio.to_thread(self._namespace.delete, namespace_plan)
            if not cleanup.succeeded:
                raise ConnectionLifecycleError("namespace_cleanup_failed")
            steps.append("NAMESPACE_REMOVED")
            return ConnectionRuntimeResult(
                status=ConnectionStatus.STOPPED,
                exit_ip=None,
                network_type=NetworkType.UNKNOWN,
                pid=None,
                socks_active=False,
                steps=tuple(steps),
                simulated=False,
            )
        except Exception as exc:
            raise ConnectionLifecycleError(self._code(exc)) from exc


def build_connection_lifecycle_driver(
    executor: NetworkExecutor,
    *,
    enable_real_connections: bool,
    namespace_manager: NamespaceManager,
    killswitch_manager: KillSwitchManager,
    openvpn_manager: OpenVPNManager,
    socks_service: SocksEndpointService,
    exit_probe: NamespaceExitProbe,
    intelligence_service: NodeIntelligenceEnricher,
    dns_servers: tuple[str, ...],
) -> ConnectionLifecycleDriver:
    if not enable_real_connections:
        return MockConnectionLifecycleDriver()
    if os.getenv("VPNGATE_ENABLE_REAL_CONNECTIONS") != "true":
        raise RuntimeError(
            "real connection lifecycle requires VPNGATE_ENABLE_REAL_CONNECTIONS=true"
        )
    if not isinstance(executor, RealNetworkExecutor):
        raise RuntimeError("real connection lifecycle requires real network executor")
    return RealConnectionLifecycleDriver(
        namespace_manager,
        killswitch_manager,
        openvpn_manager,
        socks_service,
        exit_probe,
        intelligence_service,
        dns_servers=dns_servers,
    )
