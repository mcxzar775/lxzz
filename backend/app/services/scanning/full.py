import asyncio
from typing import Protocol

from app.models.enums import ScanStatus
from app.services.network.killswitch import (
    KillSwitchOperationError,
    KillSwitchPlan,
    KillSwitchRuntime,
)
from app.services.network.namespace import (
    NamespaceCleanupReport,
    NamespaceOperationError,
    NamespacePlan,
    allocate_namespace_plan,
)
from app.services.network.openvpn_manager import (
    OpenVPNOperationError,
    OpenVPNRuntime,
)
from app.services.scanning.probe import ExitProbeError, ExitProbeResult
from app.services.scanning.types import NodeScanOutcome, NodeScanTarget
from app.services.unlock import (
    ALL_UNLOCK_SERVICES,
    MockUnlockProbe,
    UnlockProbe,
)


class FullScanRunner(Protocol):
    async def scan(
        self, target: NodeScanTarget, *, resource_id: int
    ) -> NodeScanOutcome: ...


class NamespaceController(Protocol):
    def create(self, plan: NamespacePlan) -> NamespacePlan: ...

    def delete(self, plan: NamespacePlan) -> NamespaceCleanupReport: ...


class KillSwitchController(Protocol):
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
    ) -> KillSwitchPlan: ...

    def apply(self, plan: KillSwitchPlan) -> KillSwitchRuntime: ...

    def remove(self, plan: KillSwitchPlan) -> KillSwitchRuntime: ...


class OpenVPNController(Protocol):
    def stage_config(self, node_id: int, sanitized_config: str) -> object: ...

    def start(
        self,
        connection_id: int,
        *,
        node_id: int,
        sanitized_config: str,
    ) -> OpenVPNRuntime: ...

    def stop(self, connection_id: int, *, node_id: int) -> OpenVPNRuntime: ...


class ExitProbeController(Protocol):
    def probe(self, resource_id: int) -> ExitProbeResult: ...


class SimulatedFullScanRunner:
    def __init__(self) -> None:
        self._unlock_probe = MockUnlockProbe()

    async def scan(
        self, target: NodeScanTarget, *, resource_id: int
    ) -> NodeScanOutcome:
        unlock_checks = [
            self._unlock_probe.check(resource_id, service_name).safe_details()
            for service_name in ALL_UNLOCK_SERVICES
        ]
        return NodeScanOutcome(
            scan_type="full",
            status=ScanStatus.SUCCEEDED,
            latency_ms=float(target.advertised_ping_ms or 0),
            exit_ip=target.ip_address,
            details={
                "simulated": True,
                "resource_id": resource_id,
                "dns_ok": False,
                "https_ok": False,
                "download_bps": 0,
                "unlock_checks": unlock_checks,
            },
        )


def _error_code(exc: Exception) -> str:
    if isinstance(
        exc,
        (
            NamespaceOperationError,
            KillSwitchOperationError,
            OpenVPNOperationError,
            ExitProbeError,
        ),
    ):
        return exc.code
    return "full_scan_failed"


class IsolatedFullScanRunner:
    def __init__(
        self,
        namespace_manager: NamespaceController,
        killswitch_manager: KillSwitchController,
        openvpn_manager: OpenVPNController,
        exit_probe: ExitProbeController,
        *,
        dns_servers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8"),
        unlock_probe: UnlockProbe | None = None,
    ) -> None:
        self._namespace_manager = namespace_manager
        self._killswitch_manager = killswitch_manager
        self._openvpn_manager = openvpn_manager
        self._exit_probe = exit_probe
        self._dns_servers = dns_servers
        self._unlock_probe = unlock_probe

    def _run_unlock_checks(self, resource_id: int) -> list[dict[str, object]]:
        if self._unlock_probe is None:
            return []
        checks: list[dict[str, object]] = []
        for service_name in ALL_UNLOCK_SERVICES:
            try:
                result = self._unlock_probe.check(resource_id, service_name)
            except Exception:
                result = MockUnlockProbe().check(resource_id, service_name)
            checks.append(result.safe_details())
        return checks

    def _cleanup(
        self,
        target: NodeScanTarget,
        namespace_plan: NamespacePlan,
        killswitch_plan: KillSwitchPlan | None,
        *,
        namespace_created: bool,
        openvpn_attempted: bool,
        killswitch_attempted: bool,
    ) -> list[str]:
        failures: list[str] = []
        openvpn_stopped = True
        if openvpn_attempted:
            try:
                self._openvpn_manager.stop(
                    namespace_plan.connection_id,
                    node_id=target.node_id,
                )
            except Exception:
                openvpn_stopped = False
                failures.append("openvpn_stop")

        killswitch_removed = not killswitch_attempted
        if killswitch_attempted and openvpn_stopped and killswitch_plan is not None:
            try:
                self._killswitch_manager.remove(killswitch_plan)
                killswitch_removed = True
            except Exception:
                failures.append("killswitch_remove")
        elif killswitch_attempted:
            failures.append("killswitch_preserved")

        if namespace_created and openvpn_stopped and killswitch_removed:
            try:
                report = self._namespace_manager.delete(namespace_plan)
            except Exception:
                failures.append("namespace_delete")
            else:
                failures.extend(
                    f"namespace_{operation.value}" for operation in report.failures
                )
        elif namespace_created:
            failures.append("namespace_preserved")
        return failures

    def _scan_sync(
        self, target: NodeScanTarget, *, resource_id: int
    ) -> NodeScanOutcome:
        namespace_plan = allocate_namespace_plan(
            resource_id,
            dns_servers=self._dns_servers,
        )
        killswitch_plan: KillSwitchPlan | None = None
        namespace_created = False
        killswitch_attempted = False
        openvpn_attempted = False
        outcome: NodeScanOutcome
        try:
            self._namespace_manager.create(namespace_plan)
            namespace_created = True
            self._openvpn_manager.stage_config(
                target.node_id,
                target.sanitized_config,
            )
            killswitch_plan = self._killswitch_manager.build_plan(
                resource_id,
                node_id=target.node_id,
                remote_address=target.ip_address,
                remote_port=target.remote_port,
                remote_protocol=target.protocol,
                socks_port=None,
            )
            killswitch_attempted = True
            self._killswitch_manager.apply(killswitch_plan)
            openvpn_attempted = True
            self._openvpn_manager.start(
                resource_id,
                node_id=target.node_id,
                sanitized_config=target.sanitized_config,
            )
            probe = self._exit_probe.probe(resource_id)
            unlock_checks = self._run_unlock_checks(resource_id)
            outcome = NodeScanOutcome(
                scan_type="full",
                status=ScanStatus.SUCCEEDED,
                latency_ms=probe.latency_ms,
                exit_ip=probe.exit_ip,
                details={
                    "simulated": False,
                    "resource_id": resource_id,
                    "dns_ok": probe.dns_ok,
                    "https_ok": probe.https_ok,
                    "download_bps": probe.download_bps,
                    "unlock_checks": unlock_checks,
                },
            )
        except Exception as exc:
            code = _error_code(exc)
            outcome = NodeScanOutcome(
                scan_type="full",
                status=ScanStatus.TIMEOUT if "timeout" in code else ScanStatus.FAILED,
                error_code=code,
                details={"simulated": False, "resource_id": resource_id},
            )

        cleanup_failures = self._cleanup(
            target,
            namespace_plan,
            killswitch_plan,
            namespace_created=namespace_created,
            openvpn_attempted=openvpn_attempted,
            killswitch_attempted=killswitch_attempted,
        )
        if cleanup_failures:
            details = outcome.safe_details
            if outcome.error_code is not None:
                details["primary_error_code"] = outcome.error_code
            details["cleanup_failures"] = cleanup_failures
            return NodeScanOutcome(
                scan_type="full",
                status=ScanStatus.FAILED,
                latency_ms=outcome.latency_ms,
                exit_ip=outcome.exit_ip,
                error_code="full_scan_cleanup_failed",
                details=details,
            )
        return outcome

    async def scan(
        self, target: NodeScanTarget, *, resource_id: int
    ) -> NodeScanOutcome:
        return await asyncio.to_thread(
            self._scan_sync,
            target,
            resource_id=resource_id,
        )
