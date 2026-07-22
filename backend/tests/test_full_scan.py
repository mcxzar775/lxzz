import asyncio
from dataclasses import dataclass, field

from app.models.enums import ScanStatus
from app.services.network import NetworkOperation
from app.services.network.killswitch import (
    KillSwitchPlan,
    KillSwitchRuntime,
    build_killswitch_plan,
)
from app.services.network.namespace import NamespaceCleanupReport, NamespacePlan
from app.services.network.openvpn_manager import OpenVPNRuntime
from app.services.scanning.fast import MockFastScanTransport
from app.services.scanning.full import IsolatedFullScanRunner, SimulatedFullScanRunner
from app.services.scanning.probe import ExitProbeError, ExitProbeResult
from app.services.scanning.service import NodeScanCoordinator
from app.services.scanning.types import NodeScanOutcome, NodeScanTarget


def _target() -> NodeScanTarget:
    return NodeScanTarget(
        node_id=9,
        host_name=None,
        ip_address="8.8.8.8",
        protocol="udp",
        remote_port=1194,
        sanitized_config="client\n",
        advertised_ping_ms=42,
    )


@dataclass
class FakeNamespaceManager:
    events: list[str]
    cleanup_failures: tuple[NetworkOperation, ...] = ()

    def create(self, plan: NamespacePlan) -> NamespacePlan:
        self.events.append("namespace_create")
        return plan

    def delete(self, plan: NamespacePlan) -> NamespaceCleanupReport:
        self.events.append("namespace_delete")
        return NamespaceCleanupReport(
            attempted=(NetworkOperation.NAMESPACE_DELETE,),
            failures=self.cleanup_failures,
        )


@dataclass
class FakeKillSwitchManager:
    events: list[str]

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
        self.events.append("killswitch_build")
        return build_killswitch_plan(
            connection_id,
            node_id=node_id,
            remote_address=remote_address,
            remote_port=remote_port,
            remote_protocol=remote_protocol,
            socks_port=socks_port,
            client_ip_allowlist=client_ip_allowlist,
        )

    def apply(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        self.events.append("killswitch_apply")
        return KillSwitchRuntime(plan.connection_id, plan.namespace, True, "nftables")

    def remove(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        self.events.append("killswitch_remove")
        return KillSwitchRuntime(plan.connection_id, plan.namespace, False, None)


@dataclass
class FakeOpenVPNManager:
    events: list[str]
    stop_fails: bool = False

    def stage_config(self, node_id: int, sanitized_config: str) -> object:
        del node_id, sanitized_config
        self.events.append("openvpn_stage")
        return object()

    def start(
        self,
        connection_id: int,
        *,
        node_id: int,
        sanitized_config: str,
    ) -> OpenVPNRuntime:
        del sanitized_config
        self.events.append("openvpn_start")
        return OpenVPNRuntime(
            connection_id, node_id, f"lxvpn-{connection_id}", "tun0", True, 4321
        )

    def stop(self, connection_id: int, *, node_id: int) -> OpenVPNRuntime:
        self.events.append("openvpn_stop")
        if self.stop_fails:
            raise RuntimeError("stop failed")
        return OpenVPNRuntime(
            connection_id, node_id, f"lxvpn-{connection_id}", "tun0", False, None
        )


@dataclass
class FakeExitProbe:
    events: list[str]
    failure: ExitProbeError | None = None

    def probe(self, resource_id: int) -> ExitProbeResult:
        self.events.append("exit_probe")
        if self.failure is not None:
            raise self.failure
        return ExitProbeResult("1.1.1.1", 18.5, 8_000_000, True, True)


def _runner(
    events: list[str],
    *,
    stop_fails: bool = False,
    probe_failure: ExitProbeError | None = None,
) -> IsolatedFullScanRunner:
    return IsolatedFullScanRunner(
        FakeNamespaceManager(events),
        FakeKillSwitchManager(events),
        FakeOpenVPNManager(events, stop_fails=stop_fails),
        FakeExitProbe(events, failure=probe_failure),
    )


def test_full_scan_runs_isolated_probe_and_cleans_in_safe_order() -> None:
    events: list[str] = []

    outcome = asyncio.run(_runner(events).scan(_target(), resource_id=16382))

    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.exit_ip == "1.1.1.1"
    assert outcome.safe_details["download_bps"] == 8_000_000
    assert events == [
        "namespace_create",
        "openvpn_stage",
        "killswitch_build",
        "killswitch_apply",
        "openvpn_start",
        "exit_probe",
        "openvpn_stop",
        "killswitch_remove",
        "namespace_delete",
    ]


def test_probe_failure_is_persistable_and_still_cleans_every_resource() -> None:
    events: list[str] = []

    outcome = asyncio.run(
        _runner(
            events,
            probe_failure=ExitProbeError("exit_probe_tunnel_not_ready"),
        ).scan(_target(), resource_id=16382)
    )

    assert outcome.status is ScanStatus.FAILED
    assert outcome.error_code == "exit_probe_tunnel_not_ready"
    assert events[-3:] == [
        "openvpn_stop",
        "killswitch_remove",
        "namespace_delete",
    ]


def test_stop_failure_preserves_killswitch_and_namespace_fail_closed() -> None:
    events: list[str] = []

    outcome = asyncio.run(
        _runner(events, stop_fails=True).scan(_target(), resource_id=16382)
    )

    assert outcome.status is ScanStatus.FAILED
    assert outcome.error_code == "full_scan_cleanup_failed"
    assert outcome.safe_details["cleanup_failures"] == [
        "openvpn_stop",
        "killswitch_preserved",
        "namespace_preserved",
    ]
    assert "killswitch_remove" not in events
    assert "namespace_delete" not in events


def test_simulated_full_scan_is_explicit_and_has_no_side_effects() -> None:
    outcome = asyncio.run(
        SimulatedFullScanRunner().scan(_target(), resource_id=16382)
    )

    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.simulated is True
    assert outcome.safe_details["resource_id"] == 16382
    checks = outcome.safe_details["unlock_checks"]
    assert len(checks) == 4
    assert all(check["details"]["simulated"] is True for check in checks)


def test_coordinator_rotates_reserved_namespace_slots() -> None:
    coordinator = NodeScanCoordinator(
        MockFastScanTransport(),
        SimulatedFullScanRunner(),
        concurrency=3,
    )

    async def run_scans() -> list[int]:
        first = await coordinator.scan(_target(), scan_type="full")
        second = await coordinator.scan(_target(), scan_type="full")
        return [
            int(first.safe_details["resource_id"]),
            int(second.safe_details["resource_id"]),
        ]

    assert asyncio.run(run_scans()) == [16_382, 16_383]


def test_coordinator_waits_for_cleanup_before_returning_timeout() -> None:
    cleaned: list[bool] = []

    class SlowRunner:
        async def scan(
            self, target: NodeScanTarget, *, resource_id: int
        ) -> NodeScanOutcome:
            del target, resource_id
            await asyncio.sleep(0.01)
            cleaned.append(True)
            return NodeScanOutcome(
                scan_type="full",
                status=ScanStatus.SUCCEEDED,
                details={"simulated": False},
            )

    coordinator = NodeScanCoordinator(
        MockFastScanTransport(),
        SlowRunner(),
        concurrency=1,
        full_timeout_seconds=0.001,
    )

    outcome = asyncio.run(coordinator.scan(_target(), scan_type="full"))

    assert outcome.status is ScanStatus.TIMEOUT
    assert outcome.error_code == "full_scan_timeout"
    assert cleaned == [True]
