import ipaddress
from dataclasses import dataclass
from typing import Literal

from app.services.network.commands import NetworkCommand, NetworkOperation
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor
from app.services.network.namespace import allocate_namespace_plan
from app.services.network.socks5 import normalize_client_ip_allowlist
from app.services.network.validation import (
    ResourceValidationError,
    validate_port,
    validate_remote_endpoint,
)


FirewallBackend = Literal["auto", "nftables", "iptables"]


class KillSwitchOperationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class KillSwitchPlan:
    connection_id: int
    node_id: int
    namespace: str
    host_veth: str
    namespace_veth: str
    host_address: str
    namespace_address: str
    remote_address: str
    remote_port: int
    remote_protocol: str
    socks_port: int | None
    client_ip_allowlist: tuple[str, ...]
    backend: FirewallBackend


@dataclass(frozen=True)
class KillSwitchRuntime:
    connection_id: int
    namespace: str
    active: bool
    backend: str | None


def build_killswitch_plan(
    connection_id: int,
    *,
    node_id: int,
    remote_address: str,
    remote_port: int,
    remote_protocol: str,
    socks_port: int | None,
    client_ip_allowlist: tuple[str, ...] = (),
    backend: FirewallBackend = "auto",
) -> KillSwitchPlan:
    namespace_plan = allocate_namespace_plan(connection_id)
    if isinstance(node_id, bool) or node_id <= 0 or node_id > 2_147_483_647:
        raise KillSwitchOperationError("invalid_killswitch_plan")
    try:
        remote = validate_remote_endpoint(
            remote_address, remote_port, remote_protocol
        )
        if socks_port is not None:
            validate_port(socks_port, minimum=1024)
    except ResourceValidationError as exc:
        raise KillSwitchOperationError("invalid_killswitch_plan") from exc
    if not isinstance(ipaddress.ip_address(remote.address), ipaddress.IPv4Address):
        raise KillSwitchOperationError("invalid_killswitch_plan")
    if backend not in {"auto", "nftables", "iptables"}:
        raise KillSwitchOperationError("invalid_firewall_backend")
    allowlist = normalize_client_ip_allowlist(client_ip_allowlist)
    return KillSwitchPlan(
        connection_id=connection_id,
        node_id=node_id,
        namespace=namespace_plan.namespace,
        host_veth=namespace_plan.host_veth,
        namespace_veth=namespace_plan.namespace_veth,
        host_address=namespace_plan.gateway_address,
        namespace_address=namespace_plan.namespace_address_cidr.split("/", 1)[0],
        remote_address=remote.address,
        remote_port=remote.port,
        remote_protocol=remote.protocol,
        socks_port=socks_port,
        client_ip_allowlist=allowlist,
        backend=backend,
    )


def killswitch_apply_command(plan: KillSwitchPlan) -> NetworkCommand:
    allowlist = ",".join(plan.client_ip_allowlist) or "-"
    return NetworkCommand(
        NetworkOperation.KILLSWITCH_APPLY,
        (
            plan.namespace,
            str(plan.connection_id),
            str(plan.node_id),
            plan.remote_address,
            str(plan.remote_port),
            plan.remote_protocol,
            str(plan.socks_port) if plan.socks_port is not None else "-",
            plan.backend,
            allowlist,
        ),
    )


def killswitch_remove_command(plan: KillSwitchPlan) -> NetworkCommand:
    return NetworkCommand(
        NetworkOperation.KILLSWITCH_REMOVE,
        (plan.namespace, str(plan.connection_id)),
    )


def killswitch_status_command(plan: KillSwitchPlan) -> NetworkCommand:
    return NetworkCommand(
        NetworkOperation.KILLSWITCH_STATUS,
        (plan.namespace, str(plan.connection_id)),
    )


class KillSwitchManager:
    def __init__(
        self,
        executor: NetworkExecutor,
        *,
        allow_real_firewall: bool = False,
        default_backend: FirewallBackend = "auto",
        command_timeout_seconds: float = 20.0,
    ) -> None:
        if command_timeout_seconds <= 0 or command_timeout_seconds > 120:
            raise ValueError("invalid_timeout")
        if default_backend not in {"auto", "nftables", "iptables"}:
            raise ValueError("invalid_firewall_backend")
        self._executor = executor
        self._allow_real_firewall = allow_real_firewall
        self._default_backend = default_backend
        self._command_timeout_seconds = command_timeout_seconds

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
            backend=self._default_backend,
        )

    def _run(self, command: NetworkCommand) -> tuple[int, str]:
        if isinstance(self._executor, RealNetworkExecutor) and not self._allow_real_firewall:
            raise KillSwitchOperationError(
                "real firewall execution requires VPNGATE_ENABLE_REAL_FIREWALL=true"
            )
        try:
            result = self._executor.run(
                command, timeout_seconds=self._command_timeout_seconds
            )
        except Exception as exc:
            raise KillSwitchOperationError("killswitch_command_failed") from exc
        return result.returncode, result.stdout.strip()

    def status(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        returncode, output = self._run(killswitch_status_command(plan))
        if returncode not in {0, 3}:
            raise KillSwitchOperationError("killswitch_status_failed")
        backend = output if output in {"nftables", "iptables"} else None
        if returncode == 0 and backend is None:
            raise KillSwitchOperationError("killswitch_status_failed")
        return KillSwitchRuntime(
            connection_id=plan.connection_id,
            namespace=plan.namespace,
            active=returncode == 0,
            backend=backend,
        )

    def remove(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        returncode, _ = self._run(killswitch_remove_command(plan))
        if returncode != 0:
            raise KillSwitchOperationError("killswitch_remove_failed")
        return KillSwitchRuntime(
            connection_id=plan.connection_id,
            namespace=plan.namespace,
            active=False,
            backend=None,
        )

    def apply(self, plan: KillSwitchPlan) -> KillSwitchRuntime:
        returncode, _ = self._run(killswitch_apply_command(plan))
        if returncode != 0:
            try:
                self.remove(plan)
            except KillSwitchOperationError as exc:
                raise KillSwitchOperationError(
                    "killswitch_apply_failed_cleanup_failed"
                ) from exc
            raise KillSwitchOperationError("killswitch_apply_failed")
        try:
            runtime = self.status(plan)
        except KillSwitchOperationError:
            try:
                self.remove(plan)
            except KillSwitchOperationError as exc:
                raise KillSwitchOperationError(
                    "killswitch_verify_failed_cleanup_failed"
                ) from exc
            raise
        if not runtime.active:
            try:
                self.remove(plan)
            except KillSwitchOperationError as exc:
                raise KillSwitchOperationError(
                    "killswitch_verify_failed_cleanup_failed"
                ) from exc
            raise KillSwitchOperationError("killswitch_verify_failed")
        return runtime
