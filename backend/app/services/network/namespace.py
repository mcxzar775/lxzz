import ipaddress
from dataclasses import dataclass

from app.services.network.commands import (
    INTERNAL_NETWORK,
    MAX_NAMESPACE_RESOURCES,
    NetworkCommand,
    NetworkOperation,
    host_veth_name,
    namespace_name,
    namespace_veth_name,
)
from app.services.network.executor import NetworkExecutor


MAX_NAMESPACES = MAX_NAMESPACE_RESOURCES
DEFAULT_COMMAND_TIMEOUT_SECONDS = 20.0


class NamespacePlanError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NamespaceOperationError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        failed_operation: NetworkOperation,
        rollback_failures: tuple[NetworkOperation, ...] = (),
    ) -> None:
        super().__init__(code)
        self.code = code
        self.failed_operation = failed_operation
        self.rollback_failures = rollback_failures


@dataclass(frozen=True)
class NamespacePlan:
    connection_id: int
    namespace: str
    host_veth: str
    namespace_veth: str
    subnet_cidr: str
    host_address_cidr: str
    namespace_address_cidr: str
    gateway_address: str
    dns_servers: tuple[str, ...]


@dataclass(frozen=True)
class NamespaceCleanupReport:
    attempted: tuple[NetworkOperation, ...]
    failures: tuple[NetworkOperation, ...]

    @property
    def succeeded(self) -> bool:
        return not self.failures


def allocate_namespace_plan(
    connection_id: int,
    *,
    dns_servers: tuple[str, ...] = ("1.1.1.1", "8.8.8.8"),
) -> NamespacePlan:
    if isinstance(connection_id, bool) or connection_id <= 0:
        raise NamespacePlanError("invalid_connection_id")
    if connection_id > MAX_NAMESPACES:
        raise NamespacePlanError("namespace_capacity_exceeded")

    network_address = int(INTERNAL_NETWORK.network_address) + (connection_id - 1) * 4
    subnet = ipaddress.IPv4Network((network_address, 30))
    host_address, namespace_address = tuple(subnet.hosts())
    namespace = namespace_name(connection_id)
    NetworkCommand(
        NetworkOperation.NAMESPACE_DNS_WRITE,
        (namespace, *dns_servers),
    )
    return NamespacePlan(
        connection_id=connection_id,
        namespace=namespace,
        host_veth=host_veth_name(connection_id),
        namespace_veth=namespace_veth_name(connection_id),
        subnet_cidr=str(subnet),
        host_address_cidr=f"{host_address}/30",
        namespace_address_cidr=f"{namespace_address}/30",
        gateway_address=str(host_address),
        dns_servers=dns_servers,
    )


def creation_commands(plan: NamespacePlan) -> tuple[NetworkCommand, ...]:
    return (
        NetworkCommand(NetworkOperation.NAMESPACE_CREATE, (plan.namespace,)),
        NetworkCommand(
            NetworkOperation.VETH_CREATE,
            (plan.host_veth, plan.namespace_veth),
        ),
        NetworkCommand(
            NetworkOperation.VETH_MOVE,
            (plan.namespace_veth, plan.namespace),
        ),
        NetworkCommand(
            NetworkOperation.HOST_ADDRESS_ADD,
            (plan.host_address_cidr, plan.host_veth),
        ),
        NetworkCommand(
            NetworkOperation.NAMESPACE_ADDRESS_ADD,
            (plan.namespace, plan.namespace_address_cidr, plan.namespace_veth),
        ),
        NetworkCommand(NetworkOperation.HOST_LINK_UP, (plan.host_veth,)),
        NetworkCommand(NetworkOperation.NAMESPACE_LINK_UP, (plan.namespace, "lo")),
        NetworkCommand(
            NetworkOperation.NAMESPACE_LINK_UP,
            (plan.namespace, plan.namespace_veth),
        ),
        NetworkCommand(
            NetworkOperation.NAMESPACE_DEFAULT_ROUTE,
            (plan.namespace, plan.gateway_address, plan.namespace_veth),
        ),
        NetworkCommand(
            NetworkOperation.NAMESPACE_DNS_WRITE,
            (plan.namespace, *plan.dns_servers),
        ),
    )


def cleanup_commands(plan: NamespacePlan) -> tuple[NetworkCommand, ...]:
    return (
        NetworkCommand(NetworkOperation.NAMESPACE_DNS_DELETE, (plan.namespace,)),
        NetworkCommand(NetworkOperation.NAMESPACE_DELETE, (plan.namespace,)),
        NetworkCommand(NetworkOperation.VETH_DELETE, (plan.host_veth,)),
    )


class NamespaceManager:
    def __init__(
        self,
        executor: NetworkExecutor,
        *,
        command_timeout_seconds: float = DEFAULT_COMMAND_TIMEOUT_SECONDS,
    ) -> None:
        if command_timeout_seconds <= 0 or command_timeout_seconds > 120:
            raise ValueError("invalid_timeout")
        self._executor = executor
        self._command_timeout_seconds = command_timeout_seconds

    def create(self, plan: NamespacePlan) -> NamespacePlan:
        for command in creation_commands(plan):
            try:
                result = self._executor.run(
                    command, timeout_seconds=self._command_timeout_seconds
                )
            except Exception as exc:
                rollback = self.delete(plan)
                raise NamespaceOperationError(
                    "namespace_create_rollback_failed"
                    if rollback.failures
                    else "namespace_create_failed",
                    failed_operation=command.operation,
                    rollback_failures=rollback.failures,
                ) from exc
            if result.returncode != 0:
                rollback = self.delete(plan)
                raise NamespaceOperationError(
                    "namespace_create_rollback_failed"
                    if rollback.failures
                    else "namespace_create_failed",
                    failed_operation=command.operation,
                    rollback_failures=rollback.failures,
                )
        return plan

    def delete(self, plan: NamespacePlan) -> NamespaceCleanupReport:
        attempted: list[NetworkOperation] = []
        failures: list[NetworkOperation] = []
        for command in cleanup_commands(plan):
            attempted.append(command.operation)
            try:
                result = self._executor.run(
                    command, timeout_seconds=self._command_timeout_seconds
                )
            except Exception:
                failures.append(command.operation)
                continue
            if result.returncode != 0:
                failures.append(command.operation)
        return NamespaceCleanupReport(
            attempted=tuple(attempted),
            failures=tuple(failures),
        )
