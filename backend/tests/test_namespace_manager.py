from dataclasses import dataclass, field

import pytest

from app.services.network import (
    CommandResult,
    MAX_NAMESPACES,
    MockNetworkExecutor,
    NamespaceManager,
    NamespaceOperationError,
    NamespacePlanError,
    NetworkCommand,
    NetworkOperation,
    allocate_namespace_plan,
    build_ip_argv,
    cleanup_commands,
    creation_commands,
)


@dataclass
class ControlledExecutor:
    fail_on_call: int | None = None
    cleanup_failure: NetworkOperation | None = None
    commands: list[NetworkCommand] = field(default_factory=list)

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        assert 0 < timeout_seconds <= 120
        self.commands.append(command)
        call_number = len(self.commands)
        if self.fail_on_call == call_number:
            return CommandResult(command, 1, "", "simulated failure")
        if self.cleanup_failure is command.operation:
            return CommandResult(command, 1, "", "simulated cleanup failure")
        return CommandResult(command, 0, "mock", "")


def test_allocates_deterministic_non_overlapping_slash_30_subnets() -> None:
    first = allocate_namespace_plan(1)
    second = allocate_namespace_plan(2)
    final = allocate_namespace_plan(MAX_NAMESPACES)

    assert first.namespace == "lxvpn-1"
    assert first.host_veth == "lvh1"
    assert first.namespace_veth == "lvn1"
    assert first.subnet_cidr == "10.220.0.0/30"
    assert first.host_address_cidr == "10.220.0.1/30"
    assert first.namespace_address_cidr == "10.220.0.2/30"
    assert second.subnet_cidr == "10.220.0.4/30"
    assert final.subnet_cidr == "10.220.255.252/30"


@pytest.mark.parametrize("connection_id", [False, 0, -1])
def test_rejects_invalid_connection_identifier(connection_id: int) -> None:
    with pytest.raises(NamespacePlanError, match="invalid_connection_id"):
        allocate_namespace_plan(connection_id)


def test_rejects_namespace_pool_exhaustion() -> None:
    with pytest.raises(NamespacePlanError, match="namespace_capacity_exceeded"):
        allocate_namespace_plan(MAX_NAMESPACES + 1)


def test_create_runs_complete_fixed_operation_sequence_in_mock_mode() -> None:
    executor = MockNetworkExecutor()
    manager = NamespaceManager(executor)
    plan = allocate_namespace_plan(7)

    returned = manager.create(plan)

    assert returned == plan
    assert executor.commands == list(creation_commands(plan))
    assert [command.operation for command in executor.commands] == [
        NetworkOperation.NAMESPACE_CREATE,
        NetworkOperation.VETH_CREATE,
        NetworkOperation.VETH_MOVE,
        NetworkOperation.HOST_ADDRESS_ADD,
        NetworkOperation.NAMESPACE_ADDRESS_ADD,
        NetworkOperation.HOST_LINK_UP,
        NetworkOperation.NAMESPACE_LINK_UP,
        NetworkOperation.NAMESPACE_LINK_UP,
        NetworkOperation.NAMESPACE_DEFAULT_ROUTE,
        NetworkOperation.NAMESPACE_DNS_WRITE,
    ]


def test_default_route_is_scoped_to_namespace_not_host() -> None:
    plan = allocate_namespace_plan(3)
    argv_values = [
        build_ip_argv(command, ip_binary="/usr/sbin/ip")
        for command in creation_commands(plan)
    ]
    default_routes = [
        argv for argv in argv_values if argv is not None and "default" in argv
    ]

    assert default_routes == [
        (
            "/usr/sbin/ip",
            "-n",
            "lxvpn-3",
            "route",
            "replace",
            "default",
            "via",
            "10.220.0.9",
            "dev",
            "lvn3",
        )
    ]


def test_failure_triggers_reverse_resource_cleanup() -> None:
    executor = ControlledExecutor(fail_on_call=5)
    manager = NamespaceManager(executor)
    plan = allocate_namespace_plan(4)

    with pytest.raises(NamespaceOperationError) as captured:
        manager.create(plan)

    assert captured.value.code == "namespace_create_failed"
    assert captured.value.failed_operation is NetworkOperation.NAMESPACE_ADDRESS_ADD
    assert executor.commands[-3:] == list(cleanup_commands(plan))
    assert captured.value.rollback_failures == ()


def test_reports_cleanup_failure_without_leaking_command_output() -> None:
    executor = ControlledExecutor(
        fail_on_call=2,
        cleanup_failure=NetworkOperation.NAMESPACE_DELETE,
    )
    manager = NamespaceManager(executor)
    plan = allocate_namespace_plan(5)

    with pytest.raises(
        NamespaceOperationError, match="namespace_create_rollback_failed"
    ) as captured:
        manager.create(plan)

    assert captured.value.rollback_failures == (NetworkOperation.NAMESPACE_DELETE,)
    assert "simulated" not in str(captured.value)


def test_delete_is_repeatable_with_mock_executor() -> None:
    executor = MockNetworkExecutor()
    manager = NamespaceManager(executor)
    plan = allocate_namespace_plan(8)

    first = manager.delete(plan)
    second = manager.delete(plan)

    assert first.succeeded and second.succeeded
    assert first.attempted == tuple(
        command.operation for command in cleanup_commands(plan)
    )


def test_rejects_unsafe_dns_during_resource_planning() -> None:
    with pytest.raises(ValueError, match="invalid_dns_server"):
        allocate_namespace_plan(1, dns_servers=("127.0.0.1",))
