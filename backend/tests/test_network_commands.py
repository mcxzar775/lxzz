import pytest

from app.services.network.commands import (
    CommandValidationError,
    NetworkCommand,
    NetworkOperation,
    build_ip_argv,
    host_veth_name,
    namespace_name,
    namespace_veth_name,
)


def test_generates_bounded_project_resource_names() -> None:
    assert namespace_name(42) == "lxvpn-42"
    assert host_veth_name(42) == "lvh42"
    assert namespace_veth_name(42) == "lvn42"

    with pytest.raises(CommandValidationError, match="invalid_resource_id"):
        namespace_name(0)


def test_connection_purge_accepts_only_a_canonical_managed_id() -> None:
    command = NetworkCommand(NetworkOperation.CONNECTION_PURGE, ("42",))
    assert build_ip_argv(command, ip_binary="/usr/sbin/ip") is None

    for unsafe in ("0", "01", "1;id", "lxvpn-1", "../1"):
        with pytest.raises(CommandValidationError):
            NetworkCommand(NetworkOperation.CONNECTION_PURGE, (unsafe,))


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (
            NetworkCommand(NetworkOperation.NAMESPACE_CREATE, ("lxvpn-7",)),
            ("/usr/sbin/ip", "netns", "add", "lxvpn-7"),
        ),
        (
            NetworkCommand(NetworkOperation.VETH_CREATE, ("lvh7", "lvn7")),
            (
                "/usr/sbin/ip",
                "link",
                "add",
                "lvh7",
                "type",
                "veth",
                "peer",
                "name",
                "lvn7",
            ),
        ),
        (
            NetworkCommand(
                NetworkOperation.NAMESPACE_DEFAULT_ROUTE,
                ("lxvpn-7", "10.220.0.25", "lvn7"),
            ),
            (
                "/usr/sbin/ip",
                "-n",
                "lxvpn-7",
                "route",
                "replace",
                "default",
                "via",
                "10.220.0.25",
                "dev",
                "lvn7",
            ),
        ),
    ],
)
def test_maps_validated_operations_to_fixed_ip_argv(
    command: NetworkCommand, expected: tuple[str, ...]
) -> None:
    assert build_ip_argv(command, ip_binary="/usr/sbin/ip") == expected


@pytest.mark.parametrize(
    "untrusted_name",
    [
        "lxvpn-1;id",
        "lxvpn-1 --help",
        "../lxvpn-1",
        "lxvpn-0",
        "other-1",
        "lxvpn-１２",
    ],
)
def test_rejects_namespace_command_injection(untrusted_name: str) -> None:
    with pytest.raises(CommandValidationError, match="invalid_namespace"):
        NetworkCommand(NetworkOperation.NAMESPACE_CREATE, (untrusted_name,))


def test_rejects_mismatched_resource_identifiers() -> None:
    with pytest.raises(CommandValidationError, match="resource_mismatch"):
        NetworkCommand(NetworkOperation.VETH_CREATE, ("lvh1", "lvn2"))


@pytest.mark.parametrize(
    "address",
    ["8.8.8.8/30", "10.220.0.1/24", "10.220.0.0/30", "10.220.0.3/30"],
)
def test_rejects_address_outside_allocated_internal_host_range(address: str) -> None:
    with pytest.raises(CommandValidationError, match="invalid_interface_address"):
        NetworkCommand(NetworkOperation.HOST_ADDRESS_ADD, (address, "lvh1"))


def test_accepts_only_matching_namespace_link_resources() -> None:
    command = NetworkCommand(
        NetworkOperation.NAMESPACE_ADDRESS_ADD,
        ("lxvpn-3", "10.220.0.10/30", "lvn3"),
    )

    assert command.arguments[2] == "lvn3"


@pytest.mark.parametrize(
    "command",
    [
        (NetworkOperation.HOST_ADDRESS_ADD, ("10.220.0.5/30", "lvh1")),
        (
            NetworkOperation.NAMESPACE_ADDRESS_ADD,
            ("lxvpn-1", "10.220.0.6/30", "lvn1"),
        ),
        (
            NetworkOperation.NAMESPACE_DEFAULT_ROUTE,
            ("lxvpn-1", "10.220.0.5", "lvn1"),
        ),
    ],
)
def test_rejects_address_from_another_resource_subnet(
    command: tuple[NetworkOperation, tuple[str, ...]],
) -> None:
    with pytest.raises(CommandValidationError, match="resource_mismatch"):
        NetworkCommand(*command)


def test_self_test_never_maps_to_an_external_command() -> None:
    command = NetworkCommand(NetworkOperation.SELF_TEST)

    assert build_ip_argv(command, ip_binary="/untrusted/ip") is None


def test_dns_operation_is_validated_but_not_mapped_to_ip_command() -> None:
    command = NetworkCommand(
        NetworkOperation.NAMESPACE_DNS_WRITE,
        ("lxvpn-1", "1.1.1.1", "8.8.8.8"),
    )

    assert build_ip_argv(command, ip_binary="/usr/sbin/ip") is None


@pytest.mark.parametrize(
    "arguments",
    [
        ("lxvpn-1", "127.0.0.1"),
        ("lxvpn-1", "1.1.1.1", "1.1.1.1"),
        ("lxvpn-1;id", "1.1.1.1"),
        ("lxvpn-1", "1.1.1.1\noptions rotate"),
    ],
)
def test_rejects_unsafe_namespace_dns_arguments(arguments: tuple[str, ...]) -> None:
    with pytest.raises(CommandValidationError):
        NetworkCommand(NetworkOperation.NAMESPACE_DNS_WRITE, arguments)


def test_validates_fixed_openvpn_operations() -> None:
    start = NetworkCommand(
        NetworkOperation.OPENVPN_START,
        ("lxvpn-7", "7", "99"),
    )
    ready = NetworkCommand(
        NetworkOperation.OPENVPN_TUN_READY,
        ("lxvpn-7", "7"),
    )

    assert build_ip_argv(start, ip_binary="/usr/sbin/ip") is None
    assert build_ip_argv(ready, ip_binary="/usr/sbin/ip") is None


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        (NetworkOperation.OPENVPN_START, ("lxvpn-1", "2", "3")),
        (NetworkOperation.OPENVPN_START, ("lxvpn-1", "1", "../3")),
        (NetworkOperation.OPENVPN_START, ("lxvpn-1", "01", "3")),
        (NetworkOperation.OPENVPN_STOP, ("1;id",)),
        (NetworkOperation.OPENVPN_STATUS, ("0",)),
        (NetworkOperation.OPENVPN_TUN_READY, ("lxvpn-2", "1")),
    ],
)
def test_rejects_injected_or_mismatched_openvpn_identifiers(
    operation: NetworkOperation,
    arguments: tuple[str, ...],
) -> None:
    with pytest.raises(CommandValidationError):
        NetworkCommand(operation, arguments)


def test_validates_fixed_socks_operations_without_credentials() -> None:
    start = NetworkCommand(
        NetworkOperation.SOCKS5_START,
        ("lxvpn-7", "7", "99"),
    )
    ready = NetworkCommand(
        NetworkOperation.SOCKS5_READY,
        ("lxvpn-7", "7", "21007"),
    )

    assert build_ip_argv(start, ip_binary="/usr/sbin/ip") is None
    assert build_ip_argv(ready, ip_binary="/usr/sbin/ip") is None
    assert len(start.arguments) == 3


@pytest.mark.parametrize(
    ("operation", "arguments"),
    [
        (NetworkOperation.SOCKS5_START, ("lxvpn-1", "2", "3")),
        (NetworkOperation.SOCKS5_START, ("lxvpn-1", "1", "../3")),
        (NetworkOperation.SOCKS5_STOP, ("1;id",)),
        (NetworkOperation.SOCKS5_STATUS, ("0",)),
        (NetworkOperation.SOCKS5_READY, ("lxvpn-2", "1", "21000")),
        (NetworkOperation.SOCKS5_READY, ("lxvpn-1", "1", "22;id")),
    ],
)
def test_rejects_injected_or_mismatched_socks_identifiers(
    operation: NetworkOperation,
    arguments: tuple[str, ...],
) -> None:
    with pytest.raises(CommandValidationError):
        NetworkCommand(operation, arguments)


def test_validates_fixed_killswitch_operation() -> None:
    command = NetworkCommand(
        NetworkOperation.KILLSWITCH_APPLY,
        (
            "lxvpn-7",
            "7",
            "99",
            "8.8.8.8",
            "443",
            "tcp",
            "21007",
            "auto",
            "198.51.100.7/32,203.0.113.0/24",
        ),
    )

    assert build_ip_argv(command, ip_binary="/usr/sbin/ip") is None

    scan_only = NetworkCommand(
        NetworkOperation.KILLSWITCH_APPLY,
        ("lxvpn-7", "7", "99", "8.8.8.8", "443", "tcp", "-", "auto", "-"),
    )
    assert build_ip_argv(scan_only, ip_binary="/usr/sbin/ip") is None

    exit_probe = NetworkCommand(
        NetworkOperation.NODE_EXIT_PROBE,
        ("lxvpn-7", "7"),
    )
    assert build_ip_argv(exit_probe, ip_binary="/usr/sbin/ip") is None

    unlock_probe = NetworkCommand(
        NetworkOperation.SERVICE_UNLOCK_PROBE,
        ("lxvpn-7", "7", "netflix"),
    )
    assert build_ip_argv(unlock_probe, ip_binary="/usr/sbin/ip") is None


@pytest.mark.parametrize(
    "arguments",
    [
        ("lxvpn-1", "2", "netflix"),
        ("lxvpn-1;id", "1", "netflix"),
        ("lxvpn-1", "1", "netflix;id"),
        ("lxvpn-1", "1", "arbitrary_url"),
        ("lxvpn-1", "1", "netflix", "extra"),
    ],
)
def test_unlock_probe_accepts_only_fixed_service_names(
    arguments: tuple[str, ...],
) -> None:
    with pytest.raises(CommandValidationError):
        NetworkCommand(NetworkOperation.SERVICE_UNLOCK_PROBE, arguments)


@pytest.mark.parametrize(
    "arguments",
    [
        ("lxvpn-1", "2", "3", "8.8.8.8", "443", "tcp", "21001", "auto", "-"),
        ("lxvpn-1", "1", "../3", "8.8.8.8", "443", "tcp", "21001", "auto", "-"),
        ("lxvpn-1", "1", "3", "8.8.8.8;id", "443", "tcp", "21001", "auto", "-"),
        ("lxvpn-1", "1", "3", "8.8.8.8", "443;id", "tcp", "21001", "auto", "-"),
        ("lxvpn-1", "1", "3", "8.8.8.8", "443", "icmp", "21001", "auto", "-"),
        ("lxvpn-1", "1", "3", "8.8.8.8", "443", "tcp", "22", "auto", "-"),
        ("lxvpn-1", "1", "3", "8.8.8.8", "443", "tcp", "21001", "mixed", "-"),
        (
            "lxvpn-1",
            "1",
            "3",
            "8.8.8.8",
            "443",
            "tcp",
            "21001",
            "auto",
            "203.0.113.7;accept",
        ),
    ],
)
def test_rejects_injected_killswitch_arguments(arguments: tuple[str, ...]) -> None:
    with pytest.raises(CommandValidationError):
        NetworkCommand(NetworkOperation.KILLSWITCH_APPLY, arguments)
