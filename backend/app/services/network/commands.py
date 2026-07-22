import ipaddress
import re
from dataclasses import dataclass
from enum import Enum


INTERNAL_NETWORK = ipaddress.IPv4Network("10.220.0.0/16")
MAX_NAMESPACE_RESOURCES = INTERNAL_NETWORK.num_addresses // 4
NAMESPACE_PATTERN = re.compile(r"^lxvpn-([1-9][0-9]{0,7})$")
HOST_VETH_PATTERN = re.compile(r"^lvh([1-9][0-9]{0,7})$")
NAMESPACE_VETH_PATTERN = re.compile(r"^lvn([1-9][0-9]{0,7})$")
FIREWALL_BACKENDS = {"auto", "nftables", "iptables"}
UNLOCK_SERVICES = {"netflix", "chatgpt", "openai_api", "youtube"}


class CommandValidationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class NetworkOperation(str, Enum):
    SELF_TEST = "self-test"
    CONNECTION_PURGE = "connection-purge"
    NAMESPACE_CREATE = "namespace-create"
    NAMESPACE_DELETE = "namespace-delete"
    VETH_CREATE = "veth-create"
    VETH_DELETE = "veth-delete"
    VETH_MOVE = "veth-move"
    HOST_ADDRESS_ADD = "host-address-add"
    NAMESPACE_ADDRESS_ADD = "namespace-address-add"
    HOST_LINK_UP = "host-link-up"
    NAMESPACE_LINK_UP = "namespace-link-up"
    NAMESPACE_DEFAULT_ROUTE = "namespace-default-route"
    NAMESPACE_DNS_WRITE = "namespace-dns-write"
    NAMESPACE_DNS_DELETE = "namespace-dns-delete"
    OPENVPN_START = "openvpn-start"
    OPENVPN_STOP = "openvpn-stop"
    OPENVPN_STATUS = "openvpn-status"
    OPENVPN_TUN_READY = "openvpn-tun-ready"
    SOCKS5_START = "socks5-start"
    SOCKS5_STOP = "socks5-stop"
    SOCKS5_STATUS = "socks5-status"
    SOCKS5_READY = "socks5-ready"
    KILLSWITCH_APPLY = "killswitch-apply"
    KILLSWITCH_REMOVE = "killswitch-remove"
    KILLSWITCH_STATUS = "killswitch-status"
    NODE_EXIT_PROBE = "node-exit-probe"
    SERVICE_UNLOCK_PROBE = "service-unlock-probe"


@dataclass(frozen=True)
class NetworkCommand:
    operation: NetworkOperation
    arguments: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        validate_command(self)


def namespace_name(node_id: int) -> str:
    if node_id <= 0 or node_id > MAX_NAMESPACE_RESOURCES:
        raise CommandValidationError("invalid_resource_id")
    return f"lxvpn-{node_id}"


def host_veth_name(node_id: int) -> str:
    namespace_name(node_id)
    return f"lvh{node_id}"


def namespace_veth_name(node_id: int) -> str:
    namespace_name(node_id)
    return f"lvn{node_id}"


def _require_arguments(command: NetworkCommand, count: int) -> None:
    if len(command.arguments) != count:
        raise CommandValidationError("invalid_argument_count")


def _match_resource(pattern: re.Pattern[str], value: str, code: str) -> str:
    matched = pattern.fullmatch(value)
    if matched is None:
        raise CommandValidationError(code)
    identifier = matched.group(1)
    if int(identifier) > MAX_NAMESPACE_RESOURCES:
        raise CommandValidationError(code)
    return identifier


def _validate_namespace(value: str) -> str:
    return _match_resource(NAMESPACE_PATTERN, value, "invalid_namespace")


def _validate_host_veth(value: str) -> str:
    if len(value) > 15:
        raise CommandValidationError("invalid_interface")
    return _match_resource(HOST_VETH_PATTERN, value, "invalid_interface")


def _validate_namespace_veth(value: str) -> str:
    if len(value) > 15:
        raise CommandValidationError("invalid_interface")
    return _match_resource(NAMESPACE_VETH_PATTERN, value, "invalid_interface")


def _validate_interface_address(value: str) -> None:
    try:
        interface = ipaddress.ip_interface(value)
    except ValueError as exc:
        raise CommandValidationError("invalid_interface_address") from exc
    if (
        not isinstance(interface, ipaddress.IPv4Interface)
        or interface.network.prefixlen != 30
        or not interface.network.subnet_of(INTERNAL_NETWORK)
        or interface.ip in {interface.network.network_address, interface.network.broadcast_address}
    ):
        raise CommandValidationError("invalid_interface_address")


def _allocated_addresses(identifier: str) -> tuple[str, str, str]:
    network_address = int(INTERNAL_NETWORK.network_address) + (int(identifier) - 1) * 4
    subnet = ipaddress.IPv4Network((network_address, 30))
    host_address, namespace_address = tuple(subnet.hosts())
    return f"{host_address}/30", f"{namespace_address}/30", str(host_address)


def _validate_gateway(value: str) -> None:
    try:
        gateway = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CommandValidationError("invalid_gateway") from exc
    if not isinstance(gateway, ipaddress.IPv4Address) or gateway not in INTERNAL_NETWORK:
        raise CommandValidationError("invalid_gateway")


def _validate_dns_server(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CommandValidationError("invalid_dns_server") from exc
    if not address.is_global or str(address) != value:
        raise CommandValidationError("invalid_dns_server")


def _require_same_resource(*identifiers: str) -> None:
    if len(set(identifiers)) != 1:
        raise CommandValidationError("resource_mismatch")


def _validate_decimal_identifier(value: str, *, maximum: int) -> str:
    if not value.isascii() or not value.isdecimal():
        raise CommandValidationError("invalid_resource_id")
    identifier = int(value, 10)
    if identifier <= 0 or identifier > maximum or str(identifier) != value:
        raise CommandValidationError("invalid_resource_id")
    return value


def _validate_decimal_port(value: str) -> str:
    _validate_decimal_identifier(value, maximum=65535)
    if int(value, 10) < 1024:
        raise CommandValidationError("invalid_port")
    return value


def _validate_optional_decimal_port(value: str) -> str:
    if value == "-":
        return value
    return _validate_decimal_port(value)


def _validate_firewall_remote(address: str, port: str, protocol: str) -> None:
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise CommandValidationError("invalid_remote_address") from exc
    if (
        not isinstance(parsed_address, ipaddress.IPv4Address)
        or not parsed_address.is_global
        or str(parsed_address) != address
    ):
        raise CommandValidationError("invalid_remote_address")
    _validate_decimal_identifier(port, maximum=65535)
    if protocol not in {"tcp", "udp"}:
        raise CommandValidationError("invalid_protocol")


def _validate_firewall_allowlist(value: str) -> None:
    if value == "-":
        return
    if len(value) > 4096:
        raise CommandValidationError("invalid_client_ip_allowlist")
    entries = value.split(",")
    if not entries or len(entries) > 64 or len(set(entries)) != len(entries):
        raise CommandValidationError("invalid_client_ip_allowlist")
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError as exc:
            raise CommandValidationError("invalid_client_ip_allowlist") from exc
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or str(network) != entry
            or network.network_address.is_unspecified
            or network.network_address.is_multicast
            or network.network_address.is_loopback
            or network.network_address.is_link_local
        ):
            raise CommandValidationError("invalid_client_ip_allowlist")


def validate_command(command: NetworkCommand) -> None:
    if not isinstance(command.operation, NetworkOperation):
        raise CommandValidationError("invalid_operation")
    operation = command.operation
    if operation is NetworkOperation.SELF_TEST:
        _require_arguments(command, 0)
        return
    if operation is NetworkOperation.CONNECTION_PURGE:
        _require_arguments(command, 1)
        _validate_decimal_identifier(
            command.arguments[0], maximum=MAX_NAMESPACE_RESOURCES
        )
        return
    if operation in {NetworkOperation.NAMESPACE_CREATE, NetworkOperation.NAMESPACE_DELETE}:
        _require_arguments(command, 1)
        _validate_namespace(command.arguments[0])
        return
    if operation is NetworkOperation.VETH_CREATE:
        _require_arguments(command, 2)
        host_id = _validate_host_veth(command.arguments[0])
        peer_id = _validate_namespace_veth(command.arguments[1])
        _require_same_resource(host_id, peer_id)
        return
    if operation is NetworkOperation.VETH_DELETE:
        _require_arguments(command, 1)
        _validate_host_veth(command.arguments[0])
        return
    if operation is NetworkOperation.VETH_MOVE:
        _require_arguments(command, 2)
        peer_id = _validate_namespace_veth(command.arguments[0])
        namespace_id = _validate_namespace(command.arguments[1])
        _require_same_resource(peer_id, namespace_id)
        return
    if operation is NetworkOperation.HOST_ADDRESS_ADD:
        _require_arguments(command, 2)
        _validate_interface_address(command.arguments[0])
        host_id = _validate_host_veth(command.arguments[1])
        expected_host_address, _, _ = _allocated_addresses(host_id)
        if command.arguments[0] != expected_host_address:
            raise CommandValidationError("resource_mismatch")
        return
    if operation is NetworkOperation.NAMESPACE_ADDRESS_ADD:
        _require_arguments(command, 3)
        namespace_id = _validate_namespace(command.arguments[0])
        _validate_interface_address(command.arguments[1])
        peer_id = _validate_namespace_veth(command.arguments[2])
        _require_same_resource(namespace_id, peer_id)
        _, expected_namespace_address, _ = _allocated_addresses(namespace_id)
        if command.arguments[1] != expected_namespace_address:
            raise CommandValidationError("resource_mismatch")
        return
    if operation is NetworkOperation.HOST_LINK_UP:
        _require_arguments(command, 1)
        _validate_host_veth(command.arguments[0])
        return
    if operation is NetworkOperation.NAMESPACE_LINK_UP:
        _require_arguments(command, 2)
        namespace_id = _validate_namespace(command.arguments[0])
        interface = command.arguments[1]
        if interface != "lo":
            peer_id = _validate_namespace_veth(interface)
            _require_same_resource(namespace_id, peer_id)
        return
    if operation is NetworkOperation.NAMESPACE_DEFAULT_ROUTE:
        _require_arguments(command, 3)
        namespace_id = _validate_namespace(command.arguments[0])
        _validate_gateway(command.arguments[1])
        peer_id = _validate_namespace_veth(command.arguments[2])
        _require_same_resource(namespace_id, peer_id)
        _, _, expected_gateway = _allocated_addresses(namespace_id)
        if command.arguments[1] != expected_gateway:
            raise CommandValidationError("resource_mismatch")
        return
    if operation is NetworkOperation.NAMESPACE_DNS_WRITE:
        if len(command.arguments) < 2 or len(command.arguments) > 4:
            raise CommandValidationError("invalid_argument_count")
        _validate_namespace(command.arguments[0])
        for server in command.arguments[1:]:
            _validate_dns_server(server)
        if len(set(command.arguments[1:])) != len(command.arguments[1:]):
            raise CommandValidationError("duplicate_dns_server")
        return
    if operation is NetworkOperation.NAMESPACE_DNS_DELETE:
        _require_arguments(command, 1)
        _validate_namespace(command.arguments[0])
        return
    if operation is NetworkOperation.OPENVPN_START:
        _require_arguments(command, 3)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _validate_decimal_identifier(command.arguments[2], maximum=2_147_483_647)
        _require_same_resource(namespace_id, connection_id)
        return
    if operation in {NetworkOperation.OPENVPN_STOP, NetworkOperation.OPENVPN_STATUS}:
        _require_arguments(command, 1)
        _validate_decimal_identifier(
            command.arguments[0], maximum=MAX_NAMESPACE_RESOURCES
        )
        return
    if operation is NetworkOperation.OPENVPN_TUN_READY:
        _require_arguments(command, 2)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _require_same_resource(namespace_id, connection_id)
        return
    if operation is NetworkOperation.SOCKS5_START:
        _require_arguments(command, 3)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _validate_decimal_identifier(command.arguments[2], maximum=2_147_483_647)
        _require_same_resource(namespace_id, connection_id)
        return
    if operation in {NetworkOperation.SOCKS5_STOP, NetworkOperation.SOCKS5_STATUS}:
        _require_arguments(command, 1)
        _validate_decimal_identifier(
            command.arguments[0], maximum=MAX_NAMESPACE_RESOURCES
        )
        return
    if operation is NetworkOperation.SOCKS5_READY:
        _require_arguments(command, 3)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _validate_decimal_port(command.arguments[2])
        _require_same_resource(namespace_id, connection_id)
        return
    if operation is NetworkOperation.KILLSWITCH_APPLY:
        _require_arguments(command, 9)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _require_same_resource(namespace_id, connection_id)
        _validate_decimal_identifier(command.arguments[2], maximum=2_147_483_647)
        _validate_firewall_remote(
            command.arguments[3], command.arguments[4], command.arguments[5]
        )
        _validate_optional_decimal_port(command.arguments[6])
        if command.arguments[7] not in FIREWALL_BACKENDS:
            raise CommandValidationError("invalid_firewall_backend")
        _validate_firewall_allowlist(command.arguments[8])
        return
    if operation in {
        NetworkOperation.KILLSWITCH_REMOVE,
        NetworkOperation.KILLSWITCH_STATUS,
        NetworkOperation.NODE_EXIT_PROBE,
    }:
        _require_arguments(command, 2)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _require_same_resource(namespace_id, connection_id)
        return
    if operation is NetworkOperation.SERVICE_UNLOCK_PROBE:
        _require_arguments(command, 3)
        namespace_id = _validate_namespace(command.arguments[0])
        connection_id = _validate_decimal_identifier(
            command.arguments[1], maximum=MAX_NAMESPACE_RESOURCES
        )
        _require_same_resource(namespace_id, connection_id)
        if command.arguments[2] not in UNLOCK_SERVICES:
            raise CommandValidationError("invalid_unlock_service")
        return
    raise CommandValidationError("invalid_operation")


def build_ip_argv(command: NetworkCommand, *, ip_binary: str) -> tuple[str, ...] | None:
    validate_command(command)
    args = command.arguments
    operation = command.operation
    if operation in {
        NetworkOperation.SELF_TEST,
        NetworkOperation.CONNECTION_PURGE,
        NetworkOperation.NAMESPACE_DNS_WRITE,
        NetworkOperation.NAMESPACE_DNS_DELETE,
        NetworkOperation.OPENVPN_START,
        NetworkOperation.OPENVPN_STOP,
        NetworkOperation.OPENVPN_STATUS,
        NetworkOperation.OPENVPN_TUN_READY,
        NetworkOperation.SOCKS5_START,
        NetworkOperation.SOCKS5_STOP,
        NetworkOperation.SOCKS5_STATUS,
        NetworkOperation.SOCKS5_READY,
        NetworkOperation.KILLSWITCH_APPLY,
        NetworkOperation.KILLSWITCH_REMOVE,
        NetworkOperation.KILLSWITCH_STATUS,
        NetworkOperation.NODE_EXIT_PROBE,
        NetworkOperation.SERVICE_UNLOCK_PROBE,
    }:
        return None
    if operation is NetworkOperation.NAMESPACE_CREATE:
        return (ip_binary, "netns", "add", args[0])
    if operation is NetworkOperation.NAMESPACE_DELETE:
        return (ip_binary, "netns", "delete", args[0])
    if operation is NetworkOperation.VETH_CREATE:
        return (ip_binary, "link", "add", args[0], "type", "veth", "peer", "name", args[1])
    if operation is NetworkOperation.VETH_DELETE:
        return (ip_binary, "link", "delete", args[0])
    if operation is NetworkOperation.VETH_MOVE:
        return (ip_binary, "link", "set", args[0], "netns", args[1])
    if operation is NetworkOperation.HOST_ADDRESS_ADD:
        return (ip_binary, "address", "add", args[0], "dev", args[1])
    if operation is NetworkOperation.NAMESPACE_ADDRESS_ADD:
        return (ip_binary, "-n", args[0], "address", "add", args[1], "dev", args[2])
    if operation is NetworkOperation.HOST_LINK_UP:
        return (ip_binary, "link", "set", args[0], "up")
    if operation is NetworkOperation.NAMESPACE_LINK_UP:
        return (ip_binary, "-n", args[0], "link", "set", args[1], "up")
    if operation is NetworkOperation.NAMESPACE_DEFAULT_ROUTE:
        return (
            ip_binary,
            "-n",
            args[0],
            "route",
            "replace",
            "default",
            "via",
            args[1],
            "dev",
            args[2],
        )
    raise CommandValidationError("invalid_operation")
