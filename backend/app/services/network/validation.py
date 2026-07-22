import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path


TUN_PATTERN = re.compile(r"^tun([1-9][0-9]{0,7})$")


class ResourceValidationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RemoteEndpoint:
    address: str
    port: int
    protocol: str


def tun_name(connection_id: int) -> str:
    if connection_id <= 0 or connection_id > 99_999_999:
        raise ResourceValidationError("invalid_resource_id")
    return f"tun{connection_id}"


def validate_tun_name(value: str) -> str:
    if len(value) > 15 or TUN_PATTERN.fullmatch(value) is None:
        raise ResourceValidationError("invalid_tun_name")
    return value


def validate_port(value: int, *, minimum: int = 1, maximum: int = 65535) -> int:
    if (
        isinstance(value, bool)
        or minimum < 1
        or maximum > 65535
        or minimum > maximum
        or value < minimum
        or value > maximum
    ):
        raise ResourceValidationError("invalid_port")
    return value


def validate_remote_endpoint(
    address: str,
    port: int,
    protocol: str,
) -> RemoteEndpoint:
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ResourceValidationError("invalid_remote_address") from exc
    if not parsed_address.is_global:
        raise ResourceValidationError("invalid_remote_address")
    normalized_protocol = protocol.lower()
    if normalized_protocol not in {"tcp", "udp"}:
        raise ResourceValidationError("invalid_protocol")
    return RemoteEndpoint(
        address=str(parsed_address),
        port=validate_port(port),
        protocol=normalized_protocol,
    )


def validate_managed_config_path(
    value: str | Path,
    *,
    directory: str | Path,
    node_id: int,
) -> Path:
    if node_id <= 0:
        raise ResourceValidationError("invalid_resource_id")
    root = Path(directory)
    candidate = Path(value)
    if (
        not root.is_absolute()
        or not candidate.is_absolute()
        or ".." in root.parts
        or ".." in candidate.parts
        or root.is_symlink()
        or candidate.is_symlink()
    ):
        raise ResourceValidationError("invalid_managed_path")
    expected = root / f"node-{node_id}.ovpn"
    if candidate != expected:
        raise ResourceValidationError("invalid_managed_path")
    return candidate
