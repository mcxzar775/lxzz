import ipaddress
from dataclasses import dataclass
from typing import Any, Literal

from app.models.enums import ScanStatus


ScanType = Literal["fast", "full"]


@dataclass(frozen=True)
class NodeScanTarget:
    node_id: int
    host_name: str | None
    ip_address: str
    protocol: str
    remote_port: int
    sanitized_config: str
    advertised_ping_ms: int | None = None

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.ip_address)
        except ValueError as exc:
            raise ValueError("invalid_scan_target") from exc
        if (
            isinstance(self.node_id, bool)
            or self.node_id <= 0
            or self.node_id > 2_147_483_647
            or not isinstance(address, ipaddress.IPv4Address)
            or not address.is_global
            or str(address) != self.ip_address
            or self.protocol not in {"tcp", "udp"}
            or isinstance(self.remote_port, bool)
            or not 1 <= self.remote_port <= 65535
            or not self.sanitized_config
            or "\x00" in self.sanitized_config
            or (
                self.host_name is not None
                and (not self.host_name or len(self.host_name) > 255)
            )
        ):
            raise ValueError("invalid_scan_target")


@dataclass(frozen=True)
class NodeScanOutcome:
    scan_type: ScanType
    status: ScanStatus
    latency_ms: float | None = None
    exit_ip: str | None = None
    error_code: str | None = None
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.latency_ms is not None and (
            self.latency_ms < 0 or self.latency_ms > 3_600_000
        ):
            raise ValueError("invalid_scan_outcome")
        if self.exit_ip is not None:
            try:
                address = ipaddress.ip_address(self.exit_ip)
            except ValueError as exc:
                raise ValueError("invalid_scan_outcome") from exc
            if not address.is_global or str(address) != self.exit_ip:
                raise ValueError("invalid_scan_outcome")
        if self.error_code is not None and (
            not self.error_code.isascii()
            or len(self.error_code) > 64
            or not self.error_code.replace("_", "").isalnum()
        ):
            raise ValueError("invalid_scan_outcome")

    @property
    def safe_details(self) -> dict[str, Any]:
        return dict(self.details or {})

    @property
    def simulated(self) -> bool:
        return self.safe_details.get("simulated") is True
