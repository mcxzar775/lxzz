import asyncio
import os
import socket
import time
from typing import Protocol

from app.models.enums import ScanStatus
from app.services.scanning.types import NodeScanOutcome, NodeScanTarget


class FastScanTransport(Protocol):
    async def scan(self, target: NodeScanTarget) -> NodeScanOutcome: ...


class MockFastScanTransport:
    """Deterministic development transport that never opens a network socket."""

    async def scan(self, target: NodeScanTarget) -> NodeScanOutcome:
        latency = (
            float(target.advertised_ping_ms)
            if target.advertised_ping_ms is not None
            else 0.0
        )
        return NodeScanOutcome(
            scan_type="fast",
            status=ScanStatus.SUCCEEDED,
            latency_ms=latency,
            details={
                "simulated": True,
                "dns_checked": False,
                "transport": target.protocol,
            },
        )


class SocketFastScanTransport:
    def __init__(
        self,
        *,
        connect_timeout_seconds: float = 15.0,
        total_timeout_seconds: float = 30.0,
    ) -> None:
        if not 0 < connect_timeout_seconds <= 60:
            raise ValueError("invalid_connect_timeout")
        if not connect_timeout_seconds <= total_timeout_seconds <= 120:
            raise ValueError("invalid_total_timeout")
        self._connect_timeout_seconds = connect_timeout_seconds
        self._total_timeout_seconds = total_timeout_seconds

    @staticmethod
    def _reverse_ptr(ip_address: str) -> str | None:
        try:
            value = socket.gethostbyaddr(ip_address)[0].rstrip(".")
        except (OSError, UnicodeError):
            return None
        if not value or len(value) > 255 or any(char.isspace() for char in value):
            return None
        return value

    def _resolve_host(self, target: NodeScanTarget) -> tuple[bool, list[str]]:
        if target.host_name is None:
            return False, []
        # VPNGate's HostName column is commonly an unqualified server label such
        # as ``public-vpn-50`` rather than a DNS name.  The feed's public IP is
        # already validated during parsing, so short labels must not prevent the
        # transport probe from using that address.  Keep the DNS/IP consistency
        # check for fully-qualified names supplied by other feed variants.
        if "." not in target.host_name.rstrip("."):
            return False, []
        socket_type = socket.SOCK_STREAM if target.protocol == "tcp" else socket.SOCK_DGRAM
        records = socket.getaddrinfo(
            target.host_name,
            target.remote_port,
            family=socket.AF_INET,
            type=socket_type,
        )
        addresses = sorted({str(record[4][0]) for record in records})
        if target.ip_address not in addresses:
            raise RuntimeError("dns_address_mismatch")
        return True, addresses[:16]

    def _probe_tcp(self, target: NodeScanTarget) -> float:
        started = time.monotonic()
        connection = socket.create_connection(
            (target.ip_address, target.remote_port),
            timeout=self._connect_timeout_seconds,
        )
        try:
            return (time.monotonic() - started) * 1000
        finally:
            connection.close()

    def _probe_udp_route(self, target: NodeScanTarget) -> float:
        started = time.monotonic()
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.settimeout(self._connect_timeout_seconds)
            probe.connect((target.ip_address, target.remote_port))
            local_address = probe.getsockname()[0]
            if local_address == "0.0.0.0":
                raise OSError("udp_route_unavailable")
            return (time.monotonic() - started) * 1000
        finally:
            probe.close()

    def _scan_sync(self, target: NodeScanTarget) -> NodeScanOutcome:
        try:
            dns_checked, resolved_addresses = self._resolve_host(target)
        except socket.gaierror:
            return NodeScanOutcome(
                scan_type="fast",
                status=ScanStatus.FAILED,
                error_code="dns_failed",
                details={"dns_checked": True, "transport": target.protocol},
            )
        except RuntimeError:
            return NodeScanOutcome(
                scan_type="fast",
                status=ScanStatus.FAILED,
                error_code="dns_address_mismatch",
                details={"dns_checked": True, "transport": target.protocol},
            )

        try:
            latency = (
                self._probe_tcp(target)
                if target.protocol == "tcp"
                else self._probe_udp_route(target)
            )
        except (TimeoutError, socket.timeout):
            return NodeScanOutcome(
                scan_type="fast",
                status=ScanStatus.TIMEOUT,
                error_code="transport_timeout",
                details={"dns_checked": dns_checked, "transport": target.protocol},
            )
        except OSError:
            return NodeScanOutcome(
                scan_type="fast",
                status=ScanStatus.FAILED,
                error_code="transport_unreachable",
                details={"dns_checked": dns_checked, "transport": target.protocol},
            )

        details: dict[str, object] = {
            "simulated": False,
            "dns_checked": dns_checked,
            "transport": target.protocol,
            "transport_probe": "tcp_connect"
            if target.protocol == "tcp"
            else "udp_route",
            "node_reachability_confirmed": target.protocol == "tcp",
        }
        if resolved_addresses:
            details["resolved_addresses"] = resolved_addresses
        elif target.host_name is not None:
            details["dns_skip_reason"] = "unqualified_host_name"
        ptr = self._reverse_ptr(target.ip_address)
        if ptr is not None:
            details["ptr"] = ptr
        return NodeScanOutcome(
            scan_type="fast",
            status=ScanStatus.SUCCEEDED,
            latency_ms=latency,
            details=details,
        )

    async def scan(self, target: NodeScanTarget) -> NodeScanOutcome:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._scan_sync, target),
                timeout=self._total_timeout_seconds,
            )
        except TimeoutError:
            return NodeScanOutcome(
                scan_type="fast",
                status=ScanStatus.TIMEOUT,
                error_code="scan_timeout",
                details={"transport": target.protocol, "simulated": False},
            )


def build_fast_scan_transport(
    *,
    enable_real_scans: bool,
    connect_timeout_seconds: float,
    total_timeout_seconds: float,
) -> FastScanTransport:
    if not enable_real_scans:
        return MockFastScanTransport()
    if os.getenv("VPNGATE_ENABLE_REAL_SCANS") != "true":
        raise RuntimeError(
            "real scans require VPNGATE_ENABLE_REAL_SCANS=true"
        )
    return SocketFastScanTransport(
        connect_timeout_seconds=connect_timeout_seconds,
        total_timeout_seconds=total_timeout_seconds,
    )
