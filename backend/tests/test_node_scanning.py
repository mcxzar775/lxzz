import asyncio
import socket
from typing import Any

import pytest

from app.services.network import CommandResult, NetworkCommand, NetworkOperation
from app.services.scanning.probe import ExitProbeError, NamespaceExitProbe
from app.models.enums import ScanStatus
from app.services.scanning.fast import (
    MockFastScanTransport,
    SocketFastScanTransport,
    build_fast_scan_transport,
)
from app.services.scanning.types import NodeScanTarget


def _target(*, protocol: str = "tcp") -> NodeScanTarget:
    return NodeScanTarget(
        node_id=9,
        host_name="vpn.example.test",
        ip_address="8.8.8.8",
        protocol=protocol,
        remote_port=1194,
        sanitized_config="client\n",
        advertised_ping_ms=42,
    )


def test_mock_scan_is_explicitly_marked() -> None:
    outcome = asyncio.run(MockFastScanTransport().scan(_target()))

    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.latency_ms == 42
    assert outcome.simulated is True


def test_real_tcp_scan_checks_dns_transport_and_ptr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class FakeConnection:
        def close(self) -> None:
            closed.append(True)

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 1194))
        ],
    )
    monkeypatch.setattr(
        socket, "create_connection", lambda *_args, **_kwargs: FakeConnection()
    )
    monkeypatch.setattr(
        socket, "gethostbyaddr", lambda _: ("dns.google.", [], ["8.8.8.8"])
    )

    outcome = asyncio.run(SocketFastScanTransport().scan(_target()))

    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.simulated is False
    assert outcome.safe_details["resolved_addresses"] == ["8.8.8.8"]
    assert outcome.safe_details["ptr"] == "dns.google"
    assert outcome.safe_details["transport_probe"] == "tcp_connect"
    assert closed == [True]


def test_real_scan_skips_dns_for_vpngate_short_hostname(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _target()
    target = NodeScanTarget(
        node_id=target.node_id,
        host_name="public-vpn-50",
        ip_address=target.ip_address,
        protocol=target.protocol,
        remote_port=target.remote_port,
        sanitized_config=target.sanitized_config,
        advertised_ping_ms=target.advertised_ping_ms,
    )

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("an unqualified VPNGate label must not be resolved")
        ),
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: type(
            "FakeConnection", (), {"close": lambda self: None}
        )(),
    )
    monkeypatch.setattr(socket, "gethostbyaddr", lambda _: ("dns.google", [], []))

    outcome = asyncio.run(SocketFastScanTransport().scan(target))

    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.safe_details["dns_checked"] is False
    assert outcome.safe_details["dns_skip_reason"] == "unqualified_host_name"
    assert outcome.safe_details["node_reachability_confirmed"] is True


def test_dns_mismatch_fails_before_transport_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("9.9.9.9", 1194))
        ],
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("transport probe must not run")
        ),
    )

    outcome = asyncio.run(SocketFastScanTransport().scan(_target()))

    assert outcome.status is ScanStatus.FAILED
    assert outcome.error_code == "dns_address_mismatch"


def test_transport_timeout_is_normalized_without_exception_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 1194))
        ],
    )
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            socket.timeout("private transport detail")
        ),
    )

    outcome = asyncio.run(SocketFastScanTransport().scan(_target()))

    assert outcome.status is ScanStatus.TIMEOUT
    assert outcome.error_code == "transport_timeout"
    assert "private" not in str(outcome.safe_details)


def test_udp_fast_scan_is_route_only_and_sends_no_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, Any]] = []

    class FakeUdpSocket:
        def settimeout(self, timeout: float) -> None:
            calls.append(("timeout", timeout))

        def connect(self, endpoint: tuple[str, int]) -> None:
            calls.append(("connect", endpoint))

        def getsockname(self) -> tuple[str, int]:
            return ("192.0.2.10", 45678)

        def close(self) -> None:
            calls.append(("close", True))

    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("8.8.8.8", 1194))
        ],
    )
    original_socket = socket.socket

    def fake_socket(
        family: int = socket.AF_INET,
        type: int = socket.SOCK_STREAM,
        proto: int = 0,
        fileno: int | None = None,
    ) -> socket.socket | FakeUdpSocket:
        if family == socket.AF_INET and type == socket.SOCK_DGRAM and fileno is None:
            return FakeUdpSocket()
        return original_socket(family, type, proto, fileno)

    monkeypatch.setattr(socket, "socket", fake_socket)
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda _: (_ for _ in ()).throw(OSError("no ptr")),
    )

    outcome = asyncio.run(SocketFastScanTransport().scan(_target(protocol="udp")))

    assert outcome.status is ScanStatus.SUCCEEDED
    assert outcome.safe_details["transport_probe"] == "udp_route"
    assert not any(name == "send" for name, _ in calls)


def test_real_scan_builder_requires_exact_environment_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_SCANS", "false")
    with pytest.raises(RuntimeError, match="VPNGATE_ENABLE_REAL_SCANS=true"):
        build_fast_scan_transport(
            enable_real_scans=True,
            connect_timeout_seconds=5,
            total_timeout_seconds=10,
        )

    monkeypatch.setenv("VPNGATE_ENABLE_REAL_SCANS", "true")
    assert isinstance(
        build_fast_scan_transport(
            enable_real_scans=True,
            connect_timeout_seconds=5,
            total_timeout_seconds=10,
        ),
        SocketFastScanTransport,
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"node_id": 0},
        {"ip_address": "127.0.0.1"},
        {"protocol": "icmp"},
        {"remote_port": 0},
    ],
)
def test_scan_target_rejects_unsafe_values(overrides: dict[str, object]) -> None:
    values: dict[str, object] = {
        "node_id": 9,
        "host_name": None,
        "ip_address": "8.8.8.8",
        "protocol": "tcp",
        "remote_port": 1194,
        "sanitized_config": "client\n",
    }
    values.update(overrides)

    with pytest.raises(ValueError, match="invalid_scan_target"):
        NodeScanTarget(**values)  # type: ignore[arg-type]


class ProbeExecutor:
    def __init__(self, *, output: str, returncode: int = 0) -> None:
        self.output = output
        self.returncode = returncode
        self.command: NetworkCommand | None = None

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        assert timeout_seconds == 60
        self.command = command
        return CommandResult(command, self.returncode, self.output, "")


def test_namespace_exit_probe_accepts_only_bounded_canonical_json() -> None:
    executor = ProbeExecutor(
        output=(
            '{"dns_ok":true,"download_bps":8000000,"exit_ip":"8.8.8.8",'
            '"https_ok":true,"latency_ms":12.5}'
        )
    )

    result = NamespaceExitProbe(executor).probe(7)

    assert result.exit_ip == "8.8.8.8"
    assert result.download_bps == 8_000_000
    assert executor.command is not None
    assert executor.command.operation is NetworkOperation.NODE_EXIT_PROBE
    assert executor.command.arguments == ("lxvpn-7", "7")


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        '{"exit_ip":"127.0.0.1","dns_ok":true,"https_ok":true,'
        '"latency_ms":1,"download_bps":1}',
        '{"exit_ip":"8.8.8.8","dns_ok":true,"https_ok":true,'
        '"latency_ms":1,"download_bps":1,"token":"private"}',
    ],
)
def test_namespace_exit_probe_rejects_invalid_or_extra_output(output: str) -> None:
    with pytest.raises(ExitProbeError, match="exit_probe_invalid_response"):
        NamespaceExitProbe(ProbeExecutor(output=output)).probe(7)
