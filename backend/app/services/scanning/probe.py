import ipaddress
import json
from dataclasses import dataclass

from app.services.network.commands import NetworkCommand, NetworkOperation, namespace_name
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor


class ExitProbeError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ExitProbeResult:
    exit_ip: str
    latency_ms: float
    download_bps: int
    dns_ok: bool
    https_ok: bool


class NamespaceExitProbe:
    def __init__(
        self,
        executor: NetworkExecutor,
        *,
        allow_real_full_scans: bool = False,
        timeout_seconds: float = 60.0,
    ) -> None:
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("invalid_probe_timeout")
        self._executor = executor
        self._allow_real_full_scans = allow_real_full_scans
        self._timeout_seconds = timeout_seconds

    @staticmethod
    def _command(resource_id: int) -> NetworkCommand:
        return NetworkCommand(
            NetworkOperation.NODE_EXIT_PROBE,
            (namespace_name(resource_id), str(resource_id)),
        )

    @staticmethod
    def _parse_output(output: str) -> ExitProbeResult:
        if len(output.encode("utf-8")) > 4096:
            raise ExitProbeError("exit_probe_invalid_response")
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            raise ExitProbeError("exit_probe_invalid_response") from exc
        if (
            not isinstance(payload, dict)
            or set(payload)
            != {"dns_ok", "download_bps", "exit_ip", "https_ok", "latency_ms"}
            or payload.get("dns_ok") is not True
            or payload.get("https_ok") is not True
            or isinstance(payload.get("latency_ms"), bool)
            or not isinstance(payload.get("latency_ms"), (int, float))
            or not 0 <= payload["latency_ms"] <= 120_000
            or isinstance(payload.get("download_bps"), bool)
            or not isinstance(payload.get("download_bps"), int)
            or not 0 <= payload["download_bps"] <= 100_000_000_000
            or not isinstance(payload.get("exit_ip"), str)
        ):
            raise ExitProbeError("exit_probe_invalid_response")
        try:
            address = ipaddress.ip_address(payload["exit_ip"])
        except ValueError as exc:
            raise ExitProbeError("exit_probe_invalid_response") from exc
        if not address.is_global or str(address) != payload["exit_ip"]:
            raise ExitProbeError("exit_probe_invalid_response")
        return ExitProbeResult(
            exit_ip=payload["exit_ip"],
            latency_ms=float(payload["latency_ms"]),
            download_bps=payload["download_bps"],
            dns_ok=True,
            https_ok=True,
        )

    def probe(self, resource_id: int) -> ExitProbeResult:
        if isinstance(self._executor, RealNetworkExecutor) and not self._allow_real_full_scans:
            raise ExitProbeError(
                "real exit probe requires VPNGATE_ENABLE_REAL_FULL_SCANS=true"
            )
        try:
            result = self._executor.run(
                self._command(resource_id),
                timeout_seconds=self._timeout_seconds,
            )
        except Exception as exc:
            raise ExitProbeError("exit_probe_command_failed") from exc
        if result.returncode == 3:
            raise ExitProbeError("exit_probe_tunnel_not_ready")
        if result.returncode != 0:
            raise ExitProbeError("exit_probe_failed")
        return self._parse_output(result.stdout.strip())
