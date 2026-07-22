import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from app.services.network.commands import NetworkCommand, NetworkOperation, namespace_name
from app.services.network.executor import NetworkExecutor, RealNetworkExecutor
from app.services.vpngate.openvpn import validate_stored_openvpn_config
from app.services.vpngate.storage import SecureConfigStore
from app.services.vpngate.types import OpenVPNConfigError


class OpenVPNOperationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class OpenVPNRuntime:
    connection_id: int
    node_id: int
    namespace: str
    tun_device: str
    running: bool
    pid: int | None


class OpenVPNManager:
    def __init__(
        self,
        executor: NetworkExecutor,
        config_store: SecureConfigStore,
        *,
        allow_real_openvpn: bool = False,
        tun_timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 0.5,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if tun_timeout_seconds <= 0 or tun_timeout_seconds > 120:
            raise ValueError("invalid_tun_timeout")
        if poll_interval_seconds <= 0 or poll_interval_seconds > tun_timeout_seconds:
            raise ValueError("invalid_poll_interval")
        self._executor = executor
        self._allow_real_openvpn = allow_real_openvpn
        self._config_store = config_store
        self._tun_timeout_seconds = tun_timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._clock = clock
        self._sleeper = sleeper

    @staticmethod
    def _start_command(connection_id: int, node_id: int) -> NetworkCommand:
        return NetworkCommand(
            NetworkOperation.OPENVPN_START,
            (namespace_name(connection_id), str(connection_id), str(node_id)),
        )

    @staticmethod
    def _stop_command(connection_id: int) -> NetworkCommand:
        return NetworkCommand(NetworkOperation.OPENVPN_STOP, (str(connection_id),))

    @staticmethod
    def _status_command(connection_id: int) -> NetworkCommand:
        return NetworkCommand(NetworkOperation.OPENVPN_STATUS, (str(connection_id),))

    @staticmethod
    def _tun_ready_command(connection_id: int) -> NetworkCommand:
        return NetworkCommand(
            NetworkOperation.OPENVPN_TUN_READY,
            (namespace_name(connection_id), str(connection_id)),
        )

    def _run(self, command: NetworkCommand, *, timeout_seconds: float = 20.0) -> int:
        if isinstance(self._executor, RealNetworkExecutor) and not self._allow_real_openvpn:
            raise OpenVPNOperationError(
                "real OpenVPN execution requires VPNGATE_ENABLE_REAL_OPENVPN=true"
            )
        try:
            result = self._executor.run(command, timeout_seconds=timeout_seconds)
        except Exception as exc:
            raise OpenVPNOperationError("openvpn_command_failed") from exc
        return result.returncode

    def _rollback_stop(self, connection_id: int) -> bool:
        try:
            return self._run(self._stop_command(connection_id)) == 0
        except OpenVPNOperationError:
            return False

    def _raise_after_rollback(self, connection_id: int, code: str) -> None:
        if not self._rollback_stop(connection_id):
            raise OpenVPNOperationError(f"{code}_cleanup_failed")
        raise OpenVPNOperationError(code)

    def stage_config(self, node_id: int, sanitized_config: str) -> Path:
        """Validate and persist a node config before installing its kill switch."""
        if isinstance(node_id, bool) or node_id <= 0 or node_id > 2_147_483_647:
            raise OpenVPNOperationError("invalid_node_id")
        try:
            validate_stored_openvpn_config(sanitized_config.encode("utf-8"))
        except (OpenVPNConfigError, UnicodeEncodeError) as exc:
            raise OpenVPNOperationError("openvpn_config_invalid") from exc
        return self._config_store.write(node_id, sanitized_config)

    def status(self, connection_id: int, *, node_id: int) -> OpenVPNRuntime:
        if isinstance(node_id, bool) or node_id <= 0:
            raise OpenVPNOperationError("invalid_node_id")
        command = self._status_command(connection_id)
        if isinstance(self._executor, RealNetworkExecutor) and not self._allow_real_openvpn:
            raise OpenVPNOperationError(
                "real OpenVPN execution requires VPNGATE_ENABLE_REAL_OPENVPN=true"
            )
        try:
            result = self._executor.run(command, timeout_seconds=10.0)
        except Exception as exc:
            raise OpenVPNOperationError("openvpn_status_failed") from exc
        if result.returncode not in {0, 3}:
            raise OpenVPNOperationError("openvpn_status_failed")
        raw_pid = result.stdout.strip()
        parsed_pid = int(raw_pid) if raw_pid.isascii() and raw_pid.isdecimal() else 0
        pid = parsed_pid if 1 < parsed_pid <= 2_147_483_647 else None
        return OpenVPNRuntime(
            connection_id=connection_id,
            node_id=node_id,
            namespace=namespace_name(connection_id),
            tun_device="tun0",
            running=result.returncode == 0,
            pid=pid,
        )

    def stop(self, connection_id: int, *, node_id: int) -> OpenVPNRuntime:
        if self._run(self._stop_command(connection_id)) != 0:
            raise OpenVPNOperationError("openvpn_stop_failed")
        return self.status(connection_id, node_id=node_id)

    def start(
        self,
        connection_id: int,
        *,
        node_id: int,
        sanitized_config: str,
    ) -> OpenVPNRuntime:
        start_command = self._start_command(connection_id, node_id)
        self.stage_config(node_id, sanitized_config)
        if self._run(start_command) != 0:
            self._raise_after_rollback(connection_id, "openvpn_start_failed")

        deadline = self._clock() + self._tun_timeout_seconds
        ready_command = self._tun_ready_command(connection_id)
        while True:
            result_code = self._run(ready_command, timeout_seconds=10.0)
            if result_code == 0:
                runtime = self.status(connection_id, node_id=node_id)
                if not runtime.running:
                    self._raise_after_rollback(
                        connection_id, "openvpn_process_exited"
                    )
                return runtime
            if result_code != 3:
                self._raise_after_rollback(
                    connection_id, "openvpn_tun_check_failed"
                )
            remaining = deadline - self._clock()
            if remaining <= 0:
                self._raise_after_rollback(connection_id, "openvpn_tun_timeout")
            self._sleeper(min(self._poll_interval_seconds, remaining))
