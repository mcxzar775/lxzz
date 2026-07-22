import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from app.core.logging import redact_text
from app.services.network.commands import NetworkCommand, validate_command


MAX_COMMAND_OUTPUT_BYTES = 16 * 1024
SAFE_PROCESS_ENVIRONMENT = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


class NetworkCommandExecutionError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CommandResult:
    command: NetworkCommand
    returncode: int
    stdout: str
    stderr: str


class NetworkExecutor(Protocol):
    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult: ...


def _safe_absolute_path(value: str, *, code: str) -> str:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise ValueError(code)
    return str(path)


def _bounded_output(value: str) -> str:
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) > MAX_COMMAND_OUTPUT_BYTES:
        encoded = encoded[:MAX_COMMAND_OUTPUT_BYTES]
        value = encoded.decode("utf-8", errors="ignore") + "\n[TRUNCATED]"
    return redact_text(value)


class MockNetworkExecutor:
    """Records validated operations without touching host networking."""

    def __init__(self) -> None:
        self.commands: list[NetworkCommand] = []

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        validate_command(command)
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("invalid_timeout")
        self.commands.append(command)
        return CommandResult(command, 0, "mock execution", "")


class RealNetworkExecutor:
    """Executes only validated helper operations behind an explicit environment gate."""

    def __init__(
        self,
        *,
        enabled: bool,
        sudo_path: str,
        helper_path: str,
    ) -> None:
        if not enabled or os.getenv("VPNGATE_ENABLE_REAL_NETWORK", "").lower() not in {
            "1",
            "true",
            "yes",
        }:
            raise RuntimeError(
                "real network execution requires VPNGATE_ENABLE_REAL_NETWORK=true"
            )
        self._sudo_path = _safe_absolute_path(sudo_path, code="invalid_sudo_path")
        self._helper_path = _safe_absolute_path(helper_path, code="invalid_helper_path")

    def run(self, command: NetworkCommand, *, timeout_seconds: float) -> CommandResult:
        validate_command(command)
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("invalid_timeout")
        argv = (
            self._sudo_path,
            "-n",
            "--",
            self._helper_path,
            command.operation.value,
            *command.arguments,
        )
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                stdin=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env=SAFE_PROCESS_ENVIRONMENT,
            )
        except subprocess.TimeoutExpired as exc:
            raise NetworkCommandExecutionError("command_timeout") from exc
        except OSError as exc:
            raise NetworkCommandExecutionError("command_start_failed") from exc
        return CommandResult(
            command,
            completed.returncode,
            _bounded_output(completed.stdout),
            _bounded_output(completed.stderr),
        )


def build_network_executor(
    *,
    enable_real_network: bool,
    sudo_path: str = "/usr/bin/sudo",
    helper_path: str = "/usr/local/libexec/vpngate-manager-helper",
) -> NetworkExecutor:
    if enable_real_network:
        return RealNetworkExecutor(
            enabled=True,
            sudo_path=sudo_path,
            helper_path=helper_path,
        )
    return MockNetworkExecutor()
