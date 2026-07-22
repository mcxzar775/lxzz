from dataclasses import dataclass

from app.models.enums import ConnectionStatus, NetworkType


class ConnectionLifecycleError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ConnectionRuntimeResult:
    status: ConnectionStatus
    exit_ip: str | None
    network_type: NetworkType
    pid: int | None
    socks_active: bool
    steps: tuple[str, ...]
    simulated: bool


@dataclass(frozen=True)
class ConnectionLifecycleOutcome:
    connection_id: int
    action: str
    status: ConnectionStatus
    exit_ip: str | None
    network_type: NetworkType
    socks_active: bool
    steps: tuple[str, ...]
    simulated: bool
    failure_code: str | None = None

    def safe_details(self) -> dict[str, object]:
        return {
            "connection_id": self.connection_id,
            "action": self.action,
            "status": self.status.value,
            "exit_ip": self.exit_ip,
            "network_type": self.network_type.value,
            "socks_active": self.socks_active,
            "steps": list(self.steps),
            "simulated": self.simulated,
            "failure_code": self.failure_code,
        }
