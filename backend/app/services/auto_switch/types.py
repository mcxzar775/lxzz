from dataclasses import dataclass, field
from enum import Enum

from app.models.enums import NetworkType
from app.services.unlock import UnlockCheckResult, UnlockServiceName


class SwitchTrigger(str, Enum):
    MANUAL = "MANUAL"
    OPENVPN_DISCONNECTED = "OPENVPN_DISCONNECTED"
    EXIT_IP_UNAVAILABLE = "EXIT_IP_UNAVAILABLE"
    HEALTH_CHECK_FAILED = "HEALTH_CHECK_FAILED"
    EXIT_IP_CHANGED = "EXIT_IP_CHANGED"
    PERFORMANCE_DEGRADED = "PERFORMANCE_DEGRADED"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    NETWORK_POLICY_MISMATCH = "NETWORK_POLICY_MISMATCH"


class SwitchMode(str, Enum):
    MANUAL = "MANUAL"
    AUTOMATIC = "AUTOMATIC"


class SwitchStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"


class AutoSwitchOperationError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class HealthPolicy:
    max_latency_ms: float | None = None
    min_download_bps: int | None = None
    allowed_network_types: frozenset[NetworkType] = field(default_factory=frozenset)
    required_services: tuple[UnlockServiceName, ...] = ()

    def __post_init__(self) -> None:
        if self.max_latency_ms is not None and (
            isinstance(self.max_latency_ms, bool)
            or not 1 <= self.max_latency_ms <= 120_000
        ):
            raise ValueError("invalid_max_latency")
        if self.min_download_bps is not None and (
            isinstance(self.min_download_bps, bool)
            or not 0 <= self.min_download_bps <= 100_000_000_000
        ):
            raise ValueError("invalid_min_download_bps")
        if len(self.required_services) > 4 or len(set(self.required_services)) != len(
            self.required_services
        ):
            raise ValueError("invalid_required_services")


UNLOCK_SUCCESS_STATUSES: dict[UnlockServiceName, frozenset[str]] = {
    UnlockServiceName.NETFLIX: frozenset({"FULL", "ORIGINALS_ONLY", "REACHABLE"}),
    UnlockServiceName.CHATGPT: frozenset({"UNLOCKED", "SUPPORTED_REGION"}),
    UnlockServiceName.OPENAI_API: frozenset({"REACHABLE"}),
    UnlockServiceName.YOUTUBE: frozenset({"REGION_DETECTED", "REACHABLE"}),
}


def unlock_checks_satisfy_policy(
    results: tuple[UnlockCheckResult, ...],
) -> bool:
    return all(
        result.status in UNLOCK_SUCCESS_STATUSES[result.service_name]
        for result in results
    )


@dataclass(frozen=True)
class HealthObservation:
    healthy: bool
    trigger: SwitchTrigger | None
    exit_ip: str | None
    latency_ms: float | None
    download_bps: int | None
    network_type: NetworkType
    unlock_checks: tuple[UnlockCheckResult, ...] = ()
    failure_code: str | None = None
    simulated: bool = False

    def __post_init__(self) -> None:
        if self.healthy != (self.trigger is None and self.failure_code is None):
            raise ValueError("invalid_health_observation")


@dataclass(frozen=True)
class SwitchExecution:
    exit_ip: str
    latency_ms: float
    download_bps: int
    network_type: NetworkType
    unlock_checks: tuple[UnlockCheckResult, ...]
    steps: tuple[str, ...]
    socks_resumed: bool
    simulated: bool
    pid: int | None = None


@dataclass(frozen=True)
class SwitchOutcome:
    connection_id: int
    previous_node_id: int
    candidate_node_id: int
    mode: SwitchMode
    trigger: SwitchTrigger
    status: SwitchStatus
    exit_ip: str | None
    network_type: NetworkType
    unlock_checks: tuple[UnlockCheckResult, ...]
    steps: tuple[str, ...]
    socks_resumed: bool
    simulated: bool
    failure_code: str | None = None

    def safe_details(self) -> dict[str, object]:
        network_type = NetworkType(self.network_type)
        return {
            "connection_id": self.connection_id,
            "previous_node_id": self.previous_node_id,
            "candidate_node_id": self.candidate_node_id,
            "mode": self.mode.value,
            "trigger": self.trigger.value,
            "status": self.status.value,
            "exit_ip": self.exit_ip,
            "network_type": network_type.value,
            "services": {
                result.service_name.value: result.status
                for result in self.unlock_checks
            },
            "steps": list(self.steps),
            "socks_resumed": self.socks_resumed,
            "simulated": self.simulated,
            "failure_code": self.failure_code,
        }


@dataclass(frozen=True)
class HealthCheckOutcome:
    connection_id: int
    observation: HealthObservation
    consecutive_failures: int
    switch_outcome: SwitchOutcome | None = None
    auto_switch_error: str | None = None
