from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol


class UnlockServiceName(str, Enum):
    NETFLIX = "netflix"
    CHATGPT = "chatgpt"
    OPENAI_API = "openai_api"
    YOUTUBE = "youtube"


ALL_UNLOCK_SERVICES = tuple(UnlockServiceName)

ALLOWED_STATUSES: dict[UnlockServiceName, frozenset[str]] = {
    UnlockServiceName.NETFLIX: frozenset(
        {
            "FULL",
            "ORIGINALS_ONLY",
            "BLOCKED",
            "REACHABLE",
            "UNKNOWN",
            "TIMEOUT",
        }
    ),
    UnlockServiceName.CHATGPT: frozenset(
        {
            "UNLOCKED",
            "SUPPORTED_REGION",
            "UNSUPPORTED_REGION",
            "PARTIAL",
            "CHALLENGE",
            "HTTP_BLOCKED",
            "DNS_FAILED",
            "TLS_FAILED",
            "TIMEOUT",
            "UNKNOWN",
        }
    ),
    UnlockServiceName.OPENAI_API: frozenset(
        {
            "REACHABLE",
            "HTTP_BLOCKED",
            "DNS_FAILED",
            "TLS_FAILED",
            "TIMEOUT",
            "UNKNOWN",
        }
    ),
    UnlockServiceName.YOUTUBE: frozenset(
        {
            "REGION_DETECTED",
            "REACHABLE",
            "BLOCKED",
            "DNS_FAILED",
            "TLS_FAILED",
            "TIMEOUT",
            "UNKNOWN",
        }
    ),
}


@dataclass(frozen=True)
class UnlockCheckResult:
    service_name: UnlockServiceName
    status: str
    region: str | None = None
    latency_ms: float | None = None
    failure_reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    simulated: bool = False

    def __post_init__(self) -> None:
        if self.status not in ALLOWED_STATUSES[self.service_name]:
            raise ValueError("invalid_unlock_status")
        if self.region is not None and (
            len(self.region) != 2
            or not self.region.isascii()
            or not self.region.isalpha()
            or self.region != self.region.upper()
        ):
            raise ValueError("invalid_unlock_region")
        if self.latency_ms is not None and not 0 <= self.latency_ms <= 60_000:
            raise ValueError("invalid_unlock_latency")
        if self.failure_reason is not None and (
            not self.failure_reason
            or len(self.failure_reason) > 128
            or not self.failure_reason.isascii()
            or not self.failure_reason.replace("_", "").isalnum()
        ):
            raise ValueError("invalid_unlock_failure_reason")

    def safe_details(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name.value,
            "status": self.status,
            "region": self.region,
            "latency_ms": self.latency_ms,
            "failure_reason": self.failure_reason,
            "details": {**self.details, "simulated": self.simulated},
        }


class UnlockProbe(Protocol):
    def check(
        self,
        connection_id: int,
        service_name: UnlockServiceName,
    ) -> UnlockCheckResult: ...
