from dataclasses import dataclass


class VPNGateError(Exception):
    """Base exception whose message is safe to expose or log."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class VPNGateFetchError(VPNGateError):
    pass


class VPNGateFeedError(VPNGateError):
    pass


class OpenVPNConfigError(VPNGateError):
    pass


@dataclass(frozen=True)
class SanitizedOpenVPNConfig:
    text: str
    config_hash: str
    remote_ip: str
    remote_port: int
    protocol: str


@dataclass(frozen=True)
class ParsedVPNGateNode:
    config_hash: str
    host_name: str | None
    ip_address: str
    score: int | None
    ping_ms: int | None
    speed_bps: int | None
    country_long: str | None
    country_code: str | None
    sessions: int | None
    uptime_seconds: int | None
    total_users: int | None
    total_traffic_bytes: int | None
    protocol: str
    remote_port: int
    sanitized_config: str


@dataclass(frozen=True)
class ParseReport:
    nodes: list[ParsedVPNGateNode]
    rejected_rows: int
    duplicate_rows: int
    rejection_reasons: dict[str, int]


@dataclass(frozen=True)
class ImportResult:
    inserted: int
    updated: int
