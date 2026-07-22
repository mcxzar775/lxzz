from datetime import datetime
import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


LogSource = Literal["audit", "login", "connection", "scan"]


class AdminLogRead(BaseModel):
    id: str
    source: LogSource
    category: str
    level: Literal["INFO", "WARN", "ERROR"]
    message: str
    actor: str | None
    target: str | None
    details: dict[str, object]
    created_at: datetime


class AdminLogList(BaseModel):
    items: list[AdminLogRead]
    total: int
    limit: int
    offset: int


class DiagnosticCheckRead(BaseModel):
    key: str
    label: str
    status: Literal["PASS", "WARN", "FAIL", "SKIP"]
    detail: str


class RuntimeDiagnosticsRead(BaseModel):
    version: str
    environment: str
    runtime_mode: Literal["simulated", "real"]
    network_executor: str
    real_feature_gates: dict[str, bool]
    overall_status: Literal["PASS", "WARN", "FAIL"]
    checks: list[DiagnosticCheckRead]
    generated_at: datetime


class AdminSettingsRead(BaseModel):
    node_refresh_minutes: int
    scan_concurrency: int
    socks_port_start: int
    socks_port_end: int
    namespace_dns_servers: list[str]
    log_retention_days: int
    health_check_interval_seconds: float
    auto_switch_max_per_hour: int
    ipinfo_api_token_configured: bool
    requires_restart: bool


class AdminSettingsUpdate(BaseModel):
    node_refresh_minutes: int = Field(ge=5, le=1440)
    scan_concurrency: int = Field(ge=1, le=10)
    socks_port_start: int = Field(ge=1024, le=65535)
    socks_port_end: int = Field(ge=1024, le=65535)
    namespace_dns_servers: list[str] = Field(min_length=1, max_length=3)
    log_retention_days: int = Field(ge=1, le=3650)
    health_check_interval_seconds: float = Field(ge=10, le=3600)
    auto_switch_max_per_hour: int = Field(ge=1, le=20)

    @field_validator("namespace_dns_servers")
    @classmethod
    def dns_servers_are_canonical_public_addresses(
        cls,
        value: list[str],
    ) -> list[str]:
        normalized: list[str] = []
        for item in value:
            try:
                address = ipaddress.ip_address(item)
            except ValueError as exc:
                raise ValueError("DNS servers must be IP addresses") from exc
            if not address.is_global or str(address) != item:
                raise ValueError("DNS servers must be canonical public addresses")
            normalized.append(item)
        if len(set(normalized)) != len(normalized):
            raise ValueError("DNS servers must be unique")
        return normalized

    @model_validator(mode="after")
    def port_pool_must_be_ordered(self) -> "AdminSettingsUpdate":
        if self.socks_port_end < self.socks_port_start:
            raise ValueError("SOCKS port pool must be ordered")
        return self
