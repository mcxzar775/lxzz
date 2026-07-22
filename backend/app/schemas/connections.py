from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models.enums import ConnectionStatus, NetworkType, RoutingMode
from app.services.auto_switch import (
    HealthPolicy,
    SwitchMode,
    SwitchStatus,
    SwitchTrigger,
)
from app.services.unlock import ALL_UNLOCK_SERVICES, UnlockServiceName


class ConnectionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    node_id: int | None
    node_ip: str | None = None
    node_country_code: str | None = None
    node_speed_bps: int | None = None
    routing_mode: RoutingMode
    preferred_country_code: str | None
    namespace: str
    tun_device: str
    status: ConnectionStatus
    exit_ip: str | None
    started_at: datetime | None
    stopped_at: datetime | None
    last_health_at: datetime | None
    consecutive_failures: int
    auto_switch_count: int
    last_error: str | None
    socks_port: int | None = None
    socks_username: str | None = None
    socks_active: bool = False
    socks_bytes_up: int = 0
    socks_bytes_down: int = 0
    created_at: datetime
    updated_at: datetime


class ConnectionList(BaseModel):
    items: list[ConnectionRead]
    total: int
    limit: int
    offset: int


class ConnectionCreate(BaseModel):
    name: str = Field(
        min_length=3,
        max_length=96,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_. -]{2,95}$",
    )
    node_id: int = Field(ge=1)
    routing_mode: RoutingMode = RoutingMode.AUTO
    preferred_country_code: str | None = Field(
        default=None,
        min_length=2,
        max_length=2,
        pattern=r"^[A-Za-z]{2}$",
    )
    create_socks: bool = True
    socks_username: str | None = Field(
        default=None,
        min_length=3,
        max_length=64,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$",
    )
    socks_port: int | None = Field(default=None, ge=1024, le=65535)
    client_ip_allowlist: list[str] = Field(default_factory=list, max_length=64)
    max_connections: int = Field(default=100, ge=1, le=1000)
    timeout_seconds: int = Field(default=300, ge=10, le=3600)

    @model_validator(mode="after")
    def routing_policy_is_consistent(self) -> "ConnectionCreate":
        if self.preferred_country_code is not None:
            self.preferred_country_code = self.preferred_country_code.upper()
        if self.routing_mode is RoutingMode.FIXED_COUNTRY:
            if self.preferred_country_code is None:
                raise ValueError("fixed country routing requires a country code")
        elif self.preferred_country_code is not None:
            raise ValueError("country code is only valid for fixed country routing")
        return self


class ConnectionRoutingUpdate(BaseModel):
    routing_mode: RoutingMode
    preferred_country_code: str | None = Field(
        default=None,
        min_length=2,
        max_length=2,
        pattern=r"^[A-Za-z]{2}$",
    )

    @model_validator(mode="after")
    def routing_policy_is_consistent(self) -> "ConnectionRoutingUpdate":
        if self.preferred_country_code is not None:
            self.preferred_country_code = self.preferred_country_code.upper()
        if self.routing_mode is RoutingMode.FIXED_COUNTRY:
            if self.preferred_country_code is None:
                raise ValueError("fixed country routing requires a country code")
        elif self.preferred_country_code is not None:
            raise ValueError("country code is only valid for fixed country routing")
        return self


class ConnectionCreateResponse(BaseModel):
    connection: ConnectionRead
    one_time_socks_password: str | None


class ConnectionLifecycleResultRead(BaseModel):
    action: str
    status: ConnectionStatus
    exit_ip: str | None
    network_type: NetworkType
    socks_active: bool
    steps: list[str]
    simulated: bool
    failure_code: str | None


class ConnectionLifecycleResponse(BaseModel):
    connection: ConnectionRead
    result: ConnectionLifecycleResultRead


class SocksPasswordRotateResponse(BaseModel):
    connection_id: int
    username: str
    one_time_socks_password: str


class UnlockCheckRequest(BaseModel):
    services: list[UnlockServiceName] = Field(
        default_factory=lambda: list(ALL_UNLOCK_SERVICES),
        min_length=1,
        max_length=len(ALL_UNLOCK_SERVICES),
    )

    @field_validator("services")
    @classmethod
    def services_must_be_unique(
        cls,
        value: list[UnlockServiceName],
    ) -> list[UnlockServiceName]:
        if len(set(value)) != len(value):
            raise ValueError("unlock services must be unique")
        return value


class ServiceCheckRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    connection_id: int
    service_name: UnlockServiceName
    status: str
    region: str | None
    latency_ms: float | None
    failure_reason: str | None
    details: dict[str, object]
    checked_at: datetime


class ServiceCheckList(BaseModel):
    items: list[ServiceCheckRead]
    total: int
    limit: int
    offset: int


class UnlockCheckResponse(BaseModel):
    items: list[ServiceCheckRead]


class HealthPolicyRequest(BaseModel):
    max_latency_ms: float | None = Field(default=None, ge=1, le=120_000)
    min_download_bps: int | None = Field(
        default=None,
        ge=0,
        le=100_000_000_000,
    )
    allowed_network_types: list[NetworkType] = Field(default_factory=list, max_length=7)
    required_services: list[UnlockServiceName] = Field(default_factory=list, max_length=4)

    @field_validator("allowed_network_types")
    @classmethod
    def network_types_must_be_unique(
        cls,
        value: list[NetworkType],
    ) -> list[NetworkType]:
        if len(set(value)) != len(value):
            raise ValueError("policy values must be unique")
        return value

    @field_validator("required_services")
    @classmethod
    def required_services_must_be_unique(
        cls,
        value: list[UnlockServiceName],
    ) -> list[UnlockServiceName]:
        if len(set(value)) != len(value):
            raise ValueError("policy values must be unique")
        return value

    def to_policy(self) -> HealthPolicy:
        return HealthPolicy(
            max_latency_ms=self.max_latency_ms,
            min_download_bps=self.min_download_bps,
            allowed_network_types=frozenset(self.allowed_network_types),
            required_services=tuple(self.required_services),
        )


class ConnectionSwitchRequest(HealthPolicyRequest):
    target_node_id: int | None = Field(default=None, ge=1)


class RuntimeUnlockCheckRead(BaseModel):
    service_name: UnlockServiceName
    status: str
    region: str | None
    latency_ms: float | None
    failure_reason: str | None
    simulated: bool


class ConnectionSwitchResponse(BaseModel):
    connection_id: int
    previous_node_id: int
    candidate_node_id: int
    mode: SwitchMode
    trigger: SwitchTrigger
    status: SwitchStatus
    exit_ip: str | None
    network_type: NetworkType
    unlock_checks: list[RuntimeUnlockCheckRead]
    steps: list[str]
    socks_resumed: bool
    simulated: bool
    failure_code: str | None
    switches_last_hour: int


class HealthCheckResponse(BaseModel):
    connection_id: int
    healthy: bool
    trigger: SwitchTrigger | None
    exit_ip: str | None
    latency_ms: float | None
    download_bps: int | None
    network_type: NetworkType
    unlock_checks: list[RuntimeUnlockCheckRead]
    failure_code: str | None
    simulated: bool
    consecutive_failures: int
    auto_switch: ConnectionSwitchResponse | None
    auto_switch_error: str | None


class ConnectionEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    connection_id: int | None
    event_type: str
    status: str
    message: str | None
    details: dict[str, object]
    created_at: datetime


class ConnectionEventList(BaseModel):
    items: list[ConnectionEventRead]
    total: int
    limit: int
    offset: int
