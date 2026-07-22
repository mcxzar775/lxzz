from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.models.enums import NetworkType, ScanStatus, TaskStatus


class NodeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
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
    first_seen_at: datetime
    last_seen_at: datetime
    last_success_at: datetime | None
    failure_count: int
    is_available: bool
    is_blocked: bool = False
    is_favorite: bool = False
    asn: int | None
    asn_organization: str | None
    isp: str | None
    ptr: str | None
    classified_exit_ip: str | None
    exit_country_code: str | None
    exit_country_name: str | None
    exit_city: str | None
    intelligence_source: str | None
    intelligence_checked_at: datetime | None
    network_classification_reasons: list[str]
    network_type: NetworkType
    network_confidence: float | None
    created_at: datetime
    updated_at: datetime


class NodeList(BaseModel):
    items: list[NodeRead]
    total: int
    limit: int
    offset: int


class NodeRefreshResponse(BaseModel):
    fetched_bytes: int = Field(ge=0)
    valid_nodes: int = Field(ge=0)
    inserted: int = Field(ge=0)
    updated: int = Field(ge=0)
    rejected_rows: int = Field(ge=0)
    duplicate_rows: int = Field(ge=0)
    rejection_reasons: dict[str, int]


class NodeScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    node_id: int
    scan_type: Literal["fast", "full"]
    status: ScanStatus
    latency_ms: float | None
    exit_ip: str | None
    error_code: str | None
    details: dict[str, Any]
    created_at: datetime
    completed_at: datetime | None

    @computed_field
    def simulated(self) -> bool:
        return self.details.get("simulated") is True


class NodeScanList(BaseModel):
    items: list[NodeScanRead]
    total: int
    limit: int
    offset: int


class BatchScanRequest(BaseModel):
    node_ids: list[int] = Field(min_length=1, max_length=50)
    scan_type: Literal["fast", "full"] = "fast"

    @field_validator("node_ids")
    @classmethod
    def _validate_node_ids(cls, values: list[int]) -> list[int]:
        if any(isinstance(value, bool) or value <= 0 for value in values):
            raise ValueError("node IDs must be positive integers")
        if len(set(values)) != len(values):
            raise ValueError("node IDs must be unique")
        return values


class BatchScanItemRead(BaseModel):
    node_id: int
    status: ScanStatus
    error_code: str | None
    simulated: bool


class BatchScanTaskRead(BaseModel):
    id: int
    status: TaskStatus
    scan_type: Literal["fast", "full"]
    total: int
    completed: int
    succeeded: int
    failed: int
    items: list[BatchScanItemRead]
    last_error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class NodeBlockRequest(BaseModel):
    reason: str | None = Field(default=None, min_length=1, max_length=255)


class NodeBlockRead(BaseModel):
    node_id: int
    blocked: bool
    reason: str | None


class NodeFavoriteRead(BaseModel):
    node_id: int
    favorite: bool
