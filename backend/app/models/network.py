from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, utcnow
from app.models.enums import (
    ConnectionStatus,
    NetworkType,
    RoutingMode,
    ScanStatus,
    TaskStatus,
)


class VPNGateNode(TimestampMixin, Base):
    __tablename__ = "vpngate_nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    config_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    host_name: Mapped[str | None] = mapped_column(String(255))
    ip_address: Mapped[str] = mapped_column(String(64), index=True)
    score: Mapped[int | None] = mapped_column(Integer)
    ping_ms: Mapped[int | None] = mapped_column(Integer)
    speed_bps: Mapped[int | None] = mapped_column(Integer)
    country_long: Mapped[str | None] = mapped_column(String(128))
    country_code: Mapped[str | None] = mapped_column(String(8), index=True)
    sessions: Mapped[int | None] = mapped_column(Integer)
    uptime_seconds: Mapped[int | None] = mapped_column(Integer)
    total_users: Mapped[int | None] = mapped_column(Integer)
    total_traffic_bytes: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(8))
    remote_port: Mapped[int] = mapped_column(Integer)
    sanitized_config: Mapped[str] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(default=utcnow, index=True, nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failure_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_available: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    asn: Mapped[int | None] = mapped_column(Integer)
    asn_organization: Mapped[str | None] = mapped_column(String(255))
    isp: Mapped[str | None] = mapped_column(String(255))
    ptr: Mapped[str | None] = mapped_column(String(255))
    classified_exit_ip: Mapped[str | None] = mapped_column(String(64), index=True)
    exit_country_code: Mapped[str | None] = mapped_column(String(8))
    exit_country_name: Mapped[str | None] = mapped_column(String(128))
    exit_city: Mapped[str | None] = mapped_column(String(128))
    intelligence_source: Mapped[str | None] = mapped_column(String(32))
    intelligence_checked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    network_classification_reasons: Mapped[list[str]] = mapped_column(
        JSON, default=list, nullable=False
    )
    network_type: Mapped[NetworkType] = mapped_column(
        String(32), default=NetworkType.UNKNOWN, index=True
    )
    network_confidence: Mapped[float | None] = mapped_column(Float)


class NodeScanResult(Base):
    __tablename__ = "node_scan_results"
    __table_args__ = (Index("ix_node_scan_node_created", "node_id", "created_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(
        ForeignKey("vpngate_nodes.id", ondelete="CASCADE"), index=True
    )
    scan_type: Mapped[str] = mapped_column(String(32))
    status: Mapped[ScanStatus] = mapped_column(String(32), index=True)
    latency_ms: Mapped[float | None] = mapped_column(Float)
    exit_ip: Mapped[str | None] = mapped_column(String(64))
    error_code: Mapped[str | None] = mapped_column(String(64))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class VPNConnection(TimestampMixin, Base):
    __tablename__ = "vpn_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(96), unique=True)
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("vpngate_nodes.id", ondelete="SET NULL"), index=True
    )
    routing_mode: Mapped[RoutingMode] = mapped_column(
        String(32), default=RoutingMode.AUTO, nullable=False, index=True
    )
    preferred_country_code: Mapped[str | None] = mapped_column(String(8), index=True)
    namespace: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    veth_host: Mapped[str] = mapped_column(String(32), unique=True)
    veth_namespace: Mapped[str] = mapped_column(String(32), unique=True)
    subnet_cidr: Mapped[str] = mapped_column(String(64), unique=True)
    tun_device: Mapped[str] = mapped_column(String(32), default="tun0")
    status: Mapped[ConnectionStatus] = mapped_column(
        String(32), default=ConnectionStatus.PENDING, index=True
    )
    exit_ip: Mapped[str | None] = mapped_column(String(64))
    pid: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_health_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    auto_switch_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text)


class SocksEndpoint(TimestampMixin, Base):
    __tablename__ = "socks_endpoints"

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(
        ForeignKey("vpn_connections.id", ondelete="CASCADE"), unique=True, index=True
    )
    bind_address: Mapped[str] = mapped_column(String(64), default="0.0.0.0")
    port: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    username: Mapped[str] = mapped_column(String(128))
    encrypted_password: Mapped[str] = mapped_column(Text)
    client_ip_allowlist: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    max_connections: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=300, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    bytes_up: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    bytes_down: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class ServiceCheck(Base):
    __tablename__ = "service_checks"
    __table_args__ = (
        Index("ix_service_check_connection_service", "connection_id", "service_name"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(
        ForeignKey("vpn_connections.id", ondelete="CASCADE"), index=True
    )
    service_name: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(64), index=True)
    region: Mapped[str | None] = mapped_column(String(32))
    latency_ms: Mapped[float | None] = mapped_column(Float)
    failure_reason: Mapped[str | None] = mapped_column(String(128))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(default=utcnow, index=True, nullable=False)


class ConnectionEvent(Base):
    __tablename__ = "connection_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int | None] = mapped_column(
        ForeignKey("vpn_connections.id", ondelete="SET NULL"), index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(32))
    message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True, nullable=False)


class BlockedNode(Base):
    __tablename__ = "blocked_nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int | None] = mapped_column(
        ForeignKey("vpngate_nodes.id", ondelete="CASCADE"), unique=True
    )
    config_hash: Mapped[str] = mapped_column(String(64), unique=True)
    reason: Mapped[str | None] = mapped_column(String(255))
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)


class FavoriteNode(Base):
    __tablename__ = "favorite_nodes"

    id: Mapped[int] = mapped_column(primary_key=True)
    node_id: Mapped[int] = mapped_column(
        ForeignKey("vpngate_nodes.id", ondelete="CASCADE"), unique=True, index=True
    )
    created_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(default=utcnow, nullable=False)


class ScheduledTask(TimestampMixin, Base):
    __tablename__ = "scheduled_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_type: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[TaskStatus] = mapped_column(
        String(32), default=TaskStatus.PENDING, index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
