from typing import Annotated

import psutil
from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from sqlalchemy.sql import Select

from app.api.dependencies import AuthContext, DbSession, require_permission
from app.core.permissions import Permission
from app.models.enums import ConnectionStatus, NetworkType
from app.models.network import ServiceCheck, SocksEndpoint, VPNConnection, VPNGateNode
from app.schemas.dashboard import DashboardCounts, DashboardResponse, SystemMetrics


router = APIRouter(tags=["dashboard"])
DashboardAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.DASHBOARD_READ))
]


def _count(db: Session, statement: Select[tuple[int]]) -> int:
    return int(db.scalar(statement) or 0)


def _latest_service_count(
    db: Session,
    *,
    service_name: str,
    statuses: tuple[str, ...],
) -> int:
    latest_ids = (
        select(func.max(ServiceCheck.id).label("id"))
        .where(ServiceCheck.service_name == service_name)
        .group_by(ServiceCheck.connection_id)
        .subquery()
    )
    return _count(
        db,
        select(func.count(ServiceCheck.id)).where(
            ServiceCheck.id.in_(select(latest_ids.c.id)),
            ServiceCheck.status.in_(statuses),
        ),
    )


@router.get("/dashboard", response_model=DashboardResponse)
def dashboard(request: Request, _: DashboardAuth, db: DbSession) -> DashboardResponse:
    del _
    disk = psutil.disk_usage("/")
    network = psutil.net_io_counters()
    counts = DashboardCounts(
        total_nodes=_count(db, select(func.count(VPNGateNode.id))),
        available_nodes=_count(
            db,
            select(func.count(VPNGateNode.id)).where(VPNGateNode.is_available.is_(True)),
        ),
        online_vpns=_count(
            db,
            select(func.count(VPNConnection.id)).where(
                VPNConnection.status == ConnectionStatus.RUNNING
            ),
        ),
        online_socks=_count(
            db,
            select(func.count(SocksEndpoint.id)).where(SocksEndpoint.is_active.is_(True)),
        ),
        anomalies=_count(
            db,
            select(func.count(VPNConnection.id)).where(
                VPNConnection.status == ConnectionStatus.FAILED
            ),
        ),
        residential_likely=_count(
            db,
            select(func.count(VPNGateNode.id)).where(
                VPNGateNode.network_type == NetworkType.RESIDENTIAL_LIKELY
            ),
        ),
        netflix_full=_latest_service_count(
            db,
            service_name="netflix",
            statuses=("FULL",),
        ),
        chatgpt_available=_latest_service_count(
            db,
            service_name="chatgpt",
            statuses=("UNLOCKED", "SUPPORTED_REGION"),
        ),
    )
    metrics = SystemMetrics(
        cpu_percent=float(psutil.cpu_percent(interval=None)),
        memory_percent=float(psutil.virtual_memory().percent),
        disk_percent=float(disk.percent),
        network_bytes_sent=int(network.bytes_sent),
        network_bytes_received=int(network.bytes_recv),
    )
    return DashboardResponse(
        counts=counts,
        system=metrics,
        network_executor=type(request.app.state.network_executor).__name__,
    )
