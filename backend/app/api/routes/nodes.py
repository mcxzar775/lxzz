from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy import func, or_, select

from app.api.dependencies import AuthContext, CsrfAuth, DbSession, require_permission
from app.core.permissions import Permission
from app.models.enums import NetworkType, ScanStatus
from app.models.network import (
    BlockedNode,
    FavoriteNode,
    NodeScanResult,
    ScheduledTask,
    VPNGateNode,
)
from app.schemas.nodes import (
    BatchScanRequest,
    BatchScanTaskRead,
    NodeBlockRead,
    NodeBlockRequest,
    NodeFavoriteRead,
    NodeList,
    NodeRead,
    NodeRefreshResponse,
    NodeScanList,
    NodeScanRead,
)
from app.services.audit import record_audit
from app.services.ip_intelligence import IPIntelligenceService
from app.services.scanning.service import NodeScanCoordinator, scan_node
from app.services.scanning.batch import BatchScanTaskError, BatchScanTaskService
from app.services.scanning.types import ScanType
from app.services.vpngate.client import VPNGateFetcher
from app.services.vpngate.importer import import_nodes
from app.services.vpngate.parser import parse_vpngate_csv
from app.services.vpngate.types import VPNGateError


router = APIRouter(prefix="/nodes", tags=["nodes"])
ReadNodesAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.NETWORK_READ))
]
ManageNodesAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.NETWORK_MANAGE))
]
NodeSort = Literal[
    "score",
    "ping_ms",
    "speed_bps",
    "last_seen_at",
    "last_success_at",
    "network_confidence",
    "asn",
    "id",
]
SortOrder = Literal["asc", "desc"]


def get_vpngate_fetcher(request: Request) -> VPNGateFetcher:
    fetcher: VPNGateFetcher = request.app.state.vpngate_fetcher
    return fetcher


Fetcher = Annotated[VPNGateFetcher, Depends(get_vpngate_fetcher)]


def get_node_scan_coordinator(request: Request) -> NodeScanCoordinator:
    coordinator: NodeScanCoordinator = request.app.state.node_scan_coordinator
    return coordinator


Scanner = Annotated[NodeScanCoordinator, Depends(get_node_scan_coordinator)]


def get_batch_scan_service(request: Request) -> BatchScanTaskService:
    service: BatchScanTaskService = request.app.state.batch_scan_service
    return service


BatchScanner = Annotated[BatchScanTaskService, Depends(get_batch_scan_service)]


def get_ip_intelligence_service(request: Request) -> IPIntelligenceService:
    service: IPIntelligenceService = request.app.state.ip_intelligence_service
    return service


IntelligenceService = Annotated[
    IPIntelligenceService, Depends(get_ip_intelligence_service)
]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _batch_scan_read(task: ScheduledTask) -> BatchScanTaskRead:
    result = task.result
    scan_type = task.payload.get("scan_type")
    if scan_type not in {"fast", "full"}:
        scan_type = "fast"
    return BatchScanTaskRead(
        id=task.id,
        status=task.status,
        scan_type=scan_type,
        total=int(result.get("total", 0)),
        completed=int(result.get("completed", 0)),
        succeeded=int(result.get("succeeded", 0)),
        failed=int(result.get("failed", 0)),
        items=result.get("items", []),
        last_error=task.last_error,
        created_at=task.created_at,
        started_at=task.started_at,
        completed_at=task.completed_at,
    )


@router.get("", response_model=NodeList)
def list_nodes(
    _: ReadNodesAuth,
    db: DbSession,
    country_code: Annotated[str | None, Query(min_length=2, max_length=2)] = None,
    protocol: Annotated[Literal["udp", "tcp"] | None, Query()] = None,
    available: Annotated[bool | None, Query()] = None,
    favorite: Annotated[bool | None, Query()] = None,
    network_type: Annotated[NetworkType | None, Query()] = None,
    asn: Annotated[int | None, Query(ge=1, le=4_294_967_295)] = None,
    min_confidence: Annotated[float | None, Query(ge=0, le=1)] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=128)] = None,
    sort_by: Annotated[NodeSort, Query()] = "score",
    sort_order: Annotated[SortOrder, Query()] = "desc",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> NodeList:
    filters = []
    if country_code is not None:
        filters.append(VPNGateNode.country_code == country_code.upper())
    if protocol is not None:
        filters.append(VPNGateNode.protocol == protocol)
    if available is not None:
        filters.append(VPNGateNode.is_available.is_(available))
    favorite_node_ids = select(FavoriteNode.node_id)
    if favorite is True:
        filters.append(VPNGateNode.id.in_(favorite_node_ids))
    elif favorite is False:
        filters.append(VPNGateNode.id.not_in(favorite_node_ids))
    if network_type is not None:
        filters.append(VPNGateNode.network_type == network_type)
    if asn is not None:
        filters.append(VPNGateNode.asn == asn)
    if min_confidence is not None:
        filters.append(VPNGateNode.network_confidence >= min_confidence)
    if search is not None:
        term = f"%{search.strip()}%"
        filters.append(
            or_(
                VPNGateNode.host_name.ilike(term),
                VPNGateNode.ip_address.ilike(term),
                VPNGateNode.country_long.ilike(term),
                VPNGateNode.classified_exit_ip.ilike(term),
                VPNGateNode.exit_country_name.ilike(term),
                VPNGateNode.exit_city.ilike(term),
                VPNGateNode.asn_organization.ilike(term),
                VPNGateNode.isp.ilike(term),
                VPNGateNode.ptr.ilike(term),
            )
        )

    sort_columns = {
        "score": VPNGateNode.score,
        "ping_ms": VPNGateNode.ping_ms,
        "speed_bps": VPNGateNode.speed_bps,
        "last_seen_at": VPNGateNode.last_seen_at,
        "last_success_at": VPNGateNode.last_success_at,
        "network_confidence": VPNGateNode.network_confidence,
        "asn": VPNGateNode.asn,
        "id": VPNGateNode.id,
    }
    order_column = sort_columns[sort_by]
    order_expression = (
        order_column.asc().nulls_last()
        if sort_order == "asc"
        else order_column.desc().nulls_last()
    )
    total = int(
        db.scalar(select(func.count(VPNGateNode.id)).where(*filters)) or 0
    )
    records = db.scalars(
        select(VPNGateNode)
        .where(*filters)
        .order_by(order_expression, VPNGateNode.id.asc())
        .limit(limit)
        .offset(offset)
    ).all()
    blocked_node_ids = set(
        db.scalars(
            select(BlockedNode.node_id).where(
                BlockedNode.node_id.in_([record.id for record in records])
            )
        ).all()
    )
    blocked_hashes = set(
        db.scalars(
            select(BlockedNode.config_hash).where(
                BlockedNode.config_hash.in_([record.config_hash for record in records])
            )
        ).all()
    )
    favorite_ids = set(
        db.scalars(
            select(FavoriteNode.node_id).where(
                FavoriteNode.node_id.in_([record.id for record in records])
            )
        ).all()
    )
    return NodeList(
        items=[
            NodeRead.model_validate(record).model_copy(
                update={
                    "is_blocked": record.id in blocked_node_ids
                    or record.config_hash in blocked_hashes,
                    "is_favorite": record.id in favorite_ids,
                }
            )
            for record in records
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/batch-scans",
    response_model=BatchScanTaskRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_batch_scan(
    request: Request,
    payload: BatchScanRequest,
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
    batch_scanner: BatchScanner,
) -> BatchScanTaskRead:
    del csrf
    try:
        task = batch_scanner.start(
            db,
            node_ids=payload.node_ids,
            scan_type=payload.scan_type,
        )
    except BatchScanTaskError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.code,
        ) from exc
    record_audit(
        db,
        action="nodes.batch_scan.start",
        status="success",
        user_id=auth.user.id,
        target_type="scheduled_task",
        target_id=str(task.id),
        ip_address=_client_ip(request),
        details={
            "scan_type": payload.scan_type,
            "node_count": len(payload.node_ids),
        },
    )
    db.commit()
    db.refresh(task)
    return _batch_scan_read(task)


@router.get("/batch-scans/{task_id}", response_model=BatchScanTaskRead)
def get_batch_scan(
    task_id: Annotated[int, Path(ge=1)],
    _: ReadNodesAuth,
    db: DbSession,
) -> BatchScanTaskRead:
    task = db.get(ScheduledTask, task_id)
    if task is None or task.task_type != "node_batch_scan":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Batch scan task not found",
        )
    return _batch_scan_read(task)


@router.post("/{node_id}/favorite", response_model=NodeFavoriteRead)
def favorite_node(
    request: Request,
    node_id: Annotated[int, Path(ge=1)],
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> NodeFavoriteRead:
    del csrf
    node = db.get(VPNGateNode, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    favorite = db.scalar(select(FavoriteNode).where(FavoriteNode.node_id == node.id))
    if favorite is None:
        db.add(FavoriteNode(node_id=node.id, created_by_user_id=auth.user.id))
    record_audit(
        db,
        action="nodes.favorite",
        status="success",
        user_id=auth.user.id,
        target_type="vpngate_node",
        target_id=str(node.id),
        ip_address=_client_ip(request),
    )
    db.commit()
    return NodeFavoriteRead(node_id=node.id, favorite=True)


@router.delete("/{node_id}/favorite", response_model=NodeFavoriteRead)
def unfavorite_node(
    request: Request,
    node_id: Annotated[int, Path(ge=1)],
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> NodeFavoriteRead:
    del csrf
    node = db.get(VPNGateNode, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    favorite = db.scalar(select(FavoriteNode).where(FavoriteNode.node_id == node.id))
    if favorite is not None:
        db.delete(favorite)
    record_audit(
        db,
        action="nodes.unfavorite",
        status="success",
        user_id=auth.user.id,
        target_type="vpngate_node",
        target_id=str(node.id),
        ip_address=_client_ip(request),
    )
    db.commit()
    return NodeFavoriteRead(node_id=node.id, favorite=False)


@router.post("/{node_id}/block", response_model=NodeBlockRead)
def block_node(
    request: Request,
    node_id: Annotated[int, Path(ge=1)],
    payload: NodeBlockRequest,
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> NodeBlockRead:
    del csrf
    node = db.get(VPNGateNode, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    blocked = db.scalar(
        select(BlockedNode).where(
            or_(BlockedNode.node_id == node.id, BlockedNode.config_hash == node.config_hash)
        )
    )
    if blocked is None:
        blocked = BlockedNode(
            node_id=node.id,
            config_hash=node.config_hash,
            reason=payload.reason,
            created_by_user_id=auth.user.id,
        )
        db.add(blocked)
    else:
        blocked.reason = payload.reason
    record_audit(
        db,
        action="nodes.block",
        status="success",
        user_id=auth.user.id,
        target_type="vpngate_node",
        target_id=str(node.id),
        ip_address=_client_ip(request),
        details={"reason": payload.reason},
    )
    db.commit()
    return NodeBlockRead(node_id=node.id, blocked=True, reason=blocked.reason)


@router.delete("/{node_id}/block", response_model=NodeBlockRead)
def unblock_node(
    request: Request,
    node_id: Annotated[int, Path(ge=1)],
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> NodeBlockRead:
    del csrf
    node = db.get(VPNGateNode, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    blocked = db.scalar(
        select(BlockedNode).where(
            or_(BlockedNode.node_id == node.id, BlockedNode.config_hash == node.config_hash)
        )
    )
    previous_reason = blocked.reason if blocked is not None else None
    if blocked is not None:
        db.delete(blocked)
    record_audit(
        db,
        action="nodes.unblock",
        status="success",
        user_id=auth.user.id,
        target_type="vpngate_node",
        target_id=str(node.id),
        ip_address=_client_ip(request),
    )
    db.commit()
    return NodeBlockRead(node_id=node.id, blocked=False, reason=previous_reason)


@router.post("/refresh", response_model=NodeRefreshResponse)
async def refresh_nodes(
    request: Request,
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
    fetcher: Fetcher,
) -> NodeRefreshResponse:
    del csrf
    try:
        payload = await fetcher.fetch_csv()
        report = parse_vpngate_csv(
            payload,
            max_rows=request.app.state.settings.vpngate_max_rows,
        )
    except VPNGateError as exc:
        record_audit(
            db,
            action="nodes.refresh",
            status="failed",
            user_id=auth.user.id,
            target_type="vpngate_feed",
            ip_address=_client_ip(request),
            details={"error_code": exc.code},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="VPNGate source is unavailable or invalid",
        ) from exc

    imported = import_nodes(db, report.nodes)
    record_audit(
        db,
        action="nodes.refresh",
        status="success",
        user_id=auth.user.id,
        target_type="vpngate_feed",
        ip_address=_client_ip(request),
        details={
            "valid_nodes": len(report.nodes),
            "inserted": imported.inserted,
            "updated": imported.updated,
            "rejected_rows": report.rejected_rows,
            "duplicate_rows": report.duplicate_rows,
            "rejection_reasons": report.rejection_reasons,
        },
    )
    db.commit()
    return NodeRefreshResponse(
        fetched_bytes=len(payload),
        valid_nodes=len(report.nodes),
        inserted=imported.inserted,
        updated=imported.updated,
        rejected_rows=report.rejected_rows,
        duplicate_rows=report.duplicate_rows,
        rejection_reasons=report.rejection_reasons,
    )


@router.post("/{node_id}/scan", response_model=NodeScanRead)
async def scan_single_node(
    request: Request,
    node_id: Annotated[int, Path(ge=1)],
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
    scanner: Scanner,
    intelligence_service: IntelligenceService,
    scan_type: Annotated[ScanType, Query()] = "fast",
) -> NodeScanResult:
    del csrf
    node = db.get(VPNGateNode, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")

    result = await scan_node(
        db,
        node,
        scanner,
        scan_type=scan_type,
        intelligence_service=intelligence_service,
    )
    record_audit(
        db,
        action="nodes.scan",
        status=(
            "success" if result.status == ScanStatus.SUCCEEDED else "failed"
        ),
        user_id=auth.user.id,
        target_type="vpngate_node",
        target_id=str(node.id),
        ip_address=_client_ip(request),
        details={
            "scan_id": result.id,
            "scan_type": result.scan_type,
            "scan_status": result.status,
            "error_code": result.error_code,
            "simulated": result.details.get("simulated") is True,
        },
    )
    db.commit()
    db.refresh(result)
    return result


@router.post("/{node_id}/classify", response_model=NodeRead)
async def classify_node_exit(
    request: Request,
    node_id: Annotated[int, Path(ge=1)],
    auth: ManageNodesAuth,
    csrf: CsrfAuth,
    db: DbSession,
    intelligence_service: IntelligenceService,
) -> VPNGateNode:
    del csrf
    node = db.get(VPNGateNode, node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    candidates = db.scalars(
        select(NodeScanResult)
        .where(
            NodeScanResult.node_id == node_id,
            NodeScanResult.scan_type == "full",
            NodeScanResult.status == ScanStatus.SUCCEEDED,
            NodeScanResult.exit_ip.is_not(None),
        )
        .order_by(NodeScanResult.created_at.desc(), NodeScanResult.id.desc())
        .limit(100)
    ).all()
    latest_real = next(
        (candidate for candidate in candidates if candidate.details.get("simulated") is False),
        None,
    )
    if latest_real is None or latest_real.exit_ip is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A successful real full scan is required before classification",
        )

    summary = await intelligence_service.enrich_node(
        node,
        exit_ip=latest_real.exit_ip,
    )
    record_audit(
        db,
        action="nodes.classify",
        status="success",
        user_id=auth.user.id,
        target_type="vpngate_node",
        target_id=str(node.id),
        ip_address=_client_ip(request),
        details={
            "scan_id": latest_real.id,
            "source": summary.source,
            "network_type": summary.network_type,
            "confidence": summary.confidence,
            "provider_error_code": summary.provider_error_code,
        },
    )
    db.commit()
    db.refresh(node)
    return node


@router.get("/{node_id}/scans", response_model=NodeScanList)
def list_node_scans(
    node_id: Annotated[int, Path(ge=1)],
    _: ReadNodesAuth,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> NodeScanList:
    if db.get(VPNGateNode, node_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    filters = (NodeScanResult.node_id == node_id,)
    total = int(db.scalar(select(func.count(NodeScanResult.id)).where(*filters)) or 0)
    records = db.scalars(
        select(NodeScanResult)
        .where(*filters)
        .order_by(NodeScanResult.created_at.desc(), NodeScanResult.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return NodeScanList(
        items=[NodeScanRead.model_validate(record) for record in records],
        total=total,
        limit=limit,
        offset=offset,
    )
