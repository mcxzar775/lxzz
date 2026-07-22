import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from sqlalchemy import func, or_, select

from app.api.dependencies import (
    AppSettings,
    AuthContext,
    CsrfAuth,
    DbSession,
    require_permission,
)
from app.core.permissions import Permission
from app.models.enums import ConnectionStatus
from app.models.network import (
    BlockedNode,
    ConnectionEvent,
    ServiceCheck,
    SocksEndpoint,
    VPNConnection,
    VPNGateNode,
)
from app.schemas.connections import (
    ConnectionCreate,
    ConnectionCreateResponse,
    ConnectionEventList,
    ConnectionEventRead,
    ConnectionList,
    ConnectionLifecycleResponse,
    ConnectionLifecycleResultRead,
    ConnectionRead,
    ConnectionSwitchRequest,
    ConnectionSwitchResponse,
    HealthCheckResponse,
    HealthPolicyRequest,
    RuntimeUnlockCheckRead,
    ServiceCheckList,
    ServiceCheckRead,
    UnlockCheckRequest,
    UnlockCheckResponse,
    SocksPasswordRotateResponse,
)
from app.services.auto_switch import (
    AutoSwitchOperationError,
    ConnectionSwitchService,
    SwitchMode,
    SwitchOutcome,
    SwitchTrigger,
)
from app.services.audit import record_audit
from app.services.connections import (
    ConnectionLifecycleError,
    ConnectionLifecycleOutcome,
    ConnectionLifecycleService,
)
from app.services.network.namespace import NamespacePlanError, allocate_namespace_plan
from app.services.network.socks5 import Socks5OperationError, SocksEndpointService
from app.services.unlock import (
    UnlockCheckCoordinator,
    UnlockCheckResult,
    UnlockServiceName,
    persist_unlock_checks,
)


router = APIRouter(prefix="/connections", tags=["connections"])
ReadConnectionsAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.NETWORK_READ))
]
ManageConnectionsAuth = Annotated[
    AuthContext, Depends(require_permission(Permission.NETWORK_MANAGE))
]


def get_unlock_check_coordinator(request: Request) -> UnlockCheckCoordinator:
    coordinator: UnlockCheckCoordinator = request.app.state.unlock_check_coordinator
    return coordinator


UnlockCoordinator = Annotated[
    UnlockCheckCoordinator, Depends(get_unlock_check_coordinator)
]


def get_connection_switch_service(request: Request) -> ConnectionSwitchService:
    service: ConnectionSwitchService = request.app.state.connection_switch_service
    return service


ConnectionSwitcher = Annotated[
    ConnectionSwitchService, Depends(get_connection_switch_service)
]


def get_connection_lifecycle_service(request: Request) -> ConnectionLifecycleService:
    service: ConnectionLifecycleService = request.app.state.connection_lifecycle_service
    return service


LifecycleService = Annotated[
    ConnectionLifecycleService, Depends(get_connection_lifecycle_service)
]


def get_socks_endpoint_service(request: Request) -> SocksEndpointService:
    service: SocksEndpointService = request.app.state.socks_endpoint_service
    return service


SocksService = Annotated[SocksEndpointService, Depends(get_socks_endpoint_service)]


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _connection_read(db: DbSession, connection: VPNConnection) -> ConnectionRead:
    node = db.get(VPNGateNode, connection.node_id) if connection.node_id is not None else None
    endpoint = db.scalar(
        select(SocksEndpoint).where(SocksEndpoint.connection_id == connection.id)
    )
    return ConnectionRead.model_validate(connection).model_copy(
        update={
            "node_ip": node.ip_address if node is not None else None,
            "node_country_code": node.country_code if node is not None else None,
            "node_speed_bps": node.speed_bps if node is not None else None,
            "socks_port": endpoint.port if endpoint is not None else None,
            "socks_username": endpoint.username if endpoint is not None else None,
            "socks_active": endpoint.is_active if endpoint is not None else False,
            "socks_bytes_up": endpoint.bytes_up if endpoint is not None else 0,
            "socks_bytes_down": endpoint.bytes_down if endpoint is not None else 0,
        }
    )


def _lifecycle_result(outcome: ConnectionLifecycleOutcome) -> ConnectionLifecycleResultRead:
    return ConnectionLifecycleResultRead(
        action=outcome.action,
        status=outcome.status,
        exit_ip=outcome.exit_ip,
        network_type=outcome.network_type,
        socks_active=outcome.socks_active,
        steps=list(outcome.steps),
        simulated=outcome.simulated,
        failure_code=outcome.failure_code,
    )


def _lifecycle_http_error(exc: ConnectionLifecycleError) -> HTTPException:
    return HTTPException(status_code=status.HTTP_409_CONFLICT, detail=exc.code)


def _runtime_check(result: UnlockCheckResult) -> RuntimeUnlockCheckRead:
    return RuntimeUnlockCheckRead(
        service_name=result.service_name,
        status=result.status,
        region=result.region,
        latency_ms=result.latency_ms,
        failure_reason=result.failure_reason,
        simulated=result.simulated,
    )


def _switch_response(
    outcome: SwitchOutcome,
    *,
    switches_last_hour: int,
) -> ConnectionSwitchResponse:
    return ConnectionSwitchResponse(
        connection_id=outcome.connection_id,
        previous_node_id=outcome.previous_node_id,
        candidate_node_id=outcome.candidate_node_id,
        mode=outcome.mode,
        trigger=outcome.trigger,
        status=outcome.status,
        exit_ip=outcome.exit_ip,
        network_type=outcome.network_type,
        unlock_checks=[_runtime_check(result) for result in outcome.unlock_checks],
        steps=list(outcome.steps),
        socks_resumed=outcome.socks_resumed,
        simulated=outcome.simulated,
        failure_code=outcome.failure_code,
        switches_last_hour=switches_last_hour,
    )


def _switch_http_error(exc: AutoSwitchOperationError) -> HTTPException:
    if exc.code == "auto_switch_rate_limited":
        return HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=exc.code,
        )
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=exc.code,
    )


@router.get("", response_model=ConnectionList)
def list_connections(
    _: ReadConnectionsAuth,
    db: DbSession,
    connection_status: Annotated[ConnectionStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConnectionList:
    filters = []
    if connection_status is not None:
        filters.append(VPNConnection.status == connection_status)
    total = int(db.scalar(select(func.count(VPNConnection.id)).where(*filters)) or 0)
    records = db.scalars(
        select(VPNConnection)
        .where(*filters)
        .order_by(VPNConnection.id.asc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ConnectionList(
        items=[_connection_read(db, record) for record in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=ConnectionCreateResponse, status_code=status.HTTP_201_CREATED)
def create_connection(
    request: Request,
    payload: ConnectionCreate,
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    socks_service: SocksService,
) -> ConnectionCreateResponse:
    del csrf
    if db.scalar(select(VPNConnection.id).where(VPNConnection.name == payload.name)):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connection name already exists",
        )
    node = db.get(VPNGateNode, payload.node_id)
    if node is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Node not found")
    blocked = db.scalar(
        select(BlockedNode.id).where(
            or_(BlockedNode.node_id == node.id, BlockedNode.config_hash == node.config_hash)
        )
    )
    if not node.is_available or blocked is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Node is unavailable or blocked",
        )

    temporary = secrets.token_hex(8)
    connection = VPNConnection(
        name=payload.name,
        node_id=node.id,
        namespace=f"pending-{temporary}",
        veth_host=f"pending-h-{temporary}",
        veth_namespace=f"pending-n-{temporary}",
        subnet_cidr=f"pending-{temporary}",
        status=ConnectionStatus.STOPPED,
    )
    db.add(connection)
    try:
        db.flush()
        plan = allocate_namespace_plan(
            connection.id,
            dns_servers=request.app.state.settings.namespace_dns_servers,
        )
        connection.namespace = plan.namespace
        connection.veth_host = plan.host_veth
        connection.veth_namespace = plan.namespace_veth
        connection.subnet_cidr = plan.subnet_cidr
        one_time_password: str | None = None
        if payload.create_socks:
            _, one_time_password = socks_service.create(
                db,
                connection_id=connection.id,
                username=payload.socks_username or f"exit{connection.id}",
                requested_port=payload.socks_port,
                client_ip_allowlist=payload.client_ip_allowlist,
                max_connections=payload.max_connections,
                timeout_seconds=payload.timeout_seconds,
            )
    except (NamespacePlanError, Socks5OperationError) as exc:
        db.rollback()
        code = exc.code
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=code,
        ) from exc
    db.add(
        ConnectionEvent(
            connection_id=connection.id,
            event_type="connection_created",
            status=ConnectionStatus.STOPPED.value,
            message="connection created",
            details={
                "node_id": node.id,
                "socks_enabled": payload.create_socks,
                "simulated": True,
            },
        )
    )
    record_audit(
        db,
        action="connections.create",
        status="success",
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details={"node_id": node.id, "socks_enabled": payload.create_socks},
    )
    db.commit()
    db.refresh(connection)
    return ConnectionCreateResponse(
        connection=_connection_read(db, connection),
        one_time_socks_password=one_time_password,
    )


async def _run_lifecycle_action(
    request: Request,
    connection: VPNConnection,
    auth: AuthContext,
    db: DbSession,
    lifecycle: ConnectionLifecycleService,
    *,
    action: str,
) -> ConnectionLifecycleResponse:
    try:
        if action == "start":
            outcome = await lifecycle.start(db, connection)
        elif action == "stop":
            outcome = await lifecycle.stop(db, connection)
        elif action == "restart":
            stopped, started = await lifecycle.restart(db, connection)
            outcome = started or stopped
        else:
            raise RuntimeError("invalid lifecycle action")
    except ConnectionLifecycleError as exc:
        raise _lifecycle_http_error(exc) from exc
    record_audit(
        db,
        action=f"connections.{action}",
        status=("success" if outcome.failure_code is None else "failed"),
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details=outcome.safe_details(),
    )
    db.commit()
    db.refresh(connection)
    return ConnectionLifecycleResponse(
        connection=_connection_read(db, connection),
        result=_lifecycle_result(outcome),
    )


@router.post("/{connection_id}/start", response_model=ConnectionLifecycleResponse)
async def start_connection(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    lifecycle: LifecycleService,
) -> ConnectionLifecycleResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    return await _run_lifecycle_action(
        request,
        connection,
        auth,
        db,
        lifecycle,
        action="start",
    )


@router.post("/{connection_id}/stop", response_model=ConnectionLifecycleResponse)
async def stop_connection(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    lifecycle: LifecycleService,
) -> ConnectionLifecycleResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    return await _run_lifecycle_action(
        request,
        connection,
        auth,
        db,
        lifecycle,
        action="stop",
    )


@router.post("/{connection_id}/restart", response_model=ConnectionLifecycleResponse)
async def restart_connection(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    lifecycle: LifecycleService,
) -> ConnectionLifecycleResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    return await _run_lifecycle_action(
        request,
        connection,
        auth,
        db,
        lifecycle,
        action="restart",
    )


@router.post(
    "/{connection_id}/rotate-password",
    response_model=SocksPasswordRotateResponse,
)
def rotate_connection_socks_password(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    socks_service: SocksService,
) -> SocksPasswordRotateResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    endpoint = db.scalar(
        select(SocksEndpoint).where(SocksEndpoint.connection_id == connection.id)
    )
    if endpoint is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SOCKS endpoint not found",
        )
    try:
        one_time_password = socks_service.rotate_password(endpoint)
    except Socks5OperationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=exc.code,
        ) from exc
    record_audit(
        db,
        action="connections.rotate_socks_password",
        status="success",
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details={"endpoint_id": endpoint.id},
    )
    db.commit()
    return SocksPasswordRotateResponse(
        connection_id=connection.id,
        username=endpoint.username,
        one_time_socks_password=one_time_password,
    )


@router.delete("/{connection_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_connection(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
) -> None:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    if connection.status not in {ConnectionStatus.PENDING, ConnectionStatus.STOPPED}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connection must be stopped before deletion",
        )
    record_audit(
        db,
        action="connections.delete",
        status="success",
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details={"node_id": connection.node_id},
    )
    db.delete(connection)
    db.commit()


@router.post("/{connection_id}/check-unlock", response_model=UnlockCheckResponse)
async def check_connection_unlock(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    payload: UnlockCheckRequest,
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    coordinator: UnlockCoordinator,
) -> UnlockCheckResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    if connection.status != ConnectionStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connection must be running before unlock checks",
        )
    services = tuple(payload.services)
    results = await coordinator.check(connection.id, services)
    records = persist_unlock_checks(db, connection, results)
    record_audit(
        db,
        action="connections.check_unlock",
        status="success",
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details={
            "services": [result.service_name for result in results],
            "statuses": {
                result.service_name.value: result.status for result in results
            },
            "simulated": all(result.simulated for result in results),
        },
    )
    db.commit()
    for record in records:
        db.refresh(record)
    return UnlockCheckResponse(
        items=[ServiceCheckRead.model_validate(record) for record in records]
    )


@router.get("/{connection_id}/checks", response_model=ServiceCheckList)
def list_connection_checks(
    connection_id: Annotated[int, Path(ge=1)],
    _: ReadConnectionsAuth,
    db: DbSession,
    service: Annotated[UnlockServiceName | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ServiceCheckList:
    if db.get(VPNConnection, connection_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    filters = [ServiceCheck.connection_id == connection_id]
    if service is not None:
        filters.append(ServiceCheck.service_name == service.value)
    total = int(db.scalar(select(func.count(ServiceCheck.id)).where(*filters)) or 0)
    records = db.scalars(
        select(ServiceCheck)
        .where(*filters)
        .order_by(ServiceCheck.checked_at.desc(), ServiceCheck.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ServiceCheckList(
        items=[ServiceCheckRead.model_validate(record) for record in records],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/{connection_id}/switch", response_model=ConnectionSwitchResponse)
async def switch_connection(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    payload: ConnectionSwitchRequest,
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    db: DbSession,
    switcher: ConnectionSwitcher,
) -> ConnectionSwitchResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    try:
        outcome = await switcher.switch(
            db,
            connection,
            payload.to_policy(),
            mode=SwitchMode.MANUAL,
            trigger=SwitchTrigger.MANUAL,
            requested_node_id=payload.target_node_id,
        )
    except AutoSwitchOperationError as exc:
        raise _switch_http_error(exc) from exc
    record_audit(
        db,
        action="connections.switch",
        status=outcome.status.value.lower(),
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details=outcome.safe_details(),
    )
    db.commit()
    return _switch_response(
        outcome,
        switches_last_hour=switcher.switches_last_hour(db, connection.id),
    )


@router.post("/{connection_id}/health-check", response_model=HealthCheckResponse)
async def check_connection_health(
    request: Request,
    connection_id: Annotated[int, Path(ge=1)],
    payload: HealthPolicyRequest,
    auth: ManageConnectionsAuth,
    csrf: CsrfAuth,
    settings: AppSettings,
    db: DbSession,
    switcher: ConnectionSwitcher,
) -> HealthCheckResponse:
    del csrf
    connection = db.get(VPNConnection, connection_id)
    if connection is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    try:
        outcome = await switcher.check_health(
            db,
            connection,
            payload.to_policy(),
            auto_switch=settings.enable_auto_switch,
        )
    except AutoSwitchOperationError as exc:
        raise _switch_http_error(exc) from exc
    record_audit(
        db,
        action="connections.health_check",
        status="success" if outcome.observation.healthy else "failed",
        user_id=auth.user.id,
        target_type="vpn_connection",
        target_id=str(connection.id),
        ip_address=_client_ip(request),
        details={
            "healthy": outcome.observation.healthy,
            "trigger": (
                outcome.observation.trigger.value
                if outcome.observation.trigger is not None
                else None
            ),
            "failure_code": outcome.observation.failure_code,
            "simulated": outcome.observation.simulated,
            "auto_switch_status": (
                outcome.switch_outcome.status.value
                if outcome.switch_outcome is not None
                else None
            ),
            "auto_switch_error": outcome.auto_switch_error,
        },
    )
    db.commit()
    switch_response = (
        _switch_response(
            outcome.switch_outcome,
            switches_last_hour=switcher.switches_last_hour(db, connection.id),
        )
        if outcome.switch_outcome is not None
        else None
    )
    observation = outcome.observation
    return HealthCheckResponse(
        connection_id=connection.id,
        healthy=observation.healthy,
        trigger=observation.trigger,
        exit_ip=observation.exit_ip,
        latency_ms=observation.latency_ms,
        download_bps=observation.download_bps,
        network_type=observation.network_type,
        unlock_checks=[
            _runtime_check(result) for result in observation.unlock_checks
        ],
        failure_code=observation.failure_code,
        simulated=observation.simulated,
        consecutive_failures=outcome.consecutive_failures,
        auto_switch=switch_response,
        auto_switch_error=outcome.auto_switch_error,
    )


@router.get("/{connection_id}/events", response_model=ConnectionEventList)
def list_connection_events(
    connection_id: Annotated[int, Path(ge=1)],
    _: ReadConnectionsAuth,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConnectionEventList:
    if db.get(VPNConnection, connection_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connection not found",
        )
    filters = [ConnectionEvent.connection_id == connection_id]
    total = int(db.scalar(select(func.count(ConnectionEvent.id)).where(*filters)) or 0)
    records = db.scalars(
        select(ConnectionEvent)
        .where(*filters)
        .order_by(ConnectionEvent.created_at.desc(), ConnectionEvent.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ConnectionEventList(
        items=[ConnectionEventRead.model_validate(record) for record in records],
        total=total,
        limit=limit,
        offset=offset,
    )
