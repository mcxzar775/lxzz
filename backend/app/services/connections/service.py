from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import ConnectionStatus, NetworkType
from app.models.network import ConnectionEvent, SocksEndpoint, VPNConnection, VPNGateNode
from app.services.connections.driver import ConnectionLifecycleDriver
from app.services.connections.types import (
    ConnectionLifecycleError,
    ConnectionLifecycleOutcome,
)


class ConnectionLifecycleService:
    def __init__(self, driver: ConnectionLifecycleDriver) -> None:
        self._driver = driver

    @staticmethod
    def _endpoint(db: Session, connection_id: int) -> SocksEndpoint | None:
        return db.scalar(
            select(SocksEndpoint).where(SocksEndpoint.connection_id == connection_id)
        )

    @staticmethod
    def _event(
        connection: VPNConnection,
        *,
        action: str,
        status: ConnectionStatus,
        details: dict[str, object],
    ) -> ConnectionEvent:
        return ConnectionEvent(
            connection_id=connection.id,
            event_type=f"connection_{action}",
            status=status.value,
            message=f"connection {action} {status.value.lower()}",
            details=details,
        )

    async def start(
        self,
        db: Session,
        connection: VPNConnection,
    ) -> ConnectionLifecycleOutcome:
        if connection.status not in {
            ConnectionStatus.PENDING,
            ConnectionStatus.STOPPED,
            ConnectionStatus.FAILED,
        }:
            raise ConnectionLifecycleError("connection_not_startable")
        if connection.node_id is None:
            raise ConnectionLifecycleError("connection_node_missing")
        node = db.get(VPNGateNode, connection.node_id)
        if node is None:
            raise ConnectionLifecycleError("current_node_not_found")
        endpoint = self._endpoint(db, connection.id)
        connection.status = ConnectionStatus.STARTING
        try:
            runtime = await self._driver.start(connection, node, endpoint)
        except ConnectionLifecycleError as exc:
            connection.status = ConnectionStatus.FAILED
            connection.pid = None
            connection.last_error = exc.code
            connection.last_health_at = utcnow()
            if endpoint is not None:
                endpoint.is_active = False
            outcome = ConnectionLifecycleOutcome(
                connection_id=connection.id,
                action="start",
                status=ConnectionStatus.FAILED,
                exit_ip=None,
                network_type=NetworkType.UNKNOWN,
                socks_active=False,
                steps=(),
                simulated=False,
                failure_code=exc.code,
            )
            db.add(
                self._event(
                    connection,
                    action="start",
                    status=ConnectionStatus.FAILED,
                    details=outcome.safe_details(),
                )
            )
            return outcome

        now = utcnow()
        connection.status = ConnectionStatus.RUNNING
        connection.exit_ip = runtime.exit_ip
        connection.pid = runtime.pid
        connection.started_at = now
        connection.stopped_at = None
        connection.last_health_at = now
        connection.consecutive_failures = 0
        connection.last_error = None
        if endpoint is not None:
            endpoint.is_active = runtime.socks_active
        outcome = ConnectionLifecycleOutcome(
            connection_id=connection.id,
            action="start",
            status=ConnectionStatus.RUNNING,
            exit_ip=runtime.exit_ip,
            network_type=runtime.network_type,
            socks_active=runtime.socks_active,
            steps=runtime.steps,
            simulated=runtime.simulated,
        )
        db.add(
            self._event(
                connection,
                action="start",
                status=ConnectionStatus.RUNNING,
                details=outcome.safe_details(),
            )
        )
        return outcome

    async def stop(
        self,
        db: Session,
        connection: VPNConnection,
    ) -> ConnectionLifecycleOutcome:
        if connection.status in {ConnectionStatus.PENDING, ConnectionStatus.STOPPED}:
            connection.status = ConnectionStatus.STOPPED
            return ConnectionLifecycleOutcome(
                connection_id=connection.id,
                action="stop",
                status=ConnectionStatus.STOPPED,
                exit_ip=None,
                network_type=NetworkType.UNKNOWN,
                socks_active=False,
                steps=(),
                simulated=True,
            )
        if connection.node_id is None:
            raise ConnectionLifecycleError("connection_node_missing")
        node = db.get(VPNGateNode, connection.node_id)
        if node is None:
            raise ConnectionLifecycleError("current_node_not_found")
        endpoint = self._endpoint(db, connection.id)
        connection.status = ConnectionStatus.STOPPING
        try:
            runtime = await self._driver.stop(connection, node, endpoint)
        except ConnectionLifecycleError as exc:
            connection.status = ConnectionStatus.FAILED
            connection.last_error = exc.code
            outcome = ConnectionLifecycleOutcome(
                connection_id=connection.id,
                action="stop",
                status=ConnectionStatus.FAILED,
                exit_ip=connection.exit_ip,
                network_type=NetworkType.UNKNOWN,
                socks_active=bool(endpoint and endpoint.is_active),
                steps=(),
                simulated=False,
                failure_code=exc.code,
            )
            db.add(
                self._event(
                    connection,
                    action="stop",
                    status=ConnectionStatus.FAILED,
                    details=outcome.safe_details(),
                )
            )
            return outcome

        connection.status = ConnectionStatus.STOPPED
        connection.exit_ip = None
        connection.pid = None
        connection.stopped_at = utcnow()
        connection.last_error = None
        if endpoint is not None:
            endpoint.is_active = False
        outcome = ConnectionLifecycleOutcome(
            connection_id=connection.id,
            action="stop",
            status=ConnectionStatus.STOPPED,
            exit_ip=None,
            network_type=NetworkType.UNKNOWN,
            socks_active=False,
            steps=runtime.steps,
            simulated=runtime.simulated,
        )
        db.add(
            self._event(
                connection,
                action="stop",
                status=ConnectionStatus.STOPPED,
                details=outcome.safe_details(),
            )
        )
        return outcome

    async def restart(
        self,
        db: Session,
        connection: VPNConnection,
    ) -> tuple[ConnectionLifecycleOutcome, ConnectionLifecycleOutcome | None]:
        stopped = await self.stop(db, connection)
        if stopped.status is ConnectionStatus.FAILED:
            return stopped, None
        started = await self.start(db, connection)
        return stopped, started
