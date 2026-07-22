from sqlalchemy import or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import utcnow
from app.models.enums import ConnectionStatus
from app.models.network import ConnectionEvent, SocksEndpoint, VPNConnection
from app.services.network.commands import NetworkCommand, NetworkOperation
from app.services.network.executor import NetworkExecutor


class StartupRecoveryError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def recover_interrupted_connections(
    session_factory: sessionmaker[Session],
    executor: NetworkExecutor,
    *,
    enable_real_connections: bool,
) -> int:
    """Fail closed after a service restart before any SOCKS endpoint is trusted.

    Real installations ask the fixed root helper to purge each interrupted
    connection. Mock installations update database state only and never invoke
    the executor, which keeps local development and automated tests network-free.
    """

    with session_factory() as db:
        connection_ids = list(
            db.scalars(
                select(VPNConnection.id)
                .outerjoin(
                    SocksEndpoint,
                    SocksEndpoint.connection_id == VPNConnection.id,
                )
                .where(
                    or_(
                        VPNConnection.status != ConnectionStatus.STOPPED,
                        SocksEndpoint.is_active.is_(True),
                    )
                )
                .order_by(VPNConnection.id.asc())
                .distinct()
            ).all()
        )
        if not connection_ids:
            return 0

        if enable_real_connections:
            for connection_id in connection_ids:
                result = executor.run(
                    NetworkCommand(
                        NetworkOperation.CONNECTION_PURGE,
                        (str(connection_id),),
                    ),
                    timeout_seconds=120,
                )
                if result.returncode != 0:
                    db.rollback()
                    raise StartupRecoveryError("startup_connection_purge_failed")

        now = utcnow()
        for connection_id in connection_ids:
            connection = db.get(VPNConnection, connection_id)
            if connection is None:
                continue
            endpoint = db.scalar(
                select(SocksEndpoint).where(
                    SocksEndpoint.connection_id == connection_id
                )
            )
            connection.status = ConnectionStatus.STOPPED
            connection.exit_ip = None
            connection.pid = None
            connection.stopped_at = now
            connection.last_health_at = now
            connection.consecutive_failures = 0
            connection.last_error = "startup_recovery"
            if endpoint is not None:
                endpoint.is_active = False
            db.add(
                ConnectionEvent(
                    connection_id=connection_id,
                    event_type="connection_startup_recovery",
                    status=ConnectionStatus.STOPPED.value,
                    message="connection stopped during startup recovery",
                    details={
                        "simulated": not enable_real_connections,
                        "runtime_purged": enable_real_connections,
                    },
                )
            )
        db.commit()
        return len(connection_ids)
