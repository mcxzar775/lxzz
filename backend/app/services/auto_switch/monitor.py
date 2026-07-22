import asyncio
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.models.enums import ConnectionStatus
from app.models.network import VPNConnection
from app.services.auto_switch.service import ConnectionSwitchService
from app.services.auto_switch.types import HealthPolicy


logger = logging.getLogger(__name__)


class ConnectionHealthMonitor:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        switch_service: ConnectionSwitchService,
        policy: HealthPolicy,
        *,
        interval_seconds: float = 60.0,
    ) -> None:
        if interval_seconds < 10 or interval_seconds > 3600:
            raise ValueError("invalid_health_check_interval")
        self._session_factory = session_factory
        self._switch_service = switch_service
        self._policy = policy
        self._interval_seconds = interval_seconds

    async def tick(self) -> int:
        with self._session_factory() as db:
            connection_ids = list(
                db.scalars(
                    select(VPNConnection.id).where(
                        VPNConnection.status == ConnectionStatus.RUNNING
                    )
                ).all()
            )
        checked = 0
        for connection_id in connection_ids:
            with self._session_factory() as db:
                connection = db.get(VPNConnection, connection_id)
                if connection is None or connection.status != ConnectionStatus.RUNNING:
                    continue
                try:
                    await self._switch_service.check_health(
                        db,
                        connection,
                        self._policy,
                        auto_switch=True,
                    )
                    db.commit()
                except Exception:
                    db.rollback()
                    logger.exception(
                        "connection health monitor failed",
                        extra={"connection_id": connection_id},
                    )
                else:
                    checked += 1
        return checked

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            await self.tick()
            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=self._interval_seconds,
                )
            except TimeoutError:
                continue
