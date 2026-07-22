import asyncio
from collections.abc import Callable
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import ConnectionStatus, NetworkType
from app.models.network import (
    ConnectionEvent,
    SocksEndpoint,
    VPNConnection,
    VPNGateNode,
)
from app.services.auto_switch.candidates import select_candidate_node
from app.services.auto_switch.driver import ConnectionRuntimeDriver
from app.services.auto_switch.types import (
    AutoSwitchOperationError,
    HealthCheckOutcome,
    HealthPolicy,
    SwitchMode,
    SwitchOutcome,
    SwitchStatus,
    SwitchTrigger,
)
from app.services.unlock import persist_unlock_checks


AUTO_SWITCH_EVENT = "auto_switch"
MANUAL_SWITCH_EVENT = "manual_switch"
HEALTH_CHECK_EVENT = "health_check"


class ConnectionSwitchService:
    def __init__(
        self,
        driver: ConnectionRuntimeDriver,
        *,
        failure_threshold: int = 3,
        max_auto_switches_per_hour: int = 5,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if isinstance(failure_threshold, bool) or not 1 <= failure_threshold <= 20:
            raise ValueError("invalid_health_failure_threshold")
        if (
            isinstance(max_auto_switches_per_hour, bool)
            or not 1 <= max_auto_switches_per_hour <= 20
        ):
            raise ValueError("invalid_auto_switch_limit")
        self._driver = driver
        self._failure_threshold = failure_threshold
        self._max_auto_switches_per_hour = max_auto_switches_per_hour
        self._clock = clock
        self._locks: dict[int, asyncio.Lock] = {}

    @property
    def failure_threshold(self) -> int:
        return self._failure_threshold

    def _lock_for(self, connection_id: int) -> asyncio.Lock:
        lock = self._locks.get(connection_id)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[connection_id] = lock
        return lock

    def switches_last_hour(self, db: Session, connection_id: int) -> int:
        cutoff = self._clock() - timedelta(hours=1)
        return int(
            db.scalar(
                select(func.count(ConnectionEvent.id)).where(
                    ConnectionEvent.connection_id == connection_id,
                    ConnectionEvent.event_type == AUTO_SWITCH_EVENT,
                    ConnectionEvent.created_at >= cutoff,
                )
            )
            or 0
        )

    @staticmethod
    def _event(
        connection: VPNConnection,
        *,
        event_type: str,
        status: str,
        message: str,
        details: dict[str, object],
    ) -> ConnectionEvent:
        return ConnectionEvent(
            connection_id=connection.id,
            event_type=event_type,
            status=status,
            message=message,
            details=details,
        )

    async def switch(
        self,
        db: Session,
        connection: VPNConnection,
        policy: HealthPolicy,
        *,
        mode: SwitchMode,
        trigger: SwitchTrigger,
        requested_node_id: int | None = None,
    ) -> SwitchOutcome:
        if connection.node_id is None:
            raise AutoSwitchOperationError("connection_node_missing")
        if connection.status not in {ConnectionStatus.RUNNING, ConnectionStatus.FAILED}:
            raise AutoSwitchOperationError("connection_not_switchable")

        async with self._lock_for(connection.id):
            if (
                mode is SwitchMode.AUTOMATIC
                and self.switches_last_hour(db, connection.id)
                >= self._max_auto_switches_per_hour
            ):
                raise AutoSwitchOperationError("auto_switch_rate_limited")

            current_node = db.get(VPNGateNode, connection.node_id)
            if current_node is None:
                raise AutoSwitchOperationError("current_node_not_found")
            candidate = select_candidate_node(
                db,
                connection,
                policy,
                requested_node_id=requested_node_id,
            )
            endpoint = db.scalar(
                select(SocksEndpoint).where(
                    SocksEndpoint.connection_id == connection.id
                )
            )
            now = self._clock()
            event_type = (
                AUTO_SWITCH_EVENT
                if mode is SwitchMode.AUTOMATIC
                else MANUAL_SWITCH_EVENT
            )
            try:
                execution = await self._driver.switch(
                    connection,
                    current_node,
                    candidate,
                    endpoint,
                    policy,
                )
            except AutoSwitchOperationError as exc:
                if mode is SwitchMode.AUTOMATIC:
                    connection.auto_switch_count += 1
                connection.status = ConnectionStatus.FAILED
                connection.pid = None
                connection.last_health_at = now
                connection.consecutive_failures += 1
                connection.last_error = exc.code
                if endpoint is not None:
                    endpoint.is_active = False
                outcome = SwitchOutcome(
                    connection_id=connection.id,
                    previous_node_id=current_node.id,
                    candidate_node_id=candidate.id,
                    mode=mode,
                    trigger=trigger,
                    status=SwitchStatus.FAILED,
                    exit_ip=None,
                    network_type=NetworkType.UNKNOWN,
                    unlock_checks=(),
                    steps=(),
                    socks_resumed=False,
                    simulated=False,
                    failure_code=exc.code,
                )
                db.add(
                    self._event(
                        connection,
                        event_type=event_type,
                        status=SwitchStatus.FAILED.value,
                        message="connection switch failed",
                        details=outcome.safe_details(),
                    )
                )
                return outcome

            if mode is SwitchMode.AUTOMATIC:
                connection.auto_switch_count += 1
            connection.node_id = candidate.id
            connection.status = ConnectionStatus.RUNNING
            connection.exit_ip = execution.exit_ip
            connection.pid = execution.pid
            connection.started_at = now
            connection.stopped_at = None
            connection.last_health_at = now
            connection.consecutive_failures = 0
            connection.last_error = None
            candidate.failure_count = 0
            candidate.last_success_at = now
            if not execution.simulated:
                candidate.is_available = True
            if execution.unlock_checks:
                persist_unlock_checks(
                    db,
                    connection,
                    list(execution.unlock_checks),
                )
            outcome = SwitchOutcome(
                connection_id=connection.id,
                previous_node_id=current_node.id,
                candidate_node_id=candidate.id,
                mode=mode,
                trigger=trigger,
                status=SwitchStatus.SUCCEEDED,
                exit_ip=execution.exit_ip,
                network_type=NetworkType(execution.network_type),
                unlock_checks=execution.unlock_checks,
                steps=execution.steps,
                socks_resumed=execution.socks_resumed,
                simulated=execution.simulated,
            )
            db.add(
                self._event(
                    connection,
                    event_type=event_type,
                    status=SwitchStatus.SUCCEEDED.value,
                    message="connection switch completed",
                    details=outcome.safe_details(),
                )
            )
            return outcome

    async def check_health(
        self,
        db: Session,
        connection: VPNConnection,
        policy: HealthPolicy,
        *,
        auto_switch: bool,
    ) -> HealthCheckOutcome:
        if connection.node_id is None:
            raise AutoSwitchOperationError("connection_node_missing")
        if connection.status != ConnectionStatus.RUNNING:
            raise AutoSwitchOperationError("connection_not_running")
        node = db.get(VPNGateNode, connection.node_id)
        if node is None:
            raise AutoSwitchOperationError("current_node_not_found")

        observation = await self._driver.health(connection, node, policy)
        now = self._clock()
        connection.last_health_at = now
        if observation.unlock_checks:
            persist_unlock_checks(db, connection, list(observation.unlock_checks))
        if observation.healthy:
            connection.consecutive_failures = 0
            connection.last_error = None
            if observation.exit_ip is not None:
                connection.exit_ip = observation.exit_ip
            event_status = "SUCCEEDED"
        else:
            connection.consecutive_failures += 1
            connection.last_error = observation.failure_code
            event_status = "FAILED"
        db.add(
            self._event(
                connection,
                event_type=HEALTH_CHECK_EVENT,
                status=event_status,
                message=(
                    "connection health check passed"
                    if observation.healthy
                    else "connection health check failed"
                ),
                details={
                    "trigger": observation.trigger.value
                    if observation.trigger is not None
                    else None,
                    "failure_code": observation.failure_code,
                    "exit_ip": observation.exit_ip,
                    "latency_ms": observation.latency_ms,
                    "download_bps": observation.download_bps,
                    "network_type": observation.network_type.value,
                    "services": {
                        result.service_name.value: result.status
                        for result in observation.unlock_checks
                    },
                    "simulated": observation.simulated,
                },
            )
        )

        switch_outcome: SwitchOutcome | None = None
        auto_switch_error: str | None = None
        if (
            not observation.healthy
            and auto_switch
            and connection.consecutive_failures >= self._failure_threshold
        ):
            try:
                switch_outcome = await self.switch(
                    db,
                    connection,
                    policy,
                    mode=SwitchMode.AUTOMATIC,
                    trigger=observation.trigger or SwitchTrigger.HEALTH_CHECK_FAILED,
                )
            except AutoSwitchOperationError as exc:
                auto_switch_error = exc.code
                db.add(
                    self._event(
                        connection,
                        event_type="auto_switch_skipped",
                        status="FAILED",
                        message="automatic switch skipped",
                        details={
                            "failure_code": exc.code,
                            "trigger": (
                                observation.trigger.value
                                if observation.trigger is not None
                                else SwitchTrigger.HEALTH_CHECK_FAILED.value
                            ),
                        },
                    )
                )
        return HealthCheckOutcome(
            connection_id=connection.id,
            observation=observation,
            consecutive_failures=connection.consecutive_failures,
            switch_outcome=switch_outcome,
            auto_switch_error=auto_switch_error,
        )
