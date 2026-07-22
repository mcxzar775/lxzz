import asyncio

from sqlalchemy.orm import Session

from app.models.network import ServiceCheck, VPNConnection
from app.services.unlock.types import (
    ALL_UNLOCK_SERVICES,
    UnlockCheckResult,
    UnlockProbe,
    UnlockServiceName,
)


class UnlockCheckCoordinator:
    def __init__(self, probe: UnlockProbe, *, concurrency: int = 2) -> None:
        if isinstance(concurrency, bool) or not 1 <= concurrency <= 4:
            raise ValueError("invalid_unlock_concurrency")
        self._probe = probe
        self._semaphore = asyncio.Semaphore(concurrency)

    async def check(
        self,
        connection_id: int,
        services: tuple[UnlockServiceName, ...] = ALL_UNLOCK_SERVICES,
    ) -> list[UnlockCheckResult]:
        async with self._semaphore:
            results: list[UnlockCheckResult] = []
            for service_name in services:
                result = await asyncio.to_thread(
                    self._probe.check,
                    connection_id,
                    service_name,
                )
                results.append(result)
            return results


def persist_unlock_checks(
    db: Session,
    connection: VPNConnection,
    results: list[UnlockCheckResult],
) -> list[ServiceCheck]:
    records = [
        ServiceCheck(
            connection_id=connection.id,
            service_name=result.service_name.value,
            status=result.status,
            region=result.region,
            latency_ms=result.latency_ms,
            failure_reason=result.failure_reason,
            details={**result.details, "simulated": result.simulated},
        )
        for result in results
    ]
    db.add_all(records)
    return records
