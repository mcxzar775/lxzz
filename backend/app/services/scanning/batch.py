import asyncio
from collections.abc import Sequence

from sqlalchemy import select, update
from sqlalchemy.orm import Session, sessionmaker

from app.db.base import utcnow
from app.models.enums import ScanStatus, TaskStatus
from app.models.network import ScheduledTask, VPNGateNode
from app.services.ip_intelligence import NodeIntelligenceEnricher
from app.services.scanning.service import NodeScanCoordinator, scan_node
from app.services.scanning.types import ScanType


class BatchScanTaskError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class BatchScanTaskService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        coordinator: NodeScanCoordinator,
        intelligence_service: NodeIntelligenceEnricher,
        *,
        max_nodes: int = 50,
    ) -> None:
        if not 1 <= max_nodes <= 200:
            raise ValueError("invalid_batch_scan_limit")
        self._session_factory = session_factory
        self._coordinator = coordinator
        self._intelligence_service = intelligence_service
        self._max_nodes = max_nodes
        self._tasks: set[asyncio.Task[None]] = set()
        self._progress_lock = asyncio.Lock()

    def recover_interrupted(self) -> None:
        with self._session_factory() as db:
            db.execute(
                update(ScheduledTask)
                .where(
                    ScheduledTask.task_type == "node_batch_scan",
                    ScheduledTask.status.in_(
                        [TaskStatus.PENDING.value, TaskStatus.RUNNING.value]
                    ),
                )
                .values(
                    status=TaskStatus.CANCELLED,
                    last_error="service_restarted",
                )
            )
            db.commit()

    def start(
        self,
        db: Session,
        *,
        node_ids: Sequence[int],
        scan_type: ScanType,
    ) -> ScheduledTask:
        normalized = list(dict.fromkeys(node_ids))
        if not normalized or len(normalized) > self._max_nodes:
            raise BatchScanTaskError("invalid_batch_node_count")
        existing = set(
            db.scalars(select(VPNGateNode.id).where(VPNGateNode.id.in_(normalized))).all()
        )
        if existing != set(normalized):
            raise BatchScanTaskError("batch_node_not_found")
        record = ScheduledTask(
            task_type="node_batch_scan",
            status=TaskStatus.PENDING,
            payload={"node_ids": normalized, "scan_type": scan_type},
            result={
                "total": len(normalized),
                "completed": 0,
                "succeeded": 0,
                "failed": 0,
                "items": [],
            },
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        operation = asyncio.create_task(
            self._run(record.id, normalized, scan_type),
            name=f"node-batch-scan-{record.id}",
        )
        self._tasks.add(operation)
        operation.add_done_callback(self._tasks.discard)
        return record

    async def _record_result(
        self,
        task_id: int,
        *,
        node_id: int,
        status: ScanStatus,
        error_code: str | None,
        simulated: bool,
    ) -> None:
        async with self._progress_lock:
            with self._session_factory() as db:
                task = db.get(ScheduledTask, task_id)
                if task is None:
                    return
                result = dict(task.result)
                items = list(result.get("items", []))
                items.append(
                    {
                        "node_id": node_id,
                        "status": status.value,
                        "error_code": error_code,
                        "simulated": simulated,
                    }
                )
                succeeded = int(result.get("succeeded", 0))
                failed = int(result.get("failed", 0))
                if status is ScanStatus.SUCCEEDED:
                    succeeded += 1
                else:
                    failed += 1
                task.result = {
                    **result,
                    "completed": len(items),
                    "succeeded": succeeded,
                    "failed": failed,
                    "items": items,
                }
                db.commit()

    async def _scan_one(
        self,
        task_id: int,
        node_id: int,
        scan_type: ScanType,
    ) -> None:
        with self._session_factory() as db:
            node = db.get(VPNGateNode, node_id)
            if node is None:
                await self._record_result(
                    task_id,
                    node_id=node_id,
                    status=ScanStatus.FAILED,
                    error_code="node_not_found",
                    simulated=False,
                )
                return
            try:
                result = await scan_node(
                    db,
                    node,
                    self._coordinator,
                    scan_type=scan_type,
                    intelligence_service=self._intelligence_service,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._record_result(
                    task_id,
                    node_id=node_id,
                    status=ScanStatus.FAILED,
                    error_code="scan_internal_error",
                    simulated=False,
                )
                return
            await self._record_result(
                task_id,
                node_id=node_id,
                status=ScanStatus(result.status),
                error_code=result.error_code,
                simulated=result.details.get("simulated") is True,
            )

    async def _run(
        self,
        task_id: int,
        node_ids: list[int],
        scan_type: ScanType,
    ) -> None:
        with self._session_factory() as db:
            task = db.get(ScheduledTask, task_id)
            if task is None:
                return
            task.status = TaskStatus.RUNNING
            task.started_at = utcnow()
            db.commit()
        try:
            await asyncio.gather(
                *(self._scan_one(task_id, node_id, scan_type) for node_id in node_ids)
            )
        except asyncio.CancelledError:
            with self._session_factory() as db:
                task = db.get(ScheduledTask, task_id)
                if task is not None:
                    task.status = TaskStatus.CANCELLED
                    task.last_error = "task_cancelled"
                    db.commit()
            raise
        except Exception:
            with self._session_factory() as db:
                task = db.get(ScheduledTask, task_id)
                if task is not None:
                    task.status = TaskStatus.FAILED
                    task.last_error = "batch_scan_internal_error"
                    db.commit()
            return
        with self._session_factory() as db:
            task = db.get(ScheduledTask, task_id)
            if task is not None:
                task.status = TaskStatus.SUCCEEDED
                task.completed_at = utcnow()
                db.commit()

    async def stop(self) -> None:
        operations = list(self._tasks)
        for operation in operations:
            operation.cancel()
        if operations:
            await asyncio.gather(*operations, return_exceptions=True)
