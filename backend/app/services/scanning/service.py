import asyncio

from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.enums import ScanStatus
from app.models.network import NodeScanResult, VPNGateNode
from app.services.ip_intelligence import NodeIntelligenceEnricher
from app.services.network.commands import MAX_NAMESPACE_RESOURCES
from app.services.scanning.fast import FastScanTransport
from app.services.scanning.full import FullScanRunner
from app.services.scanning.types import NodeScanOutcome, NodeScanTarget, ScanType


class NodeScanCoordinator:
    def __init__(
        self,
        fast_transport: FastScanTransport,
        full_runner: FullScanRunner,
        *,
        concurrency: int = 3,
        fast_timeout_seconds: float = 30.0,
        full_timeout_seconds: float = 90.0,
    ) -> None:
        if isinstance(concurrency, bool) or not 1 <= concurrency <= 10:
            raise ValueError("invalid_scan_concurrency")
        if not 0 < fast_timeout_seconds <= 120:
            raise ValueError("invalid_fast_scan_timeout")
        if not 0 < full_timeout_seconds <= 300:
            raise ValueError("invalid_full_scan_timeout")
        self._fast_transport = fast_transport
        self._full_runner = full_runner
        self._semaphore = asyncio.Semaphore(concurrency)
        self._slots: asyncio.Queue[int] = asyncio.Queue(maxsize=concurrency)
        first_slot = MAX_NAMESPACE_RESOURCES - concurrency + 1
        for resource_id in range(first_slot, MAX_NAMESPACE_RESOURCES + 1):
            self._slots.put_nowait(resource_id)
        self._fast_timeout_seconds = fast_timeout_seconds
        self._full_timeout_seconds = full_timeout_seconds

    @staticmethod
    async def _wait_safely(
        operation: "asyncio.Task[NodeScanOutcome]",
        *,
        timeout_seconds: float,
        timeout_code: str,
        scan_type: ScanType,
    ) -> NodeScanOutcome:
        try:
            return await asyncio.wait_for(
                asyncio.shield(operation),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            try:
                await operation
            except Exception:
                pass
            return NodeScanOutcome(
                scan_type=scan_type,
                status=ScanStatus.TIMEOUT,
                error_code=timeout_code,
                details={"simulated": False},
            )
        except asyncio.CancelledError:
            try:
                await operation
            except Exception:
                pass
            raise

    async def scan(
        self,
        target: NodeScanTarget,
        *,
        scan_type: ScanType,
    ) -> NodeScanOutcome:
        async with self._semaphore:
            if scan_type == "fast":
                operation = asyncio.create_task(self._fast_transport.scan(target))
                try:
                    return await self._wait_safely(
                        operation,
                        timeout_seconds=self._fast_timeout_seconds,
                        timeout_code="fast_scan_timeout",
                        scan_type="fast",
                    )
                except Exception:
                    return NodeScanOutcome(
                        scan_type="fast",
                        status=ScanStatus.FAILED,
                        error_code="scan_internal_error",
                        details={"simulated": False},
                    )

            resource_id = await self._slots.get()
            try:
                operation = asyncio.create_task(
                    self._full_runner.scan(target, resource_id=resource_id)
                )
                try:
                    return await self._wait_safely(
                        operation,
                        timeout_seconds=self._full_timeout_seconds,
                        timeout_code="full_scan_timeout",
                        scan_type="full",
                    )
                except Exception:
                    return NodeScanOutcome(
                        scan_type="full",
                        status=ScanStatus.FAILED,
                        error_code="scan_internal_error",
                        details={"simulated": False, "resource_id": resource_id},
                    )
            finally:
                self._slots.put_nowait(resource_id)


def node_scan_target(node: VPNGateNode) -> NodeScanTarget:
    return NodeScanTarget(
        node_id=node.id,
        host_name=node.host_name,
        ip_address=node.ip_address,
        protocol=node.protocol,
        remote_port=node.remote_port,
        sanitized_config=node.sanitized_config,
        advertised_ping_ms=node.ping_ms,
    )


def _apply_real_outcome(node: VPNGateNode, outcome: NodeScanOutcome) -> None:
    if outcome.status is ScanStatus.SUCCEEDED:
        reachability_confirmed = (
            outcome.scan_type == "full"
            or outcome.safe_details.get("node_reachability_confirmed") is True
        )
        if reachability_confirmed:
            node.is_available = True
            node.failure_count = 0
            node.last_success_at = utcnow()
        if outcome.latency_ms is not None:
            node.ping_ms = min(round(outcome.latency_ms), 2_147_483_647)
        ptr = outcome.safe_details.get("ptr")
        if isinstance(ptr, str) and len(ptr) <= 255:
            node.ptr = ptr
    else:
        node.is_available = False
        node.failure_count += 1


async def scan_node(
    db: Session,
    node: VPNGateNode,
    coordinator: NodeScanCoordinator,
    *,
    scan_type: ScanType,
    intelligence_service: NodeIntelligenceEnricher | None = None,
) -> NodeScanResult:
    record = NodeScanResult(
        node_id=node.id,
        scan_type=scan_type,
        status=ScanStatus.RUNNING,
        details={"simulated": False},
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    try:
        outcome = await coordinator.scan(
            node_scan_target(node),
            scan_type=scan_type,
        )
    except asyncio.CancelledError:
        record.status = ScanStatus.FAILED
        record.error_code = "scan_cancelled"
        record.details = {"simulated": False}
        record.completed_at = utcnow()
        db.commit()
        raise

    details = outcome.safe_details
    if (
        intelligence_service is not None
        and outcome.scan_type == "full"
        and outcome.status is ScanStatus.SUCCEEDED
        and outcome.exit_ip is not None
        and not outcome.simulated
    ):
        try:
            summary = await intelligence_service.enrich_node(
                node,
                exit_ip=outcome.exit_ip,
            )
        except Exception:
            details["ip_intelligence"] = {
                "source": "local_fallback",
                "network_type": "UNKNOWN",
                "confidence": 0.0,
                "reasons": ["classification_internal_error"],
                "provider_error_code": "ip_intelligence_internal_error",
            }
        else:
            details["ip_intelligence"] = summary.safe_details()

    record.status = outcome.status
    record.latency_ms = outcome.latency_ms
    record.exit_ip = outcome.exit_ip
    record.error_code = outcome.error_code
    record.details = details
    record.completed_at = utcnow()
    if not outcome.simulated:
        _apply_real_outcome(node, outcome)
    db.commit()
    db.refresh(record)
    return record
