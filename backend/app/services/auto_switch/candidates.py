from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import NetworkType
from app.models.network import BlockedNode, VPNConnection, VPNGateNode
from app.services.auto_switch.types import AutoSwitchOperationError, HealthPolicy


def _satisfies_cached_policy(node: VPNGateNode, policy: HealthPolicy) -> bool:
    if (
        policy.max_latency_ms is not None
        and (node.ping_ms is None or node.ping_ms > policy.max_latency_ms)
    ):
        return False
    if (
        policy.min_download_bps is not None
        and (node.speed_bps is None or node.speed_bps < policy.min_download_bps)
    ):
        return False
    return (
        not policy.allowed_network_types
        or NetworkType(node.network_type) in policy.allowed_network_types
    )


def select_candidate_node(
    db: Session,
    connection: VPNConnection,
    policy: HealthPolicy,
    *,
    requested_node_id: int | None = None,
) -> VPNGateNode:
    blocked = db.execute(
        select(BlockedNode.node_id, BlockedNode.config_hash)
    ).all()
    blocked_ids = {node_id for node_id, _ in blocked if node_id is not None}
    blocked_hashes = {config_hash for _, config_hash in blocked}

    if requested_node_id is not None:
        candidate = db.get(VPNGateNode, requested_node_id)
        candidates = [candidate] if candidate is not None else []
    else:
        candidates = list(
            db.scalars(
                select(VPNGateNode).where(VPNGateNode.is_available.is_(True))
            ).all()
        )

    eligible = [
        node
        for node in candidates
        if node is not None
        and node.id != connection.node_id
        and node.is_available
        and node.id not in blocked_ids
        and node.config_hash not in blocked_hashes
        and bool(node.sanitized_config)
        and _satisfies_cached_policy(node, policy)
    ]
    if not eligible:
        raise AutoSwitchOperationError("no_eligible_candidate")

    eligible.sort(
        key=lambda node: (
            node.failure_count,
            node.ping_ms if node.ping_ms is not None else 2_147_483_647,
            -(node.speed_bps or 0),
            -(node.score or 0),
            node.id,
        )
    )
    return eligible[0]
