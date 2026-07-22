from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.base import utcnow
from app.models.network import VPNGateNode
from app.services.vpngate.types import ImportResult, ParsedVPNGateNode


def _apply_metadata(target: VPNGateNode, source: ParsedVPNGateNode) -> None:
    target.host_name = source.host_name
    target.ip_address = source.ip_address
    target.score = source.score
    target.ping_ms = source.ping_ms
    target.speed_bps = source.speed_bps
    target.country_long = source.country_long
    target.country_code = source.country_code
    target.sessions = source.sessions
    target.uptime_seconds = source.uptime_seconds
    target.total_users = source.total_users
    target.total_traffic_bytes = source.total_traffic_bytes
    target.protocol = source.protocol
    target.remote_port = source.remote_port
    target.sanitized_config = source.sanitized_config


def import_nodes(
    db: Session,
    nodes: list[ParsedVPNGateNode],
    *,
    observed_at: datetime | None = None,
) -> ImportResult:
    now = observed_at or utcnow()
    hashes = [node.config_hash for node in nodes]
    existing: dict[str, VPNGateNode] = {}
    for start in range(0, len(hashes), 500):
        batch = hashes[start : start + 500]
        existing.update(
            {
                item.config_hash: item
                for item in db.scalars(
                    select(VPNGateNode).where(VPNGateNode.config_hash.in_(batch))
                )
            }
        )

    inserted = 0
    updated = 0
    for source in nodes:
        target = existing.get(source.config_hash)
        if target is None:
            target = VPNGateNode(
                config_hash=source.config_hash,
                ip_address=source.ip_address,
                protocol=source.protocol,
                remote_port=source.remote_port,
                sanitized_config=source.sanitized_config,
                first_seen_at=now,
                last_seen_at=now,
            )
            _apply_metadata(target, source)
            db.add(target)
            existing[source.config_hash] = target
            inserted += 1
        else:
            _apply_metadata(target, source)
            target.last_seen_at = now
            updated += 1
    db.flush()
    return ImportResult(inserted=inserted, updated=updated)
