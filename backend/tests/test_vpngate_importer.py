from datetime import datetime, timedelta, timezone

from fastapi import FastAPI
from sqlalchemy import select

from app.models.network import VPNGateNode
from app.services.vpngate.importer import import_nodes
from app.services.vpngate.parser import parse_vpngate_csv
from vpngate_helpers import make_csv_row, make_openvpn_config, make_vpngate_csv


def test_imports_then_updates_observation_without_resetting_health(app: FastAPI) -> None:
    first_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    second_time = first_time + timedelta(hours=1)
    config = make_openvpn_config()
    first_report = parse_vpngate_csv(
        make_vpngate_csv([make_csv_row(config, score="1000")])
    )
    second_report = parse_vpngate_csv(
        make_vpngate_csv([make_csv_row(config, score="2000")])
    )

    with app.state.session_factory() as db:
        first = import_nodes(db, first_report.nodes, observed_at=first_time)
        db.commit()
        node = db.scalar(select(VPNGateNode))
        assert node is not None
        node.last_success_at = first_time
        node.failure_count = 3
        node.is_available = True
        db.commit()

        second = import_nodes(db, second_report.nodes, observed_at=second_time)
        db.commit()
        db.refresh(node)

        assert first.inserted == 1 and first.updated == 0
        assert second.inserted == 0 and second.updated == 1
        assert node.score == 2000
        assert node.first_seen_at.replace(tzinfo=timezone.utc) == first_time
        assert node.last_seen_at.replace(tzinfo=timezone.utc) == second_time
        assert node.last_success_at is not None
        assert node.failure_count == 3
        assert node.is_available is True
