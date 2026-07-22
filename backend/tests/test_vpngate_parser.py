import pytest

from app.services.vpngate.parser import parse_vpngate_csv
from app.services.vpngate.types import VPNGateFeedError
from vpngate_helpers import make_csv_row, make_openvpn_config, make_vpngate_csv


def test_parses_valid_rows_and_deduplicates_by_sanitized_content() -> None:
    config = make_openvpn_config()
    payload = make_vpngate_csv(
        [
            make_csv_row(config, host_name="first"),
            make_csv_row(config, host_name="duplicate"),
        ]
    )

    report = parse_vpngate_csv(payload)

    assert len(report.nodes) == 1
    assert report.duplicate_rows == 1
    assert report.rejected_rows == 0
    assert report.nodes[0].host_name == "first"
    assert report.nodes[0].uptime_seconds == 3600
    assert report.nodes[0].sanitized_config.startswith("client\n")


def test_rejects_bad_base64_and_dangerous_config_but_keeps_valid_row() -> None:
    bad_base64 = make_csv_row(make_openvpn_config(), host_name="bad-base64")
    bad_base64[-1] = "not valid base64!"
    dangerous = make_csv_row(
        make_openvpn_config(extra_directive="script-security 2"),
        host_name="dangerous",
    )
    valid = make_csv_row(make_openvpn_config(), host_name="valid")

    report = parse_vpngate_csv(make_vpngate_csv([bad_base64, dangerous, valid]))

    assert len(report.nodes) == 1
    assert report.rejected_rows == 2
    assert report.rejection_reasons == {
        "dangerous_directive": 1,
        "invalid_config_base64": 1,
    }


def test_rejects_feed_without_header() -> None:
    with pytest.raises(VPNGateFeedError, match="missing_csv_header"):
        parse_vpngate_csv(b"HostName,IP\n")


def test_rejects_feed_with_only_invalid_nodes() -> None:
    row = make_csv_row(make_openvpn_config(ip_address="10.0.0.1"), ip_address="10.0.0.1")

    with pytest.raises(VPNGateFeedError, match="no_valid_nodes"):
        parse_vpngate_csv(make_vpngate_csv([row]))


def test_enforces_row_limit() -> None:
    row = make_csv_row(make_openvpn_config())

    with pytest.raises(VPNGateFeedError, match="row_limit_exceeded"):
        parse_vpngate_csv(make_vpngate_csv([row, row]), max_rows=1)
