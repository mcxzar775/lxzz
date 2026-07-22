from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.models.enums import ScanStatus
from app.services.ip_intelligence import IPIntelligence, IPIntelligenceService
from app.services.scanning.types import NodeScanOutcome, NodeScanTarget, ScanType
from conftest import UserCredentials, login
from vpngate_helpers import make_csv_row, make_openvpn_config, make_vpngate_csv


class StaticFetcher:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    async def fetch_csv(self) -> bytes:
        return self.payload


class StaticScanCoordinator:
    def __init__(self, outcome: NodeScanOutcome) -> None:
        self.outcome = outcome
        self.targets: list[tuple[NodeScanTarget, ScanType]] = []

    async def scan(
        self,
        target: NodeScanTarget,
        *,
        scan_type: ScanType,
    ) -> NodeScanOutcome:
        self.targets.append((target, scan_type))
        return self.outcome


def _refresh_one_node(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> str:
    app.state.vpngate_fetcher = StaticFetcher(
        make_vpngate_csv([make_csv_row(make_openvpn_config())])
    )
    csrf = login(client, test_users.admin_username, test_users.admin_password)
    response = client.post("/api/v1/nodes/refresh", headers={"X-CSRF-Token": csrf})
    assert response.status_code == 200
    return csrf


def test_admin_refreshes_and_viewer_lists_nodes(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    config = make_openvpn_config()
    payload = make_vpngate_csv([make_csv_row(config)])
    app.state.vpngate_fetcher = StaticFetcher(payload)
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    response = client.post(
        "/api/v1/nodes/refresh", headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "fetched_bytes": len(payload),
        "valid_nodes": 1,
        "inserted": 1,
        "updated": 0,
        "rejected_rows": 0,
        "duplicate_rows": 0,
        "rejection_reasons": {},
    }

    login(client, test_users.viewer_username, test_users.viewer_password)
    listing = client.get("/api/v1/nodes?country_code=us&protocol=udp")

    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["total"] == 1
    assert body["limit"] == 50
    assert body["offset"] == 0
    assert body["items"][0]["ip_address"] == "8.8.8.8"
    assert "sanitized_config" not in body["items"][0]


def test_refresh_updates_existing_node(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    config = make_openvpn_config()
    app.state.vpngate_fetcher = StaticFetcher(
        make_vpngate_csv([make_csv_row(config)])
    )
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    first = client.post("/api/v1/nodes/refresh", headers={"X-CSRF-Token": csrf})
    second = client.post("/api/v1/nodes/refresh", headers={"X-CSRF-Token": csrf})

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["inserted"] == 0
    assert second.json()["updated"] == 1


def test_viewer_cannot_refresh_nodes(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    app.state.vpngate_fetcher = StaticFetcher(b"unused")
    csrf = login(client, test_users.viewer_username, test_users.viewer_password)

    response = client.post(
        "/api/v1/nodes/refresh", headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 403


def test_refresh_requires_csrf(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    app.state.vpngate_fetcher = StaticFetcher(b"unused")
    login(client, test_users.admin_username, test_users.admin_password)

    response = client.post("/api/v1/nodes/refresh")

    assert response.status_code == 403


def test_invalid_feed_returns_generic_error_without_config_content(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    secret_marker = "do-not-expose-this-config-marker"
    app.state.vpngate_fetcher = StaticFetcher(secret_marker.encode("utf-8"))
    csrf = login(client, test_users.admin_username, test_users.admin_password)

    response = client.post(
        "/api/v1/nodes/refresh", headers={"X-CSRF-Token": csrf}
    )

    assert response.status_code == 502
    assert secret_marker not in response.text


def test_admin_runs_simulated_fast_scan_and_viewer_reads_history(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = _refresh_one_node(app, client, test_users)

    response = client.post(
        "/api/v1/nodes/1/scan?scan_type=fast",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["scan_type"] == "fast"
    assert result["status"] == "SUCCEEDED"
    assert result["simulated"] is True
    assert result["details"]["simulated"] is True
    assert "sanitized_config" not in response.text

    login(client, test_users.viewer_username, test_users.viewer_password)
    history = client.get("/api/v1/nodes/1/scans")
    assert history.status_code == 200
    assert history.json()["total"] == 1
    assert history.json()["items"][0]["id"] == result["id"]


def test_real_scan_outcome_updates_availability_without_exposing_config(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = _refresh_one_node(app, client, test_users)
    coordinator = StaticScanCoordinator(
        NodeScanOutcome(
            scan_type="fast",
            status=ScanStatus.SUCCEEDED,
            latency_ms=12.4,
            details={
                "simulated": False,
                "ptr": "dns.google",
                "node_reachability_confirmed": True,
            },
        )
    )
    app.state.node_scan_coordinator = coordinator

    response = client.post(
        "/api/v1/nodes/1/scan",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200
    assert response.json()["simulated"] is False
    listing = client.get("/api/v1/nodes?available=true")
    assert listing.status_code == 200
    item = listing.json()["items"][0]
    assert item["is_available"] is True
    assert item["failure_count"] == 0
    assert item["ping_ms"] == 12
    assert item["ptr"] == "dns.google"
    assert coordinator.targets[0][0].sanitized_config.startswith("client\n")
    assert "sanitized_config" not in listing.text


def test_viewer_cannot_scan_and_scan_requires_csrf(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    _refresh_one_node(app, client, test_users)
    viewer_csrf = login(
        client, test_users.viewer_username, test_users.viewer_password
    )

    forbidden = client.post(
        "/api/v1/nodes/1/scan",
        headers={"X-CSRF-Token": viewer_csrf},
    )
    assert forbidden.status_code == 403

    login(client, test_users.admin_username, test_users.admin_password)
    missing_csrf = client.post("/api/v1/nodes/1/scan")
    assert missing_csrf.status_code == 403


def test_full_scan_uses_reserved_simulation_and_missing_node_is_404(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = _refresh_one_node(app, client, test_users)

    response = client.post(
        "/api/v1/nodes/1/scan?scan_type=full",
        headers={"X-CSRF-Token": csrf},
    )
    missing = client.post(
        "/api/v1/nodes/999/scan",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200
    assert response.json()["scan_type"] == "full"
    assert response.json()["simulated"] is True
    assert 16_375 <= response.json()["details"]["resource_id"] <= 16_384
    assert missing.status_code == 404


def test_real_full_scan_enriches_exit_ip_with_network_free_fallback(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = _refresh_one_node(app, client, test_users)
    app.state.node_scan_coordinator = StaticScanCoordinator(
        NodeScanOutcome(
            scan_type="full",
            status=ScanStatus.SUCCEEDED,
            latency_ms=19.0,
            exit_ip="1.1.1.1",
            details={"simulated": False, "https_ok": True},
        )
    )

    response = client.post(
        "/api/v1/nodes/1/scan?scan_type=full",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 200, response.text
    intelligence = response.json()["details"]["ip_intelligence"]
    assert intelligence == {
        "source": "local",
        "network_type": "UNKNOWN",
        "confidence": 0.0,
        "reasons": ["insufficient_evidence"],
    }
    listing = client.get("/api/v1/nodes")
    item = listing.json()["items"][0]
    assert item["classified_exit_ip"] == "1.1.1.1"
    assert item["intelligence_source"] == "local"
    assert item["network_type"] == "UNKNOWN"
    assert item["network_confidence"] == 0.0
    assert item["intelligence_checked_at"] is not None

    classified = client.post(
        "/api/v1/nodes/1/classify",
        headers={"X-CSRF-Token": csrf},
    )
    assert classified.status_code == 200
    assert classified.json()["classified_exit_ip"] == "1.1.1.1"


def test_classification_requires_a_real_full_scan(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = _refresh_one_node(app, client, test_users)

    response = client.post(
        "/api/v1/nodes/1/classify",
        headers={"X-CSRF-Token": csrf},
    )

    assert response.status_code == 409


def test_node_list_filters_classification_fields(
    app: FastAPI,
    client: TestClient,
    test_users: UserCredentials,
) -> None:
    csrf = _refresh_one_node(app, client, test_users)

    class ResidentialProvider:
        async def lookup(self, ip_address: str) -> IPIntelligence:
            return IPIntelligence(
                ip_address,
                "test_provider",
                asn=64512,
                asn_organization="Example Broadband",
                asn_type="isp",
                ptr="customer-1.broadband.example",
            )

    app.state.ip_intelligence_service = IPIntelligenceService(ResidentialProvider())
    app.state.node_scan_coordinator = StaticScanCoordinator(
        NodeScanOutcome(
            scan_type="full",
            status=ScanStatus.SUCCEEDED,
            exit_ip="8.8.8.8",
            details={"simulated": False},
        )
    )
    scanned = client.post(
        "/api/v1/nodes/1/scan?scan_type=full",
        headers={"X-CSRF-Token": csrf},
    )
    assert scanned.status_code == 200

    residential = client.get(
        "/api/v1/nodes?network_type=RESIDENTIAL_LIKELY&min_confidence=0.5"
    )
    by_search = client.get("/api/v1/nodes?search=broadband.example")
    wrong_type = client.get("/api/v1/nodes?network_type=DATACENTER")

    assert residential.status_code == 200
    assert residential.json()["total"] == 1
    assert by_search.json()["total"] == 1
    assert wrong_type.json()["total"] == 0
