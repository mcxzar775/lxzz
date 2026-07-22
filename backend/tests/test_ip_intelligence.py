import asyncio
import json

import httpx
import pytest
from pydantic import SecretStr

from app.models.enums import NetworkType
from app.models.network import VPNGateNode
from app.services.ip_intelligence import (
    IPInfoProvider,
    IPIntelligence,
    IPIntelligenceError,
    IPIntelligenceService,
    build_ip_intelligence_service,
    classify_ip,
    parse_ipinfo_response,
)


def _node() -> VPNGateNode:
    return VPNGateNode(
        id=7,
        config_hash="a" * 64,
        host_name="public-vpn.example",
        ip_address="8.8.8.8",
        country_code="US",
        country_long="United States",
        protocol="udp",
        remote_port=1194,
        sanitized_config="client\n",
        ptr="customer-8-8-8-8.broadband.example",
    )


@pytest.mark.parametrize(
    ("intelligence", "expected_type", "minimum_confidence"),
    [
        (
            IPIntelligence(
                "1.1.1.1",
                "test",
                is_hosting=True,
                asn_type="hosting",
                asn_organization="Example Cloud Hosting",
            ),
            NetworkType.DATACENTER,
            0.9,
        ),
        (
            IPIntelligence("1.1.1.1", "test", is_mobile=True),
            NetworkType.MOBILE,
            0.9,
        ),
        (
            IPIntelligence("1.1.1.1", "test", is_vpn=True),
            NetworkType.PUBLIC_VPN,
            0.9,
        ),
        (
            IPIntelligence("1.1.1.1", "test", is_residential_proxy=True),
            NetworkType.PROXY,
            0.9,
        ),
        (
            IPIntelligence(
                "1.1.1.1",
                "test",
                asn_type="isp",
                ptr="customer-12-34.cpe.broadband.example",
            ),
            NetworkType.RESIDENTIAL_LIKELY,
            0.85,
        ),
        (
            IPIntelligence("1.1.1.1", "test", asn_type="business"),
            NetworkType.BUSINESS_ISP,
            0.8,
        ),
    ],
)
def test_classifier_maps_explainable_network_types(
    intelligence: IPIntelligence,
    expected_type: NetworkType,
    minimum_confidence: float,
) -> None:
    result = classify_ip(intelligence)

    assert result.network_type is expected_type
    assert result.confidence >= minimum_confidence
    assert result.reasons


def test_classifier_returns_unknown_without_evidence_and_reduces_conflicts() -> None:
    unknown = classify_ip(IPIntelligence("1.1.1.1", "test"))
    conflict = classify_ip(
        IPIntelligence(
            "1.1.1.1",
            "test",
            is_hosting=True,
            is_mobile=True,
        )
    )

    assert unknown.network_type is NetworkType.UNKNOWN
    assert unknown.confidence == 0.0
    assert unknown.reasons == ("insufficient_evidence",)
    assert conflict.network_type is NetworkType.MOBILE
    assert conflict.confidence < 0.9
    assert "conflicting_signals" in conflict.reasons


def test_ipinfo_parser_supports_lookup_schema_and_privacy_flags() -> None:
    result = parse_ipinfo_response(
        {
            "ip": "1.1.1.1",
            "hostname": "one.one.one.one",
            "geo": {
                "city": "Brisbane",
                "country": "Australia",
                "country_code": "AU",
            },
            "as": {
                "asn": "AS13335",
                "name": "Cloudflare, Inc.",
                "type": "hosting",
            },
            "anonymous": {
                "is_proxy": False,
                "is_relay": False,
                "is_tor": False,
                "is_vpn": False,
                "is_res_proxy": False,
            },
            "is_anonymous": False,
            "is_hosting": True,
            "is_mobile": False,
        },
        requested_ip="1.1.1.1",
    )

    assert result.country_code == "AU"
    assert result.country_name == "Australia"
    assert result.city == "Brisbane"
    assert result.asn == 13335
    assert result.asn_organization == "Cloudflare, Inc."
    assert result.ptr == "one.one.one.one"
    assert result.is_hosting is True
    assert classify_ip(result).network_type is NetworkType.DATACENTER


def test_ipinfo_parser_rejects_an_address_mismatch() -> None:
    with pytest.raises(IPIntelligenceError) as exc_info:
        parse_ipinfo_response({"ip": "8.8.8.8"}, requested_ip="1.1.1.1")
    assert exc_info.value.code == "ip_intelligence_address_mismatch"


def test_ipinfo_provider_uses_bearer_header_without_token_in_url() -> None:
    secret = "unit-test-token-do-not-log"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://api.ipinfo.io/lookup/1.1.1.1")
        assert request.headers["Authorization"] == f"Bearer {secret}"
        assert secret not in str(request.url)
        return httpx.Response(
            200,
            json={
                "ip": "1.1.1.1",
                "geo": {"country": "Australia", "country_code": "AU"},
                "as": {"asn": "AS13335", "name": "Cloudflare", "type": "hosting"},
                "is_hosting": True,
            },
        )

    async def run() -> IPIntelligence:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = IPInfoProvider(SecretStr(secret), client=client)
            return await provider.lookup("1.1.1.1")

    result = asyncio.run(run())
    assert result.asn == 13335
    assert secret not in repr(IPInfoProvider(SecretStr(secret)))


def test_ipinfo_provider_enforces_response_limit_and_safe_error_codes() -> None:
    oversized = json.dumps({"ip": "1.1.1.1", "padding": "x" * 2048}).encode()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=oversized)

    async def run() -> None:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            provider = IPInfoProvider(
                SecretStr("unit-test-token"),
                max_response_bytes=1024,
                client=client,
            )
            with pytest.raises(IPIntelligenceError) as exc_info:
                await provider.lookup("1.1.1.1")
            assert exc_info.value.code == "ip_intelligence_response_too_large"

    asyncio.run(run())


def test_service_falls_back_to_local_context_without_failing_classification() -> None:
    class FailingProvider:
        async def lookup(self, ip_address: str) -> IPIntelligence:
            del ip_address
            raise IPIntelligenceError("ip_intelligence_provider_unavailable")

    node = _node()
    service = IPIntelligenceService(FailingProvider())

    summary = asyncio.run(service.enrich_node(node, exit_ip="8.8.8.8"))

    assert summary.source == "local_fallback"
    assert summary.provider_error_code == "ip_intelligence_provider_unavailable"
    assert summary.network_type is NetworkType.RESIDENTIAL_LIKELY
    assert node.classified_exit_ip == "8.8.8.8"
    assert node.exit_country_code == "US"
    assert node.network_classification_reasons
    assert node.intelligence_checked_at is not None


def test_real_provider_builder_requires_both_setting_and_exact_environment_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = SecretStr("unit-test-token")
    monkeypatch.delenv("VPNGATE_ENABLE_REAL_IP_INTELLIGENCE", raising=False)

    with pytest.raises(RuntimeError):
        build_ip_intelligence_service(
            enable_real_ip_intelligence=True,
            api_token=token,
            timeout_seconds=10,
            max_response_bytes=65536,
        )

    monkeypatch.setenv("VPNGATE_ENABLE_REAL_IP_INTELLIGENCE", "true")
    service = build_ip_intelligence_service(
        enable_real_ip_intelligence=True,
        api_token=token,
        timeout_seconds=10,
        max_response_bytes=65536,
    )
    assert isinstance(service, IPIntelligenceService)


def test_disabled_provider_never_requires_a_token_or_environment_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNGATE_ENABLE_REAL_IP_INTELLIGENCE", "true")

    service = build_ip_intelligence_service(
        enable_real_ip_intelligence=False,
        api_token=None,
        timeout_seconds=10,
        max_response_bytes=65536,
    )
    assert isinstance(service, IPIntelligenceService)
