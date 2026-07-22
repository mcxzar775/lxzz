import os

from pydantic import SecretStr

from app.db.base import utcnow
from app.models.network import VPNGateNode
from app.services.ip_intelligence.classifier import classify_ip
from app.services.ip_intelligence.providers import (
    IPInfoProvider,
    IPIntelligenceError,
    LocalIPIntelligenceProvider,
)
from app.services.ip_intelligence.types import (
    IPClassificationSummary,
    IPIntelligence,
    IPIntelligenceProvider,
)


class IPIntelligenceService:
    def __init__(self, provider: IPIntelligenceProvider) -> None:
        self._provider = provider

    @staticmethod
    def _local_context(
        node: VPNGateNode,
        intelligence: IPIntelligence,
        *,
        exit_ip: str,
    ) -> IPIntelligence:
        same_server_ip = node.ip_address == exit_ip
        same_cached_exit = node.classified_exit_ip == exit_ip
        if not same_server_ip and not same_cached_exit:
            return intelligence
        country_code = intelligence.country_code
        country_name = intelligence.country_name
        city = intelligence.city
        asn = intelligence.asn
        asn_organization = intelligence.asn_organization
        isp = intelligence.isp
        ptr = intelligence.ptr
        source = intelligence.source
        if same_cached_exit:
            country_code = country_code or node.exit_country_code
            country_name = country_name or node.exit_country_name
            city = city or node.exit_city
            source = "local_cache" if source == "local" else source
        if same_server_ip:
            country_code = country_code or node.country_code
            country_name = country_name or node.country_long
            source = "local_vpngate" if source == "local" else source
        asn = asn or node.asn
        asn_organization = asn_organization or node.asn_organization
        isp = isp or node.isp
        ptr = ptr or node.ptr
        return IPIntelligence(
            ip_address=exit_ip,
            source=source,
            country_code=country_code,
            country_name=country_name,
            city=city,
            asn=asn,
            asn_organization=asn_organization,
            asn_type=intelligence.asn_type,
            isp=isp,
            ptr=ptr,
            is_anonymous=intelligence.is_anonymous,
            is_hosting=intelligence.is_hosting,
            is_mobile=intelligence.is_mobile,
            is_proxy=intelligence.is_proxy,
            is_residential_proxy=intelligence.is_residential_proxy,
            is_tor=intelligence.is_tor,
            is_relay=intelligence.is_relay,
            is_vpn=intelligence.is_vpn,
        )

    async def enrich_node(
        self,
        node: VPNGateNode,
        *,
        exit_ip: str,
    ) -> IPClassificationSummary:
        provider_error_code: str | None = None
        try:
            intelligence = await self._provider.lookup(exit_ip)
        except IPIntelligenceError as exc:
            provider_error_code = exc.code
            intelligence = IPIntelligence(
                ip_address=exit_ip,
                source="local_fallback",
            )
        intelligence = self._local_context(node, intelligence, exit_ip=exit_ip)
        classification = classify_ip(intelligence)

        node.classified_exit_ip = exit_ip
        node.exit_country_code = intelligence.country_code
        node.exit_country_name = intelligence.country_name
        node.exit_city = intelligence.city
        node.asn = intelligence.asn
        node.asn_organization = intelligence.asn_organization
        node.isp = intelligence.isp or intelligence.asn_organization
        node.ptr = intelligence.ptr
        node.intelligence_source = intelligence.source
        node.intelligence_checked_at = utcnow()
        node.network_type = classification.network_type
        node.network_confidence = classification.confidence
        node.network_classification_reasons = list(classification.reasons)
        return IPClassificationSummary(
            source=intelligence.source,
            network_type=classification.network_type,
            confidence=classification.confidence,
            reasons=classification.reasons,
            provider_error_code=provider_error_code,
        )


def build_ip_intelligence_service(
    *,
    enable_real_ip_intelligence: bool,
    api_token: SecretStr | None,
    timeout_seconds: float,
    max_response_bytes: int,
) -> IPIntelligenceService:
    if not enable_real_ip_intelligence:
        return IPIntelligenceService(LocalIPIntelligenceProvider())
    if os.getenv("VPNGATE_ENABLE_REAL_IP_INTELLIGENCE") != "true":
        raise RuntimeError(
            "real IP intelligence requires VPNGATE_ENABLE_REAL_IP_INTELLIGENCE=true"
        )
    if api_token is None or not api_token.get_secret_value():
        raise RuntimeError("real IP intelligence requires an IPinfo API token")
    return IPIntelligenceService(
        IPInfoProvider(
            api_token,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )
    )
