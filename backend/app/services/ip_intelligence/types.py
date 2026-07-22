import ipaddress
from dataclasses import dataclass
from typing import Protocol

from app.models.enums import NetworkType
from app.models.network import VPNGateNode


@dataclass(frozen=True)
class IPIntelligence:
    ip_address: str
    source: str
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None
    asn: int | None = None
    asn_organization: str | None = None
    asn_type: str | None = None
    isp: str | None = None
    ptr: str | None = None
    is_anonymous: bool | None = None
    is_hosting: bool | None = None
    is_mobile: bool | None = None
    is_proxy: bool | None = None
    is_residential_proxy: bool | None = None
    is_tor: bool | None = None
    is_relay: bool | None = None
    is_vpn: bool | None = None

    def __post_init__(self) -> None:
        try:
            address = ipaddress.ip_address(self.ip_address)
        except ValueError as exc:
            raise ValueError("invalid_ip_intelligence") from exc
        text_limits = (
            (self.source, 32),
            (self.country_code, 8),
            (self.country_name, 128),
            (self.city, 128),
            (self.asn_organization, 255),
            (self.asn_type, 32),
            (self.isp, 255),
            (self.ptr, 255),
        )
        if (
            not address.is_global
            or str(address) != self.ip_address
            or not self.source
            or not self.source.isascii()
            or any(
                value is not None
                and (
                    not value
                    or len(value) > limit
                    or any(ord(character) < 32 for character in value)
                )
                for value, limit in text_limits
            )
            or self.asn is not None
            and (isinstance(self.asn, bool) or not 1 <= self.asn <= 4_294_967_295)
        ):
            raise ValueError("invalid_ip_intelligence")


@dataclass(frozen=True)
class ClassificationResult:
    network_type: NetworkType
    confidence: float
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            not 0 <= self.confidence <= 1
            or not self.reasons
            or any(
                not reason
                or len(reason) > 64
                or not reason.isascii()
                or not reason.replace("_", "").isalnum()
                for reason in self.reasons
            )
        ):
            raise ValueError("invalid_classification_result")


@dataclass(frozen=True)
class IPClassificationSummary:
    source: str
    network_type: NetworkType
    confidence: float
    reasons: tuple[str, ...]
    provider_error_code: str | None = None

    def safe_details(self) -> dict[str, object]:
        details: dict[str, object] = {
            "source": self.source,
            "network_type": self.network_type.value,
            "confidence": self.confidence,
            "reasons": list(self.reasons),
        }
        if self.provider_error_code is not None:
            details["provider_error_code"] = self.provider_error_code
        return details


class NodeIntelligenceEnricher(Protocol):
    async def enrich_node(
        self,
        node: VPNGateNode,
        *,
        exit_ip: str,
    ) -> IPClassificationSummary: ...


class IPIntelligenceProvider(Protocol):
    async def lookup(self, ip_address: str) -> IPIntelligence: ...
