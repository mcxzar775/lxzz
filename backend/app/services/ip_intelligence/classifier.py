import re

from app.models.enums import NetworkType
from app.services.ip_intelligence.types import ClassificationResult, IPIntelligence


_DATACENTER_PHRASES = (
    "amazon web services",
    "azure",
    "cloud",
    "colocation",
    "contabo",
    "data center",
    "datacenter",
    "digitalocean",
    "google cloud",
    "hetzner",
    "hosting",
    "leaseweb",
    "linode",
    "ovh",
    "server farm",
    "vps",
    "vultr",
)
_MOBILE_PHRASES = (
    "cellular",
    "mobile network",
    "mobile telecom",
    "wireless broadband",
)
_MOBILE_TOKENS = {"3g", "4g", "5g", "lte", "mobile"}
_RESIDENTIAL_PHRASES = (
    "broadband",
    "cable internet",
    "consumer internet",
    "fiber internet",
    "fibre internet",
    "home internet",
    "residential",
)
_RESIDENTIAL_TOKENS = {"cpe", "dsl", "dynamic", "fios", "pppoe", "subscriber"}
_BUSINESS_PHRASES = (
    "business network",
    "corporate network",
    "enterprise network",
)
_VPN_PHRASES = ("openvpn", "public vpn", "softether", "vpn gate", "vpngate")
_PROXY_PHRASES = ("open proxy", "proxy service", "residential proxy", "tor exit")


def _searchable_text(intelligence: IPIntelligence) -> tuple[str, set[str]]:
    raw = " ".join(
        value
        for value in (
            intelligence.asn_organization,
            intelligence.asn_type,
            intelligence.isp,
            intelligence.ptr,
        )
        if value
    ).lower()
    normalized = " ".join(re.findall(r"[a-z0-9]+", raw))
    return normalized, set(normalized.split())


def classify_ip(intelligence: IPIntelligence) -> ClassificationResult:
    scores: dict[NetworkType, int] = {}
    reasons: dict[NetworkType, list[str]] = {}

    def add(candidate: NetworkType, score: int, reason: str) -> None:
        previous = scores.get(candidate)
        scores[candidate] = score if previous is None else min(99, max(previous, score) + 4)
        bucket = reasons.setdefault(candidate, [])
        if reason not in bucket:
            bucket.append(reason)

    text, tokens = _searchable_text(intelligence)

    if any(
        flag is True
        for flag in (
            intelligence.is_proxy,
            intelligence.is_residential_proxy,
            intelligence.is_tor,
            intelligence.is_relay,
        )
    ):
        add(NetworkType.PROXY, 97, "provider_proxy_flag")
    if intelligence.is_vpn is True:
        add(NetworkType.PUBLIC_VPN, 96, "provider_vpn_flag")
    if intelligence.is_anonymous is True and not any(
        flag is True
        for flag in (
            intelligence.is_proxy,
            intelligence.is_residential_proxy,
            intelligence.is_tor,
            intelligence.is_relay,
            intelligence.is_vpn,
        )
    ):
        add(NetworkType.PROXY, 74, "provider_anonymous_flag")
    if intelligence.is_hosting is True:
        add(NetworkType.DATACENTER, 93, "provider_hosting_flag")
    if intelligence.is_mobile is True:
        add(NetworkType.MOBILE, 96, "provider_mobile_flag")

    asn_type = (intelligence.asn_type or "").lower()
    if asn_type == "hosting":
        add(NetworkType.DATACENTER, 88, "hosting_asn_type")
    elif asn_type == "business":
        add(NetworkType.BUSINESS_ISP, 86, "business_asn_type")
    elif asn_type in {"education", "government"}:
        add(NetworkType.BUSINESS_ISP, 78, "institutional_asn_type")

    if any(phrase in text for phrase in _PROXY_PHRASES):
        add(NetworkType.PROXY, 85, "proxy_keyword")
    if any(phrase in text for phrase in _VPN_PHRASES):
        add(NetworkType.PUBLIC_VPN, 88, "vpn_keyword")
    if any(phrase in text for phrase in _DATACENTER_PHRASES):
        add(NetworkType.DATACENTER, 82, "datacenter_keyword")
    if any(phrase in text for phrase in _MOBILE_PHRASES) or tokens.intersection(
        _MOBILE_TOKENS
    ):
        add(NetworkType.MOBILE, 84, "mobile_keyword")
    residential_signal = any(
        phrase in text for phrase in _RESIDENTIAL_PHRASES
    ) or bool(tokens.intersection(_RESIDENTIAL_TOKENS))
    if residential_signal:
        score = 88 if asn_type == "isp" else 78
        add(NetworkType.RESIDENTIAL_LIKELY, score, "consumer_access_keyword")
    if any(phrase in text for phrase in _BUSINESS_PHRASES):
        add(NetworkType.BUSINESS_ISP, 80, "business_keyword")

    if not scores:
        return ClassificationResult(
            NetworkType.UNKNOWN,
            0.0,
            ("insufficient_evidence",),
        )

    priority = {
        NetworkType.PROXY: 6,
        NetworkType.PUBLIC_VPN: 5,
        NetworkType.DATACENTER: 4,
        NetworkType.MOBILE: 3,
        NetworkType.RESIDENTIAL_LIKELY: 2,
        NetworkType.BUSINESS_ISP: 1,
    }
    ordered = sorted(
        scores,
        key=lambda candidate: (scores[candidate], priority[candidate]),
        reverse=True,
    )
    winner = ordered[0]
    confidence = scores[winner] / 100
    winner_reasons = list(reasons[winner])
    if len(ordered) > 1 and scores[ordered[1]] >= scores[winner] - 10:
        confidence = max(0.5, confidence - 0.15)
        winner_reasons.append("conflicting_signals")
    return ClassificationResult(
        winner,
        round(confidence, 2),
        tuple(winner_reasons),
    )
