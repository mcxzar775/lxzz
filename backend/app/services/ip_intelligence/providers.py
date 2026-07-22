import ipaddress
import json
from typing import Any
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from app.services.ip_intelligence.types import IPIntelligence


IPINFO_LOOKUP_URL = "https://api.ipinfo.io/lookup"


class IPIntelligenceError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _validated_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError("invalid_ip_intelligence_address") from exc
    if not address.is_global or str(address) != value:
        raise ValueError("invalid_ip_intelligence_address")
    return value


def _text(value: object, *, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > limit
        or any(ord(character) < 32 for character in normalized)
    ):
        return None
    return normalized


def _mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _hostname(value: object) -> str | None:
    hostname = _text(value, limit=255)
    return hostname.rstrip(".") if hostname is not None else None


def _flag(container: dict[str, Any], key: str) -> bool | None:
    value = container.get(key)
    return value if isinstance(value, bool) else None


def _combine_flags(*values: bool | None) -> bool | None:
    if any(value is True for value in values):
        return True
    if any(value is False for value in values):
        return False
    return None


def _asn_number(value: object) -> int | None:
    if isinstance(value, str) and value.upper().startswith("AS"):
        value = value[2:]
    if isinstance(value, str) and value.isdecimal():
        parsed = int(value)
    elif isinstance(value, int) and not isinstance(value, bool):
        parsed = value
    else:
        return None
    return parsed if 1 <= parsed <= 4_294_967_295 else None


def parse_ipinfo_response(
    payload: object,
    *,
    requested_ip: str,
) -> IPIntelligence:
    if not isinstance(payload, dict):
        raise IPIntelligenceError("ip_intelligence_invalid_response")
    data = {str(key): value for key, value in payload.items()}
    response_ip = _text(data.get("ip"), limit=64)
    if response_ip != requested_ip:
        raise IPIntelligenceError("ip_intelligence_address_mismatch")

    geo = _mapping(data.get("geo"))
    as_data = _mapping(data.get("as")) or _mapping(data.get("asn"))
    anonymous = _mapping(data.get("anonymous"))
    privacy = _mapping(data.get("privacy"))
    mobile = data.get("mobile")
    mobile_details = _mapping(mobile)
    mobile_flag = _flag(data, "is_mobile")
    if mobile_flag is None and mobile_details:
        mobile_flag = True

    country_code = _text(
        geo.get("country_code", data.get("country_code")), limit=8
    )
    if country_code is not None:
        country_code = country_code.upper()
    asn_organization = _text(
        as_data.get("name", data.get("as_name")), limit=255
    )
    return IPIntelligence(
        ip_address=requested_ip,
        source="ipinfo",
        country_code=country_code,
        country_name=_text(geo.get("country", data.get("country")), limit=128),
        city=_text(geo.get("city", data.get("city")), limit=128),
        asn=_asn_number(as_data.get("asn", data.get("asn"))),
        asn_organization=asn_organization,
        asn_type=_text(as_data.get("type"), limit=32),
        isp=asn_organization,
        ptr=_hostname(data.get("hostname")),
        is_anonymous=_flag(data, "is_anonymous"),
        is_hosting=_combine_flags(
            _flag(data, "is_hosting"),
            _flag(privacy, "hosting"),
        ),
        is_mobile=mobile_flag,
        is_proxy=_combine_flags(
            _flag(anonymous, "is_proxy"),
            _flag(privacy, "proxy"),
        ),
        is_residential_proxy=_flag(anonymous, "is_res_proxy"),
        is_tor=_combine_flags(
            _flag(anonymous, "is_tor"),
            _flag(privacy, "tor"),
        ),
        is_relay=_combine_flags(
            _flag(anonymous, "is_relay"),
            _flag(privacy, "relay"),
        ),
        is_vpn=_combine_flags(
            _flag(anonymous, "is_vpn"),
            _flag(privacy, "vpn"),
        ),
    )


class LocalIPIntelligenceProvider:
    """Network-free provider used by default and in automated tests."""

    async def lookup(self, ip_address: str) -> IPIntelligence:
        return IPIntelligence(
            ip_address=_validated_address(ip_address),
            source="local",
        )


class IPInfoProvider:
    def __init__(
        self,
        api_token: SecretStr,
        *,
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 64 * 1024,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_token.get_secret_value():
            raise ValueError("missing_ipinfo_api_token")
        if not 0 < timeout_seconds <= 30:
            raise ValueError("invalid_ip_intelligence_timeout")
        if not 1024 <= max_response_bytes <= 1024 * 1024:
            raise ValueError("invalid_ip_intelligence_response_limit")
        self._api_token = api_token
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._client = client

    async def _request(self, client: httpx.AsyncClient, ip_address: str) -> bytes:
        url = f"{IPINFO_LOOKUP_URL}/{quote(ip_address, safe='')}"
        try:
            async with client.stream(
                "GET",
                url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._api_token.get_secret_value()}",
                },
                follow_redirects=False,
                timeout=self._timeout_seconds,
            ) as response:
                if response.status_code in {401, 403}:
                    raise IPIntelligenceError("ip_intelligence_auth_failed")
                if response.status_code == 429:
                    raise IPIntelligenceError("ip_intelligence_rate_limited")
                if response.status_code != 200:
                    raise IPIntelligenceError("ip_intelligence_provider_unavailable")
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_length = int(content_length)
                    except ValueError:
                        declared_length = 0
                    if declared_length > self._max_response_bytes:
                        raise IPIntelligenceError("ip_intelligence_response_too_large")
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > self._max_response_bytes:
                        raise IPIntelligenceError("ip_intelligence_response_too_large")
                return bytes(payload)
        except IPIntelligenceError:
            raise
        except (httpx.HTTPError, TimeoutError) as exc:
            raise IPIntelligenceError("ip_intelligence_provider_unavailable") from exc

    async def lookup(self, ip_address: str) -> IPIntelligence:
        requested_ip = _validated_address(ip_address)
        if self._client is None:
            async with httpx.AsyncClient() as client:
                raw = await self._request(client, requested_ip)
        else:
            raw = await self._request(self._client, requested_ip)
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IPIntelligenceError("ip_intelligence_invalid_response") from exc
        return parse_ipinfo_response(payload, requested_ip=requested_ip)
