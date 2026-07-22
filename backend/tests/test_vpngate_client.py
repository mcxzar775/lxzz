import asyncio

import httpx
import pytest

from app.services.vpngate.client import VPNGateClient
from app.services.vpngate.types import VPNGateFetchError


def _client(handler: httpx.MockTransport, *, maximum: int = 1024) -> VPNGateClient:
    return VPNGateClient(
        url="https://example.test/api/iphone/",
        timeout_seconds=2,
        max_response_bytes=maximum,
        transport=handler,
    )


def test_fetches_csv_without_following_redirects() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, content=b"safe"))

    assert asyncio.run(_client(transport).fetch_csv()) == b"safe"


def test_rejects_redirect() -> None:
    transport = httpx.MockTransport(
        lambda _: httpx.Response(302, headers={"Location": "https://other.test/"})
    )

    with pytest.raises(VPNGateFetchError, match="unexpected_redirect"):
        asyncio.run(_client(transport).fetch_csv())


def test_rejects_oversized_response() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, content=b"123456"))

    with pytest.raises(VPNGateFetchError, match="response_too_large"):
        asyncio.run(_client(transport, maximum=5).fetch_csv())


def test_requires_https_source() -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        VPNGateClient(
            url="http://example.test/",
            timeout_seconds=2,
            max_response_bytes=1024,
        )
