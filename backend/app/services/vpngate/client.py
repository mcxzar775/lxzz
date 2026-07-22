import asyncio
from typing import Protocol

import httpx

from app import __version__
from app.services.vpngate.types import VPNGateFetchError


class VPNGateFetcher(Protocol):
    async def fetch_csv(self) -> bytes: ...


class VPNGateClient:
    def __init__(
        self,
        *,
        url: str,
        timeout_seconds: float,
        max_response_bytes: int,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not url.startswith("https://"):
            raise ValueError("VPNGate API URL must use HTTPS")
        self._url = url
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._transport = transport

    async def _fetch(self) -> bytes:
        timeout = httpx.Timeout(self._timeout_seconds)
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=self._transport,
            headers={
                "Accept": "text/csv,text/plain;q=0.9",
                "User-Agent": f"vpngate-manager/{__version__}",
            },
        ) as client:
            async with client.stream("GET", self._url) as response:
                if 300 <= response.status_code < 400:
                    raise VPNGateFetchError("unexpected_redirect")
                if response.status_code != 200:
                    raise VPNGateFetchError("upstream_http_error")
                content_length = response.headers.get("content-length")
                if content_length is not None:
                    try:
                        declared_size = int(content_length, 10)
                    except ValueError as exc:
                        raise VPNGateFetchError("invalid_content_length") from exc
                    if declared_size < 0 or declared_size > self._max_response_bytes:
                        raise VPNGateFetchError("response_too_large")
                chunks: list[bytes] = []
                received = 0
                async for chunk in response.aiter_bytes():
                    received += len(chunk)
                    if received > self._max_response_bytes:
                        raise VPNGateFetchError("response_too_large")
                    chunks.append(chunk)
                return b"".join(chunks)

    async def fetch_csv(self) -> bytes:
        try:
            return await asyncio.wait_for(
                self._fetch(), timeout=self._timeout_seconds + 1.0
            )
        except VPNGateFetchError:
            raise
        except (asyncio.TimeoutError, httpx.TimeoutException) as exc:
            raise VPNGateFetchError("upstream_timeout") from exc
        except httpx.HTTPError as exc:
            raise VPNGateFetchError("upstream_network_error") from exc
