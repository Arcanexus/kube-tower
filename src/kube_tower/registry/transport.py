"""HTTP client shared by the registry, Helm repository and git clients."""

from __future__ import annotations

import asyncio
import logging

import httpx

log = logging.getLogger(__name__)

# Transient failures worth another try: the host did not answer in time or the connection failed.
RETRIABLE = (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError)
RETRIABLE_STATUS = {502, 503, 504}


class RetryingClient(httpx.AsyncClient):
    """An AsyncClient that retries transient failures (timeouts, connection errors, 502/503/504)
    with a growing delay.

    Registries such as Docker Hub regularly drop or stall a few requests in a burst: without
    retries each of them ends as an image in error until the next scan. Retrying in `send` (not
    in a custom transport) keeps the environment proxy settings (HTTPS_PROXY, NO_PROXY).
    """

    def __init__(self, *args, retries: int = 2, backoff: float = 1.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.retries = retries
        self.backoff = backoff

    async def send(self, request: httpx.Request, **kwargs) -> httpx.Response:
        for attempt in range(self.retries + 1):
            last = attempt == self.retries
            try:
                response = await super().send(request, **kwargs)
            except RETRIABLE as exc:
                if last:
                    raise
                reason = f"{exc.__class__.__name__}: {exc}".rstrip(": ")
            else:
                if response.status_code not in RETRIABLE_STATUS or last:
                    return response
                await response.aclose()
                reason = f"HTTP {response.status_code}"
            delay = self.backoff * 2**attempt
            log.debug(
                "%s %s failed (%s), retry %d/%d in %.0fs",
                request.method,
                request.url.copy_with(query=None),
                reason,
                attempt + 1,
                self.retries,
                delay,
            )
            await asyncio.sleep(delay)
        raise AssertionError("unreachable")  # pragma: no cover
