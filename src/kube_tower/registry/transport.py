"""HTTP client shared by the registry, Helm repository and git clients."""

from __future__ import annotations

import asyncio
import email.utils
import logging
import time

import httpx

log = logging.getLogger(__name__)

# Transient failures worth another try: the host did not answer in time or the connection failed.
RETRIABLE = (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError)
RETRIABLE_STATUS = {502, 503, 504}
# Rate limited (429): wait as long as the registry asks (Retry-After), up to this; beyond, give up at once.
MAX_RATE_LIMIT_WAIT = 60.0


def retry_after(response: httpx.Response) -> float | None:
    """Seconds to wait from a Retry-After header (seconds or HTTP date), None without a usable one."""
    value = response.headers.get("retry-after", "").strip()
    if not value:
        return None
    if value.isdigit():
        return float(value)
    try:
        return max(0.0, email.utils.parsedate_to_datetime(value).timestamp() - time.time())
    except (TypeError, ValueError):
        return None


class RateLimits:
    """Hosts that rate limited kube-tower (HTTP 429), kept by the scanner between scans and rescans.

    After a short wait asked by the host, every request to it waits, instead of each concurrent request
    hitting the limit again (which makes it last longer). After a long one (beyond MAX_RATE_LIMIT_WAIT,
    e.g. a quota exhausted for hours), requests to it fail at once until then, instead of stalling the scan.
    """

    def __init__(self):
        self.until: dict[str, float] = {}  # host -> time.monotonic() when requests may go again
        self.blocked: dict[str, float] = {}  # host -> time.monotonic() until which requests fail at once
        self.limited: dict[str, int] = {}  # host -> number of 429 answers
        self._warned: set[str] = set()

    def pause(self, host: str, seconds: float) -> None:
        end = time.monotonic() + seconds
        if seconds > MAX_RATE_LIMIT_WAIT:
            self.blocked[host] = max(self.blocked.get(host, 0.0), end)
        else:
            self.until[host] = max(self.until.get(host, 0.0), end)
        self.limited[host] = self.limited.get(host, 0) + 1

    def blocked_for(self, host: str) -> float:
        """Seconds during which requests to the host fail at once (0: not blocked)."""
        return max(0.0, self.blocked.get(host, 0.0) - time.monotonic())

    async def wait(self, host: str) -> None:
        if (delay := self.until.get(host, 0.0) - time.monotonic()) > 0:
            await asyncio.sleep(delay)

    def note_quota(self, response: httpx.Response) -> None:
        """Docker Hub tells the pulls left (`ratelimit-remaining: 76;w=21600`): warn once when none are left."""
        remaining = response.headers.get("ratelimit-remaining", "").split(";")[0].strip()
        host = response.request.url.host
        if remaining.isdigit() and int(remaining) == 0 and host not in self._warned:
            self._warned.add(host)
            limit = response.headers.get("ratelimit-limit", "").split(";")[0].strip()
            log.warning(
                "%s: no pulls left in the current window (limit %s): its images can fail until the window resets; "
                "use credentials of an account with a higher limit, or scan less often (refreshInterval)",
                host,
                limit or "unknown",
            )
        elif remaining.isdigit() and int(remaining) > 0:
            self._warned.discard(host)


class RetryingClient(httpx.AsyncClient):
    """An AsyncClient that retries transient failures (timeouts, connection errors, 502/503/504)
    with a growing delay, and rate limits (429) after the delay the registry asks for.

    Registries such as Docker Hub regularly drop or stall a few requests in a burst: without
    retries each of them ends as an image in error until the next scan. Retrying in `send` (not
    in a custom transport) keeps the environment proxy settings (HTTPS_PROXY, NO_PROXY).
    """

    def __init__(
        self,
        *args,
        retries: int = 2,
        backoff: float = 1.0,
        rate_limit_backoff: float = 5.0,
        rate_limits: RateLimits | None = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.retries = retries
        self.backoff = backoff
        self.rate_limit_backoff = rate_limit_backoff  # wait after a 429 without Retry-After, doubled each time
        self.rate_limits = rate_limits or RateLimits()

    async def send(self, request: httpx.Request, **kwargs) -> httpx.Response:
        host = request.url.host
        for attempt in range(self.retries + 1):
            last = attempt == self.retries
            await self.rate_limits.wait(host)
            if blocked := self.rate_limits.blocked_for(host):
                # Answered without asking the host: it said not to come back before then.
                return httpx.Response(429, request=request, headers={"retry-after": str(round(blocked))})
            delay = self.backoff * 2**attempt
            try:
                response = await super().send(request, **kwargs)
            except RETRIABLE as exc:
                if last:
                    raise
                reason = f"{exc.__class__.__name__}: {exc}".rstrip(": ")
            else:
                self.rate_limits.note_quota(response)
                if response.status_code == 429:
                    asked = retry_after(response)
                    delay = asked if asked is not None else self.rate_limit_backoff * 2**attempt
                    # Every request to this host waits, not only this one.
                    self.rate_limits.pause(host, delay)
                    if last or delay > MAX_RATE_LIMIT_WAIT:
                        return response
                    await response.aclose()
                    log.info(
                        "%s rate limited kube-tower, requests to it wait %.0fs (retry %d/%d)",
                        host,
                        delay,
                        attempt + 1,
                        self.retries,
                    )
                    continue
                if response.status_code not in RETRIABLE_STATUS or last:
                    return response
                await response.aclose()
                reason = f"HTTP {response.status_code}"
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
