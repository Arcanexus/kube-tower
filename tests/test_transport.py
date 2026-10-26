import httpx
import pytest

from kube_tower.registry.transport import RetryingClient


class Flaky(httpx.AsyncBaseTransport):
    """Fails with the given outcomes (exception classes or status codes), then answers 200."""

    def __init__(self, *outcomes):
        self.outcomes, self.calls = list(outcomes), 0

    async def handle_async_request(self, request):
        self.calls += 1
        outcome = self.outcomes.pop(0) if self.outcomes else 200
        if isinstance(outcome, int):
            return httpx.Response(outcome, request=request)
        raise outcome("boom", request=request)


async def _get(inner, retries=2):
    async with RetryingClient(transport=inner, retries=retries, backoff=0) as http:
        return await http.get("https://registry-1.docker.io/v2/")


async def test_retries_transient_failures(caplog):
    caplog.set_level("DEBUG", logger="kube_tower")
    inner = Flaky(httpx.ReadTimeout, 503)
    assert (await _get(inner)).status_code == 200
    assert inner.calls == 3
    assert "GET https://registry-1.docker.io/v2/ failed (ReadTimeout: boom), retry 1/2" in caplog.text


async def test_gives_up_after_the_last_retry():
    inner = Flaky(httpx.ConnectTimeout, httpx.ConnectTimeout, httpx.ConnectTimeout)
    with pytest.raises(httpx.ConnectTimeout):
        await _get(inner)
    assert inner.calls == 3
    inner = Flaky(503, 503)
    assert (await _get(inner, retries=1)).status_code == 503


async def test_does_not_retry_other_answers():
    inner = Flaky(404)
    assert (await _get(inner)).status_code == 404
    assert inner.calls == 1


class Limited(httpx.AsyncBaseTransport):
    """Answers the given responses (status, headers), then 200."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), 0

    async def handle_async_request(self, request):
        self.calls += 1
        status, headers = self.answers.pop(0) if self.answers else (200, {})
        return httpx.Response(status, headers=headers, request=request)


def _client(inner, limits=None, retries=2):
    return RetryingClient(transport=inner, retries=retries, backoff=0, rate_limit_backoff=0, rate_limits=limits)


async def test_rate_limited_requests_wait_and_retry(caplog, monkeypatch):
    from kube_tower.registry import transport

    waits = []

    async def sleep(seconds):
        waits.append(round(seconds))

    monkeypatch.setattr(transport.asyncio, "sleep", sleep)
    caplog.set_level("INFO", logger="kube_tower")
    limits = transport.RateLimits()
    inner = Limited((429, {"retry-after": "3"}))
    async with _client(inner, limits) as http:
        assert (await http.get("https://ghcr.io/v2/")).status_code == 200
    assert inner.calls == 2 and waits == [3]  # the next request waited as asked
    assert limits.limited == {"ghcr.io": 1}
    assert "ghcr.io rate limited kube-tower, requests to it wait 3s (retry 1/2)" in caplog.text
    # Without Retry-After: the growing rate limit backoff; the last answer is returned
    inner = Limited((429, {}), (429, {}), (429, {}))
    async with _client(inner) as http:
        assert (await http.get("https://ghcr.io/v2/")).status_code == 429
    assert inner.calls == 3


async def test_long_rate_limit_fails_at_once():
    from kube_tower.registry.transport import RateLimits

    limits = RateLimits()
    inner = Limited((429, {"retry-after": "3600"}))
    async with _client(inner, limits) as http:
        assert (await http.get("https://registry-1.docker.io/v2/a")).status_code == 429
        # Other requests to that host do not reach it until then; other hosts are not affected
        resp = await http.get("https://registry-1.docker.io/v2/b")
        assert resp.status_code == 429 and int(resp.headers["retry-after"]) > 3500
        assert (await http.get("https://ghcr.io/v2/")).status_code == 200
    assert inner.calls == 2


def test_retry_after_and_messages():
    from kube_tower.errors import http_error_message
    from kube_tower.registry.transport import retry_after

    request = httpx.Request("GET", "https://registry-1.docker.io/v2/")
    assert retry_after(httpx.Response(429, headers={"retry-after": "12"}, request=request)) == 12
    assert retry_after(httpx.Response(429, headers={"retry-after": "Wed, 21 Oct 2015 07:28:00 GMT"}, request=request)) == 0
    assert retry_after(httpx.Response(429, headers={"retry-after": "soon"}, request=request)) is None
    assert retry_after(httpx.Response(429, request=request)) is None
    resp = httpx.Response(429, headers={"retry-after": "5400"}, request=request)
    message = http_error_message("cannot list the tags of docker.io/library/nginx", resp)
    assert message.startswith(
        "cannot list the tags of docker.io/library/nginx: HTTP 429 Too Many Requests (retry in 90 min) - rate"
    )
    assert "(retry in 3 h)" in http_error_message("x", httpx.Response(429, headers={"retry-after": "10800"}, request=request))
    assert "(retry in 30s)" in http_error_message("x", httpx.Response(429, headers={"retry-after": "30"}, request=request))


async def test_docker_hub_quota_warning(caplog):
    inner = Limited(
        (200, {"ratelimit-limit": "100;w=21600", "ratelimit-remaining": "0;w=21600"}),
        (200, {"ratelimit-remaining": "0;w=21600"}),
        (200, {"ratelimit-remaining": "5;w=21600"}),
        (200, {"ratelimit-remaining": "0;w=21600"}),
    )
    async with _client(inner) as http:
        for _ in range(4):
            await http.head("https://registry-1.docker.io/v2/library/nginx/manifests/1")
    assert caplog.text.count("registry-1.docker.io: no pulls left in the current window") == 2  # again after a reset
