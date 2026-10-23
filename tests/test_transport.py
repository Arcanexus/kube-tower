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
