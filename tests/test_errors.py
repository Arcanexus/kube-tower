import httpx
from kubernetes import client

from kube_tower.errors import cluster_unreachable_message, explain, http_error_message, http_hint, kubernetes_hint


def _response(status):
    return httpx.Response(status, request=httpx.Request("GET", "https://registry-1.docker.io/v2/library/x/tags/list"))


def test_http_error_message_explains_the_status():
    assert http_error_message("cannot list the tags of docker.io/library/x", _response(429)) == (
        "cannot list the tags of docker.io/library/x: HTTP 429 Too Many Requests - rate limited by "
        "registry-1.docker.io, even after waiting as it asked: add credentials for it (anonymous requests are limited), "
        "use an account with a higher limit, lower registries.concurrency or scan less often"
    )
    assert "registries.credentials" in http_hint(401, "ghcr.io")
    assert "server error" in http_hint(503, "ghcr.io")
    assert http_hint(418, "ghcr.io") == ""
    assert http_error_message("x", _response(418)) == "x: HTTP 418 I'm a teapot"


def test_explain_network_errors():
    request = httpx.Request("GET", "https://quay.io/v2/")
    assert explain(httpx.ReadTimeout("", request=request)).startswith("quay.io accepted the connection but did not answer")
    assert "broken IPv6" in explain(httpx.ConnectTimeout("", request=request))
    assert "lower registries.concurrency" in explain(httpx.PoolTimeout("", request=request))
    assert explain(httpx.ConnectError("Name or service not known", request=request)) == (
        "cannot connect to quay.io: Name or service not known (DNS, network policy, proxy or TLS certificate?)"
    )
    assert explain(httpx.RemoteProtocolError("closed", request=request)) == "request to quay.io failed: closed"
    assert explain(httpx.ProxyError("403 Forbidden", request=request)).startswith("the HTTP proxy refused or failed")
    assert "does not exist" in http_hint(401, "registry-1.docker.io")
    assert explain(httpx.TransportError("no request")) == "request to the remote host failed: no request"
    assert explain(ValueError("bad\nsecond line")) == "bad"


def test_kubernetes_messages():
    assert "renew its cluster secret" in kubernetes_hint(401, "pods")
    assert "remote-cluster-rbac.yaml" in kubernetes_hint(403, "pods")
    assert kubernetes_hint(404, "CronJob") == "the CronJob API is not available on this cluster"
    assert kubernetes_hint(500, "pods") == ""
    server = "https://prod:6443"
    assert "renew its cluster secret" in cluster_unreachable_message(
        client.ApiException(status=401, reason="Unauthorized"), server
    )
    assert "not allowed to read /version" in cluster_unreachable_message(
        client.ApiException(status=403, reason="Forbidden"), server
    )
    assert "check caData" in cluster_unreachable_message(Exception("SSLError(CERTIFICATE_VERIFY_FAILED)"), server)
    assert cluster_unreachable_message(Exception("Connection refused"), server) == (
        "cannot reach https://prod:6443: Connection refused (address, network or firewall?)"
    )
