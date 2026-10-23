"""Explicit error messages: what failed, why, and what to do about it.

These messages end up in the logs, the scan errors of the UI and the `message` of each
image or chart, so they must make sense without reading the code.
"""

from __future__ import annotations

import httpx

REGISTRY_CREDENTIALS = "registries.credentials"
GIT_CREDENTIALS = "git.token / git.existingSecret"


def http_hint(status: int, host: str, credentials: str = REGISTRY_CREDENTIALS) -> str:
    """What an HTTP status returned by a registry, a Helm repository or a git host means here."""
    if status == 401:
        return f"authentication required or refused by {host}: add or fix its credentials ({credentials})"
    if status == 403:
        return f"access denied by {host}: the credentials used for it are not allowed to pull this repository"
    if status == 404:
        return f"not found on {host}: check the name, or it is private and needs credentials ({credentials})"
    if status == 429:
        return f"rate limited by {host}: add credentials for it (anonymous pulls are limited) or lower registries.concurrency"
    if status >= 500:
        return f"{host} returned a server error, it is retried at the next scan"
    return ""


def http_error_message(what: str, response: httpx.Response, credentials: str = REGISTRY_CREDENTIALS) -> str:
    """`<what>: HTTP 401 Unauthorized - <hint>`."""
    host = response.request.url.host
    message = f"{what}: HTTP {response.status_code} {response.reason_phrase}".rstrip()
    hint = http_hint(response.status_code, host, credentials)
    return f"{message} - {hint}" if hint else message


def explain(exc: BaseException) -> str:
    """One explicit line for an exception raised while querying a registry, a Helm repository or git."""
    if isinstance(exc, httpx.TimeoutException):
        return (
            f"no answer from {_host(exc)} before registries.timeout: "
            "the host is slow or unreachable from the pod (network policy, proxy?)"
        )
    if isinstance(exc, httpx.ConnectError):
        return f"cannot connect to {_host(exc)}: {_first_line(exc)} (DNS, network policy, proxy or TLS certificate?)"
    if isinstance(exc, httpx.HTTPError):
        return f"request to {_host(exc)} failed: {_first_line(exc)}"
    return _first_line(exc)


def kubernetes_hint(status: int | None, what: str) -> str:
    """What a Kubernetes API error means when kube-tower lists `what`."""
    if status == 401:
        return "the credentials of this cluster were rejected (expired or revoked token): renew its cluster secret"
    if status == 403:
        return (
            f"the ServiceAccount used for this cluster is not allowed to list {what} in all namespaces: "
            "apply deploy/remote-cluster-rbac.yaml on remote clusters, keep rbac.create=true for the local one"
        )
    if status == 404:
        return f"the {what} API is not available on this cluster"
    return ""


def cluster_unreachable_message(exc: BaseException, server: str) -> str:
    """Why kube-tower cannot use a cluster (its /version probe failed)."""
    status = getattr(exc, "status", None)
    if status in (401, 403):
        reason = getattr(exc, "reason", "") or ""
        hint = (
            kubernetes_hint(status, "the server version") if status == 401 else "authenticated but not allowed to read /version"
        )
        return f"HTTP {status} {reason} from {server}: {hint}".replace("  ", " ")
    text = _first_line(exc)
    if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "SSLError" in str(exc):
        return f"TLS error with {server}: {text} - check caData / insecure in the cluster secret"
    return f"cannot reach {server}: {text} (address, network or firewall?)"


def _host(exc: httpx.HTTPError) -> str:
    try:
        return exc.request.url.host
    except RuntimeError:  # no request attached
        return "the remote host"


def _first_line(exc: BaseException) -> str:
    return (str(exc) or exc.__class__.__name__).strip().splitlines()[0][:300]
