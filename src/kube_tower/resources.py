"""CPU and memory recommendations of krr (https://github.com/robusta-dev/krr), the Resources page.

krr reads the usage of every container in Prometheus and compares it with its requests and limits. It
needs Python 3.12 and libraries that the kube-tower image does not have: the Helm chart runs it in a pod
of its own (the official krr image with charts/kube-tower/files/krr-server.py, `resources.serverUrl`),
to which a worker sends a kubeconfig of the cluster and the krr options. Without a server URL, the krr
command (`resources.binary`) runs in the kube-tower process (development, or an image of your own).

The recommendations come from two weeks of history by default: the controller reuses those of a cluster
for `resources.interval` before asking again (scanner.py). A failed run leaves a message, never fails
the scan.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import fnmatch
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx
import yaml

from kube_tower.config import PrometheusSettings, ResourcesSettings
from kube_tower.models import Fit, ResourceRecommendation, ResourceScan, ResourceValue

if TYPE_CHECKING:
    from kubernetes.client import Configuration

    from kube_tower.clusters import Cluster

log = logging.getLogger(__name__)

SA_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # sent to the krr server, which checks it
MESSAGE_LIMIT = 500
_LOG_LINE = re.compile(r"^(?:\[[\d:]+\]\s*)?(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s+(.*?)(?:\s+[\w.]+\.py:\d+)?$")
_EXCEPTION = re.compile(r"^[A-Za-z_][\w.]*(Error|Exception|Exceeded|Timeout)\w*: \S")


class KrrError(Exception):
    """krr could not give recommendations for a cluster: the message is shown on the Resources page."""


# What krr is given


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def _authorization(cfg: Configuration) -> str:
    """The Authorization header of a Kubernetes client, its token refreshed first (exec plugins, in-cluster)."""
    if cfg.refresh_api_key_hook is not None:
        cfg.refresh_api_key_hook(cfg)
    return cfg.get_api_key_with_prefix("authorization") or ""


def kubeconfig_of(cluster: Cluster) -> str:
    """A kubeconfig reaching the cluster as kube-tower does: its address, CA, client certificate and token."""
    cfg = cluster.api_client.configuration
    entry: dict[str, Any] = {"server": cfg.host}
    if not cfg.verify_ssl:
        entry["insecure-skip-tls-verify"] = True
    elif cfg.ssl_ca_cert:
        entry["certificate-authority-data"] = base64.b64encode(_read(cfg.ssl_ca_cert)).decode()
    if getattr(cfg, "tls_server_name", None):
        entry["tls-server-name"] = cfg.tls_server_name
    user: dict[str, Any] = {}
    if cfg.cert_file and cfg.key_file:
        user["client-certificate-data"] = base64.b64encode(_read(cfg.cert_file)).decode()
        user["client-key-data"] = base64.b64encode(_read(cfg.key_file)).decode()
    scheme, _, credentials = _authorization(cfg).partition(" ")
    if scheme.lower() == "bearer" and credentials:
        user["token"] = credentials.strip()
    elif scheme.lower() == "basic" and credentials:
        username, _, password = base64.b64decode(credentials).decode().partition(":")
        user |= {"username": username, "password": password}
    name = cluster.name
    data = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": name, "cluster": entry}],
        "users": [{"name": name, "user": user}],
        "contexts": [{"name": name, "context": {"cluster": name, "user": name}}],
        "current-context": name,
    }
    return yaml.safe_dump(data, sort_keys=False)


def prometheus_of(settings: ResourcesSettings, cluster: str) -> PrometheusSettings | None:
    """The first resources.prometheus entry matching the cluster, None when krr should find Prometheus."""
    return next((p for p in settings.prometheus if any(fnmatch.fnmatchcase(cluster, c) for c in p.clusters)), None)


def _auth_header(prometheus: PrometheusSettings) -> str:
    if prometheus.auth_header_env:
        return os.environ.get(prometheus.auth_header_env, "").strip()
    if prometheus.auth_header_file:
        try:
            return _read(prometheus.auth_header_file).decode().strip()
        except OSError as exc:
            raise KrrError(f"cannot read resources.prometheus authHeaderFile: {exc}") from exc
    return ""


def krr_args(settings: ResourcesSettings, cluster: str) -> list[str]:
    """The krr options of a cluster (after the strategy; the kubeconfig and the output are added by the runner)."""
    args: list[str] = []
    for namespace in settings.namespaces:
        args += ["--namespace", namespace]
    if prometheus := prometheus_of(settings, cluster):
        if prometheus.url:
            args += ["--prometheus-url", prometheus.url]
        if header := _auth_header(prometheus):
            args += ["--prometheus-auth-header", header]
        for name, value in prometheus.headers.items():
            args += ["--prometheus-headers", f"{name}: {value}"]
        if prometheus.cluster_label:
            args += ["--prometheus-label", prometheus.cluster_label]
            args += ["--prometheus-cluster-label", prometheus.cluster_value or cluster]
    return args + list(settings.args)


# Where krr runs


def error_message(stderr: str) -> str:
    """Why krr failed: its last error log line, with the exception that ended it (as krr-server.py does)."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    logged = [(i, m[2]) for i, line in enumerate(lines) if (m := _LOG_LINE.match(line)) and m[1] in ("ERROR", "CRITICAL")]
    start, message = logged[-1] if logged else (0, "")
    exceptions = [line for line in lines[start:] if _EXCEPTION.match(line)]
    message = ": ".join(filter(None, [message, exceptions[-1] if exceptions else ""])) or (lines[-1] if lines else "krr failed")
    return message if len(message) <= MESSAGE_LIMIT else message[: MESSAGE_LIMIT - 1] + "…"


async def run_local(settings: ResourcesSettings, kubeconfig: str, args: list[str]) -> dict:
    """Run the krr command in this process and return its JSON result."""
    binary = shutil.which(settings.binary) or (settings.binary if os.path.isfile(settings.binary) else None)
    if binary is None:
        raise KrrError(
            f"krr not found ({settings.binary!r}): enable krr in the Helm chart (krr.enabled), or set resources.serverUrl"
        )
    with tempfile.TemporaryDirectory(prefix="kube-tower-krr-") as workdir:
        config = os.path.join(workdir, "kubeconfig")
        with open(os.open(config, os.O_WRONLY | os.O_CREAT, 0o600), "w") as fh:
            fh.write(kubeconfig)
        output = os.path.join(workdir, "result.json")
        argv = [binary, settings.strategy, "--kubeconfig", config, "--formatter", "json", "--fileoutput", output]
        argv += ["--logtostderr", "--width", "4000", *args]
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=workdir, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
        )
        try:
            _, stderr = await asyncio.wait_for(proc.communicate(), settings.timeout)
        except TimeoutError as exc:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            raise KrrError(f"krr did not finish within {settings.timeout}s") from exc
        if proc.returncode != 0 or not os.path.exists(output):
            raise KrrError(error_message(stderr.decode(errors="replace")))
        with open(output) as fh:
            return json.load(fh)


def _service_account_token() -> str:
    try:
        return _read(SA_TOKEN).decode().strip()
    except OSError:
        return ""


async def run_remote(settings: ResourcesSettings, kubeconfig: str, args: list[str]) -> dict:
    """Ask the krr server (resources.serverUrl) to run krr and return its JSON result."""
    headers = {"User-Agent": "kube-tower"}
    if token := _service_account_token():
        headers["Authorization"] = f"Bearer {token}"
    body = {"strategy": settings.strategy, "kubeconfig": kubeconfig, "args": args, "timeout": settings.timeout}
    url = settings.server_url.rstrip("/") + "/run"
    try:
        async with httpx.AsyncClient(timeout=settings.timeout + 30) as http:
            response = await http.post(url, json=body, headers=headers)
    except httpx.HTTPError as exc:
        raise KrrError(f"krr server {settings.server_url} unreachable: {exc.__class__.__name__} {exc}".strip()) from exc
    try:
        data = response.json()
    except ValueError:
        data = {}
    if response.status_code != 200 or not isinstance(data.get("result"), dict):
        message = data.get("error") if isinstance(data, dict) else None
        raise KrrError(f"krr server answered {response.status_code}: {message or response.text[:200] or response.reason_phrase}")
    return data["result"]


# What krr answered


def _number(value: Any) -> tuple[float | None, bool]:
    """(value, known) of a krr value: a number, null (unset) or "?" (not enough data)."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value), True
    return None, value is None


def _value(scan: dict, selector: str, resource: str) -> ResourceValue:
    current, _ = _number(((scan.get("object") or {}).get("allocations") or {}).get(selector, {}).get(resource))
    recommended = ((scan.get("recommended") or {}).get(selector) or {}).get(resource)
    if isinstance(recommended, dict):  # {"value": ..., "severity": ...}
        value, known = _number(recommended.get("value"))
        return ResourceValue(current, value, known, Fit.parse(recommended.get("severity")))
    value, known = _number(recommended)
    return ResourceValue(current, value, known)


def parse_result(cluster: str, data: dict) -> tuple[list[ResourceRecommendation], ResourceScan]:
    """The recommendations of a cluster from the JSON of `krr <strategy> --formatter json`."""
    recommendations = []
    for scan in data.get("scans") or []:
        obj = scan.get("object") or {}
        info = ((scan.get("recommended") or {}).get("info")) or {}
        recommendations.append(
            ResourceRecommendation(
                cluster=cluster,
                namespace=obj.get("namespace", ""),
                kind=obj.get("kind", ""),
                name=obj.get("name", ""),
                container=obj.get("container", ""),
                cpu_request=_value(scan, "requests", "cpu"),
                cpu_limit=_value(scan, "limits", "cpu"),
                memory_request=_value(scan, "requests", "memory"),
                memory_limit=_value(scan, "limits", "memory"),
                fit=Fit.parse(scan.get("severity")),
                pods=sum(1 for p in obj.get("pods") or [] if not p.get("deleted")),
                hpa=obj.get("hpa") is not None,
                info=" · ".join(dict.fromkeys(str(v) for v in info.values() if v)),
                warnings=sorted(obj.get("warnings") or []),
            )
        )
    recommendations.sort(key=lambda r: r.key)
    strategy = data.get("strategy") or {}
    score = data.get("score")
    status = ResourceScan(
        cluster=cluster,
        scanned_at=datetime.now(UTC),
        strategy=str(strategy.get("name") or ""),
        score=score if isinstance(score, int) and recommendations else None,
        settings={str(k): str(v) for k, v in (strategy.get("settings") or {}).items() if v is not None},
    )
    return recommendations, status


async def recommend(settings: ResourcesSettings, cluster: Cluster) -> tuple[list[ResourceRecommendation], ResourceScan]:
    """The recommendations of krr for a cluster; a failure gives none and a ResourceScan with the reason."""
    prometheus = prometheus_of(settings, cluster.name)
    url = prometheus.url if prometheus else ""
    try:
        kubeconfig = await asyncio.to_thread(kubeconfig_of, cluster)
        args = krr_args(settings, cluster.name)
        run = run_remote if settings.server_url else run_local
        data = await run(settings, kubeconfig, args)
        recommendations, status = parse_result(cluster.name, data)
    except (KrrError, OSError, ValueError) as exc:
        log.warning("cluster %s: no CPU and memory recommendations: %s", cluster.name, exc)
        return [], ResourceScan(cluster.name, datetime.now(UTC), message=str(exc), strategy=settings.strategy, prometheus=url)
    status.prometheus = url
    errors = [e for e in data.get("errors") or [] if isinstance(e, dict)]
    if errors:
        status.message = "; ".join(dict.fromkeys(str(e.get("error") or e) for e in errors))[:MESSAGE_LIMIT]
    log.info("cluster %s: %d CPU and memory recommendation(s) from krr", cluster.name, len(recommendations))
    return recommendations, status
