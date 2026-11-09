"""The pods of the Helm release, read from the Kubernetes API, for the Pods tab of the Administration page.

The kube-tower pods report themselves (processes.py), the others do not: Valkey, Dex, the Trivy server and the
krr pod of the chart. The chart gives each kube-tower pod its namespace (POD_NAMESPACE) and the name of its
release (KUBE_TOWER_RELEASE): the pods labelled app.kubernetes.io/instance=<release> there are the release's.
Outside a cluster, or without these variables, there is no list. The ClusterRole already lets kube-tower list
the pods (inventory of the images).
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime

from kubernetes import client, config

log = logging.getLogger(__name__)

CACHE_SECONDS = 5  # the Pods tab polls every 5 seconds, in every browser showing it
INSTANCE = "app.kubernetes.io/instance"
_cache: tuple[float, list[ChartPod] | None] = (0.0, None)
_api: client.CoreV1Api | None = None


@dataclass
class ChartPod:
    name: str
    component: str  # app.kubernetes.io/component, else the app.kubernetes.io/name without the chart prefix
    ready: bool
    state: str  # ok, or why not: pending, crashloopbackoff, imagepullbackoff, terminating...
    restarts: int = 0
    version: str = ""  # tag of the image of its first container
    started_at: datetime | None = None


def _component(labels: dict[str, str], release: str) -> str:
    if component := labels.get("app.kubernetes.io/component"):
        return component
    name = labels.get("app.kubernetes.io/name", "")
    for prefix in ("kube-tower-", f"{release}-"):
        if name.startswith(prefix):
            return name[len(prefix) :]
    return name or "pod"


def _tag(image: str) -> str:
    image = image.split("@", 1)[0]
    last = image.rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else ""


def chart_pod(pod, release: str) -> ChartPod:
    """A ChartPod from a V1Pod."""
    meta, status = pod.metadata, pod.status
    statuses = (status.container_statuses if status else None) or []
    ready = bool(statuses) and all(s.ready for s in statuses)
    phase = ((status.phase if status else None) or "Unknown").lower()
    reason = next((s.state.waiting.reason for s in statuses if s.state and s.state.waiting and s.state.waiting.reason), "")
    if meta.deletion_timestamp:
        state = "terminating"
    elif ready:
        state = "ok"
    else:
        state = (reason or ("not ready" if phase == "running" else phase)).lower()
    containers = pod.spec.containers if pod.spec else []
    return ChartPod(
        name=meta.name,
        component=_component(meta.labels or {}, release),
        ready=ready,
        state=state,
        restarts=sum(s.restart_count or 0 for s in statuses),
        version=_tag(containers[0].image) if containers else "",
        started_at=status.start_time if status else None,
    )


def _list(namespace: str, release: str) -> list[ChartPod]:
    global _api
    if _api is None:
        configuration = client.Configuration()
        config.load_incluster_config(client_configuration=configuration)
        _api = client.CoreV1Api(client.ApiClient(configuration))
    pods = _api.list_namespaced_pod(namespace, label_selector=f"{INSTANCE}={release}", _request_timeout=5).items
    return sorted((chart_pod(p, release) for p in pods), key=lambda p: (p.component, p.name))


async def chart_pods() -> list[ChartPod] | None:
    """The pods of the release, None when they cannot be listed (outside a cluster, no permission)."""
    global _cache
    namespace, release = os.environ.get("POD_NAMESPACE"), os.environ.get("KUBE_TOWER_RELEASE")
    if not namespace or not release:
        return None
    now = time.monotonic()
    if now - _cache[0] < CACHE_SECONDS:
        return _cache[1]
    try:
        pods = await asyncio.to_thread(_list, namespace, release)
    except Exception as exc:  # noqa: BLE001 - the tab shows the kube-tower pods anyway
        log.debug("cannot list the pods of the release %s in %s: %s", release, namespace, exc)
        pods = None
    _cache = (now, pods)
    return pods
