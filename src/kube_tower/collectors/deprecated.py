"""Deprecated APIs that clients still request, from the metrics of the API server.

The API server sets `apiserver_requested_deprecated_apis{group, version, resource, subresource,
removed_release}` to 1 for each deprecated API requested since it started. Only these lines are kept from
/metrics, read as a stream (the whole text weighs megabytes on a large cluster).
"""

from __future__ import annotations

import logging
import re

import urllib3
from kubernetes import client

from kube_tower.clusters import Cluster
from kube_tower.errors import kubernetes_hint
from kube_tower.models import DeprecatedApi

log = logging.getLogger(__name__)

METRIC = "apiserver_requested_deprecated_apis{"
_LABEL = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


def parse_metrics(lines) -> list[dict[str, str]]:
    """The labels of each apiserver_requested_deprecated_apis sample whose value is not 0."""
    found = []
    for line in lines:
        if not line.startswith(METRIC):
            continue
        labels, _, value = line.rpartition("}")
        if value.strip().split(" ")[0] in ("0", "0.0"):
            continue
        found.append({k: v.replace('\\"', '"').replace("\\\\", "\\") for k, v in _LABEL.findall(labels)})
    return found


def _lines(response, chunk_size: int = 64 * 1024):
    pending = b""
    for chunk in response.stream(chunk_size):
        pending += chunk
        *lines, pending = pending.split(b"\n")
        for line in lines:
            yield line.decode("utf-8", "replace")
    if pending:
        yield pending.decode("utf-8", "replace")


def collect_deprecated_apis(cluster: Cluster) -> tuple[list[DeprecatedApi], list[str]]:
    try:
        response = cluster.api_client.call_api(
            "/metrics",
            "GET",
            header_params={"Accept": "text/plain"},
            auth_settings=["BearerToken"],
            _preload_content=False,
            _return_http_data_only=True,
        )
        try:
            samples = parse_metrics(_lines(response))
        finally:
            response.release_conn()
    except client.ApiException as exc:
        message = f"[{cluster.name}] cannot read the deprecated APIs (API server /metrics): {exc.status} {exc.reason}"
        if exc.status == 403:
            hint = (
                "the ServiceAccount used for this cluster is not allowed to get the /metrics URL (nonResourceURLs): "
                "apply deploy/remote-cluster-rbac.yaml on remote clusters, keep rbac.create=true for the local one, "
                "or set kubernetesVersions.deprecatedApis: false"
            )
        else:
            hint = kubernetes_hint(exc.status, "the /metrics URL")
        if hint:
            message += f" - {hint}"
        log.warning("%s", message)
        return [], [message]
    except (urllib3.exceptions.HTTPError, OSError) as exc:
        message = f"[{cluster.name}] cannot read the deprecated APIs (API server /metrics): {exc}"
        log.warning("%s", message)
        return [], [message]
    apis = sorted(
        {
            (
                s.get("group", ""),
                s.get("version", ""),
                s.get("resource", ""),
                s.get("subresource", ""),
                s.get("removed_release", ""),
            )
            for s in samples
        }
    )
    found = [DeprecatedApi(cluster.name, *a) for a in apis]
    log.info("[%s] %d deprecated API(s) requested since the API server started", cluster.name, len(found))
    return found, []
