"""Inventory of the Helm charts installed with the helm command: the release Secrets (owner=helm)."""

from __future__ import annotations

import base64
import gzip
import json
import logging

from kubernetes import client

from kube_tower.helmvalues import booleans, merge
from kube_tower.models import ChartDependency, ChartReport

log = logging.getLogger(__name__)

SELECTOR = "owner=helm,status=deployed"
PAGE = 20  # a release Secret holds the whole chart (templates included): a few per request
# Labels Flux puts on the releases it makes: those charts come from their HelmRelease
FLUX_LABELS = ("helm.toolkit.fluxcd.io/name", "helm.toolkit.fluxcd.io/namespace")


def decode(data: str) -> dict:
    """The release JSON of a Secret `release` key: base64 (of the Secret) of base64 of gzipped JSON."""
    raw = base64.b64decode(base64.b64decode(data))
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    return json.loads(raw)


def chart_from_release(cluster: str, release: dict) -> ChartReport | None:
    chart = release.get("chart") or {}
    metadata = chart.get("metadata") or {}
    if not metadata.get("name"):
        return None
    # Only the booleans of the values are kept (conditions and tags of the subcharts); the defaults of the
    # chart under the values given at install, like Helm renders it
    values = merge(booleans(chart.get("values") or {}), booleans(release.get("config") or {}))
    return ChartReport(
        cluster=cluster,
        application=release.get("name", ""),
        app_namespace=release.get("namespace", ""),
        chart=metadata["name"],
        repository="",  # not recorded by Helm: helm.repositories, else Artifact Hub
        version=str(metadata.get("version", "")),
        source_type="helm",
        destination_namespace=release.get("namespace", ""),
        inline_values=values,
        manager="helm",
        dependencies=[
            ChartDependency(
                name=d.get("name", ""),
                version=str(d.get("version", "")),
                repository=d.get("repository", ""),
                alias=d.get("alias") or "",
                condition=str(d.get("condition") or ""),
                tags=[str(t) for t in d.get("tags") or []],
            )
            for d in metadata.get("dependencies") or []
        ],
    )


def collect(cluster: str, core: client.CoreV1Api) -> list[ChartReport]:
    """The deployed releases of every namespace, the last revision of each, except those made by Flux."""
    latest: dict[tuple[str, str], tuple[int, client.V1Secret]] = {}
    token = None
    while True:
        page = core.list_secret_for_all_namespaces(
            label_selector=SELECTOR, field_selector="type=helm.sh/release.v1", limit=PAGE, _continue=token
        )
        for secret in page.items:
            labels = secret.metadata.labels or {}
            if any(label in labels for label in FLUX_LABELS):
                continue
            key = (secret.metadata.namespace, labels.get("name", ""))
            revision = int(labels.get("version") or 0)
            if key not in latest or revision > latest[key][0]:
                latest[key] = (revision, secret)
        token = page.metadata._continue if page.metadata else None
        if not token:
            break
    reports = []
    for (namespace, name), (_, secret) in sorted(latest.items(), key=lambda item: item[0]):
        try:
            report = chart_from_release(cluster, decode((secret.data or {}).get("release", "")))
        except (ValueError, OSError, EOFError) as exc:
            log.warning("[%s] cannot read the Helm release %s/%s: %s", cluster, namespace, name, exc)
            continue
        if report:
            reports.append(report)
    return reports
