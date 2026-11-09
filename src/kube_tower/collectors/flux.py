"""Inventory of Helm charts deployed by Flux HelmReleases (helm.toolkit.fluxcd.io)."""

from __future__ import annotations

import logging

from kubernetes import client

from kube_tower.helmvalues import booleans
from kube_tower.models import ChartReport

log = logging.getLogger(__name__)

HELM_GROUP, SOURCE_GROUP = "helm.toolkit.fluxcd.io", "source.toolkit.fluxcd.io"
# Newest first: the first API version the cluster serves is used
HELM_VERSIONS = ("v2", "v2beta2", "v2beta1")
SOURCE_VERSIONS = ("v1", "v1beta2")
SOURCES = {"HelmRepository": "helmrepositories", "GitRepository": "gitrepositories", "OCIRepository": "ocirepositories"}


class NotInstalled(Exception):
    """The CRD is not served by the cluster."""


def list_objects(api: client.CustomObjectsApi, group: str, versions: tuple[str, ...], plural: str) -> list[dict]:
    """Every object of a CRD in the first served API version; NotInstalled when none is served."""
    for version in versions:
        try:
            return api.list_cluster_custom_object(group, version, plural)["items"]
        except client.ApiException as exc:
            if exc.status != 404:
                raise
    raise NotInstalled(f"{group}/{plural}")


def _index(objects: list[dict]) -> dict[tuple[str, str], dict]:
    return {((o.get("metadata") or {}).get("namespace", ""), (o.get("metadata") or {}).get("name", "")): o for o in objects}


def _git_ref(ref: dict) -> str:
    return ref.get("tag") or ref.get("commit") or ref.get("branch") or ref.get("name") or "HEAD"


def deployed_version(release: dict) -> str:
    """The chart version of the last release Flux made: status.history (v2), else lastAppliedRevision (v2beta1)."""
    status = release.get("status") or {}
    history = status.get("history") or []
    if history and history[0].get("chartVersion"):
        return str(history[0]["chartVersion"])
    return str(status.get("lastAppliedRevision") or status.get("lastAttemptedRevision") or "")


def release_name(release: dict) -> tuple[str, str]:
    """(namespace, name) of the Helm release made by a HelmRelease, as Flux names it."""
    meta, spec = release.get("metadata") or {}, release.get("spec") or {}
    history = (release.get("status") or {}).get("history") or []
    if history and history[0].get("name"):
        return history[0].get("namespace") or meta.get("namespace", ""), history[0]["name"]
    target = spec.get("targetNamespace")
    name = spec.get("releaseName") or (f"{target}-{meta.get('name', '')}" if target else meta.get("name", ""))
    return spec.get("storageNamespace") or target or meta.get("namespace", ""), name


def chart_from_helmrelease(cluster: str, release: dict, sources: dict[str, dict[tuple[str, str], dict]]) -> ChartReport:
    """The chart of a HelmRelease, its repository read from its source object (`sources`: kind -> objects)."""
    meta, spec = release.get("metadata") or {}, release.get("spec") or {}
    namespace = meta.get("namespace", "")
    chart_spec = ((spec.get("chart") or {}).get("spec")) or {}
    report = ChartReport(
        cluster=cluster,
        application=meta.get("name", ""),
        app_namespace=namespace,
        chart=chart_spec.get("chart") or "",
        repository="",
        version=deployed_version(release),
        source_type="helm",
        destination_namespace=spec.get("targetNamespace") or namespace,
        inline_values=booleans(spec.get("values") or {}),
        manager="flux",
    )
    ref = spec.get("chartRef") or chart_spec.get("sourceRef") or {}
    kind, key = ref.get("kind", ""), (ref.get("namespace") or namespace, ref.get("name", ""))
    source = (sources.get(kind) or {}).get(key)
    if kind == "HelmChart":
        report.message = "chartRef to a HelmChart: not read by kube-tower"
    elif kind not in SOURCES:
        report.message = f"source {kind or 'unknown'} not supported (HelmRepository, GitRepository, OCIRepository)"
    elif source is None:
        report.message = f"{kind} {key[0]}/{key[1]} not found"
    else:
        source_spec = source.get("spec") or {}
        url = str(source_spec.get("url") or "")
        if kind == "OCIRepository":
            # oci://ghcr.io/org/charts/app: the repository and the chart name
            report.repository, _, report.chart = url.rstrip("/").rpartition("/")
            report.source_type = "oci"
            if not report.version:
                report.version = str((source_spec.get("ref") or {}).get("tag") or "")
        elif kind == "GitRepository":
            path = report.chart or "."
            report.repository, report.source_type, report.path = url, "git", path
            report.git_ref, report.version = _git_ref(source_spec.get("ref") or {}), ""
        else:
            oci = source_spec.get("type") == "oci" or url.startswith("oci://")
            report.repository, report.source_type = url, "oci" if oci else "helm"
    if not report.version:
        report.version = str(chart_spec.get("version") or "")
    return report


def collect(cluster: str, api: client.CustomObjectsApi) -> tuple[list[ChartReport], set[tuple[str, str]]]:
    """The charts of every HelmRelease of the cluster and the (namespace, name) of the Helm releases they
    made; NotInstalled without Flux."""
    releases = list_objects(api, HELM_GROUP, HELM_VERSIONS, "helmreleases")
    sources: dict[str, dict[tuple[str, str], dict]] = {}
    for kind, plural in SOURCES.items():
        try:
            sources[kind] = _index(list_objects(api, SOURCE_GROUP, SOURCE_VERSIONS, plural))
        except NotInstalled:
            sources[kind] = {}
    return [chart_from_helmrelease(cluster, r, sources) for r in releases], {release_name(r) for r in releases}
